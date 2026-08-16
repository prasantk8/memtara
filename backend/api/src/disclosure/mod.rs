// Disclosure requests: the org-initiated "please prove X to me" lifecycle
// that a bank/AI platform/hospital/government counter drives, and that the
// `verify` module's proof submission route resolves.
//
// Org auth is real: every org-facing route below is guarded by
// `orgs::OrgAuth`, which resolves a presented `Authorization: Bearer
// <api_key>` header to an org id the same way `auth::AuthUser` resolves a
// session token to a user id (see orgs/mod.rs). This replaces an earlier
// pass's `X-Org-Id: <uuid>` trust-me-header stub — there is no longer any
// header this module trusts at face value.

use axum::extract::{Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::session_token::hash_token;
use crate::domain::{CircuitType, DisclosureStatus, SessionPolicy};
use crate::error::{ApiError, ApiResult};
use crate::orgs::{org_id_for_api_key, OrgAuth};
use crate::state::AppState;

/// Lower/upper bounds on a disclosure request's requested lifetime. Nothing
/// in the product needs a pending request to outlive a week (an org that
/// still wants a proof after that should just create a new request), and
/// bounding it keeps stale-pending rows from accumulating unboundedly.
const MIN_TTL_SECONDS: i64 = 1;
const MAX_TTL_SECONDS: i64 = 7 * 24 * 3600;

/// Number of random bytes generated for a disclosure request's nonce. 31
/// bytes (248 bits) rather than 32: every session circuit's `nonce` is a
/// `Field` (a BN254 scalar, ~254-bit modulus), and picking a value that's
/// guaranteed less than the field modulus without doing big-integer modular
/// reduction here is simpler and just as unguessable. Stored as a 32-byte
/// big-endian value (leading zero byte) so it compares byte-for-byte equal
/// to how a `Field` public input is packed by `bb` (see verify/mod.rs).
const NONCE_RANDOM_BYTES: usize = 31;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/disclosure-requests", post(create_disclosure_request).get(list_disclosure_requests))
        .route("/disclosure-requests/:id", get(get_disclosure_request))
        .route("/disclosure-requests/:id/revoke", post(revoke_disclosure_request))
}

// ---------------------------------------------------------------------
// Dual-audience authorization (org-or-user)
// ---------------------------------------------------------------------

/// Dual-audience ownership check shared by every route below (and by
/// `verify::submit_proof`, which lives under the same `/disclosure-requests/
/// :id/...` path space): a disclosure request may be read/revoked/resolved
/// by either the org that created it (a valid API key matching
/// `expected_org_id`) or the user it's for (a valid session bearer token
/// matching `expected_user_id`). Not implemented as a single
/// `FromRequestParts` extractor because "org key OR user session, checked
/// against a row we haven't fetched yet" doesn't fit the "reject before the
/// handler body runs" shape `OrgAuth`/`AuthUser` use individually — we need
/// the row's org_id/user_id first, so both possibilities are tried against
/// the one `Authorization: Bearer <token>` header the caller sent: first as
/// an org API key (`orgs::org_id_for_api_key`), then, if that doesn't match
/// anything, as a user session token. A single header/scheme for both
/// credential kinds (rather than a bespoke `X-Org-Id`-style header for one
/// of them) is deliberate — it's the same reasoning `orgs::OrgAuth`'s doc
/// comment gives for reading `Authorization: Bearer` instead of a custom
/// header.
pub(crate) async fn authorize_org_or_user(
    state: &AppState,
    headers: &HeaderMap,
    expected_org_id: Uuid,
    expected_user_id: Uuid,
) -> ApiResult<()> {
    let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return Err(ApiError::Unauthorized);
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err(ApiError::Unauthorized);
    };

    if let Some(org_id) = org_id_for_api_key(&state.db, token).await? {
        return if org_id == expected_org_id { Ok(()) } else { Err(ApiError::Forbidden) };
    }

    let token_hash = hash_token(token);
    let row = sqlx::query!(
        r#"
        select user_id from sessions
        where token_hash = $1 and revoked_at is null and expires_at > now()
        "#,
        token_hash,
    )
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some(row) if row.user_id == expected_user_id => Ok(()),
        Some(_) => Err(ApiError::Forbidden),
        None => Err(ApiError::Unauthorized),
    }
}

fn generate_nonce() -> Vec<u8> {
    let mut bytes = [0u8; NONCE_RANDOM_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Left-pad to 32 bytes so this matches the fixed-width big-endian
    // packing bb uses for a Field public input (see verify/mod.rs).
    let mut padded = vec![0u8; 32 - NONCE_RANDOM_BYTES];
    padded.extend_from_slice(&bytes);
    padded
}

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Flip `pending` -> `expired` if the deadline has passed. Lazy
/// check-on-read, called from every route that returns a request's status,
/// per HANDOFF.md ("lazy check-on-read is fine for this pass — don't build
/// a cron job"). Idempotent and safe under concurrent callers: the UPDATE's
/// `where status = 'pending'` means a racing caller that already flipped it
/// just affects zero rows here, and both callers converge on returning
/// `Expired`.
pub(crate) async fn effective_status(
    db: &sqlx::PgPool,
    id: Uuid,
    status: DisclosureStatus,
    expires_at: DateTime<Utc>,
) -> ApiResult<DisclosureStatus> {
    if status == DisclosureStatus::Pending && expires_at <= Utc::now() {
        sqlx::query!(
            "update disclosure_requests set status = 'expired' where id = $1 and status = 'pending'",
            id,
        )
        .execute(db)
        .await?;
        Ok(DisclosureStatus::Expired)
    } else {
        Ok(status)
    }
}

fn parse_status(s: &str) -> DisclosureStatus {
    // Every row's status column is written exclusively by this module and
    // is CHECK-constrained at the DB level to one of these four values, so
    // this can't actually fail — but `DisclosureStatus::parse` returns
    // `Option`, and unwrapping a `None` here would panic the request
    // instead of failing gracefully, so fall back to `Pending` rather than
    // unwrap. (Kept as a named function instead of `.unwrap_or(..)` inline
    // so the "this shouldn't happen" reasoning has somewhere to live.)
    DisclosureStatus::parse(s).unwrap_or(DisclosureStatus::Pending)
}

// ---------------------------------------------------------------------
// POST /disclosure-requests
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateDisclosureRequestBody {
    user_id: Uuid,
    circuit_type: String,
    policy: SessionPolicy,
    ttl_seconds: i64,
}

#[derive(Serialize)]
struct DisclosureRequestResponse {
    id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    circuit_type: String,
    policy: SessionPolicy,
    status: String,
    /// Base64 (URL-safe, no padding) — the exact nonce the client must
    /// embed as the `nonce` public input when it builds the proof.
    nonce: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

async fn create_disclosure_request(
    OrgAuth(org_id): OrgAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateDisclosureRequestBody>,
) -> ApiResult<(StatusCode, Json<DisclosureRequestResponse>)> {
    let circuit_type = CircuitType::parse(&body.circuit_type)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown circuit_type '{}'", body.circuit_type)))?;

    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&body.ttl_seconds) {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )));
    }

    // No separate "does this org exist" check needed here (an earlier,
    // header-stub pass needed one): `OrgAuth` already proved `org_id` names
    // a real row by successfully resolving the presented API key against
    // `organizations.api_key_hash`.

    let user_exists =
        sqlx::query_scalar!(r#"select exists(select 1 from users where id = $1) as "exists!""#, body.user_id)
            .fetch_one(&state.db)
            .await?;
    if !user_exists {
        return Err(ApiError::NotFound);
    }

    let policy_json = serde_json::to_value(&body.policy)
        .map_err(|e| ApiError::BadRequest(format!("policy did not serialize: {e}")))?;
    let nonce = generate_nonce();
    let expires_at = Utc::now() + chrono::Duration::seconds(body.ttl_seconds);

    let row = sqlx::query!(
        r#"
        insert into disclosure_requests (org_id, user_id, circuit_type, policy, status, nonce, expires_at)
        values ($1, $2, $3, $4, 'pending', $5, $6)
        returning id, org_id, user_id, circuit_type, policy, status, nonce, expires_at, created_at
        "#,
        org_id,
        body.user_id,
        circuit_type.as_str(),
        policy_json,
        nonce,
        expires_at,
    )
    .fetch_one(&state.db)
    .await?;

    let policy: SessionPolicy = serde_json::from_value(row.policy)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("stored policy failed to deserialize: {e}")))?;

    // ref_id = the disclosure_requests row this event is about — every
    // disclosure/proof audit event in this codebase uses that same
    // convention, which is what lets `GET /orgs/:id/audit-log`
    // (audit/mod.rs) join audit_log -> disclosure_requests -> org_id to
    // scope an org to only its own trail.
    crate::audit::record(
        &state.db,
        Some(row.org_id),
        "disclosure_request_created",
        Some(row.id),
        serde_json::json!({
            "user_id": row.user_id,
            "circuit_type": row.circuit_type,
            "ttl_seconds": body.ttl_seconds,
        }),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(DisclosureRequestResponse {
            id: row.id,
            org_id: row.org_id,
            user_id: row.user_id,
            circuit_type: row.circuit_type,
            policy,
            status: row.status,
            nonce: encode_b64(&row.nonce),
            expires_at: row.expires_at,
            created_at: row.created_at,
        }),
    ))
}

// ---------------------------------------------------------------------
// GET /disclosure-requests/:id
// ---------------------------------------------------------------------

async fn get_disclosure_request(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<DisclosureRequestResponse>> {
    let row = sqlx::query!(
        r#"
        select id, org_id, user_id, circuit_type, policy, status, nonce, expires_at, created_at
        from disclosure_requests
        where id = $1
        "#,
        id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    authorize_org_or_user(&state, &headers, row.org_id, row.user_id).await?;

    let status = effective_status(&state.db, row.id, parse_status(&row.status), row.expires_at).await?;
    let policy: SessionPolicy = serde_json::from_value(row.policy)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("stored policy failed to deserialize: {e}")))?;

    Ok(Json(DisclosureRequestResponse {
        id: row.id,
        org_id: row.org_id,
        user_id: row.user_id,
        circuit_type: row.circuit_type,
        policy,
        status: status.as_str().to_string(),
        nonce: encode_b64(&row.nonce),
        expires_at: row.expires_at,
        created_at: row.created_at,
    }))
}

// ---------------------------------------------------------------------
// GET /disclosure-requests?user_id=...&status=pending
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct ListQuery {
    user_id: Option<Uuid>,
    status: Option<String>,
}

#[derive(Serialize)]
struct DisclosureRequestSummary {
    id: Uuid,
    org_id: Uuid,
    circuit_type: String,
    status: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// This is the authenticated user's own view (powers the wireframe's
/// "Pending Request" card) — not an org-side listing. `user_id` in the
/// query string is accepted for a self-describing URL but must name the
/// caller's own account; a different value is rejected rather than
/// silently ignored, since silently substituting the authenticated user's
/// id would make the query param a lie.
async fn list_disclosure_requests(
    crate::auth::AuthUser(user_id): crate::auth::AuthUser,
    Query(query): Query<ListQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<DisclosureRequestSummary>>> {
    if let Some(requested) = query.user_id {
        if requested != user_id {
            return Err(ApiError::Forbidden);
        }
    }

    let status_filter = match &query.status {
        Some(s) => Some(
            DisclosureStatus::parse(s).ok_or_else(|| ApiError::BadRequest(format!("unknown status '{s}'")))?,
        ),
        None => None,
    };

    let rows = sqlx::query!(
        r#"
        select id, org_id, circuit_type, status, nonce, expires_at, created_at
        from disclosure_requests
        where user_id = $1
        order by created_at desc
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let status = effective_status(&state.db, row.id, parse_status(&row.status), row.expires_at).await?;
        if let Some(filter) = status_filter {
            if status != filter {
                continue;
            }
        }
        out.push(DisclosureRequestSummary {
            id: row.id,
            org_id: row.org_id,
            circuit_type: row.circuit_type,
            status: status.as_str().to_string(),
            expires_at: row.expires_at,
            created_at: row.created_at,
        });
    }

    Ok(Json(out))
}

// ---------------------------------------------------------------------
// POST /disclosure-requests/:id/revoke
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct RevokeResponse {
    id: Uuid,
    status: String,
}

async fn revoke_disclosure_request(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<RevokeResponse>> {
    let row = sqlx::query!(
        "select org_id, user_id, status, expires_at from disclosure_requests where id = $1",
        id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    authorize_org_or_user(&state, &headers, row.org_id, row.user_id).await?;

    // Lazily expire first: an expired request should report "expired" on
    // revoke, not silently succeed as "revoked" past its own deadline.
    let current = effective_status(&state.db, id, parse_status(&row.status), row.expires_at).await?;

    if current == DisclosureStatus::Revoked {
        // Idempotent: revoking an already-revoked request is a no-op success.
        return Ok(Json(RevokeResponse { id, status: current.as_str().to_string() }));
    }
    if current != DisclosureStatus::Pending {
        return Err(ApiError::Conflict(format!("cannot revoke a request that is already {}", current.as_str())));
    }

    let updated = sqlx::query_scalar!(
        r#"
        update disclosure_requests set status = 'revoked'
        where id = $1 and status = 'pending'
        returning status
        "#,
        id,
    )
    .fetch_optional(&state.db)
    .await?;

    match updated {
        Some(status) => {
            crate::audit::record(
                &state.db,
                Some(row.org_id),
                "disclosure_request_revoked",
                Some(id),
                serde_json::json!({ "user_id": row.user_id }),
            )
            .await?;
            Ok(Json(RevokeResponse { id, status }))
        }
        // Lost a race with something else that changed status between the
        // check above and this UPDATE (e.g. a concurrent proof submission
        // fulfilling it). Re-fetch and report the real current state rather
        // than claiming a revoke that didn't happen.
        None => {
            let status: String =
                sqlx::query_scalar!("select status from disclosure_requests where id = $1", id)
                    .fetch_one(&state.db)
                    .await?;
            Err(ApiError::Conflict(format!("cannot revoke a request that is already {status}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_32_bytes_and_left_padded() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert_eq!(nonce[0], 0, "top byte must be zero-padded (only 31 random bytes)");
    }

    #[test]
    fn nonces_are_not_all_equal() {
        // Not a rigorous randomness test — just a sanity check that we
        // didn't accidentally return a fixed buffer.
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
    }

    #[test]
    fn b64_nonce_round_trips() {
        let nonce = generate_nonce();
        let encoded = encode_b64(&nonce);
        assert!(!encoded.contains('='));
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded, nonce);
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;
        use sqlx::PgPool;

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(5).connect(&url).await.ok()
        }

        async fn make_user(db: &PgPool) -> Uuid {
            sqlx::query_scalar!(
                "insert into users (email) values ($1) returning id",
                format!("disclosure-test-{}@example.invalid", Uuid::new_v4()),
            )
            .fetch_one(db)
            .await
            .expect("insert test user")
        }

        /// Returns `(org_id, raw_api_key)` — a real key generated the exact
        /// same way `orgs::create_org` does, hashed the exact same way
        /// (`hash_token`), so tests exercising `authorize_org_or_user`/
        /// `OrgAuth` are presenting a credential that round-trips for real,
        /// not a placeholder string that happens to satisfy the column's
        /// NOT NULL/unique constraints.
        async fn make_org(db: &PgPool) -> (Uuid, String) {
            let api_key = crate::orgs::generate_api_key();
            let api_key_hash = hash_token(&api_key);
            let org_id = sqlx::query_scalar!(
                r#"
                insert into organizations (name, org_type, api_key_hash)
                values ($1, 'bank', $2)
                returning id
                "#,
                format!("Test Bank {}", Uuid::new_v4()),
                api_key_hash,
            )
            .fetch_one(db)
            .await
            .expect("insert test org");
            (org_id, api_key)
        }

        async fn cleanup(db: &PgPool, org_id: Uuid, user_id: Uuid) {
            let _ = sqlx::query!(
                "delete from audit_log where ref_id in (select id from disclosure_requests where org_id = $1)",
                org_id,
            )
            .execute(db)
            .await;
            let _ = sqlx::query!("delete from disclosure_requests where org_id = $1", org_id).execute(db).await;
            let _ = sqlx::query!("delete from organizations where id = $1", org_id).execute(db).await;
            let _ = sqlx::query!("delete from users where id = $1", user_id).execute(db).await;
        }

        /// Proves the lazy expiry sweep is real: insert a disclosure_request
        /// whose `expires_at` is already in the past but whose stored
        /// status is still 'pending' (simulating "nobody has read it since
        /// it expired"), then call `effective_status` — the same function
        /// every route calls on read — and confirm it both (a) reports
        /// `Expired` and (b) actually wrote that back to the row, not just
        /// computed it in memory.
        #[tokio::test]
        async fn lazy_expiry_flips_pending_past_deadline_to_expired_in_db() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let (org_id, _api_key) = make_org(&db).await;
            let user_id = make_user(&db).await;

            let past = Utc::now() - chrono::Duration::seconds(10);
            let request_id: Uuid = sqlx::query_scalar!(
                r#"
                insert into disclosure_requests (org_id, user_id, circuit_type, policy, status, nonce, expires_at)
                values ($1, $2, 'emergency_session', '{}'::jsonb, 'pending', $3, $4)
                returning id
                "#,
                org_id,
                user_id,
                vec![1u8; 32],
                past,
            )
            .fetch_one(&db)
            .await
            .unwrap();

            let computed = effective_status(&db, request_id, DisclosureStatus::Pending, past).await.unwrap();
            assert_eq!(computed, DisclosureStatus::Expired);

            let stored: String =
                sqlx::query_scalar!("select status from disclosure_requests where id = $1", request_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(stored, "expired", "the row itself must be updated, not just the in-memory return value");

            cleanup(&db, org_id, user_id).await;
        }

        /// A request that hasn't hit its deadline yet must be left alone.
        #[tokio::test]
        async fn lazy_expiry_leaves_unexpired_pending_request_untouched() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let (org_id, _api_key) = make_org(&db).await;
            let user_id = make_user(&db).await;

            let future = Utc::now() + chrono::Duration::seconds(3600);
            let request_id: Uuid = sqlx::query_scalar!(
                r#"
                insert into disclosure_requests (org_id, user_id, circuit_type, policy, status, nonce, expires_at)
                values ($1, $2, 'emergency_session', '{}'::jsonb, 'pending', $3, $4)
                returning id
                "#,
                org_id,
                user_id,
                vec![2u8; 32],
                future,
            )
            .fetch_one(&db)
            .await
            .unwrap();

            let computed = effective_status(&db, request_id, DisclosureStatus::Pending, future).await.unwrap();
            assert_eq!(computed, DisclosureStatus::Pending);

            cleanup(&db, org_id, user_id).await;
        }

        /// `authorize_org_or_user` is the gate every disclosure/verify route
        /// shares. Exercise it directly against real org API keys and real
        /// session rows: the owning org's real key passes, a *different*
        /// real org's key is forbidden (not just any garbage bearer token —
        /// this proves the org lookup genuinely resolves to a distinct org
        /// id, not that it accidentally always matches), and a session
        /// token belonging to a different user is forbidden — proving this
        /// isn't a no-op that accidentally allows everything through.
        #[tokio::test]
        async fn authorize_org_or_user_enforces_real_ownership() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let (org_id, api_key) = make_org(&db).await;
            let (other_org_id, other_org_api_key) = make_org(&db).await;
            let user_id = make_user(&db).await;
            let other_user_id = make_user(&db).await;

            let state = AppState {
                db: db.clone(),
                config: std::sync::Arc::new(crate::config::Config::from_env().unwrap()),
                webauthn: std::sync::Arc::new(crate::auth::webauthn::build(&crate::config::Config::from_env().unwrap()).unwrap()),
                webauthn_ceremonies: std::sync::Arc::new(crate::auth::webauthn::WebauthnCeremonies::default()),
                otp_provider: std::sync::Arc::new(crate::auth::otp::LoggingOtpProvider),
                uae_pass_provider: std::sync::Arc::new(crate::auth::uae_pass::StubUaePassProvider {
                    authorize_base: "https://stg-id.uaepass.ae/idshub/authorize".into(),
                    client_id: "test".into(),
                    redirect_uri: "http://localhost/cb".into(),
                }),
                signer: std::sync::Arc::new(crate::crypto::signer::IssuerKey::from_seed(
                    [0u8; 32],
                    "https://api.memtara.test",
                )),
                metrics: std::sync::Arc::new(crate::ops::metrics::Metrics::default()),
                rate_limiter: std::sync::Arc::new(crate::ops::rate_limit::RateLimiter::new(
                    10,
                    std::time::Duration::from_secs(60),
                )),
            };

            // Matching org's real API key: allowed.
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {api_key}").parse().unwrap());
            assert!(authorize_org_or_user(&state, &headers, org_id, user_id).await.is_ok());

            // A different, equally real org's API key: forbidden (resolves
            // to a real-but-wrong org id, not treated as "no credentials").
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {other_org_api_key}").parse().unwrap());
            assert!(matches!(
                authorize_org_or_user(&state, &headers, org_id, user_id).await,
                Err(ApiError::Forbidden)
            ));

            // Real session token for `other_user_id`, but the row belongs
            // to `user_id`: forbidden, not silently allowed.
            let issued = crate::auth::session_token::issue_session(&db, other_user_id, None, std::time::Duration::from_secs(3600))
                .await
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {}", issued.token).parse().unwrap());
            assert!(matches!(
                authorize_org_or_user(&state, &headers, org_id, user_id).await,
                Err(ApiError::Forbidden)
            ));

            // Real session token for the actual `user_id`: allowed.
            let issued_owner =
                crate::auth::session_token::issue_session(&db, user_id, None, std::time::Duration::from_secs(3600))
                    .await
                    .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {}", issued_owner.token).parse().unwrap());
            assert!(authorize_org_or_user(&state, &headers, org_id, user_id).await.is_ok());

            // Garbage bearer token matching neither an org key nor a
            // session: unauthorized (not silently forbidden or allowed).
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, "Bearer totally-not-a-real-credential".parse().unwrap());
            assert!(matches!(
                authorize_org_or_user(&state, &headers, org_id, user_id).await,
                Err(ApiError::Unauthorized)
            ));

            // No credentials at all: unauthorized.
            let headers = HeaderMap::new();
            assert!(matches!(
                authorize_org_or_user(&state, &headers, org_id, user_id).await,
                Err(ApiError::Unauthorized)
            ));

            let _ = sqlx::query!("delete from sessions where user_id in ($1, $2)", user_id, other_user_id)
                .execute(&db)
                .await;
            cleanup(&db, org_id, user_id).await;
            let _ = sqlx::query!("delete from organizations where id = $1", other_org_id).execute(&db).await;
            let _ = sqlx::query!("delete from users where id = $1", other_user_id).execute(&db).await;
        }
    }
}
