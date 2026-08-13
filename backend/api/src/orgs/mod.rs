// Orgs: relying-party accounts (banks, AI platforms, hospitals, government
// counters — matches `organizations.org_type` CHECK constraint, see
// `domain::OrgType`). This module is what turns the disclosure/verify
// modules' `X-Org-Id: <uuid>` trust-me stub into real auth: an org gets a
// randomly generated API key exactly once at creation time, the server only
// ever stores its hash (`organizations.api_key_hash`), and every org-facing
// route downstream (this module's own, plus `disclosure::` and
// `verify::`) now goes through `OrgAuth`, which resolves that key back to
// an org id the same way `auth::session_token::AuthUser` resolves a session
// token back to a user id.

use axum::extract::{FromRequestParts, Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::session_token::hash_token;
use crate::disclosure::effective_status;
use crate::domain::{DisclosureStatus, OrgType};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/orgs", post(create_org))
        .route("/orgs/:id/disclosure-requests", get(list_org_disclosure_requests))
}

// ---------------------------------------------------------------------
// API key generation / hashing
//
// Deliberately mirrors `auth::session_token::generate_token`/`hash_token`
// rather than inventing a second convention: 32 random bytes from the OS
// CSPRNG, base64url-no-pad encoded for the value handed to the org, plain
// SHA-256 for the stored hash (no argon2 — same reasoning as session
// tokens: the input already carries 256 bits of entropy, so there's no
// low-entropy secret to slow-hash against offline brute force). `hash_token`
// itself is reused directly (not reimplemented) so there is exactly one
// hashing routine in the codebase for "secret handed to a client, only its
// hash persisted".
// ---------------------------------------------------------------------

const API_KEY_BYTES: usize = 32;

/// `pub(crate)` (not private) so other modules' tests can generate a real,
/// properly-hashable API key when seeding a test org, rather than writing a
/// second ad-hoc "fake looking hash" convention (see disclosure/mod.rs's
/// `make_org` test helper).
pub(crate) fn generate_api_key() -> String {
    let mut bytes = [0u8; API_KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Resolve a presented API key to its owning org id, or `None` if it
/// doesn't match any stored hash. Shared by `OrgAuth` below and by
/// `disclosure::authorize_org_or_user`, which needs the same lookup for its
/// dual-audience (org-or-user) routes but doesn't want to duplicate the
/// hash-and-query logic.
pub(crate) async fn org_id_for_api_key(db: &PgPool, presented_key: &str) -> ApiResult<Option<Uuid>> {
    let key_hash = hash_token(presented_key);
    let id = sqlx::query_scalar!("select id from organizations where api_key_hash = $1", key_hash)
        .fetch_optional(db)
        .await?;
    Ok(id)
}

// ---------------------------------------------------------------------
// OrgAuth extractor — mirrors AuthUser's FromRequestParts shape exactly.
// Reads `Authorization: Bearer <api_key>` (same header/scheme AuthUser
// reads a session token from) rather than a bespoke header: this module's
// whole point is to make org auth a real, first-class credential, not a
// second-class "custom header" scheme living next to real session auth.
// ---------------------------------------------------------------------

pub struct OrgAuth(pub Uuid);

#[axum::async_trait]
impl FromRequestParts<AppState> for OrgAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let key = header.strip_prefix("Bearer ").ok_or(ApiError::Unauthorized)?;

        let org_id = org_id_for_api_key(&state.db, key).await?.ok_or(ApiError::Unauthorized)?;
        Ok(OrgAuth(org_id))
    }
}

// ---------------------------------------------------------------------
// POST /orgs
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateOrgBody {
    name: String,
    org_type: String,
}

#[derive(Serialize)]
struct CreateOrgResponse {
    id: Uuid,
    name: String,
    org_type: String,
    /// Shown exactly once. The server never stores this value, only
    /// `hash_token(api_key)` in `organizations.api_key_hash` — losing it
    /// means the org must be issued a new key (not implemented in this
    /// pass; see report), not that it can be recovered.
    api_key: String,
    created_at: DateTime<Utc>,
}

/// Org self-registration. Deliberately unauthenticated, same posture as
/// user registration (`auth::find_or_create_user_by_phone` et al. — no
/// admin gate exists there either): an org proves who it is by presenting
/// the key it's handed here on every subsequent call, not by some
/// out-of-band approval step this pass doesn't build. Gating org creation
/// behind an admin/allowlist is a real product question but out of scope
/// for this pass (see report).
async fn create_org(
    State(state): State<AppState>,
    Json(body): Json<CreateOrgBody>,
) -> ApiResult<(StatusCode, Json<CreateOrgResponse>)> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    let org_type = OrgType::parse(&body.org_type)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown org_type '{}'", body.org_type)))?;

    let api_key = generate_api_key();
    let api_key_hash = hash_token(&api_key);

    let row = sqlx::query!(
        r#"
        insert into organizations (name, org_type, api_key_hash)
        values ($1, $2, $3)
        returning id, name, org_type, created_at
        "#,
        body.name,
        org_type.as_str(),
        api_key_hash,
    )
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateOrgResponse {
            id: row.id,
            name: row.name,
            org_type: row.org_type,
            api_key,
            created_at: row.created_at,
        }),
    ))
}

// ---------------------------------------------------------------------
// GET /orgs/:id/disclosure-requests
//
// Backs the wireframe's `EnterpriseBankView` ("Compliance Analyst
// Portal"): the analyst-facing screen needs, per request, its current
// status and whatever proof attempts have been made against it (the
// verified/redacted attributes shown in the "Vault Preview" pane come from
// the org's own policy selection, not from this endpoint — this endpoint's
// job is "what did we ask for, and what came back").
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct ProofResult {
    id: Uuid,
    valid: bool,
    verified_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct OrgDisclosureRequestSummary {
    id: Uuid,
    user_id: Uuid,
    circuit_type: String,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// Every proof attempt against this request, both accepted and
    /// rejected (see verify/mod.rs: an invalid proof is recorded with
    /// `valid = false` but doesn't consume the request), oldest first.
    proofs: Vec<ProofResult>,
}

/// `:id` is the org whose requests are being listed; `OrgAuth` is who is
/// actually asking. They must match — a valid API key only ever grants
/// visibility into its own org's requests, not an arbitrary `:id` in the
/// URL.
async fn list_org_disclosure_requests(
    OrgAuth(auth_org_id): OrgAuth,
    Path(path_org_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<OrgDisclosureRequestSummary>>> {
    if auth_org_id != path_org_id {
        return Err(ApiError::Forbidden);
    }

    let requests = sqlx::query!(
        r#"
        select id, circuit_type, status, expires_at, created_at, user_id
        from disclosure_requests
        where org_id = $1
        order by created_at desc
        "#,
        path_org_id,
    )
    .fetch_all(&state.db)
    .await?;

    let proof_rows = sqlx::query!(
        r#"
        select p.id, p.request_id, p.valid, p.verified_at
        from proofs p
        join disclosure_requests dr on dr.id = p.request_id
        where dr.org_id = $1
        order by p.verified_at asc
        "#,
        path_org_id,
    )
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(requests.len());
    for req in requests {
        let status =
            effective_status(&state.db, req.id, DisclosureStatus::parse(&req.status).unwrap_or(DisclosureStatus::Pending), req.expires_at)
                .await?;
        let proofs = proof_rows
            .iter()
            .filter(|p| p.request_id == req.id)
            .map(|p| ProofResult { id: p.id, valid: p.valid, verified_at: p.verified_at })
            .collect();

        out.push(OrgDisclosureRequestSummary {
            id: req.id,
            user_id: req.user_id,
            circuit_type: req.circuit_type,
            status: status.as_str().to_string(),
            created_at: req.created_at,
            expires_at: req.expires_at,
            proofs,
        });
    }

    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_api_key_is_url_safe_without_padding() {
        let key = generate_api_key();
        assert!(!key.contains('='));
        assert!(!key.contains('+'));
        assert!(!key.contains('/'));
        assert_eq!(key.len(), 43, "32 bytes base64url-no-pad encodes to 43 chars");
    }

    #[test]
    fn generated_api_keys_are_not_all_equal() {
        let a = generate_api_key();
        let b = generate_api_key();
        assert_ne!(a, b);
    }

    #[test]
    fn api_key_hash_is_deterministic_and_never_equals_the_key() {
        let key = generate_api_key();
        let h1 = hash_token(&key);
        let h2 = hash_token(&key);
        assert_eq!(h1, h2);
        assert_ne!(h1, key);
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(5).connect(&url).await.ok()
        }

        async fn cleanup(db: &PgPool, org_id: Uuid) {
            let _ = sqlx::query!("delete from organizations where id = $1", org_id).execute(db).await;
        }

        /// End-to-end against real Postgres: creating an org via the same
        /// SQL `create_org` runs, then resolving its freshly-generated key
        /// back to the org id via `org_id_for_api_key` (the exact function
        /// `OrgAuth` calls) — proving the whole "generate key -> hash ->
        /// store -> look up by presenting the raw key again" loop actually
        /// works, not just that each half compiles.
        #[tokio::test]
        async fn org_id_for_api_key_resolves_a_freshly_created_org() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };

            let api_key = generate_api_key();
            let api_key_hash = hash_token(&api_key);
            let org_id: Uuid = sqlx::query_scalar!(
                r#"insert into organizations (name, org_type, api_key_hash) values ($1, 'bank', $2) returning id"#,
                format!("Orgs Test Bank {}", Uuid::new_v4()),
                api_key_hash,
            )
            .fetch_one(&db)
            .await
            .unwrap();

            let resolved = org_id_for_api_key(&db, &api_key).await.unwrap();
            assert_eq!(resolved, Some(org_id));

            let wrong_key_resolved = org_id_for_api_key(&db, "not-the-real-key").await.unwrap();
            assert_eq!(wrong_key_resolved, None);

            cleanup(&db, org_id).await;
        }
    }
}
