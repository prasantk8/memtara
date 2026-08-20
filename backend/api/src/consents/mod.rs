// Consent: a first-class, revocable grant — the record `purpose_hash` has
// always been mistaken for.
//
// -------------------------------------------------------------------
// WHY THIS MODULE EXISTS, AND WHY IT TOOK THIS LONG
// -------------------------------------------------------------------
// `tests/break_it/test_attack_08_consent_revocation.py` stood as a tripwire
// through the binding stage: it greps `backend/api/src/` for "consent" and
// FAILS the moment the word appears near a table or a route, precisely so
// that nobody could mistake a stale green skip for "consent revocation was
// verified". Its own analysis is the reason that skip was honest rather
// than lazy: the nearest thing this system had, `vault::session::
// SessionPolicy.purpose_hash` (built once per request in
// `wealth::issue_wealth_request` from a hardcoded string), is a purpose
// BINDING — it says what a session was FOR — and has never said that anyone
// AGREED to it, and cannot say that agreement was later withdrawn, because
// it carries nothing that could be withdrawn: no id, no grant time, no
// scope, no revocation path.
//
// This module is that missing concept. It does not touch `purpose_hash` —
// `SessionPolicy` still binds a purpose the same way it always did — and it
// does not retire it either: `evidence::Consent::purpose_hash` keeps
// carrying it precisely so populating a real consent record can never be
// mistaken for having always had one. What this module adds is the thing
// that was never there: an id, a scope, a version, a grant time, a channel,
// and — the part attack 8 is named after — a revocation.
//
// -------------------------------------------------------------------
// WHY THE ORG GRANTS, NOT THE USER
// -------------------------------------------------------------------
// Every route below is `OrgAuth`-guarded, mirroring `disclosure_requests`
// rather than the dual-audience shape `disclosure::authorize_org_or_user`
// gives its own routes. That is a deliberate, narrower choice: `granted_via`
// (`assisted_kiosk`, `mobile_app`) says a consent grant is captured THROUGH
// an organisation's channel — the journeys doc's non-tech-savvy flows need
// exactly this, a bank clerk or kiosk recording that a customer agreed,
// often on hardware the customer does not operate directly. The row is
// therefore the ORGANISATION's assertion, made under its API key, that a
// grant of this shape happened — precisely as `decision_reviews.reviewer_id`
// is the organisation's assertion about who reviewed a decision, not a fact
// Memtara independently witnessed. A user-authenticated "I consent" route is
// a real and different feature, is not what any of this stage's callers
// need, and is not built here.
//
// -------------------------------------------------------------------
// WHAT THIS MODULE DOES NOT CLAIM
// -------------------------------------------------------------------
// It does not verify a human actually agreed to anything — see the header
// of migrations/0011 for the fuller argument, the same one
// `decision_reviews.reviewer_id` already makes. It does not retroactively
// change history: `issue_wealth_request`'s enforcement (`wealth/mod.rs`)
// checks whether a live grant covers a decision at the MOMENT the decision
// opens, and a later revocation refuses the NEXT decision, not the ones
// already opened — their evidence answers "was consent live when this was
// decided", which is the question an examiner asks, and mutating it after
// the fact would be answering a different one. And it claims consent for
// exactly one enforcement point: `issue_wealth_request`. A table and four
// routes existing is not the same claim as every code path having been
// wired to check them.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

/// How far ahead of the server's clock a claimed `granted_at` may sit. Same
/// number and same reasoning as `wealth::review::MAX_CLOCK_SKEW_SECONDS`: a
/// caller integrating both endpoints has one allowance to learn. There is
/// deliberately no BACKDATE bound to match it — unlike a declared model-call
/// timestamp, which attack 11 showed could smuggle a stale attestation past
/// a decision it did not describe, a consent grant legitimately migrates in
/// from a legacy CRM or a paper file with a grant date years in the past,
/// and this module has no basis on which to call that implausible.
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// The shortest revocation reason this endpoint accepts. Same floor and
/// same reasoning as `evidence::MIN_OVERRIDE_REASON_CHARS`: not a quality
/// bar, just the point past which `"x"`, `"n/a"` and `"-"` stop fitting.
/// `consent_grants_revocation_needs_reason` in migrations/0011 holds the
/// same number as a CHECK constraint so the two cannot drift.
const MIN_REVOCATION_REASON_CHARS: usize = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/consents", post(create_consent).get(list_consents))
        .route("/api/v1/consents/:id", get(get_consent))
        .route("/api/v1/consents/:id/revoke", post(revoke_consent))
}

// ---------------------------------------------------------------------
// The row, and the one shape every route serves it in.
// ---------------------------------------------------------------------

/// One `consent_grants` row, exactly as stored. The single read shape every
/// route below uses — `sqlx::query_as!` against this struct on the way in
/// from `POST`, `POST .../revoke`, `GET .../:id` and `GET ?user_id=` alike —
/// so a column added to one response and not another is a compile error
/// rather than a support ticket.
struct ConsentGrantRow {
    id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    scope: serde_json::Value,
    consent_version: String,
    purpose_hash: Option<String>,
    granted_at: DateTime<Utc>,
    granted_via: String,
    revoked_at: Option<DateTime<Utc>>,
    revocation_reason: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub scope: Vec<String>,
    pub consent_version: String,
    pub purpose_hash: Option<String>,
    pub granted_at: DateTime<Utc>,
    pub granted_via: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ConsentGrantRow {
    /// `scope` came back through the CHECK constraint in migrations/0011
    /// (`consent_scope_is_array_of_nonempty_strings`), so this can only fail
    /// if a row was written around the schema — handled rather than
    /// unwrapped for the reason `wealth/evidence.rs` gives about impossible
    /// database rows: a row read out of a database is input, and the honest
    /// failure for one is an error naming what was found, not a panic.
    fn into_response(self) -> ApiResult<ConsentResponse> {
        let scope: Vec<String> = serde_json::from_value(self.scope).map_err(|e| {
            ApiError::Other(anyhow::anyhow!(
                "consent_grants.scope for {} is not an array of strings ({e}), which \
                 consent_scope_is_array_of_nonempty_strings forbids; the row was written around \
                 the schema",
                self.id
            ))
        })?;
        Ok(ConsentResponse {
            id: self.id,
            org_id: self.org_id,
            user_id: self.user_id,
            scope,
            consent_version: self.consent_version,
            purpose_hash: self.purpose_hash,
            granted_at: self.granted_at,
            granted_via: self.granted_via,
            revoked_at: self.revoked_at,
            revocation_reason: self.revocation_reason,
            created_at: self.created_at,
        })
    }
}

fn required(field: &str, value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_string())
}

/// A lower-case hex SHA-256, or a 400. Same rule and same wording as
/// `wealth::model_intake::parse_digest` — duplicated rather than shared,
/// because that function lives in a private submodule of `wealth` and this
/// module has no business reaching into it; two small, independently
/// readable copies of a five-line check cost less than the coupling would.
fn parse_purpose_hash(value: &str) -> ApiResult<String> {
    let v = value.trim().to_ascii_lowercase();
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "purpose_hash must be a SHA-256 as 64 lower-case hex characters (got {} characters). \
             It is a digest an examiner recomputes or it is nothing, so a value that is not one \
             is refused rather than stored under a name that promises it is",
            v.len()
        )));
    }
    Ok(v)
}

/// `scope` arrives as untyped JSON, not `Vec<String>`, for the reason
/// `wealth::model_intake::resolve_value` gives for its own untyped field:
/// typing it directly hands a malformed scope to axum's `Json` rejection,
/// which answers a bare 422 naming nothing. A caller who sends
/// `["a", 1.5]` — the concrete shape trap 2 warns about, a float smuggled
/// into an otherwise ordinary-looking array — gets told exactly that here,
/// and a 400, not a 500 raised after the row already exists.
fn parse_scope(value: &serde_json::Value) -> ApiResult<Vec<String>> {
    let Some(items) = value.as_array() else {
        return Err(ApiError::BadRequest(
            "scope must be a non-empty JSON array of strings, e.g. \
             [\"wealth.suitability_recommendation\"]"
                .into(),
        ));
    };
    if items.is_empty() {
        return Err(ApiError::BadRequest(
            "scope must not be empty. A consent grant that covers nothing authorises nothing, \
             and an empty array reads to anyone replaying the chain as a gap rather than as the \
             deliberate absence it would actually be"
                .into(),
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, v)| match v.as_str() {
            Some(s) if !s.trim().is_empty() => Ok(s.trim().to_string()),
            Some(_) => Err(ApiError::BadRequest(format!(
                "scope[{i}] must not be blank"
            ))),
            None => Err(ApiError::BadRequest(format!(
                "scope[{i}] must be a string (got {v}). Every element of scope is a purpose or \
                 category string; a number here — a float most dangerously, since it has no \
                 rendering Python's json.dumps and Rust's ryu agree on — cannot be recorded as \
                 evidence"
            ))),
        })
        .collect()
}

// ---------------------------------------------------------------------
// POST /api/v1/consents
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateConsentBody {
    pub user_id: Uuid,
    /// Untyped — see `parse_scope`.
    pub scope: serde_json::Value,
    /// The consent POLICY version this grant was made under — the text the
    /// customer actually saw.
    pub consent_version: String,
    /// The domain-separated digest of the purpose this grant covers, if the
    /// capturing system computed one. Optional — see migrations/0011's
    /// header for why `purpose_hash` is the one column here that is not
    /// required.
    #[serde(default)]
    pub purpose_hash: Option<String>,
    /// Defaults to the server's clock. Accepted because a grant captured at
    /// a kiosk five minutes ago is the ordinary case, and because migrating
    /// consent history from a legacy system needs to be able to say a grant
    /// happened years ago — see `MAX_CLOCK_SKEW_SECONDS` for the one bound
    /// that survives.
    #[serde(default)]
    pub granted_at: Option<DateTime<Utc>>,
    /// e.g. `assisted_kiosk`, `mobile_app`.
    pub granted_via: String,
}

async fn create_consent(
    OrgAuth(org_id): OrgAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateConsentBody>,
) -> ApiResult<(StatusCode, Json<ConsentResponse>)> {
    let scope = parse_scope(&body.scope)?;
    let scope_json = serde_json::json!(scope);
    // Belt and braces on the rule `parse_scope` already enforces by
    // construction (every surviving element is a JSON string, and a JSON
    // string cannot be a float) — the same defence-in-depth
    // `disclosure::create_disclosure_request` runs on `policy` before an
    // insert, checked here for the reason given on
    // `audit::binding::check_scope_is_bindable`: a rule that lives only in
    // this handler is a rule a future call site can route around.
    crate::audit::binding::check_scope_is_bindable(&scope_json)?;

    let consent_version = required("consent_version", &body.consent_version)?;
    let granted_via = required("granted_via", &body.granted_via)?;
    let purpose_hash = body
        .purpose_hash
        .as_deref()
        .map(parse_purpose_hash)
        .transpose()?;

    let user_exists =
        sqlx::query_scalar!(r#"select exists(select 1 from users where id = $1) as "exists!""#, body.user_id)
            .fetch_one(&state.db)
            .await?;
    if !user_exists {
        return Err(ApiError::NotFoundDetail(format!("no user {}", body.user_id)));
    }

    let server_received_at = Utc::now();
    let granted_at = body.granted_at.unwrap_or(server_received_at);
    if granted_at > server_received_at + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) {
        return Err(ApiError::BadRequest(format!(
            "granted_at ({granted_at}) is in the future by more than the \
             {MAX_CLOCK_SKEW_SECONDS} seconds of clock skew this endpoint tolerates. This field \
             records when the grant happened, and a grant that has not happened yet is not one"
        )));
    }

    let mut tx = state.db.begin().await?;

    let row = sqlx::query!(
        r#"
        insert into consent_grants (org_id, user_id, scope, consent_version, purpose_hash,
                                     granted_at, granted_via)
        values ($1, $2, $3, $4, $5, $6, $7)
        returning id, created_at
        "#,
        org_id,
        body.user_id,
        scope_json,
        consent_version,
        purpose_hash,
        granted_at,
        granted_via,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Records THAT a grant was made, in the ordinary audit trail an org
    // reads without knowing binding events exist. `record_consent_grant_
    // binding` below records WHAT it said — the same split
    // `wealth::issue_wealth_request` draws between
    // `wealth_suitability_requested` and its binding events, and for the
    // same reason: this event's payload is not a pure function of one row
    // (it also carries `user_id` outside the row's own columns via the
    // chain's org injection), so it cannot itself be the tamper-evident
    // commitment.
    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "consent_granted",
        Some(row.id),
        serde_json::json!({
            "user_id": body.user_id,
            "scope": scope,
            "consent_version": consent_version,
            "purpose_hash": purpose_hash,
            "granted_via": granted_via,
        }),
    )
    .await?;

    // Same transaction as the insert: a grant that exists without the event
    // that commits to its contents is precisely the gap this stage closes.
    crate::audit::binding::record_consent_grant_binding(&mut tx, org_id, row.id).await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(ConsentResponse {
            id: row.id,
            org_id,
            user_id: body.user_id,
            scope,
            consent_version,
            purpose_hash,
            granted_at,
            granted_via,
            revoked_at: None,
            revocation_reason: None,
            created_at: row.created_at,
        }),
    ))
}

// ---------------------------------------------------------------------
// POST /api/v1/consents/:id/revoke
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeConsentBody {
    pub revocation_reason: String,
}

fn revocation_reason(value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.chars().count() < MIN_REVOCATION_REASON_CHARS {
        return Err(ApiError::BadRequest(format!(
            "revocation_reason must be at least {MIN_REVOCATION_REASON_CHARS} characters. \
             Revocation is a first-class recorded fact, not a deleted row, and the reason is \
             what an examiner reads beside the grant it withdraws — say why: the customer asked, \
             a relationship ended, a regulator ordered it"
        )));
    }
    Ok(trimmed.to_string())
}

async fn revoke_consent(
    OrgAuth(org_id): OrgAuth,
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(body): Json<RevokeConsentBody>,
) -> ApiResult<Json<ConsentResponse>> {
    let reason = revocation_reason(&body.revocation_reason)?;

    // Scoped by `org_id` in the WHERE clause on the way in below, not
    // fetched-then-checked — same reasoning as every other org-scoped
    // lookup in this codebase: another tenant's grant is indistinguishable
    // from one that does not exist. This existence check runs first only to
    // give a plain 404 rather than a 404-shaped 409; the transactional
    // UPDATE below is the actual authority.
    let existing = sqlx::query!(
        "select revoked_at from consent_grants where id = $1 and org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    if existing.revoked_at.is_some() {
        // Revoking twice is a 409, not a silent success — unlike
        // `disclosure::revoke_disclosure_request`'s idempotent no-op, and
        // deliberately so. A disclosure request's revoke exists to stop a
        // pending proof from being answered; calling it twice changes
        // nothing about the world. A consent revocation is itself a fact an
        // examiner reads — WHEN, and WHY — and a second call carrying a
        // second, possibly different reason must not be swallowed into the
        // first silently. The database enforces the same rule one layer
        // down (`consent_grants_revocation_is_final`, migrations/0011); this
        // is the answer a caller gets without a connection string.
        return Err(ApiError::Conflict(format!(
            "consent grant {id} was already revoked at {}; revocation is recorded once and \
             never overwritten",
            existing
                .revoked_at
                .expect("checked is_some above")
                .to_rfc3339()
        )));
    }

    let mut tx = state.db.begin().await?;

    let updated = sqlx::query_as!(
        ConsentGrantRow,
        r#"
        update consent_grants set revoked_at = now(), revocation_reason = $2
        where id = $1 and org_id = $3 and revoked_at is null
        returning id, org_id, user_id, scope, consent_version, purpose_hash, granted_at,
                  granted_via, revoked_at, revocation_reason, created_at
        "#,
        id,
        reason,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    // Lost a race with a concurrent revoke between the check above and this
    // UPDATE. The pre-check gave a friendly early exit; this WHERE clause is
    // the actual guard, and losing it reports the same 409 rather than a
    // silent success — the same shape `disclosure::revoke_disclosure_
    // request` uses for its own race, with the opposite idempotency
    // decision for the reason given above.
    let Some(updated) = updated else {
        return Err(ApiError::Conflict(format!(
            "consent grant {id} was already revoked; revocation is recorded once and never \
             overwritten"
        )));
    };

    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "consent_revoked",
        Some(id),
        serde_json::json!({
            "user_id": updated.user_id,
            "revocation_reason": reason,
        }),
    )
    .await?;

    crate::audit::binding::record_consent_revocation_binding(&mut tx, org_id, id).await?;

    tx.commit().await?;

    Ok(Json(updated.into_response()?))
}

// ---------------------------------------------------------------------
// GET /api/v1/consents/:id
// ---------------------------------------------------------------------

async fn get_consent(
    OrgAuth(org_id): OrgAuth,
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<ConsentResponse>> {
    let row = sqlx::query_as!(
        ConsentGrantRow,
        r#"
        select id, org_id, user_id, scope, consent_version, purpose_hash, granted_at,
               granted_via, revoked_at, revocation_reason, created_at
        from consent_grants
        where id = $1 and org_id = $2
        "#,
        id,
        org_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(row.into_response()?))
}

// ---------------------------------------------------------------------
// GET /api/v1/consents?user_id=...
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct ListQuery {
    user_id: Uuid,
}

/// This org's consent history for one user — every grant, revoked or not,
/// newest first. Not filtered to unrevoked-only: a bank asking "what has
/// this customer ever agreed to and withdrawn" is the more common question
/// an examiner has, and `revoked_at`/`revocation_reason` on each row already
/// answer it without a second endpoint.
async fn list_consents(
    OrgAuth(org_id): OrgAuth,
    Query(query): Query<ListQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ConsentResponse>>> {
    let rows = sqlx::query_as!(
        ConsentGrantRow,
        r#"
        select id, org_id, user_id, scope, consent_version, purpose_hash, granted_at,
               granted_via, revoked_at, revocation_reason, created_at
        from consent_grants
        where org_id = $1 and user_id = $2
        order by granted_at desc
        "#,
        org_id,
        query.user_id,
    )
    .fetch_all(&state.db)
    .await?;

    rows.into_iter().map(ConsentGrantRow::into_response).collect::<ApiResult<Vec<_>>>().map(Json)
}

// ---------------------------------------------------------------------
// Enforcement: the one question `issue_wealth_request` asks this module.
// ---------------------------------------------------------------------

/// Find the grant that authorises a decision for `purpose`, or refuse.
///
/// `purpose` is matched against `scope` by jsonb containment
/// (`scope @> to_jsonb(purpose)`) — Postgres's own rule for "this array
/// contains this scalar element" — rather than by fetching every grant and
/// comparing in Rust, so the definition of "covers" lives in exactly one
/// place: the query, which `wealth/mod.rs` and any future caller share by
/// construction rather than by convention.
///
/// Returns the covering grant's id on success. On refusal the message names
/// what happened: no grant naming this purpose exists at all, or the most
/// recent one that did was revoked (named, with when) — never a bare
/// "forbidden" that leaves an integrator unable to tell the two apart. Only
/// facts inside the caller's own tenant are ever named.
pub async fn require_covering_grant(
    db: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    purpose: &str,
) -> ApiResult<Uuid> {
    let candidates = sqlx::query!(
        r#"
        select id, revoked_at, revocation_reason
        from consent_grants
        where org_id = $1 and user_id = $2 and scope @> to_jsonb($3::text)
        order by granted_at desc
        "#,
        org_id,
        user_id,
        purpose,
    )
    .fetch_all(db)
    .await?;

    if let Some(live) = candidates.iter().find(|c| c.revoked_at.is_none()) {
        return Ok(live.id);
    }

    match candidates.first() {
        Some(most_recent) => Err(ApiError::ForbiddenDetail(format!(
            "no unrevoked consent grant covers purpose '{purpose}' for this user. The most \
             recent grant that did, {}, was revoked at {}{}. Grant a new one with \
             POST /api/v1/consents before opening this decision",
            most_recent.id,
            most_recent
                .revoked_at
                .expect("filtered to revoked-only above")
                .to_rfc3339(),
            most_recent
                .revocation_reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default(),
        ))),
        None => Err(ApiError::ForbiddenDetail(format!(
            "no consent grant on file for this user covers purpose '{purpose}'. Grant one with \
             POST /api/v1/consents before opening this decision"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_refuses_empty_non_array_and_non_string_elements() {
        assert!(parse_scope(&serde_json::json!(["wealth.suitability_recommendation"])).is_ok());

        for bad in [
            serde_json::json!([]),
            serde_json::json!("not-an-array"),
            serde_json::json!(["ok", 1.5]),
            serde_json::json!(["ok", ""]),
            serde_json::json!(["ok", "   "]),
            serde_json::json!(null),
        ] {
            assert!(parse_scope(&bad).is_err(), "{bad} must be refused");
        }
    }

    /// Trap 1: non-ASCII scope strings are the target market, not an edge
    /// case, and must parse exactly like any other string.
    #[test]
    fn parse_scope_accepts_french_and_arabic_purpose_strings() {
        let scope = parse_scope(&serde_json::json!([
            "évaluation.pertinence_patrimoniale",
            "تقييم_الملاءمة_المالية",
        ]))
        .unwrap();
        assert_eq!(scope, vec!["évaluation.pertinence_patrimoniale", "تقييم_الملاءمة_المالية"]);
    }

    #[test]
    fn parse_purpose_hash_accepts_only_a_64_char_hex_digest() {
        let good = "ab".repeat(32);
        assert_eq!(parse_purpose_hash(&good.to_uppercase()).unwrap(), good);
        assert!(parse_purpose_hash("not-a-digest").is_err());
        assert!(parse_purpose_hash(&"a".repeat(63)).is_err());
        assert!(parse_purpose_hash(&"g".repeat(64)).is_err());
    }

    #[test]
    fn revocation_reason_has_a_floor_and_it_is_the_documented_one() {
        for weak in ["", "  ", "n/a", "no"] {
            assert!(revocation_reason(weak).is_err(), "{weak:?}");
        }
        assert!(revocation_reason("customer withdrew consent at branch counter").is_ok());
        // The floor matches migrations/0011's CHECK constraint exactly, so
        // the API and the row-level rule cannot drift into refusing
        // different things — the asymmetry trap #5 warns about.
        assert_eq!(MIN_REVOCATION_REASON_CHARS, 10);
    }
}
