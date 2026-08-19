// POST /api/v1/wealth-assessments/:request_id/review — the per-decision
// human review gate.
//
// -------------------------------------------------------------------
// WHAT DID NOT EXIST BEFORE THIS FILE
// -------------------------------------------------------------------
// The only governance-shaped field in the codebase was
// `products.approved_by_risk_committee`, which approves a *catalogue entry*.
// A product being cleared for sale is not a human having looked at one
// client's recommendation, and the adversarial suite's "bypass human review"
// attack could not even be run: there was no review action to bypass.
//
// -------------------------------------------------------------------
// A DECLINE PRODUCES THE SAME SIGNED EVIDENCE AS AN APPROVAL
// -------------------------------------------------------------------
// This is a commitment already made in writing to the pilot buyer, and it is
// the reason this endpoint returns the full `DecisionEvidence` record rather
// than an acknowledgement. There is no `if rejected` below and no second
// response shape: `action` is an input, the record is built by one call to
// one constructor, and `decline_and_approval_produce_identical_key_sets`
// asserts it through this handler rather than at the type level — because
// the type-level guarantee says nothing about a handler that takes an early
// return on one branch.
//
// The stakes are specific. The seal is a SHA-256 over canonical bytes. A key
// that appears only on the approval path changes the byte layout of every
// decline, which makes "this record was tampered with" and "this client was
// declined" look alike to anyone recomputing a digest.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::evidence::{DecisionAction, ReviewOverride};
use crate::orgs::OrgAuth;
use crate::state::AppState;

use super::evidence::{build_decision_evidence, respond, DecisionEvidenceResponse};

/// How far ahead of the server's clock a claimed `reviewed_at` may sit.
/// Generous enough for ordinary clock skew on a bank desktop, tight enough
/// that "reviewed at" cannot be a date in next quarter.
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBody {
    /// The firm's own identifier for the reviewer. Text, not a foreign key:
    /// Memtara has no directory of a bank's staff, and inventing one would
    /// be a worse claim than quoting theirs. The org asserts this under its
    /// API key and the audit event records that it did.
    pub reviewer_id: String,
    /// The role they were acting in. Required and separate from the
    /// identifier, because "who" and "with what authority" are different
    /// questions and a supervisor reviewing a concentration override asks
    /// the second one first.
    pub reviewer_role: String,
    /// `approved` | `rejected` | `modified`. Required on every branch.
    pub action: String,
    /// Which revision of the firm's own review procedure the reviewer
    /// worked under.
    pub human_review_protocol_version: String,

    /// Whether the reviewer went against the control's verdict.
    ///
    /// Defaults to `false`, and the default is safe because the server
    /// checks it: an action that contradicts the cryptographic verdict with
    /// `override: false` is refused, so a reviewer cannot quietly override
    /// by leaving the flag alone.
    #[serde(default, rename = "override")]
    pub overridden: bool,
    #[serde(default)]
    pub override_reason: Option<String>,

    /// When the human decided. Defaults to the server's clock. Accepted
    /// because a review that happened on a desk five minutes ago is a
    /// legitimate submission, and bounded because "reviewed at" is not a
    /// free-text field.
    #[serde(default)]
    pub reviewed_at: Option<DateTime<Utc>>,

    // ---------------------------------------------------------------
    // The Cigna pair. Two ways in, one meaning out, and the source is
    // always recorded alongside the number — see the module note on
    // `decision_reviews.review_duration_source` in migrations/0006.
    // ---------------------------------------------------------------
    /// The reviewing client timed itself and is telling us.
    #[serde(default)]
    pub review_duration_ms: Option<i64>,
    /// When the reviewer opened the case. The server subtracts it from its
    /// own receipt time, which makes at least the end of the interval ours.
    #[serde(default)]
    pub review_started_at: Option<DateTime<Utc>>,
}

fn required(field: &str, value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_string())
}

fn parse_action(raw: &str) -> ApiResult<DecisionAction> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "approved" => Ok(DecisionAction::Approved),
        "rejected" => Ok(DecisionAction::Rejected),
        "modified" => Ok(DecisionAction::Modified),
        other => Err(ApiError::BadRequest(format!(
            "action must be one of approved, rejected, modified (got {other:?}). There is no \
             fourth value and no 'pending': a review record is written about a verdict a human \
             reached, and a review still in progress is the absence of a record, not a record \
             saying nothing"
        ))),
    }
}

fn action_str(a: DecisionAction) -> &'static str {
    match a {
        DecisionAction::Approved => "approved",
        DecisionAction::Rejected => "rejected",
        DecisionAction::Modified => "modified",
    }
}

/// The duration and where it came from, or neither.
///
/// Never one without the other. A duration whose provenance is unstated is
/// admissible as neither an asserted number nor a measured one, which is why
/// this returns a single `Option` of a pair rather than two independent
/// `Option`s that a later edit could separate.
fn resolve_duration(
    body: &ReviewBody,
    server_received_at: DateTime<Utc>,
) -> ApiResult<Option<(i64, &'static str)>> {
    if let Some(ms) = body.review_duration_ms {
        if ms < 0 {
            return Err(ApiError::BadRequest(
                "review_duration_ms must not be negative".into(),
            ));
        }
        if body.review_started_at.is_some() {
            return Err(ApiError::BadRequest(
                "supply review_duration_ms or review_started_at, not both. They have different \
                 provenance — one is asserted by the reviewing client, the other is computed \
                 here from a declared start — and a record that carried both would have to \
                 choose which one review_duration_source names"
                    .into(),
            ));
        }
        return Ok(Some((ms, "reviewer_client_asserted")));
    }

    let Some(started) = body.review_started_at else {
        return Ok(None);
    };
    // Deliberately measured to the server's receipt time, not to the
    // caller's `reviewed_at`. Both ends being caller-supplied would make the
    // whole interval caller-chosen; this way the end of it is ours, and the
    // result is an upper bound on the real duration rather than an arbitrary
    // number. `review_duration_source` says exactly this, so nobody reads it
    // as an independent measurement — the start is still theirs.
    let elapsed = server_received_at - started;
    if elapsed < Duration::zero() {
        return Err(ApiError::BadRequest(
            "review_started_at is in the future".into(),
        ));
    }
    Ok(Some((
        elapsed.num_milliseconds(),
        "server_computed_from_declared_start",
    )))
}

pub(super) async fn record_review(
    db: &PgPool,
    vkeys_dir: &str,
    org_id: Uuid,
    request_id: Uuid,
    body: ReviewBody,
) -> ApiResult<DecisionEvidenceResponse> {
    let reviewer_id = required("reviewer_id", &body.reviewer_id)?;
    let reviewer_role = required("reviewer_role", &body.reviewer_role)?;
    let protocol_version =
        required("human_review_protocol_version", &body.human_review_protocol_version)?;
    let action = parse_action(&body.action)?;

    // The override pairing, at the type level. `ReviewOverride::overridden`
    // is the only constructor for the overridden case and it consumes a
    // reason, so there is no route through this function to `override: true`
    // with nothing behind it. The CHECK constraint in migrations/0006 says
    // the same thing to anyone who writes to the table directly.
    let over_ride = match (body.overridden, body.override_reason.as_deref()) {
        (false, None) => ReviewOverride::NotOverridden,
        (false, Some(_)) => {
            return Err(ApiError::BadRequest(
                "override_reason was supplied without override: true. The field means 'why this \
                 reviewer went against the control', so a reason attached to a non-override is a \
                 different fact wearing this field's name. If the intent was to record why the \
                 reviewer agreed, that is not this field"
                    .into(),
            ))
        }
        (true, reason) => ReviewOverride::overridden(reason.unwrap_or_default())
            .map_err(|e| ApiError::BadRequest(e.to_string()))?,
    };

    // The verdict this review is about. Scoped by `org_id` in the WHERE
    // clause: another tenant's assessment is indistinguishable from one that
    // does not exist.
    let assessment = sqlx::query!(
        r#"
        select w.suitable, w.assessed_at, w.product_isin, d.user_id
        from wealth_requests w
        join disclosure_requests d on d.id = w.request_id
        where w.request_id = $1 and d.org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(db)
    .await?
    .ok_or(ApiError::NotFound)?;

    let (Some(suitable), Some(assessed_at)) = (assessment.suitable, assessment.assessed_at) else {
        // Reviewing a decision that has not been made is not evidence of
        // review. The continuity mode where the proof service is down and a
        // human decides anyway ("human-only, proof unavailable") is a real
        // and named state — `DecisionBasis::HumanOnlyProofUnavailable` —
        // that this system cannot produce today, and accepting a review here
        // would manufacture it without anyone having built it.
        return Err(ApiError::Conflict(
            "this assessment has no verdict yet, so there is nothing for a human to review. \
             A review recorded against an undecided assessment would evidence a control that \
             did not run"
                .into(),
        ));
    };

    let server_received_at = Utc::now();
    let reviewed_at = body.reviewed_at.unwrap_or(server_received_at);
    if reviewed_at > server_received_at + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) {
        return Err(ApiError::BadRequest(
            "reviewed_at is in the future".into(),
        ));
    }
    if reviewed_at < assessed_at {
        return Err(ApiError::BadRequest(format!(
            "reviewed_at ({reviewed_at}) precedes the assessment it reviews ({assessed_at}); a \
             review cannot have happened before the verdict it is about"
        )));
    }

    // -----------------------------------------------------------------
    // The override consistency check.
    //
    // Without this, `override` is a self-assessment: a reviewer who
    // approves a client the circuit found unsuitable and leaves the flag
    // false produces a record that reads as routine concurrence. The server
    // knows the verdict, so it can tell.
    //
    // `Modified` is deliberately exempt. A modified recommendation is a
    // change to what was recommended, not a contradiction of whether the
    // client cleared the thresholds, and forcing it to declare an override
    // would either train reviewers to tick the box or push them towards
    // `approved`.
    // -----------------------------------------------------------------
    let contradicts = match action {
        DecisionAction::Approved => !suitable,
        DecisionAction::Rejected => suitable,
        DecisionAction::Modified => false,
    };
    if contradicts && !body.overridden {
        return Err(ApiError::BadRequest(format!(
            "this review records '{}' against a cryptographic verdict of suitable={suitable}, \
             which is an override of the control. Set override: true and state why. A reviewer \
             who can contradict the control without declaring it turns the override flag into a \
             self-assessment, and the flag is the field a supervisor searches on",
            action_str(action),
        )));
    }

    let duration = resolve_duration(&body, server_received_at)?;

    let mut tx = db.begin().await?;

    // `on conflict do nothing` rather than an upsert, and the reason is
    // immutability rather than caution: `DecisionEvidence.human_review` is a
    // single block inside bytes that get sealed, so "which review does the
    // sealed record describe" must have exactly one answer. A second review
    // overwriting the first would silently change what an already-exported
    // record said. Escalation — a junior's verdict superseded by a senior's
    // — is a real workflow this deliberately does not model yet.
    let inserted = sqlx::query_scalar!(
        r#"
        insert into decision_reviews (
            request_id, org_id, reviewer_id, reviewer_role, action,
            "override", override_reason, review_duration_ms, review_duration_source,
            human_review_protocol_version, reviewed_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        on conflict (request_id) do nothing
        returning request_id
        "#,
        request_id,
        org_id,
        reviewer_id,
        reviewer_role,
        action_str(action),
        matches!(over_ride, ReviewOverride::Overridden { .. }),
        match &over_ride {
            ReviewOverride::NotOverridden => None,
            ReviewOverride::Overridden { reason } => Some(reason.clone()),
        },
        duration.map(|(ms, _)| ms),
        duration.map(|(_, source)| source),
        protocol_version,
        reviewed_at,
    )
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        return Err(ApiError::Conflict(
            "this decision has already been reviewed. A decision carries one review, because the \
             evidence record carries one human_review block and it is sealed: a second review \
             would change what an already-exported record said"
                .into(),
        ));
    }

    // Same transaction as the insert. A review that exists without the
    // chain entry that created it is the gap this table is meant to close,
    // not one it should open. The duration goes into the hashed payload as
    // well as the column — the chain is the evidence and the table is the
    // index (migrations/0005) — so the number a compliance function later
    // queries is one nobody could have edited afterwards.
    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "decision_human_reviewed",
        Some(request_id),
        serde_json::json!({
            "user_id": assessment.user_id,
            "product_isin": assessment.product_isin,
            "reviewer_id": reviewer_id,
            "reviewer_role": reviewer_role,
            "action": action_str(action),
            "override": matches!(over_ride, ReviewOverride::Overridden { .. }),
            "override_reason": match &over_ride {
                ReviewOverride::NotOverridden => None,
                ReviewOverride::Overridden { reason } => Some(reason.clone()),
            },
            "cryptographic_verdict_suitable": suitable,
            "contradicts_cryptographic_verdict": contradicts,
            "review_duration_ms": duration.map(|(ms, _)| ms),
            "review_duration_source": duration.map(|(_, source)| source),
            "human_review_protocol_version": protocol_version,
            "reviewed_at": reviewed_at,
            // The server's own observation, beside the reviewer's claim. A
            // batch of reviews all claiming to be hours apart while arriving
            // in the same second is visible from these two alone, without
            // trusting either clock.
            "received_at": server_received_at,
            "dfsa_rules": ["COB 3.1"],
        }),
    )
    .await?;

    tx.commit().await?;

    // One builder, one shape, whatever the verdict was. The record is
    // returned rather than an acknowledgement precisely so that a decline
    // and an approval can be compared as bytes by anyone who doubts they are
    // the same — including the test at the bottom of this file.
    let record = build_decision_evidence(db, vkeys_dir, org_id, request_id).await?;
    respond(record)
}

pub(super) async fn submit_review(
    OrgAuth(org_id): OrgAuth,
    Path(request_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(body): Json<ReviewBody>,
) -> ApiResult<(StatusCode, Json<DecisionEvidenceResponse>)> {
    let response =
        record_review(&state.db, &state.config.vkeys_dir, org_id, request_id, body).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session_token::hash_token;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeSet;

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
        PgPoolOptions::new().max_connections(5).connect(&url).await.ok()
    }

    /// A vkeys directory that deliberately does not exist.
    ///
    /// The verification-key digest is then absent on every branch, which is
    /// the point: the key-set comparison below must be testing the record's
    /// shape, not whether a build artefact happened to be on disk. A path
    /// that existed on one machine and not another would make this test
    /// pass or fail for a reason that has nothing to do with the invariant.
    const NO_VKEYS: &str = "/nonexistent/vkeys-for-review-tests";

    async fn make_org(db: &PgPool) -> Uuid {
        sqlx::query_scalar!(
            "insert into organizations (name, org_type, api_key_hash) values ($1, 'bank', $2) \
             returning id",
            format!("Review Test Bank {}", Uuid::new_v4()),
            hash_token(&crate::orgs::generate_api_key()),
        )
        .fetch_one(db)
        .await
        .expect("insert test org")
    }

    async fn make_user(db: &PgPool) -> Uuid {
        sqlx::query_scalar!(
            "insert into users (phone_e164) values ($1) returning id",
            format!("+9715{:08}", rand::random::<u32>() % 100_000_000),
        )
        .fetch_one(db)
        .await
        .expect("insert test user")
    }

    /// One assessed wealth request, with a known verdict.
    ///
    /// Built by inserting rows rather than by driving the HTTP endpoints,
    /// because what is under test is the review path and the record it
    /// produces — standing up a real proof would make this a `bb`
    /// integration test that skips on any machine without the toolchain,
    /// and the invariant it protects is not about proofs.
    async fn make_assessed_request(db: &PgPool, org_id: Uuid, user_id: Uuid, suitable: bool) -> Uuid {
        let product_id = sqlx::query_scalar!(
            r#"
            insert into products (org_id, product_isin, product_name, risk_level,
                                  min_income, min_liquidity, max_concentration_percent)
            values ($1, $2, 'Test Note', 3, 500000, 1000000, 30)
            returning id
            "#,
            org_id,
            format!("XS{:010}", rand::random::<u32>() % 1_000_000_000),
        )
        .fetch_one(db)
        .await
        .expect("insert product");

        let request_id = sqlx::query_scalar!(
            r#"
            insert into disclosure_requests (org_id, user_id, circuit_type, policy, status,
                                             nonce, expires_at)
            values ($1, $2, 'wealth_suitability', '{}'::jsonb, 'pending', $3, now() + interval '1 hour')
            returning id
            "#,
            org_id,
            user_id,
            // Unique per org: `disclosure_requests_org_nonce_idx` enforces
            // it, and these tests deliberately open several assessments for
            // one org.
            Uuid::new_v4().as_bytes().repeat(2),
        )
        .fetch_one(db)
        .await
        .expect("insert disclosure request");

        sqlx::query!(
            r#"
            insert into wealth_requests (
                request_id, product_id, product_isin, product_name, product_ref,
                min_income, min_liquidity, max_concentration_percent, product_risk_level,
                window_start, window_end, terms_version, suitable, assessed_at, vault_root
            )
            values ($1, $2, 'XS0000000000', 'Test Note', $3, 500000, 1000000, 30, 3,
                    now() - interval '10 minutes', now() + interval '1 hour', 1, $4,
                    now() - interval '5 minutes', $5)
            "#,
            request_id,
            product_id,
            vec![9u8; 32],
            suitable,
            vec![4u8; 32],
        )
        .execute(db)
        .await
        .expect("insert wealth request");

        sqlx::query!(
            r#"
            insert into decision_model_attestations (request_id, org_id, declaration,
                                                     unidentified_reason)
            values ($1, $2, 'participated_but_unidentified', $3)
            "#,
            request_id,
            org_id,
            "the calling system supplied no declaration on this test fixture",
        )
        .execute(db)
        .await
        .expect("insert attestation");

        request_id
    }

    async fn cleanup(db: &PgPool, org_id: Uuid, user_id: Uuid) {
        let _ = sqlx::query!(
            "delete from audit_log where org_id = $1 or ref_id in \
             (select id from disclosure_requests where org_id = $1)",
            org_id
        )
        .execute(db)
        .await;
        let _ = sqlx::query!("delete from disclosure_requests where org_id = $1", org_id)
            .execute(db)
            .await;
        let _ = sqlx::query!("delete from products where org_id = $1", org_id).execute(db).await;
        let _ = sqlx::query!("delete from organizations where id = $1", org_id).execute(db).await;
        let _ = sqlx::query!("delete from users where id = $1", user_id).execute(db).await;
    }

    fn body(action: &str) -> ReviewBody {
        ReviewBody {
            reviewer_id: "emp-4417".into(),
            reviewer_role: "senior_suitability_officer".into(),
            action: action.into(),
            human_review_protocol_version: "cob-review-2026.2".into(),
            overridden: false,
            override_reason: None,
            reviewed_at: None,
            review_duration_ms: Some(214_000),
            review_started_at: None,
        }
    }

    /// Every key path in a value, arrays flattened, so two records with
    /// different array lengths still compare structurally. Same walk as
    /// `evidence::tests::key_paths`, duplicated rather than made public:
    /// this test must not be able to pass because it shares a helper with
    /// the thing it is checking.
    fn key_paths(value: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let path = format!("{prefix}.{k}");
                    out.insert(path.clone());
                    key_paths(v, &path, out);
                }
            }
            serde_json::Value::Array(items) => {
                let path = format!("{prefix}[]");
                for v in items {
                    key_paths(v, &path, out);
                }
            }
            _ => {}
        }
    }

    fn paths_of(v: &serde_json::Value) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        key_paths(v, "", &mut out);
        out
    }

    // -----------------------------------------------------------------
    // The commitment made in writing to the pilot buyer.
    // -----------------------------------------------------------------

    /// A decline produces the same signed evidence as an approval —
    /// asserted through this endpoint, against a real database, not at the
    /// type level.
    ///
    /// The type-level test in `evidence/mod.rs` proves the *struct* cannot
    /// change shape. It says nothing about a handler that takes an early
    /// return on one branch, skips a table on a decline, or returns a
    /// different response type when the answer is no — which is where this
    /// defect actually lives in every system that has it.
    ///
    /// What this catches: a `if action == Rejected { return ... }` added
    /// here; a decline that skips the `decision_reviews` insert; a nullable
    /// field that stops being written on one branch; a response wrapper that
    /// differs by outcome. Any of those changes the canonical bytes for a
    /// reason unrelated to tampering, and makes a declined client's record
    /// look altered to anyone recomputing the seal.
    #[tokio::test]
    async fn decline_and_approval_produce_identical_key_sets_through_the_endpoint() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;

        // Two decisions that differ only in their verdict, each reviewed by
        // a human who concurred with it.
        let approved_id = make_assessed_request(&db, org_id, user_id, true).await;
        let declined_id = make_assessed_request(&db, org_id, user_id, false).await;

        let approved = record_review(&db, NO_VKEYS, org_id, approved_id, body("approved"))
            .await
            .expect("an approval is recorded");
        let declined = record_review(&db, NO_VKEYS, org_id, declined_id, body("rejected"))
            .await
            .expect("a decline is recorded, through the same path, with no special casing");

        let a = serde_json::to_value(&approved.decision_evidence).unwrap();
        let d = serde_json::to_value(&declined.decision_evidence).unwrap();

        let ap = paths_of(&a);
        let dp = paths_of(&d);
        let only_approved: Vec<_> = ap.difference(&dp).collect();
        let only_declined: Vec<_> = dp.difference(&ap).collect();
        assert!(
            only_approved.is_empty() && only_declined.is_empty(),
            "a decline must produce the same key set as an approval. \
             only in approval: {only_approved:?}; only in decline: {only_declined:?}"
        );

        // And the two are genuinely different records — otherwise this test
        // would pass just as happily against two copies of one decision.
        assert_eq!(
            a.pointer("/decision/final_decision/outcome").and_then(|v| v.as_str()),
            Some("affirmative")
        );
        assert_eq!(
            d.pointer("/decision/final_decision/outcome").and_then(|v| v.as_str()),
            Some("negative")
        );
        assert_eq!(
            d.pointer("/human_review/action").and_then(|v| v.as_str()),
            Some("rejected")
        );
        assert_ne!(
            approved.canonical_evidence_sha256,
            declined.canonical_evidence_sha256
        );

        // Both are fully-formed records, not a stub on the decline branch:
        // the human review is present, populated and identical in shape.
        for v in [&a, &d] {
            assert_eq!(v.pointer("/human_review/performed"), Some(&serde_json::Value::Bool(true)));
            assert_eq!(
                v.pointer("/human_review/reviewer_id/value").and_then(|x| x.as_str()),
                Some("emp-4417")
            );
            assert_eq!(
                v.pointer("/human_review/review_duration_ms/value").and_then(|x| x.as_i64()),
                Some(214_000)
            );
        }

        cleanup(&db, org_id, user_id).await;
    }

    /// An override with no reason is refused by the endpoint, and a
    /// reviewer cannot override without saying they did.
    ///
    /// Three refusals, because there are three ways to get an unexplained
    /// override past a naive handler: declare it and give no reason, declare
    /// it and give a token one, or contradict the verdict while leaving the
    /// flag alone.
    #[tokio::test]
    async fn an_unexplained_or_undeclared_override_is_refused() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        // A decision the circuit found UNSUITABLE. Approving it is an
        // override of the control.
        let request_id = make_assessed_request(&db, org_id, user_id, false).await;

        // (a) override declared, no reason.
        let mut b = body("approved");
        b.overridden = true;
        let err = record_review(&db, NO_VKEYS, org_id, request_id, b).await.unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "{err:?}");

        // (b) override declared, token reason.
        let mut b = body("approved");
        b.overridden = true;
        b.override_reason = Some("n/a".into());
        let err = record_review(&db, NO_VKEYS, org_id, request_id, b).await.unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "{err:?}");

        // (c) The quiet one: contradict the verdict and leave the flag
        //     false. Without the server-side check this reads as routine
        //     concurrence, and the override flag becomes a self-assessment.
        let err = record_review(&db, NO_VKEYS, org_id, request_id, body("approved"))
            .await
            .unwrap_err();
        match &err {
            ApiError::BadRequest(m) => assert!(m.contains("override"), "{m}"),
            other => panic!("expected a refusal naming the override, got {other:?}"),
        }

        // Nothing was written by any of the three.
        let count = sqlx::query_scalar!(
            r#"select count(*) as "c!" from decision_reviews where request_id = $1"#,
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 0, "a refused review must not leave a row behind");

        // (d) The same override, declared and explained, is accepted — so
        //     the check is a gate and not a wall.
        let mut good = body("approved");
        good.overridden = true;
        good.override_reason =
            Some("documented liquidity event post-dates the vault snapshot; evidence on file \
                  under case 2026-0841"
                .into());
        let ok = record_review(&db, NO_VKEYS, org_id, request_id, good).await.unwrap();
        let v = serde_json::to_value(&ok.decision_evidence).unwrap();
        assert_eq!(v.pointer("/human_review/override"), Some(&serde_json::Value::Bool(true)));
        // The basis names the override. This is the variant a supervisor
        // greps for, and it is derived, never assigned.
        assert_eq!(
            v.pointer("/decision/final_decision/decision_basis/value").and_then(|x| x.as_str()),
            Some("proof_and_human_override")
        );

        cleanup(&db, org_id, user_id).await;
    }

    /// A decision carries exactly one review, and an unreviewed decision
    /// carries no reviewer's judgement.
    #[tokio::test]
    async fn a_decision_carries_one_review_and_an_unreviewed_one_says_so() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_assessed_request(&db, org_id, user_id, true).await;

        // Before any review: performed is false, and every reviewer field
        // asserts non-applicability rather than admitting ignorance.
        let before =
            crate::wealth::evidence::build_decision_evidence(&db, NO_VKEYS, org_id, request_id)
                .await
                .unwrap();
        let bv = serde_json::to_value(&before).unwrap();
        assert_eq!(bv.pointer("/human_review/performed"), Some(&serde_json::Value::Bool(false)));
        assert_eq!(
            bv.pointer("/human_review/reviewer_id/state").and_then(|x| x.as_str()),
            Some("not_applicable")
        );
        assert_eq!(
            bv.pointer("/decision/final_decision/decision_basis/value").and_then(|x| x.as_str()),
            Some("proof_only")
        );

        record_review(&db, NO_VKEYS, org_id, request_id, body("approved")).await.unwrap();

        // A second review is refused rather than overwriting the first: the
        // record is sealed, and a silent overwrite would change what an
        // already-exported record said. Deliberately a *valid* second
        // review — same action, different reviewer — so the refusal is the
        // one-review rule and not some other validation firing first.
        let mut second = body("approved");
        second.reviewer_id = "emp-9002".into();
        let err = record_review(&db, NO_VKEYS, org_id, request_id, second).await.unwrap_err();
        assert!(matches!(err, ApiError::Conflict(_)), "{err:?}");

        let stored = sqlx::query_scalar!(
            "select reviewer_id from decision_reviews where request_id = $1",
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(stored, "emp-4417", "the first review must survive the second attempt");

        cleanup(&db, org_id, user_id).await;
    }

    /// The Cigna field, end to end: a duration is recorded with its source,
    /// and the two ways of supplying one produce different, honestly-named
    /// provenance.
    #[tokio::test]
    async fn review_duration_is_captured_with_its_provenance() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;

        // (a) Client-asserted. The 1.2-second review: accepted, recorded,
        //     and visibly labelled as the client's own claim.
        let fast = make_assessed_request(&db, org_id, user_id, true).await;
        let mut b = body("approved");
        b.review_duration_ms = Some(1_200);
        let r = record_review(&db, NO_VKEYS, org_id, fast, b).await.unwrap();
        let v = serde_json::to_value(&r.decision_evidence).unwrap();
        assert_eq!(
            v.pointer("/human_review/review_duration_ms/value").and_then(|x| x.as_i64()),
            Some(1_200)
        );
        assert_eq!(
            v.pointer("/human_review/review_duration_source/value").and_then(|x| x.as_str()),
            Some("reviewer_client_asserted"),
            "a client-timed duration must not be presentable as a measurement"
        );

        // (b) Server-computed from a declared start.
        let timed = make_assessed_request(&db, org_id, user_id, true).await;
        let mut b = body("approved");
        b.review_duration_ms = None;
        b.review_started_at = Some(Utc::now() - Duration::seconds(90));
        let r = record_review(&db, NO_VKEYS, org_id, timed, b).await.unwrap();
        let v = serde_json::to_value(&r.decision_evidence).unwrap();
        assert_eq!(
            v.pointer("/human_review/review_duration_source/value").and_then(|x| x.as_str()),
            Some("server_computed_from_declared_start")
        );
        let ms = v
            .pointer("/human_review/review_duration_ms/value")
            .and_then(|x| x.as_i64())
            .unwrap();
        assert!((89_000..95_000).contains(&ms), "expected ~90s, got {ms}ms");

        // (c) Neither: both fields unpopulated, both naming what would fill
        //     them. Never a recorded number with a blank source.
        let untimed = make_assessed_request(&db, org_id, user_id, true).await;
        let mut b = body("approved");
        b.review_duration_ms = None;
        let r = record_review(&db, NO_VKEYS, org_id, untimed, b).await.unwrap();
        let v = serde_json::to_value(&r.decision_evidence).unwrap();
        for f in ["review_duration_ms", "review_duration_source"] {
            assert_eq!(
                v.pointer(&format!("/human_review/{f}/state")).and_then(|x| x.as_str()),
                Some("unpopulated"),
                "{f}"
            );
        }

        // (d) Both at once is refused: they have different provenance and
        //     the record has one `review_duration_source` to name.
        let both = make_assessed_request(&db, org_id, user_id, true).await;
        let mut b = body("approved");
        b.review_started_at = Some(Utc::now() - Duration::seconds(5));
        assert!(record_review(&db, NO_VKEYS, org_id, both, b).await.is_err());

        cleanup(&db, org_id, user_id).await;
    }

    /// A review cannot be recorded against a decision that has not been
    /// made, and cannot be backdated to before the verdict it reviews.
    #[tokio::test]
    async fn a_review_cannot_precede_the_decision_it_reviews() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_assessed_request(&db, org_id, user_id, true).await;

        let mut b = body("approved");
        b.reviewed_at = Some(Utc::now() - Duration::hours(2));
        let err = record_review(&db, NO_VKEYS, org_id, request_id, b).await.unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "{err:?}");

        let mut b = body("approved");
        b.reviewed_at = Some(Utc::now() + Duration::hours(2));
        assert!(record_review(&db, NO_VKEYS, org_id, request_id, b).await.is_err());

        // An undecided assessment has nothing to review.
        sqlx::query!(
            "update wealth_requests set suitable = null, assessed_at = null where request_id = $1",
            request_id
        )
        .execute(&db)
        .await
        .unwrap();
        let err = record_review(&db, NO_VKEYS, org_id, request_id, body("approved"))
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Conflict(_)), "{err:?}");

        cleanup(&db, org_id, user_id).await;
    }

    /// Another tenant's decision is not reviewable, and is indistinguishable
    /// from one that does not exist.
    #[tokio::test]
    async fn a_review_cannot_reach_another_tenants_decision() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let other_org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_assessed_request(&db, org_id, user_id, true).await;

        let err = record_review(&db, NO_VKEYS, other_org_id, request_id, body("approved"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::NotFound),
            "a competitor's assessment must be indistinguishable from one that does not exist, \
             got {err:?}"
        );

        cleanup(&db, org_id, user_id).await;
        cleanup(&db, other_org_id, user_id).await;
    }
}
