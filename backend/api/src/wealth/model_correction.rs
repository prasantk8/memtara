// POST /api/v1/wealth-assessments/:request_id/model-corrections — the only
// route through which a decision's model attestation can be contradicted.
//
// -------------------------------------------------------------------
// WHAT DID NOT EXIST BEFORE THIS FILE
// -------------------------------------------------------------------
// `decision_model_attestations` is written by `issue-wealth-request`, in the
// same transaction as the assessment, before the client's device has proved
// anything and before any human has reviewed it. It is a forward declaration,
// and until this endpoint there was no route, no row and no field through
// which anyone — including the organisation that made it, acting honestly —
// could say it had turned out to be wrong. `tests/break_it/
// test_attack_11_swap_model_undetected.py` proves that against a running
// server by trying: PATCH, PUT and POST answer 405/405/404, a second
// attestation row is refused by the primary key, and the review endpoint is
// `deny_unknown_fields` and rejects a smuggled `model_name`.
//
// The finding's own sentence for that state is the one this file exists to
// falsify: "the honest correction is as impossible as the dishonest one".
//
// -------------------------------------------------------------------
// WHY A NEW COLLECTION AND NOT A PATCH ON THE ASSESSMENT
// -------------------------------------------------------------------
// A PATCH would say the attestation is a mutable property of the assessment.
// It is not: it is a statement a named party made at a named time, and the
// statement is evidence whether or not it was accurate. So corrections are a
// collection — plural in the path, because there can be many — and each POST
// appends one. The original row is never touched, which is also what keeps
// `audit/binding.rs` honest: that module rebuilds the attestation's payload
// from the live row at verification time, so an in-place edit here would make
// `GET /orgs/:id/audit-log/replay` report ALTERED against a decision nobody
// attacked. A correction path that trips the tamper detector is a correction
// path nobody uses.
//
// -------------------------------------------------------------------
// WHY THIS ENDPOINT DOES NOT REQUIRE A VERDICT, AND `/review` DOES
// -------------------------------------------------------------------
// `review.rs` returns 409 for an assessment with no verdict, because a review
// recorded against an undecided assessment would evidence a control that did
// not run. The opposite is true here. Finding 7's own words are that an
// organisation "discovers MID-FLIGHT that a different model served the
// request" and has nowhere to say so — so refusing a correction until a proof
// lands would close the exact window the finding is about. A correction filed
// before the verdict is the earliest and most credible kind.
//
// -------------------------------------------------------------------
// WHY THE RESPONSE IS NOT THE `DecisionEvidence` RECORD
// -------------------------------------------------------------------
// `review.rs` returns the full record, and copying that here was the first
// instinct. It does not work, and the reason is the paragraph above:
// `build_decision_evidence` refuses an undecided assessment with a 409, so a
// correction filed mid-flight would either have to return a different shape
// from one filed after the verdict, or fail. A response whose shape depends on
// the state of the thing it describes is the defect this codebase spends
// `from_inputs` and `respond` avoiding, so this endpoint has one response
// shape and points at the record instead of embedding it.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

use super::model_intake::{self, RecordedDeclaration};

/// The shortest correction reason this endpoint accepts.
///
/// Three times `model_intake::MIN_STATEMENT_CHARS`, and the difference is
/// deliberate rather than arbitrary. Ten characters is the floor that stops
/// `"x"`, `"n/a"` and `"-"` — what a required free-text field collects when
/// nobody means to fill it in — and that is the right floor for a declaration
/// made at open time, before anything has gone wrong. A correction is a
/// statement that a record this organisation already signed named the wrong
/// deciding system, and ten characters cannot carry what was discovered, when
/// or how. Thirty is still not a quality bar and does not pretend to be one;
/// it is the point at which a caller has to write a sentence.
///
/// `decision_model_corrections_reason_is_substantive` in migrations/0009
/// holds the same number as a CHECK constraint, so the two cannot drift and
/// neither is bypassable by removing the other from the path.
const MIN_CORRECTION_REASON_CHARS: usize = 30;

/// How far ahead of the server's clock a claimed `asserted_at` may sit. Same
/// number and same reasoning as `review::MAX_CLOCK_SKEW_SECONDS` and
/// `model_intake::MAX_MODEL_CALL_SKEW_SECONDS`: a caller integrating any of
/// the three has one allowance to learn.
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCorrectionBody {
    /// The organisation's own identifier for whoever is asserting the
    /// correction. Text, not a foreign key, for the reason
    /// `ReviewBody::reviewer_id` gives: Memtara has no directory of a bank's
    /// staff and inventing one would be a worse claim than quoting theirs.
    pub asserted_by: String,
    /// The authority they are asserting it under. Separate from the
    /// identifier, because "who" and "with what authority" are different
    /// questions and a contradiction of a signed model attestation is exactly
    /// the kind of statement where the second one is asked first.
    pub asserted_by_role: String,
    /// Why the correction is being made. Required, substantive, and stored
    /// verbatim — see `MIN_CORRECTION_REASON_CHARS`.
    pub correction_reason: String,

    /// What the organisation now says about AI participation in this
    /// decision, in the same wire shape `ai_participation` uses on
    /// `POST /api/v1/issue-wealth-request`.
    ///
    /// Untyped for the reason `model_intake::resolve_value` gives: typing it
    /// as the enum hands a malformed declaration to axum's `Json` rejection,
    /// which answers a bare 422 naming nothing, and the caller most likely to
    /// send a malformed block is the one doing this for the first time.
    ///
    /// Reusing the intake shape rather than inventing a flat one is what
    /// makes the declared model-call timestamp, the config-fingerprint digest
    /// rule and the "an identification that names neither provider nor model
    /// is not one" rule apply here without being written twice. A correction
    /// held to a weaker standard than the declaration it corrects would be a
    /// door into the same record.
    pub corrected_model: serde_json::Value,

    /// When the organisation determined the correction. Defaults to the
    /// server's clock. Accepted because a determination reached at yesterday's
    /// model-risk meeting is a legitimate submission, and bounded because
    /// "asserted at" is not a free-text field.
    #[serde(default)]
    pub asserted_at: Option<DateTime<Utc>>,
}

/// What was recorded. Deliberately not the evidence record — see the module
/// header.
#[derive(Debug, Serialize)]
pub struct ModelCorrectionResponse {
    pub correction_id: Uuid,
    pub request_id: Uuid,
    /// Dense from 1, per decision. Rendered in the evidence record too, so a
    /// missing number is legible as a removed correction to an examiner with
    /// no database access.
    pub correction_no: i32,
    /// Which of the two corrected declarations was written. Echoed for the
    /// reason `ai_participation_recorded` is echoed on
    /// `issue-wealth-request`: the difference between them is invisible at
    /// integration time and expensive at export time.
    pub corrected_declaration: RecordedDeclaration,
    pub asserted_at: DateTime<Utc>,
    /// The server's own observation of when the correction arrived, beside
    /// the caller's claim about when it was determined. The gap between the
    /// two is the only unforgeable thing about the first.
    pub recorded_at: DateTime<Utc>,
    /// Where to read what the record now says. Not the record itself: this
    /// endpoint answers the same way whether or not the assessment has been
    /// decided.
    pub decision_evidence: String,
}

fn required(field: &str, value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_string())
}

fn correction_reason(value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.chars().count() < MIN_CORRECTION_REASON_CHARS {
        return Err(ApiError::BadRequest(format!(
            "correction_reason must be at least {MIN_CORRECTION_REASON_CHARS} characters. A \
             correction says that a record this organisation already signed named the wrong \
             deciding system, and it becomes part of that record permanently — the original \
             attestation is never altered, so what an examiner reads is your correction beside \
             the declaration it contradicts. Say what was discovered and how: a gateway log, a \
             vendor incident notice, a reconciliation against your own inference records. The \
             floor is not a quality bar; it is the point at which a required field stops \
             collecting \"n/a\""
        )));
    }
    Ok(trimmed.to_string())
}

/// Reject the one declaration a correction may never make.
///
/// The full argument is in the header of migrations/0009. In one line: a
/// correction may weaken or re-point the organisation's AI claim and may never
/// strengthen it into `no_ai_participated`, which is the strongest assertion
/// this system can make and the one `model_intake.rs` exists almost entirely
/// to keep unreachable by accident.
fn refuse_the_no_ai_assertion(declaration: &str) -> ApiResult<()> {
    if declaration != "no_ai_participated" {
        return Ok(());
    }
    Err(ApiError::BadRequest(
        "corrected_model.declaration may not be no_ai_participated. That declaration is a signed \
         assertion that no AI system took part, and this endpoint deliberately cannot reach it: a \
         correction is filed after the decision — after the verdict, after the review, possibly \
         after a complaint — which is when an organisation has the strongest reason to want the \
         flattering answer and the weakest claim to it. The declaration made when the assessment \
         was opened was made before anyone knew how it would turn out, and that is where its \
         evidential weight comes from. If an AI participated and you can no longer identify it, \
         declare participated_but_unidentified with a reason; that is the honest correction and \
         it is reachable. Retracting the participation claim entirely is a larger act than \
         correcting an identity and is not built"
            .into(),
    ))
}

/// Record one correction. Split from the handler so the tests exercise the
/// real path against a real database without standing up a webauthn context
/// and an issuer key to do it — the same reason `review::record_review` is
/// shaped this way.
pub(super) async fn record_model_correction(
    db: &PgPool,
    org_id: Uuid,
    request_id: Uuid,
    body: ModelCorrectionBody,
) -> ApiResult<ModelCorrectionResponse> {
    let asserted_by = required("asserted_by", &body.asserted_by)?;
    let asserted_by_role = required("asserted_by_role", &body.asserted_by_role)?;
    let reason = correction_reason(&body.correction_reason)?;

    // Scoped by `org_id` in the WHERE clause, not fetched-then-checked:
    // another tenant's assessment is indistinguishable from one that does not
    // exist, which is the only answer that does not confirm a competitor's
    // decision exists.
    //
    // `created_at` is read because the corrected model-call timestamp is
    // measured against the assessment's own open time, exactly as the
    // original declaration's was. A correction held to `now()` instead would
    // accept a model call that the declaration it corrects would have been
    // refused for, which is a door into the same record through a slower
    // route.
    let assessment = sqlx::query!(
        r#"
        select w.created_at as opened_at
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

    // Checked on the wire tag BEFORE parsing, and again on the parsed row
    // after. Not belt-and-braces for its own sake: `resolve_value` validates
    // the no-AI branch's own required statement, so without the first check a
    // caller attempting a declaration this endpoint will never accept is told
    // to lengthen their attestation, complies, and is then told the whole
    // declaration is unavailable. The refusal that matters should arrive
    // first. The second check is the authoritative one, because the first
    // depends on the wire tag's spelling and the second does not.
    refuse_the_no_ai_assertion(
        body.corrected_model
            .get("declaration")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
    )?;
    let corrected = model_intake::resolve_value(
        Some(body.corrected_model.clone()),
        assessment.opened_at,
    )?;
    refuse_the_no_ai_assertion(corrected.declaration)?;

    let server_received_at = Utc::now();
    let asserted_at = body.asserted_at.unwrap_or(server_received_at);
    if asserted_at > server_received_at + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) {
        return Err(ApiError::BadRequest(format!(
            "asserted_at ({asserted_at}) is in the future by more than the \
             {MAX_CLOCK_SKEW_SECONDS} seconds of clock skew this endpoint tolerates. The field \
             records when your organisation determined the correction, and a determination it has \
             not made yet is not a correction"
        )));
    }
    // TWO CLOCKS, AND THE ALLOWANCE IS NOT OPTIONAL.
    //
    // `wealth_requests.created_at` is Postgres's `now()`, taken inside the
    // database container. `asserted_at` defaults to this process's
    // `Utc::now()`. The break-it suite documents those two as observably
    // apart — `test_attack_11`'s `_just_after` helper exists for exactly this
    // reason — and on this machine the database is roughly 130ms AHEAD.
    //
    // A bare `asserted_at < opened_at` therefore refuses the single most
    // ordinary correction there is: one filed in the same breath as the
    // assessment, by a desk that noticed immediately, with no `asserted_at`
    // supplied at all. That was written first and every test in this module
    // failed on it. The allowance is the same 300 seconds the future bound
    // uses, so the rule is symmetric and there is one number to learn.
    //
    // What survives the allowance is what the check is for: a correction
    // dated before the decision existed by any margin a clock could not
    // explain.
    if asserted_at + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) < assessment.opened_at {
        return Err(ApiError::BadRequest(format!(
            "asserted_at ({asserted_at}) precedes the assessment this correction is about \
             ({}) by more than the {MAX_CLOCK_SKEW_SECONDS} seconds of clock skew this endpoint \
             tolerates. A correction cannot have been determined before the decision it corrects \
             existed. If the underlying discovery predates the assessment — a vendor incident \
             notice covering a period that includes it — then the correction was determined when \
             you connected the two, and that is the date this field wants",
            assessment.opened_at
        )));
    }

    let mut tx = db.begin().await?;

    // Locks the attestation row for the rest of this transaction, which does
    // two jobs at once. It is the existence-and-tenancy check for the thing
    // being corrected, and it serialises concurrent corrections to the same
    // decision so that `max(correction_no) + 1` below cannot hand two of them
    // the same number. The unique constraint in migrations/0009 would catch
    // that anyway; catching it here means the caller gets a correction rather
    // than a 500 they have to retry.
    let attested = sqlx::query_scalar!(
        r#"
        select declaration
        from decision_model_attestations
        where request_id = $1 and org_id = $2
        for update
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(original_declaration) = attested else {
        // The assessment exists — it was found above — so this is not a 404.
        // It is a decision opened before migrations/0006 existed, which has
        // no declaration to contradict. Correcting nothing into something
        // would manufacture an attestation for a decision whose calling
        // system was never asked the question, and `absent_attestation`
        // exists precisely to stop that reading.
        return Err(ApiError::Conflict(
            "this assessment carries no model attestation, so there is nothing to correct. It \
             was opened before model identity capture existed \
             (migrations/0006_decision_capture.sql) and no declaration was ever requested from \
             the calling system. A correction filed here would not be correcting a record — it \
             would be creating one, backdated, for a decision nobody asked the question about. \
             Absence of a declaration is not a declaration of absence, and it is not a \
             declaration this endpoint may supply on your behalf"
                .into(),
        ));
    };

    let next_no: i32 = sqlx::query_scalar!(
        r#"
        select coalesce(max(correction_no), 0) + 1 as "next!"
        from decision_model_attestation_corrections
        where request_id = $1
        "#,
        request_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    let inserted = sqlx::query!(
        r#"
        insert into decision_model_attestation_corrections (
            request_id, org_id, correction_no, asserted_by, asserted_by_role,
            correction_reason, corrected_declaration, unidentified_reason,
            corrected_model_provider, corrected_model_name, corrected_model_version,
            corrected_prompt_version, corrected_model_environment,
            corrected_model_config_fingerprint, corrected_model_system_prompt_or_policy_id,
            corrected_model_timestamp, asserted_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        returning id, created_at
        "#,
        request_id,
        org_id,
        next_no,
        asserted_by,
        asserted_by_role,
        reason,
        corrected.declaration,
        corrected.unidentified_reason,
        corrected.provider,
        corrected.model_name,
        corrected.model_version,
        corrected.prompt_version,
        corrected.environment,
        corrected.config_fingerprint,
        corrected.system_prompt_or_policy_id,
        corrected.model_timestamp,
        asserted_at,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Same transaction as the insert, for the reason `review.rs` gives for
    // its own event: a correction that exists without the chain entry that
    // created it is the gap this table is meant to close, not one it should
    // open.
    //
    // This event carries the human-readable narrative and is keyed on the
    // DECISION, so it lands in that decision's audit excerpt
    // (`wealth/evidence.rs` selects `where ref_id = $1`). The binding event
    // below is keyed on the correction row and is what commits to its
    // contents; the two are different claims and are deliberately not merged.
    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "decision_model_attestation_corrected",
        Some(request_id),
        serde_json::json!({
            "correction_id": inserted.id,
            "correction_no": next_no,
            "asserted_by": asserted_by,
            "asserted_by_role": asserted_by_role,
            "correction_reason": reason,
            // Both declarations, so the chain records the direction of the
            // change and not only its destination. "model_identified ->
            // model_identified" and "no_ai_participated -> model_identified"
            // are very different admissions and the second one should not
            // have to be reconstructed by joining.
            "declaration_as_opened": original_declaration,
            "corrected_declaration": corrected.declaration,
            "corrected_model_provider": corrected.provider,
            "corrected_model_name": corrected.model_name,
            "asserted_at": asserted_at,
            "received_at": server_received_at,
            "dfsa_rules": ["COB 3.1"],
        }),
    )
    .await?;

    crate::audit::binding::record_model_attestation_correction_binding(
        &mut tx,
        org_id,
        inserted.id,
    )
    .await?;

    tx.commit().await?;

    Ok(ModelCorrectionResponse {
        correction_id: inserted.id,
        request_id,
        correction_no: next_no,
        corrected_declaration: corrected.recorded_declaration(),
        asserted_at,
        recorded_at: inserted.created_at,
        decision_evidence: format!("/api/v1/wealth-assessments/{request_id}/decision-evidence"),
    })
}

pub(super) async fn submit_model_correction(
    OrgAuth(org_id): OrgAuth,
    Path(request_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(body): Json<ModelCorrectionBody>,
) -> ApiResult<(StatusCode, Json<ModelCorrectionResponse>)> {
    let response = record_model_correction(&state.db, org_id, request_id, body).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session_token::hash_token;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
        PgPoolOptions::new().max_connections(5).connect(&url).await.ok()
    }

    /// A vkeys directory that deliberately does not exist — same reasoning as
    /// `review::tests::NO_VKEYS`: the assertions below are about the record's
    /// model surface, and must not pass or fail because a build artefact
    /// happened to be on disk.
    const NO_VKEYS: &str = "/nonexistent/vkeys-for-model-correction-tests";

    async fn make_org(db: &PgPool) -> Uuid {
        sqlx::query_scalar!(
            "insert into organizations (name, org_type, api_key_hash) values ($1, 'bank', $2) \
             returning id",
            format!("Correction Test Bank {}", Uuid::new_v4()),
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

    /// One assessed wealth request whose model attestation names a model.
    ///
    /// Rows rather than HTTP, for the reason `review::tests` gives: standing
    /// up a real proof would make this a `bb` integration test that skips on
    /// any machine without the toolchain, and the invariants under test are
    /// not about proofs.
    async fn make_attested_request(
        db: &PgPool,
        org_id: Uuid,
        user_id: Uuid,
        declaration: &str,
    ) -> Uuid {
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
            values ($1, $2, 'wealth_suitability', '{}'::jsonb, 'pending', $3,
                    now() + interval '1 hour')
            returning id
            "#,
            org_id,
            user_id,
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
                    now() - interval '10 minutes', now() + interval '1 hour', 1, true,
                    now() - interval '5 minutes', $4)
            "#,
            request_id,
            product_id,
            vec![9u8; 32],
            vec![4u8; 32],
        )
        .execute(db)
        .await
        .expect("insert wealth request");

        match declaration {
            "no_ai_participated" => {
                sqlx::query!(
                    r#"
                    insert into decision_model_attestations (request_id, org_id, declaration,
                                                             no_ai_attestation)
                    values ($1, $2, 'no_ai_participated', $3)
                    "#,
                    request_id,
                    org_id,
                    "suitability produced by the deterministic rules engine, no model in the path",
                )
                .execute(db)
                .await
                .expect("insert attestation");
            }
            _ => {
                sqlx::query!(
                    r#"
                    insert into decision_model_attestations (
                        request_id, org_id, declaration, model_provider, model_name,
                        model_version, model_environment, model_timestamp)
                    values ($1, $2, 'model_identified', 'anthropic', 'claude-opus-4',
                            '20260514', 'production', now() - interval '20 minutes')
                    "#,
                    request_id,
                    org_id,
                )
                .execute(db)
                .await
                .expect("insert attestation");
            }
        }

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

    const REASON: &str = "the group model gateway's request log shows this request was served by \
                          the fallback deployment during the 18 Aug incident, not by the model \
                          named when the assessment was opened";

    fn body(corrected_model: serde_json::Value) -> ModelCorrectionBody {
        ModelCorrectionBody {
            asserted_by: "mrm-desk-11".into(),
            asserted_by_role: "model_risk_officer".into(),
            correction_reason: REASON.into(),
            corrected_model,
            asserted_at: None,
        }
    }

    fn named_model() -> serde_json::Value {
        json!({
            "declaration": "model_identified",
            "provider": "a-different-vendor",
            "model_name": "a-different-model",
            "model_version": "2026.3",
            "environment": "production",
        })
    }

    // -----------------------------------------------------------------
    // The finding, closed.
    // -----------------------------------------------------------------

    /// Corrections append, in order, and the row they contradict is never
    /// touched.
    ///
    /// The second half is the load-bearing one. The original attestation is
    /// what the organisation said at the time, which is a fact about the
    /// organisation rather than about the model, and `audit/binding.rs`
    /// rebuilds that row's hashed payload from the live row at verification
    /// time — so an in-place edit here would make an untouched decision
    /// report ALTERED. This test reads every column of the original before
    /// and after two corrections and requires them identical.
    #[tokio::test]
    async fn corrections_append_in_order_and_never_touch_the_original_attestation() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        let original = sqlx::query!(
            "select declaration, model_provider, model_name, model_version, model_environment, \
             model_timestamp, created_at from decision_model_attestations where request_id = $1",
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();

        let first = record_model_correction(&db, org_id, request_id, body(named_model()))
            .await
            .expect("a correction is recorded");
        assert_eq!(first.correction_no, 1);
        assert_eq!(
            first.corrected_declaration,
            RecordedDeclaration::ModelIdentified
        );

        // A second correction of the same decision appends rather than
        // replacing. Corrections are a history, not a current value: an
        // organisation that corrects twice has said two things and an
        // examiner is entitled to both.
        let second = record_model_correction(
            &db,
            org_id,
            request_id,
            body(json!({
                "declaration": "participated_but_unidentified",
                "reason": "on further review the gateway log cannot distinguish which of the two \
                           fallback deployments answered, so the earlier correction named a model \
                           we cannot stand behind",
            })),
        )
        .await
        .expect("a second correction is recorded");
        assert_eq!(second.correction_no, 2);
        assert_ne!(first.correction_id, second.correction_id);

        let after = sqlx::query!(
            "select declaration, model_provider, model_name, model_version, model_environment, \
             model_timestamp, created_at from decision_model_attestations where request_id = $1",
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(original.declaration, after.declaration);
        assert_eq!(original.model_provider, after.model_provider);
        assert_eq!(original.model_name, after.model_name);
        assert_eq!(original.model_version, after.model_version);
        assert_eq!(original.model_environment, after.model_environment);
        assert_eq!(original.model_timestamp, after.model_timestamp);
        assert_eq!(
            original.created_at, after.created_at,
            "the declaration made at open time is what the organisation said then, and nothing \
             in the correction path may rewrite it"
        );

        // And the chain commits to each correction's contents individually.
        // Keyed on the correction's own id rather than the request's,
        // because a rebuild must be a pure function of one row — see
        // `binding::model_attestation_correction_payload`.
        let mut conn = db.acquire().await.unwrap();
        for id in [first.correction_id, second.correction_id] {
            let bound = sqlx::query_scalar!(
                r#"select count(*) as "n!" from audit_log
                   where event_type = 'decision_model_attestation_correction_bound' and ref_id = $1"#,
                id
            )
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            assert_eq!(bound, 1, "every correction carries exactly one binding event");
        }

        let report = crate::audit::replay::replay_org(&mut conn, org_id).await.unwrap();
        assert_eq!(
            report.summary.altered, 0,
            "an untouched database must not report tampering: {:?}",
            report.events
        );
        assert!(
            report.summary.intact >= 2,
            "both correction bindings must replay, got {:?}",
            report.summary
        );
        drop(conn);

        cleanup(&db, org_id, user_id).await;
    }

    /// The honest answer stays reachable, and the flattering one does not.
    ///
    /// A correction table that could only ever name a replacement model would
    /// reproduce the original defect one level up: the realistic discovery is
    /// "we can no longer tell which deployment answered", and an organisation
    /// in that position must not have to choose between guessing at a model
    /// and saying nothing. The reverse — correcting INTO the assertion that
    /// no AI took part — is the one direction that is closed, for the reason
    /// `refuse_the_no_ai_assertion` gives.
    #[tokio::test]
    async fn a_correction_can_admit_ignorance_but_can_never_assert_that_no_ai_took_part() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        // (a) The honest middle state, reachable.
        let unnameable = record_model_correction(
            &db,
            org_id,
            request_id,
            body(json!({
                "declaration": "participated_but_unidentified",
                "reason": "the group model gateway does not return which deployment served a \
                           request and the pool was rotated before we asked",
            })),
        )
        .await
        .expect("admitting ignorance must be recordable");
        assert_eq!(
            unnameable.corrected_declaration,
            RecordedDeclaration::ParticipatedButUnidentified
        );

        // (b) The strongest assertion in the system, unreachable from here —
        //     whether or not the caller supplied the statement that
        //     declaration would otherwise require. The second form is the one
        //     that matters: a caller told only "your attestation is too
        //     short" would lengthen it and come back to a refusal they could
        //     have had first.
        for attempt in [
            json!({
                "declaration": "no_ai_participated",
                "attestation": "on review the recommendation came from the deterministic rules \
                                engine and no model was in the path",
            }),
            json!({ "declaration": "no_ai_participated", "attestation": "n/a" }),
        ] {
            let err = record_model_correction(&db, org_id, request_id, body(attempt))
                .await
                .unwrap_err();
            match &err {
                ApiError::BadRequest(m) => assert!(
                    m.contains("may not be no_ai_participated"),
                    "the refusal must name the rule, not the field length: {m}"
                ),
                other => panic!("expected a 400 naming the declaration, got {other:?}"),
            }
        }

        // (c) The reverse direction is open, and must be: an organisation
        //     retracting a no-AI assertion is making an admission, and no
        //     rule needs to protect the system from an admission.
        let had_said_no_ai =
            make_attested_request(&db, org_id, user_id, "no_ai_participated").await;
        let retraction = record_model_correction(
            &db,
            org_id,
            had_said_no_ai,
            body(json!({
                "declaration": "participated_but_unidentified",
                "reason": "an inference-log reconciliation shows a model was in the path for this \
                           desk during the period covering this decision",
            })),
        )
        .await
        .expect("retracting a no-AI assertion must be recordable");
        assert_eq!(retraction.correction_no, 1);

        // Nothing the two refusals touched left a row behind.
        let filed = sqlx::query_scalar!(
            r#"select count(*) as "n!" from decision_model_attestation_corrections
               where request_id = $1"#,
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(filed, 1, "a refused correction must not leave a row behind");

        cleanup(&db, org_id, user_id).await;
    }

    /// The four refusals, each of which a naive handler would accept.
    #[tokio::test]
    async fn a_correction_without_a_stated_reason_an_author_or_a_possible_timestamp_is_refused() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        // (a) A token reason. Ten characters is enough for the declaration
        //     made at open time and is not enough for a contradiction of it.
        for weak in ["", "   ", "n/a", "model changed"] {
            let mut b = body(named_model());
            b.correction_reason = weak.into();
            let err = record_model_correction(&db, org_id, request_id, b).await.unwrap_err();
            assert!(matches!(err, ApiError::BadRequest(_)), "{weak:?} -> {err:?}");
        }

        // (b) An unattributed correction. The whole point of the row is that
        //     a named party said this at a named time.
        for (who, role) in [("", "model_risk_officer"), ("mrm-desk-11", "  ")] {
            let mut b = body(named_model());
            b.asserted_by = who.into();
            b.asserted_by_role = role.into();
            assert!(record_model_correction(&db, org_id, request_id, b).await.is_err());
        }

        // (c) THE FINDING'S OWN FIELD. A corrected model call timestamped
        //     three years before the assessment is refused here exactly as it
        //     is on the intake path — a correction held to a weaker standard
        //     than the declaration it corrects would be a door into the same
        //     record through a slower route.
        let mut b = body(json!({
            "declaration": "model_identified",
            "provider": "a-different-vendor",
            "model_name": "a-different-model",
            "timestamp": "2023-01-05T04:00:00Z",
        }));
        b.correction_reason = REASON.into();
        let err = record_model_correction(&db, org_id, request_id, b).await.unwrap_err();
        match &err {
            ApiError::BadRequest(m) => assert!(m.contains("days before this assessment"), "{m}"),
            other => panic!("expected the intake timestamp refusal, got {other:?}"),
        }

        // (d) A correction determined before the decision it corrects
        //     existed, and one determined next month.
        for bad in [
            Utc::now() - Duration::days(400),
            Utc::now() + Duration::days(30),
        ] {
            let mut b = body(named_model());
            b.asserted_at = Some(bad);
            assert!(record_model_correction(&db, org_id, request_id, b).await.is_err(), "{bad}");
        }

        // (e) And the negative control for (d), which is not decoration: the
        //     assessment's `created_at` is Postgres's clock and a defaulted
        //     `asserted_at` is this process's, and the two are observably
        //     apart. A bare "asserted_at must not precede opened_at" refuses
        //     the most ordinary correction there is — filed immediately, by a
        //     desk that noticed at once — and it refused every test in this
        //     module before the skew allowance was added.
        let mut immediate = body(named_model());
        immediate.asserted_at = None;
        assert!(
            record_model_correction(&db, org_id, request_id, immediate).await.is_ok(),
            "a correction filed the instant the assessment was opened must not be refused by a \
             clock difference between the database container and this process"
        );
        // That one is real and must be cleaned up before the count below.
        sqlx::query!(
            "delete from decision_model_attestation_corrections where request_id = $1",
            request_id
        )
        .execute(&db)
        .await
        .unwrap();

        let filed = sqlx::query_scalar!(
            r#"select count(*) as "n!" from decision_model_attestation_corrections
               where request_id = $1"#,
            request_id
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(filed, 0, "not one of these may leave a row behind");

        cleanup(&db, org_id, user_id).await;
    }

    /// Another tenant's decision is not correctable, and is indistinguishable
    /// from one that does not exist. A correction endpoint that answered 409
    /// for a competitor's assessment would confirm the assessment exists.
    #[tokio::test]
    async fn a_correction_cannot_reach_another_tenants_decision() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let other_org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        let err = record_model_correction(&db, other_org_id, request_id, body(named_model()))
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::NotFound), "{err:?}");

        // And a decision that carries no attestation at all is a 409 rather
        // than a 404 — it exists, there is simply nothing to contradict.
        // Creating one here would manufacture a backdated declaration for a
        // decision whose calling system was never asked the question.
        sqlx::query!(
            "delete from decision_model_attestations where request_id = $1",
            request_id
        )
        .execute(&db)
        .await
        .unwrap();
        let err = record_model_correction(&db, org_id, request_id, body(named_model()))
            .await
            .unwrap_err();
        match &err {
            ApiError::Conflict(m) => assert!(m.contains("nothing to correct"), "{m}"),
            other => panic!("expected a 409, got {other:?}"),
        }

        cleanup(&db, org_id, user_id).await;
        cleanup(&db, other_org_id, user_id).await;
    }

    /// The constraints hold with the API removed from the path.
    ///
    /// This is the test Finding 8 of docs/BREAK_IT_FINDINGS.md is about, run
    /// against the new table: attack 4 demonstrated that every defence living
    /// in a request handler is irrelevant to someone holding a connection
    /// string, and `decision_reviews` survived that because its rules are
    /// CHECK constraints and not handler code. Each insert below is written
    /// straight into Postgres and must be refused BY NAME — the name matters,
    /// because a refusal from some other constraint would mean the rule under
    /// test is not the one doing the work.
    ///
    /// The residual is the same one Finding 8 states and is worth repeating
    /// rather than leaving implied: a constraint stops an internally
    /// inconsistent forgery and cannot stop a consistent lie. A fabricated
    /// correction naming a plausible author with a plausible reason is
    /// accepted here, because no constraint can know whether anyone made that
    /// determination. What it cannot do is arrive without a binding event,
    /// and that contradiction is what `replay_org` reports.
    #[tokio::test]
    async fn the_correction_rules_are_enforced_by_postgres_and_not_only_by_the_handler() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        // (declaration, reason, provider, name, unidentified_reason,
        //  fingerprint, the constraint that must refuse it)
        let attempts: Vec<(&str, &str, Option<&str>, Option<&str>, Option<&str>, Option<&str>, &str)> = vec![
            // The rule this table exists to hold: a correction may never
            // reach the strongest assertion in the system.
            (
                "no_ai_participated", REASON, None, None, None, None,
                "decision_model_corrections_cannot_assert_no_ai",
            ),
            // A correction with no stated reason is not evidence of anything;
            // it is an unattributed edit wearing an audit trail.
            (
                "model_identified", "n/a", Some("v"), Some("m"), None, None,
                "decision_model_corrections_reason_is_substantive",
            ),
            // An identification that names neither provider nor model.
            (
                "model_identified", REASON, None, Some("m"), None, None,
                "decision_model_corrections_identified_names_something",
            ),
            // An admission of ignorance that does not say why.
            (
                "participated_but_unidentified", REASON, None, None, None, None,
                "decision_model_corrections_unidentified_names_why",
            ),
            // ...or that smuggles a model in beside itself, which would make
            // the record say two contradictory things at once.
            (
                "participated_but_unidentified", REASON, Some("v"), None,
                Some("the gateway does not report the deployment"), None,
                "decision_model_corrections_unidentified_names_why",
            ),
            // A fingerprint that is not a digest. 0006 enforces this shape
            // for the original attestation at the API boundary only; this
            // table declines to reproduce that gap.
            (
                "model_identified", REASON, Some("v"), Some("m"), None, Some("temperature=0"),
                "decision_model_corrections_fingerprint_is_a_digest",
            ),
        ];

        for (declaration, reason, provider, name, unidentified, fingerprint, constraint) in attempts {
            let err = sqlx::query!(
                r#"
                insert into decision_model_attestation_corrections (
                    request_id, org_id, correction_no, asserted_by, asserted_by_role,
                    correction_reason, corrected_declaration, unidentified_reason,
                    corrected_model_provider, corrected_model_name,
                    corrected_model_config_fingerprint, asserted_at)
                values ($1, $2, 1, 'mrm-11', 'model_risk_officer', $3, $4, $5, $6, $7, $8, now())
                "#,
                request_id,
                org_id,
                reason,
                declaration,
                unidentified,
                provider,
                name,
                fingerprint,
            )
            .execute(&db)
            .await
            .expect_err(&format!("{constraint} must refuse this row"));

            let named = err
                .as_database_error()
                .and_then(|e| e.constraint())
                .unwrap_or("<none>")
                .to_string();
            assert_eq!(
                named, constraint,
                "the row was refused by {named} rather than by {constraint}; the rule under test \
                 is not the one doing the work"
            );
        }

        // Two corrections cannot share a number, which is what makes a
        // deletion legible: dense numbering only means something if the
        // numbers cannot be reused.
        for expect_ok in [true, false] {
            let result = sqlx::query!(
                r#"
                insert into decision_model_attestation_corrections (
                    request_id, org_id, correction_no, asserted_by, asserted_by_role,
                    correction_reason, corrected_declaration, corrected_model_provider,
                    corrected_model_name, asserted_at)
                values ($1, $2, 1, 'mrm-11', 'model_risk_officer', $3, 'model_identified',
                        'v', 'm', now())
                "#,
                request_id,
                org_id,
                REASON,
            )
            .execute(&db)
            .await;
            if expect_ok {
                result.expect("a well-formed correction is accepted; the rules are a gate, not a wall");
            } else {
                let named = result
                    .unwrap_err()
                    .as_database_error()
                    .and_then(|e| e.constraint())
                    .unwrap_or("<none>")
                    .to_string();
                assert_eq!(named, "decision_model_corrections_are_ordered_per_request");
            }
        }

        cleanup(&db, org_id, user_id).await;
    }

    // -----------------------------------------------------------------
    // The half that matters: what the record then says.
    // -----------------------------------------------------------------

    /// A corrected decision's evidence record must stop looking unchanged.
    ///
    /// This is the assertion the whole feature is for. A correction path that
    /// files rows nobody reading the record can see would have corrected
    /// nothing: the record would go on serving the pre-decision declaration
    /// with `state: "recorded"`, which is exactly what attack 11 demonstrates
    /// and exactly what makes the finding a finding.
    #[tokio::test]
    async fn a_corrected_decisions_record_serves_the_correction_and_preserves_the_original() {
        let Some(db) = test_pool().await else {
            eprintln!("skipping: no DB reachable");
            return;
        };
        let org_id = make_org(&db).await;
        let user_id = make_user(&db).await;
        let request_id = make_attested_request(&db, org_id, user_id, "model_identified").await;

        let before = crate::wealth::evidence::build_decision_evidence(
            &db, NO_VKEYS, org_id, request_id,
        )
        .await
        .unwrap();
        let bv = serde_json::to_value(&before).unwrap();
        assert_eq!(
            bv.pointer("/model/provider/value").and_then(|v| v.as_str()),
            Some("anthropic")
        );
        assert_eq!(
            bv.pointer("/model_provenance/corrected"),
            Some(&serde_json::Value::Bool(false))
        );
        // The record already says WHEN the declaration was made, which is the
        // fact attack 11 asserts is nowhere in it. An examiner can compare it
        // against decision.timestamps.assessed_at and see for themselves that
        // the attestation predates the decision.
        assert_eq!(
            bv.pointer("/model_provenance/declared_at/state").and_then(|v| v.as_str()),
            Some("recorded")
        );

        record_model_correction(&db, org_id, request_id, body(named_model()))
            .await
            .unwrap();

        let after = crate::wealth::evidence::build_decision_evidence(
            &db, NO_VKEYS, org_id, request_id,
        )
        .await
        .unwrap();
        let av = serde_json::to_value(&after).unwrap();

        // 1. The record no longer serves the superseded identity as the
        //    answer. This is the assertion attack 11 currently makes in the
        //    opposite direction.
        assert_eq!(
            av.pointer("/model/provider/value").and_then(|v| v.as_str()),
            Some("a-different-vendor")
        );
        assert_ne!(av.pointer("/model"), bv.pointer("/model"));

        // 2. And the original survives verbatim, where an examiner can read
        //    what was declared before the decision existed beside what the
        //    organisation says now.
        assert_eq!(
            av.pointer("/model_provenance/as_declared_at_open/identity/provider")
                .and_then(|v| v.as_str()),
            Some("anthropic")
        );
        assert_eq!(
            av.pointer("/model_provenance/as_declared_at_open/declaration")
                .and_then(|v| v.as_str()),
            Some("model_identified")
        );

        // 3. With who said so, why, and when.
        assert_eq!(
            av.pointer("/model_provenance/corrected"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            av.pointer("/model_provenance/correction_count").and_then(|v| v.as_i64()),
            Some(1)
        );
        assert_eq!(
            av.pointer("/model_provenance/corrections/0/asserted_by").and_then(|v| v.as_str()),
            Some("mrm-desk-11")
        );
        assert!(av
            .pointer("/model_provenance/corrections/0/correction_reason")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("fallback deployment"));

        // 4. The seal moves. A correction that did not change the digest
        //    would be a correction the sealed bytes do not carry.
        assert_ne!(
            before.canonical_sha256_hex().unwrap(),
            after.canonical_sha256_hex().unwrap()
        );

        // 5. A correction that admits ignorance downgrades the served leaves
        //    rather than leaving the superseded model in place — and says, in
        //    the leaf itself, that a correction is why it is empty.
        record_model_correction(
            &db,
            org_id,
            request_id,
            body(json!({
                "declaration": "participated_but_unidentified",
                "reason": "the gateway log cannot distinguish which of the two fallback \
                           deployments answered this request",
            })),
        )
        .await
        .unwrap();
        let latest = crate::wealth::evidence::build_decision_evidence(
            &db, NO_VKEYS, org_id, request_id,
        )
        .await
        .unwrap();
        let lv = serde_json::to_value(&latest).unwrap();
        assert_eq!(
            lv.pointer("/model/provider/state").and_then(|v| v.as_str()),
            Some("unpopulated")
        );
        assert!(lv
            .pointer("/model/provider/unpopulated_reason")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("correction 2"));
        // Still not the no-AI assertion. An AI whose identity is unknown must
        // never collapse into the bytes that say no AI took part.
        assert!(lv.pointer("/model").unwrap().is_object());
        assert!(!latest.model.asserts_no_ai());
        assert_eq!(
            lv.pointer("/model_provenance/correction_count").and_then(|v| v.as_i64()),
            Some(2)
        );

        cleanup(&db, org_id, user_id).await;
    }
}
