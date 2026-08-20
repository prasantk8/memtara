// `GET /api/v1/wealth-assessments/:request_id` — everything needed to
// reconstruct one suitability assessment, in one call.
//
// -------------------------------------------------------------------
// WHY THIS IS AN API AND NOT A REPORT GENERATOR
// -------------------------------------------------------------------
// The obvious way to build a compliance evidence pack is a script that
// queries Postgres directly. It is also the wrong way, for a reason that
// only shows up later: a bank's compliance function will eventually want the
// pack in their own template, in Arabic, joined to their own CRM. If the
// only way to get the evidence is a script we wrote against our schema, they
// are blocked on us for every one of those.
//
// So the schema stays private and the evidence is a documented, org-scoped
// response. `scripts/export_audit_evidence.py` is then just one consumer of
// it — the one that happens to render a PDF — and a bank can write another.
//
// What is deliberately NOT in here: the client's income, liquid assets, risk
// tolerance or holdings. The server never had them. That absence is the
// product, so the response says so explicitly rather than leaving a reader to
// notice the gap and wonder whether it is an oversight.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto::signer::proof_digest_hex;
use crate::domain::CircuitType;
use crate::error::{ApiError, ApiResult};
use crate::evidence::{
    derive_decision_basis, CompletedReview, Consent, CryptographicProof, DecisionAction,
    DecisionEvidence, DecisionInputs, DecisionOutcome, DeclaredAttestation, DeclaredIdentity,
    EvidenceArtifact, HumanReviewInputs, Institution, ModelCorrection, ModelProvenance,
    Provenanced, RegulatoryControl, ReviewOverride,
};
use crate::orgs::OrgAuth;
use crate::state::AppState;
use crate::verify::public_input_layout;

use super::model_intake::{self, AttestationRow};
use super::BUSINESS_PROCESS;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) async fn get_wealth_assessment(
    OrgAuth(org_id): OrgAuth,
    Path(request_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    // Scoped by `org_id` in the WHERE clause, not fetched-then-checked. A
    // request belonging to another tenant is indistinguishable from one that
    // does not exist, which is the only answer that doesn't confirm the
    // existence of a competitor's assessment.
    let req = sqlx::query!(
        r#"
        select w.product_isin, w.product_name, w.product_id, w.product_ref,
               w.min_income, w.min_liquidity, w.max_concentration_percent, w.product_risk_level,
               w.window_start, w.window_end, w.suitable, w.assessed_at, w.created_at,
               d.user_id, d.org_id, d.status, d.nonce, d.expires_at,
               o.name as org_name, o.org_type
        from wealth_requests w
        join disclosure_requests d on d.id = w.request_id
        join organizations o on o.id = d.org_id
        where w.request_id = $1 and d.org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    // Every attempt, accepted and rejected. A pack that showed only the
    // accepted proof would hide the fact that four earlier submissions
    // failed, which is exactly the pattern a reviewer is looking for.
    let proofs = sqlx::query!(
        r#"
        select id, valid, verified_at, public_inputs, proof_bytes
        from proofs
        where request_id = $1
        order by verified_at asc
        "#,
        request_id,
    )
    .fetch_all(&state.db)
    .await?;

    let proof_json: Vec<serde_json::Value> = proofs
        .iter()
        .map(|p| {
            json!({
                "proof_id": p.id,
                "accepted_by_bb_verify": p.valid,
                "verified_at": p.verified_at,
                "proof_bytes": p.proof_bytes.len(),
                // The same digest that appears in the token's `proof_hash`
                // claim and in AIHOOTS's audit chain. Three independent
                // records of one artefact; if they agree, the chain is
                // genuinely tied to this proof.
                "proof_sha256": proof_digest_hex(&p.proof_bytes),
                "public_inputs": p.public_inputs,
            })
        })
        .collect();

    // The audit excerpt: this request's own events, in chain order, with the
    // linkage a verifier needs. `seq` is the position in the global chain —
    // see audit/mod.rs on why consecutive entries here are not adjacent.
    let events = sqlx::query!(
        r#"
        select seq as "seq!", event_type, event_hash, prev_hash, created_at
        from audit_log
        where ref_id = $1 and (org_id = $2 or org_id is null)
        order by seq asc
        "#,
        request_id,
        org_id,
    )
    .fetch_all(&state.db)
    .await?;

    let event_json: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            json!({
                "seq": e.seq,
                "event_type": e.event_type,
                "event_hash": hex(&e.event_hash),
                "prev_hash": e.prev_hash.as_ref().map(|h| hex(h)),
                "created_at": e.created_at,
            })
        })
        .collect();

    // The verification key this assessment was checked against. An examiner
    // re-verifying the proof needs its digest to know they are holding the
    // same key; without it, "the proof verifies" is a claim about a key
    // nobody identified.
    let vkey_path =
        std::path::Path::new(&state.config.vkeys_dir).join(CircuitType::WealthSuitability.as_str()).join("vk");
    let vkey = match tokio::fs::read(&vkey_path).await {
        Ok(bytes) => json!({
            "sha256": hex(&<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&bytes))),
            "bytes": bytes.len(),
            "verifier_target": "noir-recursive",
            "published_at": "circuits/wealth_suitability/vkey/vk",
        }),
        Err(_) => json!({ "sha256": null, "note": "verification key not readable on this instance" }),
    };

    let layout = public_input_layout(CircuitType::WealthSuitability);

    Ok(Json(json!({
        "request_id": request_id,
        "circuit": CircuitType::WealthSuitability.as_str(),
        "status": req.status,
        "organisation": { "id": req.org_id, "name": req.org_name, "type": req.org_type },
        "subject": {
            "user_id": req.user_id,
            // Named rather than left implicit. A reader of an evidence pack
            // will look for the client's finances; this tells them why they
            // will not find them.
            "disclosed_attributes": [],
            "note": "Memtara holds no income, liquidity, risk-tolerance or holdings figure for \
                     this subject. The assessment was computed on the holder's device and only \
                     its one-bit result was disclosed.",
        },
        "product": {
            "id": req.product_id,
            "isin": req.product_isin,
            "name": req.product_name,
            "product_ref": format!("0x{}", hex(&req.product_ref)),
        },
        "terms_assessed_against": {
            "min_income": req.min_income,
            "min_liquidity": req.min_liquidity,
            "max_concentration_percent": req.max_concentration_percent,
            "product_risk_level": req.product_risk_level,
            "source": "product registry, snapshotted when the assessment was opened",
        },
        "window": {
            "start": req.window_start,
            "end": req.window_end,
            "expires_at": req.expires_at,
        },
        "outcome": {
            "assessed": req.suitable.is_some(),
            "suitable": req.suitable,
            "assessed_at": req.assessed_at,
            "read_from": format!("public input {} of {}", layout.outcome_index.unwrap_or(0), layout.count),
            "note": "`bb verify` succeeding means the proof is well formed, not that the client \
                     passed. The verdict is the circuit's public output and is read explicitly.",
        },
        "nonce": format!("0x{}", hex(&req.nonce)),
        "verification_key": vkey,
        "proofs": proof_json,
        "audit_chain_excerpt": event_json,
        "regulatory_mapping": {
            "dfsa": ["COB 3.1"],
            "cbuae": ["5(c)", "5(d)", "4(a)"],
        },
        "opened_at": req.created_at,
    })))
}

// =====================================================================
// GET /api/v1/wealth-assessments/:request_id/decision-evidence
//
// The DecisionEvidence v1.1.0 record for one assessment: the object an
// offline auditor validates against schema/decision_evidence/v1.1.0.json,
// and the object whose canonical bytes a seal digests.
//
// -------------------------------------------------------------------
// WHY THIS IS A SECOND ROUTE AND NOT A RESHAPING OF THE FIRST
// -------------------------------------------------------------------
// The route above is the operational view: a bank's own tooling already
// consumes its shape, and `scripts/export_audit_evidence.py` renders from
// it. This one is the sealed shape, pinned to a versioned JSON Schema that
// becomes immutable the moment a record is sealed under it. Collapsing the
// two would make every convenience change to the operational view a
// breaking change to a schema that cannot break.
// =====================================================================

/// Everything one decision's evidence is assembled from, in one place.
///
/// A struct rather than a tuple of query results because the assembly below
/// has to be the single construction site — the same discipline
/// `product_response!` enforces for `ProductResponse` and `from_inputs`
/// enforces for the record itself. Two code paths building this object is
/// how `vault_root` ends up populated on one endpoint and empty on another.
struct EvidenceSources {
    outcome: DecisionOutcome,
    status: DecisionAction,
    decided_at: chrono::DateTime<chrono::Utc>,
    opened_at: chrono::DateTime<chrono::Utc>,
    assessed_at: Option<chrono::DateTime<chrono::Utc>>,
    org: Institution,
    subject_id: String,
    consent: Consent,
    vault_root: Provenanced<String>,
    threshold_set_id: Provenanced<String>,
    threshold_version: Provenanced<String>,
    threshold_values: BTreeMap<String, serde_json::Value>,
    model: crate::evidence::ModelAttestation,
    model_provenance: ModelProvenance,
    input_context_fingerprint: Provenanced<String>,
    output_fingerprint: Provenanced<String>,
    review: HumanReviewInputs,
    artifacts: Vec<EvidenceArtifact>,
    proofs: Vec<CryptographicProof>,
}

/// The refusal returned for an assessment that has not been decided.
///
/// `DecisionAction` has three variants and deliberately no `Pending`,
/// because an evidence record is written about a decision that was reached.
/// Rather than inventing a fourth disposition for a request still in flight,
/// this refuses — a decision in flight having no evidence record is a
/// different and honest state, and one an examiner can tell apart from a
/// missing record.
fn not_decided_yet() -> ApiError {
    ApiError::Conflict(
        "this assessment has not been decided yet, so there is no decision to evidence. \
         A record is written about a decision that was reached; an assessment still in flight \
         has no record, which is a different and honest state from a record that is missing \
         fields. Submit a proof to POST /api/v1/submit-wealth-proof first"
            .into(),
    )
}

/// Load and shape everything one record is built from.
///
/// Takes a pool and a vkeys directory rather than `AppState` so that the
/// review endpoint's tests can exercise the real assembly against a real
/// database without standing up a webauthn context and an issuer key to do
/// it — a test that cannot afford to run is a test that does not run.
async fn gather(
    db: &PgPool,
    vkeys_dir: &str,
    org_id: Uuid,
    request_id: Uuid,
) -> ApiResult<EvidenceSources> {
    // Scoped by `org_id` in the WHERE clause, not fetched-then-checked —
    // same reasoning as the route above.
    let req = sqlx::query!(
        r#"
        select w.product_id, w.product_isin, w.min_income, w.min_liquidity,
               w.max_concentration_percent, w.product_risk_level,
               w.suitable, w.assessed_at, w.created_at, w.terms_version, w.vault_root,
               w.consent_grant_id,
               d.user_id, d.org_id, o.name as org_name, o.org_type
        from wealth_requests w
        join disclosure_requests d on d.id = w.request_id
        join organizations o on o.id = d.org_id
        where w.request_id = $1 and d.org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(db)
    .await?
    .ok_or(ApiError::NotFound)?;

    // The verdict, read from the record of what the circuit output — not
    // inferred from the proof having verified. `bb verify` exiting 0 on a
    // proof of unsuitability is a correctly-formed rejection, not a pass.
    let (Some(suitable), Some(assessed_at)) = (req.suitable, req.assessed_at) else {
        return Err(not_decided_yet());
    };
    let outcome = if suitable {
        DecisionOutcome::Affirmative
    } else {
        DecisionOutcome::Negative
    };

    // ---------------------------------------------------------------
    // CONSENT. `wealth_requests.consent_grant_id` is snapshotted once, at
    // open, by `issue_wealth_request`'s enforcement check — see
    // `consents::require_covering_grant`. It is read here and joined LIVE
    // rather than re-resolved, and that distinction matters: re-running the
    // enforcement query today would answer "which grant covers this user
    // NOW", and a grant revoked an hour after this decision opened would
    // make an untouched, already-decided assessment's evidence go blank.
    // The five leaves below answer what this decision was actually opened
    // under — see docs/STAGE_PLAN_CONSENT_AND_WITNESS.md §A3 and the
    // consent block's own $comment in schema/decision_evidence/v1.3.0.json.
    const NO_GRANT: &str =
        "this assessment carries no consent_grant_id: it was opened before \
         migrations/0011_consent_grants.sql existed, when nothing in the backend enforced or \
         recorded a consent grant, so there was never a binding event to replay";
    let consent = match req.consent_grant_id {
        Some(consent_id) => {
            let grant = sqlx::query!(
                r#"
                select scope, consent_version, purpose_hash, granted_at
                from consent_grants
                where id = $1
                "#,
                consent_id,
            )
            .fetch_optional(db)
            .await?;

            match grant {
                Some(g) => {
                    let scope: Vec<String> = serde_json::from_value(g.scope).map_err(|e| {
                        ApiError::Other(anyhow::anyhow!(
                            "consent_grants.scope for {consent_id} is not an array of strings \
                             ({e}), which consent_scope_is_array_of_nonempty_strings forbids; \
                             the row was written around the schema"
                        ))
                    })?;
                    Consent {
                        consent_id: Provenanced::recorded(consent_id.to_string()),
                        consent_version: Provenanced::recorded(g.consent_version),
                        scope: Provenanced::recorded(scope),
                        granted_at: Provenanced::recorded(g.granted_at),
                        purpose_hash: match g.purpose_hash {
                            Some(h) => Provenanced::recorded(h),
                            None => Provenanced::not_applicable(
                                "the capturing system did not supply a purpose_hash when this \
                                 grant was made (consent_grants.purpose_hash is optional — see \
                                 migrations/0011); this grant's scope is what actually covers \
                                 this decision's purpose",
                            ),
                        },
                    }
                }
                // The grant this decision cites has been deleted. Every leaf
                // is unpopulated rather than the block being silently
                // dropped — a required key with a stated reason, exactly the
                // shape `model_intake::absent_attestation` uses for the
                // analogous gap on the model side. The DELETE itself is what
                // `test_attack_08_consent_revocation.py` step 4 exercises,
                // and it is independently visible in a replay report as
                // `source_row_missing` on this grant's binding events.
                None => {
                    let reason = format!(
                        "the consent grant this decision cites ({consent_id}) no longer exists \
                         in consent_grants. wealth_requests.consent_grant_id still names it — \
                         migrations/0013_consent_grant_id_outlives_the_grant.sql removed the \
                         foreign key precisely so this id would survive its row's deletion — so \
                         replaying this decision's binding_integrity still finds and reports the \
                         grant's own consent_grant_bound/consent_revocation_bound events as \
                         source_row_missing rather than silently dropping them from scope"
                    );
                    Consent {
                        consent_id: Provenanced::unpopulated(reason.clone()),
                        consent_version: Provenanced::unpopulated(reason.clone()),
                        scope: Provenanced::unpopulated(reason.clone()),
                        granted_at: Provenanced::unpopulated(reason.clone()),
                        purpose_hash: Provenanced::unpopulated(reason),
                    }
                }
            }
        }
        None => Consent {
            consent_id: Provenanced::unpopulated(NO_GRANT),
            consent_version: Provenanced::unpopulated(NO_GRANT),
            scope: Provenanced::unpopulated(NO_GRANT),
            granted_at: Provenanced::unpopulated(NO_GRANT),
            purpose_hash: Provenanced::unpopulated(NO_GRANT),
        },
    };

    // ---------------------------------------------------------------
    // MODEL. A missing row is not the no-AI assertion — see
    // `model_intake::absent_attestation`.
    // ---------------------------------------------------------------
    let attestation = sqlx::query!(
        r#"
        select declaration, no_ai_attestation, unidentified_reason,
               model_provider, model_name, model_version, prompt_version, model_environment,
               model_config_fingerprint, model_system_prompt_or_policy_id, model_timestamp,
               input_context_fingerprint, output_fingerprint, created_at
        from decision_model_attestations
        where request_id = $1 and org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(db)
    .await?;

    // Every correction filed against that declaration, oldest first.
    //
    // Read unconditionally, on every build, and not behind a "does this
    // decision look corrected" check — there is no cheaper signal to check,
    // and a correction surface that only appears when something else already
    // said to look for it is the shape of a control nobody invokes.
    let corrections = sqlx::query!(
        r#"
        select id, correction_no, asserted_by, asserted_by_role, correction_reason,
               corrected_declaration, unidentified_reason,
               corrected_model_provider, corrected_model_name, corrected_model_version,
               corrected_prompt_version, corrected_model_environment,
               corrected_model_config_fingerprint, corrected_model_system_prompt_or_policy_id,
               corrected_model_timestamp, asserted_at, created_at
        from decision_model_attestation_corrections
        where request_id = $1 and org_id = $2
        order by correction_no asc
        "#,
        request_id,
        org_id,
    )
    .fetch_all(db)
    .await?;

    // `AttestationRow`'s `declaration` is a `&'static str` because it is a
    // closed set the CHECK constraints already guarantee; anything else was
    // written around the schema. Shared by both readers below rather than
    // written twice, so the two cannot disagree about what an unrecognised
    // value means.
    fn declaration_of(raw: &str) -> &'static str {
        match raw {
            "no_ai_participated" => "no_ai_participated",
            "model_identified" => "model_identified",
            _ => "participated_but_unidentified",
        }
    }

    /// One correction's model identity in the flat shape
    /// `model_intake::correction_to_attestation` reads.
    fn corrected_row(
        declaration: &'static str,
        unidentified_reason: Option<String>,
        provider: Option<String>,
        model_name: Option<String>,
        model_version: Option<String>,
        prompt_version: Option<String>,
        environment: Option<String>,
        config_fingerprint: Option<String>,
        system_prompt_or_policy_id: Option<String>,
        model_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AttestationRow {
        AttestationRow {
            declaration,
            no_ai_attestation: None,
            unidentified_reason,
            provider,
            model_name,
            model_version,
            prompt_version,
            environment,
            config_fingerprint,
            system_prompt_or_policy_id,
            model_timestamp,
        }
    }

    let mut correction_entries: Vec<ModelCorrection> = Vec::with_capacity(corrections.len());
    // The identity the LAST correction asserts, if any. Built inside the same
    // loop that renders the history so the two cannot describe different
    // rows: the block a reader acts on and the block it came from are one
    // pass over one result set.
    let mut effective_from_correction: Option<crate::evidence::ModelAttestation> = None;

    for c in corrections {
        let row = corrected_row(
            declaration_of(&c.corrected_declaration),
            c.unidentified_reason.clone(),
            c.corrected_model_provider.clone(),
            c.corrected_model_name.clone(),
            c.corrected_model_version.clone(),
            c.corrected_prompt_version.clone(),
            c.corrected_model_environment.clone(),
            c.corrected_model_config_fingerprint.clone(),
            c.corrected_model_system_prompt_or_policy_id.clone(),
            c.corrected_model_timestamp,
        );
        effective_from_correction = Some(model_intake::correction_to_attestation(
            c.correction_no,
            &c.asserted_by,
            c.asserted_at,
            &row,
        ));
        correction_entries.push(ModelCorrection {
            correction_id: c.id,
            correction_no: c.correction_no,
            asserted_by: c.asserted_by,
            asserted_by_role: c.asserted_by_role,
            correction_reason: c.correction_reason,
            asserted_at: c.asserted_at,
            recorded_at: c.created_at,
            declaration: c.corrected_declaration,
            unidentified_reason: c.unidentified_reason,
            identity: DeclaredIdentity {
                provider: c.corrected_model_provider,
                model_name: c.corrected_model_name,
                model_version: c.corrected_model_version,
                prompt_version: c.corrected_prompt_version,
                environment: c.corrected_model_environment,
                config_fingerprint: c.corrected_model_config_fingerprint,
                system_prompt_or_policy_id: c.corrected_model_system_prompt_or_policy_id,
                timestamp: c.corrected_model_timestamp,
            },
        });
    }

    let (model, model_provenance, input_fp, output_fp) = match attestation {
        Some(a) => {
            let row = AttestationRow {
                declaration: declaration_of(&a.declaration),
                no_ai_attestation: a.no_ai_attestation.clone(),
                unidentified_reason: a.unidentified_reason.clone(),
                provider: a.model_provider.clone(),
                model_name: a.model_name.clone(),
                model_version: a.model_version.clone(),
                prompt_version: a.prompt_version.clone(),
                environment: a.model_environment.clone(),
                config_fingerprint: a.model_config_fingerprint.clone(),
                system_prompt_or_policy_id: a.model_system_prompt_or_policy_id.clone(),
                model_timestamp: a.model_timestamp,
            };

            // The declaration as made at open, kept verbatim. Built from the
            // same row the effective identity is built from, and never
            // rewritten by a correction: it is what this organisation
            // asserted before it knew how the decision would turn out, which
            // is a fact about the organisation rather than about the model.
            let as_declared = DeclaredAttestation {
                declaration: a.declaration,
                no_ai_attestation: a.no_ai_attestation,
                unidentified_reason: a.unidentified_reason,
                identity: DeclaredIdentity {
                    provider: a.model_provider,
                    model_name: a.model_name,
                    model_version: a.model_version,
                    prompt_version: a.prompt_version,
                    environment: a.model_environment,
                    config_fingerprint: a.model_config_fingerprint,
                    system_prompt_or_policy_id: a.model_system_prompt_or_policy_id,
                    timestamp: a.model_timestamp,
                },
            };

            (
                // The latest correction wins, and the original is the answer
                // only until one exists. A reader who looks at `model` and
                // nothing else must not be handed an identity this
                // organisation has retracted — that reader is every reader,
                // and every tool written against schema 1.1.0.
                effective_from_correction
                    .clone()
                    .unwrap_or_else(|| model_intake::to_attestation(&row)),
                ModelProvenance::new(
                    Provenanced::recorded(a.created_at),
                    as_declared,
                    correction_entries.clone(),
                ),
                a.input_context_fingerprint,
                a.output_fingerprint,
            )
        }
        // No attestation row at all. Not the no-AI assertion — see
        // `model_intake::absent_attestation` — and not correctable either,
        // which is why `model_correction.rs` answers 409 here rather than
        // creating a declaration on the organisation's behalf. The
        // corrections read above is therefore empty by the foreign key, and
        // is not consulted.
        None => (
            model_intake::absent_attestation(),
            ModelProvenance::never_declared(NEVER_DECLARED),
            None,
            None,
        ),
    };

    const NEVER_DECLARED: &str =
        "this assessment was opened before model identity capture existed \
         (migrations/0006_decision_capture.sql), so no declaration was ever requested from the \
         calling system and there is none to correct. Absence of a declaration is not a \
         declaration of absence";

    const NO_FINGERPRINT: &str =
        "the calling system did not supply this digest on \
         POST /api/v1/issue-wealth-request; nothing in memtara-api can compute it, because \
         the context and output it commits to never reach this server";
    let provenanced = |v: Option<String>| match v {
        Some(x) => Provenanced::recorded(x),
        None => Provenanced::unpopulated(NO_FINGERPRINT),
    };

    // ---------------------------------------------------------------
    // HUMAN REVIEW.
    // ---------------------------------------------------------------
    let review_row = sqlx::query!(
        r#"
        select reviewer_id, reviewer_role, action, "override" as "overridden!", override_reason,
               review_duration_ms, review_duration_source, human_review_protocol_version,
               reviewed_at
        from decision_reviews
        where request_id = $1 and org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(db)
    .await?;

    // The disposition the automated path reached, used when nobody
    // reviewed. Derived from the verdict rather than defaulted, so an
    // unreviewed decline is `Rejected` and not an approval-shaped blank.
    let automated_action = match outcome {
        DecisionOutcome::Affirmative => DecisionAction::Approved,
        DecisionOutcome::Negative => DecisionAction::Rejected,
        DecisionOutcome::NoVerdict => unreachable!("refused above by not_decided_yet"),
    };

    let (review, status, decided_at) = match review_row {
        None => (
            HumanReviewInputs::not_performed(automated_action),
            automated_action,
            assessed_at,
        ),
        Some(r) => {
            let action = parse_action(&r.action)?;
            let over_ride = match (r.overridden, r.override_reason) {
                (false, _) => ReviewOverride::NotOverridden,
                // The DB constraint makes the `None` arm unreachable for any
                // row written through the endpoint. It is handled rather
                // than unwrapped because a record read out of a database is
                // input, and the honest failure for an impossible row is an
                // error, not a panic that takes the process down.
                (true, None) => {
                    return Err(ApiError::Other(anyhow::anyhow!(
                        "decision_reviews row for {request_id} has override=true with no reason, \
                         which decision_reviews_override_requires_reason forbids; the row was \
                         written around the schema"
                    )))
                }
                (true, Some(reason)) => {
                    crate::evidence::ReviewOverride::overridden(reason).map_err(|e| {
                        ApiError::Other(anyhow::anyhow!(
                            "decision_reviews row for {request_id} has an unusable override \
                             reason: {e}"
                        ))
                    })?
                }
            };
            let duration = match (r.review_duration_ms, r.review_duration_source) {
                (Some(ms), Some(source)) => Some((ms, source)),
                // Also guarded by a CHECK constraint; same reasoning.
                _ => None,
            };
            let reviewed_at = r.reviewed_at;
            (
                HumanReviewInputs::completed(CompletedReview {
                    reviewer_id: r.reviewer_id,
                    reviewer_role: r.reviewer_role,
                    action,
                    over_ride,
                    reviewed_at,
                    protocol_version: r.human_review_protocol_version,
                    duration,
                }),
                action,
                // The decision was reached when the human reached it. Using
                // `assessed_at` here would date an override to the moment
                // the proof landed, which is the one timestamp an override
                // is definitionally not contemporaneous with.
                reviewed_at,
            )
        }
    };

    // ---------------------------------------------------------------
    // Proofs and artefacts.
    // ---------------------------------------------------------------
    let proof_rows = sqlx::query!(
        r#"
        select valid, public_inputs, proof_bytes
        from proofs
        where request_id = $1
        order by verified_at asc
        "#,
        request_id,
    )
    .fetch_all(db)
    .await?;

    let vkey_path = std::path::Path::new(vkeys_dir)
        .join(CircuitType::WealthSuitability.as_str())
        .join("vk");
    let vkey_digest = match tokio::fs::read(&vkey_path).await {
        Ok(bytes) => hex(&<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&bytes))),
        // Empty rather than a plausible-looking placeholder: a digest an
        // examiner cannot match against `circuits/.../vk_hash` must not look
        // like one they can.
        Err(_) => String::new(),
    };

    // Every attempt, accepted and rejected — the same reasoning as the
    // route above. A record showing only the accepted proof hides the four
    // that failed first, which is exactly the pattern a reviewer looks for.
    let proofs: Vec<CryptographicProof> = proof_rows
        .iter()
        .map(|p| CryptographicProof {
            circuit: CircuitType::WealthSuitability.as_str().to_string(),
            proof_digest: proof_digest_hex(&p.proof_bytes),
            public_inputs: public_inputs_as_strings(&p.public_inputs),
            verification_key_digest: vkey_digest.clone(),
            accepted_by_bb_verify: p.valid,
        })
        .collect();

    let mut artifacts: Vec<EvidenceArtifact> = proofs
        .iter()
        .map(|p| EvidenceArtifact {
            artifact_type: "zk_proof".to_string(),
            // Relative to the verification bundle root, never an http URL:
            // a bundle that resolves its own contents over the network is
            // not offline-verifiable.
            uri: "proof/wealth_suitability.proof".to_string(),
            digest: p.proof_digest.clone(),
        })
        .collect();
    if !vkey_digest.is_empty() {
        artifacts.push(EvidenceArtifact {
            artifact_type: "verification_key".to_string(),
            uri: "vkey/wealth_suitability.vk".to_string(),
            digest: vkey_digest,
        });
    }

    let mut threshold_values = BTreeMap::new();
    threshold_values.insert("min_income".to_string(), json!(req.min_income));
    threshold_values.insert("min_liquidity".to_string(), json!(req.min_liquidity));
    threshold_values.insert(
        "max_concentration_percent".to_string(),
        json!(req.max_concentration_percent),
    );
    threshold_values.insert("product_risk_level".to_string(), json!(req.product_risk_level));

    Ok(EvidenceSources {
        outcome,
        status,
        decided_at,
        opened_at: req.created_at,
        assessed_at: Some(assessed_at),
        org: Institution {
            org_id: req.org_id,
            org_name: req.org_name,
            org_type: req.org_type,
        },
        subject_id: req.user_id.to_string(),
        consent,
        vault_root: match req.vault_root {
            Some(root) => Provenanced::recorded(format!("0x{}", hex(&root))),
            None => Provenanced::unpopulated(
                "this assessment was decided before the vault root was snapshotted onto the \
                 request (migrations/0007_threshold_and_vault_provenance.sql). The value was \
                 checked against the holder's registered root at submission and then discarded, \
                 so it cannot be recovered now: `vault_blobs.vault_root` moves on every sync and \
                 reading it today would quote a root this assessment was not computed against",
            ),
        },
        threshold_set_id: match req.product_id {
            Some(id) => Provenanced::recorded(id.to_string()),
            None => Provenanced::unpopulated(
                "the product registry row this assessment's thresholds came from has since been \
                 deleted; the threshold values themselves are snapshotted on the request and are \
                 unaffected",
            ),
        },
        threshold_version: match req.terms_version {
            Some(v) => Provenanced::recorded(v.to_string()),
            None => Provenanced::unpopulated(
                "this assessment was opened before products.terms_version existed \
                 (migrations/0007_threshold_and_vault_provenance.sql), so the threshold set it \
                 was measured against was genuinely unversioned. Writing `1` here would invent a \
                 fact",
            ),
        },
        threshold_values,
        model,
        model_provenance,
        input_context_fingerprint: provenanced(input_fp),
        output_fingerprint: provenanced(output_fp),
        review,
        artifacts,
        proofs,
    })
}

fn parse_action(s: &str) -> ApiResult<DecisionAction> {
    match s {
        "approved" => Ok(DecisionAction::Approved),
        "rejected" => Ok(DecisionAction::Rejected),
        "modified" => Ok(DecisionAction::Modified),
        other => Err(ApiError::Other(anyhow::anyhow!(
            "decision_reviews.action holds {other:?}, which the CHECK constraint forbids"
        ))),
    }
}

/// `proofs.public_inputs` is `jsonb`. The circuit's inputs are field
/// elements and reach us as an array of `0x`-prefixed hex strings; anything
/// else is rendered rather than dropped, because a public input missing from
/// the record is a public input an examiner cannot re-verify against.
fn public_inputs_as_strings(value: &serde_json::Value) -> Vec<String> {
    match value.as_array() {
        Some(items) => items
            .iter()
            .map(|v| match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            })
            .collect(),
        None => vec![],
    }
}

/// Build one decision's evidence record. The single construction site.
pub(super) async fn build_decision_evidence(
    db: &PgPool,
    vkeys_dir: &str,
    org_id: Uuid,
    request_id: Uuid,
) -> ApiResult<DecisionEvidence> {
    let s = gather(db, vkeys_dir, org_id, request_id).await?;

    // Derived, never assigned: no code path can reach an override without
    // the basis that names it, which is the variant a supervisor greps for.
    let basis = derive_decision_basis(&s.review);

    let record = DecisionEvidence::from_inputs(DecisionInputs {
        decision_id: request_id,
        institution: s.org,
        status: s.status,
        outcome: s.outcome,
        decided_at: s.decided_at,
        opened_at: s.opened_at,
        assessed_at: s.assessed_at,
        exported_at: Utc::now(),
        subject_id: s.subject_id,
        consent: s.consent,
        // Empty by design rather than by omission: the server never had the
        // client's income, liquidity, risk tolerance or holdings.
        disclosed_attributes: vec![],
        provenance_statement: "Memtara holds no income, liquidity, risk-tolerance or holdings \
                               figure for this subject. The assessment was computed on the \
                               holder's device and only its one-bit result was disclosed."
            .to_string(),
        policy_source: "disclosure_requests.policy, snapshotted at open".to_string(),
        threshold_source: "product registry, snapshotted when the assessment was opened"
            .to_string(),
        threshold_values: s.threshold_values,
        regulatory_control_mapping: vec![
            RegulatoryControl { framework: "DFSA".to_string(), clause: "COB 3.1".to_string() },
            RegulatoryControl { framework: "CBUAE".to_string(), clause: "5(c)".to_string() },
            RegulatoryControl { framework: "CBUAE".to_string(), clause: "5(d)".to_string() },
            RegulatoryControl { framework: "CBUAE".to_string(), clause: "4(a)".to_string() },
        ],
        model: s.model,
        model_provenance: s.model_provenance,
        human_review: s.review,
        evidence_artifacts: s.artifacts,
        cryptographic_proofs: s.proofs,
        business_process: Provenanced::recorded(BUSINESS_PROCESS.to_string()),
        decision_basis: Provenanced::recorded(basis),
        input_context_fingerprint: s.input_context_fingerprint,
        output_fingerprint: s.output_fingerprint,
        vault_root: s.vault_root,
        threshold_set_id: s.threshold_set_id,
        threshold_version: s.threshold_version,
    });

    // Belt and braces on the one pairing that can make a bypassed control
    // look clean. Unreachable through this path — the DB constraint and
    // `ReviewOverride` both prevent it — which is exactly why a failure here
    // would mean something has gone wrong that nobody predicted.
    record
        .validate_override_pairing()
        .map_err(|e| ApiError::Other(anyhow::anyhow!("{e}")))?;

    Ok(record)
}

/// The record plus the digest a seal would carry, so a caller can compare
/// bytes without re-deriving our canonicalisation rules.
#[derive(Debug, Serialize)]
pub(super) struct DecisionEvidenceResponse {
    pub decision_evidence: DecisionEvidence,
    /// SHA-256 over the canonical bytes — the same value that goes in a
    /// seal's `canonical_evidence_sha256`, computed the way
    /// `scripts/export_audit_evidence.py` computes it.
    pub canonical_evidence_sha256: String,
    pub evidence_schema: String,
    /// Whether the mutable rows this record was built from still say what
    /// the hash chain committed to. See `binding_integrity` below.
    ///
    /// `None` only on the paths that build a record without a database to
    /// check it against (the fixture builders in the tests below). A caller
    /// reading a served record always gets a value, because a record served
    /// with no integrity statement at all is exactly the silence this field
    /// exists to end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_integrity: Option<crate::audit::replay::ReplayReport>,
}

/// Envelope field, deliberately NOT part of the record.
///
/// Two reasons it sits beside `decision_evidence` rather than inside it.
/// The record is pinned by `schema/decision_evidence/vX.Y.Z.json` and is the
/// thing that gets sealed and canonicalised; a field whose value depends on
/// when you ask cannot live inside bytes whose whole purpose is to be
/// identical every time they are produced. And it is a claim ABOUT the
/// record, made by the server at read time, not a fact the record asserts —
/// putting it inside would let a tampered record vouch for itself.
pub(super) fn respond(record: DecisionEvidence) -> ApiResult<DecisionEvidenceResponse> {
    let digest = record
        .canonical_sha256_hex()
        .map_err(|e| ApiError::Other(anyhow::anyhow!("canonicalisation failed: {e}")))?;
    Ok(DecisionEvidenceResponse {
        evidence_schema: format!(
            "schema/decision_evidence/v{}.json",
            crate::evidence::EVIDENCE_SCHEMA_VERSION
        ),
        decision_evidence: record,
        canonical_evidence_sha256: digest,
        binding_integrity: None,
    })
}

pub(super) async fn get_decision_evidence(
    OrgAuth(org_id): OrgAuth,
    Path(request_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<DecisionEvidenceResponse>> {
    let record =
        build_decision_evidence(&state.db, &state.config.vkeys_dir, org_id, request_id).await?;
    let mut response = respond(record)?;

    // The binding check runs on every read of a record, not only when
    // someone thinks to ask.
    //
    // `tests/break_it/test_attack_04_model_identity_change.py` is the reason
    // it is here rather than only behind `GET /orgs/:id/audit-log/replay`. A
    // database UPDATE against `decision_model_attestations` changes the model
    // identity this record serves, and every value it serves it with — the
    // provenance still reads `state: "recorded"`, because from the record
    // builder's point of view nothing is wrong. If detecting that required a
    // second call to a second endpoint, the default behaviour of this system
    // would be to serve the altered identity silently, and a control nobody
    // invokes is not a control.
    //
    // Computed on a separate code path from the decision's own outcome and
    // reported separately, for the reason `docs/VERIFY.md` gives at length:
    // EVIDENCE INTEGRITY and DECISION OUTCOME answer different questions,
    // and a client that is unsuitable is not a record that is broken.
    // Every ref_id this decision's evidence rests on, not only the decision's
    // own. A correction's binding event is keyed on the CORRECTION ROW's id
    // rather than the request's — it has to be, because a rebuild must be a
    // pure function of one row (see
    // `binding::model_attestation_correction_payload`) — so scoping this
    // check to `request_id` alone would check the original attestation and
    // silently skip every correction that supersedes it. That is the worse
    // half to skip: the correction is the newer statement and the one an
    // examiner is reading the record for.
    let mut refs = vec![request_id];
    refs.extend(
        response
            .decision_evidence
            .model_provenance
            .corrections
            .iter()
            .map(|c| c.correction_id),
    );
    // The consent grant this decision was opened under, if it has one —
    // `consent_grant_bound` and any `consent_revocation_bound` are keyed on
    // the GRANT's own id (audit/binding.rs), not on `request_id`, for the
    // same structural reason a correction's binding is: the rebuild has to
    // be a pure function of one row, and that row is `consent_grants`, not
    // this decision.
    //
    // Read from `wealth_requests` directly rather than parsed back out of
    // the served record — deliberately NOT the correction pattern above,
    // which reuses ids the record already carries. The consent block
    // degrades to `unpopulated` (with `value: null`) the moment the grant
    // row is deleted, by design (`Consent`'s "grant was deleted" branch
    // above), so parsing the id out of the served string would lose it at
    // exactly the moment attack 8 step 4 needs it kept: replaying a grant's
    // binding events AFTER its row is gone is the entire point of a binding
    // event outliving its source row. `wealth_requests.consent_grant_id`
    // survives that deletion on purpose — see
    // migrations/0013_consent_grant_id_outlives_the_grant.sql — which is
    // what makes it, and not the record, the right place to read this from.
    let consent_grant_id: Option<Uuid> = sqlx::query_scalar!(
        "select consent_grant_id from wealth_requests where request_id = $1",
        request_id,
    )
    .fetch_optional(&state.db)
    .await?
    .flatten();
    refs.extend(consent_grant_id);

    let mut conn = state.db.acquire().await?;
    response.binding_integrity =
        Some(crate::audit::replay::replay_refs(&mut conn, org_id, &refs).await?);

    Ok(Json(response))
}
