// Structured-product suitability: DFSA Conduct of Business 3.1, evidenced
// by a zero-knowledge proof instead of a filing cabinet.
//
// The regulated act is narrow. Before a firm recommends a structured product
// it must satisfy itself the product is suitable for that client, and be
// able to show it did. Conventionally that means collecting salary slips,
// portfolio statements and a risk questionnaire, and retaining them — the
// firm ends up holding a complete picture of the client's finances in order
// to justify a single yes/no.
//
// Here the client's device evaluates the four COB 3.1 limbs against the
// product's published terms inside `circuits/wealth_suitability`, and the
// firm receives one bit plus a proof. The bank can show the regulator
// exactly what it assessed, against which terms, for which instrument, and
// can re-verify it years later — while holding none of the underlying
// figures.
//
// Two endpoints, deliberately separate from the generic issuance surface:
//
//   POST /api/v1/issue-wealth-request  (org)    opens an assessment and
//                                               fixes the terms
//   POST /api/v1/submit-wealth-proof   (client) answers it
//
// -------------------------------------------------------------------
// WHY THIS ISN'T JUST ANOTHER `issue-proof` PREDICATE
// -------------------------------------------------------------------
// `issuance::issue_proof` mints a token when a proof verifies. That is the
// whole check, and for the four asserting circuits it is sufficient: those
// circuits are unsatisfiable unless the predicate holds, so "a proof exists"
// IS the answer.
//
// `wealth_suitability` is not like that. It has a public output, and a proof
// of "not suitable" verifies exactly as cleanly as a proof of "suitable".
// Two further checks are therefore mandatory here and absent there:
//
//   1. The submitted public inputs must match the terms the ORG registered
//      when it opened the request. Without this, a client picks its own
//      `min_income` — proving suitability against a threshold of zero is
//      trivially satisfiable and cryptographically impeccable.
//
//   2. The circuit's output must be read, not inferred. A caller that
//      treats a successful `bb verify` as approval will approve every
//      client who fails the assessment.
//
// `issuance` refuses the predicate outright rather than trusting anyone to
// remember this (see `issuance::Issuer`).

mod evidence;
mod model_correction;
mod model_intake;
mod review;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::signer::{proof_digest_hex, ProofTokenClaims};
use crate::domain::CircuitType;
use crate::error::{ApiError, ApiResult};
use crate::issuance::lookup_predicate;
use crate::orgs::OrgAuth;
use crate::state::AppState;
use crate::verify::{parse_field_hex, public_input_layout};

/// The predicate name that lands in the issued token. Registered in
/// `issuance::PREDICATES` so `GET /api/v1/predicates` documents it and so
/// the CBUAE/DFSA citations have one source of truth.
const PREDICATE: &str = "structured_product_suitable";

/// Default assessment window if the caller doesn't specify one. 15 minutes:
/// long enough for a client to approve a prompt on their phone, short enough
/// that a stale assessment can't be presented as a current one.
const DEFAULT_TTL_SECONDS: i64 = 900;
const MIN_TTL_SECONDS: i64 = 60;
const MAX_TTL_SECONDS: i64 = 24 * 3600;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/issue-wealth-request", post(issue_wealth_request))
        .route("/api/v1/submit-wealth-proof", post(submit_wealth_proof))
        .route(
            "/api/v1/wealth-assessments/:request_id",
            axum::routing::get(evidence::get_wealth_assessment),
        )
        // The DecisionEvidence v1.1.0 record for one assessment: the object
        // an offline auditor validates against
        // `schema/decision_evidence/v1.1.0.json`. Separate from the route
        // above rather than replacing it — that one is the operational view
        // a bank's own tooling already consumes, this one is the sealed
        // shape, and collapsing them would make every change to either a
        // breaking change to both.
        .route(
            "/api/v1/wealth-assessments/:request_id/decision-evidence",
            axum::routing::get(evidence::get_decision_evidence),
        )
        // Per-decision human review. The control the "bypass human review"
        // attack had nothing to bypass until now.
        .route(
            "/api/v1/wealth-assessments/:request_id/review",
            post(review::submit_review),
        )
        // Corrections to a decision's model attestation. A COLLECTION, and
        // plural in the path, because the attestation is written before the
        // decision exists and an organisation may have to contradict it more
        // than once — the first correction naming a replacement model, a
        // later one admitting the replacement cannot be stood behind either.
        // Not a PATCH on the assessment: the attestation is a statement a
        // named party made at a named time, not a mutable property of the
        // decision, and the original row is never altered.
        .route(
            "/api/v1/wealth-assessments/:request_id/model-corrections",
            post(model_correction::submit_model_correction),
        )
}

/// The firm's own process taxonomy entry for what this module does.
///
/// Not `CircuitType::WealthSuitability.as_str()`, which names a *proof type*.
/// Conflating the two would put a cryptographic artefact where a regulator
/// expects a bank's process taxonomy — "wealth_suitability" answers "how was
/// it proved", and `business_process` answers "what was being decided".
/// Still a constant rather than a lookup table: the module that implements a
/// process is the one entitled to name it, and a config table with one row
/// in it would be indirection pretending to be flexibility.
pub(crate) const BUSINESS_PROCESS: &str = "wealth.suitability_recommendation";

// ---------------------------------------------------------------------
// ISIN handling
//
// Validation lives in `products::isin`, because the registry is where an
// identifier enters the system: by the time this module sees an ISIN it has
// already been through `products::normalise_isin` and been stored. What
// stays here is the derivation that binds it into the circuit.
// ---------------------------------------------------------------------

/// The `product_ref` field element bound into the circuit and into the
/// commitment the client signs.
///
/// SHA-256 over a domain-separated encoding of the ISIN, with the top byte
/// zeroed so the result is guaranteed below the BN254 scalar modulus without
/// doing modular reduction here — the same 248-bit trick
/// `disclosure::generate_nonce` uses, and for the same reason.
///
/// Domain separation (`memtara:isin:v1:`) means this digest can never
/// collide with a hash of something else in the system that happens to share
/// bytes with an ISIN.
pub(crate) fn product_ref(isin: &str) -> [u8; 32] {
    let mut out: [u8; 32] = Sha256::digest(format!("memtara:isin:v1:{isin}").as_bytes()).into();
    out[0] = 0;
    out
}

fn hex_0x(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Interpret a 32-byte big-endian field element as a u64, refusing anything
/// that doesn't fit rather than truncating. A truncating read here would let
/// a client smuggle a huge value past a threshold comparison by having it
/// wrap to something small.
fn field_to_u64(bytes: &[u8; 32]) -> Option<u64> {
    if bytes[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&bytes[24..]);
    Some(u64::from_be_bytes(v))
}

fn generate_nonce() -> Vec<u8> {
    // 31 random bytes in a 32-byte big-endian buffer — identical rationale
    // to disclosure::generate_nonce (stay below the BN254 modulus without
    // bignum reduction, and compare byte-for-byte against how bb packs a
    // Field).
    let mut nonce = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce[1..]);
    nonce
}

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------
// POST /api/v1/issue-wealth-request
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IssueWealthRequestBody {
    pub user_id: Uuid,
    pub product_isin: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,

    // ---------------------------------------------------------------
    // MODEL identity intake. See `model_intake` for the contract and for
    // why omission maps to "an AI participated and we cannot say which"
    // rather than to the assertion that none did.
    //
    // `Option`, not required, and that is a considered choice rather than
    // laxity. Making it mandatory would 400 every existing integration,
    // and an endpoint that returns 400 is an endpoint a bank routes
    // around — the pressure would land on getting the field *present*,
    // which is exactly the pressure that produces a stock declaration
    // pasted into every call. Optional-but-never-flattering keeps the
    // cost of silence on the record instead of on the integration: a
    // caller that says nothing gets a record that says nothing was
    // established, which is true, and which is visible in the export.
    // ---------------------------------------------------------------
    /// Untyped here on purpose — see `model_intake::resolve_value`. Typing
    /// it as the enum would hand a malformed declaration to axum's `Json`
    /// rejection, which answers 422 "Failed to deserialize the JSON body"
    /// and names nothing. The refusal would still be safe; it would just be
    /// useless to the integrator who most needs it.
    #[serde(default)]
    pub ai_participation: Option<serde_json::Value>,

    /// SHA-256 over the context the deciding system saw, computed by the
    /// caller. A sibling of the model block rather than a child of it: when
    /// no AI participated the decision still had inputs, and a fingerprint
    /// that disappeared along with the model would leave a non-AI decision
    /// with nothing committing to what it was decided on.
    #[serde(default)]
    pub input_context_fingerprint: Option<String>,
    /// SHA-256 over the deciding system's structured output. Distinct from
    /// `proof_sha256`, which digests the *proof*: a proof digest commits to
    /// the artefact that was verified, not to what the model said.
    #[serde(default)]
    pub output_fingerprint: Option<String>,

    // ---------------------------------------------------------------
    // Accepted by the parser, refused by the handler.
    //
    // These four used to be the request's terms. They now live in the
    // product registry, and the endpoint reads them there. Deserializing
    // them anyway — rather than letting `serde` ignore unknown fields —
    // is what makes the refusal possible.
    //
    // Silently ignoring them would be the dangerous option, and it is the
    // one that happens by default. An advisor's integration that still
    // posts `min_income: 0` would keep returning 201, the assessment would
    // run against the registry's real threshold, and nobody would learn
    // that the caller believed it was setting the bar. That belief is
    // worth surfacing loudly once rather than leaving latent.
    // ---------------------------------------------------------------
    #[serde(default)]
    pub min_income: Option<i64>,
    #[serde(default)]
    pub min_liquidity: Option<i64>,
    #[serde(default)]
    pub max_concentration_percent: Option<i16>,
    #[serde(default)]
    pub product_risk_level: Option<i16>,
}

#[derive(Serialize)]
pub struct IssueWealthRequestResponse {
    pub request_id: Uuid,
    pub circuit: String,
    /// Base64url-no-pad. The exact bytes the client must supply as the
    /// `nonce` public input and bind into the signed commitment.
    pub nonce: String,
    /// `0x`-prefixed hex. Derived from the ISIN by `product_ref`; returned
    /// so the client doesn't have to reimplement the derivation and risk
    /// disagreeing with the server about it.
    pub product_ref: String,
    pub product_isin: String,
    /// From the registry, snapshotted onto this request. Echoed so the
    /// advisor-facing surface can name the instrument without a second
    /// lookup, and so the injected AI claim can say what was assessed.
    pub product_name: String,
    /// The registry row these terms came from. The evidence exporter follows
    /// it to show which catalogue entry, under which governance state,
    /// supplied the thresholds.
    pub product_id: Uuid,
    pub min_income: i64,
    pub min_liquidity: i64,
    pub max_concentration_percent: i16,
    pub product_risk_level: i16,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub expires_in: i64,
    /// The public-input vector the client must produce, in order, with every
    /// server-fixed value already filled in and the client-supplied ones
    /// named. Returned because the ordering is a protocol detail the client
    /// has no other way to learn, and getting it wrong produces a proof that
    /// fails verification with no clue as to why.
    pub public_input_template: Vec<serde_json::Value>,

    /// Which of the three AI-participation declarations was written into
    /// this decision's evidence.
    ///
    /// Echoed because the difference between them is invisible at
    /// integration time and expensive at export time. An integrator who
    /// meant to declare a model and mistyped a field would otherwise
    /// discover it in a compliance export months later, by which point the
    /// records are sealed and cannot be corrected. This costs one string and
    /// makes the mistake visible on the first call.
    pub ai_participation_recorded: model_intake::RecordedDeclaration,

    /// The monotonic version of the threshold set this assessment was fixed
    /// against (`products.terms_version`, snapshotted). Returned so a caller
    /// can name the exact version its recommendation was measured under
    /// without re-reading the registry, which may have moved on by then.
    pub threshold_version: i32,
}

async fn issue_wealth_request(
    OrgAuth(org_id): OrgAuth,
    State(state): State<AppState>,
    Json(body): Json<IssueWealthRequestBody>,
) -> ApiResult<(StatusCode, Json<IssueWealthRequestResponse>)> {
    // Refuse caller-supplied terms before doing anything else, so an
    // integration that has not been updated fails immediately and visibly
    // rather than succeeding against thresholds it did not choose.
    let supplied: Vec<&str> = [
        body.min_income.map(|_| "min_income"),
        body.min_liquidity.map(|_| "min_liquidity"),
        body.max_concentration_percent.map(|_| "max_concentration_percent"),
        body.product_risk_level.map(|_| "product_risk_level"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !supplied.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "suitability terms are no longer accepted here ({} supplied). They come from the \
             product registry — register the instrument with POST /api/v1/products, and the \
             assessment will be measured against the terms recorded there. A recommendation \
             assessed against thresholds chosen by whoever is making it is not an assessment",
            supplied.join(", "),
        )));
    }

    // The assessment's open time, taken once and used for both the intake
    // check and the window below. Taken HERE rather than beside the inserts
    // so that the declared model-call timestamp is measured against the
    // moment this request arrived, not against a moment several database
    // round trips later — the two differ by however long the product lookup
    // took, which is not a fact about the model and should not move a bound.
    let opened_at = Utc::now();

    // Resolved before any write, so a malformed declaration costs the caller
    // a 400 and costs the database nothing. `None` is not an error here — it
    // resolves to `participated_but_unidentified`, which is the honest
    // reading of silence and the only reading that cannot flatter.
    //
    // `opened_at` is passed in because `ai_participation.timestamp` is the
    // only leaf of the model block that can be checked against anything this
    // server knows, and until this pass nothing checked it: attack 11
    // declares a model call three years before the assessment and the row
    // took it verbatim.
    let attestation =
        model_intake::resolve_value(body.ai_participation.clone(), opened_at)?;
    let input_context_fingerprint = body
        .input_context_fingerprint
        .as_deref()
        .map(|v| model_intake::parse_digest("input_context_fingerprint", v))
        .transpose()?;
    let output_fingerprint = body
        .output_fingerprint
        .as_deref()
        .map(|v| model_intake::parse_digest("output_fingerprint", v))
        .transpose()?;

    let isin = crate::products::normalise_isin(&body.product_isin)?;

    // The terms. Read, not accepted.
    let product = crate::products::load(&state.db, org_id, &isin).await.map_err(|e| match e {
        ApiError::NotFound => ApiError::NotFoundDetail(format!(
            "product '{isin}' is not in this organisation's registry; register it with \
             POST /api/v1/products first"
        )),
        other => other,
    })?;

    // Product governance is a precondition, not a label. An assessment
    // against an unapproved instrument produces evidence that a controlled
    // process was followed when it was not, which is worse than producing no
    // evidence at all.
    if !product.approved_by_risk_committee {
        return Err(ApiError::Conflict(format!(
            "product '{isin}' has not been approved by the risk committee and cannot be \
             assessed against; approve it with PATCH /api/v1/products/{isin}"
        )));
    }

    let ttl = body.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )));
    }

    let user_exists =
        sqlx::query_scalar!(r#"select exists(select 1 from users where id = $1) as "exists!""#, body.user_id)
            .fetch_one(&state.db)
            .await?;
    if !user_exists {
        return Err(ApiError::NotFoundDetail(format!("no user {}", body.user_id)));
    }

    // -----------------------------------------------------------------
    // CONSENT. Refuse before anything else about this decision is written,
    // naming the covering grant's absence or its revocation — never a bare
    // 403. `consents::require_covering_grant` is the one place "does a
    // grant cover this purpose" is decided; see its doc comment and
    // `docs/STAGE_PLAN_CONSENT_AND_WITNESS.md` §A3 for why a decision
    // already opened under a since-revoked grant STANDS rather than being
    // unwound here — this check runs once, at open, and its answer is what
    // the decision's evidence (`wealth/evidence.rs`) later shows as the
    // consent basis it was opened under.
    let consent_grant_id =
        crate::consents::require_covering_grant(&state.db, org_id, body.user_id, BUSINESS_PROCESS)
            .await?;

    // Read separately rather than added to `products::ProductRow`, which
    // belongs to the registry module. The column is new (migrations/0007)
    // and the trigger that maintains it is the authority on its value; this
    // is the read that snapshots it onto the assessment.
    let terms_version: i32 = sqlx::query_scalar!(
        r#"select terms_version as "terms_version!" from products where id = $1"#,
        product.id,
    )
    .fetch_one(&state.db)
    .await?;

    let window_start = opened_at;
    let window_end = window_start + Duration::seconds(ttl);
    let nonce = generate_nonce();
    let product_ref_bytes = product_ref(&isin);

    // The `policy` column is typed as the vault's own `SessionPolicy` by the
    // generic disclosure routes, so it has to deserialize as one — the terms
    // themselves live in `wealth_requests` where they can be typed and
    // constrained. `Custom` is the honest session type: this is not one of
    // the four the vault enumerates.
    let policy = serde_json::json!({
        "session_type": "Custom",
        "purpose_hash": Sha256::digest(b"memtara:purpose:structured_product_suitability")
            .iter()
            .copied()
            .collect::<Vec<u8>>(),
        "categories": ["financial"],
        "duration_seconds": ttl,
        "predicates": [],
        "max_payload_size": null,
    });

    let mut tx = state.db.begin().await?;

    let request_id: Uuid = sqlx::query_scalar!(
        r#"
        insert into disclosure_requests (org_id, user_id, circuit_type, policy, status, nonce, expires_at)
        values ($1, $2, $3, $4, 'pending', $5, $6)
        returning id
        "#,
        org_id,
        body.user_id,
        CircuitType::WealthSuitability.as_str(),
        policy,
        nonce,
        window_end,
    )
    .fetch_one(&mut *tx)
    .await?;

    // The terms are copied out of the registry into this row rather than
    // joined to it at submission time. That snapshot is what makes an
    // assessment reproducible: amending the product tomorrow must not change
    // what today's proof was measured against, and `submit_wealth_proof`
    // checks the submitted public inputs against these columns, never
    // against `products`.
    sqlx::query!(
        r#"
        insert into wealth_requests (
            request_id, product_id, product_isin, product_name, product_ref,
            min_income, min_liquidity, max_concentration_percent, product_risk_level,
            window_start, window_end, terms_version, consent_grant_id
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
        request_id,
        product.id,
        isin,
        product.product_name,
        &product_ref_bytes[..],
        product.min_income,
        product.min_liquidity,
        product.max_concentration_percent,
        product.risk_level,
        window_start,
        window_end,
        terms_version,
        consent_grant_id,
    )
    .execute(&mut *tx)
    .await?;

    // The model attestation, in the same transaction as the request it is
    // about. A decision that exists without a declaration of whether an AI
    // took part is the exact gap the board named, and it must not be
    // reachable by a partial failure: either both rows land or neither does.
    sqlx::query!(
        r#"
        insert into decision_model_attestations (
            request_id, org_id, declaration, no_ai_attestation, unidentified_reason,
            model_provider, model_name, model_version, prompt_version, model_environment,
            model_config_fingerprint, model_system_prompt_or_policy_id, model_timestamp,
            input_context_fingerprint, output_fingerprint
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
        request_id,
        org_id,
        attestation.declaration,
        attestation.no_ai_attestation,
        attestation.unidentified_reason,
        attestation.provider,
        attestation.model_name,
        attestation.model_version,
        attestation.prompt_version,
        attestation.environment,
        attestation.config_fingerprint,
        attestation.system_prompt_or_policy_id,
        attestation.model_timestamp,
        input_context_fingerprint,
        output_fingerprint,
    )
    .execute(&mut *tx)
    .await?;

    // Same transaction as both inserts: a suitability request that exists
    // without a corresponding trail entry is precisely the gap COB 3.1
    // record-keeping is meant to close.
    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "wealth_suitability_requested",
        Some(request_id),
        serde_json::json!({
            "user_id": body.user_id,
            "product_id": product.id,
            "product_isin": isin,
            "product_name": product.product_name,
            "min_income": product.min_income,
            "min_liquidity": product.min_liquidity,
            "max_concentration_percent": product.max_concentration_percent,
            "product_risk_level": product.risk_level,
            // Recorded so the case file can show the terms were not chosen
            // by whoever opened the assessment.
            "terms_source": "product_registry",
            "product_registry_updated_at": product.updated_at,
            // Which version of the threshold set this assessment is fixed
            // against. Previously answerable only by replaying every
            // `product_terms_amended` event and counting.
            "threshold_version": terms_version,
            // In the hashed payload, not only in the row: the chain is the
            // evidence and the table is the index (see 0005's note). A firm
            // that later disputes which declaration it made can be shown the
            // event, not just the row someone could have updated.
            "ai_participation_declared": attestation.declaration,
            // The grant this decision was authorised under. Narrative only —
            // this event's payload is `PayloadEncoding::Serde` and is never
            // rebuilt, so it is not what makes the consent basis tamper-
            // evident. That is `consent_grant_bound`/`consent_revocation_
            // bound` (audit/binding.rs), keyed on the grant's own id.
            "consent_grant_id": consent_grant_id,
            "dfsa_rules": ["COB 3.1"],
        }),
    )
    .await?;

    // Bind the two rows this decision is about to be judged on — the model
    // identity that was declared, and the predicate set it will be measured
    // against — into the hash chain, in the same transaction that created
    // them.
    //
    // The event above records THAT a declaration was made. These record WHAT
    // it said. Until they existed, an UPDATE against
    // `decision_model_attestations` could rewrite the model the sealed record
    // serves — up to and including moving it to `no_ai_participated`, so the
    // record asserted no AI took part in a decision opened naming one — and
    // leave the chain byte-identical. `audit/binding.rs` carries the full
    // argument; `tests/break_it/test_attack_04_change_model_identity.py` is
    // the demonstration that made it necessary.
    crate::audit::binding::record_model_attestation_binding(&mut tx, org_id, request_id).await?;
    crate::audit::binding::record_policy_binding(&mut *tx, org_id, request_id).await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(IssueWealthRequestResponse {
            request_id,
            circuit: CircuitType::WealthSuitability.as_str().to_string(),
            nonce: encode_b64(&nonce),
            product_ref: hex_0x(&product_ref_bytes),
            product_isin: isin,
            product_name: product.product_name.clone(),
            product_id: product.id,
            min_income: product.min_income,
            min_liquidity: product.min_liquidity,
            max_concentration_percent: product.max_concentration_percent,
            product_risk_level: product.risk_level,
            window_start,
            window_end,
            expires_in: ttl,
            public_input_template: public_input_template(
                window_end,
                &product_ref_bytes,
                product.min_income,
                product.min_liquidity,
                product.max_concentration_percent,
                product.risk_level,
                &nonce,
            ),
            ai_participation_recorded: attestation.recorded_declaration(),
            threshold_version: terms_version,
        }),
    ))
}

/// The 12-element public input vector, annotated. Fixed values are given
/// literally; the four the client owns are marked `client`.
fn public_input_template(
    window_end: DateTime<Utc>,
    product_ref_bytes: &[u8; 32],
    min_income: i64,
    min_liquidity: i64,
    max_concentration_percent: i16,
    product_risk_level: i16,
    nonce: &[u8],
) -> Vec<serde_json::Value> {
    fn fixed(name: &str, value: String) -> serde_json::Value {
        serde_json::json!({ "name": name, "value": value })
    }
    fn client(name: &str, note: &str) -> serde_json::Value {
        serde_json::json!({ "name": name, "value": "client", "note": note })
    }
    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(nonce);

    vec![
        client("current_time", "unix seconds, must fall inside [window_start, window_end]"),
        fixed("expiry_time", format!("0x{:x}", window_end.timestamp())),
        client("vault_root", "must equal the vault root registered via PUT /vault"),
        fixed("product_ref", hex_0x(product_ref_bytes)),
        fixed("min_income", format!("0x{min_income:x}")),
        fixed("min_liquidity", format!("0x{min_liquidity:x}")),
        fixed("max_concentration_percent", format!("0x{max_concentration_percent:x}")),
        fixed("product_risk_level", format!("0x{product_risk_level:x}")),
        client("user_public_key_x", "Baby Jubjub public key, x"),
        client("user_public_key_y", "Baby Jubjub public key, y"),
        fixed("nonce", hex_0x(&nonce_bytes)),
        client("suitable", "circuit output: 0 or 1 — not chosen by the client, produced by the proof"),
    ]
}

// ---------------------------------------------------------------------
// POST /api/v1/submit-wealth-proof
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SubmitWealthProofBody {
    pub request_id: Uuid,
    /// 12 `0x`-prefixed hex field elements in circuit order.
    pub public_inputs: Vec<String>,
    /// base64url-no-pad `bb` proof bytes.
    pub proof: String,
}

#[derive(Serialize)]
pub struct SubmitWealthProofResponse {
    pub proof_token: String,
    pub expires_in: i64,
    /// The circuit's verdict, echoed outside the token so a caller can act
    /// on it without decoding the JWT. Authoritative copy is the `suitable`
    /// claim inside the signed token.
    pub suitable: bool,
    pub product_isin: String,
    /// As recorded on the request, not as the registry reads today — see the
    /// snapshot note in `issue_wealth_request`.
    pub product_name: Option<String>,
    pub regulatory_audit_id: Uuid,
}

async fn submit_wealth_proof(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<SubmitWealthProofBody>,
) -> ApiResult<(StatusCode, HeaderMap, Json<SubmitWealthProofResponse>)> {
    let terms = sqlx::query!(
        r#"
        select w.product_isin, w.product_name, w.product_ref, w.min_income, w.min_liquidity,
               w.max_concentration_percent, w.product_risk_level,
               w.window_start, w.window_end, w.suitable,
               d.user_id, d.org_id
        from wealth_requests w
        join disclosure_requests d on d.id = w.request_id
        where w.request_id = $1
        "#,
        body.request_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    if terms.suitable.is_some() {
        return Err(ApiError::Conflict("this suitability request has already been assessed".into()));
    }

    // Rate limit here — after the one indexed lookup that resolves the key,
    // and before everything expensive. The key is the request's own
    // `user_id`, not anything the caller supplies, so a caller cannot reset
    // its own bucket by relabelling itself.
    //
    // Deliberately no audit event on a refusal. `audit_log` is an
    // append-only hash chain, so emitting an entry per rejected request
    // would hand an unauthenticated caller a way to grow it without bound —
    // turning a rate limit into an amplification vector against the very
    // structure it is protecting. A refusal is a log line and a counter.
    let decision = state.rate_limiter.check(&terms.user_id.to_string());
    if !decision.allowed {
        tracing::warn!(
            user_id = %terms.user_id,
            request_id = %body.request_id,
            "proof submission rate limited"
        );
        return Err(ApiError::RateLimitedRetryAfter {
            retry_after_seconds: decision.reset_after_seconds,
            message: format!(
                "too many proof submissions for this user; the limit is {} per {} seconds",
                state.rate_limiter.limit(),
                state.config.proof_rate_limit_window.as_secs(),
            ),
        });
    }

    let layout = public_input_layout(CircuitType::WealthSuitability);
    if body.public_inputs.len() != layout.count {
        return Err(ApiError::BadRequest(format!(
            "wealth_suitability expects exactly {} public inputs, got {}",
            layout.count,
            body.public_inputs.len()
        )));
    }

    let parsed: Vec<[u8; 32]> = body
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, s)| parse_field_hex(i, s))
        .collect::<ApiResult<Vec<_>>>()?;

    // -----------------------------------------------------------------
    // The terms check. This is the load-bearing part of this handler.
    //
    // `bb verify` will happily confirm a proof that the client's income
    // exceeds zero. It is this comparison — submitted public inputs against
    // the terms the ORG registered before the client ever saw the request —
    // that makes the verdict mean what the bank thinks it means.
    // -----------------------------------------------------------------
    let mismatch = |field: &str, expected: String, got: &str| {
        ApiError::BadRequest(format!(
            "public input '{field}' does not match the terms this request was opened with \
             (expected {expected}, got {got}); a suitability verdict is only meaningful against \
             the product's registered terms"
        ))
    };

    let expect_u64 = |index: usize, name: &str, expected: i64| -> ApiResult<()> {
        let got = field_to_u64(&parsed[index])
            .ok_or_else(|| ApiError::BadRequest(format!("public input '{name}' does not fit in a u64")))?;
        if got as i64 != expected {
            return Err(mismatch(name, expected.to_string(), &got.to_string()));
        }
        Ok(())
    };

    if parsed[3] != terms.product_ref.as_slice() {
        return Err(mismatch("product_ref", terms.product_isin.clone(), &body.public_inputs[3]));
    }
    expect_u64(4, "min_income", terms.min_income)?;
    expect_u64(5, "min_liquidity", terms.min_liquidity)?;
    expect_u64(6, "max_concentration_percent", terms.max_concentration_percent as i64)?;
    expect_u64(7, "product_risk_level", terms.product_risk_level as i64)?;
    expect_u64(1, "expiry_time", terms.window_end.timestamp())?;

    // `current_time` is the client's claim about when it ran the assessment.
    // The circuit constrains it to the session window relative to the
    // client's own `start_time` witness, which the client also supplies — so
    // the circuit alone cannot stop a client from proving inside a window of
    // its own invention. Pinning it to the server's window here is what
    // makes the assessment contemporaneous.
    let current_time = field_to_u64(&parsed[0])
        .ok_or_else(|| ApiError::BadRequest("public input 'current_time' does not fit in a u64".into()))?
        as i64;
    if current_time < terms.window_start.timestamp() || current_time > terms.window_end.timestamp() {
        return Err(ApiError::BadRequest(format!(
            "public input 'current_time' ({current_time}) is outside this request's assessment window \
             [{}, {}]",
            terms.window_start.timestamp(),
            terms.window_end.timestamp(),
        )));
    }

    // The vault root must be the one this user actually registered. Without
    // this the Merkle limb inside the circuit proves only that the figures
    // are consistent with *some* tree — which a client can build to order.
    //
    // Note this is stronger than what the four session circuits get today:
    // `verify::verify_against_request` does not pin the root. Retrofitting
    // it there is a real improvement and a deliberate non-goal of this pass;
    // it is recorded as a gap in docs/REGULATORY_MATRIX.md rather than
    // silently left unmentioned.
    let registered_root = sqlx::query_scalar!(
        "select vault_root from vault_blobs where user_id = $1",
        terms.user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        ApiError::Conflict(
            "this user has no synced vault, so there is no committed root to check the \
             assessment against — sync the vault before proving"
                .into(),
        )
    })?;

    if parsed[2].as_slice() != registered_root.as_slice() {
        return Err(mismatch("vault_root", encode_b64(&registered_root), &body.public_inputs[2]));
    }

    // Cryptography last, and only through the shared pipeline: authorization,
    // nonce binding, replay consumption, `bb verify`, and the proofs/audit
    // rows all happen in `verify_against_request`. Reimplementing any of it
    // here is how the two paths drift apart.
    let proof_bytes = crate::verify::verify_and_consume(
        &state,
        &headers,
        body.request_id,
        Some(CircuitType::WealthSuitability),
        &body.public_inputs,
        &body.proof,
    )
    .await?;

    // Read the verdict. Do not infer it.
    let outcome_index = layout
        .outcome_index
        .ok_or_else(|| ApiError::Other(anyhow::anyhow!("wealth_suitability layout has no outcome index")))?;
    let suitable = match field_to_u64(&parsed[outcome_index]) {
        Some(0) => false,
        Some(1) => true,
        _ => {
            return Err(ApiError::BadRequest(
                "public output 'suitable' is neither 0 nor 1; the circuit produces a boolean and \
                 anything else means the submitted public inputs do not belong to this circuit"
                    .into(),
            ))
        }
    };

    let spec = lookup_predicate(PREDICATE)?;
    let regulatory_audit_id = Uuid::new_v4();
    let now = Utc::now().timestamp();
    let ttl = state.config.proof_token_ttl_seconds;

    let claims = ProofTokenClaims {
        iss: state.signer.issuer().to_string(),
        sub: terms.user_id.to_string(),
        user_id: terms.user_id.to_string(),
        predicate: PREDICATE.to_string(),
        // `verified` is about the proof, not the answer: the assessment was
        // performed and cryptographically checked. `suitable` carries the
        // answer, and it is legitimately false sometimes.
        verified: true,
        circuit: CircuitType::WealthSuitability.as_str().to_string(),
        proof_hash: proof_digest_hex(&proof_bytes),
        regulatory_audit_id: regulatory_audit_id.to_string(),
        cbuae_clauses: spec.cbuae_clauses.clone(),
        product_isin: Some(terms.product_isin.clone()),
        suitable: Some(suitable),
        dfsa_rules: spec.dfsa_rules.clone(),
        iat: now,
        exp: now + ttl,
        jti: Uuid::new_v4().to_string(),
    };

    let proof_token = state
        .signer
        .issue(&claims)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("failed to sign suitability token: {e}")))?;

    // `vault_root` is written here and not at open time, and is snapshotted
    // rather than joined.
    //
    // By this line the value has been checked twice: bound into the circuit
    // as public input 2, and compared byte-for-byte against the holder's
    // registered `vault_blobs.vault_root` a hundred lines above. It is the
    // nearest thing to a provenance proof this system has, and until now it
    // was discarded the moment that comparison passed —
    // `data.customer.data_provenance.vault_root` sat unpopulated in the
    // evidence record while the value itself flowed through this handler.
    //
    // Not a join, because `vault_blobs.vault_root` moves every time the
    // holder syncs. An evidence record that resolved it live would quote
    // today's root as the one this assessment was computed against, which is
    // a false statement in signed bytes and worse than the empty field it
    // replaces.
    sqlx::query!(
        "update wealth_requests set suitable = $2, assessed_at = now(), vault_root = $3 \
         where request_id = $1",
        body.request_id,
        suitable,
        &parsed[2][..],
    )
    .execute(&state.db)
    .await?;

    crate::audit::record(
        &state.db,
        Some(terms.org_id),
        "wealth_suitability_assessed",
        Some(body.request_id),
        serde_json::json!({
            "regulatory_audit_id": regulatory_audit_id,
            "user_id": terms.user_id,
            "product_isin": terms.product_isin,
            "product_name": terms.product_name,
            "predicate": PREDICATE,
            "circuit": CircuitType::WealthSuitability.as_str(),
            "suitable": suitable,
            "min_income": terms.min_income,
            "min_liquidity": terms.min_liquidity,
            "max_concentration_percent": terms.max_concentration_percent,
            "product_risk_level": terms.product_risk_level,
            "cbuae_clauses": spec.cbuae_clauses,
            "dfsa_rules": spec.dfsa_rules,
            "proof_hash": claims.proof_hash,
            "jti": claims.jti,
            "expires_at": claims.exp,
        }),
    )
    .await?;

    // Advertised on the way out, not only on the way to a refusal: a client
    // that can see its budget shrinking can back off before it is refused,
    // and one that only learns the limit exists by hitting it cannot.
    let mut headers = HeaderMap::new();
    headers.insert("x-ratelimit-limit", state.rate_limiter.limit().into());
    headers.insert("x-ratelimit-remaining", decision.remaining.into());

    Ok((
        StatusCode::OK,
        headers,
        Json(SubmitWealthProofResponse {
            proof_token,
            expires_in: ttl,
            suitable,
            product_isin: terms.product_isin,
            product_name: terms.product_name,
            regulatory_audit_id,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_ref_is_deterministic_domain_separated_and_in_field() {
        let a = product_ref("XS1234567890");
        let b = product_ref("XS1234567890");
        assert_eq!(a, b, "the client and the server must derive the same value");
        assert_ne!(a, product_ref("US0378331005"));
        assert_eq!(a[0], 0, "top byte must be cleared to stay below the BN254 modulus");

        // Domain separation: not a bare SHA-256 of the ISIN.
        let bare: [u8; 32] = Sha256::digest(b"XS1234567890").into();
        assert_ne!(a, bare);
    }

    #[test]
    fn field_to_u64_refuses_to_truncate() {
        let mut small = [0u8; 32];
        small[31] = 42;
        assert_eq!(field_to_u64(&small), Some(42));

        let mut max = [0u8; 32];
        max[24..].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(field_to_u64(&max), Some(u64::MAX));

        // One bit above u64::MAX. Truncating would report 0 — which, read as
        // an income, would sail past any threshold comparison from below and
        // fail one from above. Refusing is the only safe answer.
        let mut too_big = [0u8; 32];
        too_big[23] = 1;
        assert_eq!(field_to_u64(&too_big), None);
    }

    #[test]
    fn hex_0x_round_trips_through_the_verify_layers_parser() {
        // The template this module hands the client is parsed back by
        // `verify::parse_field_hex` on submission. If the two disagree about
        // padding or case, every honest client produces an unverifiable
        // proof — so pin the round trip rather than trusting two format
        // strings to stay in sync.
        let bytes = product_ref("XS1234567890");
        let rendered = hex_0x(&bytes);
        assert_eq!(rendered.len(), 66);
        assert_eq!(parse_field_hex(0, &rendered).unwrap(), bytes);
    }

    #[test]
    fn the_layout_this_module_indexes_into_is_the_one_verify_uses() {
        // Every index in `submit_wealth_proof` is hardcoded against the
        // circuit's declared parameter order. Pin them here so a change to
        // the circuit signature breaks a test rather than silently
        // comparing min_liquidity against product_risk_level.
        let layout = public_input_layout(CircuitType::WealthSuitability);
        assert_eq!(layout.count, 12);
        assert_eq!(layout.nonce_index, 10);
        assert_eq!(layout.outcome_index, Some(11));
    }

    #[test]
    fn the_predicate_this_module_signs_is_registered_and_routed_here() {
        let spec = lookup_predicate(PREDICATE).expect("predicate must exist in the issuance registry");
        assert_eq!(spec.circuit, CircuitType::WealthSuitability);
        assert!(spec.dfsa_rules.contains(&"COB 3.1".to_string()));
        assert!(!spec.cbuae_clauses.is_empty(), "the CBUAE column applies to this disclosure too");
    }

    #[test]
    fn public_input_template_names_every_position_in_circuit_order() {
        let window_end = DateTime::from_timestamp(1_755_000_900, 0).unwrap();
        let nonce = vec![3u8; 32];
        let template =
            public_input_template(window_end, &product_ref("XS1234567890"), 500_000, 1_000_000, 30, 3, &nonce);

        let names: Vec<&str> = template.iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "current_time",
                "expiry_time",
                "vault_root",
                "product_ref",
                "min_income",
                "min_liquidity",
                "max_concentration_percent",
                "product_risk_level",
                "user_public_key_x",
                "user_public_key_y",
                "nonce",
                "suitable",
            ]
        );
        // The fixed values must be parseable by the same function that will
        // read them back on submission.
        assert_eq!(parse_field_hex(1, template[1]["value"].as_str().unwrap()).unwrap()[24..], 1_755_000_900i64.to_be_bytes());
    }
}
