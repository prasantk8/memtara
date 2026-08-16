// Proof issuance: `POST /api/v1/issue-proof`.
//
// This is the seam between Memtara's ZK world and everything downstream of
// it. A relying party that speaks JOSE (AIHOOTS, a bank's own gateway, an
// LLM front door) has no way to consume a Barretenberg proof; what it can
// consume is a short-lived signed attestation that a proof was checked and
// what it said. That is what this endpoint mints.
//
// -------------------------------------------------------------------
// ONE THING TO BE CLEAR ABOUT, BECAUSE THE NAME INVITES THE WRONG READING
// -------------------------------------------------------------------
// "Issue proof" does NOT mean this server generates a proof. It cannot,
// and the inability is the product: generating a proof for `income >= X`
// requires the income as a witness, so a server that could prove would be a
// server that holds plaintext, and ARCHITECTURE.md's "the vault never
// leaves the device" guarantee — plus the entire §5 column of
// docs/REGULATORY_MATRIX.md — would be false.
//
// So "run the appropriate circuit to evaluate the predicate" is honoured
// the only way it can be: by running the real compiled circuit's verifier
// (`bb verify`, the same path `verify::submit_proof` uses) over a proof the
// *client* generated on the holder's device. The circuit really does
// decide the boolean. Memtara just isn't the party that knows the witness.
//
// Two request shapes, both real evaluations:
//
//   FRESH     — caller supplies `public_inputs` + `proof`. They are checked
//               against the circuit's verification key right now, the
//               request's nonce is consumed, and a token is issued only on
//               a genuine cryptographic pass.
//
//   ATTESTED  — caller supplies neither. The most recent proof that already
//               passed `bb verify` for this (user, circuit) pair is
//               re-attested. No new cryptography, and the token says so via
//               `evaluation` in the audit payload. This exists because a
//               proof is single-use by design (the nonce is burned), but a
//               bank may legitimately need a second token for the same
//               verified fact inside one onboarding session.
//
// A relying party cannot tell the two apart from the token, and shouldn't:
// both mean "this circuit accepted this proof". The distinction is an audit
// fact, and it lives in the audit chain where audit facts belong.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::signer::{proof_digest_hex, ProofTokenClaims};
use crate::disclosure::authorize_org_or_user;
use crate::domain::CircuitType;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/issue-proof", post(issue_proof))
        .route("/api/v1/predicates", axum::routing::get(list_predicates))
}

/// `GET /api/v1/predicates` — the closed set of predicates this deployment
/// will attest to, with the circuit each runs on and the CBUAE clauses it
/// is evidence for.
///
/// Unauthenticated, like the JWKS endpoint: it is a published contract, and
/// `scripts/generate_regulatory_demo.py` reads it rather than hardcoding a
/// second copy that could silently disagree with the server.
async fn list_predicates() -> Json<serde_json::Value> {
    Json(predicate_catalogue())
}

// ---------------------------------------------------------------------
// Predicate registry
//
// A predicate name is part of the public API contract — it lands in a
// signed token that a relying party pattern-matches on — so it is a closed
// set defined here, not a free-text string echoed from the request. An
// unknown predicate is a 400, which means a typo fails at the boundary
// instead of producing a valid-looking token asserting something nobody
// defined.
//
// Each entry also carries the CBUAE clauses the disclosure is evidence for.
// Those clause ids are the real ones from CBUAE_EN_6958_VER1 (see
// docs/REGULATORY_MATRIX.md, including its note on why the commissioning
// brief's "4.3"/"5.2" don't exist in the document).
// ---------------------------------------------------------------------

/// Which endpoint mints a token for a given predicate.
///
/// Almost everything goes through `/api/v1/issue-proof`. Suitability does
/// not, and the distinction is enforced rather than documented: the wealth
/// circuit has a public *output* and per-request terms that must be checked
/// against the submitted public inputs, and `issue_proof` does neither.
/// Routing a wealth proof through the generic endpoint would therefore mint
/// a token that says `verified: true` for a proof that might have answered
/// "not suitable", against thresholds the client chose. So this is a closed
/// enum consulted by `issue_proof`, not a comment nobody reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Issuer {
    GenericProof,
    /// `POST /api/v1/submit-wealth-proof` — see wealth/mod.rs.
    WealthSuitability,
}

impl Issuer {
    fn endpoint(&self) -> &'static str {
        match self {
            Issuer::GenericProof => "/api/v1/issue-proof",
            Issuer::WealthSuitability => "/api/v1/submit-wealth-proof",
        }
    }
}

/// `(predicate, circuit, cbuae_clauses, dfsa_rules, issuer, description)`.
const PREDICATES: &[(&str, CircuitType, &[&str], &[&str], Issuer, &str)] = &[
    (
        "income_gte_threshold",
        CircuitType::TaxSession,
        &["5(c)", "5(d)", "4(a)"],
        &[],
        Issuer::GenericProof,
        "Income meets or exceeds the requested threshold; the income itself is not disclosed.",
    ),
    (
        "funds_gte_price",
        CircuitType::TaxSession,
        &["5(c)", "5(d)"],
        &[],
        Issuer::GenericProof,
        "Available funds meet or exceed the quoted price (real-estate proof-of-funds).",
    ),
    (
        "accredited_investor",
        CircuitType::TaxSession,
        &["5(c)", "7(b)"],
        &["COB 3.1"],
        Issuer::GenericProof,
        "Meets the accredited-investor asset/income threshold. A single boolean.",
    ),
    (
        "residency_valid",
        CircuitType::IdentitySession,
        &["5(c)", "4(a)"],
        &[],
        Issuer::GenericProof,
        "Residency status is currently valid.",
    ),
    (
        "investor_category_verified",
        CircuitType::IdentitySession,
        &["5(c)", "5(a)"],
        &[],
        Issuer::GenericProof,
        "Golden Visa / investor category confirmed without disclosing net worth.",
    ),
    (
        "compliance_clear",
        CircuitType::IdentitySession,
        &["5(e)", "3(a)"],
        &[],
        Issuer::GenericProof,
        "No PEP or sanctions match; risk band within policy. Source documents stay private.",
    ),
    (
        "emergency_medical_disclosure",
        CircuitType::EmergencySession,
        &["5(c)", "7(b)"],
        &[],
        Issuer::GenericProof,
        "Blood type, key medications and allergies, for a strictly time-boxed emergency window.",
    ),
    (
        "ai_category_scope",
        CircuitType::AiSession,
        &["4(a)", "5(c)"],
        &[],
        Issuer::GenericProof,
        "The AI session is scoped to an approved category set and nothing outside it.",
    ),
    (
        "structured_product_suitable",
        CircuitType::WealthSuitability,
        &["5(c)", "5(d)", "4(a)"],
        &["COB 3.1"],
        Issuer::WealthSuitability,
        "Income, liquidity, risk tolerance and concentration were assessed against a specific \
         product's published terms. Discloses one bit — suitable or not — and no figure behind it.",
    ),
];

#[derive(Debug)]
pub(crate) struct PredicateSpec {
    pub(crate) circuit: CircuitType,
    pub(crate) cbuae_clauses: Vec<String>,
    pub(crate) dfsa_rules: Vec<String>,
    pub(crate) issuer: Issuer,
}

pub(crate) fn lookup_predicate(name: &str) -> ApiResult<PredicateSpec> {
    PREDICATES
        .iter()
        .find(|(p, _, _, _, _, _)| *p == name)
        .map(|(_, circuit, clauses, dfsa, issuer, _)| PredicateSpec {
            circuit: *circuit,
            cbuae_clauses: clauses.iter().map(|c| c.to_string()).collect(),
            dfsa_rules: dfsa.iter().map(|r| r.to_string()).collect(),
            issuer: *issuer,
        })
        .ok_or_else(|| {
            let known: Vec<&str> = PREDICATES.iter().map(|(p, _, _, _, _, _)| *p).collect();
            ApiError::BadRequest(format!(
                "unknown predicate '{name}'; known predicates: {}",
                known.join(", ")
            ))
        })
}

/// Exposed for `scripts/generate_regulatory_demo.py` and the OpenAPI spec,
/// so the catalogue has exactly one source of truth rather than three that
/// drift.
pub fn predicate_catalogue() -> serde_json::Value {
    serde_json::json!(PREDICATES
        .iter()
        .map(|(name, circuit, clauses, dfsa, issuer, description)| serde_json::json!({
            "predicate": name,
            "circuit": circuit.as_str(),
            "cbuae_clauses": clauses,
            "dfsa_rules": dfsa,
            "endpoint": issuer.endpoint(),
            "description": description,
        }))
        .collect::<Vec<_>>())
}

// ---------------------------------------------------------------------
// POST /api/v1/issue-proof
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IssueProofBody {
    pub user_id: Uuid,
    pub predicate: String,
    /// The disclosure request this proof answers. Required for the FRESH
    /// path (it carries the nonce the proof must commit to); optional for
    /// ATTESTED, where it narrows which prior proof to re-attest.
    #[serde(default)]
    pub disclosure_request_id: Option<Uuid>,
    /// `0x`-prefixed hex field elements, in the circuit's declared order.
    /// Supplying these (with `proof`) selects the FRESH path.
    #[serde(default)]
    pub public_inputs: Option<Vec<String>>,
    /// base64url-no-pad `bb` proof bytes.
    #[serde(default)]
    pub proof: Option<String>,
}

#[derive(Serialize)]
pub struct IssueProofResponse {
    pub proof_token: String,
    pub expires_in: i64,
    /// Echoed so a caller can log the correlation id without decoding the
    /// JWT first — the value is inside the token too.
    pub regulatory_audit_id: Uuid,
}

async fn issue_proof(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<IssueProofBody>,
) -> ApiResult<(StatusCode, Json<IssueProofResponse>)> {
    let spec = lookup_predicate(&body.predicate)?;

    // Fail closed on predicates this endpoint cannot honestly attest to.
    // `issue_proof` checks that a proof verifies; it does not read a
    // circuit's public output, and it does not compare the submitted public
    // inputs against terms the org registered in advance. For a circuit that
    // answers a question rather than asserting one, both omissions are
    // exploitable: a proof of "not suitable", against thresholds the client
    // supplied, verifies perfectly well and would come back as a token
    // reading `verified: true`.
    if spec.issuer != Issuer::GenericProof {
        return Err(ApiError::BadRequest(format!(
            "predicate '{}' is issued by {}, not this endpoint — it carries a circuit output and \
             per-request terms that must be checked before a token can be minted",
            body.predicate,
            spec.issuer.endpoint(),
        )));
    }

    let (proof_bytes, evaluation, request_id) = match (&body.public_inputs, &body.proof) {
        (Some(public_inputs), Some(proof)) => {
            let request_id = body.disclosure_request_id.ok_or_else(|| {
                ApiError::BadRequest(
                    "disclosure_request_id is required when submitting public_inputs and proof \
                     (the proof must commit to that request's nonce)"
                        .into(),
                )
            })?;
            let bytes = crate::verify::verify_and_consume(
                &state,
                &headers,
                request_id,
                Some(spec.circuit),
                public_inputs,
                proof,
            )
            .await?;
            (bytes, "fresh", Some(request_id))
        }
        (None, None) => {
            let (bytes, request_id) =
                attest_existing_proof(&state, &headers, body.user_id, spec.circuit, body.disclosure_request_id)
                    .await?;
            (bytes, "attested", Some(request_id))
        }
        _ => {
            return Err(ApiError::BadRequest(
                "public_inputs and proof must be supplied together, or both omitted".into(),
            ))
        }
    };

    // Which tenant this issuance belongs to. Read back from the disclosure
    // request rather than taken from the caller: both paths above have
    // already been through `authorize_org_or_user`, so the request's own
    // `org_id` is the authenticated answer, and a body field would not be.
    let event_org_id = match request_id {
        Some(id) => {
            sqlx::query_scalar!("select org_id from disclosure_requests where id = $1", id)
                .fetch_optional(&state.db)
                .await?
        }
        None => None,
    };

    // One id ties together: this issuance event in Memtara's `audit_log`
    // hash chain, the `regulatory_audit_id` claim inside the token, and
    // whatever the relying party writes into its own chain. Generated here
    // (not derived from the proof) so re-attesting the same proof produces
    // a distinguishable second event rather than colliding with the first.
    let regulatory_audit_id = Uuid::new_v4();
    let now = Utc::now().timestamp();
    let ttl = state.config.proof_token_ttl_seconds;

    let claims = ProofTokenClaims {
        iss: state.signer.issuer().to_string(),
        sub: body.user_id.to_string(),
        user_id: body.user_id.to_string(),
        predicate: body.predicate.clone(),
        verified: true,
        circuit: spec.circuit.as_str().to_string(),
        proof_hash: proof_digest_hex(&proof_bytes),
        regulatory_audit_id: regulatory_audit_id.to_string(),
        cbuae_clauses: spec.cbuae_clauses.clone(),
        product_isin: None,
        suitable: None,
        dfsa_rules: spec.dfsa_rules.clone(),
        iat: now,
        exp: now + ttl,
        jti: Uuid::new_v4().to_string(),
    };

    let proof_token = state
        .signer
        .issue(&claims)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("failed to sign proof token: {e}")))?;

    // `ref_id` is the disclosure request, matching the convention every
    // other disclosure/proof event uses (see audit/mod.rs) — that's what
    // lets `GET /orgs/:id/audit-log` scope this event to the right org.
    //
    // The token itself is deliberately NOT in the payload. It is a bearer
    // credential; the hash chain is a commitment, not a secret store. The
    // `jti` and `proof_hash` are enough to prove after the fact which token
    // this event refers to, without the log becoming a place to steal one.
    crate::audit::record(
        &state.db,
        event_org_id,
        "proof_token_issued",
        request_id,
        serde_json::json!({
            "regulatory_audit_id": regulatory_audit_id,
            "user_id": body.user_id,
            "predicate": body.predicate,
            "circuit": spec.circuit.as_str(),
            "cbuae_clauses": spec.cbuae_clauses,
            "evaluation": evaluation,
            "proof_hash": claims.proof_hash,
            "jti": claims.jti,
            "expires_at": claims.exp,
        }),
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(IssueProofResponse { proof_token, expires_in: ttl, regulatory_audit_id }),
    ))
}

/// ATTESTED path: find the most recent proof that already passed
/// `bb verify` for this user and circuit, and return its bytes.
///
/// Authorization is checked against the disclosure request that proof
/// belongs to, using the same `authorize_org_or_user` gate the rest of the
/// disclosure surface uses — so an org can only re-attest proofs from
/// requests it created, and a user only their own. Without that check this
/// endpoint would be a way to mint tokens about strangers.
async fn attest_existing_proof(
    state: &AppState,
    headers: &HeaderMap,
    user_id: Uuid,
    circuit: CircuitType,
    request_id: Option<Uuid>,
) -> ApiResult<(Vec<u8>, Uuid)> {
    let row = sqlx::query!(
        r#"
        select p.proof_bytes, d.id as request_id, d.org_id, d.user_id
        from proofs p
        join disclosure_requests d on d.id = p.request_id
        where p.valid = true
          and d.user_id = $1
          and d.circuit_type = $2
          and ($3::uuid is null or d.id = $3)
        order by p.verified_at desc
        limit 1
        "#,
        user_id,
        circuit.as_str(),
        request_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "no verified {} proof exists for this user — submit public_inputs and proof to \
             evaluate one, or fulfil a disclosure request first",
            circuit.as_str()
        ))
    })?;

    authorize_org_or_user(state, headers, row.org_id, row.user_id).await?;
    Ok((row.proof_bytes, row.request_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_predicate_maps_to_a_real_circuit_and_at_least_one_clause() {
        for (name, circuit, clauses, _dfsa, _issuer, description) in PREDICATES {
            // Round-tripping through `parse` proves the circuit name this
            // entry will put in a signed token is one the verifier actually
            // knows, not a plausible-looking string.
            assert_eq!(
                CircuitType::parse(circuit.as_str()),
                Some(*circuit),
                "{name} names a circuit the domain layer doesn't know"
            );
            assert!(!clauses.is_empty(), "{name} claims no CBUAE clause");
            assert!(!description.is_empty(), "{name} has no description");
        }
    }

    #[test]
    fn predicate_names_are_unique() {
        let mut names: Vec<&str> = PREDICATES.iter().map(|(p, _, _, _, _, _)| *p).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate predicate name in the registry");
    }

    #[test]
    fn all_four_circuits_are_reachable_through_some_predicate() {
        // A circuit with no predicate pointing at it can never be exercised
        // through this endpoint — that would be a silent coverage hole
        // rather than a deliberate omission.
        for circuit in [
            CircuitType::EmergencySession,
            CircuitType::AiSession,
            CircuitType::TaxSession,
            CircuitType::IdentitySession,
            CircuitType::WealthSuitability,
        ] {
            assert!(
                PREDICATES.iter().any(|(_, c, _, _, _, _)| *c == circuit),
                "no predicate routes to {}",
                circuit.as_str()
            );
        }
    }

    #[test]
    fn a_circuit_with_a_public_output_is_never_issued_by_the_generic_endpoint() {
        // The guard in `issue_proof` is only as good as this invariant: any
        // circuit whose verdict lives in a public output must be routed to
        // an issuer that actually reads that output. Derived from the
        // verify-layer layout table rather than restated, so adding an
        // output to an existing circuit fails here instead of silently
        // producing tokens that ignore it.
        for (name, circuit, _, _, issuer, _) in PREDICATES {
            if crate::verify::public_input_layout(*circuit).outcome_index.is_some() {
                assert_ne!(
                    *issuer,
                    Issuer::GenericProof,
                    "{name} runs on {}, which has a public output the generic issuer does not read",
                    circuit.as_str(),
                );
            }
        }
    }

    #[test]
    fn suitability_predicate_is_rejected_by_name_with_a_pointer_to_the_right_endpoint() {
        let spec = lookup_predicate("structured_product_suitable").unwrap();
        assert_eq!(spec.issuer, Issuer::WealthSuitability);
        assert_eq!(spec.issuer.endpoint(), "/api/v1/submit-wealth-proof");
        assert_eq!(spec.dfsa_rules, vec!["COB 3.1".to_string()]);
    }

    #[test]
    fn unknown_predicate_is_a_bad_request_that_lists_the_known_ones() {
        let err = lookup_predicate("income_gte_treshold").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("unknown predicate"));
                // The error must be actionable: a typo should surface the
                // correct spelling, not just a rejection.
                assert!(msg.contains("income_gte_threshold"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn known_predicate_resolves_to_its_declared_circuit() {
        assert_eq!(lookup_predicate("income_gte_threshold").unwrap().circuit, CircuitType::TaxSession);
        assert_eq!(
            lookup_predicate("emergency_medical_disclosure").unwrap().circuit,
            CircuitType::EmergencySession
        );
        assert_eq!(lookup_predicate("residency_valid").unwrap().circuit, CircuitType::IdentitySession);
        assert_eq!(lookup_predicate("ai_category_scope").unwrap().circuit, CircuitType::AiSession);
    }

    #[test]
    fn catalogue_exposes_every_registry_entry() {
        let catalogue = predicate_catalogue();
        let entries = catalogue.as_array().expect("catalogue is an array");
        assert_eq!(entries.len(), PREDICATES.len());
        for (name, circuit, _, _, _, _) in PREDICATES {
            let found = entries
                .iter()
                .find(|e| e["predicate"] == *name)
                .unwrap_or_else(|| panic!("{name} missing from catalogue"));
            assert_eq!(found["circuit"], circuit.as_str());
        }
    }
}
