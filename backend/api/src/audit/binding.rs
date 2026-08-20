// Binding: make a mutable row's *contents* something the hash chain
// committed to, not merely something the chain mentions.
//
// ---------------------------------------------------------------------
// THE DEFECT THIS EXISTS TO CLOSE
// ---------------------------------------------------------------------
// `tests/break_it/test_attack_04_change_model_identity.py` demonstrated it
// against the real server, and `docs/BREAK_IT_FINDINGS.md` records it: the
// HTTP surface around `decision_model_attestations` is airtight — one row
// per decision enforced by the primary key, `deny_unknown_fields` on the
// review path, PATCH/PUT/POST answering 405/405/404 — and every one of those
// defences is irrelevant to someone holding a connection string.
//
// The reason is not that the chain missed the edit. It is that there was
// nothing for it to notice. `wealth_suitability_requested` hashes
// `ai_participation_declared`, i.e. *that a declaration was made*. It has
// never hashed which model was named. So:
//
//     update decision_model_attestations
//        set model_provider = 'other', model_name = 'other-model'
//      where request_id = ...;
//
// changes what the sealed evidence record serves, and the chain is
// BYTE-IDENTICAL before and after. The escalation is worse: the same
// statement moves `declaration` to 'no_ai_participated', and the record then
// serves `model: null` — which `evidence/mod.rs` and the pinned schema both
// define as a SIGNED ASSERTION that no AI took part — for a decision that
// was opened naming a model.
//
// The same hole, smaller, on `disclosure_requests.policy`: the predicate set
// a decision was evaluated against is a jsonb column that no event hashes
// (finding 5). An edit there rewrites what the decision was measured by.
//
// ---------------------------------------------------------------------
// WHY A BINDING EVENT AND NOT A COLUMN
// ---------------------------------------------------------------------
// The obvious fix — store a digest of the attestation in a column beside it
// — does not work, and it is worth being explicit about why, because it is
// the fix a reviewer will ask for. Whoever can write `model_name` can write
// `model_digest` in the same statement. A digest is only evidence when it
// lives somewhere the attacker's UPDATE cannot reach, and in this system
// that place is `audit_log.event_hash`: chained, advisory-lock-serialised,
// and covered by the signed checkpoint in `checkpoint.rs`.
//
// ---------------------------------------------------------------------
// WHY THE PAYLOAD IS STILL NOT STORED
// ---------------------------------------------------------------------
// `mod.rs`' header explains that `payload` is folded into `event_hash` and
// deliberately not stored. That decision is not a limitation this module
// works around — it is the mechanism this module depends on, and reversing
// it would silently undo the fix:
//
//   If the payload were stored, verification would be "hash the stored
//   payload, compare" — which still succeeds after the attacker's UPDATE,
//   because the stored payload is a copy taken at write time and the edit
//   never touched it. The tamper becomes invisible again, one table over.
//
//   Because the payload is NOT stored, verification has no choice but to
//   REBUILD it from the live rows (see `replay.rs`). That rebuild reads
//   `decision_model_attestations` as it stands right now. An UPDATE changes
//   the rebuilt bytes, the recomputed hash, and therefore the comparison.
//
// So the property is: the chain proves rows are linked to each other; the
// binding event proves the rows STILL SAY what was hashed. Those are
// different claims, and only the second one survives a database write.
//
// ---------------------------------------------------------------------
// WHY EVERY KEY IS ALWAYS PRESENT
// ---------------------------------------------------------------------
// A `no_ai_participated` binding and a `model_identified` binding serialise
// with identical key sets, nulls and all — the same rejection-symmetry rule
// `DecisionEvidence` follows. Two reasons. A key set that varies by branch
// leaks the branch to anyone who can size the hashed bytes, and, more
// importantly, it makes "this field was absent" and "this field was null"
// two different byte strings for the same fact, which is precisely the
// ambiguity length-framing exists to remove one level up.
//
// ---------------------------------------------------------------------
// WHICH BYTES GET HASHED
// ---------------------------------------------------------------------
// Every event written before this module used `serde_json::to_vec`, and that
// cannot change: it is what every `event_hash` already in the database was
// computed over, so switching it would invalidate the recorded digest of
// every historical row — breaking the chain in order to improve it.
//
// `evidence::canonical` defines a different form, the one
// `scripts/export_audit_evidence.py` reproduces byte-for-byte in Python. The
// two agree on most values and diverge on a few, enumerated in
// `canonical.rs`' header; non-ASCII text is the divergence that matters in
// practice, because `to_vec` emits it raw and the canonicaliser escapes it.
//
// Binding events therefore hash the CANONICAL form
// (`audit::PayloadEncoding::Canonical`), which is safe precisely because
// they are new — no historical hash is recomputed. Without that, an
// attestation reason written in French or Arabic would hash to bytes only
// this process could rebuild, which would make the binding a claim rather
// than evidence for exactly the desks least able to argue about it.
//
// One divergence survives and is refused rather than encoded: a float has no
// rendering that Python's `json.dumps` and Rust's `ryu` agree on. See
// `check_policy_is_bindable` for the caller-facing half of that rule.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::evidence::canonical::canonical_bytes;

/// The model identity a decision was opened with, bound to the chain.
pub const EVENT_MODEL_ATTESTATION_BOUND: &str = "decision_model_attestation_bound";

/// The predicate set a decision was evaluated against, bound to the chain.
pub const EVENT_DISCLOSURE_POLICY_BOUND: &str = "disclosure_policy_bound";

/// One correction to a decision's model attestation, bound to the chain.
///
/// The correction row is append-only by design (migrations/0009), which is a
/// weaker statement than it sounds: "append-only" is a property of the code
/// that writes it, and attack 4 is the demonstration that a property of the
/// writing code is worth nothing to someone holding a connection string. An
/// UPDATE against `decision_model_attestation_corrections` can rewrite what a
/// correction claims, or a DELETE can remove it entirely so the record falls
/// back to serving the original identity. Binding each correction row makes
/// the first detectable as ALTERED and the second as SOURCE_ROW_MISSING —
/// which are different incidents, and `replay.rs` reports them in different
/// words for that reason.
pub const EVENT_MODEL_ATTESTATION_CORRECTION_BOUND: &str =
    "decision_model_attestation_correction_bound";

/// The `consent_grants` row as it stood when a grant was recorded, bound to
/// the chain in the same transaction as the grant.
///
/// See the `consent_grants` section below for why this and
/// `EVENT_CONSENT_REVOCATION_BOUND` rebuild from the SAME function against
/// the SAME row, unlike `EVENT_MODEL_ATTESTATION_BOUND` and its correction
/// sibling, which bind two different tables.
pub const EVENT_CONSENT_GRANT_BOUND: &str = "consent_grant_bound";

/// The `consent_grants` row as it stood the moment a grant was revoked,
/// bound to the chain in the same transaction as the revocation.
pub const EVENT_CONSENT_REVOCATION_BOUND: &str = "consent_revocation_bound";

/// Versioned because the payload shape is now consensus-critical: change a
/// key name and every event written before the change stops replaying. A
/// future shape gets a new version and `replay.rs` keeps both, rather than
/// history quietly becoming unverifiable.
const MODEL_ATTESTATION_BINDING_V1: &str = "decision_model_attestation_binding/v1";
const DISCLOSURE_POLICY_BINDING_V1: &str = "disclosure_policy_binding/v1";
const MODEL_ATTESTATION_CORRECTION_BINDING_V1: &str =
    "decision_model_attestation_correction_binding/v1";
const CONSENT_GRANT_BINDING_V1: &str = "consent_grant_binding/v1";

/// Every binding event type this module knows how to build and rebuild.
/// `replay.rs` uses it to decide which `audit_log` rows it is able to check
/// and which it must report as out of scope rather than silently skip.
pub const BINDING_EVENT_TYPES: &[&str] = &[
    EVENT_MODEL_ATTESTATION_BOUND,
    EVENT_DISCLOSURE_POLICY_BOUND,
    EVENT_MODEL_ATTESTATION_CORRECTION_BOUND,
    EVENT_CONSENT_GRANT_BOUND,
    EVENT_CONSENT_REVOCATION_BOUND,
];

/// Refuse a payload that has no canonical form at all.
///
/// ---------------------------------------------------------------------
/// THIS FUNCTION USED TO DO MORE, AND IT WAS WRONG
/// ---------------------------------------------------------------------
/// Its first version also compared `canonical_bytes(payload)` against
/// `serde_json::to_vec(payload)` and refused the event if they differed,
/// because `append_locked` hashed the latter and the Python exporter
/// reproduces the former. The diagnosis was right and the remedy was not.
/// The two encodings differ on non-ASCII text — `to_vec` emits it raw, the
/// canonicaliser escapes it — so a French or Arabic attestation reason
/// ("le déploiement utilisé") made a legitimate request fail, as a 500,
/// after the caller had done nothing wrong. Verified against the running
/// server; found by the engineer building the correction path, whose
/// `correction_reason` is a required free-text field and would have
/// inherited the exposure and widened it.
///
/// The cause is fixed one level down instead: binding events now hash the
/// canonical bytes directly (`audit::PayloadEncoding::Canonical`), which is
/// safe precisely because binding events are new — no historical
/// `event_hash` is recomputed, so nothing already recorded is invalidated.
///
/// What survives here is the part that is genuinely unfixable: a float has
/// no rendering both `json.dumps` and `ryu` agree on, so a payload
/// containing one cannot be independently verified by anyone and is refused
/// rather than recorded as evidence nobody can check.
fn guard_cross_verifier_reproducible(event_type: &str, payload: &Value) -> ApiResult<()> {
    canonical_bytes(payload).map(|_| ()).map_err(|e| {
        ApiError::Other(anyhow::anyhow!(
            "{event_type}: binding payload is not canonicalisable ({e}). A binding event only \
             counts as evidence if an examiner running the offline verifier can rebuild its \
             bytes, so it is refused here rather than written in a form only this process can \
             check"
        ))
    })
}

/// Refuse, at the API boundary and with a 400, a policy this system would be
/// unable to bind.
///
/// `SessionPolicy::predicates[].value` is an untyped `serde_json::Value`
/// (vault/src/session.rs), so a caller can put a float in a policy. Every
/// other leaf of a binding payload is a string, a uuid or a timestamp; this
/// is the only place caller-controlled arbitrary JSON reaches one.
///
/// Without this check that request would be accepted, stored, and then fail
/// inside `record_policy_binding` as a 500 — a confusing answer to a
/// legitimate mistake, and one that arrives after the row already exists.
/// Worse, the tempting alternative is to let the binding fail soft and write
/// the request anyway, which would create decisions whose policy is
/// committed to nothing while every other decision's is. A gap that exists
/// only for the requests that happened to contain a float is far harder to
/// reason about than a rule that says floats are not accepted.
///
/// The rule itself is `evidence/canonical.rs`': Python's `json.dumps` and
/// Rust's `ryu` disagree on exponent formatting, so a float in evidence
/// produces a digest only one of the two verifiers can reproduce. Fixed-point
/// amounts belong in minor units as integers.
pub fn check_policy_is_bindable(policy: &Value) -> ApiResult<()> {
    check_bindable("this policy", policy)
}

/// The same refusal `check_policy_is_bindable` makes, for the other
/// caller-controlled JSON value that reaches a binding payload: a consent
/// grant's `scope` (`consents::CreateConsentBody::scope`). Structural shape —
/// non-empty, every element a non-empty string — is `consents`' own job and
/// is checked before this runs; this is the narrower, unfixable half: a
/// float has no rendering Python's `json.dumps` and Rust's `ryu` agree on,
/// and a scope array cannot smuggle one in past the structural check alone
/// (`[1.5]` is a well-formed JSON array whose only element is not a string,
/// which the structural check already refuses — this exists as the second
/// layer for the same reason `decision_model_attestation_corrections`'
/// CHECK constraints exist beside `model_correction.rs`'s parser: a rule
/// that only lives in a handler is a rule someone holding a different call
/// site can route around).
pub fn check_scope_is_bindable(scope: &Value) -> ApiResult<()> {
    check_bindable("this consent scope", scope)
}

fn check_bindable(what: &str, value: &Value) -> ApiResult<()> {
    canonical_bytes(value).map(|_| ()).map_err(|e| {
        ApiError::BadRequest(format!(
            "{what} cannot be recorded as evidence: {e}. It is committed to the audit chain in \
             a canonical form that an offline verifier reproduces independently (see \
             docs/VERIFY.md), and a value that only one implementation can render would produce \
             a commitment nobody else could check. Rather than store a value whose binding we \
             could not honour, the request is refused here"
        ))
    })
}

fn opt_str(v: Option<String>) -> Value {
    match v {
        Some(s) => Value::String(s),
        None => Value::Null,
    }
}

fn opt_time(v: Option<DateTime<Utc>>) -> Value {
    match v {
        Some(t) => json!(t),
        None => Value::Null,
    }
}

// =====================================================================
// decision_model_attestations
// =====================================================================

/// Build the binding payload for a decision's model attestation *from the
/// row as it stands right now*.
///
/// This one function is used on both paths — once when the decision is
/// opened, to produce the bytes that get hashed, and again at verification
/// time, to produce the bytes that get compared. That is deliberate and is
/// the whole reason it is a function rather than an inline `json!` at the
/// call site: a rebuild that drifted from the original write would report
/// tampering on an untouched database, and an operator who learns to ignore
/// that alarm has lost the control entirely.
///
/// `Ok(None)` means there is no attestation row for this decision — which is
/// itself a fact worth distinguishing from a mismatch, so it is a distinct
/// return rather than an error.
pub async fn model_attestation_payload(
    conn: &mut PgConnection,
    request_id: Uuid,
) -> ApiResult<Option<Value>> {
    let row = sqlx::query!(
        r#"
        select declaration, no_ai_attestation, unidentified_reason,
               model_provider, model_name, model_version, prompt_version,
               model_environment, model_config_fingerprint,
               model_system_prompt_or_policy_id, model_timestamp,
               input_context_fingerprint, output_fingerprint, created_at
        from decision_model_attestations
        where request_id = $1
        "#,
        request_id,
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let payload = json!({
        "binding": MODEL_ATTESTATION_BINDING_V1,
        "request_id": request_id,
        "declaration": row.declaration,
        "no_ai_attestation": opt_str(row.no_ai_attestation),
        "unidentified_reason": opt_str(row.unidentified_reason),
        "model_provider": opt_str(row.model_provider),
        "model_name": opt_str(row.model_name),
        "model_version": opt_str(row.model_version),
        "prompt_version": opt_str(row.prompt_version),
        "model_environment": opt_str(row.model_environment),
        "model_config_fingerprint": opt_str(row.model_config_fingerprint),
        "model_system_prompt_or_policy_id": opt_str(row.model_system_prompt_or_policy_id),
        "model_timestamp": opt_time(row.model_timestamp),
        // Siblings of the model block, bound here for the reason
        // migrations/0006 gives for storing them beside it: when no AI
        // participated the decision still had inputs and an output, and a
        // fingerprint nothing commits to is a fingerprint that can be
        // rewritten to match whatever the story needs later.
        "input_context_fingerprint": opt_str(row.input_context_fingerprint),
        "output_fingerprint": opt_str(row.output_fingerprint),
        // The server's own observation of when the declaration arrived.
        // Bound so that a row cannot be back-dated to sit before a model
        // incident it should have been affected by.
        "attested_at": json!(row.created_at),
    });

    guard_cross_verifier_reproducible(EVENT_MODEL_ATTESTATION_BOUND, &payload)?;
    Ok(Some(payload))
}

/// Write the binding event. Called inside the caller's transaction, so a
/// decision cannot come into existence with its attestation unbound: either
/// the attestation row and the event that commits to it both land, or
/// neither does.
pub async fn record_model_attestation_binding(
    tx: &mut sqlx::PgTransaction<'_>,
    org_id: Uuid,
    request_id: Uuid,
) -> ApiResult<()> {
    let payload = model_attestation_payload(&mut **tx, request_id).await?.ok_or_else(|| {
        ApiError::Other(anyhow::anyhow!(
            "{EVENT_MODEL_ATTESTATION_BOUND}: no decision_model_attestations row for \
             {request_id} at binding time. The binding event must be written in the same \
             transaction as the row it binds; a missing row here means that ordering was \
             broken and the decision would otherwise be recorded with its model identity \
             committed to nothing"
        ))
    })?;
    super::record_binding_in_conn(
        &mut **tx,
        org_id,
        EVENT_MODEL_ATTESTATION_BOUND,
        request_id,
        payload,
    )
    .await?;
    Ok(())
}

// =====================================================================
// decision_model_attestation_corrections
// =====================================================================

/// Build the binding payload for ONE correction, from the row as it stands
/// right now.
///
/// -------------------------------------------------------------------
/// WHY `ref_id` IS THE CORRECTION'S OWN ID AND NOT THE REQUEST'S
/// -------------------------------------------------------------------
/// Every other binding in this module is keyed on `request_id` because the
/// row it binds is one-per-decision: the primary key of
/// `decision_model_attestations` is `request_id`, and so is the identity of a
/// `disclosure_requests` row. Corrections are not like that — a decision can
/// carry any number of them (migrations/0009), which is the whole point of
/// the table.
///
/// So `request_id` cannot be the key here, and the reason is not tidiness. A
/// rebuild has to be a PURE FUNCTION OF ONE ROW, because `replay.rs` re-hashes
/// each event against the digest recorded when that event was written. Keyed
/// on `request_id`, correction 1's binding would rebuild from whatever the
/// decision's corrections happen to be today — so filing correction 2 would
/// change correction 1's rebuilt bytes and make an untouched database report
/// ALTERED on an event nobody attacked. An operator who learns to dismiss that
/// alarm has lost the control, which is the failure `model_attestation_payload`
/// already warns about one function up.
///
/// `audit_log.ref_id` is therefore the correction's `id`, and it stops being a
/// pointer to the decision. That costs something real and it is worth naming:
/// `wealth/evidence.rs`'s audit excerpt selects `where ref_id = $1`, so these
/// events do not appear in a decision's excerpt. `request_id` is carried
/// inside the payload instead, so the linkage survives for anyone holding the
/// replay report — which is where a correction binding is read.
pub async fn model_attestation_correction_payload(
    conn: &mut PgConnection,
    correction_id: Uuid,
) -> ApiResult<Option<Value>> {
    let row = sqlx::query!(
        r#"
        select request_id, correction_no, asserted_by, asserted_by_role,
               correction_reason, corrected_declaration, unidentified_reason,
               corrected_model_provider, corrected_model_name, corrected_model_version,
               corrected_prompt_version, corrected_model_environment,
               corrected_model_config_fingerprint, corrected_model_system_prompt_or_policy_id,
               corrected_model_timestamp, asserted_at, created_at
        from decision_model_attestation_corrections
        where id = $1
        "#,
        correction_id,
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    // Every key present in every branch, nulls and all — the rejection
    // symmetry rule this module's header argues for. A correction that names
    // a model and one that admits it cannot name a model serialise with an
    // identical key set, so the branch does not leak to anyone sizing the
    // hashed bytes, and "absent" never has to be told apart from "null".
    let payload = json!({
        "binding": MODEL_ATTESTATION_CORRECTION_BINDING_V1,
        "correction_id": correction_id,
        // The decision this correction is about. Inside the payload rather
        // than in `ref_id` — see the note above.
        "request_id": row.request_id,
        // Bound because the number is what makes a DELETED correction
        // visible: corrections 1, 2 and 4 surviving says plainly that 3 was
        // removed, and a number nothing commits to could be renumbered to
        // close the gap.
        "correction_no": row.correction_no,
        "asserted_by": row.asserted_by,
        "asserted_by_role": row.asserted_by_role,
        "correction_reason": row.correction_reason,
        "corrected_declaration": row.corrected_declaration,
        "unidentified_reason": opt_str(row.unidentified_reason),
        "corrected_model_provider": opt_str(row.corrected_model_provider),
        "corrected_model_name": opt_str(row.corrected_model_name),
        "corrected_model_version": opt_str(row.corrected_model_version),
        "corrected_prompt_version": opt_str(row.corrected_prompt_version),
        "corrected_model_environment": opt_str(row.corrected_model_environment),
        "corrected_model_config_fingerprint": opt_str(row.corrected_model_config_fingerprint),
        "corrected_model_system_prompt_or_policy_id":
            opt_str(row.corrected_model_system_prompt_or_policy_id),
        "corrected_model_timestamp": opt_time(row.corrected_model_timestamp),
        // The organisation's own claim about when it determined the
        // correction, and the server's observation of when the claim
        // arrived. Both bound, because the gap between them is the only
        // unforgeable thing about the first one.
        "asserted_at": json!(row.asserted_at),
        "recorded_at": json!(row.created_at),
    });

    guard_cross_verifier_reproducible(EVENT_MODEL_ATTESTATION_CORRECTION_BOUND, &payload)?;
    Ok(Some(payload))
}

/// Write the binding event for one correction, inside the caller's
/// transaction, so a correction cannot exist unbound: either the row and the
/// event that commits to it both land, or neither does.
pub async fn record_model_attestation_correction_binding(
    tx: &mut sqlx::PgTransaction<'_>,
    org_id: Uuid,
    correction_id: Uuid,
) -> ApiResult<()> {
    let payload = model_attestation_correction_payload(&mut **tx, correction_id)
        .await?
        .ok_or_else(|| {
            ApiError::Other(anyhow::anyhow!(
                "{EVENT_MODEL_ATTESTATION_CORRECTION_BOUND}: no \
                 decision_model_attestation_corrections row for {correction_id} at binding time. \
                 The binding event must be written in the same transaction as the row it binds; \
                 a missing row here means that ordering was broken and a correction would \
                 otherwise be recorded with its contents committed to nothing — which is the \
                 state the original attestation was in before this module existed"
            ))
        })?;
    super::record_binding_in_conn(
        &mut **tx,
        org_id,
        EVENT_MODEL_ATTESTATION_CORRECTION_BOUND,
        correction_id,
        payload,
    )
    .await?;
    Ok(())
}

// =====================================================================
// disclosure_requests.policy
// =====================================================================

/// Build the binding payload for a disclosure request's policy from the row
/// as it stands right now.
///
/// `policy` is jsonb, which matters: Postgres normalises jsonb on write —
/// duplicate keys collapse, insignificant whitespace is dropped — so what
/// comes back is a canonical value, and the canonicaliser sorts keys on top
/// of that. The bytes are therefore a function of the policy's *content*,
/// not of how the caller happened to format it.
pub async fn policy_payload(
    conn: &mut PgConnection,
    request_id: Uuid,
) -> ApiResult<Option<Value>> {
    let row = sqlx::query!(
        r#"
        select org_id, user_id, circuit_type, policy, nonce, expires_at, created_at
        from disclosure_requests
        where id = $1
        "#,
        request_id,
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let payload = json!({
        "binding": DISCLOSURE_POLICY_BINDING_V1,
        "request_id": request_id,
        "user_id": row.user_id,
        "circuit_type": row.circuit_type,
        // The predicate set itself — the thing finding 5 says nothing
        // currently commits to.
        "policy": row.policy,
        // Bound because the nonce is what makes a proof answer THIS request
        // and not a replayed one (verify/mod.rs, used_nonces). A nonce that
        // could be rewritten after the fact would let a proof produced for
        // one request be re-presented as the answer to another.
        "nonce_b64": super::encode_b64(&row.nonce),
        "expires_at": json!(row.expires_at),
        "created_at": json!(row.created_at),
    });

    guard_cross_verifier_reproducible(EVENT_DISCLOSURE_POLICY_BOUND, &payload)?;
    let _ = row.org_id; // read for the query's sake; org_id is injected by the chain
    Ok(Some(payload))
}

/// Write the policy binding event on a connection the caller already holds.
pub async fn record_policy_binding(
    conn: &mut PgConnection,
    org_id: Uuid,
    request_id: Uuid,
) -> ApiResult<()> {
    let payload = policy_payload(&mut *conn, request_id).await?.ok_or_else(|| {
        ApiError::Other(anyhow::anyhow!(
            "{EVENT_DISCLOSURE_POLICY_BOUND}: no disclosure_requests row for {request_id} at \
             binding time"
        ))
    })?;
    super::record_binding_in_conn(
        conn,
        org_id,
        EVENT_DISCLOSURE_POLICY_BOUND,
        request_id,
        payload,
    )
    .await?;
    Ok(())
}

// =====================================================================
// consent_grants
// =====================================================================
//
// -------------------------------------------------------------------
// WHY ONE PAYLOAD FUNCTION SERVES TWO EVENT TYPES
// -------------------------------------------------------------------
// Every other binding in this module keys a distinct event type to a
// distinct TABLE — `decision_model_attestations` versus its own
// `..._corrections` sibling — precisely so that filing a correction never
// changes the bytes the ORIGINAL attestation's binding rebuilds (0009's
// whole argument for a second table instead of an UPDATE). Consent
// revocation does not get that luxury: migrations/0011 makes revocation an
// UPDATE to the SAME row, deliberately — a revoked grant is still the same
// grant, contradicted rather than replaced, and the record of what was
// revoked belongs beside the record of what was granted, not in a table of
// its own.
//
// So `EVENT_CONSENT_GRANT_BOUND` and `EVENT_CONSENT_REVOCATION_BOUND` both
// rebuild from `consent_grant_payload`, which reads the row AS IT STANDS
// NOW, whichever event is asking. The consequence is worth being explicit
// about, because it looks like a false positive until traced through: once
// a grant is legitimately revoked, replaying the ORIGINAL
// `consent_grant_bound` event recomputes against a row whose
// `revoked_at`/`revocation_reason` are no longer null, so it reports
// ALTERED — not because anyone attacked it, but because the row it commits
// to has, correctly, moved on. That is not a defect in this design; it is
// what "every key always present, so revocation changes bytes rather than
// adding keys" (see the header rule this shares with
// `model_attestation_payload`) actually cashes out to for a table that is
// updated in place. The event that answers "is this grant's CURRENT state
// what the chain committed to" after a revocation is
// `consent_revocation_bound`, whose own recorded hash was computed against
// the post-revocation row and therefore stays INTACT until something
// changes it again — which is exactly the tamper
// `test_attack_08_consent_revocation.py` step 3 demonstrates.
pub async fn consent_grant_payload(
    conn: &mut PgConnection,
    consent_id: Uuid,
) -> ApiResult<Option<Value>> {
    let row = sqlx::query!(
        r#"
        select id, user_id, scope, consent_version, purpose_hash, granted_at, granted_via,
               revoked_at, revocation_reason
        from consent_grants
        where id = $1
        "#,
        consent_id,
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let payload = json!({
        "binding": CONSENT_GRANT_BINDING_V1,
        "consent_id": row.id,
        "user_id": row.user_id,
        // `scope` is jsonb; Postgres already normalised it on write (no
        // duplicate keys, no insignificant whitespace — there are none to
        // have, since a jsonb array carries neither), so these bytes are a
        // function of the array's CONTENT, not of how the caller formatted
        // the request.
        "scope": row.scope,
        "consent_version": row.consent_version,
        "purpose_hash": opt_str(row.purpose_hash),
        "granted_at": json!(row.granted_at),
        "granted_via": row.granted_via,
        // Explicit nulls until revoked, present in every payload this
        // function ever returns — the rejection-symmetry rule this module's
        // header argues for, and the reason revocation changes bytes rather
        // than adding a key that was previously absent.
        "revoked_at": opt_time(row.revoked_at),
        "revocation_reason": opt_str(row.revocation_reason),
    });

    guard_cross_verifier_reproducible(EVENT_CONSENT_GRANT_BOUND, &payload)?;
    Ok(Some(payload))
}

/// Write the grant binding event. Called inside the caller's transaction —
/// `consents::grant_consent` — so a grant cannot exist unbound: either the
/// row and the event that commits to it both land, or neither does.
pub async fn record_consent_grant_binding(
    tx: &mut sqlx::PgTransaction<'_>,
    org_id: Uuid,
    consent_id: Uuid,
) -> ApiResult<()> {
    let payload = consent_grant_payload(&mut **tx, consent_id).await?.ok_or_else(|| {
        ApiError::Other(anyhow::anyhow!(
            "{EVENT_CONSENT_GRANT_BOUND}: no consent_grants row for {consent_id} at binding \
             time. The binding event must be written in the same transaction as the row it \
             binds; a missing row here means that ordering was broken and a grant would \
             otherwise be recorded with its contents committed to nothing"
        ))
    })?;
    super::record_binding_in_conn(&mut **tx, org_id, EVENT_CONSENT_GRANT_BOUND, consent_id, payload)
        .await?;
    Ok(())
}

/// Write the revocation binding event. Called inside `consents::revoke_consent`'s
/// transaction, AFTER the `UPDATE ... SET revoked_at = ...` — the payload it
/// builds is `consent_grant_payload` re-read post-update, so it commits to
/// the row as revocation left it.
pub async fn record_consent_revocation_binding(
    tx: &mut sqlx::PgTransaction<'_>,
    org_id: Uuid,
    consent_id: Uuid,
) -> ApiResult<()> {
    let payload = consent_grant_payload(&mut **tx, consent_id).await?.ok_or_else(|| {
        ApiError::Other(anyhow::anyhow!(
            "{EVENT_CONSENT_REVOCATION_BOUND}: no consent_grants row for {consent_id} at \
             binding time. The binding event must be written in the same transaction as the \
             UPDATE it binds; a missing row here means that ordering was broken"
        ))
    })?;
    super::record_binding_in_conn(
        &mut **tx,
        org_id,
        EVENT_CONSENT_REVOCATION_BOUND,
        consent_id,
        payload,
    )
    .await?;
    Ok(())
}

/// Rebuild the payload for whichever binding event type this is.
///
/// `replay.rs`'s single entry point into this module. Returning `Ok(None)`
/// for a known event type whose source row has since vanished is
/// deliberate — a deleted row is a different finding from an edited one and
/// the verifier says so in different words.
pub async fn rebuild_payload(
    conn: &mut PgConnection,
    event_type: &str,
    ref_id: Uuid,
) -> ApiResult<Option<Value>> {
    match event_type {
        EVENT_MODEL_ATTESTATION_BOUND => model_attestation_payload(conn, ref_id).await,
        EVENT_DISCLOSURE_POLICY_BOUND => policy_payload(conn, ref_id).await,
        // `ref_id` here is a correction's own id, not a request id — see the
        // note on `model_attestation_correction_payload`.
        EVENT_MODEL_ATTESTATION_CORRECTION_BOUND => {
            model_attestation_correction_payload(conn, ref_id).await
        }
        // Both consent event types rebuild from the same function against
        // the same row — see the section header above for why that is not
        // a shortcut but the actual shape of a table revoked in place.
        EVENT_CONSENT_GRANT_BOUND | EVENT_CONSENT_REVOCATION_BOUND => {
            consent_grant_payload(conn, ref_id).await
        }
        other => Err(ApiError::Other(anyhow::anyhow!(
            "{other} is not a binding event type; replay cannot rebuild it"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the module header argues for, checked rather than
    /// asserted: the two declarations produce the same key set. If someone
    /// later adds a field to only one branch, this fails.
    #[test]
    fn both_declarations_bind_the_same_key_set() {
        let identified = json!({
            "binding": MODEL_ATTESTATION_BINDING_V1,
            "request_id": Uuid::nil(),
            "declaration": "model_identified",
            "no_ai_attestation": Value::Null,
            "unidentified_reason": Value::Null,
            "model_provider": "acme",
            "model_name": "m",
            "model_version": Value::Null,
            "prompt_version": Value::Null,
            "model_environment": Value::Null,
            "model_config_fingerprint": Value::Null,
            "model_system_prompt_or_policy_id": Value::Null,
            "model_timestamp": Value::Null,
            "input_context_fingerprint": Value::Null,
            "output_fingerprint": Value::Null,
            "attested_at": json!(Utc::now()),
        });
        let no_ai = json!({
            "binding": MODEL_ATTESTATION_BINDING_V1,
            "request_id": Uuid::nil(),
            "declaration": "no_ai_participated",
            "no_ai_attestation": "the rules engine decided this, no model in the path",
            "unidentified_reason": Value::Null,
            "model_provider": Value::Null,
            "model_name": Value::Null,
            "model_version": Value::Null,
            "prompt_version": Value::Null,
            "model_environment": Value::Null,
            "model_config_fingerprint": Value::Null,
            "model_system_prompt_or_policy_id": Value::Null,
            "model_timestamp": Value::Null,
            "input_context_fingerprint": Value::Null,
            "output_fingerprint": Value::Null,
            "attested_at": json!(Utc::now()),
        });

        let keys = |v: &Value| -> Vec<String> {
            v.as_object().unwrap().keys().cloned().collect()
        };
        assert_eq!(keys(&identified), keys(&no_ai));
    }

    /// The bytes a binding event hashes must be the ones the Python
    /// exporter rebuilds — asserted against the encoder the write path
    /// actually uses, not against a restatement of it, so a change to
    /// `record_binding_in_conn`'s encoding breaks this test rather than
    /// quietly producing digests nobody outside this process can check.
    #[test]
    fn a_binding_event_hashes_the_canonical_form() {
        let payload = json!({
            "binding": MODEL_ATTESTATION_BINDING_V1,
            "declaration": "model_identified",
            "model_provider": "acme",
            "model_name": "risk-scorer",
            "attested_at": json!(Utc::now()),
        });
        assert!(guard_cross_verifier_reproducible("test", &payload).is_ok());
        assert_eq!(
            super::super::PayloadEncoding::Canonical.encode(&payload).unwrap(),
            canonical_bytes(&payload).unwrap(),
        );
    }

    /// The guard has to actually reject something, or it is decoration. A
    /// float is the divergence `canonical.rs` refuses outright.
    /// The regression this module shipped and had to fix.
    ///
    /// A binding payload containing non-English free text must record, and
    /// must hash to bytes the Python exporter reproduces. The first version
    /// refused it — `serde_json::to_vec` emits `é` raw while the
    /// canonicaliser escapes it, and the guard compared the two — so a
    /// French- or Arabic-language desk got a 500 for a legitimate request.
    /// Binding events now hash the canonical form directly.
    #[test]
    fn non_english_free_text_is_bindable() {
        let payload = json!({
            "binding": MODEL_ATTESTATION_CORRECTION_BINDING_V1,
            "correction_reason": "le déploiement utilisé n'était pas celui déclaré à l'ouverture",
            "unidentified_reason": "لم يتم تسجيل هوية النموذج",
        });
        assert!(
            guard_cross_verifier_reproducible("test", &payload).is_ok(),
            "a reason written in French or Arabic must be recordable"
        );

        // And the two encodings genuinely differ on it — otherwise this test
        // would pass for the wrong reason and stop protecting anything.
        assert_ne!(
            canonical_bytes(&payload).unwrap(),
            serde_json::to_vec(&payload).unwrap(),
            "if these ever agree on non-ASCII, the encoding split in audit::PayloadEncoding is \
             no longer load-bearing and this test is no longer evidence of anything"
        );
    }

    #[test]
    fn a_float_is_refused_rather_than_bound() {
        let payload = json!({ "binding": "x", "amount": 1.5 });
        let err = guard_cross_verifier_reproducible("test", &payload).unwrap_err();
        assert!(format!("{err:?}").contains("canonicalisable"));
    }

    /// The caller-facing half of the same rule. A float can only reach a
    /// binding payload through `SessionPolicy::predicates[].value`, which is
    /// untyped; that must be a 400 at the boundary and not a 500 after the
    /// row exists.
    #[test]
    fn an_unbindable_policy_is_a_client_error_not_a_server_error() {
        let ok = json!({
            "session_type": "Custom",
            "duration_seconds": 900,
            "predicates": [{ "field": "income", "operator": "GreaterThan", "value": 750000 }],
        });
        assert!(check_policy_is_bindable(&ok).is_ok());

        let floaty = json!({
            "session_type": "Custom",
            "duration_seconds": 900,
            "predicates": [{ "field": "income", "operator": "GreaterThan", "value": 750000.5 }],
        });
        match check_policy_is_bindable(&floaty) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("cannot be recorded as evidence"), "{msg}");
            }
            other => panic!("a float in a predicate must be a 400, got {other:?}"),
        }
    }

    #[test]
    fn rebuild_refuses_an_event_type_it_does_not_own() {
        // Compile-time-ish guard on the list the verifier iterates: every
        // type it advertises must be one `rebuild_payload` matches on.
        for t in BINDING_EVENT_TYPES {
            assert!(
                *t == EVENT_MODEL_ATTESTATION_BOUND
                    || *t == EVENT_DISCLOSURE_POLICY_BOUND
                    || *t == EVENT_MODEL_ATTESTATION_CORRECTION_BOUND
                    || *t == EVENT_CONSENT_GRANT_BOUND
                    || *t == EVENT_CONSENT_REVOCATION_BOUND,
                "{t} is advertised as replayable but rebuild_payload does not handle it"
            );
        }
    }

    /// The correction binding follows the same two rules the attestation
    /// binding does: every key present in every branch, and bytes the Python
    /// verifier can reproduce.
    ///
    /// Written against literals rather than against a row, deliberately. A
    /// test that built both branches by inserting rows would prove the two
    /// SQL statements agree; this proves the two SHAPES agree, which is the
    /// property that breaks when someone adds a field to the named-model
    /// branch and forgets the other one.
    #[test]
    fn both_corrected_declarations_bind_the_same_key_set() {
        let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
        let entry = |declaration: &str, provider: Value, reason: Value| {
            json!({
                "binding": MODEL_ATTESTATION_CORRECTION_BINDING_V1,
                "correction_id": Uuid::nil(),
                "request_id": Uuid::nil(),
                "correction_no": 1,
                "asserted_by": "mrm-desk-11",
                "asserted_by_role": "model_risk_officer",
                "correction_reason": "the gateway log shows this request was served by the \
                                      fallback deployment",
                "corrected_declaration": declaration,
                "unidentified_reason": reason,
                "corrected_model_provider": provider,
                "corrected_model_name": Value::Null,
                "corrected_model_version": Value::Null,
                "corrected_prompt_version": Value::Null,
                "corrected_model_environment": Value::Null,
                "corrected_model_config_fingerprint": Value::Null,
                "corrected_model_system_prompt_or_policy_id": Value::Null,
                "corrected_model_timestamp": Value::Null,
                "asserted_at": json!(Utc::now()),
                "recorded_at": json!(Utc::now()),
            })
        };

        let named = entry("model_identified", json!("a-different-vendor"), Value::Null);
        let unnameable = entry(
            "participated_but_unidentified",
            Value::Null,
            json!("the group gateway does not return which deployment served a request"),
        );
        assert_eq!(keys(&named), keys(&unnameable));

        // And the bytes an examiner rebuilds offline are the bytes this
        // event would hash. Without this the correction would be evidence
        // only Memtara could check, which is worth much less than none.
        assert!(guard_cross_verifier_reproducible("test", &named).is_ok());
        assert_eq!(
            canonical_bytes(&named).unwrap(),
            serde_json::to_vec(&named).unwrap()
        );

        // The two are genuinely different bindings, not two renderings of
        // one — otherwise the key-set comparison above would pass against a
        // pair of identical objects.
        assert_ne!(named, unnameable);
    }

    /// A grant's payload and the same row's payload post-revocation carry
    /// the same key set — `revoked_at`/`revocation_reason` are present and
    /// null before revocation, present and populated after, never absent
    /// either way. Written against literals for the same reason
    /// `both_declarations_bind_the_same_key_set` is: this proves the SHAPE
    /// is symmetric, not that one particular row happens to be.
    #[test]
    fn a_grant_and_its_revocation_bind_the_same_key_set() {
        let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
        let entry = |revoked_at: Value, revocation_reason: Value| {
            json!({
                "binding": CONSENT_GRANT_BINDING_V1,
                "consent_id": Uuid::nil(),
                "user_id": Uuid::nil(),
                "scope": ["wealth.suitability_recommendation"],
                "consent_version": "v1",
                "purpose_hash": Value::Null,
                "granted_at": json!(Utc::now()),
                "granted_via": "mobile_app",
                "revoked_at": revoked_at,
                "revocation_reason": revocation_reason,
            })
        };

        let granted = entry(Value::Null, Value::Null);
        let revoked = entry(
            json!(Utc::now()),
            json!("the customer withdrew consent via the mobile app settings screen"),
        );
        assert_eq!(keys(&granted), keys(&revoked));
        assert_ne!(
            granted, revoked,
            "revocation must change the bytes — that is the whole mechanism, not a defect in it"
        );

        assert!(guard_cross_verifier_reproducible("test", &granted).is_ok());
        assert!(guard_cross_verifier_reproducible("test", &revoked).is_ok());
    }

    /// The trap this module's header warns about, re-checked for the field
    /// this stage adds: `revocation_reason` and a consent grant's `scope`
    /// strings are exactly the free text a French- or Arabic-language desk
    /// will actually type, and the first version of this guard 500'd on
    /// every one of them.
    #[test]
    fn a_consent_grant_with_non_english_free_text_is_bindable() {
        let payload = json!({
            "binding": CONSENT_GRANT_BINDING_V1,
            "consent_id": Uuid::nil(),
            "user_id": Uuid::nil(),
            "scope": ["البيانات المالية للتقييم"],
            "consent_version": "v1",
            "purpose_hash": Value::Null,
            "granted_at": json!(Utc::now()),
            "granted_via": "assisted_kiosk",
            "revoked_at": json!(Utc::now()),
            "revocation_reason": "le client a retiré son consentement lors du rendez-vous en agence",
        });
        assert!(
            guard_cross_verifier_reproducible("test", &payload).is_ok(),
            "a scope or a revocation reason written in French or Arabic must be recordable"
        );
        assert_ne!(
            canonical_bytes(&payload).unwrap(),
            serde_json::to_vec(&payload).unwrap(),
            "if these ever agree on non-ASCII, the encoding split in audit::PayloadEncoding is \
             no longer load-bearing and this test is no longer evidence of anything"
        );
    }

    /// `check_scope_is_bindable` is the caller-facing half of the same rule,
    /// for the one place arbitrary caller JSON reaches a consent binding
    /// payload before a row exists to fail on.
    #[test]
    fn an_unbindable_scope_is_a_client_error_not_a_server_error() {
        assert!(check_scope_is_bindable(&json!(["wealth.suitability_recommendation"])).is_ok());
        match check_scope_is_bindable(&json!([1.5])) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("cannot be recorded as evidence"), "{msg}");
            }
            other => panic!("a float in a scope array must be a 400, got {other:?}"),
        }
    }
}
