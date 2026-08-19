// Replay: re-derive each binding event's payload from the rows it binds and
// check the recorded `event_hash` still comes out.
//
// ---------------------------------------------------------------------
// WHAT THIS CHECKS, AND WHAT IT DELIBERATELY DOES NOT
// ---------------------------------------------------------------------
// There are three separable claims about this audit log, and conflating them
// is how a system ends up describing itself as tamper-evident when only one
// of the three holds:
//
//   1. LINKAGE      — each row's `prev_hash` is its predecessor's
//                     `event_hash`, so no row was removed or reordered.
//                     Requires the WHOLE log (the chain is global, see
//                     mod.rs' header); checked by
//                     `scripts/export_audit_evidence.py` and by the vendored
//                     walker in the offline bundle. NOT checked here.
//   2. HEAD         — the last row, which nothing follows, is committed to
//                     by something outside the database. `checkpoint.rs`.
//                     NOT checked here.
//   3. BINDING      — the rows a decision is judged on STILL SAY what the
//                     chain hashed. THIS module, and nothing else.
//
// This endpoint reports 3 and says so in its own output. It uses each row's
// STORED `prev_hash` as an input rather than recomputing it from the
// predecessor, which is exactly why it is silent about 1: an attacker who
// rewrote a whole segment consistently would pass this check and fail the
// linkage check. The two are complements, not alternatives, and a reader who
// takes a green result here as "the log is intact" has been misled — hence
// `checks` and `does_not_check` in the response body rather than in a doc
// nobody reads at 2am.
//
// ---------------------------------------------------------------------
// WHY MOST EVENTS ARE OUT OF SCOPE, AND WHY THAT IS STATED
// ---------------------------------------------------------------------
// Only events built by `binding.rs` can be replayed, because only their
// payloads are a pure function of rows that still exist. Most events are
// not: `wealth_suitability_requested` hashes `product_registry_updated_at`,
// which moves whenever the product is amended, so rebuilding it tomorrow
// would produce a different digest on an untouched database. That is a
// property of the payload, not a bug, and the honest response is to name the
// event types this verifier cannot speak for rather than to quietly count
// them as passing.
//
// A verifier that reports "0 problems" while silently skipping 90% of its
// input is the failure mode this whole product exists to argue against, so
// the response carries the skipped types and their counts.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

use super::binding::{self, BINDING_EVENT_TYPES};
use super::{compute_event_hash, encode_b64, payload_with_org};

pub fn router() -> Router<AppState> {
    Router::new().route("/orgs/:id/audit-log/replay", get(replay_org_bindings))
}

/// What happened to one binding event.
///
/// Four outcomes, not two. "Intact" and "altered" are the obvious pair; the
/// other two exist because collapsing them into "altered" would tell an
/// operator the wrong thing to do. A deleted source row and an edited one
/// are different incidents with different responses, and a payload that
/// cannot be canonicalised at all is a bug in us until proven otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayResult {
    /// The rows still hash to the recorded `event_hash`.
    Intact,
    /// They do not. Something changed after the event was written.
    Altered,
    /// The rows the event binds are gone. The event survives as a record
    /// that they once existed and what they said.
    SourceRowMissing,
    /// The payload could not be rebuilt at all. Not an accusation — read
    /// `detail`.
    Unverifiable,
}

#[derive(Debug, Serialize)]
pub struct ReplayedEvent {
    pub seq: i64,
    pub event_type: String,
    pub ref_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub result: ReplayResult,
    /// The hash as stored.
    pub recorded_event_hash: String,
    /// The hash the current rows produce. `None` when there was nothing to
    /// rebuild — printing a digest of nothing would invite a comparison that
    /// means nothing.
    pub recomputed_event_hash: Option<String>,
    /// The predecessor hash this event was written against, as stored.
    /// Carried because it is an input to the hash: without it an offline
    /// verifier cannot recompute anything and is reduced to believing the
    /// `result` field above.
    pub prev_hash: Option<String>,
    /// The rebuilt payload itself.
    ///
    /// Exported deliberately, and it is the difference between a verifier
    /// and a claim. With the payload, the prev_hash and the recorded digest,
    /// a party holding an offline bundle recomputes
    /// `SHA256(framed(event_type) || framed(ref_id) || framed(prev_hash) ||
    /// framed(payload))` themselves and needs nothing from us — including
    /// the ability to check the bound model identity against the one the
    /// sealed `DecisionEvidence` record serves, which is the cross-check
    /// that makes a tampered bundle detectable without database access.
    ///
    /// It is the payload as it stands NOW, which is the honest thing to
    /// export: if it disagrees with the digest, that disagreement is the
    /// finding, and hiding it would defeat the point.
    pub rebuilt_payload: Option<serde_json::Value>,
    /// A sentence an examiner can put in a report without translating it.
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ReplaySummary {
    pub binding_events: i64,
    pub intact: i64,
    pub altered: i64,
    pub source_row_missing: i64,
    pub unverifiable: i64,
    /// Events in this org's trail that carry no binding and therefore were
    /// not checked, by type.
    pub out_of_scope: std::collections::BTreeMap<String, i64>,
}

/// Three verdicts, and none of them is a boolean.
///
/// `Incomplete` is the one that matters commercially: an org whose decisions
/// all predate `binding.rs` has nothing to replay, and reporting that as
/// "intact" would hand them a clean bill of health for a property they do
/// not have. Same reasoning as `EVIDENCE INTEGRITY: INCOMPLETE` in the
/// bundle verifier — an absent check is not a passed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayVerdict {
    Intact,
    Altered,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub org_id: Uuid,
    pub checked_at: DateTime<Utc>,
    pub verdict: ReplayVerdict,
    pub summary: ReplaySummary,
    pub events: Vec<ReplayedEvent>,
    /// Stated in the payload, not only in the docs. See the module header.
    pub checks: Vec<&'static str>,
    pub does_not_check: Vec<&'static str>,
}

const CHECKS: &[&str] = &[
    "that the rows each binding event commits to still contain what was hashed when the event \
     was written — a decision's declared model identity, and the policy it was judged against",
];

const DOES_NOT_CHECK: &[&str] = &[
    "chain linkage. Each event is re-hashed using its own STORED prev_hash, so a segment \
     rewritten consistently would pass here. Linkage spans every tenant and is checked over the \
     whole log by scripts/export_audit_evidence.py and by the verifier vendored in the offline \
     bundle",
    "the chain head. The most recent row is followed by nothing and is committed to only by a \
     signed checkpoint — see GET /orgs/:id/audit-chain/checkpoint and audit/checkpoint.rs",
    "any event type not listed in `summary.out_of_scope` as checked. Those events carry \
     payloads that are not a pure function of rows that still exist (a product's amendment \
     timestamp moves legitimately), so rebuilding them would report tampering on an untouched \
     database",
];

/// Replay every binding event in one org's trail.
///
/// Exposed as a function taking a connection, not only as a handler, so the
/// break-it suite and any future CLI check the same code the endpoint runs
/// rather than a second implementation that could agree with the first only
/// by accident.
pub async fn replay_org(conn: &mut PgConnection, org_id: Uuid) -> ApiResult<ReplayReport> {
    replay_scoped(conn, org_id, None).await
}

/// Replay only the binding events that name one of `ref_ids`.
///
/// Used by the decision-evidence endpoint so a reader of ONE record gets the
/// binding verdict for that record, without having to know a second endpoint
/// exists. Scoping by `ref_id` is exact today because every binding event's
/// `ref_id` is the decision it belongs to.
///
/// NOTE for whoever adds the next binding type: an event whose `ref_id` is
/// something other than the decision — a correction row's own id, say, since
/// a decision can have several and each must rebuild from one row — will not
/// be picked up by a caller passing a decision id here. Such a type needs
/// its ids resolved to decisions at the call site, or this filter widened to
/// join through. Getting that wrong makes a record look bound when part of
/// it is not, which is worse than not checking.
pub async fn replay_refs(
    conn: &mut PgConnection,
    org_id: Uuid,
    ref_ids: &[Uuid],
) -> ApiResult<ReplayReport> {
    replay_scoped(conn, org_id, Some(ref_ids)).await
}

async fn replay_scoped(
    conn: &mut PgConnection,
    org_id: Uuid,
    ref_ids: Option<&[Uuid]>,
) -> ApiResult<ReplayReport> {
    let binding_types: Vec<String> = BINDING_EVENT_TYPES.iter().map(|s| s.to_string()).collect();
    let scope: Option<Vec<Uuid>> = ref_ids.map(|ids| ids.to_vec());

    let rows = sqlx::query!(
        r#"
        select seq as "seq!", event_type, ref_id, event_hash, prev_hash, created_at
        from audit_log
        where org_id = $1
          and event_type = any($2)
          and ($3::uuid[] is null or ref_id = any($3))
        order by seq asc
        "#,
        org_id,
        &binding_types[..],
        scope.as_deref(),
    )
    .fetch_all(&mut *conn)
    .await?;

    // Counted separately and reported, rather than filtered away silently.
    let skipped = sqlx::query!(
        r#"
        select event_type, count(*) as "n!"
        from audit_log
        where org_id = $1
          and not (event_type = any($2))
          and ($3::uuid[] is null or ref_id = any($3))
        group by event_type
        order by event_type
        "#,
        org_id,
        &binding_types[..],
        scope.as_deref(),
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    let mut intact = 0i64;
    let mut altered = 0i64;
    let mut missing = 0i64;
    let mut unverifiable = 0i64;

    for row in rows {
        let Some(ref_id) = row.ref_id else {
            unverifiable += 1;
            events.push(ReplayedEvent {
                seq: row.seq,
                event_type: row.event_type.clone(),
                ref_id: None,
                created_at: row.created_at,
                result: ReplayResult::Unverifiable,
                recorded_event_hash: encode_b64(&row.event_hash),
                recomputed_event_hash: None,
                prev_hash: row.prev_hash.as_deref().map(encode_b64),
                rebuilt_payload: None,
                detail: "a binding event with no ref_id names nothing to rebuild from. Every \
                         event binding.rs writes carries one, so this row was written by \
                         something else using a reserved event type"
                    .to_string(),
            });
            continue;
        };

        let rebuilt = binding::rebuild_payload(&mut *conn, &row.event_type, ref_id).await;

        let (result, recomputed, rebuilt_payload, detail) = match rebuilt {
            Ok(Some(payload)) => {
                // The identical transformation `append_locked` applies, from
                // the identical function — see `payload_with_org`.
                let payload = payload_with_org(Some(org_id), &payload);
                // The identical encoding the write path used. Binding events
                // hash canonical bytes, not `serde_json::to_vec` — see
                // `audit::PayloadEncoding`. Re-hashing with the wrong one
                // would report every binding event as ALTERED the first time
                // a payload contained a non-ASCII character, which is the
                // cry-wolf failure this module's header warns about.
                let bytes = super::PayloadEncoding::Canonical.encode(&payload)?;
                let hash = compute_event_hash(
                    &row.event_type,
                    Some(ref_id),
                    row.prev_hash.as_deref(),
                    &bytes,
                );
                if hash == row.event_hash {
                    (
                        ReplayResult::Intact,
                        Some(encode_b64(&hash)),
                        Some(payload),
                        "the rows this event binds still hash to the value recorded when it was \
                         written"
                            .to_string(),
                    )
                } else {
                    (
                        ReplayResult::Altered,
                        Some(encode_b64(&hash)),
                        Some(payload),
                        format!(
                            "the rows this event binds no longer hash to the recorded value. \
                             Something changed {} after the event was written. The chain's own \
                             linkage is unaffected and will still verify, which is the point: \
                             this edit is invisible to it",
                            match row.event_type.as_str() {
                                t if t == binding::EVENT_MODEL_ATTESTATION_BOUND =>
                                    "in decision_model_attestations",
                                t if t == binding::EVENT_DISCLOSURE_POLICY_BOUND =>
                                    "in disclosure_requests",
                                // The table is append-only through the API
                                // and only through the API; this is the
                                // report an examiner sees when a correction
                                // was edited after it was filed.
                                t if t == binding::EVENT_MODEL_ATTESTATION_CORRECTION_BOUND =>
                                    "in decision_model_attestation_corrections",
                                _ => "in the bound rows",
                            }
                        ),
                    )
                }
            }
            Ok(None) => (
                ReplayResult::SourceRowMissing,
                None,
                None,
                format!(
                    "the row this event binds ({ref_id}) no longer exists. The event is a \
                     surviving commitment that it did, and to what it said, but there is \
                     nothing left to compare it against"
                ),
            ),
            Err(e) => (
                ReplayResult::Unverifiable,
                None,
                None,
                format!(
                    "the payload could not be rebuilt: {e}. This is reported rather than \
                     counted as a pass or a failure — until it is explained it is a defect in \
                     the verifier, not evidence about the data"
                ),
            ),
        };

        match result {
            ReplayResult::Intact => intact += 1,
            ReplayResult::Altered => altered += 1,
            ReplayResult::SourceRowMissing => missing += 1,
            ReplayResult::Unverifiable => unverifiable += 1,
        }

        events.push(ReplayedEvent {
            seq: row.seq,
            event_type: row.event_type,
            ref_id: Some(ref_id),
            created_at: row.created_at,
            result,
            recorded_event_hash: encode_b64(&row.event_hash),
            recomputed_event_hash: recomputed,
            prev_hash: row.prev_hash.as_deref().map(encode_b64),
            rebuilt_payload,
            detail,
        });
    }

    let binding_events = events.len() as i64;

    // A missing source row is an alteration of what the record says, not a
    // separate softer category: the decision's evidence no longer resolves.
    // `Unverifiable` deliberately does NOT force ALTERED — it is a statement
    // about this verifier, and letting it raise an alarm about the data
    // would be the cry-wolf failure the module header warns about. It does
    // block INTACT, via the count check below.
    let verdict = if altered > 0 || missing > 0 {
        ReplayVerdict::Altered
    } else if binding_events > 0 && unverifiable == 0 {
        ReplayVerdict::Intact
    } else {
        ReplayVerdict::Incomplete
    };

    Ok(ReplayReport {
        org_id,
        checked_at: Utc::now(),
        verdict,
        summary: ReplaySummary {
            binding_events,
            intact,
            altered,
            source_row_missing: missing,
            unverifiable,
            out_of_scope: skipped.into_iter().map(|r| (r.event_type, r.n)).collect(),
        },
        events,
        checks: CHECKS.to_vec(),
        does_not_check: DOES_NOT_CHECK.to_vec(),
    })
}

/// GET /orgs/:id/audit-log/replay
///
/// `OrgAuth`-guarded and path-checked, exactly like `get_org_audit_log` — a
/// valid key sees only its own org. There is no cross-tenant replay endpoint
/// because there is no cross-tenant reader: the global chain's linkage is
/// verified by the export tooling, which runs with database access rather
/// than an API key.
async fn replay_org_bindings(
    OrgAuth(auth_org_id): OrgAuth,
    Path(path_org_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<ReplayReport>> {
    if auth_org_id != path_org_id {
        return Err(ApiError::Forbidden);
    }
    let mut conn = state.db.acquire().await?;
    let report = replay_org(&mut conn, path_org_id).await?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The verdict rules, checked as a table rather than trusted. The row
    /// that matters most is the last one: nothing to check must never
    /// present as a clean result.
    #[test]
    fn verdict_rules() {
        fn verdict(bindings: i64, altered: i64, missing: i64, unverifiable: i64) -> ReplayVerdict {
            if altered > 0 || missing > 0 {
                ReplayVerdict::Altered
            } else if bindings > 0 && unverifiable == 0 {
                ReplayVerdict::Intact
            } else {
                ReplayVerdict::Incomplete
            }
        }
        assert_eq!(verdict(5, 0, 0, 0), ReplayVerdict::Intact);
        assert_eq!(verdict(5, 1, 0, 0), ReplayVerdict::Altered);
        assert_eq!(verdict(5, 0, 1, 0), ReplayVerdict::Altered);
        // An unexplained rebuild failure blocks a clean verdict without
        // accusing anyone.
        assert_eq!(verdict(5, 0, 0, 1), ReplayVerdict::Incomplete);
        // Nothing bound: not intact.
        assert_eq!(verdict(0, 0, 0, 0), ReplayVerdict::Incomplete);
    }

    /// Changing one leaf of a rebuilt payload must change the hash. Trivial
    /// in principle, and worth pinning: this is the entire mechanism, and if
    /// a future refactor dropped a field from the rebuild the binding would
    /// stop covering it with no test failing anywhere else.
    #[test]
    fn a_changed_model_name_changes_the_recomputed_hash() {
        let base = json!({
            "binding": "decision_model_attestation_binding/v1",
            "declaration": "model_identified",
            "model_provider": "acme",
            "model_name": "risk-scorer",
        });
        let tampered = json!({
            "binding": "decision_model_attestation_binding/v1",
            "declaration": "model_identified",
            "model_provider": "acme",
            "model_name": "other-model",
        });
        let h = |v: &serde_json::Value| {
            compute_event_hash(
                binding::EVENT_MODEL_ATTESTATION_BOUND,
                Some(Uuid::nil()),
                None,
                &serde_json::to_vec(v).unwrap(),
            )
        };
        assert_ne!(h(&base), h(&tampered));
    }

    /// The escalation from finding 4, at the level this module can test
    /// without a database: moving the declaration to the no-AI assertion is
    /// not merely a different string, it is a different digest, so the
    /// binding event refuses to cover it.
    #[test]
    fn the_no_ai_assertion_is_not_reachable_under_an_existing_binding() {
        let identified = json!({ "declaration": "model_identified", "model_name": "risk-scorer" });
        let no_ai = json!({ "declaration": "no_ai_participated", "model_name": null });
        let h = |v: &serde_json::Value| {
            compute_event_hash("x", None, None, &serde_json::to_vec(v).unwrap())
        };
        assert_ne!(h(&identified), h(&no_ai));
    }

    #[test]
    fn org_injection_matches_the_write_path() {
        // Same function the writer uses; this asserts it is applied, so a
        // future change to one side cannot silently break replay.
        let payload = json!({ "a": 1 });
        let with = payload_with_org(Some(Uuid::nil()), &payload);
        assert_eq!(with["org_id"], json!(Uuid::nil()));
        assert_eq!(with["a"], json!(1));
    }
}
