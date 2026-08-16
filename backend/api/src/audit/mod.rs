// Audit: a hash-chained, append-only log against `audit_log`
// (migrations/0001_init.sql — `id, event_type, ref_id, event_hash,
// prev_hash, created_at`, plus `seq` added in
// migrations/0002_audit_log_seq.sql — a new migration, not an edit to the
// applied one; see that file for why `created_at` alone isn't a safe total
// order for the chain).
//
// Chain scope: GLOBAL, not per-org — and it stayed that way when
// `audit_log.org_id` arrived in migrations/0005. That column made a per-org
// chain *possible*, which is exactly why it is worth saying why we still
// don't want one:
//
//   A global chain is a STRONGER tamper-evidence property than a per-org
//   one, not a weaker one. It commits to the real interleaving order of
//   events across every tenant, so history cannot be doctored by reordering
//   events between two orgs' otherwise-independent chains — and it means one
//   deleted row is detectable by every tenant downstream of it, not only by
//   the one it belonged to.
//
// `GET /orgs/:id/audit-log` still shows each org only its own rows. That
// endpoint returns a *filtered view* of one chain, not a chain: consecutive
// rows in the response will normally have non-consecutive `seq`, and their
// `prev_hash` values point at rows the caller cannot see. Verifying linkage
// therefore requires the whole log; the per-tenant view proves membership
// and position, not adjacency.
//
// Hash function: SHA-256, matching `auth::session_token::hash_token`'s
// choice (the only other "hash a secret/value for integrity" precedent in
// this codebase) rather than introducing a second hash primitive.
// `event_hash = SHA256(len-prefixed(event_type) || len-prefixed(ref_id) ||
// len-prefixed(prev_hash) || len-prefixed(payload))`. Each component is
// framed with an 8-byte big-endian length prefix before hashing (see
// `write_framed`) specifically so that, e.g., `event_type="a"` + a
// `payload` starting with more of what could otherwise look like part of
// the type string can't be crafted to collide with a different
// `event_type`/`payload` split that concatenates to the same raw bytes —
// framing removes that ambiguity, not just string-concatenating the parts.
//
// `payload` (the event's contextual detail — org/user/proof ids, valid/
// invalid, etc.) is folded into `event_hash` but deliberately NOT stored in
// `audit_log` itself: there's no column for it, and schema is final. This
// makes the chain a commitment scheme (proves "IF someone claims this
// happened, it's exactly this payload, in this position in history, or the
// hash doesn't match") rather than an append-only *record store* — callers
// that need the payload for display join through `ref_id` to the row the
// event is about (see `orgs::list_org_disclosure_requests` for the
// disclosure/proof case).

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/orgs/:id/audit-log", get(get_org_audit_log))
}

/// Fixed, arbitrary key for a Postgres advisory lock that serializes every
/// "read the chain's last event_hash, then insert a row claiming it as
/// prev_hash" sequence — across concurrent requests, connections, and (since
/// advisory locks are server-wide, not connection-local) even multiple app
/// instances against the same DB. Without this, two concurrent `record`
/// calls could both read the same last `event_hash`, both compute a
/// `prev_hash` pointing at it, and both insert — silently forking the chain
/// into two branches with the same predecessor instead of one linear
/// history. The chain's linearity isn't expressible as a DB constraint the
/// way `used_nonces`' primary key expresses replay-uniqueness
/// (verify/mod.rs), so it needs an explicit lock instead. Value itself is
/// meaningless, just needs to be constant and not collide with some other
/// advisory lock this codebase might take out later.
const AUDIT_CHAIN_LOCK_KEY: i64 = 0x4d454d54_41524132; // "MEMT" "ARA2" as hex, arbitrary

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn write_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Pure function: `event_hash` as a function of this event's own fields and
/// the chain's `prev_hash`. Exposed (not just inlined into `append_locked`)
/// so tests can recompute it independently to check a stored row's hash is
/// genuinely derived from its payload, not decorative.
pub(crate) fn compute_event_hash(
    event_type: &str,
    ref_id: Option<Uuid>,
    prev_hash: Option<&[u8]>,
    payload: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    write_framed(&mut hasher, event_type.as_bytes());
    write_framed(&mut hasher, ref_id.map(|id| *id.as_bytes()).unwrap_or_default().as_slice());
    write_framed(&mut hasher, prev_hash.unwrap_or(&[]));
    write_framed(&mut hasher, payload);
    hasher.finalize().to_vec()
}

pub struct AuditEntry {
    pub id: Uuid,
    /// The tenant this event belongs to. `None` only for events that
    /// genuinely have no owning org (none today) and for rows written before
    /// migrations/0005.
    pub org_id: Option<Uuid>,
    pub event_type: String,
    pub ref_id: Option<Uuid>,
    pub event_hash: Vec<u8>,
    pub prev_hash: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Does the actual lock -> read-last -> hash -> insert sequence against
/// whatever connection/transaction it's handed. Not exposed directly: call
/// `record` (own transaction) or `record_in_tx` (caller's existing
/// transaction), depending on whether the audit write needs to be atomic
/// with some other write the caller is already doing.
async fn append_locked(
    conn: &mut PgConnection,
    org_id: Option<Uuid>,
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: &serde_json::Value,
) -> ApiResult<AuditEntry> {
    sqlx::query!("select pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    // Ordered by `seq` (a bigserial, see migrations/0002_audit_log_seq.sql),
    // not `created_at` — timestamp resolution can tie under rapid
    // lock-serialized inserts, and a UUID tiebreak would be arbitrary with
    // respect to true insertion order. `seq` never ties.
    let prev_hash: Option<Vec<u8>> =
        sqlx::query_scalar!("select event_hash from audit_log order by seq desc limit 1")
            .fetch_optional(&mut *conn)
            .await?;

    // `org_id` goes into the hashed payload here, in exactly one place,
    // rather than being left to each call site to remember. That is what
    // makes `audit_log.org_id` — which is outside the hash, see
    // migrations/0005 — safe to rely on for tenant filtering: the column can
    // only disagree with the chain if someone edits the database directly,
    // and then it disagrees with a digest that anyone holding the payload can
    // recompute. Overwriting rather than merging is deliberate: a caller that
    // passes a different `org_id` in its own payload is confused, and the
    // authenticated one must win.
    let payload = match (org_id, payload) {
        (Some(id), serde_json::Value::Object(map)) => {
            let mut map = map.clone();
            map.insert("org_id".into(), serde_json::json!(id));
            serde_json::Value::Object(map)
        }
        _ => payload.clone(),
    };

    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("audit payload did not serialize: {e}")))?;
    let event_hash = compute_event_hash(event_type, ref_id, prev_hash.as_deref(), &payload_bytes);

    let row = sqlx::query!(
        r#"
        insert into audit_log (org_id, event_type, ref_id, event_hash, prev_hash)
        values ($1, $2, $3, $4, $5)
        returning id, created_at
        "#,
        org_id,
        event_type,
        ref_id,
        event_hash,
        prev_hash,
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(AuditEntry {
        id: row.id,
        org_id,
        event_type: event_type.to_string(),
        ref_id,
        event_hash,
        prev_hash,
        created_at: row.created_at,
    })
}

/// Append one event to the chain in its own transaction. Use this from a
/// call site that isn't already inside a `sqlx::Transaction` (e.g. right
/// after a plain single-statement UPDATE/INSERT completes).
pub async fn record(
    db: &PgPool,
    org_id: Option<Uuid>,
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: serde_json::Value,
) -> ApiResult<AuditEntry> {
    let mut tx = db.begin().await?;
    let entry = append_locked(&mut *tx, org_id, event_type, ref_id, &payload).await?;
    tx.commit().await?;
    Ok(entry)
}

/// Append one event as part of a transaction the caller already holds.
/// `verify::record_valid_proof` uses this so the `proof_verified` audit
/// entry commits or rolls back atomically with the nonce consumption and
/// the request's flip to `fulfilled` — a crash or error between "proof
/// accepted" and "audit entry written" can't happen, because they're the
/// same transaction.
pub async fn record_in_tx(
    tx: &mut sqlx::PgTransaction<'_>,
    org_id: Option<Uuid>,
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: serde_json::Value,
) -> ApiResult<AuditEntry> {
    append_locked(&mut **tx, org_id, event_type, ref_id, &payload).await
}

// ---------------------------------------------------------------------
// GET /orgs/:id/audit-log
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct AuditLogEntryResponse {
    id: Uuid,
    /// Position in the global chain. Exposed because a tenant's view is a
    /// *filter* over one global hash chain, not a chain of its own — so
    /// consecutive rows here will normally have non-consecutive `seq`, and a
    /// consumer that tried to check `prev_hash == previous.event_hash`
    /// across this filtered list would be checking something that was never
    /// true. `scripts/export_audit_evidence.py` uses `seq` to say where in
    /// the whole log an excerpt sits.
    seq: i64,
    event_type: String,
    ref_id: Option<Uuid>,
    event_hash: String,
    prev_hash: Option<String>,
    created_at: DateTime<Utc>,
}

/// An org's own trail. `OrgAuth`-guarded, and additionally checked against
/// the `:id` path param so a valid key only ever exposes its own org's
/// trail.
///
/// Two attribution paths, unioned, because the log spans both eras: rows
/// written since migrations/0005 carry `org_id` directly, and rows written
/// before it are attributed the old way — by joining `ref_id` to one of this
/// org's disclosure requests, which is the convention every call site in
/// `disclosure::`/`verify::` already followed. Dropping the join would
/// silently truncate every tenant's history at the migration boundary.
///
/// Events that name no disclosure request — a product registered, its terms
/// amended — are only reachable through the first path, which is the reason
/// the column exists.
async fn get_org_audit_log(
    OrgAuth(auth_org_id): OrgAuth,
    Path(path_org_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<AuditLogEntryResponse>>> {
    if auth_org_id != path_org_id {
        return Err(ApiError::Forbidden);
    }

    let rows = sqlx::query!(
        r#"
        select al.id, al.event_type, al.ref_id, al.event_hash, al.prev_hash, al.created_at,
               al.seq as "seq!"
        from audit_log al
        where al.org_id = $1
           or (al.org_id is null
               and exists (select 1 from disclosure_requests dr
                            where dr.id = al.ref_id and dr.org_id = $1))
        order by al.seq asc
        "#,
        path_org_id,
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AuditLogEntryResponse {
                id: r.id,
                seq: r.seq,
                event_type: r.event_type,
                ref_id: r.ref_id,
                event_hash: encode_b64(&r.event_hash),
                prev_hash: r.prev_hash.map(|h| encode_b64(&h)),
                created_at: r.created_at,
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_hash_is_deterministic() {
        let a = compute_event_hash("disclosure_request_created", Some(Uuid::nil()), None, b"{}");
        let b = compute_event_hash("disclosure_request_created", Some(Uuid::nil()), None, b"{}");
        assert_eq!(a, b);
    }

    #[test]
    fn event_hash_changes_if_payload_changes() {
        // This IS the "hash is genuinely computed over the payload, not
        // decorative" property: two events identical in every other field
        // but a different payload byte must not hash the same.
        let ref_id = Some(Uuid::nil());
        let a = compute_event_hash("proof_verified", ref_id, None, br#"{"valid":true}"#);
        let b = compute_event_hash("proof_verified", ref_id, None, br#"{"valid":false}"#);
        assert_ne!(a, b, "tampering with the payload must change the hash");
    }

    #[test]
    fn event_hash_changes_if_prev_hash_changes() {
        let a = compute_event_hash("x", None, Some(&[1u8; 32]), b"{}");
        let b = compute_event_hash("x", None, Some(&[2u8; 32]), b"{}");
        assert_ne!(a, b, "the chain link itself must affect the hash, or a forged predecessor wouldn't be detectable");
    }

    #[test]
    fn framing_prevents_concatenation_ambiguity() {
        // Without length-prefixing, event_type="ab" + payload="cd" would
        // hash identically to event_type="a" + payload="bcd" (both
        // concatenate to "abcd"). Framing must make these different.
        let a = compute_event_hash("ab", None, None, b"cd");
        let b = compute_event_hash("a", None, None, b"bcd");
        assert_ne!(a, b, "length-framed components must not be confusable across a field boundary");
    }

    /// Builds a short in-memory chain the same way `append_locked` would
    /// (each entry's `prev_hash` is the previous entry's `event_hash`),
    /// confirms the linkage holds end to end, and then confirms that
    /// tampering with one entry's payload — recomputing its hash with the
    /// same event_type/ref_id/prev_hash but a different payload — produces
    /// a different `event_hash` than what's "on record", which is exactly
    /// what would let a verifier notice the tamper (the recomputed hash for
    /// the tampered entry no longer matches, AND it no longer matches what
    /// the next entry in the chain recorded as ITS prev_hash).
    #[test]
    fn chain_integrity_holds_and_tampering_is_detectable() {
        struct ChainEntry {
            event_type: &'static str,
            ref_id: Uuid,
            payload: serde_json::Value,
            prev_hash: Option<Vec<u8>>,
            event_hash: Vec<u8>,
        }

        fn append(
            chain: &mut Vec<ChainEntry>,
            event_type: &'static str,
            ref_id: Uuid,
            payload: serde_json::Value,
        ) {
            let prev_hash = chain.last().map(|e| e.event_hash.clone());
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            let event_hash = compute_event_hash(event_type, Some(ref_id), prev_hash.as_deref(), &payload_bytes);
            chain.push(ChainEntry { event_type, ref_id, payload, prev_hash, event_hash });
        }

        let request_id = Uuid::new_v4();
        let mut chain = Vec::new();
        append(&mut chain, "disclosure_request_created", request_id, serde_json::json!({"circuit": "emergency_session"}));
        append(&mut chain, "proof_verification_failed", request_id, serde_json::json!({"valid": false}));
        append(&mut chain, "proof_verified", request_id, serde_json::json!({"valid": true}));

        // 1. Every entry after the first must genuinely chain: its
        // prev_hash equals the immediately-prior entry's event_hash.
        for i in 1..chain.len() {
            assert_eq!(
                chain[i].prev_hash.as_deref(),
                Some(chain[i - 1].event_hash.as_slice()),
                "entry {i}'s prev_hash must equal entry {}'s event_hash",
                i - 1
            );
        }
        assert_eq!(chain[0].prev_hash, None, "the first entry in a fresh chain has no predecessor");

        // 2. Every entry's stored event_hash must actually be reproducible
        // from its own fields — proving the hash is a real function of the
        // payload, not a random/opaque value that happens to differ.
        for entry in &chain {
            let payload_bytes = serde_json::to_vec(&entry.payload).unwrap();
            let recomputed =
                compute_event_hash(entry.event_type, Some(entry.ref_id), entry.prev_hash.as_deref(), &payload_bytes);
            assert_eq!(recomputed, entry.event_hash, "stored event_hash must match a fresh recomputation");
        }

        // 3. Tamper with the middle entry's payload (as if someone edited
        // the row's underlying data after the fact) and recompute its hash
        // with everything else unchanged: it must NOT match the original
        // stored event_hash, and it must NOT match what the next entry in
        // the chain recorded as its prev_hash either — both are how a
        // verifier walking the chain would notice the tamper.
        let tampered_payload = serde_json::json!({"valid": true}); // was {"valid": false}
        let tampered_payload_bytes = serde_json::to_vec(&tampered_payload).unwrap();
        let tampered_hash = compute_event_hash(
            chain[1].event_type,
            Some(chain[1].ref_id),
            chain[1].prev_hash.as_deref(),
            &tampered_payload_bytes,
        );
        assert_ne!(tampered_hash, chain[1].event_hash, "tampered payload must not reproduce the original hash");
        assert_ne!(
            chain[2].prev_hash.as_deref(),
            Some(tampered_hash.as_slice()),
            "a tampered predecessor must not match what the next entry actually recorded as prev_hash"
        );
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(10).connect(&url).await.ok()
        }

        /// Real-DB version of the chain-linkage property: append events
        /// for real, re-read them from Postgres, and confirm each one's
        /// `prev_hash` really is the previous row's `event_hash` and each
        /// `event_hash` really is a function of that row's own stored
        /// contents — the exact walk an external auditor performs.
        ///
        /// The three appends go through `record_in_tx` inside ONE
        /// transaction, and that is load-bearing rather than incidental.
        /// `append_locked` takes `pg_advisory_xact_lock`, which is held
        /// until the transaction ends, so no other writer can interleave a
        /// row between our three — they are guaranteed adjacent in `seq`,
        /// and adjacency is exactly what a linkage assertion needs.
        ///
        /// The obvious alternative — three separate `record` calls, then
        /// walk every row in the resulting seq window — was tried and is
        /// genuinely unsound as a test, for two independent reasons:
        ///
        ///   1. `cargo test` runs test functions concurrently, and other
        ///      modules' db tests (disclosure, verify) call `audit::record`
        ///      for real, so foreign rows land between ours. Survivable —
        ///      just walk the window rather than assuming adjacency.
        ///   2. Fatal: those same tests DELETE their audit rows in cleanup
        ///      (`delete from audit_log where ref_id in (...)`, see
        ///      disclosure/mod.rs and verify/mod.rs). A foreign row can be
        ///      inserted between ours and then deleted before we read,
        ///      leaving a hole in the window. The walk then compares two
        ///      rows that were never adjacent and reports a broken chain
        ///      when nothing is broken.
        ///
        /// No window-based formulation survives (2), because the deletes
        /// are concurrent with the read. Holding the chain lock across all
        /// three appends removes the interleaving instead of trying to
        /// tolerate it, which is why this test is structured that way.
        ///
        /// (Those cleanup deletes are also the whole explanation for any
        /// `prev_hash` in a dev database that points at a row which is no
        /// longer there. That is test housekeeping leaving holes, not
        /// evidence of a forked chain — nothing in the production code path
        /// ever deletes from `audit_log`.)
        #[tokio::test]
        async fn appended_entries_form_a_real_chain_in_postgres() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };

            let ref_id = Uuid::new_v4();
            let payloads = [
                serde_json::json!({"n": 1}),
                serde_json::json!({"n": 2}),
                serde_json::json!({"n": 3}),
            ];
            let types = ["test_event_a", "test_event_b", "test_event_c"];

            let mut tx = db.begin().await.unwrap();
            let mut appended = Vec::new();
            for (event_type, payload) in types.iter().zip(payloads.iter()) {
                appended.push(record_in_tx(&mut tx, None, event_type, Some(ref_id), payload.clone()).await.unwrap());
            }
            tx.commit().await.unwrap();

            // Re-read from Postgres rather than trusting what `record_in_tx`
            // returned: the point is that the persisted rows form the chain,
            // not that the in-memory return values agree with each other.
            let rows = sqlx::query!(
                r#"
                select id, event_type, event_hash, prev_hash
                from audit_log
                where ref_id = $1
                order by seq asc
                "#,
                ref_id,
            )
            .fetch_all(&db)
            .await
            .unwrap();

            assert_eq!(rows.len(), 3, "all three appends must have committed");
            for (i, row) in rows.iter().enumerate() {
                assert_eq!(row.id, appended[i].id, "row {i} out of insertion order");
                assert_eq!(row.event_type, types[i]);
            }

            // Linkage: rows 2 and 3 chain to their immediate predecessor.
            // Row 1 chains to whatever preceded our transaction, which is
            // some other test's row or nothing — not ours to assert on.
            for i in 1..rows.len() {
                assert_eq!(
                    rows[i].prev_hash.as_deref(),
                    Some(rows[i - 1].event_hash.as_slice()),
                    "row {i} (id {}) must chain to the row immediately before it (id {})",
                    rows[i].id,
                    rows[i - 1].id,
                );
            }

            // Integrity: every persisted event_hash must be reproducible
            // from that row's own stored fields. This is what makes the
            // chain tamper-EVIDENT rather than merely tamper-labelled —
            // editing a payload after the fact would break this equality
            // even if prev_hash still lined up.
            for (i, row) in rows.iter().enumerate() {
                let recomputed = compute_event_hash(
                    types[i],
                    Some(ref_id),
                    row.prev_hash.as_deref(),
                    &serde_json::to_vec(&payloads[i]).unwrap(),
                );
                assert_eq!(recomputed, row.event_hash, "row {i}'s hash is not a function of its contents");
            }

            // And `record` (its own transaction, the path most call sites
            // use) must produce the same self-consistency property.
            let solo_ref = Uuid::new_v4();
            let solo_payload = serde_json::json!({"solo": true});
            let solo = record(&db, None, "test_event_solo", Some(solo_ref), solo_payload.clone()).await.unwrap();
            let solo_row = sqlx::query!(
                "select event_hash, prev_hash from audit_log where id = $1",
                solo.id,
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(
                compute_event_hash(
                    "test_event_solo",
                    Some(solo_ref),
                    solo_row.prev_hash.as_deref(),
                    &serde_json::to_vec(&solo_payload).unwrap(),
                ),
                solo_row.event_hash,
            );

            let _ = sqlx::query!("delete from audit_log where ref_id in ($1, $2)", ref_id, solo_ref)
                .execute(&db)
                .await;
        }

        /// `record_in_tx` inside a rolled-back transaction must leave no
        /// trace — proving it really participates in the caller's
        /// transaction rather than silently committing on its own.
        #[tokio::test]
        async fn record_in_tx_rolls_back_with_the_caller_transaction() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };

            let ref_id = Uuid::new_v4();
            let mut tx = db.begin().await.unwrap();
            let entry = record_in_tx(&mut tx, None, "should_not_persist", Some(ref_id), serde_json::json!({})).await.unwrap();
            tx.rollback().await.unwrap();

            let found: Option<Uuid> = sqlx::query_scalar!("select id from audit_log where id = $1", entry.id)
                .fetch_optional(&db)
                .await
                .unwrap();
            assert_eq!(found, None, "a rolled-back transaction's audit entry must not be visible");
        }
    }
}
