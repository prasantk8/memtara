// Audit: a hash-chained, append-only log against `audit_log`
// (migrations/0001_init.sql — `id, event_type, ref_id, event_hash,
// prev_hash, created_at`; schema is final for this pass, not touched here).
//
// Chain scope: GLOBAL, not per-org. Two reasons, both forced by the schema
// being final:
//   1. `audit_log` has no `org_id` column to key a per-org chain off of, and
//      `ref_id` is heterogeneous — depending on `event_type` it names a
//      `disclosure_requests` row (created/revoked/proof events) or, in
//      principle, some other entity later. There's no single reliable join
//      target to answer "what is this org's previous row" without already
//      committing to the disclosure-centric convention this module uses.
//   2. A global chain is a *stronger* tamper-evidence property than a
//      per-org one, not a weaker one: it also commits to the real
//      interleaving order of events across every org, so tampering with
//      history can't hide by, e.g., reordering events between two orgs'
//      otherwise-independent chains. `GET /orgs/:id/audit-log` still gives
//      each org only its own rows (filtered via a join through
//      `disclosure_requests.org_id` — see below), it just proves them
//      against a chain that spans the whole log, not a chain scoped to
//      that filter.
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
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: &serde_json::Value,
) -> ApiResult<AuditEntry> {
    sqlx::query!("select pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    let prev_hash: Option<Vec<u8>> =
        sqlx::query_scalar!("select event_hash from audit_log order by created_at desc, id desc limit 1")
            .fetch_optional(&mut *conn)
            .await?;

    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("audit payload did not serialize: {e}")))?;
    let event_hash = compute_event_hash(event_type, ref_id, prev_hash.as_deref(), &payload_bytes);

    let row = sqlx::query!(
        r#"
        insert into audit_log (event_type, ref_id, event_hash, prev_hash)
        values ($1, $2, $3, $4)
        returning id, created_at
        "#,
        event_type,
        ref_id,
        event_hash,
        prev_hash,
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(AuditEntry {
        id: row.id,
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
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: serde_json::Value,
) -> ApiResult<AuditEntry> {
    let mut tx = db.begin().await?;
    let entry = append_locked(&mut *tx, event_type, ref_id, &payload).await?;
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
    event_type: &str,
    ref_id: Option<Uuid>,
    payload: serde_json::Value,
) -> ApiResult<AuditEntry> {
    append_locked(&mut **tx, event_type, ref_id, &payload).await
}

// ---------------------------------------------------------------------
// GET /orgs/:id/audit-log
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct AuditLogEntryResponse {
    id: Uuid,
    event_type: String,
    ref_id: Option<Uuid>,
    event_hash: String,
    prev_hash: Option<String>,
    created_at: DateTime<Utc>,
}

/// An org's own trail: every audit_log row whose `ref_id` names one of
/// *this* org's disclosure requests (the convention every call site in
/// `disclosure::`/`verify::` follows — see their `audit::record(...)`
/// calls, which all pass the disclosure request's id as `ref_id`).
/// `OrgAuth`-guarded, and additionally checked against the `:id` path
/// param so a valid key only ever exposes its own org's trail.
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
        select al.id, al.event_type, al.ref_id, al.event_hash, al.prev_hash, al.created_at
        from audit_log al
        join disclosure_requests dr on dr.id = al.ref_id
        where dr.org_id = $1
        order by al.created_at asc, al.id asc
        "#,
        path_org_id,
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AuditLogEntryResponse {
                id: r.id,
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

        /// Real-DB version of the chain-linkage property: append several
        /// events for real via `record`, then re-read the *whole table*
        /// back and confirm every row's `prev_hash` equals the immediately
        /// preceding row's `event_hash` in `(created_at, id)` order — the
        /// same property `get_org_audit_log` and any external auditor would
        /// check.
        ///
        /// Deliberately does NOT assume `e2.prev_hash == e1.event_hash`
        /// directly: the chain is process-wide/global (see module doc
        /// comment), `cargo test` runs test functions concurrently by
        /// default, and several other modules' db tests (disclosure,
        /// verify) call `audit::record` for real as part of their own
        /// flows — so another test's event can genuinely land between this
        /// test's `e1` and `e2` in the real chain. That's not a bug; a
        /// global chain is supposed to capture the true interleaving of
        /// concurrent writers. So this test checks the property that's
        /// actually load-bearing (the whole chain is genuinely linked, and
        /// our 3 events appear in the order we inserted them somewhere in
        /// it), not an assumption that nothing else writes to `audit_log`
        /// while this test runs.
        #[tokio::test]
        async fn appended_entries_form_a_real_chain_in_postgres() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };

            let ref_id = Uuid::new_v4();
            let e1 = record(&db, "test_event_a", Some(ref_id), serde_json::json!({"n": 1})).await.unwrap();
            let e2 = record(&db, "test_event_b", Some(ref_id), serde_json::json!({"n": 2})).await.unwrap();
            let e3 = record(&db, "test_event_c", Some(ref_id), serde_json::json!({"n": 3})).await.unwrap();

            // Every row's persisted event_hash must be a real function of
            // its own stored fields — not "whatever record() happened to
            // return" but reproducible from scratch.
            let recomputed_e2 = compute_event_hash(
                "test_event_b",
                Some(ref_id),
                e2.prev_hash.as_deref(),
                &serde_json::to_vec(&serde_json::json!({"n": 2})).unwrap(),
            );
            assert_eq!(recomputed_e2, e2.event_hash);

            // Walk every row committed between e1 and e3 (inclusive) — a
            // contiguous slice of the global chain, whoever wrote the rows
            // — and confirm each one's prev_hash equals the row
            // immediately before it in true insertion order. This holds
            // unconditionally: `append_locked`'s advisory lock means the
            // "select last row" that produced each row's prev_hash was
            // never racing a concurrent insert, so (created_at, id) order
            // on the finished table always reproduces true causal order.
            let rows = sqlx::query!(
                r#"
                select id, event_hash, prev_hash
                from audit_log
                where created_at >= $1 and created_at <= $2
                order by created_at asc, id asc
                "#,
                e1.created_at,
                e3.created_at,
            )
            .fetch_all(&db)
            .await
            .unwrap();

            for i in 1..rows.len() {
                assert_eq!(
                    rows[i].prev_hash.as_deref(),
                    Some(rows[i - 1].event_hash.as_slice()),
                    "row {i} (id {}) must chain to the row immediately before it (id {})",
                    rows[i].id,
                    rows[i - 1].id,
                );
            }

            // And our three events specifically must appear, in the order
            // we inserted them, each still carrying the exact event_hash
            // `record` returned for it.
            let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
            let pos1 = ids.iter().position(|&id| id == e1.id).expect("e1 must be in the window");
            let pos2 = ids.iter().position(|&id| id == e2.id).expect("e2 must be in the window");
            let pos3 = ids.iter().position(|&id| id == e3.id).expect("e3 must be in the window");
            assert!(pos1 < pos2 && pos2 < pos3, "our three events must appear in insertion order");
            assert_eq!(rows[pos1].event_hash, e1.event_hash);
            assert_eq!(rows[pos2].event_hash, e2.event_hash);
            assert_eq!(rows[pos3].event_hash, e3.event_hash);

            let _ = sqlx::query!("delete from audit_log where id in ($1, $2, $3)", e1.id, e2.id, e3.id)
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
            let entry = record_in_tx(&mut tx, "should_not_persist", Some(ref_id), serde_json::json!({})).await.unwrap();
            tx.rollback().await.unwrap();

            let found: Option<Uuid> = sqlx::query_scalar!("select id from audit_log where id = $1", entry.id)
                .fetch_optional(&db)
                .await
                .unwrap();
            assert_eq!(found, None, "a rolled-back transaction's audit entry must not be visible");
        }
    }
}
