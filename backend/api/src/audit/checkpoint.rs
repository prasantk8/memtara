// Signed, published checkpoints over the head of the global audit chain.
//
// ---------------------------------------------------------------------
// WHAT THIS IS FOR
// ---------------------------------------------------------------------
// `audit/mod.rs`'s chain proves that every row WITH A SUCCESSOR is
// tamper-evident: row N+1's `prev_hash` commits to row N's `event_hash`.
// The terminal row has no successor, nothing commits to its hash, and
// because `payload` is deliberately not stored the hash cannot be
// recomputed from the database either. `update audit_log set event_hash =
// <32 forged bytes>` on the last row was therefore invisible from the
// database alone — and the last row is the newest decision, which is the
// one a regulator or a claimant actually asks about.
//
// A checkpoint is a statement made OUTSIDE the chain and signed with the
// deployment's Ed25519 key: "at checkpoint C, the head was `event_hash` H
// at `seq` S, and there were N rows at or below S." Anyone who has fetched
// it can hold the terminal row to it. The database can be rewritten; the
// signature cannot be, without the private key.
//
// ---------------------------------------------------------------------
// FOUR DECISIONS, MADE ON PURPOSE
// ---------------------------------------------------------------------
//
// 1. WHAT IS SIGNED — `checkpoint_no`, `head_seq`, `head_event_hash`,
//    `covered_row_count`, `prev_checkpoint_hash`, `iat`, `iss`, `chain`.
//
//    `head_seq` + `head_event_hash` is the minimum that pins the terminal
//    row (a hash with no position doesn't say which row it pins). The other
//    three each answer an attack the minimum does not:
//
//      * `covered_row_count` answers TRUNCATION. Deleting rows off the end
//        of the log is the sibling attack to editing the last one, and a
//        (seq, hash) pair does not catch it — chop rows 900..1000 and the
//        surviving prefix is still internally consistent. A count over
//        `seq <= head_seq` is a property of the whole covered range, so
//        any deletion inside it shows up. See `Failure::RowCountMismatch`
//        and the exact limits in "WHAT THIS DOES NOT CATCH" below.
//      * `checkpoint_no` answers REPLAY. Without a monotonic counter,
//        someone who kept checkpoint 3 could delete checkpoints 4..12 (and
//        the rows they cover) and present 3 as current — every field in it
//        verifies. A counterparty that has ever seen 12 rejects a later
//        claim of 3, and the number is inside the signature so it cannot
//        be renumbered.
//      * `prev_checkpoint_hash` chains the checkpoints to each other, so a
//        checkpoint removed from the middle of the run breaks the next
//        one's link — the same bargain, one level up.
//
//    `iss` and `chain` are domain separation: a signed blob from this key
//    must not be reinterpretable as a statement about a different
//    deployment or a different (e.g. future per-org) chain. `typ` in the
//    JWS header does the same job against the proof tokens the same key
//    issues (RFC 8725 §3.11).
//
// 2. WHICH KEY — the existing `crypto::signer::IssuerKey`, not a new one.
//
//    A second key would have to be generated, stored, rotated, published in
//    its own JWKS and validated by every relying party, and it would buy
//    one thing: an audit checkpoint would survive compromise of the proof
//    token key. That is not a threat worth a second key here, because the
//    two keys would live in the same process, loaded from the same
//    environment, on the same host — an attacker who has one has both, so
//    the separation is bookkeeping rather than security. Reusing the issuer
//    key also means a checkpoint verifies against the JWKS a relying party
//    ALREADY fetches, with the JOSE library it already has, which is the
//    difference between "publishable" and "published".
//
//    The one case that would change the answer: if checkpoints were ever
//    co-signed by a party outside this deployment (a customer's own key, a
//    notary), that key must obviously be separate. That is the external
//    anchoring work, and it is not built — see (4).
//
// 3. WHEN IT IS EMITTED — a background loop, on the earlier of N events or
//    T seconds, plus on demand.
//
//    Both bounds are needed and neither alone is enough. Events-only leaves
//    a quiet deployment's newest decision unprotected indefinitely (the
//    single-decision-per-day private bank is the realistic case, and it is
//    exactly the customer who cares). Time-only leaves a busy deployment
//    with thousands of unprotected rows between ticks. On-demand exists
//    because the moment a checkpoint is most wanted is immediately before
//    an export or a dispute, and nobody should have to wait out a timer.
//
//    STATE THE INTERVAL PLAINLY, because a customer will ask: the interval
//    IS the window during which the newest record is unprotected. Defaults
//    are 60 seconds / 64 events (`MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS`,
//    `MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS`). It cannot be zero: a checkpoint
//    is necessarily made after the event it pins.
//
// 4. WHERE IT IS PUBLISHED — locally now, externally not yet, and the
//    difference matters.
//
//    BUILT: the checkpoint is stored, chained to its predecessor, and
//    served unauthenticated at `GET /audit/checkpoints/latest` and
//    `GET /audit/checkpoints/covering/:seq` as a compact JWS that anybody
//    can verify against `/.well-known/jwks.json` without touching this
//    database. That is a real improvement — the tampered-with row is now
//    contradicted by a signature — and it is honestly only half.
//
//    NOT BUILT: an external witness. We can still delete our own
//    checkpoints. What stops a rewritten history today is (a) needing the
//    private key and (b) every copy a counterparty already fetched. The
//    schema is ready for the other half — `audit_checkpoints.anchor_target`
//    / `anchor_ref` / `anchored_at`, currently null on every row — so that
//    an anchoring job (RFC 3161 timestamp, a commit in a public repo, an
//    OpenTimestamps receipt, or simply mailing the digest to the customer's
//    own compliance address) is additive rather than another migration.
//    Do not describe checkpoints as removing our ability to rewrite history
//    until one of those runs.
//
// ---------------------------------------------------------------------
// WHAT THIS DOES NOT CATCH — read before quoting it to anyone
// ---------------------------------------------------------------------
//   * Rows appended after the newest checkpoint. That is the residual
//     window described in (3), and it is the honest cost of this design.
//   * CONTENT tamper. `event_hash` commits to `event_type` and `payload`,
//     but `payload` is not stored, so rewriting `event_type` in place while
//     leaving the hash columns alone stays invisible to anyone who does not
//     independently hold the payload. Unrelated finding, unrelated fix
//     (ship payloads in the offline bundle). A head checkpoint does not
//     address it.
//   * Delete-and-replace inside the covered range, where the attacker
//     reinserts a row at the same `seq` carrying the same `event_hash` but
//     different content. Count and linkage both still hold. This is the
//     same blind spot as the previous bullet — the hash is a commitment to
//     a payload nobody kept — not a separate one.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use std::time::Duration;

use crate::crypto::signer::IssuerKey;
use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

use super::{encode_b64, AUDIT_CHAIN_LOCK_KEY};

/// Names the chain these checkpoints are about. Versioned because the log is
/// global today (`audit/mod.rs` explains why) and a future per-org chain
/// would be a different object — a checkpoint about one must never be
/// readable as a checkpoint about the other.
pub const CHAIN_ID: &str = "memtara.audit_log.global.v1";

/// JWS `typ`. Distinct from the proof tokens' `"JWT"` so a relying party
/// cannot be handed a checkpoint where it expected an attestation, or the
/// reverse (RFC 8725 §3.11).
pub const CHECKPOINT_TYP: &str = "memtara-audit-checkpoint+jwt";

/// The signed statement. Field order here is the JSON field order, and the
/// JSON bytes are what gets signed — but nothing downstream depends on that,
/// because a compact JWS carries its own payload segment and a verifier
/// checks the bytes it was handed rather than re-serializing. That is the
/// specific reason this is a JWS and not a hand-framed digest: no
/// canonicalization rule for a third party to get wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointClaims {
    /// This deployment's public base URL, matching proof tokens' `iss`.
    pub iss: String,
    /// `CHAIN_ID` — which chain this is a statement about.
    pub chain: String,
    /// Monotonic counter. Anti-replay: see decision (1).
    pub checkpoint_no: i64,
    /// `audit_log.seq` of the row this checkpoint pins.
    pub head_seq: i64,
    /// base64url-no-pad of that row's 32-byte `event_hash`.
    pub head_event_hash: String,
    /// Rows in `audit_log` with `seq <= head_seq` at signing time. Anti-
    /// truncation: see decision (1).
    pub covered_row_count: i64,
    /// base64url-no-pad SHA-256 of the previous checkpoint's compact JWS,
    /// null for the first. Same null-means-genesis convention as
    /// `audit_log.prev_hash`.
    pub prev_checkpoint_hash: Option<String>,
    /// Seconds since the Unix epoch. Stored in `signed_at` at whole-second
    /// precision so the column and the claim are literally the same instant
    /// rather than one truncation apart.
    pub iat: i64,
}

/// A checkpoint as it lives in the database: the signed bytes plus the
/// columns that index them.
#[derive(Debug, Clone)]
pub struct StoredCheckpoint {
    pub checkpoint_no: i64,
    pub head_seq: i64,
    pub head_event_hash: Vec<u8>,
    pub covered_row_count: i64,
    pub prev_checkpoint_hash: Option<Vec<u8>>,
    pub checkpoint_hash: Vec<u8>,
    pub signed_jws: String,
    pub kid: String,
    pub signed_at: DateTime<Utc>,
    pub anchor_target: Option<String>,
    pub anchor_ref: Option<String>,
    pub anchored_at: Option<DateTime<Utc>>,
    /// The external witness's raw bytes (migrations/0012) — DER for the
    /// RFC 3161 case. `None` alongside null `anchor_target`/`anchor_ref`/
    /// `anchored_at` (the database enforces that these four are always all
    /// null or all present, migrations/0012's `audit_checkpoints_anchor_complete`).
    pub anchor_receipt: Option<Vec<u8>>,
}

/// What the database says right now about the range a checkpoint covers.
/// Separated from the comparison logic so the comparison is a pure function
/// with no I/O, and can therefore be tested against every failure mode
/// without arranging a database in each of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRange {
    /// `event_hash` of the row currently at `head_seq`, or `None` if there
    /// is no such row (it was deleted).
    pub head_event_hash: Option<Vec<u8>>,
    /// Rows currently present with `seq <= head_seq`.
    pub covered_row_count: i64,
}

/// One way a checkpoint and the database can disagree. An enum rather than
/// a bare bool because "the log is not what we signed" is not actionable —
/// which of these it is determines whether you are looking at an edit, a
/// deletion, or a forged signature, and those are three different incidents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum Failure {
    /// The compact JWS does not verify against the published JWKS, or is
    /// not a checkpoint at all. Someone rewrote `signed_jws`.
    SignatureInvalid { detail: String },
    /// The JWS verifies but the indexed columns disagree with it. Someone
    /// edited the columns and left the evidence alone.
    ColumnsDisagreeWithSignedPayload { field: &'static str },
    /// No `audit_log` row at `head_seq` any more.
    HeadRowMissing { head_seq: i64 },
    /// THE terminal-row forgery this whole module exists for.
    HeadHashMismatch { head_seq: i64, signed: String, observed: String },
    /// Rows were removed from (or inserted into) the covered range.
    RowCountMismatch { signed: i64, observed: i64 },
    /// This checkpoint's `prev_checkpoint_hash` does not match the
    /// checkpoint that actually precedes it — one was removed or replaced.
    CheckpointChainBroken { checkpoint_no: i64 },
}

/// The verdict for one checkpoint against the live database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    pub checkpoint_no: i64,
    pub head_seq: i64,
    /// True only when `failures` is empty. Serialized as its own field
    /// because a consumer that checks a boolean must not be able to read a
    /// non-empty failure list as a pass by accident.
    pub intact: bool,
    pub failures: Vec<Failure>,
}

// ---------------------------------------------------------------------
// Pure core
// ---------------------------------------------------------------------

/// Compare a signed statement against what the database currently shows.
/// No I/O, no signature check (that is `verify_jws` below) — just the
/// arithmetic of "does the log still match what we swore to".
pub fn compare(signed: &CheckpointClaims, observed: &ObservedRange) -> Vec<Failure> {
    let mut failures = Vec::new();

    match &observed.head_event_hash {
        None => failures.push(Failure::HeadRowMissing { head_seq: signed.head_seq }),
        Some(hash) if encode_b64(hash) != signed.head_event_hash => {
            failures.push(Failure::HeadHashMismatch {
                head_seq: signed.head_seq,
                signed: signed.head_event_hash.clone(),
                observed: encode_b64(hash),
            })
        }
        Some(_) => {}
    }

    if observed.covered_row_count != signed.covered_row_count {
        failures.push(Failure::RowCountMismatch {
            signed: signed.covered_row_count,
            observed: observed.covered_row_count,
        });
    }

    failures
}

/// SHA-256 over the compact JWS bytes. This is what the NEXT checkpoint
/// links to, so it must be taken over the signed serialization rather than
/// over the parsed claims — linking to a re-serialization would let two
/// different byte strings share a link value.
pub fn checkpoint_hash(signed_jws: &str) -> Vec<u8> {
    Sha256::digest(signed_jws.as_bytes()).to_vec()
}

/// The Ed25519 public key exactly as `/.well-known/jwks.json` publishes it.
///
/// Deliberately routed through the published JWKS rather than reaching into
/// `IssuerKey` for the key directly: this server then verifies checkpoints
/// the same way an outside party does, so a divergence between the key we
/// sign with and the key we publish cannot hide behind an internal shortcut.
/// Same reasoning as `ops::health`'s published-vkey comparison.
fn published_verifying_key(signer: &IssuerKey) -> anyhow::Result<VerifyingKey> {
    let jwks = signer.jwks();
    let x = jwks["keys"][0]["x"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("published JWKS has no OKP `x` parameter"))?
        .to_string();
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&x)
        .map_err(|_| anyhow::anyhow!("published JWKS `x` is not base64url"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("published JWKS `x` is not 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("published JWKS `x` is not a valid Ed25519 point: {e}"))
}

/// Verify a compact JWS checkpoint against the published key and return its
/// claims. Rejects anything whose header is not EdDSA with our checkpoint
/// `typ` BEFORE looking at the signature, so a proof token can never be
/// mistaken for a checkpoint even if it verifies (same key, different `typ`).
pub fn verify_jws(signer: &IssuerKey, token: &str) -> anyhow::Result<CheckpointClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("not a compact JWS: expected three dot-separated parts, got {}", parts.len());
    }

    let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header["alg"] != "EdDSA" {
        anyhow::bail!("unexpected alg {:?}; this issuer signs EdDSA only", header["alg"]);
    }
    if header["typ"] != CHECKPOINT_TYP {
        anyhow::bail!("typ is {:?}, not {CHECKPOINT_TYP} — this is not an audit checkpoint", header["typ"]);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)
        .map_err(|e| anyhow::anyhow!("signature is not 64 bytes: {e}"))?;
    published_verifying_key(signer)?
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|e| anyhow::anyhow!("signature does not verify against the published JWKS: {e}"))?;

    let claims: CheckpointClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    if claims.chain != CHAIN_ID {
        anyhow::bail!("checkpoint is about chain {:?}, not {CHAIN_ID}", claims.chain);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------
// Reading the chain
// ---------------------------------------------------------------------

/// The chain's current terminal row: `(seq, event_hash)`, or `None` on an
/// empty log. Ordered by `seq` for the same reason `append_locked` is —
/// `created_at` is not a safe total order (migrations/0002).
async fn read_head(conn: &mut PgConnection) -> ApiResult<Option<(i64, Vec<u8>)>> {
    let row = sqlx::query!(
        r#"select seq as "seq!", event_hash from audit_log order by seq desc limit 1"#
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|r| (r.seq, r.event_hash)))
}

async fn read_observed_range(conn: &mut PgConnection, head_seq: i64) -> ApiResult<ObservedRange> {
    let head_event_hash: Option<Vec<u8>> =
        sqlx::query_scalar!("select event_hash from audit_log where seq = $1", head_seq)
            .fetch_optional(&mut *conn)
            .await?;
    let covered_row_count = sqlx::query_scalar!(
        r#"select count(*) as "count!" from audit_log where seq <= $1"#,
        head_seq
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(ObservedRange { head_event_hash, covered_row_count })
}

// ---------------------------------------------------------------------
// Emitting
// ---------------------------------------------------------------------

/// Why `emit` did not write a checkpoint. Returned rather than logged and
/// swallowed because "nothing to do" and "the chain went backwards" are
/// wildly different facts and the caller decides which one is an alarm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEmitted {
    /// The log is empty. Nothing to pin.
    EmptyChain,
    /// The head has not moved since the last checkpoint. Signing again
    /// would produce a second signed statement about the same chain
    /// position, which is noise at best and a replay surface at worst.
    HeadUnchanged,
}

/// Take a checkpoint over the current chain head, inside a transaction the
/// caller already holds. Mirrors `audit::record_in_tx`; use `emit` if you
/// are not already in one.
///
/// THE CALLER MUST BE IN AN EXPLICIT TRANSACTION, and that is a correctness
/// requirement, not a style preference. This runs under
/// `AUDIT_CHAIN_LOCK_KEY` — the SAME advisory lock `append_locked` takes, not
/// a second one — so that "read the head, count the covered rows, sign both"
/// is atomic with respect to appends and the count and the head can never
/// describe two different moments. `pg_advisory_xact_lock` on a connection
/// running in autocommit is released at the end of that one statement, so
/// calling this outside a transaction would take the lock and immediately
/// drop it, leaving the race it exists to close wide open and looking closed.
/// A separate lock key would serialize checkpoints against each other and
/// against nothing else, which is not the race that matters.
pub async fn emit_in_tx(
    conn: &mut PgConnection,
    signer: &IssuerKey,
) -> ApiResult<Result<StoredCheckpoint, NotEmitted>> {
    sqlx::query!("select pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    let Some((head_seq, head_event_hash)) = read_head(&mut *conn).await? else {
        return Ok(Err(NotEmitted::EmptyChain));
    };

    let previous = latest(&mut *conn).await?;
    if let Some(prev) = &previous {
        if prev.head_seq == head_seq {
            return Ok(Err(NotEmitted::HeadUnchanged));
        }
        if prev.head_seq > head_seq {
            // The chain's head is BELOW where we already swore it was, which
            // means rows were removed from the end. Refuse to sign: a new
            // checkpoint here would be a fresh, valid-looking statement that
            // the (shorter) log is fine, which is precisely the laundering
            // the checkpoint exists to prevent. The contradiction is already
            // on record in `prev`; leave it standing and make a human look.
            //
            // `Conflict` (409 with this text) rather than `Other` (500
            // "internal error") on purpose. This is not an internal failure
            // — the request conflicts with a signed statement we have
            // already published — and an operator who gets an opaque 500
            // here will go looking for a database problem instead of for
            // whoever deleted the rows. The text names both positions so the
            // gap is the first thing they see.
            return Err(ApiError::Conflict(format!(
                "refusing to checkpoint: the audit chain head is at seq {head_seq} but checkpoint \
                 {} already committed to seq {}. Rows have been removed from the end of the log. \
                 That earlier checkpoint stands as the record of it; signing over the shorter log \
                 would erase the contradiction rather than resolve it.",
                prev.checkpoint_no, prev.head_seq,
            )));
        }
    }

    let observed = read_observed_range(&mut *conn, head_seq).await?;
    let iat = Utc::now().timestamp();
    let signed_at = DateTime::from_timestamp(iat, 0)
        .ok_or_else(|| ApiError::Other(anyhow::anyhow!("system clock is outside the representable range")))?;

    let claims = CheckpointClaims {
        iss: signer.issuer().to_string(),
        chain: CHAIN_ID.to_string(),
        // `checkpoint_no` is allocated by the sequence on insert; predicting
        // it here would race. Instead the insert returns it and we sign
        // afterwards — see the two-step below.
        checkpoint_no: 0,
        head_seq,
        head_event_hash: encode_b64(&head_event_hash),
        covered_row_count: observed.covered_row_count,
        prev_checkpoint_hash: previous.as_ref().map(|p| encode_b64(&p.checkpoint_hash)),
        iat,
    };

    // Two-step, and it has to be: `checkpoint_no` comes from a Postgres
    // sequence (unforgeably monotonic, which is the whole anti-replay
    // property) and the number must be INSIDE the signature. So reserve the
    // number, sign with it, then fill in the signed bytes — all inside the
    // caller's transaction and under the chain lock, so no partially-signed
    // row is ever visible and no number is ever skipped by a concurrent
    // emit.
    let reserved = sqlx::query_scalar!(
        r#"select nextval(pg_get_serial_sequence('audit_checkpoints', 'checkpoint_no')) as "no!""#
    )
    .fetch_one(&mut *conn)
    .await?;

    let claims = CheckpointClaims { checkpoint_no: reserved, ..claims };
    let payload = serde_json::to_vec(&claims)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("checkpoint claims did not serialize: {e}")))?;
    let signed_jws = signer
        .sign_compact_jws(CHECKPOINT_TYP, &payload)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("checkpoint did not sign: {e}")))?;
    let this_hash = checkpoint_hash(&signed_jws);

    sqlx::query!(
        r#"
        insert into audit_checkpoints
            (checkpoint_no, head_seq, head_event_hash, covered_row_count,
             prev_checkpoint_hash, checkpoint_hash, signed_jws, kid, signed_at)
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        reserved,
        head_seq,
        head_event_hash,
        observed.covered_row_count,
        previous.as_ref().map(|p| p.checkpoint_hash.clone()),
        this_hash,
        signed_jws,
        signer.kid(),
        signed_at,
    )
    .execute(&mut *conn)
    .await?;

    Ok(Ok(StoredCheckpoint {
        checkpoint_no: reserved,
        head_seq,
        head_event_hash,
        covered_row_count: observed.covered_row_count,
        prev_checkpoint_hash: previous.as_ref().map(|p| p.checkpoint_hash.clone()),
        checkpoint_hash: this_hash,
        signed_jws,
        kid: signer.kid().to_string(),
        signed_at,
        anchor_target: None,
        anchor_ref: None,
        anchored_at: None,
        anchor_receipt: None,
    }))
}

// ---------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------

/// Take a checkpoint in its own transaction. The ordinary entry point:
/// the background loop and `POST /audit/checkpoints` both use this.
pub async fn emit(db: &PgPool, signer: &IssuerKey) -> ApiResult<Result<StoredCheckpoint, NotEmitted>> {
    let mut tx = db.begin().await?;
    let result = emit_in_tx(&mut tx, signer).await?;
    tx.commit().await?;
    Ok(result)
}

/// The most recent checkpoint, or `None` on a deployment that has never
/// taken one.
///
/// Ordered by `checkpoint_no`, not `signed_at`: the counter is the thing that
/// is inside the signature and cannot be renumbered, whereas `signed_at` is
/// an ordinary column an insider can set to anything. Sorting the "which is
/// latest" question by the editable field would hand an attacker the answer.
pub async fn latest(conn: &mut PgConnection) -> ApiResult<Option<StoredCheckpoint>> {
    let row = sqlx::query_as!(
        StoredCheckpoint,
        r#"
        select checkpoint_no as "checkpoint_no!", head_seq, head_event_hash, covered_row_count,
               prev_checkpoint_hash, checkpoint_hash, signed_jws, kid, signed_at,
               anchor_target, anchor_ref, anchored_at, anchor_receipt
          from audit_checkpoints
         order by checkpoint_no desc
         limit 1
        "#
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row)
}

/// The checkpoint covering `seq`: the earliest one whose `head_seq` reaches
/// it. Earliest, not latest, because that is the one that pinned this row
/// first and therefore the one with the strongest claim about when it was
/// pinned — a later checkpoint also covers the row but says nothing about
/// how long it went unwitnessed.
///
/// `None` is a real answer, not an error: it means `seq` is newer than every
/// checkpoint, i.e. still inside the residual exposure window. The endpoint
/// says so in those words rather than returning a 404.
pub async fn covering(conn: &mut PgConnection, seq: i64) -> ApiResult<Option<StoredCheckpoint>> {
    let row = sqlx::query_as!(
        StoredCheckpoint,
        r#"
        select checkpoint_no as "checkpoint_no!", head_seq, head_event_hash, covered_row_count,
               prev_checkpoint_hash, checkpoint_hash, signed_jws, kid, signed_at,
               anchor_target, anchor_ref, anchored_at, anchor_receipt
          from audit_checkpoints
         where head_seq >= $1
         order by head_seq asc
         limit 1
        "#,
        seq
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------
// Verifying a stored checkpoint against the live database
// ---------------------------------------------------------------------

/// Check one checkpoint against the database as it stands right now.
///
/// The order of checks is deliberate. The signature is checked FIRST and
/// short-circuits, because if `signed_jws` does not verify then its claims
/// are attacker-controlled and comparing anything to them is theatre. Only
/// once the bytes are known to be ours are the claims used as the reference
/// against which both the indexed columns and the log itself are judged.
pub async fn verify(
    conn: &mut PgConnection,
    signer: &IssuerKey,
    stored: &StoredCheckpoint,
) -> ApiResult<Verification> {
    let claims = match verify_jws(signer, &stored.signed_jws) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Verification {
                checkpoint_no: stored.checkpoint_no,
                head_seq: stored.head_seq,
                intact: false,
                failures: vec![Failure::SignatureInvalid { detail: e.to_string() }],
            })
        }
    };

    let mut failures = Vec::new();

    // The columns are an index over the signed bytes (migrations/0008 says
    // so explicitly). Anyone who edits a column and leaves `signed_jws`
    // alone gets caught here; anyone who edits `signed_jws` got caught
    // above. There is no third option that does not require the key.
    for (field, agrees) in [
        ("checkpoint_no", claims.checkpoint_no == stored.checkpoint_no),
        ("head_seq", claims.head_seq == stored.head_seq),
        ("head_event_hash", claims.head_event_hash == encode_b64(&stored.head_event_hash)),
        ("covered_row_count", claims.covered_row_count == stored.covered_row_count),
        (
            "prev_checkpoint_hash",
            claims.prev_checkpoint_hash == stored.prev_checkpoint_hash.as_deref().map(encode_b64),
        ),
    ] {
        if !agrees {
            failures.push(Failure::ColumnsDisagreeWithSignedPayload { field });
        }
    }

    let observed = read_observed_range(&mut *conn, claims.head_seq).await?;
    failures.extend(compare(&claims, &observed));

    // Linkage to the preceding checkpoint. A GAP in `checkpoint_no` is not
    // itself a break: `nextval` is non-transactional, so a rolled-back emit
    // burns a number legitimately. What must hold is that this checkpoint's
    // `prev_checkpoint_hash` names whichever checkpoint actually precedes
    // it. A gap with intact linkage is a rolled-back emit; a gap with broken
    // linkage is a deletion. That distinction is the reason the link exists
    // at all rather than relying on the counter being contiguous.
    let preceding: Option<Vec<u8>> = sqlx::query_scalar!(
        "select checkpoint_hash from audit_checkpoints where checkpoint_no < $1 \
         order by checkpoint_no desc limit 1",
        stored.checkpoint_no
    )
    .fetch_optional(&mut *conn)
    .await?;
    if preceding != stored.prev_checkpoint_hash {
        failures.push(Failure::CheckpointChainBroken { checkpoint_no: stored.checkpoint_no });
    }

    Ok(Verification {
        checkpoint_no: stored.checkpoint_no,
        head_seq: stored.head_seq,
        intact: failures.is_empty(),
        failures,
    })
}

// ---------------------------------------------------------------------
// The background checkpointer
// ---------------------------------------------------------------------

/// How often the head gets pinned. Read once at boot, in the same style as
/// `config::Config`, but deliberately NOT a part of it.
///
/// `Config` is the house rule for "env read once at boot" and this is the
/// documented exception, for a mechanical reason rather than a taste one:
/// `Config` is constructed by exhaustive struct literal in other modules'
/// tests (`verify::tests`), so every field added to it is a compile break in
/// a file whose owner did not touch anything. Two settings used by exactly
/// one module do not justify making every other module's tests depend on
/// this module's configuration surface. If a second module ever needs these,
/// move them into `Config` and take the churn deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// The wall-clock bound on the exposure window. This number is the
    /// answer to "how long is our newest record unprotected?", and a
    /// customer will ask for it in exactly those words.
    pub interval: Duration,
    /// The event-count bound on the same window.
    pub max_events: i64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        // 60s / 64 events. Sixty seconds because it is small enough that
        // "the last minute of activity" is an acceptable statement to make
        // to a regulator and large enough that the signature cost is
        // irrelevant; 64 events because on a busy desk a minute is a lot of
        // decisions, and the count bound is what keeps the window from being
        // measured in decisions rather than seconds.
        Self { interval: Duration::from_secs(60), max_events: 64 }
    }
}

impl CheckpointPolicy {
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            interval: std::env::var("MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                // Floored at 1s rather than accepting 0: a zero interval
                // would spin the loop, and "sign continuously" is not a
                // meaningful answer to "how small can the window be" —
                // `POST /audit/checkpoints` is.
                .map(|v| Duration::from_secs(v.max(1)))
                .unwrap_or(default.interval),
            max_events: std::env::var("MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .map(|v| v.max(1))
                .unwrap_or(default.max_events),
        }
    }

    /// How often the loop wakes up. Faster than `interval` so the event
    /// bound can actually fire between ticks — with a single sleep of
    /// `interval` the count bound would be decorative on a busy deployment.
    /// Capped at 5s so a long configured interval doesn't make the count
    /// bound useless; floored so a 1s interval cannot become a hot loop.
    fn poll(&self) -> Duration {
        self.interval.clamp(Duration::from_millis(250), Duration::from_secs(5))
    }
}

/// Start the checkpointer. One line from `main`, everything else in here.
///
/// Never returns and never propagates an error out of the loop: a failed
/// tick (database blip, or the deliberate refusal in `emit_in_tx` when the
/// log has been truncated) must be loud in the logs and must not take the
/// task down, because a dead checkpointer is a silently growing exposure
/// window — the exact failure mode this module exists to bound.
pub fn spawn(state: AppState) {
    let policy = CheckpointPolicy::from_env();
    let poll = policy.poll();

    tokio::spawn(async move {
        tracing::info!(
            interval_seconds = policy.interval.as_secs(),
            max_events = policy.max_events,
            poll_seconds = poll.as_secs_f64(),
            "audit checkpointer started: the newest audit row is unprotected for at most this \
             interval, or this many events, whichever comes first"
        );
        loop {
            tokio::time::sleep(poll).await;
            if let Err(err) = tick(&state, policy).await {
                tracing::error!(error = ?err, "audit checkpointer tick failed");
            }
        }
    });
}

/// One pass of the emit decision. Split out from the loop so the policy
/// ("is a checkpoint due?") is readable on its own and the loop is only
/// scheduling and error handling.
async fn tick(state: &AppState, policy: CheckpointPolicy) -> ApiResult<()> {
    let mut conn = state.db.acquire().await?;

    let Some((head_seq, _)) = read_head(&mut conn).await? else { return Ok(()) };
    let previous = latest(&mut conn).await?;

    let due = match &previous {
        // Never checkpointed and there is something to pin: do it now rather
        // than waiting out a first interval. A deployment's very first
        // decision is not less important than its hundredth.
        None => true,
        // Head has not moved (or has gone backwards — `emit_in_tx` is the
        // one place that decides what to do about that, and it refuses).
        Some(prev) if prev.head_seq >= head_seq => false,
        Some(prev) => {
            let pending = head_seq - prev.head_seq;
            let elapsed = Utc::now().signed_duration_since(prev.signed_at);
            pending >= policy.max_events
                || elapsed.num_milliseconds().max(0) as u128 >= policy.interval.as_millis()
        }
    };
    if !due {
        return Ok(());
    }

    // Dropped, not held, across `emit`: `emit` begins its own transaction
    // from the pool and this connection has done its reading.
    drop(conn);

    match emit(&state.db, &state.signer).await? {
        Ok(cp) => tracing::info!(
            checkpoint_no = cp.checkpoint_no,
            head_seq = cp.head_seq,
            covered_row_count = cp.covered_row_count,
            "audit checkpoint signed"
        ),
        Err(reason) => tracing::debug!(?reason, "no audit checkpoint emitted this tick"),
    }
    Ok(())
}

// ---------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
        // Unauthenticated, like `/.well-known/jwks.json` and for the same
        // reason: a checkpoint whose whole purpose is to be held by third
        // parties is not published if it needs our permission to read. The
        // cost is that total audit-event volume across all tenants becomes
        // public (a `head_seq` and a row count). No tenant is named, no
        // event type is named, nothing about any decision is exposed. That
        // is the same trade Certificate Transparency makes with a signed
        // tree head, and it is worth it: an auditor who cannot fetch the
        // checkpoint without an API key cannot use it as independent
        // evidence, which defeats the point.
        .route("/audit/checkpoints/latest", get(get_latest_checkpoint))
        .route("/audit/checkpoints/covering/:seq", get(get_checkpoint_covering))
        // Authenticated, because unlike the two above these are not
        // constant-cost lookups: verification counts rows, and emission
        // signs. Any authenticated org may call them — nothing here is
        // tenant-scoped, and gating "check your evidence is intact" behind
        // an admin role would make the check something customers ask us to
        // run rather than something they run.
        .route("/audit/integrity", get(get_audit_integrity))
        .route("/audit/checkpoints", post(post_checkpoint))
}

/// `external_anchor`'s shape: always present now (B2's "distinguish three
/// cases" instruction), unlike the `Option<AnchorResponse>` this replaced —
/// "not yet anchored" and "no such field" used to be the same wire shape,
/// and a consumer had to remember which. `#[serde(flatten)]` keeps
/// `anchor::AnchorState`'s own `status` tag at this level; `receipt_der_base64`
/// is bolted on beside it rather than folded into `anchor::AnchorState`
/// itself, because that type is also the pure, DB-free unit tested by
/// `anchor::classify` and has no business carrying HTTP encoding concerns.
#[derive(Serialize)]
struct ExternalAnchorResponse {
    #[serde(flatten)]
    state: super::anchor::AnchorState,
    /// Base64 (standard) of the raw witness bytes — present only when
    /// `state` is `Anchored`. An offline verifier needs these bytes (see
    /// migrations/0012's header); everyone else can ignore the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_der_base64: Option<String>,
}

#[derive(Serialize)]
struct CheckpointResponse {
    checkpoint_no: i64,
    head_seq: i64,
    head_event_hash: String,
    covered_row_count: i64,
    prev_checkpoint_hash: Option<String>,
    checkpoint_hash: String,
    kid: String,
    signed_at: DateTime<Utc>,
    chain: &'static str,
    /// The evidence. Every field above is an index over what this says;
    /// this is the thing to keep, and the thing to verify.
    jws: String,
    typ: &'static str,
    /// Where to get the key that verifies `jws`. Included in the response so
    /// a consumer never has to be told out of band, and so the checkpoint is
    /// self-describing when it is pasted into a ticket six months from now.
    jwks_url: String,
    /// One of `anchored` / `pending` / `overdue` — see `anchor::AnchorState`.
    /// Always present: even "not yet anchored" is a reportable fact, not an
    /// absence.
    external_anchor: ExternalAnchorResponse,
}

impl CheckpointResponse {
    fn build(cp: &StoredCheckpoint, issuer: &str, anchor_policy: &super::anchor::AnchorPolicy) -> Self {
        let state = super::anchor::classify(
            cp.signed_at,
            cp.anchor_target.as_deref(),
            cp.anchor_ref.as_deref(),
            cp.anchored_at,
            anchor_policy,
            Utc::now(),
        );
        let receipt_der_base64 = match &state {
            super::anchor::AnchorState::Anchored { .. } => {
                cp.anchor_receipt.as_deref().map(super::anchor::encode_receipt)
            }
            _ => None,
        };
        Self {
            checkpoint_no: cp.checkpoint_no,
            head_seq: cp.head_seq,
            head_event_hash: encode_b64(&cp.head_event_hash),
            covered_row_count: cp.covered_row_count,
            prev_checkpoint_hash: cp.prev_checkpoint_hash.as_deref().map(encode_b64),
            checkpoint_hash: encode_b64(&cp.checkpoint_hash),
            kid: cp.kid.clone(),
            signed_at: cp.signed_at,
            chain: CHAIN_ID,
            jws: cp.signed_jws.clone(),
            typ: CHECKPOINT_TYP,
            jwks_url: format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')),
            external_anchor: ExternalAnchorResponse { state, receipt_der_base64 },
        }
    }
}

/// `GET /audit/checkpoints/latest`
async fn get_latest_checkpoint(State(state): State<AppState>) -> ApiResult<Json<CheckpointResponse>> {
    let mut conn = state.db.acquire().await?;
    let cp = latest(&mut conn)
        .await?
        .ok_or_else(|| ApiError::NotFoundDetail("no audit checkpoint has been taken yet".into()))?;
    Ok(Json(CheckpointResponse::build(&cp, state.signer.issuer(), &state.anchor_policy)))
}

#[derive(Serialize)]
struct CoveringResponse {
    seq: i64,
    /// False means this row is in the residual exposure window.
    covered: bool,
    checkpoint: Option<CheckpointResponse>,
    /// Plain English, in the response body, because the person asking this
    /// question is usually asking "is this specific decision protected?" and
    /// a bare `false` invites them to guess what that means.
    note: String,
}

/// `GET /audit/checkpoints/covering/:seq`
///
/// Answers 200 with `covered: false` rather than 404 when nothing covers the
/// row. "There is no checkpoint over this row yet" is a true and useful
/// answer about a row that exists; a 404 would say the row does not, and the
/// difference is exactly the thing a customer is trying to find out.
async fn get_checkpoint_covering(
    Path(seq): Path<i64>,
    State(state): State<AppState>,
) -> ApiResult<Json<CoveringResponse>> {
    if seq < 1 {
        return Err(ApiError::BadRequest("seq must be a positive integer".into()));
    }
    let mut conn = state.db.acquire().await?;
    match covering(&mut conn, seq).await? {
        Some(cp) => Ok(Json(CoveringResponse {
            seq,
            covered: true,
            note: format!(
                "audit_log seq {seq} is committed to by signed checkpoint {} (head_seq {}), \
                 which anyone can verify against {}/.well-known/jwks.json without this database.",
                cp.checkpoint_no,
                cp.head_seq,
                state.signer.issuer().trim_end_matches('/'),
            ),
            checkpoint: Some(CheckpointResponse::build(&cp, state.signer.issuer(), &state.anchor_policy)),
        })),
        None => {
            let head = latest(&mut conn).await?.map(|c| c.head_seq);
            Ok(Json(CoveringResponse {
                seq,
                covered: false,
                checkpoint: None,
                note: match head {
                    Some(h) => format!(
                        "audit_log seq {seq} is NEWER than the most recent checkpoint (head_seq {h}), \
                         so nothing outside the chain commits to it yet. If it is the terminal row, \
                         its event_hash can be edited undetectably until the next checkpoint. Call \
                         POST /audit/checkpoints to close that window now."
                    ),
                    None => format!(
                        "no checkpoint has ever been taken on this deployment, so audit_log seq \
                         {seq} is not committed to by anything outside the chain."
                    ),
                },
            }))
        }
    }
}

#[derive(Serialize)]
struct IntegrityResponse {
    /// True only if a checkpoint exists AND it verifies against the log.
    /// Deliberately false, not absent, when no checkpoint exists — a
    /// consumer reading a boolean must not get "true" from a deployment
    /// that has never pinned anything.
    intact: bool,
    checkpoint: Option<Verification>,
    /// Rows appended since the checkpoint. This IS the exposure, expressed
    /// as a number, and it is in the response so nobody has to compute it
    /// from two other endpoints.
    uncovered_rows: i64,
    note: String,
    /// The latest checkpoint's external-witness state — `None` only when
    /// there is no checkpoint at all yet (the branch above, where
    /// `checkpoint` is also `None`). Surfaced here too, not only on the
    /// checkpoint endpoints, because "is our evidence intact" and "is our
    /// evidence witnessed outside this organisation" are the two questions
    /// this endpoint's callers actually have, and an `overdue` anchor here
    /// is exactly the finding B2 requires reporting plainly.
    anchor: Option<super::anchor::AnchorState>,
}

/// `GET /audit/integrity` — verify the newest checkpoint against the log as
/// it stands, and report how much of the log that checkpoint does not cover.
async fn get_audit_integrity(
    OrgAuth(_org_id): OrgAuth,
    State(state): State<AppState>,
) -> ApiResult<Json<IntegrityResponse>> {
    let mut conn = state.db.acquire().await?;
    let head_seq = read_head(&mut conn).await?.map(|(seq, _)| seq);

    let Some(cp) = latest(&mut conn).await? else {
        return Ok(Json(IntegrityResponse {
            intact: false,
            checkpoint: None,
            uncovered_rows: head_seq.unwrap_or(0),
            note: "no audit checkpoint has been taken on this deployment, so the terminal row of \
                   the audit chain is not committed to by anything outside the chain."
                .into(),
            anchor: None,
        }));
    };

    let verification = verify(&mut conn, &state.signer, &cp).await?;
    let uncovered = sqlx::query_scalar!(
        r#"select count(*) as "count!" from audit_log where seq > $1"#,
        cp.head_seq
    )
    .fetch_one(&mut *conn)
    .await?;

    let note = if !verification.intact {
        "the newest checkpoint does not match the audit log: see `failures`. This is a signed \
         contradiction, not a warning — the log has been altered since it was signed."
            .to_string()
    } else if uncovered > 0 {
        format!(
            "checkpoint {} matches the log up to seq {}. {uncovered} row(s) have been appended \
             since and are not yet committed to by any checkpoint; the newest of those can be \
             edited undetectably until the next one.",
            verification.checkpoint_no, verification.head_seq,
        )
    } else {
        format!(
            "checkpoint {} matches the log, and covers every row including the terminal one.",
            verification.checkpoint_no,
        )
    };

    let anchor = super::anchor::classify(
        cp.signed_at,
        cp.anchor_target.as_deref(),
        cp.anchor_ref.as_deref(),
        cp.anchored_at,
        &state.anchor_policy,
        Utc::now(),
    );

    Ok(Json(IntegrityResponse {
        intact: verification.intact && head_seq.is_some(),
        checkpoint: Some(verification),
        uncovered_rows: uncovered,
        note,
        anchor: Some(anchor),
    }))
}

#[derive(Serialize)]
struct EmitResponse {
    /// False when the head had not moved and the existing checkpoint was
    /// returned unchanged. Idempotence made visible rather than inferred
    /// from a stable `checkpoint_no`.
    emitted: bool,
    checkpoint: Option<CheckpointResponse>,
    note: String,
}

/// `POST /audit/checkpoints` — pin the current head now.
///
/// Exists because the moment a checkpoint is most valuable is immediately
/// before an export, a dispute, or a regulator's request, and nobody should
/// have to wait out a timer for it. Idempotent: if the head has not moved
/// since the last checkpoint there is nothing new to say, and it returns the
/// existing one rather than signing a second statement about the same chain
/// position. That idempotence is also what makes the route safe to expose to
/// any authenticated org — a caller in a loop does one signature's work and
/// then no work at all.
async fn post_checkpoint(
    OrgAuth(_org_id): OrgAuth,
    State(state): State<AppState>,
) -> ApiResult<Json<EmitResponse>> {
    match emit(&state.db, &state.signer).await? {
        Ok(cp) => Ok(Json(EmitResponse {
            note: format!(
                "checkpoint {} signed over audit_log seq {} ({} rows covered).",
                cp.checkpoint_no, cp.head_seq, cp.covered_row_count
            ),
            checkpoint: Some(CheckpointResponse::build(&cp, state.signer.issuer(), &state.anchor_policy)),
            emitted: true,
        })),
        Err(NotEmitted::EmptyChain) => Ok(Json(EmitResponse {
            emitted: false,
            checkpoint: None,
            note: "the audit log is empty; there is no chain head to pin.".into(),
        })),
        Err(NotEmitted::HeadUnchanged) => {
            let mut conn = state.db.acquire().await?;
            let cp = latest(&mut conn).await?;
            Ok(Json(EmitResponse {
                emitted: false,
                note: match &cp {
                    Some(c) => format!(
                        "the chain head has not moved since checkpoint {} (seq {}); that \
                         checkpoint already covers every row.",
                        c.checkpoint_no, c.head_seq
                    ),
                    None => "nothing to checkpoint.".into(),
                },
                checkpoint: cp
                    .as_ref()
                    .map(|c| CheckpointResponse::build(c, state.signer.issuer(), &state.anchor_policy)),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record_in_tx;
    use uuid::Uuid;

    const ISSUER: &str = "https://api.memtara.test";

    fn test_signer() -> IssuerKey {
        IssuerKey::from_seed([7u8; 32], ISSUER)
    }

    fn sample_claims() -> CheckpointClaims {
        CheckpointClaims {
            iss: ISSUER.into(),
            chain: CHAIN_ID.into(),
            checkpoint_no: 12,
            head_seq: 4211,
            head_event_hash: encode_b64(&[9u8; 32]),
            covered_row_count: 4211,
            prev_checkpoint_hash: Some(encode_b64(&[3u8; 32])),
            iat: 1_760_000_000,
        }
    }

    // -----------------------------------------------------------------
    // The pure comparison — every failure mode, no database required.
    // -----------------------------------------------------------------

    #[test]
    fn an_untouched_log_produces_no_failures() {
        let signed = sample_claims();
        let observed = ObservedRange {
            head_event_hash: Some(vec![9u8; 32]),
            covered_row_count: 4211,
        };
        assert_eq!(compare(&signed, &observed), vec![]);
    }

    #[test]
    fn a_forged_terminal_event_hash_is_caught() {
        // THE attack this module exists for: 32 bytes written over the last
        // row's event_hash. Nothing in the chain notices, because nothing
        // succeeds that row. The checkpoint does.
        let signed = sample_claims();
        let observed = ObservedRange {
            head_event_hash: Some(vec![0xAAu8; 32]),
            covered_row_count: 4211,
        };
        let failures = compare(&signed, &observed);
        assert_eq!(failures.len(), 1, "one forgery, one failure: {failures:?}");
        assert!(
            matches!(failures[0], Failure::HeadHashMismatch { head_seq: 4211, .. }),
            "got {failures:?}"
        );
    }

    #[test]
    fn truncation_inside_the_covered_range_is_caught() {
        // The sibling attack: rather than editing the last row, delete rows.
        // The surviving prefix is still internally consistent — every
        // remaining prev_hash still matches its predecessor — so linkage
        // alone reports a healthy chain. The row count does not.
        let signed = sample_claims();
        let observed = ObservedRange {
            head_event_hash: Some(vec![9u8; 32]),
            covered_row_count: 4111, // 100 rows removed from the middle
        };
        assert_eq!(
            compare(&signed, &observed),
            vec![Failure::RowCountMismatch { signed: 4211, observed: 4111 }],
        );
    }

    #[test]
    fn deleting_the_head_row_itself_is_caught_as_a_missing_row_not_a_mismatch() {
        // Distinguishing these two matters operationally: a hash mismatch is
        // an edit, a missing row is a deletion, and they are different
        // incidents with different next steps.
        let signed = sample_claims();
        let observed = ObservedRange { head_event_hash: None, covered_row_count: 4210 };
        let failures = compare(&signed, &observed);
        assert!(failures.contains(&Failure::HeadRowMissing { head_seq: 4211 }), "{failures:?}");
        assert!(
            failures.contains(&Failure::RowCountMismatch { signed: 4211, observed: 4210 }),
            "deleting the head also shortens the covered range, and both facts are reported: {failures:?}"
        );
    }

    #[test]
    fn appending_rows_beyond_the_head_is_not_a_failure() {
        // This is the residual window, asserted rather than described. Rows
        // appended after a checkpoint are outside its covered range by
        // construction, so they cannot make it fail — and equally, it says
        // nothing about them. `covered_row_count` counts `seq <= head_seq`
        // precisely so that ordinary appends do not raise a false alarm.
        let signed = sample_claims();
        let observed = ObservedRange {
            head_event_hash: Some(vec![9u8; 32]),
            covered_row_count: 4211,
        };
        assert_eq!(compare(&signed, &observed), vec![]);
    }

    // -----------------------------------------------------------------
    // The signature — verified the way an outsider verifies it.
    // -----------------------------------------------------------------

    #[test]
    fn a_signed_checkpoint_verifies_against_the_published_jwks() {
        let signer = test_signer();
        let claims = sample_claims();
        let jws = signer
            .sign_compact_jws(CHECKPOINT_TYP, &serde_json::to_vec(&claims).unwrap())
            .unwrap();
        assert_eq!(verify_jws(&signer, &jws).unwrap(), claims);
    }

    #[test]
    fn rewriting_the_head_hash_inside_the_signed_payload_breaks_verification() {
        // The forgery an insider would actually try once checkpoints exist:
        // edit the audit row AND rewrite the checkpoint to agree with it.
        // Without the private key the second half is not available.
        let signer = test_signer();
        let jws = signer
            .sign_compact_jws(CHECKPOINT_TYP, &serde_json::to_vec(&sample_claims()).unwrap())
            .unwrap();
        let parts: Vec<&str> = jws.split('.').collect();

        let forged = CheckpointClaims { head_event_hash: encode_b64(&[0xAAu8; 32]), ..sample_claims() };
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let forged_jws = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

        assert!(verify_jws(&signer, &forged_jws).is_err());
    }

    #[test]
    fn a_proof_token_is_not_accepted_as_a_checkpoint() {
        // Same key, same algorithm, different claim about the world. Without
        // the `typ` check a relying party could be handed one where it asked
        // for the other and the signature would check out (RFC 8725 §3.11).
        let signer = test_signer();
        let not_a_checkpoint = signer
            .sign_compact_jws("JWT", &serde_json::to_vec(&sample_claims()).unwrap())
            .unwrap();
        let err = verify_jws(&signer, &not_a_checkpoint).unwrap_err().to_string();
        assert!(err.contains("not an audit checkpoint"), "got: {err}");
    }

    #[test]
    fn a_checkpoint_from_a_different_key_does_not_verify() {
        let ours = test_signer();
        let theirs = IssuerKey::from_seed([8u8; 32], ISSUER);
        let jws = theirs
            .sign_compact_jws(CHECKPOINT_TYP, &serde_json::to_vec(&sample_claims()).unwrap())
            .unwrap();
        assert!(verify_jws(&ours, &jws).is_err());
    }

    #[test]
    fn a_checkpoint_about_another_chain_is_rejected() {
        // Domain separation: a correctly-signed statement about some other
        // chain must not be readable as a statement about this one.
        let signer = test_signer();
        let other = CheckpointClaims { chain: "memtara.audit_log.per_org.v1".into(), ..sample_claims() };
        let jws = signer
            .sign_compact_jws(CHECKPOINT_TYP, &serde_json::to_vec(&other).unwrap())
            .unwrap();
        assert!(verify_jws(&signer, &jws).unwrap_err().to_string().contains("is about chain"));
    }

    #[test]
    fn the_checkpoint_link_is_taken_over_the_signed_bytes() {
        // If the link were computed over re-serialized claims, two different
        // byte strings could share a link value and a substituted checkpoint
        // would go unnoticed. It is taken over the JWS itself.
        let signer = test_signer();
        let a = signer.sign_compact_jws(CHECKPOINT_TYP, &serde_json::to_vec(&sample_claims()).unwrap()).unwrap();
        let b = signer
            .sign_compact_jws(
                CHECKPOINT_TYP,
                &serde_json::to_vec(&CheckpointClaims { checkpoint_no: 13, ..sample_claims() }).unwrap(),
            )
            .unwrap();
        assert_ne!(checkpoint_hash(&a), checkpoint_hash(&b));
        assert_eq!(checkpoint_hash(&a).len(), 32);
        assert_eq!(checkpoint_hash(&a), checkpoint_hash(&a.clone()));
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(10).connect(&url).await.ok()
        }

        /// Every database test here runs inside ONE transaction that is
        /// rolled back at the end, and that is load-bearing for the same
        /// reason it is in `audit::tests::db`: `emit_in_tx` takes the chain's
        /// advisory lock, so holding one transaction open for the whole test
        /// means no concurrent test can append or delete a row underneath a
        /// checkpoint we just signed. A checkpoint commits to a row COUNT,
        /// and other modules' tests delete their audit rows in cleanup — a
        /// window-based formulation would report tampering every time one of
        /// them happened to run at the wrong moment.
        ///
        /// Rolling back also means these tests leave no checkpoints behind,
        /// which matters because `emit_in_tx` deliberately refuses to sign
        /// when the head is below an existing checkpoint's `head_seq`.
        #[tokio::test]
        async fn a_checkpoint_catches_a_forgery_over_the_terminal_row() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            // Three real appends through the real code path.
            let ref_id = Uuid::new_v4();
            for n in 1..=3 {
                record_in_tx(&mut tx, None, "checkpoint_test_event", Some(ref_id), serde_json::json!({ "n": n }))
                    .await
                    .unwrap();
            }

            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("a checkpoint over a non-empty chain");

            // Healthy to start with.
            let before = verify(&mut tx, &signer, &cp).await.unwrap();
            assert!(before.intact, "a fresh checkpoint must match the log it was taken over: {before:?}");

            // The attack, verbatim from the break-it harness: 32 forged bytes
            // over the TERMINAL row's event_hash. No successor exists, so
            // chain linkage cannot see this, and the payload was never stored
            // so the hash cannot be recomputed either.
            let forged = vec![0xABu8; 32];
            sqlx::query!("update audit_log set event_hash = $1 where seq = $2", forged, cp.head_seq)
                .execute(&mut *tx)
                .await
                .unwrap();

            let after = verify(&mut tx, &signer, &cp).await.unwrap();
            assert!(!after.intact, "the checkpoint must contradict a forged terminal hash");
            assert!(
                after.failures.iter().any(|f| matches!(f, Failure::HeadHashMismatch { .. })),
                "expected a head-hash mismatch, got {:?}",
                after.failures
            );

            tx.rollback().await.unwrap();
        }

        /// Truncation, the sibling attack. Deleting a row from inside the
        /// covered range leaves every surviving `prev_hash` link intact for
        /// the rows that remain adjacent, so linkage alone under-reports it.
        #[tokio::test]
        async fn a_checkpoint_catches_rows_deleted_from_the_covered_range() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            let mut seqs = Vec::new();
            for n in 1..=3 {
                let entry =
                    record_in_tx(&mut tx, None, "checkpoint_truncation_event", Some(ref_id), serde_json::json!({ "n": n }))
                        .await
                        .unwrap();
                let seq: i64 = sqlx::query_scalar!(r#"select seq as "seq!" from audit_log where id = $1"#, entry.id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                seqs.push(seq);
            }

            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");
            assert!(verify(&mut tx, &signer, &cp).await.unwrap().intact);

            // Remove a row from the middle of the covered range. The head is
            // untouched, so the head-hash check is happy; only the count
            // notices.
            sqlx::query!("delete from audit_log where seq = $1", seqs[1])
                .execute(&mut *tx)
                .await
                .unwrap();

            let after = verify(&mut tx, &signer, &cp).await.unwrap();
            assert!(!after.intact, "a deleted row inside the covered range must be caught");
            assert!(
                after.failures.iter().any(|f| matches!(
                    f,
                    Failure::RowCountMismatch { signed, observed } if signed - observed == 1
                )),
                "expected the count to be short by exactly one, got {:?}",
                after.failures
            );
            assert!(
                !after.failures.iter().any(|f| matches!(f, Failure::HeadHashMismatch { .. })),
                "the head was not touched; reporting a hash mismatch would misdescribe the incident"
            );

            tx.rollback().await.unwrap();
        }

        /// The residual exposure window, proven rather than promised. A row
        /// appended after the checkpoint is outside its covered range, so
        /// forging ITS hash is still undetectable. This test exists so that
        /// if someone later widens the checkpoint's coverage, this assertion
        /// fails and the claim in the module header gets updated with it.
        #[tokio::test]
        async fn a_row_appended_after_the_checkpoint_is_not_protected_by_it() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            record_in_tx(&mut tx, None, "checkpoint_window_event", Some(ref_id), serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");

            // A decision arrives one second after the checkpoint.
            let later = record_in_tx(&mut tx, None, "checkpoint_window_event", Some(ref_id), serde_json::json!({"n": 2}))
                .await
                .unwrap();
            let later_seq: i64 = sqlx::query_scalar!(r#"select seq as "seq!" from audit_log where id = $1"#, later.id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert!(later_seq > cp.head_seq, "the new row is beyond the checkpointed head");

            // Forge it. This is the honest limit of the design.
            sqlx::query!("update audit_log set event_hash = $1 where seq = $2", vec![0xCDu8; 32], later_seq)
                .execute(&mut *tx)
                .await
                .unwrap();

            let after = verify(&mut tx, &signer, &cp).await.unwrap();
            assert!(
                after.intact,
                "RESIDUAL WINDOW: rows appended after a checkpoint are not covered by it, and \
                 forging the newest one is still undetectable until the next checkpoint. If this \
                 assertion ever starts failing, the coverage claim in this module's header and in \
                 the break-it harness both need updating: {after:?}"
            );

            // And the very next checkpoint closes it — over the forged value,
            // which is the other half of the honest statement: a checkpoint
            // freezes whatever is there, it does not retroactively validate it.
            let cp2 = emit_in_tx(&mut tx, &signer).await.unwrap().expect("second checkpoint");
            assert_eq!(cp2.head_seq, later_seq);
            assert!(verify(&mut tx, &signer, &cp2).await.unwrap().intact);

            tx.rollback().await.unwrap();
        }

        /// Checkpoints chain to each other, and the link is checked. Without
        /// this, an older checkpoint could be swapped in for a newer one.
        #[tokio::test]
        async fn checkpoints_link_to_their_predecessor_and_refuse_to_repeat_themselves() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            record_in_tx(&mut tx, None, "checkpoint_link_event", Some(ref_id), serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let first = emit_in_tx(&mut tx, &signer).await.unwrap().expect("first checkpoint");

            // Idempotent while the head is still: a second signed statement
            // about the same chain position is noise, and a replay surface.
            assert_eq!(
                emit_in_tx(&mut tx, &signer).await.unwrap().unwrap_err(),
                NotEmitted::HeadUnchanged,
            );

            record_in_tx(&mut tx, None, "checkpoint_link_event", Some(ref_id), serde_json::json!({"n": 2}))
                .await
                .unwrap();
            let second = emit_in_tx(&mut tx, &signer).await.unwrap().expect("second checkpoint");

            assert_eq!(
                second.prev_checkpoint_hash.as_deref(),
                Some(first.checkpoint_hash.as_slice()),
                "each checkpoint must commit to its predecessor's signed bytes",
            );
            assert!(second.checkpoint_no > first.checkpoint_no, "the counter must be monotonic");

            // The number is inside the signature, so it cannot be renumbered
            // to impersonate a later checkpoint.
            let claims = verify_jws(&signer, &second.signed_jws).unwrap();
            assert_eq!(claims.checkpoint_no, second.checkpoint_no);
            assert_eq!(claims.head_seq, second.head_seq);
            assert_eq!(claims.prev_checkpoint_hash, Some(encode_b64(&first.checkpoint_hash)));

            assert!(verify(&mut tx, &signer, &second).await.unwrap().intact);

            tx.rollback().await.unwrap();
        }

        /// Editing the indexed columns while leaving `signed_jws` alone is
        /// the obvious next move once someone realises the signature is the
        /// evidence. The columns are checked against it.
        #[tokio::test]
        async fn editing_a_checkpoints_columns_is_caught_by_its_own_signature() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            record_in_tx(&mut tx, None, "checkpoint_column_event", Some(ref_id), serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");

            sqlx::query!(
                "update audit_checkpoints set head_event_hash = $1 where checkpoint_no = $2",
                vec![0xEFu8; 32],
                cp.checkpoint_no,
            )
            .execute(&mut *tx)
            .await
            .unwrap();

            let reread = latest(&mut tx).await.unwrap().expect("checkpoint still there");
            let verdict = verify(&mut tx, &signer, &reread).await.unwrap();
            assert!(!verdict.intact);
            assert!(
                verdict.failures.contains(&Failure::ColumnsDisagreeWithSignedPayload {
                    field: "head_event_hash"
                }),
                "got {:?}",
                verdict.failures
            );

            tx.rollback().await.unwrap();
        }

        /// Refusing to sign over a truncated log. This is the difference
        /// between a checkpointer and a laundering service: if rows have
        /// been removed from the END of the chain, the head is now BELOW a
        /// position we already swore to, and signing a fresh checkpoint
        /// there would produce a new, valid-looking statement that the
        /// shorter log is fine. The existing checkpoint already contradicts
        /// the database; the right move is to leave that contradiction
        /// standing and make a human look at it.
        #[tokio::test]
        async fn the_checkpointer_refuses_to_sign_over_a_truncated_chain() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            for n in 1..=3 {
                record_in_tx(&mut tx, None, "checkpoint_truncate_end_event", Some(ref_id), serde_json::json!({"n": n}))
                    .await
                    .unwrap();
            }
            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");

            // Chop the checkpointed rows off the end of the log.
            sqlx::query!("delete from audit_log where ref_id = $1", ref_id)
                .execute(&mut *tx)
                .await
                .unwrap();

            let err = emit_in_tx(&mut tx, &signer)
                .await
                .expect_err("a checkpointer that signs here erases the evidence it exists to keep");
            let message = err.to_string();
            assert!(message.contains("refusing to checkpoint"), "got: {message}");
            assert!(
                message.contains(&cp.head_seq.to_string()),
                "the refusal must name the position we already committed to: {message}"
            );

            tx.rollback().await.unwrap();
        }

        /// `covering(seq)` must return the checkpoint that first pinned a
        /// row, and `None` for a row still inside the residual window — the
        /// two answers the public endpoint is built on.
        #[tokio::test]
        async fn covering_finds_the_first_checkpoint_over_a_row_and_admits_when_there_is_none() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let signer = test_signer();
            let mut tx = db.begin().await.unwrap();

            let ref_id = Uuid::new_v4();
            let early = record_in_tx(&mut tx, None, "checkpoint_covering_event", Some(ref_id), serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let early_seq: i64 = sqlx::query_scalar!(r#"select seq as "seq!" from audit_log where id = $1"#, early.id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            let cp = emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");

            let found = covering(&mut tx, early_seq).await.unwrap().expect("the row is covered");
            assert_eq!(found.checkpoint_no, cp.checkpoint_no);

            let uncovered = record_in_tx(&mut tx, None, "checkpoint_covering_event", Some(ref_id), serde_json::json!({"n": 2}))
                .await
                .unwrap();
            let uncovered_seq: i64 =
                sqlx::query_scalar!(r#"select seq as "seq!" from audit_log where id = $1"#, uncovered.id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert!(
                covering(&mut tx, uncovered_seq).await.unwrap().is_none(),
                "a row newer than every checkpoint is not covered, and saying so is the point",
            );

            tx.rollback().await.unwrap();
        }
    }
}
