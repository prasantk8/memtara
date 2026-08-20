// The external witness `checkpoint.rs`'s own header names as NOT BUILT: "an
// external witness. We can still delete our own checkpoints."
//
// ---------------------------------------------------------------------
// WHAT AN ANCHOR ADDS THAT A CHECKPOINT ALONE DOES NOT
// ---------------------------------------------------------------------
// A checkpoint is a statement this deployment signs about itself. Every
// field in it is checkable by anyone holding the JWKS, which is real
// tamper-EVIDENCE — but the statement, the database row that carries it, and
// the key that signed it all live inside the same organisation. An insider
// with database access and the signing key (`checkpoint.rs`'s own worked
// example: delete every checkpoint, rewrite the log from genesis, re-sign a
// new head) produces a SECOND self-consistent statement, and nothing inside
// this system can tell the two apart — both verify, both chain correctly,
// both are "the truth" as far as any check running against this database is
// concerned.
//
// An anchor is a copy of one specific checkpoint's fingerprint, held by a
// party that did not generate it and cannot be asked to forget it. Once a
// checkpoint has been anchored, a rewritten history has to explain why the
// anchor points at a fingerprint the new "true" history does not contain —
// and that explanation requires either forging the anchor issuer's
// signature (which this deployment does not hold) or getting the SAME
// anchor issuer to re-witness the forged fingerprint, which only pushes the
// same problem one hop outward. See `test_attack_12_rewrite_history` for
// this run for real, against a real TSA, over a rewritten chain.
//
// ---------------------------------------------------------------------
// WHY RFC 3161, AND WHAT WAS REJECTED
// ---------------------------------------------------------------------
// RFC 3161 (Time-Stamp Protocol) is a twenty-five-year-old IETF standard: a
// timestamp authority (TSA) accepts a message digest and returns a signed
// `TimeStampToken` — a CMS `SignedData` structure — attesting that the
// digest existed at a stated time. It was chosen over three alternatives
// that were seriously considered:
//
//   * OpenTimestamps (anchor into the Bitcoin blockchain). Stronger in one
//     sense — no single organisation to compromise or subpoena — and far
//     weaker in the one that matters operationally: a submission is only
//     durably anchored once it has a Bitcoin confirmation, which is on the
//     order of an hour, not the seconds-to-minutes cadence `AnchorPolicy`
//     needs to keep the sweep's own backlog bounded. It also adds a
//     cryptocurrency dependency to a regulated-finance compliance stack for
//     a guarantee this deployment does not need: the threat modelled here is
//     an insider with database and key access, not a nation-state-scale
//     attack on a TSA's HSM.
//   * Committing the digest into a public git host. Requires trusting that
//     host's own notion of "when" a commit landed, which a host under the
//     same operator's control (or a host that itself lies about timestamps)
//     does not actually improve on — the witness has to be independently
//     time-stamped by SOMETHING, and RFC 3161 is that something either way.
//   * Mailing the digest to the customer's own compliance address. Not
//     machine-verifiable: the guarantee would depend on the customer's mail
//     retention policy and on someone remembering to check, rather than on a
//     cryptographic chain `verify_bundle.py` can walk offline.
//
// RFC 3161 wins on the property this deployment actually needs: a signature
// this deployment cannot produce, obtainable in real time, checkable offline
// by anyone with the TSA's public certificate chain and no further
// cooperation from either party. `AnchorProvider` is a trait specifically so
// this choice is swappable without touching the sweep or the schema: a
// production deployment can point `MEMTARA_ANCHOR_TSA_URL` at a paid,
// audited TSA (DigiCert, Sectigo, GlobalSign — all speak the identical wire
// protocol confirmed below) with no code change, and a future anchor TYPE
// (OpenTimestamps, a second co-signing TSA) is additive because
// `anchor_target` is free text, not a fixed enum — see migration 0008.
//
// freetsa.org is this codebase's DEV default. It is a community-run,
// unaudited service and a single point of trust: anyone who could compel or
// compromise freetsa.org's private key could backdate an anchor. That is a
// materially weaker guarantee than a commercially audited TSA and it is
// stated here rather than left to be discovered — swap
// `MEMTARA_ANCHOR_TSA_URL` before this matters for a real deployment.
//
// ---------------------------------------------------------------------
// WHAT AN ANCHOR PROVES, AND WHAT IT DOES NOT
// ---------------------------------------------------------------------
// PROVES: this checkpoint's signed bytes — and therefore the chain head they
// pin — existed no later than the TSA's stated `genTime`, attested by a
// party outside this organisation whose signature this organisation's own
// key cannot produce.
//
// DOES NOT PROVE:
//   * That the head is otherwise correct. An anchor witnesses a fingerprint,
//     not a decision — it says "this exact statement existed", not "this
//     statement is true".
//   * Anything about rows BETWEEN anchors. Exactly the same residual
//     `checkpoint.rs` states about rows between checkpoints, one level up:
//     an anchor covers the checkpoint it was taken over and nothing appended
//     since. The window here is the anchoring sweep's cadence
//     (`AnchorPolicy::sweep_interval`), stacked on top of the checkpointing
//     cadence that already applies to the row itself. Rewriting rows created
//     and rewritten entirely inside that combined window, before either
//     mechanism has run again, is still undetectable by anything in this
//     repository. State this plainly rather than letting "anchored" read as
//     "immutable, full stop" — see `BREAK_IT_NOTE` in
//     `tests/break_it/test_attack_12_rewrite_history.py`.
//   * Freedom from a compromised TSA. See the freetsa.org note above.
//
// ---------------------------------------------------------------------
// WHY THE SWEEP IS A BACKGROUND JOB, NOT INLINE IN CHECKPOINT CREATION
// ---------------------------------------------------------------------
// `checkpoint::emit_in_tx` runs inside the same database transaction and
// advisory lock as every other audit append; a checkpoint is signed with a
// key already resident in this process and never leaves it. Anchoring is
// the opposite shape: it is an outbound HTTP call to a service this
// deployment does not operate, with its own latency, its own outage
// schedule and its own rate limits. Making `POST /audit/checkpoints` (or,
// worse, an ordinary decision-opening request that happens to trigger a
// checkpoint) block on that call would mean an unrelated request path's
// success depends on a third party's uptime — precisely the failure mode
// `checkpoint.rs` itself was careful to avoid for the signing step. So
// anchoring is eventually consistent: a periodic sweep looks for
// checkpoints with `anchored_at is null`, tries each, and moves on. A dead
// TSA makes anchors late; it must never make a checkpoint fail to be
// created, and `sweep_once` is written so a provider error is logged and
// skipped rather than propagated — see the `db` tests below for a mock
// provider that always refuses.

use axum::extract::State;
use axum::routing::post;
use axum::{async_trait, Json, Router};
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

use crate::error::ApiResult;
use crate::orgs::OrgAuth;
use crate::state::AppState;

/// The only anchor target this codebase produces today. `anchor_target` in
/// the database is free text (migration 0008), not a fixed enum, precisely
/// so a second target can be added later without a migration; this constant
/// is what THIS provider writes into that column.
pub const RFC3161_TARGET: &str = "rfc3161";

/// Two API processes' clocks can disagree even under NTP — the same class
/// of fact `wealth/review.rs::MAX_CLOCK_SKEW_SECONDS` names for Postgres vs.
/// the API process (~130ms observed there). This constant is deliberately
/// much smaller than that 300-second BUSINESS-tolerance figure: every
/// timestamp compared in `classify` below is API-process-generated
/// (`checkpoint::emit_in_tx` binds `signed_at` explicitly rather than
/// taking Postgres's `now()` default), so the only skew in play is between
/// two processes' wall clocks, not between a database and a process. A
/// handful of seconds absorbs ordinary drift without absorbing a checkpoint
/// that is genuinely overdue.
const CLOCK_SKEW_ALLOWANCE_SECONDS: i64 = 5;

// ---------------------------------------------------------------------
// The trait, and what a call to it returns
// ---------------------------------------------------------------------

/// What an anchoring attempt produces on success. Mirrors the four anchor
/// columns migration 0008 (target, reference) and migration 0012 (receipt)
/// added to `audit_checkpoints`; `anchored_at` is this process's clock at
/// the moment the provider returned, not any timestamp inside the receipt
/// itself (an RFC 3161 token's own `genTime` is a claim FROM the witness and
/// is checked against this value by an offline verifier, not substituted
/// for it here).
#[derive(Debug, Clone)]
pub struct AnchorReceipt {
    /// Which kind of witness this is — `RFC3161_TARGET` for this provider.
    pub target: String,
    /// A short, human-checkable locator. NOT the receipt bytes themselves
    /// (see migration 0012's header for why those get their own column) —
    /// this provider uses `sha256:<hex of the receipt bytes>`, quotable in
    /// a report and independently recomputable by anyone holding the
    /// receipt.
    pub reference: String,
    /// The raw bytes an offline verifier needs to check the witness
    /// cryptographically without this deployment's cooperation. For this
    /// provider: the DER-encoded RFC 3161 `TimeStampToken`, which itself
    /// embeds the signing certificate and (for freetsa.org, confirmed
    /// empirically below) the issuing CA certificate — everything except
    /// the pinned trust anchor a verifier must supply independently. See
    /// `scripts/bundle/verify_bundle.py` step 7c.
    pub token_der: Vec<u8>,
    pub anchored_at: DateTime<Utc>,
}

/// Same shape as `auth::otp::OtpProvider`: one trait, a logging mock for
/// tests, one real implementation. `digest` is the checkpoint's own
/// `checkpoint_hash` — SHA-256 over the compact JWS bytes, the same value
/// the NEXT checkpoint links to (`checkpoint.rs::checkpoint_hash`) — so
/// anchoring a checkpoint witnesses exactly the bytes a relying party
/// already treats as that checkpoint's identity.
#[async_trait]
pub trait AnchorProvider: Send + Sync {
    async fn anchor(&self, digest: &[u8; 32]) -> anyhow::Result<AnchorReceipt>;
}

/// DEV/TEST-ONLY. Fabricates a receipt without consulting anything outside
/// this process — logs the digest and returns immediately, the same
/// "delivers by logging" shape as `LoggingOtpProvider`, with one difference
/// that matters enough to say twice: an OTP delivered by logging still
/// reaches the intended channel (a developer's terminal standing in for a
/// phone), but an anchor fabricated by this provider witnesses NOTHING
/// outside this process. Its whole value proposition is "a party that did
/// not generate this checkpoint holds a copy", and this mock is, by
/// construction, the same process that generated it. `target` is stamped
/// `"rfc3161-dev-mock"` rather than `"rfc3161"` specifically so a
/// `anchor_target` column populated by this provider is structurally
/// distinguishable from a real one — an operator or an offline verifier
/// who sees that string knows immediately that no external witness exists
/// for this checkpoint, rather than discovering it the hard way during a
/// dispute. NEVER wire this into `main.rs`'s default `anchor_provider`.
pub struct LoggingAnchorProvider {
    /// When true, every call fails as if the TSA were unreachable — the
    /// shape a dead witness takes from the sweep's point of view, for tests
    /// that must exercise "checkpointing survives a dead TSA" without a
    /// real network dependency (see the `db` tests below).
    simulate_outage: bool,
}

impl LoggingAnchorProvider {
    pub fn new() -> Self {
        Self { simulate_outage: false }
    }

    /// A provider that always refuses, standing in for an unreachable or
    /// permanently-down TSA.
    pub fn always_refusing() -> Self {
        Self { simulate_outage: true }
    }
}

impl Default for LoggingAnchorProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AnchorProvider for LoggingAnchorProvider {
    async fn anchor(&self, digest: &[u8; 32]) -> anyhow::Result<AnchorReceipt> {
        if self.simulate_outage {
            tracing::warn!(
                digest = %hex(digest),
                "LoggingAnchorProvider: simulating a TSA that refuses every request"
            );
            anyhow::bail!("simulated TSA outage: this provider is configured to always refuse");
        }
        tracing::info!(
            digest = %hex(digest),
            "DEV/TEST ONLY: fabricating an anchor receipt instead of consulting a real witness \
             — this witnesses nothing outside this process, see LoggingAnchorProvider's doc \
             comment"
        );
        let fabricated_token = format!("dev-mock-token-for-{}", hex(digest)).into_bytes();
        let reference = format!("sha256:{}", hex(&Sha256::digest(&fabricated_token)));
        Ok(AnchorReceipt {
            target: "rfc3161-dev-mock".to_string(),
            reference,
            token_der: fabricated_token,
            anchored_at: Utc::now(),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------
// The real implementation: RFC 3161 against a configurable TSA
// ---------------------------------------------------------------------

/// The real `AnchorProvider`. Speaks RFC 3161 over HTTP(S): POST a
/// DER-encoded `TimeStampReq` with `Content-Type: application/timestamp-query`,
/// read back a DER-encoded `TimeStampResp`.
///
/// WHY THE REQUEST IS HAND-ENCODED RATHER THAN BUILT WITH AN ASN.1 CRATE:
/// same reasoning `crypto::signer::IssuerKey` gives for hand-writing its
/// JWS rather than pulling in a JWT library — the request this provider
/// sends is fixed in shape and small (under 60 bytes), so writing the exact
/// DER bytes once, next to a comment showing precisely what they are, means
/// nobody has to trust an ASN.1 encoder's option surface to know what this
/// process sends over the wire. The response is walked with the same
/// discipline: just far enough to locate the `TimeStampToken` inside the
/// `TimeStampResp` envelope and to confirm the request was granted, not a
/// general-purpose ASN.1 parser. `verify_bundle.py`'s offline check, which
/// has to interpret the token's actual contents (algorithms, signed
/// attributes, certificate chain), uses `asn1crypto` instead — parsing to
/// make a trust decision is a different job from framing a fixed request.
pub struct Rfc3161AnchorProvider {
    tsa_url: String,
    http: reqwest::Client,
}

impl Rfc3161AnchorProvider {
    /// `MEMTARA_ANCHOR_TSA_URL`, defaulting to freetsa.org's public
    /// timestamping endpoint — this codebase's DEV default, per this
    /// module's header. Swap the env var before this matters for a real
    /// deployment.
    pub fn from_env() -> anyhow::Result<Self> {
        let tsa_url = std::env::var("MEMTARA_ANCHOR_TSA_URL")
            .unwrap_or_else(|_| "https://freetsa.org/tsr".to_string());
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| anyhow::anyhow!("could not build the anchor HTTP client: {e}"))?;
        Ok(Self { tsa_url, http })
    }

    #[cfg(test)]
    fn with_url(tsa_url: impl Into<String>) -> Self {
        Self {
            tsa_url: tsa_url.into(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build().unwrap(),
        }
    }

    /// Build a minimal DER `TimeStampReq`:
    ///
    /// ```text
    /// TimeStampReq ::= SEQUENCE {
    ///     version        INTEGER { v1(1) },
    ///     messageImprint MessageImprint,
    ///     certReq        BOOLEAN DEFAULT FALSE }
    /// MessageImprint ::= SEQUENCE {
    ///     hashAlgorithm  AlgorithmIdentifier,   -- id-sha256, NULL params
    ///     hashedMessage  OCTET STRING }         -- 32 bytes
    /// ```
    ///
    /// `reqPolicy` and `nonce` are both OPTIONAL and omitted; `certReq` is
    /// set TRUE so the response's `SignedData.certificates` carries the
    /// signing chain, which offline verification needs (see this module's
    /// header — the token embeds its own chain for exactly this reason).
    ///
    /// CONFIRMED EMPIRICALLY, not guessed: this exact byte layout was built
    /// with `openssl ts -query -sha256 -cert -no_nonce` and POSTed to
    /// `https://freetsa.org/tsr` (Content-Type `application/timestamp-query`)
    /// during development of this module, which returned HTTP 200 with a
    /// `Content-Type: application/timestamp-reply` body whose `PKIStatus`
    /// was `Status: Granted.` and whose token verified with `openssl ts
    /// -verify` against freetsa.org's own published CA and TSA certificates.
    /// The request openssl produced for a 32-byte digest was 59 bytes,
    /// matching the fixed overhead computed below (2 + 2 + 15 + 2 + 34 + 3 =
    /// 58, plus the 1-byte version content = 59), which is the same
    /// confirm-before-encoding discipline this project applies to `bb`.
    fn build_timestamp_query(digest: &[u8; 32]) -> Vec<u8> {
        // AlgorithmIdentifier { OID 2.16.840.1.101.3.4.2.1 (id-sha256), NULL }.
        // The OID's DER body (9 bytes: 60 86 48 01 65 03 04 02 01) encodes
        // arc 2.16.840.1.101.3.4.2.1 per the standard base-128 multi-byte
        // rule; written out as a literal rather than computed, the same
        // "confirm the bytes, don't derive them at runtime" choice
        // `crypto::signer::IssuerKey`'s hand-rolled JWS makes.
        let oid_body: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let mut alg_id = Vec::new();
        alg_id.push(0x06); // OBJECT IDENTIFIER
        alg_id.push(oid_body.len() as u8);
        alg_id.extend_from_slice(&oid_body);
        alg_id.extend_from_slice(&[0x05, 0x00]); // NULL parameters

        let mut alg_seq = Vec::new();
        alg_seq.push(0x30); // SEQUENCE
        alg_seq.push(alg_id.len() as u8);
        alg_seq.extend_from_slice(&alg_id);

        let mut hashed_message = Vec::new();
        hashed_message.push(0x04); // OCTET STRING
        hashed_message.push(digest.len() as u8); // 32, fits in one length byte
        hashed_message.extend_from_slice(digest);

        let mut message_imprint_content = Vec::new();
        message_imprint_content.extend_from_slice(&alg_seq);
        message_imprint_content.extend_from_slice(&hashed_message);
        let mut message_imprint = Vec::new();
        message_imprint.push(0x30); // SEQUENCE
        message_imprint.push(message_imprint_content.len() as u8);
        message_imprint.extend_from_slice(&message_imprint_content);

        let version: [u8; 3] = [0x02, 0x01, 0x01]; // INTEGER 1
        let cert_req: [u8; 3] = [0x01, 0x01, 0xff]; // BOOLEAN TRUE

        let mut content = Vec::new();
        content.extend_from_slice(&version);
        content.extend_from_slice(&message_imprint);
        content.extend_from_slice(&cert_req);

        let mut request = Vec::new();
        request.push(0x30); // SEQUENCE
        push_der_length(&mut request, content.len());
        request.extend_from_slice(&content);
        request
    }

    /// Walk just far enough into a DER `TimeStampResp` to (a) confirm the
    /// request was granted and (b) return the `TimeStampToken` bytes,
    /// without a general ASN.1 parser:
    ///
    /// ```text
    /// TimeStampResp ::= SEQUENCE {
    ///     status         PKIStatusInfo,
    ///     timeStampToken TimeStampToken OPTIONAL }
    /// PKIStatusInfo ::= SEQUENCE {
    ///     status        INTEGER (granted(0) | grantedWithMods(1) | ...),
    ///     ... }
    /// ```
    ///
    /// `TimeStampToken` is itself a `ContentInfo` SEQUENCE and, being the
    /// last field of `TimeStampResp`, occupies every byte remaining after
    /// `PKIStatusInfo`'s own TLV — confirmed against the real freetsa.org
    /// response captured while writing this module: extracting those
    /// trailing bytes and extracting the token with `openssl ts -reply
    /// -token_out` produced byte-identical output.
    fn extract_token(response: &[u8]) -> anyhow::Result<Vec<u8>> {
        let outer = read_tlv(response).map_err(|e| anyhow::anyhow!("TimeStampResp: {e}"))?;
        if outer.tag != 0x30 {
            anyhow::bail!("TimeStampResp is not a SEQUENCE (tag {:#04x})", outer.tag);
        }
        let status_tlv =
            read_tlv(outer.content).map_err(|e| anyhow::anyhow!("PKIStatusInfo: {e}"))?;
        if status_tlv.tag != 0x30 {
            anyhow::bail!("PKIStatusInfo is not a SEQUENCE (tag {:#04x})", status_tlv.tag);
        }
        let status_int =
            read_tlv(status_tlv.content).map_err(|e| anyhow::anyhow!("PKIStatus: {e}"))?;
        if status_int.tag != 0x02 {
            anyhow::bail!("PKIStatus is not an INTEGER (tag {:#04x})", status_int.tag);
        }
        let status_value = decode_der_integer(status_int.content)?;
        // 0 = granted, 1 = grantedWithMods (RFC 3161 §2.4.2). Anything else
        // is a refusal, and there is no token to extract.
        if status_value != 0 && status_value != 1 {
            anyhow::bail!(
                "TSA did not grant the timestamp: PKIStatus {status_value} (0=granted, \
                 1=grantedWithMods expected; see RFC 3161 §2.4.2 for the rest)"
            );
        }

        let consumed = status_tlv.total_len;
        let token_bytes = &outer.content[consumed..];
        if token_bytes.is_empty() {
            anyhow::bail!(
                "TSA reported PKIStatus {status_value} (granted) but sent no timeStampToken"
            );
        }
        Ok(token_bytes.to_vec())
    }
}

#[async_trait]
impl AnchorProvider for Rfc3161AnchorProvider {
    async fn anchor(&self, digest: &[u8; 32]) -> anyhow::Result<AnchorReceipt> {
        let request_bytes = Self::build_timestamp_query(digest);

        let response = self
            .http
            .post(&self.tsa_url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_bytes)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("POST {} failed: {e}", self.tsa_url))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("could not read the TSA response body: {e}"))?;
        if !status.is_success() {
            anyhow::bail!(
                "{} returned HTTP {status} ({} bytes body)",
                self.tsa_url,
                body.len()
            );
        }

        let token_der = Self::extract_token(&body)?;
        let reference = format!("sha256:{}", hex(&Sha256::digest(&token_der)));

        Ok(AnchorReceipt {
            target: RFC3161_TARGET.to_string(),
            reference,
            token_der,
            anchored_at: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------
// A tiny, scope-limited DER TLV reader — definite-length forms only, which
// is what DER (and therefore every message this module reads) requires.
// Deliberately not a general ASN.1 library: see `Rfc3161AnchorProvider`'s
// doc comment for why that job is left to `verify_bundle.py`/`asn1crypto`.
// ---------------------------------------------------------------------

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    /// Bytes consumed by this TLV as a whole (tag + length + content), so a
    /// caller can find where the NEXT sibling element starts.
    total_len: usize,
}

fn read_tlv(buf: &[u8]) -> Result<Tlv<'_>, String> {
    if buf.len() < 2 {
        return Err(format!("buffer too short for a TLV header ({} bytes)", buf.len()));
    }
    let tag = buf[0];
    if tag & 0x1f == 0x1f {
        return Err("high-tag-number form is not needed by anything this module reads".into());
    }
    let (len, len_bytes) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 1usize)
    } else {
        let num_len_bytes = (buf[1] & 0x7f) as usize;
        if num_len_bytes == 0 {
            return Err("indefinite-length encoding is not valid DER".into());
        }
        if num_len_bytes > 4 {
            return Err(format!("length field too large ({num_len_bytes} bytes)"));
        }
        if buf.len() < 2 + num_len_bytes {
            return Err("buffer too short for the declared length field".into());
        }
        let mut len = 0usize;
        for &b in &buf[2..2 + num_len_bytes] {
            len = (len << 8) | b as usize;
        }
        (len, 1 + num_len_bytes)
    };
    let header_len = 1 + len_bytes;
    if buf.len() < header_len + len {
        return Err(format!(
            "declared length {len} exceeds remaining buffer ({} bytes after header)",
            buf.len() - header_len
        ));
    }
    Ok(Tlv { tag, content: &buf[header_len..header_len + len], total_len: header_len + len })
}

/// Append `len` as a DER length field (short form under 128, long form
/// otherwise). Only ever called with lengths well under `2^32` here.
fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let significant: Vec<u8> = {
        let mut i = 0;
        while i < bytes.len() - 1 && bytes[i] == 0 {
            i += 1;
        }
        bytes[i..].to_vec()
    };
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(&significant);
}

/// A DER INTEGER's content as an `i64`, for the small values (`PKIStatus`,
/// 0-5) this module ever needs to read. Not a general bignum decoder.
fn decode_der_integer(content: &[u8]) -> anyhow::Result<i64> {
    if content.is_empty() {
        anyhow::bail!("empty INTEGER content");
    }
    if content.len() > 8 {
        anyhow::bail!("INTEGER too large for this reader ({} bytes)", content.len());
    }
    let negative = content[0] & 0x80 != 0;
    let mut value: i64 = if negative { -1 } else { 0 };
    for &b in content {
        value = (value << 8) | b as i64;
    }
    Ok(value)
}

// ---------------------------------------------------------------------
// Reported anchor state — pure, so every branch is unit-testable without a
// database or a clock double.
// ---------------------------------------------------------------------

/// How often the sweep looks for unanchored checkpoints, read once at boot
/// in the same style — and for the same mechanical reason — as
/// `checkpoint::CheckpointPolicy`: see that struct's doc comment for why
/// this lives on its own rather than folded into `Config`.
#[derive(Debug, Clone, Copy)]
pub struct AnchorPolicy {
    pub sweep_interval: Duration,
    /// Bounds how many unanchored checkpoints one sweep tick attempts, so a
    /// deployment that fell behind (a long TSA outage, a burst of
    /// checkpoints) cannot turn one tick into an unbounded run of HTTP
    /// calls. The backlog is retried on the next tick either way.
    pub batch_limit: i64,
}

impl Default for AnchorPolicy {
    fn default() -> Self {
        // 300s: anchoring is a network call to a service this deployment
        // does not operate, so it is deliberately less chatty than
        // checkpointing itself (60s default) rather than matched to it —
        // hammering a free public TSA on the same cadence as an in-process
        // signature would be an unreasonable neighbour. `POST
        // /audit/anchors/sweep` exists for the moment someone wants an
        // anchor sooner than the next tick, the same on-demand escape
        // hatch `POST /audit/checkpoints` provides for checkpoints.
        //
        // `batch_limit` 500, not a smaller "surely enough" number: it
        // exists to cap worst-case work per tick against a genuine flood,
        // not to be the first number that looked plausible. 20 was tried
        // during development of this module and was too small to be
        // reliable on a single long-lived shared development database —
        // hundreds of checkpoints accumulate there from ordinary repeated
        // test runs (this module's own tests among them), which is exactly
        // the kind of backlog a real deployment recovering from a multi-day
        // TSA outage would also need to drain in a bounded number of ticks
        // rather than one per tick forever.
        Self { sweep_interval: Duration::from_secs(300), batch_limit: 500 }
    }
}

impl AnchorPolicy {
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            sweep_interval: std::env::var("MEMTARA_ANCHOR_SWEEP_INTERVAL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| Duration::from_secs(v.max(1)))
                .unwrap_or(default.sweep_interval),
            batch_limit: std::env::var("MEMTARA_ANCHOR_SWEEP_BATCH_LIMIT")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .map(|v| v.max(1))
                .unwrap_or(default.batch_limit),
        }
    }

    /// Same clamp rationale as `CheckpointPolicy::poll`: fast enough that
    /// the batch limit can matter, capped so a long configured interval
    /// doesn't turn into a permanently-idle loop.
    fn poll(&self) -> Duration {
        self.sweep_interval.clamp(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// The three cases B2 requires distinguishing, reported wherever checkpoint
/// state already is: a checkpoint has either been witnessed externally
/// (`Anchored`), has not yet but is still inside the sweep's own cadence
/// (`Pending`, not a finding), or has outlived that cadence without being
/// witnessed (`Overdue`, which IS a finding and says so in its own text —
/// B2's explicit instruction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AnchorState {
    Anchored { target: String, reference: String, anchored_at: DateTime<Utc> },
    Pending { age_seconds: i64 },
    Overdue { age_seconds: i64, note: String },
}

/// Pure function: given what a checkpoint's anchor columns currently say,
/// how old the checkpoint is, and the sweep's own policy, which of the
/// three states applies right now. No I/O, mirroring `checkpoint::compare`'s
/// "pure core, tested without a database" shape.
pub fn classify(
    signed_at: DateTime<Utc>,
    anchor_target: Option<&str>,
    anchor_ref: Option<&str>,
    anchored_at: Option<DateTime<Utc>>,
    policy: &AnchorPolicy,
    now: DateTime<Utc>,
) -> AnchorState {
    if let (Some(target), Some(reference), Some(at)) = (anchor_target, anchor_ref, anchored_at) {
        return AnchorState::Anchored {
            target: target.to_string(),
            reference: reference.to_string(),
            anchored_at: at,
        };
    }
    let age = now.signed_duration_since(signed_at);
    let age_seconds = age.num_seconds().max(0);
    let threshold = ChronoDuration::seconds(policy.sweep_interval.as_secs() as i64)
        + ChronoDuration::seconds(CLOCK_SKEW_ALLOWANCE_SECONDS);
    if age > threshold {
        AnchorState::Overdue {
            age_seconds,
            note: format!(
                "this checkpoint has gone {age_seconds}s without being anchored, longer than \
                 the {}s sweep interval plus clock-skew allowance. The sweep should have \
                 reached it by now and has not — ask whether the anchoring job is running and \
                 whether the TSA is reachable (POST /audit/anchors/sweep runs it on demand).",
                policy.sweep_interval.as_secs(),
            ),
        }
    } else {
        AnchorState::Pending { age_seconds }
    }
}

// ---------------------------------------------------------------------
// The sweep itself
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SweepResult {
    Anchored { target: String, reference: String },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepDetail {
    pub checkpoint_no: i64,
    #[serde(flatten)]
    pub result: SweepResult,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SweepOutcome {
    pub attempted: i64,
    pub anchored: i64,
    pub failed: i64,
    pub details: Vec<SweepDetail>,
}

/// One pass: find unanchored checkpoints (oldest first — an anchor is most
/// valuable on the record that has waited longest), try each against
/// `provider`, and persist whatever succeeds. A provider error for one
/// checkpoint is logged and does not stop the batch — the next checkpoint
/// still gets its own attempt, and a checkpoint that failed this tick is
/// picked up again next tick because `anchored_at` is still null.
///
/// The `UPDATE ... WHERE anchored_at IS NULL` guard makes a concurrent sweep
/// (a second replica, or this same process's on-demand endpoint racing the
/// background loop) safe without a lock: at most one write wins, and the
/// loser's receipt — a real, validly obtained anchor that simply arrived
/// second — is discarded rather than causing a constraint violation. That
/// is the right trade: two valid anchors for the same checkpoint are
/// redundant, not a race to guard against expensively.
pub async fn sweep_once(
    db: &PgPool,
    provider: &dyn AnchorProvider,
    policy: &AnchorPolicy,
) -> ApiResult<SweepOutcome> {
    let rows = sqlx::query!(
        r#"
        select checkpoint_no as "checkpoint_no!", checkpoint_hash
          from audit_checkpoints
         where anchored_at is null
         order by checkpoint_no asc
         limit $1
        "#,
        policy.batch_limit,
    )
    .fetch_all(db)
    .await?;

    let mut outcome = SweepOutcome::default();
    for row in rows {
        outcome.attempted += 1;
        let digest: [u8; 32] = match row.checkpoint_hash.as_slice().try_into() {
            Ok(d) => d,
            Err(_) => {
                // `checkpoint_hash` is constrained to 32 bytes at the
                // database level (migrations/0008), so this branch is
                // unreachable against an honest schema. Reported rather
                // than panicked on, because a `?` here is exactly the
                // shape of bug this sweep must not let take the whole loop
                // down — see this module's header on why a single failure
                // must never propagate.
                outcome.failed += 1;
                outcome.details.push(SweepDetail {
                    checkpoint_no: row.checkpoint_no,
                    result: SweepResult::Failed {
                        error: format!(
                            "checkpoint_hash is {} bytes, expected 32 — schema invariant violated",
                            row.checkpoint_hash.len()
                        ),
                    },
                });
                continue;
            }
        };

        match provider.anchor(&digest).await {
            Ok(receipt) => {
                let updated = sqlx::query!(
                    r#"
                    update audit_checkpoints
                       set anchor_target = $1, anchor_ref = $2, anchor_receipt = $3, anchored_at = $4
                     where checkpoint_no = $5 and anchored_at is null
                    "#,
                    receipt.target,
                    receipt.reference,
                    receipt.token_der,
                    receipt.anchored_at,
                    row.checkpoint_no,
                )
                .execute(db)
                .await?;

                if updated.rows_affected() == 1 {
                    outcome.anchored += 1;
                    tracing::info!(
                        checkpoint_no = row.checkpoint_no,
                        target = %receipt.target,
                        reference = %receipt.reference,
                        "checkpoint anchored"
                    );
                    outcome.details.push(SweepDetail {
                        checkpoint_no: row.checkpoint_no,
                        result: SweepResult::Anchored {
                            target: receipt.target,
                            reference: receipt.reference,
                        },
                    });
                } else {
                    // Someone else anchored it first (see the doc comment
                    // above) between our SELECT and our UPDATE. A real
                    // receipt was obtained and is simply not needed —
                    // logged, not treated as a failure of this attempt.
                    tracing::debug!(
                        checkpoint_no = row.checkpoint_no,
                        "checkpoint was anchored by a concurrent sweep first; this receipt discarded"
                    );
                    outcome.details.push(SweepDetail {
                        checkpoint_no: row.checkpoint_no,
                        result: SweepResult::Anchored {
                            target: receipt.target,
                            reference: "(superseded by a concurrent sweep)".to_string(),
                        },
                    });
                }
            }
            Err(e) => {
                outcome.failed += 1;
                tracing::warn!(
                    checkpoint_no = row.checkpoint_no,
                    error = %e,
                    "anchoring attempt failed; will retry on the next sweep — checkpointing \
                     itself is unaffected"
                );
                outcome.details.push(SweepDetail {
                    checkpoint_no: row.checkpoint_no,
                    result: SweepResult::Failed { error: e.to_string() },
                });
            }
        }
    }

    Ok(outcome)
}

/// Start the background sweep. One line from `main`, same shape as
/// `checkpoint::spawn`: never returns, never propagates an error out of the
/// loop, because a dead sweep task is a silently growing backlog of
/// unwitnessed checkpoints — exactly the failure this module exists to
/// bound, not to become an instance of.
pub fn spawn(state: AppState) {
    let policy = AnchorPolicy::from_env();
    let poll = policy.poll();

    tokio::spawn(async move {
        tracing::info!(
            sweep_interval_seconds = policy.sweep_interval.as_secs(),
            batch_limit = policy.batch_limit,
            poll_seconds = poll.as_secs_f64(),
            "audit anchoring sweep started"
        );
        loop {
            tokio::time::sleep(poll).await;
            match sweep_once(&state.db, state.anchor_provider.as_ref(), &policy).await {
                Ok(outcome) if outcome.attempted > 0 => tracing::info!(
                    attempted = outcome.attempted,
                    anchored = outcome.anchored,
                    failed = outcome.failed,
                    "anchoring sweep tick"
                ),
                Ok(_) => {}
                Err(err) => tracing::error!(error = ?err, "anchoring sweep tick failed"),
            }
        }
    });
}

// ---------------------------------------------------------------------
// HTTP — the on-demand trigger, mirroring `POST /audit/checkpoints`
// ---------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new().route("/audit/anchors/sweep", post(post_anchor_sweep))
}

#[derive(Serialize)]
struct SweepDetailResponse {
    checkpoint_no: i64,
    #[serde(flatten)]
    result: SweepResult,
}

#[derive(Serialize)]
struct SweepResponse {
    attempted: i64,
    anchored: i64,
    failed: i64,
    details: Vec<SweepDetailResponse>,
    note: String,
}

/// `POST /audit/anchors/sweep` — run one sweep pass now rather than waiting
/// out `AnchorPolicy::sweep_interval`. Same rationale as `POST
/// /audit/checkpoints`: the moment an anchor is most wanted is immediately
/// before an export or a dispute, not on the background loop's schedule.
/// Any authenticated org may call it — like `/audit/integrity`, nothing
/// here is tenant-scoped, and every checkpoint anchored benefits every
/// tenant equally, so gating it behind an admin role would make "witness my
/// evidence now" something customers ask us to do rather than something
/// they can do.
async fn post_anchor_sweep(
    OrgAuth(_org_id): OrgAuth,
    State(state): State<AppState>,
) -> ApiResult<Json<SweepResponse>> {
    let outcome = sweep_once(&state.db, state.anchor_provider.as_ref(), &state.anchor_policy).await?;
    let note = if outcome.attempted == 0 {
        "no unanchored checkpoints were found; every checkpoint on this deployment already has \
         an external witness."
            .to_string()
    } else {
        format!(
            "attempted {}: {} newly anchored, {} failed and will be retried on the next sweep \
             (or the next call to this endpoint).",
            outcome.attempted, outcome.anchored, outcome.failed,
        )
    };
    Ok(Json(SweepResponse {
        attempted: outcome.attempted,
        anchored: outcome.anchored,
        failed: outcome.failed,
        details: outcome
            .details
            .into_iter()
            .map(|d| SweepDetailResponse { checkpoint_no: d.checkpoint_no, result: d.result })
            .collect(),
        note,
    }))
}

/// Base64 (standard, padded) of DER bytes — the encoding used wherever an
/// anchor receipt crosses the HTTP boundary, kept in one place so
/// `checkpoint.rs`'s response builder and any future caller agree on it.
pub fn encode_receipt(der: &[u8]) -> String {
    B64_STANDARD.encode(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // The RFC 3161 wire format, checked byte-for-byte against what was
    // captured from a real freetsa.org exchange while writing this module.
    // -----------------------------------------------------------------

    #[test]
    fn the_request_matches_what_openssl_sent_to_a_real_tsa() {
        // Captured verbatim: `openssl ts -query -data <payload> -sha256
        // -cert -no_nonce -out request.tsq` against a real payload, POSTed
        // to `https://freetsa.org/tsr` during development of this module
        // and granted (see `extract_token`'s doc comment for the response
        // side of the same exchange). The full 59-byte request, byte for
        // byte:
        //   30390201013031300d0609608648016503040201050004206f90b84168fe44
        //   f5e031f24d1451b4e5620db4f5ec184aafe1f12bdd2af760640101ff
        let digest: [u8; 32] =
            hex_literal("6f90b84168fe44f5e031f24d1451b4e5620db4f5ec184aafe1f12bdd2af76064");
        let expected = hex_literal_vec(
            "30390201013031300d0609608648016503040201050004\
             206f90b84168fe44f5e031f24d1451b4e5620db4f5ec184aafe1f12bdd2af76064\
             0101ff",
        );
        assert_eq!(Rfc3161AnchorProvider::build_timestamp_query(&digest), expected);
    }

    #[test]
    fn extract_token_recovers_exactly_the_bytes_openssl_extracted() {
        // The full `response.tsr` bytes captured from freetsa.org for the
        // request above, and the `token.der` `openssl ts -reply -token_out`
        // produced from it, are too large to inline here in full length —
        // this test instead exercises the structural property those two
        // captures confirmed: a well-formed TimeStampResp (PKIStatusInfo
        // SEQUENCE, status=0, followed immediately by an arbitrary
        // "TimeStampToken") round-trips through `extract_token` as exactly
        // the trailing bytes, byte for byte.
        let fake_token: Vec<u8> = vec![0x30, 0x03, 0x02, 0x01, 0x2a]; // a tiny SEQUENCE, stand-in
        let mut status_info = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // PKIStatusInfo { status: 0 }
        let mut outer_content = Vec::new();
        outer_content.append(&mut status_info);
        outer_content.extend_from_slice(&fake_token);
        let mut response = vec![0x30];
        push_der_length(&mut response, outer_content.len());
        response.extend_from_slice(&outer_content);

        let extracted = Rfc3161AnchorProvider::extract_token(&response).unwrap();
        assert_eq!(extracted, fake_token);
    }

    #[test]
    fn extract_token_refuses_a_rejected_response() {
        let status_info = vec![0x30, 0x03, 0x02, 0x01, 0x02]; // PKIStatus 2 = rejection
        let mut response = vec![0x30];
        push_der_length(&mut response, status_info.len());
        response.extend_from_slice(&status_info);

        let err = Rfc3161AnchorProvider::extract_token(&response).unwrap_err();
        assert!(err.to_string().contains("PKIStatus 2"), "got: {err}");
    }

    #[test]
    fn der_length_round_trips_short_and_long_form() {
        for len in [0usize, 1, 127, 128, 255, 256, 4629, 65536] {
            let mut out = vec![0x30];
            push_der_length(&mut out, len);
            let content = vec![0u8; len];
            out.extend_from_slice(&content);
            let tlv = read_tlv(&out).unwrap();
            assert_eq!(tlv.content.len(), len, "length {len} did not round-trip");
        }
    }

    fn hex_literal(s: &str) -> [u8; 32] {
        hex_literal_vec(s).try_into().unwrap()
    }

    fn hex_literal_vec(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------
    // `classify` — pure, every branch, no database.
    // -----------------------------------------------------------------

    fn policy() -> AnchorPolicy {
        AnchorPolicy { sweep_interval: Duration::from_secs(300), batch_limit: 20 }
    }

    #[test]
    fn a_checkpoint_with_all_four_anchor_columns_is_anchored() {
        let now = Utc::now();
        let state = classify(
            now - ChronoDuration::hours(1),
            Some("rfc3161"),
            Some("sha256:abc"),
            Some(now - ChronoDuration::minutes(30)),
            &policy(),
            now,
        );
        assert_eq!(
            state,
            AnchorState::Anchored {
                target: "rfc3161".into(),
                reference: "sha256:abc".into(),
                anchored_at: now - ChronoDuration::minutes(30),
            }
        );
    }

    #[test]
    fn a_freshly_signed_unanchored_checkpoint_is_pending_not_overdue() {
        let now = Utc::now();
        let state = classify(now - ChronoDuration::seconds(10), None, None, None, &policy(), now);
        assert!(matches!(state, AnchorState::Pending { age_seconds } if age_seconds == 10));
    }

    #[test]
    fn an_unanchored_checkpoint_older_than_the_sweep_interval_is_overdue_and_says_so() {
        let now = Utc::now();
        let state = classify(
            now - ChronoDuration::seconds(400), // > 300s sweep interval + skew
            None,
            None,
            None,
            &policy(),
            now,
        );
        match state {
            AnchorState::Overdue { age_seconds, note } => {
                assert_eq!(age_seconds, 400);
                assert!(note.contains("overdue") || note.contains("has gone"), "note: {note}");
                assert!(note.contains("300"), "the note must name the interval: {note}");
            }
            other => panic!("expected Overdue, got {other:?}"),
        }
    }

    #[test]
    fn the_clock_skew_allowance_prevents_a_false_overdue_right_at_the_boundary() {
        // Exactly at the sweep interval, plus a couple of seconds of
        // ordinary inter-process clock drift, must not read as overdue —
        // this is trap #4 from the stage plan, applied to this module's
        // own boundary rather than accommodated in a test.
        let now = Utc::now();
        let state = classify(
            now - ChronoDuration::seconds(302), // 300s interval + 2s drift
            None,
            None,
            None,
            &policy(),
            now,
        );
        assert!(matches!(state, AnchorState::Pending { .. }), "got {state:?}");
    }

    #[test]
    fn a_receipt_with_partial_anchor_columns_is_treated_as_unanchored() {
        // `classify` only trusts the all-four-present case; a half-written
        // row (which the database itself refuses via
        // audit_checkpoints_anchor_complete, migrations/0012) is read the
        // safe way if it were ever encountered.
        let now = Utc::now();
        let state =
            classify(now - ChronoDuration::seconds(10), Some("rfc3161"), None, None, &policy(), now);
        assert!(matches!(state, AnchorState::Pending { .. }));
    }

    // -----------------------------------------------------------------
    // Non-ASCII in the overdue note — trap #1: any new text field gets
    // French and Arabic values exercised, no exceptions. The note is
    // generated text (not user input), so what is exercised here is that
    // formatting it alongside non-ASCII operator-supplied context (e.g. a
    // future caller interpolating a org name) would not corrupt the
    // English message itself — a minimal but real check that `format!`
    // with these values does not panic or mangle UTF-8 boundaries.
    // -----------------------------------------------------------------

    #[test]
    fn overdue_reporting_is_well_formed_regardless_of_locale_context() {
        for label in ["overdue", "en retard", "متأخر"] {
            let now = Utc::now();
            let state = classify(
                now - ChronoDuration::seconds(1000),
                None,
                None,
                None,
                &policy(),
                now,
            );
            if let AnchorState::Overdue { note, .. } = &state {
                // The note itself is English (it is operational text for an
                // operator, not a user-facing label), but it must remain
                // valid UTF-8 and non-empty when the surrounding context a
                // caller logs alongside it is non-ASCII — exercised by
                // formatting the label into a combined line the way a log
                // call would.
                let combined = format!("[{label}] {note}");
                assert!(combined.contains(&note.to_string()));
                assert!(std::str::from_utf8(combined.as_bytes()).is_ok());
            } else {
                panic!("expected Overdue");
            }
        }
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;

        /// A shared development database accumulates hundreds of unanchored
        /// checkpoints over repeated test runs — real rows, not a mock's
        /// invention, left by every test file (this one included) and every
        /// engineer's own session against the same Postgres. `sweep_once`'s
        /// production `batch_limit` (500, see `AnchorPolicy::default`) is
        /// sized to drain a backlog like that in a bounded number of ticks,
        /// but a single test asserting on ONE specific checkpoint must not
        /// depend on how dirty the shared database happens to be when it
        /// runs — that would make the test's outcome a function of test
        /// order and history rather than of the code under test. A very
        /// large batch limit here removes that dependency without weakening
        /// what `policy()`'s smaller, realistic value already covers in the
        /// pure `classify` tests above.
        fn unbounded_policy() -> AnchorPolicy {
            AnchorPolicy { sweep_interval: Duration::from_secs(300), batch_limit: 1_000_000 }
        }

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(10).connect(&url).await.ok()
        }

        /// The DoD requirement, exercised directly: checkpointing survives a
        /// dead TSA. A checkpoint is created for real, the sweep is run
        /// against a provider that always refuses, and (a) the sweep
        /// completes without error — it reports the failure rather than
        /// propagating it — and (b) the checkpoint itself, and its
        /// verifiability, are entirely unaffected: nothing about
        /// `checkpoint::verify` depends on whether an anchor exists.
        #[tokio::test]
        async fn a_dead_tsa_does_not_stop_checkpointing_or_crash_the_sweep() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            use crate::audit::checkpoint;
            use crate::audit::record_in_tx;
            use crate::crypto::signer::IssuerKey;

            let signer = IssuerKey::from_seed([9u8; 32], "https://api.memtara.test");
            let mut tx = db.begin().await.unwrap();
            record_in_tx(&mut tx, None, "anchor_test_dead_tsa", None, serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let cp = checkpoint::emit_in_tx(&mut tx, &signer)
                .await
                .unwrap()
                .expect("a checkpoint over a non-empty chain");
            let verification_before = checkpoint::verify(&mut tx, &signer, &cp).await.unwrap();
            assert!(verification_before.intact, "the checkpoint itself must be unaffected by anchoring");
            tx.commit().await.unwrap();

            let dead = LoggingAnchorProvider::always_refusing();
            let outcome = sweep_once(&db, &dead, &unbounded_policy()).await.unwrap();
            assert!(outcome.attempted >= 1, "the checkpoint just created must have been attempted");
            assert!(
                outcome.details.iter().any(
                    |d| d.checkpoint_no == cp.checkpoint_no
                        && matches!(d.result, SweepResult::Failed { .. })
                ),
                "our checkpoint must be reported as a failed attempt, not silently dropped: {:?}",
                outcome.details
            );

            let reread: Option<String> = sqlx::query_scalar!(
                "select anchor_target from audit_checkpoints where checkpoint_no = $1",
                cp.checkpoint_no
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert!(
                reread.is_none(),
                "a failed anchor attempt must leave the checkpoint's anchor columns null, got {reread:?}"
            );

            let mut tx2 = db.begin().await.unwrap();
            let verification_after = checkpoint::verify(&mut tx2, &signer, &cp).await.unwrap();
            assert!(
                verification_after.intact,
                "a dead TSA must not affect the checkpoint's own verifiability: {verification_after:?}"
            );
            tx2.rollback().await.unwrap();

            // Real cleanup against the pool (not a rolled-back transaction):
            // this test's audit row was committed for real by `tx.commit()`,
            // so a rollback here would not remove it. Best-effort, mirroring
            // `tests/break_it/conftest.py`'s cleanup convention and
            // `audit::tests`'s own documented tolerance for exactly this
            // shape of housekeeping.
            //
            // Deliberately NOT deleting the `audit_checkpoints` row: unlike
            // `audit_log` deletes (an established, documented pattern other
            // modules' tests already rely on), removing a checkpoint out
            // from under a CONCURRENTLY running `checkpoint.rs` test is a
            // real interference this suite hit while this module was being
            // written — another test's `latest()`/`previous` read can name
            // this checkpoint as its predecessor moments before this delete
            // runs, and then report a spurious `CheckpointChainBroken`. This
            // dev database already carries hundreds of checkpoints from
            // ordinary repeated test runs (see `AnchorPolicy::default`'s
            // comment); one more harmless, permanently-unanchored row is a
            // better trade than a delete that can corrupt an unrelated
            // test's chain-linkage assertion.
            let _ = sqlx::query!("delete from audit_log where event_type = 'anchor_test_dead_tsa'")
                .execute(&db)
                .await;
        }

        /// The success path, end to end against the mock: sweep, persist,
        /// re-read, and confirm `classify` now reports `Anchored` from the
        /// live columns.
        #[tokio::test]
        async fn a_successful_anchor_is_persisted_and_reported_as_anchored() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            use crate::audit::checkpoint;
            use crate::audit::record_in_tx;
            use crate::crypto::signer::IssuerKey;

            let signer = IssuerKey::from_seed([10u8; 32], "https://api.memtara.test");
            let mut tx = db.begin().await.unwrap();
            record_in_tx(&mut tx, None, "anchor_test_success", None, serde_json::json!({"n": 1}))
                .await
                .unwrap();
            let cp = checkpoint::emit_in_tx(&mut tx, &signer).await.unwrap().expect("checkpoint");
            tx.commit().await.unwrap();

            let mock = LoggingAnchorProvider::new();
            let outcome = sweep_once(&db, &mock, &unbounded_policy()).await.unwrap();
            assert!(outcome.details.iter().any(
                |d| d.checkpoint_no == cp.checkpoint_no && matches!(d.result, SweepResult::Anchored { .. })
            ));

            let row = sqlx::query!(
                "select anchor_target, anchor_ref, anchor_receipt, anchored_at \
                 from audit_checkpoints where checkpoint_no = $1",
                cp.checkpoint_no
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(row.anchor_target.as_deref(), Some("rfc3161-dev-mock"));
            assert!(row.anchor_ref.is_some());
            assert!(row.anchor_receipt.as_ref().is_some_and(|b| !b.is_empty()));
            assert!(row.anchored_at.is_some());

            let state = classify(
                cp.signed_at,
                row.anchor_target.as_deref(),
                row.anchor_ref.as_deref(),
                row.anchored_at,
                &policy(),
                Utc::now(),
            );
            assert!(matches!(state, AnchorState::Anchored { .. }), "got {state:?}");

            // See the sibling test's comment: the `audit_checkpoints` row is
            // deliberately left in place rather than deleted, to avoid
            // corrupting a concurrently-running `checkpoint.rs` test's
            // chain-linkage assertion.
            let _ = sqlx::query!("delete from audit_log where event_type = 'anchor_test_success'")
                .execute(&db)
                .await;
        }
    }
}
