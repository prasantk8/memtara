// Proof verification: takes a client-submitted proof against a pending
// disclosure request, shells out to `bb verify`, and — only on a genuine
// cryptographic pass — atomically consumes the request's nonce, records the
// proof, and marks the request fulfilled.
//
// This module never generates a proof. It only ever runs `bb verify`
// against bytes a caller sent it. See HANDOFF.md's "explicitly out of
// scope" section: proof generation is exclusively a client-side concern
// (out of scope here) — this backend's job stops at deciding yes/no on
// someone else's proof.

use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::disclosure::{authorize_org_or_user, effective_status};
use crate::domain::{CircuitType, DisclosureStatus};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/disclosure-requests/:id/proofs", post(submit_proof))
}

// ---------------------------------------------------------------------
// bb CLI surface (confirmed empirically — see report for the probe
// transcript). `bb --version` at the time this was written: 5.1.0.
// ---------------------------------------------------------------------

/// `--verifier_target` used for every `write_vk`/`prove`/`verify` call in
/// this module. `noir-recursive` = poseidon2 transcript hash, ZK-preserving
/// (blinded proof, per `bb --help`'s own description: "Noir circuits
/// (poseidon2, ZK)"). Deliberately NOT one of the `-no-zk` variants: this
/// product's whole premise is that a proof doesn't leak the witness beyond
/// what the public inputs already reveal, and the `-no-zk` targets trade
/// that away (meant for contexts like minimizing on-chain gas, which
/// doesn't apply here). Not `evm`/`starknet`: nothing in this product is
/// on-chain. This is a fixed protocol choice, not per-deployment config —
/// whatever eventually generates proofs client-side (out of scope for this
/// pass) MUST target the same value, or an honestly-generated proof will
/// fail to verify.
const BB_VERIFIER_TARGET: &str = "noir-recursive";

fn vkey_dir(config: &Config, circuit: CircuitType) -> PathBuf {
    Path::new(&config.vkeys_dir).join(circuit.as_str())
}

fn vkey_path(config: &Config, circuit: CircuitType) -> PathBuf {
    vkey_dir(config, circuit).join("vk")
}

/// Generate any missing per-circuit verification keys via `bb write_vk`,
/// once, at boot (per HANDOFF.md: "generate once at startup or on first
/// use" — startup was chosen over lazy-on-first-request to avoid a
/// concurrent-first-request race around file creation). Idempotent: a
/// circuit whose `vk` file already exists on disk is skipped, so repeated
/// boots don't regenerate it.
///
/// vkeys are a build artifact of `circuits/`, not source — see
/// backend/.gitignore. If `circuits/` is ever recompiled with different
/// bytecode, delete `vkeys_dir` to force regeneration.
pub async fn ensure_vkeys(config: &Config) -> anyhow::Result<()> {
    for circuit in ALL_CIRCUITS {
        let vk_path = vkey_path(config, circuit);
        if vk_path.exists() {
            continue;
        }

        let bytecode_path = Path::new(&config.circuits_target_dir).join(format!("{}.json", circuit.as_str()));
        if !bytecode_path.exists() {
            anyhow::bail!(
                "compiled circuit bytecode not found at {} — run `nargo compile` under circuits/ first \
                 (CIRCUITS_TARGET_DIR={})",
                bytecode_path.display(),
                config.circuits_target_dir,
            );
        }

        let out_dir = vkey_dir(config, circuit);
        tokio::fs::create_dir_all(&out_dir).await?;

        tracing::info!(circuit = circuit.as_str(), "generating verification key via `bb write_vk`");
        let output = tokio::process::Command::new(&config.bb_bin)
            .arg("write_vk")
            .arg("-b")
            .arg(&bytecode_path)
            .arg("-o")
            .arg(&out_dir)
            .arg("-t")
            .arg(BB_VERIFIER_TARGET)
            .output()
            .await
            .map_err(|e| {
                anyhow::anyhow!("failed to run `{}`: {e} (is bb installed and on PATH?)", config.bb_bin)
            })?;

        if !output.status.success() {
            anyhow::bail!(
                "bb write_vk failed for {}: {}",
                circuit.as_str(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    Ok(())
}

const ALL_CIRCUITS: [CircuitType; 4] =
    [CircuitType::EmergencySession, CircuitType::AiSession, CircuitType::TaxSession, CircuitType::IdentitySession];

/// Run `bb verify` against a caller-supplied proof and public inputs for
/// `circuit`'s verification key. Returns `Ok(true)`/`Ok(false)` for a
/// genuine cryptographic pass/fail (confirmed empirically: `bb verify`
/// exits 0 with "Proof verified successfully" on a real match, and exits
/// non-zero — e.g. "Proof verification failed" or "Non-canonical proof
/// element" for outright garbage — otherwise). `Err` is reserved for
/// infrastructure failure (bb missing, I/O error) — a caller sending a
/// wrong-but-well-formed proof must come back as `Ok(false)`, not a 500.
async fn run_bb_verify(
    config: &Config,
    circuit: CircuitType,
    public_inputs_bytes: &[u8],
    proof_bytes: &[u8],
) -> ApiResult<bool> {
    let vk_path = vkey_path(config, circuit);
    if !vk_path.exists() {
        return Err(ApiError::Other(anyhow::anyhow!(
            "verification key missing for {} at {} — ensure_vkeys should have generated this at boot",
            circuit.as_str(),
            vk_path.display(),
        )));
    }

    let work_dir = std::env::temp_dir().join(format!("memtara-verify-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&work_dir).await.map_err(|e| ApiError::Other(e.into()))?;
    let proof_path = work_dir.join("proof");
    let public_inputs_path = work_dir.join("public_inputs");

    let write_result = async {
        tokio::fs::write(&proof_path, proof_bytes).await?;
        tokio::fs::write(&public_inputs_path, public_inputs_bytes).await?;
        Ok::<(), std::io::Error>(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        return Err(ApiError::Other(e.into()));
    }

    let spawn_result = tokio::process::Command::new(&config.bb_bin)
        .arg("verify")
        .arg("-i")
        .arg(&public_inputs_path)
        .arg("-p")
        .arg(&proof_path)
        .arg("-k")
        .arg(&vk_path)
        .arg("-t")
        .arg(BB_VERIFIER_TARGET)
        .output()
        .await;

    let _ = tokio::fs::remove_dir_all(&work_dir).await;

    let output = spawn_result
        .map_err(|e| ApiError::Other(anyhow::anyhow!("failed to run `{} verify`: {e}", config.bb_bin)))?;

    Ok(output.status.success())
}

// ---------------------------------------------------------------------
// Public-input layout per circuit.
//
// This is `main`'s declared parameter order in each
// circuits/<name>/src/main.nr, filtered to just the `pub` ones (the order
// `pub` params appear in `main`'s signature IS the order bb packs them in
// the public-inputs file — cross-checked against each compiled circuit's
// own ABI at circuits/target/<name>.json `.abi.parameters[].visibility`,
// not just read off the source). `nonce` happens to be declared last in
// all four circuits, but this is written as an explicit per-circuit index
// rather than a hardcoded "take the last one", since that's an incidental
// fact about the current circuits, not a rule this module should assume
// holds for a circuit added later.
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PublicInputLayout {
    count: usize,
    nonce_index: usize,
}

fn public_input_layout(circuit: CircuitType) -> PublicInputLayout {
    match circuit {
        // current_time, vault_root, blood_type_hash, key_meds_hash,
        // allergies_commitment, user_public_key_x, user_public_key_y, nonce
        CircuitType::EmergencySession => PublicInputLayout { count: 8, nonce_index: 7 },
        // current_time, expiry_time, vault_root, allowed_categories_root,
        // user_public_key_x, user_public_key_y, nonce
        CircuitType::AiSession => PublicInputLayout { count: 7, nonce_index: 6 },
        // current_time, expiry_time, vault_root, min_income, max_income,
        // user_public_key_x, user_public_key_y, nonce
        CircuitType::TaxSession => PublicInputLayout { count: 8, nonce_index: 7 },
        // current_time, expiry_time, vault_root, min_years,
        // remote_preference, user_public_key_x, user_public_key_y, nonce
        CircuitType::IdentitySession => PublicInputLayout { count: 8, nonce_index: 7 },
    }
}

/// Parse one JSON public input string into the 32-byte big-endian encoding
/// `bb` expects packed into its public-inputs file (confirmed empirically:
/// a probe circuit's `bb prove` output a 64-byte `public_inputs` file for 2
/// scalar pub params — exactly 32 bytes each, big-endian, in declaration
/// order — see report). Wire format is a `0x`-prefixed hex string (how
/// Noir/NoirJS tooling represents a `Field`), not decimal, so this doesn't
/// need a bignum-decimal parser.
fn parse_field_hex(index: usize, s: &str) -> ApiResult<[u8; 32]> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| ApiError::BadRequest(format!("public_inputs[{index}]: expected a 0x-prefixed hex string")))?;

    if stripped.is_empty() || stripped.len() > 64 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "public_inputs[{index}]: not a valid hex field element (expected up to 64 hex digits after 0x)"
        )));
    }

    let mut padded = [b'0'; 64];
    padded[64 - stripped.len()..].copy_from_slice(stripped.as_bytes());

    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = std::str::from_utf8(&padded[i * 2..i * 2 + 2]).expect("ascii hex digits are valid utf8");
        out[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| ApiError::BadRequest(format!("public_inputs[{index}]: invalid hex digit")))?;
    }
    Ok(out)
}

fn decode_b64(field: &str, value: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64 (expected URL-safe, no padding)")))
}

// ---------------------------------------------------------------------
// Nonce consumption — the replay defense itself.
//
// circuits/lib/src/time_bound.nr's own comment block explains why this
// table exists rather than an in-circuit non-membership proof: a genuine
// in-circuit non-membership proof against a "used nonces" set is possible
// but heavy (sparse Merkle non-membership with sorted neighbor proofs), so
// `nonce` is threaded through as a public input and bound into the policy
// commitment hash instead, and "has this nonce been seen before" is pushed
// off-circuit to this verifier service. `used_nonces` IS that off-circuit
// registry the circuit design already commits to — not a separate
// invention of this module.
// ---------------------------------------------------------------------

enum RecordOutcome {
    Recorded { proof_id: Uuid },
    Replayed,
}

/// Atomically consume `(org_id, nonce)` for a cryptographically-valid
/// proof: insert into `used_nonces`, record the `proofs` row, and flip the
/// disclosure request to `fulfilled` — all in one transaction, rolled back
/// entirely if a concurrent winner already consumed the same nonce.
///
/// The actual race-proofing is `used_nonces`' `primary key (org_id, nonce)`
/// (migrations/0001_init.sql) plus `insert ... on conflict do nothing`: two
/// concurrent transactions racing this same statement for the same
/// `(org_id, nonce)` can't both get a row back, by Postgres's own primary
/// key enforcement — no application-level locking does that work. See the
/// `db` tests below for a real concurrent proof of this (mirrors
/// `vault_sync`'s `concurrent_cas_writes_only_one_winner_survives`).
async fn record_valid_proof(
    db: &sqlx::PgPool,
    request_id: Uuid,
    org_id: Uuid,
    nonce: &[u8],
    public_inputs_json: &serde_json::Value,
    proof_bytes: &[u8],
) -> ApiResult<RecordOutcome> {
    let mut tx = db.begin().await?;

    let consumed = sqlx::query!(
        r#"
        insert into used_nonces (org_id, nonce)
        values ($1, $2)
        on conflict (org_id, nonce) do nothing
        returning used_at
        "#,
        org_id,
        nonce,
    )
    .fetch_optional(&mut *tx)
    .await?;

    if consumed.is_none() {
        tx.rollback().await?;
        return Ok(RecordOutcome::Replayed);
    }

    let proof_id: Uuid = sqlx::query_scalar!(
        r#"
        insert into proofs (request_id, public_inputs, proof_bytes, valid)
        values ($1, $2, $3, true)
        returning id
        "#,
        request_id,
        public_inputs_json,
        proof_bytes,
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "update disclosure_requests set status = 'fulfilled' where id = $1 and status = 'pending'",
        request_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(RecordOutcome::Recorded { proof_id })
}

// ---------------------------------------------------------------------
// POST /disclosure-requests/:id/proofs
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct SubmitProofBody {
    /// One `0x`-prefixed hex string per public input, in the circuit's
    /// declared order (see `public_input_layout` above).
    public_inputs: Vec<String>,
    /// Base64 (URL-safe, no padding) raw `bb`-produced proof bytes.
    proof: String,
}

#[derive(Serialize)]
struct SubmitProofResponse {
    proof_id: Uuid,
    valid: bool,
    request_status: String,
}

/// Who may submit a proof for a request: the spec for the other
/// disclosure-requests routes explicitly says "org that created it, or the
/// user it's for" — this route isn't spelled out the same way, but the
/// same dual-audience trust boundary is the only one that makes sense here
/// too (nobody outside those two parties should be able to attempt a proof
/// against someone else's disclosure request), so it reuses
/// `authorize_org_or_user` for consistency with the rest of this module.
async fn submit_proof(
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<SubmitProofBody>,
) -> ApiResult<(StatusCode, Json<SubmitProofResponse>)> {
    let row = sqlx::query!(
        r#"
        select org_id, user_id, circuit_type, status, nonce, expires_at
        from disclosure_requests
        where id = $1
        "#,
        id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    authorize_org_or_user(&state, &headers, row.org_id, row.user_id).await?;

    let stored_status = DisclosureStatus::parse(&row.status).unwrap_or(DisclosureStatus::Pending);
    let status = effective_status(&state.db, id, stored_status, row.expires_at).await?;
    if status != DisclosureStatus::Pending {
        return Err(ApiError::Conflict(format!("disclosure request is {}, not pending", status.as_str())));
    }

    let circuit = CircuitType::parse(&row.circuit_type).ok_or_else(|| {
        ApiError::Other(anyhow::anyhow!("stored circuit_type '{}' is not a known circuit", row.circuit_type))
    })?;
    let layout = public_input_layout(circuit);

    if body.public_inputs.len() != layout.count {
        return Err(ApiError::BadRequest(format!(
            "{} expects exactly {} public inputs, got {}",
            circuit.as_str(),
            layout.count,
            body.public_inputs.len()
        )));
    }

    let mut packed = Vec::with_capacity(32 * layout.count);
    let mut field_bytes: Vec<[u8; 32]> = Vec::with_capacity(layout.count);
    for (i, s) in body.public_inputs.iter().enumerate() {
        let bytes = parse_field_hex(i, s)?;
        packed.extend_from_slice(&bytes);
        field_bytes.push(bytes);
    }

    let submitted_nonce = &field_bytes[layout.nonce_index];
    if submitted_nonce.as_slice() != row.nonce.as_slice() {
        return Err(ApiError::BadRequest(
            "public_inputs' nonce does not match this disclosure request's assigned nonce".into(),
        ));
    }

    // Fast pre-check: reject an already-replayed nonce before paying for a
    // `bb verify` subprocess. Not the authoritative check (that's the
    // atomic transaction in `record_valid_proof` below) — just avoids
    // wasted work on the common case of someone re-submitting a proof
    // that's already been consumed.
    let already_used = sqlx::query_scalar!(
        r#"select exists(select 1 from used_nonces where org_id = $1 and nonce = $2) as "exists!""#,
        row.org_id,
        row.nonce,
    )
    .fetch_one(&state.db)
    .await?;
    if already_used {
        return Err(ApiError::Conflict("this nonce has already been used to fulfill a disclosure request".into()));
    }

    let proof_bytes = decode_b64("proof", &body.proof)?;
    let valid = run_bb_verify(&state.config, circuit, &packed, &proof_bytes).await?;

    let public_inputs_json = serde_json::to_value(&body.public_inputs)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("public_inputs did not serialize: {e}")))?;

    if !valid {
        // Invalid proofs are recorded (proofs.valid = false) for the audit
        // trail but do NOT consume the nonce or touch request status — an
        // attacker submitting garbage against someone else's pending
        // request must not be able to burn the legitimate holder's one-shot
        // nonce, and the request must remain retriable.
        // TODO(audit): once orgs/audit exists (HANDOFF.md item 2), also
        // write a `proof_verification_failed` audit_log entry here.
        let proof_id: Uuid = sqlx::query_scalar!(
            r#"
            insert into proofs (request_id, public_inputs, proof_bytes, valid)
            values ($1, $2, $3, false)
            returning id
            "#,
            id,
            public_inputs_json,
            proof_bytes,
        )
        .fetch_one(&state.db)
        .await?;

        return Ok((
            StatusCode::CREATED,
            Json(SubmitProofResponse {
                proof_id,
                valid: false,
                request_status: DisclosureStatus::Pending.as_str().to_string(),
            }),
        ));
    }

    // TODO(audit): once orgs/audit exists, write a `proof_verified`
    // audit_log entry here (and a `disclosure_request_fulfilled` one).
    match record_valid_proof(&state.db, id, row.org_id, &row.nonce, &public_inputs_json, &proof_bytes).await? {
        RecordOutcome::Recorded { proof_id } => Ok((
            StatusCode::CREATED,
            Json(SubmitProofResponse {
                proof_id,
                valid: true,
                request_status: DisclosureStatus::Fulfilled.as_str().to_string(),
            }),
        )),
        RecordOutcome::Replayed => {
            Err(ApiError::Conflict("this nonce has already been used to fulfill a disclosure request".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_hex_pads_and_decodes() {
        let bytes = parse_field_hex(0, "0x64").unwrap();
        assert_eq!(bytes[31], 0x64);
        assert!(bytes[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn parse_field_hex_accepts_full_width() {
        let full = format!("0x{}", "ff".repeat(32));
        let bytes = parse_field_hex(0, &full).unwrap();
        assert_eq!(bytes, [0xffu8; 32]);
    }

    #[test]
    fn parse_field_hex_rejects_missing_prefix() {
        assert!(parse_field_hex(0, "64").is_err());
    }

    #[test]
    fn parse_field_hex_rejects_overflow() {
        let too_long = format!("0x{}", "ff".repeat(33));
        assert!(parse_field_hex(0, &too_long).is_err());
    }

    #[test]
    fn parse_field_hex_rejects_non_hex() {
        assert!(parse_field_hex(0, "0xzz").is_err());
    }

    #[test]
    fn parse_field_hex_rejects_empty() {
        assert!(parse_field_hex(0, "0x").is_err());
    }

    #[test]
    fn public_input_layout_matches_circuit_abi_counts() {
        // Cross-checked against circuits/target/<name>.json's own compiled
        // ABI (see report) — this test just pins that understanding so a
        // future edit to the layout table can't silently drift from it.
        assert_eq!(public_input_layout(CircuitType::EmergencySession).count, 8);
        assert_eq!(public_input_layout(CircuitType::AiSession).count, 7);
        assert_eq!(public_input_layout(CircuitType::TaxSession).count, 8);
        assert_eq!(public_input_layout(CircuitType::IdentitySession).count, 8);
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;
        use sqlx::PgPool;

        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(10).connect(&url).await.ok()
        }

        async fn make_user(db: &PgPool) -> Uuid {
            sqlx::query_scalar!(
                "insert into users (email) values ($1) returning id",
                format!("verify-test-{}@example.invalid", Uuid::new_v4()),
            )
            .fetch_one(db)
            .await
            .expect("insert test user")
        }

        async fn make_org(db: &PgPool) -> Uuid {
            sqlx::query_scalar!(
                r#"
                insert into organizations (name, org_type, api_key_hash)
                values ($1, 'bank', $2)
                returning id
                "#,
                format!("Verify Test Bank {}", Uuid::new_v4()),
                format!("hash-{}", Uuid::new_v4()),
            )
            .fetch_one(db)
            .await
            .expect("insert test org")
        }

        async fn make_pending_request(db: &PgPool, org_id: Uuid, user_id: Uuid, nonce: &[u8]) -> Uuid {
            sqlx::query_scalar!(
                r#"
                insert into disclosure_requests (org_id, user_id, circuit_type, policy, status, nonce, expires_at)
                values ($1, $2, 'emergency_session', '{}'::jsonb, 'pending', $3, now() + interval '1 hour')
                returning id
                "#,
                org_id,
                user_id,
                nonce,
            )
            .fetch_one(db)
            .await
            .expect("insert test disclosure_request")
        }

        async fn cleanup(db: &PgPool, org_id: Uuid, user_id: Uuid) {
            let _ = sqlx::query!("delete from used_nonces where org_id = $1", org_id).execute(db).await;
            let _ = sqlx::query!("delete from disclosure_requests where org_id = $1", org_id).execute(db).await;
            let _ = sqlx::query!("delete from organizations where id = $1", org_id).execute(db).await;
            let _ = sqlx::query!("delete from users where id = $1", user_id).execute(db).await;
        }

        /// The core replay-defense claim, tested directly against real
        /// Postgres (not mocked): the SAME (org_id, nonce) can be recorded
        /// as a valid proof exactly once. First call succeeds and actually
        /// flips the disclosure_request to 'fulfilled'; a second call with
        /// the identical nonce is rejected as `Replayed`, and the row
        /// counts prove nothing was double-written.
        #[tokio::test]
        async fn second_submission_of_same_nonce_is_rejected_as_replay() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let org_id = make_org(&db).await;
            let user_id = make_user(&db).await;
            let nonce = vec![7u8; 32];
            let request_id = make_pending_request(&db, org_id, user_id, &nonce).await;
            let public_inputs_json = serde_json::json!(["0x1", "0x2"]);

            let first =
                record_valid_proof(&db, request_id, org_id, &nonce, &public_inputs_json, b"proof-bytes-1").await.unwrap();
            assert!(matches!(first, RecordOutcome::Recorded { .. }), "first submission of a fresh nonce must succeed");

            let status: String =
                sqlx::query_scalar!("select status from disclosure_requests where id = $1", request_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(status, "fulfilled", "a successful proof must flip the request to fulfilled");

            // Same nonce again — a second, distinct (but equally
            // "cryptographically valid" for this test's purposes) proof
            // submission. Must be rejected, not recorded a second time.
            let second =
                record_valid_proof(&db, request_id, org_id, &nonce, &public_inputs_json, b"proof-bytes-2").await.unwrap();
            assert!(matches!(second, RecordOutcome::Replayed), "replaying an already-used nonce must be rejected");

            let used_nonce_count: i64 = sqlx::query_scalar!(
                "select count(*) as \"count!\" from used_nonces where org_id = $1 and nonce = $2",
                org_id,
                nonce,
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(used_nonce_count, 1, "exactly one used_nonces row, not two");

            let proof_count: i64 = sqlx::query_scalar!(
                "select count(*) as \"count!\" from proofs where request_id = $1",
                request_id,
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(proof_count, 1, "the replayed attempt must not have inserted a second proofs row");

            cleanup(&db, org_id, user_id).await;
        }

        /// Fires N concurrent `record_valid_proof` calls at the exact same
        /// (org_id, nonce) from separate pool connections, simulating N
        /// racing submissions of a proof (or a proof being replayed at the
        /// exact moment it's first being recorded). Exactly one must win —
        /// proving the atomicity comes from the DB's own primary-key
        /// constraint, not from any check-then-act race window in this
        /// module. Mirrors vault_sync's
        /// `concurrent_cas_writes_only_one_winner_survives` exactly.
        #[tokio::test]
        async fn concurrent_replay_attempts_exactly_one_winner() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let org_id = make_org(&db).await;
            let user_id = make_user(&db).await;
            let nonce = vec![9u8; 32];
            let request_id = make_pending_request(&db, org_id, user_id, &nonce).await;

            let mut handles = Vec::new();
            for i in 0..8u8 {
                let db = db.clone();
                let nonce = nonce.clone();
                handles.push(tokio::spawn(async move {
                    let public_inputs_json = serde_json::json!([format!("racer-{i}")]);
                    let proof_bytes = vec![i; 16];
                    record_valid_proof(&db, request_id, org_id, &nonce, &public_inputs_json, &proof_bytes)
                        .await
                        .unwrap()
                }));
            }

            let mut winners = 0u32;
            for h in handles {
                if matches!(h.await.unwrap(), RecordOutcome::Recorded { .. }) {
                    winners += 1;
                }
            }
            assert_eq!(winners, 1, "exactly one of N racing submissions of the same nonce must win");

            let used_nonce_count: i64 = sqlx::query_scalar!(
                "select count(*) as \"count!\" from used_nonces where org_id = $1 and nonce = $2",
                org_id,
                nonce,
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(used_nonce_count, 1);

            let proof_count: i64 =
                sqlx::query_scalar!("select count(*) as \"count!\" from proofs where request_id = $1", request_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(proof_count, 1, "only the winning transaction's proofs row must have committed");

            let status: String =
                sqlx::query_scalar!("select status from disclosure_requests where id = $1", request_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(status, "fulfilled");

            cleanup(&db, org_id, user_id).await;
        }

        /// A fresh, never-used nonce on a DIFFERENT request must not be
        /// blocked by an unrelated request's used_nonces row — proves the
        /// replay check is scoped to `(org_id, nonce)`, not e.g. request id
        /// or org id alone.
        #[tokio::test]
        async fn different_nonce_same_org_is_independent() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let org_id = make_org(&db).await;
            let user_id = make_user(&db).await;
            let nonce_a = vec![1u8; 32];
            let nonce_b = vec![2u8; 32];
            let request_a = make_pending_request(&db, org_id, user_id, &nonce_a).await;
            let request_b = make_pending_request(&db, org_id, user_id, &nonce_b).await;
            let public_inputs_json = serde_json::json!([]);

            let a = record_valid_proof(&db, request_a, org_id, &nonce_a, &public_inputs_json, b"a").await.unwrap();
            let b = record_valid_proof(&db, request_b, org_id, &nonce_b, &public_inputs_json, b"b").await.unwrap();

            assert!(matches!(a, RecordOutcome::Recorded { .. }));
            assert!(matches!(b, RecordOutcome::Recorded { .. }), "a different nonce must not be blocked by an unrelated one");

            cleanup(&db, org_id, user_id).await;
        }
    }

    /// Real `bb` subprocess tests: confirm `ensure_vkeys` and
    /// `run_bb_verify` actually invoke the installed `bb` binary and get
    /// real accept/reject decisions from it, not a stub. Skips (rather than
    /// fails) if `bb` isn't on PATH, matching this codebase's convention
    /// for environment-dependent tests (see vault_sync's DB tests).
    mod bb_integration {
        use super::*;

        async fn bb_available(bin: &str) -> bool {
            tokio::process::Command::new(bin).arg("--version").output().await.is_ok()
        }

        fn test_config(vkeys_dir: PathBuf) -> Config {
            Config {
                database_url: "unused".into(),
                bind_addr: "unused".into(),
                session_ttl: std::time::Duration::from_secs(1),
                otp_ttl: std::time::Duration::from_secs(1),
                otp_max_attempts: 1,
                webauthn_rp_id: "unused".into(),
                webauthn_rp_origin: "unused".into(),
                webauthn_rp_name: "unused".into(),
                uae_pass_client_id: "unused".into(),
                uae_pass_client_secret: "unused".into(),
                uae_pass_redirect_uri: "unused".into(),
                uae_pass_authorize_url: "unused".into(),
                bb_bin: std::env::var("BB_BIN").unwrap_or_else(|_| "bb".into()),
                circuits_target_dir: format!("{}/../../circuits/target", env!("CARGO_MANIFEST_DIR")),
                vkeys_dir: vkeys_dir.to_string_lossy().into_owned(),
            }
        }

        /// Real `bb write_vk` against all 4 real compiled circuits from
        /// `circuits/target/`. Confirms the exact invocation this module
        /// uses at boot actually produces a usable vkey file for each of
        /// the 4 real circuits, not just a toy example.
        #[tokio::test]
        async fn ensure_vkeys_generates_real_vk_files_for_all_four_circuits() {
            if !bb_available("bb").await {
                eprintln!("skipping: bb not on PATH");
                return;
            }
            let dir = std::env::temp_dir().join(format!("memtara-vktest-{}", Uuid::new_v4()));
            let config = test_config(dir.clone());

            ensure_vkeys(&config).await.expect("ensure_vkeys should succeed against the real compiled circuits");

            for circuit in ALL_CIRCUITS {
                let vk = vkey_path(&config, circuit);
                let meta = std::fs::metadata(&vk).unwrap_or_else(|e| panic!("expected vk file at {vk:?}: {e}"));
                assert!(meta.len() > 0, "{}: vk file must be non-empty", circuit.as_str());
            }

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A structurally-garbage proof against a real vkey (real
        /// `emergency_session` circuit) must be rejected by the real `bb
        /// verify` binary — not by any application-level shortcut. This is
        /// the exact code path `submit_proof` calls; the only thing not
        /// exercised here is a genuinely-valid proof, which would require a
        /// real EdDSA/Baby-Jubjub signer (no such signer exists yet in this
        /// codebase — see report for why that's out of scope for this
        /// pass).
        #[tokio::test]
        async fn bb_verify_rejects_garbage_proof_against_real_vkey() {
            if !bb_available("bb").await {
                eprintln!("skipping: bb not on PATH");
                return;
            }
            let dir = std::env::temp_dir().join(format!("memtara-vktest-{}", Uuid::new_v4()));
            let config = test_config(dir.clone());
            ensure_vkeys(&config).await.expect("ensure_vkeys should succeed");

            let layout = public_input_layout(CircuitType::EmergencySession);
            let garbage_public_inputs = vec![0u8; 32 * layout.count];
            let garbage_proof = vec![0xABu8; 14_656];

            let valid = run_bb_verify(&config, CircuitType::EmergencySession, &garbage_public_inputs, &garbage_proof)
                .await
                .expect("run_bb_verify should run bb successfully and report a real accept/reject, not error");
            assert!(!valid, "a garbage proof must be rejected by the real bb binary, not accepted");

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// `ensure_vkeys` is idempotent: calling it twice must not attempt
        /// to regenerate a vk file that's already on disk (no error, same
        /// file left in place). Runs `bb` for real for the first call.
        #[tokio::test]
        async fn ensure_vkeys_is_idempotent() {
            if !bb_available("bb").await {
                eprintln!("skipping: bb not on PATH");
                return;
            }
            let dir = std::env::temp_dir().join(format!("memtara-vktest-{}", Uuid::new_v4()));
            let config = test_config(dir.clone());

            ensure_vkeys(&config).await.unwrap();
            let vk_path = vkey_path(&config, CircuitType::EmergencySession);
            let first_modified = std::fs::metadata(&vk_path).unwrap().modified().unwrap();

            ensure_vkeys(&config).await.unwrap();
            let second_modified = std::fs::metadata(&vk_path).unwrap().modified().unwrap();
            assert_eq!(first_modified, second_modified, "an existing vk file must not be regenerated");

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
