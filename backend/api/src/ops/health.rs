// `GET /health` — a deep readiness check.
//
// `/healthz` already exists and stays: it returns "ok" as long as the
// process can answer, which is exactly what a liveness probe should test.
// Restarting a container because its database is briefly unreachable makes
// an outage worse, so liveness must not depend on anything external.
//
// This endpoint is the other half. It asks the three questions whose answers
// determine whether this instance can actually complete a suitability
// journey, and returns 503 when it cannot, so a load balancer can take it
// out of rotation without killing it:
//
//   1. Is the database reachable?
//   2. Is there an issuer key, and does the JWKS a relying party would fetch
//      actually contain the `kid` this server signs with?
//   3. Is there a verification key on disk for every circuit?
//
// The third question has a fourth part that matters more than it looks.
// `circuits/wealth_suitability/vkey/vk` is committed to the repository so a
// DFSA examiner can re-verify a suitability proof years later without
// trusting anyone's build pipeline. If the key this server verifies against
// has drifted from the published one, every proof it accepts today is
// unverifiable by that examiner tomorrow — and nothing else in the system
// would notice, because both keys work perfectly well in isolation. So the
// check compares them and says so.

use std::path::Path;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::domain::CircuitType;
use crate::state::AppState;

const ALL_CIRCUITS: [CircuitType; 5] = [
    CircuitType::EmergencySession,
    CircuitType::AiSession,
    CircuitType::TaxSession,
    CircuitType::IdentitySession,
    CircuitType::WealthSuitability,
];

#[derive(Serialize)]
pub struct HealthResponse {
    /// `ok` or `degraded`. Paired with a 200 or a 503 respectively — an
    /// orchestrator that reads status codes and a human reading JSON must
    /// not be able to reach different conclusions.
    status: &'static str,
    version: &'static str,
    checks: serde_json::Value,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let mut degraded = false;

    // ---------------------------------------------------------------
    // Database
    // ---------------------------------------------------------------
    let started = std::time::Instant::now();
    let db_check = match sqlx::query_scalar!(r#"select count(*) as "count!" from products"#)
        .fetch_one(&state.db)
        .await
    {
        // Counting a real table rather than `select 1`: a pool that connects
        // to a database with no schema in it answers `select 1` cheerfully,
        // and that is precisely the state a mis-pointed DATABASE_URL
        // produces.
        Ok(count) => json!({
            "ok": true,
            "latency_ms": started.elapsed().as_millis() as u64,
            "products_registered": count,
        }),
        Err(e) => {
            degraded = true;
            tracing::warn!(error = ?e, "health: database check failed");
            json!({ "ok": false, "error": "unreachable or schema missing" })
        }
    };

    // ---------------------------------------------------------------
    // Issuer key / JWKS
    // ---------------------------------------------------------------
    let kid = state.signer.kid().to_string();
    let jwks = state.signer.jwks();
    let kid_published = jwks["keys"]
        .as_array()
        .map(|keys| keys.iter().any(|k| k["kid"] == serde_json::Value::String(kid.clone())))
        .unwrap_or(false);
    if !kid_published {
        // A relying party validating a token fetches the JWKS and looks up
        // the token's `kid`. If it isn't there, every token this server
        // issues is unverifiable — and it would issue them happily.
        degraded = true;
    }
    let jwks_check = json!({
        "ok": kid_published,
        "kid": kid,
        "jwks_url": format!("{}/.well-known/jwks.json", state.config.issuer_base_url),
        "keys_published": jwks["keys"].as_array().map(|k| k.len()).unwrap_or(0),
    });

    // ---------------------------------------------------------------
    // Verification keys
    // ---------------------------------------------------------------
    let mut circuits = serde_json::Map::new();
    for circuit in ALL_CIRCUITS {
        let path = Path::new(&state.config.vkeys_dir).join(circuit.as_str()).join("vk");
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                circuits.insert(
                    circuit.as_str().to_string(),
                    json!({ "present": true, "bytes": bytes.len(), "sha256": sha256_hex(&bytes) }),
                );
            }
            Err(_) => {
                degraded = true;
                circuits.insert(circuit.as_str().to_string(), json!({ "present": false }));
            }
        }
    }

    // The published-key comparison. Not fatal on its own — a deployment that
    // ships without the repository present is legitimate — so a missing
    // published key reports `unknown` rather than degrading the instance. A
    // key that is present and *different* is a different matter entirely.
    let published_path = Path::new(&state.config.published_wealth_vkey_path);
    let runtime_path =
        Path::new(&state.config.vkeys_dir).join(CircuitType::WealthSuitability.as_str()).join("vk");
    let published_check =
        match (tokio::fs::read(published_path).await, tokio::fs::read(&runtime_path).await) {
            (Ok(published), Ok(runtime)) => {
                let matches = published == runtime;
                if !matches {
                    degraded = true;
                    tracing::error!(
                        published = %published_path.display(),
                        runtime = %runtime_path.display(),
                        "health: the wealth verification key in use differs from the published one — \
                         proofs accepted by this instance cannot be re-verified against the key an \
                         examiner holds"
                    );
                }
                json!({
                    "status": if matches { "matches" } else { "DIVERGED" },
                    "path": published_path.display().to_string(),
                    "published_sha256": sha256_hex(&published),
                    "runtime_sha256": sha256_hex(&runtime),
                })
            }
            _ => json!({
                "status": "unknown",
                "path": published_path.display().to_string(),
                "note": "no published key available to compare against; independent re-verification \
                         by a regulator is not being checked on this instance",
            }),
        };

    // ---------------------------------------------------------------
    // The prover binary — executed, not inferred
    //
    // Every check above this line reads a file or a config value. None of
    // them touches `bb`, which is the one dependency whose absence stops
    // verification dead: `verify::ensure_vkeys` refuses to boot without it,
    // and every submitted proof shells out to it.
    //
    // That gap was not theoretical. The adversarial suite removes `bb`
    // mid-flight (tests/break_it/test_attack_06_proof_service_removed.py)
    // and the system correctly fails closed on every request — while this
    // endpoint went on reporting `ok`, because the vkey FILES were still on
    // disk. A health check that stays green through the exact outage it
    // exists to detect is worse than no health check: an operator watching
    // it would have had no signal, and Mode B's fallback logic needs a real
    // liveness answer rather than an inferred one.
    //
    // So this runs `bb --version` and reports what actually happened. It is
    // one process spawn on a route that is polled, which is the cost of the
    // answer being true.
    // ---------------------------------------------------------------
    let prover_check = match tokio::process::Command::new(&state.config.bb_bin)
        .arg("--version")
        .kill_on_drop(true)
        .output()
        .await
    {
        Ok(out) if out.status.success() => json!({
            "ok": true,
            "binary": state.config.bb_bin,
            "version": String::from_utf8_lossy(&out.stdout).trim(),
        }),
        Ok(out) => {
            degraded = true;
            tracing::error!(
                bb = %state.config.bb_bin,
                code = ?out.status.code(),
                "health: the prover binary is present but did not run — proof verification \
                 will fail closed on every request"
            );
            json!({
                "ok": false,
                "binary": state.config.bb_bin,
                "reason": "ran but exited non-zero",
                "exit_code": out.status.code(),
            })
        }
        Err(e) => {
            degraded = true;
            tracing::error!(
                bb = %state.config.bb_bin,
                error = %e,
                "health: the prover binary could not be executed — proof verification will \
                 fail closed on every request"
            );
            json!({
                "ok": false,
                "binary": state.config.bb_bin,
                "reason": "could not be executed",
                "error": e.to_string(),
            })
        }
    };

    let status = if degraded { "degraded" } else { "ok" };
    let code = if degraded { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK };

    (
        code,
        Json(HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION"),
            checks: json!({
                "database": db_check,
                "issuer_key": jwks_check,
                "verification_keys": { "ok": !circuits.values().any(|c| c["present"] == json!(false)), "circuits": circuits },
                "published_wealth_vkey": published_check,
                "prover": prover_check,
            }),
        }),
    )
}
