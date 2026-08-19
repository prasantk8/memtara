// Env-driven config. Kept to one small struct read once at boot rather than
// scattered `std::env::var` calls through the codebase — every downstream
// role builds against `Config`, not the environment directly.

use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub session_ttl: Duration,
    pub otp_ttl: Duration,
    pub otp_max_attempts: u32,
    /// Relying-party origin(s) accepted for WebAuthn ceremonies, e.g.
    /// "https://app.memtara.ai". Must match the frontend's origin exactly.
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    pub webauthn_rp_name: String,
    /// UAE Pass (national digital identity SSO) OIDC client config. We have
    /// no sandbox credentials yet — these default to placeholder values
    /// and are only consumed by `StubUaePassProvider`. Wire real values in
    /// before switching to a real OIDC client (see auth/uae_pass.rs).
    pub uae_pass_client_id: String,
    pub uae_pass_client_secret: String,
    pub uae_pass_redirect_uri: String,
    pub uae_pass_authorize_url: String,
    /// Path (or bare name, resolved via PATH) to the `bb` (Barretenberg)
    /// CLI binary used by `verify/` to check proofs and generate
    /// verification keys. See verify/mod.rs for the exact invocations.
    pub bb_bin: String,
    /// Directory containing each circuit's compiled ACIR bytecode
    /// (`<circuit_type>.json`), produced by `nargo compile` under
    /// `circuits/`. Defaults to `circuits/target` relative to this crate's
    /// manifest dir, which is correct regardless of the process's cwd.
    pub circuits_target_dir: String,
    /// Directory `verify/` generates and caches per-circuit verification
    /// keys in (a build artifact of `circuits/`, not source — gitignored,
    /// regenerated on boot if missing). Defaults to `vkeys` under this
    /// crate's manifest dir.
    pub vkeys_dir: String,
    /// Public base URL of this deployment. Stamped into every proof token's
    /// `iss` claim and used to build the JWKS URL a relying party is told
    /// to fetch. Must match what clients actually reach, or a relying party
    /// validating `iss` will reject otherwise-good tokens.
    ///
    /// Note what is NOT here: the Ed25519 private key. `Config` derives
    /// `Debug` and is cloned into `AppState`, so a secret held on it would
    /// eventually reach a log line. The key is loaded straight from the
    /// environment into `crypto::signer::IssuerKey`, which has no `Debug`.
    pub issuer_base_url: String,
    /// Lifetime of an issued proof token. 300s (5 minutes) by default —
    /// short enough that the tokens' non-revocability is bounded, long
    /// enough to survive a slow relying-party round trip. See the §6(f)
    /// caveat in docs/REGULATORY_MATRIX.md before raising it.
    pub proof_token_ttl_seconds: i64,
    /// The verification key published alongside the source, which an
    /// examiner would use to re-verify a suitability proof independently of
    /// this server. `GET /health` compares it against the key actually in
    /// use and reports the instance degraded if they differ — see
    /// ops/health.rs for why a silent divergence is the dangerous case.
    pub published_wealth_vkey_path: String,
    /// Proof submissions permitted per user per window on
    /// `/api/v1/submit-wealth-proof`. Bounds the only genuinely expensive
    /// operation this server performs. See ops/rate_limit.rs for what this
    /// does and does not defend.
    pub proof_rate_limit: u32,
    pub proof_rate_limit_window: Duration,
    // NOTE: the audit checkpointer's interval and event bound
    // (MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS /
    // MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS) deliberately do NOT live here,
    // despite this struct's "one place for env" rule. They live in
    // `audit::checkpoint::CheckpointPolicy::from_env`, read once at boot in
    // the same style. The reason is mechanical rather than aesthetic: this
    // struct is constructed by exhaustive literal in other modules' tests,
    // so every field added here is a compile break in a file its owner did
    // not touch. A setting used by exactly one module does not justify that.
    // See the header of audit/checkpoint.rs.
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into()),
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            session_ttl: Duration::from_secs(
                env::var("SESSION_TTL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30 * 24 * 3600), // 30 days
            ),
            otp_ttl: Duration::from_secs(
                env::var("OTP_TTL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300), // 5 minutes
            ),
            otp_max_attempts: env::var("OTP_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into()),
            webauthn_rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".into()),
            webauthn_rp_name: env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Memtara".into()),
            uae_pass_client_id: env::var("UAE_PASS_CLIENT_ID")
                .unwrap_or_else(|_| "dev-stub-client-id".into()),
            uae_pass_client_secret: env::var("UAE_PASS_CLIENT_SECRET")
                .unwrap_or_else(|_| "dev-stub-client-secret".into()),
            uae_pass_redirect_uri: env::var("UAE_PASS_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:5173/auth/uae-pass/callback".into()),
            uae_pass_authorize_url: env::var("UAE_PASS_AUTHORIZE_URL")
                .unwrap_or_else(|_| "https://stg-id.uaepass.ae/idshub/authorize".into()),
            bb_bin: env::var("BB_BIN").unwrap_or_else(|_| "bb".into()),
            circuits_target_dir: env::var("CIRCUITS_TARGET_DIR")
                .unwrap_or_else(|_| format!("{}/../../circuits/target", env!("CARGO_MANIFEST_DIR"))),
            vkeys_dir: env::var("VKEYS_DIR")
                .unwrap_or_else(|_| format!("{}/vkeys", env!("CARGO_MANIFEST_DIR"))),
            issuer_base_url: env::var("MEMTARA_ISSUER_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            proof_token_ttl_seconds: env::var("MEMTARA_PROOF_TOKEN_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            published_wealth_vkey_path: env::var("MEMTARA_PUBLISHED_WEALTH_VKEY").unwrap_or_else(|_| {
                format!("{}/../../circuits/wealth_suitability/vkey/vk", env!("CARGO_MANIFEST_DIR"))
            }),
            proof_rate_limit: env::var("MEMTARA_PROOF_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            proof_rate_limit_window: Duration::from_secs(
                env::var("MEMTARA_PROOF_RATE_LIMIT_WINDOW_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60),
            ),
        })
    }
}
