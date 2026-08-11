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
        })
    }
}
