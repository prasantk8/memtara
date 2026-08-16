// Shared application state, injected into every handler via axum's State
// extractor. Extend this struct as new modules need shared resources —
// don't build parallel ad-hoc state.

use crate::auth::otp::OtpProvider;
use crate::auth::uae_pass::UaePassProvider;
use crate::auth::webauthn::WebauthnCeremonies;
use crate::config::Config;
use crate::crypto::signer::IssuerKey;
use crate::ops::metrics::Metrics;
use crate::ops::rate_limit::RateLimiter;
use sqlx::PgPool;
use std::sync::Arc;
use webauthn_rs::prelude::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    /// Configured WebAuthn relying-party instance (rp_id/origin/name from
    /// `Config`). Cheap to clone (just an Arc), safe to share across
    /// handlers.
    pub webauthn: Arc<Webauthn>,
    /// In-flight passkey registration/authentication ceremony state,
    /// process-local. See auth/webauthn.rs for why and its scaling caveat.
    pub webauthn_ceremonies: Arc<WebauthnCeremonies>,
    /// OTP delivery backend (SMS/WhatsApp). `LoggingOtpProvider` in dev,
    /// a real provider in production.
    pub otp_provider: Arc<dyn OtpProvider>,
    /// UAE Pass OIDC client. `StubUaePassProvider` until real sandbox
    /// credentials exist.
    pub uae_pass_provider: Arc<dyn UaePassProvider>,
    /// Ed25519 issuer key backing `/.well-known/jwks.json` and every proof
    /// token. Loaded once at boot so the published JWKS and the key actually
    /// signing tokens can never disagree.
    pub signer: Arc<IssuerKey>,
    /// Process-local counters behind `GET /metrics`. `Arc` rather than
    /// cloned: every replica of this struct must increment the same numbers.
    pub metrics: Arc<Metrics>,
    /// Bounds `bb verify` invocations per user. Process-local by design —
    /// see ops/rate_limit.rs for what that does and does not cover.
    pub rate_limiter: Arc<RateLimiter>,
}
