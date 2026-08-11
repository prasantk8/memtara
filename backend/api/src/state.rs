// Shared application state, injected into every handler via axum's State
// extractor. Extend this struct as new modules need shared resources —
// don't build parallel ad-hoc state.

use crate::auth::otp::OtpProvider;
use crate::auth::uae_pass::UaePassProvider;
use crate::auth::webauthn::WebauthnCeremonies;
use crate::config::Config;
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
}
