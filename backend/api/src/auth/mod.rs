// Auth: passkey (WebAuthn) as the primary path, WhatsApp/SMS OTP as
// fallback, UAE Pass as a national-identity SSO option. All three issue
// the same kind of opaque, revocable session token (session_token.rs) —
// downstream modules only need to care about `AuthUser`, not which of the
// three flows produced the session.

pub mod otp;
pub mod session_token;
pub mod uae_pass;
pub mod webauthn;

pub use session_token::AuthUser;

use axum::Router;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiResult;
use crate::state::AppState;

/// Merge every auth route under its full path (each submodule's `router()`
/// already declares full `/auth/...` paths, so this is a flat merge, not a
/// nest).
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(webauthn::router())
        .merge(otp::router())
        .merge(uae_pass::router())
}

/// Shared identity resolution: every phone-based auth entry point (OTP
/// request, passkey registration) needs to land on the same user row for a
/// given phone number. Atomic via `ON CONFLICT` so two concurrent
/// first-time logins for the same number can't race into two different
/// user rows or trip the `users.phone_e164` unique constraint.
pub(crate) async fn find_or_create_user_by_phone(db: &PgPool, phone_e164: &str) -> ApiResult<Uuid> {
    let id = sqlx::query_scalar!(
        r#"
        insert into users (phone_e164)
        values ($1)
        on conflict (phone_e164) do update set phone_e164 = excluded.phone_e164
        returning id
        "#,
        phone_e164,
    )
    .fetch_one(db)
    .await?;
    Ok(id)
}
