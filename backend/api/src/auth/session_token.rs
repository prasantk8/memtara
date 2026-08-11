// Opaque, revocable bearer session tokens.
//
// Deliberately NOT JWTs: the product needs instant, server-side revocation
// (e.g. a live "expires in 14:59" countdown and a user-triggered "sign out
// everywhere" must take effect immediately, not wait out a JWT's `exp`).
// The client holds a random 32-byte token; only SHA-256(token) is ever
// persisted (base64url-encoded, stored in `sessions.token_hash`), so a
// leaked database dump does not hand out live credentials.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

/// Number of random bytes in a session token before base64url-encoding.
const TOKEN_BYTES: usize = 32;

/// A freshly issued session, ready to hand back to the client. `token` is
/// shown to the client exactly once; the server never stores it in
/// recoverable form, only its hash.
pub struct IssuedSession {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a client-presented token for lookup/storage. Plain SHA-256 (not
/// argon2): the input already carries 256 bits of CSPRNG entropy, so there
/// is no offline brute-force risk to slow down — argon2 is reserved for
/// low-entropy secrets like OTP codes, not this.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Issue a new session for `user_id` and persist its hash. `device_id` is
/// opaque to auth (assigned by whichever caller wants to name/revoke a
/// single device later); pass `None` if the caller doesn't track one.
pub async fn issue_session(
    db: &PgPool,
    user_id: Uuid,
    device_id: Option<Uuid>,
    ttl: Duration,
) -> Result<IssuedSession, ApiError> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    sqlx::query!(
        r#"
        insert into sessions (user_id, device_id, token_hash, expires_at)
        values ($1, $2, $3, $4)
        "#,
        user_id,
        device_id,
        token_hash,
        expires_at,
    )
    .execute(db)
    .await?;

    Ok(IssuedSession { token, expires_at })
}

/// Revoke a session by its client-presented token. Idempotent: revoking an
/// already-revoked or unknown token is not an error.
pub async fn revoke_session(db: &PgPool, token: &str) -> Result<(), ApiError> {
    let token_hash = hash_token(token);
    sqlx::query!(
        "update sessions set revoked_at = now() where token_hash = $1 and revoked_at is null",
        token_hash,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Axum extractor that authenticates a request from its
/// `Authorization: Bearer <token>` header, resolving it to the owning
/// user's id. Downstream modules (vault sync, disclosure) should depend on
/// this rather than re-deriving session lookup logic:
///
/// ```ignore
/// async fn handler(AuthUser(user_id): AuthUser, State(state): State<AppState>) -> ApiResult<...> { ... }
/// ```
pub struct AuthUser(pub Uuid);

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let token = header.strip_prefix("Bearer ").ok_or(ApiError::Unauthorized)?;
        let token_hash = hash_token(token);

        let row = sqlx::query!(
            r#"
            select user_id
            from sessions
            where token_hash = $1
              and revoked_at is null
              and expires_at > now()
            "#,
            token_hash,
        )
        .fetch_optional(&state.db)
        .await?;

        row.map(|r| AuthUser(r.user_id)).ok_or(ApiError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_round_trips_and_is_deterministic() {
        let token = generate_token();
        let h1 = hash_token(&token);
        let h2 = hash_token(&token);
        assert_eq!(h1, h2, "hashing the same token twice must be stable");
        assert_ne!(token, h1, "the stored hash must never equal the raw token");
    }

    #[test]
    fn different_tokens_hash_differently() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b, "two random tokens should not collide");
        assert_ne!(hash_token(&a), hash_token(&b));
    }

    #[test]
    fn generated_token_is_url_safe_without_padding() {
        let token = generate_token();
        assert!(!token.contains('='), "no padding chars");
        assert!(!token.contains('+'), "no standard-base64 chars");
        assert!(!token.contains('/'), "no standard-base64 chars");
        // 32 bytes base64url-no-pad encodes to 43 chars.
        assert_eq!(token.len(), 43);
    }
}
