// WhatsApp/SMS OTP fallback login — used when a user has no registered
// passkey yet, or is on a device/browser that can't do WebAuthn.

use argon2::password_hash::rand_core::OsRng as ArgonOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::domain::OtpChannel;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{find_or_create_user_by_phone, session_token};

/// Delivers an OTP code to a user over SMS or WhatsApp. Swap the
/// `Arc<dyn OtpProvider>` in `AppState` for a real provider (Twilio, etc.)
/// before production; see `LoggingOtpProvider` below for the dev default.
#[axum::async_trait]
pub trait OtpProvider: Send + Sync {
    async fn send(&self, phone_e164: &str, code: &str, channel: OtpChannel) -> anyhow::Result<()>;
}

/// DEV-ONLY provider: logs the OTP instead of delivering it. Never wire
/// this up in a real deployment — anyone with log/log-aggregator access
/// could read every user's login code.
pub struct LoggingOtpProvider;

#[axum::async_trait]
impl OtpProvider for LoggingOtpProvider {
    async fn send(&self, phone_e164: &str, code: &str, channel: OtpChannel) -> anyhow::Result<()> {
        tracing::info!(
            phone = %phone_e164,
            channel = channel.as_str(),
            code = %code,
            "DEV ONLY: OTP logged instead of delivered — replace LoggingOtpProvider before production"
        );
        Ok(())
    }
}

/// 6-digit numeric code, zero-padded.
fn generate_code() -> String {
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{n:06}")
}

fn hash_code(code: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let hash = Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .map_err(|e| ApiError::Other(anyhow::anyhow!("otp hash failure: {e}")))?;
    Ok(hash.to_string())
}

fn verify_code(code: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(code.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

#[derive(Deserialize)]
struct OtpRequestBody {
    phone_e164: String,
    channel: OtpChannel,
}

#[derive(Serialize)]
struct OtpRequestResponse {
    expires_at: DateTime<Utc>,
}

async fn request_otp(
    State(state): State<AppState>,
    Json(body): Json<OtpRequestBody>,
) -> ApiResult<Json<OtpRequestResponse>> {
    if body.phone_e164.trim().is_empty() {
        return Err(ApiError::BadRequest("phone_e164 is required".into()));
    }

    let user_id = find_or_create_user_by_phone(&state.db, &body.phone_e164).await?;
    let code = generate_code();
    let code_hash = hash_code(&code)?;
    let expires_at = Utc::now() + chrono::Duration::seconds(state.config.otp_ttl.as_secs() as i64);

    sqlx::query!(
        r#"
        insert into otp_codes (user_id, code_hash, channel, expires_at)
        values ($1, $2, $3, $4)
        "#,
        user_id,
        code_hash,
        body.channel.as_str(),
        expires_at,
    )
    .execute(&state.db)
    .await?;

    state
        .otp_provider
        .send(&body.phone_e164, &code, body.channel)
        .await
        .map_err(ApiError::Other)?;

    Ok(Json(OtpRequestResponse { expires_at }))
}

#[derive(Deserialize)]
struct OtpVerifyBody {
    phone_e164: String,
    code: String,
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: DateTime<Utc>,
}

async fn verify_otp(
    State(state): State<AppState>,
    Json(body): Json<OtpVerifyBody>,
) -> ApiResult<Json<SessionResponse>> {
    let mut tx = state.db.begin().await?;

    let user = sqlx::query!("select id from users where phone_e164 = $1", body.phone_e164)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    // Most recent OTP issued for this user. Locked for the duration of this
    // transaction so two concurrent verify attempts against the same code
    // can't both slip past the attempts cap.
    let otp = sqlx::query!(
        r#"
        select id, code_hash, attempts, expires_at, consumed_at
        from otp_codes
        where user_id = $1
        order by created_at desc
        limit 1
        for update
        "#,
        user.id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    if otp.consumed_at.is_some() {
        return Err(ApiError::Unauthorized);
    }
    if otp.expires_at < Utc::now() {
        return Err(ApiError::Unauthorized);
    }
    // Once attempts have reached the cap on a prior call, reject outright —
    // even if this call's code happens to be correct — per the configured
    // `otp_max_attempts` policy.
    if otp.attempts >= state.config.otp_max_attempts as i32 {
        return Err(ApiError::RateLimited);
    }

    // Record this attempt regardless of outcome so a brute-force loop is
    // bounded even across retries with different codes.
    sqlx::query!("update otp_codes set attempts = attempts + 1 where id = $1", otp.id)
        .execute(&mut *tx)
        .await?;

    if !verify_code(&body.code, &otp.code_hash) {
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    }

    sqlx::query!("update otp_codes set consumed_at = now() where id = $1", otp.id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let issued = session_token::issue_session(&state.db, user.id, None, state.config.session_ttl).await?;
    Ok(Json(SessionResponse {
        token: issued.token,
        expires_at: issued.expires_at,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/otp/request", post(request_otp))
        .route("/auth/otp/verify", post(verify_otp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_code_hash_round_trips() {
        let code = generate_code();
        assert_eq!(code.len(), 6, "otp codes are always 6 digits, zero-padded");
        let hash = hash_code(&code).expect("hashing should succeed");
        assert!(verify_code(&code, &hash), "correct code must verify");
        assert!(!verify_code("000000", &hash) || code == "000000", "wrong code must not verify");
    }

    #[test]
    fn otp_hash_rejects_wrong_code() {
        let hash = hash_code("123456").unwrap();
        assert!(!verify_code("654321", &hash));
    }
}
