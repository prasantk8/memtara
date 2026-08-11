// Passkey register/login via webauthn-rs 0.5, against `webauthn_credentials`.
//
// Storage note: the schema's `public_key bytea` column holds the full
// serialized `webauthn_rs::prelude::Passkey` (JSON), not just a raw COSE
// key. webauthn-rs needs the whole `Passkey` (COSE key, counter, backup
// eligibility/state flags) to verify a subsequent authentication — a bare
// public key isn't enough — and `Passkey` is designed by the crate to be
// exactly this: an opaque, serialisable blob you round-trip through
// storage. `sign_count` stays as its own column too so it's cheaply
// inspectable without deserialising, but the serialized `Passkey` is the
// source of truth used for verification.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{find_or_create_user_by_phone, session_token};

/// Build the relying-party `Webauthn` instance from config. Called once at
/// startup in `main.rs` and stored in `AppState` behind an `Arc`.
pub fn build(config: &Config) -> anyhow::Result<Webauthn> {
    let rp_origin = Url::parse(&config.webauthn_rp_origin)?;
    let builder =
        WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)?.rp_name(&config.webauthn_rp_name);
    Ok(builder.build()?)
}

struct RegCeremony {
    user_id: Uuid,
    device_name: Option<String>,
    state: PasskeyRegistration,
}

struct AuthCeremony {
    user_id: Uuid,
    state: PasskeyAuthentication,
}

/// In-flight WebAuthn ceremony state, keyed by a random ceremony id handed
/// to the client between `/start` and `/finish`.
///
/// TODO(scale): this is process-local memory. Fine for a single instance,
/// but a ceremony started on one replica and finished on another (behind a
/// load balancer, mid rolling-deploy, or once we run >1 replica) will fail
/// with "unknown or expired ceremony". Move this to shared storage (Redis,
/// keyed the same way, with a TTL matching the WebAuthn ceremony timeout)
/// before horizontal scaling — don't build that out further than this
/// comment until it's actually needed.
#[derive(Default)]
pub struct WebauthnCeremonies {
    registrations: DashMap<Uuid, RegCeremony>,
    authentications: DashMap<Uuid, AuthCeremony>,
}

#[derive(Deserialize)]
struct RegisterStartBody {
    phone_e164: String,
    device_name: Option<String>,
}

#[derive(Serialize)]
struct RegisterStartResponse {
    ceremony_id: Uuid,
    challenge: CreationChallengeResponse,
}

async fn register_start(
    State(state): State<AppState>,
    Json(body): Json<RegisterStartBody>,
) -> ApiResult<Json<RegisterStartResponse>> {
    if body.phone_e164.trim().is_empty() {
        return Err(ApiError::BadRequest("phone_e164 is required".into()));
    }

    let user_id = find_or_create_user_by_phone(&state.db, &body.phone_e164).await?;

    // Exclude credential IDs already registered to this user so the same
    // authenticator can't be enrolled twice.
    let existing: Vec<Vec<u8>> = sqlx::query_scalar!(
        "select credential_id from webauthn_credentials where user_id = $1",
        user_id,
    )
    .fetch_all(&state.db)
    .await?;
    let exclude: Vec<CredentialID> = existing.into_iter().map(CredentialID::from).collect();
    let exclude = if exclude.is_empty() { None } else { Some(exclude) };

    let (challenge, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &body.phone_e164, &body.phone_e164, exclude)
        .map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;

    let ceremony_id = Uuid::new_v4();
    state.webauthn_ceremonies.registrations.insert(
        ceremony_id,
        RegCeremony {
            user_id,
            device_name: body.device_name,
            state: reg_state,
        },
    );

    Ok(Json(RegisterStartResponse { ceremony_id, challenge }))
}

#[derive(Deserialize)]
struct RegisterFinishBody {
    ceremony_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

async fn register_finish(
    State(state): State<AppState>,
    Json(body): Json<RegisterFinishBody>,
) -> ApiResult<Json<SessionResponse>> {
    let (_, ceremony) = state
        .webauthn_ceremonies
        .registrations
        .remove(&body.ceremony_id)
        .ok_or_else(|| ApiError::BadRequest("unknown or expired ceremony".into()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&body.credential, &ceremony.state)
        .map_err(|e| ApiError::BadRequest(format!("passkey registration failed: {e}")))?;

    let credential_id = passkey.cred_id().as_ref().to_vec();
    let public_key =
        serde_json::to_vec(&passkey).map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;

    let insert = sqlx::query!(
        r#"
        insert into webauthn_credentials (user_id, credential_id, public_key, sign_count, device_name)
        values ($1, $2, $3, 0, $4)
        "#,
        ceremony.user_id,
        credential_id,
        public_key,
        ceremony.device_name,
    )
    .execute(&state.db)
    .await;

    match insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return Err(ApiError::Conflict("credential already registered".into()));
        }
        Err(e) => return Err(e.into()),
    }

    let issued =
        session_token::issue_session(&state.db, ceremony.user_id, None, state.config.session_ttl)
            .await?;
    Ok(Json(SessionResponse {
        token: issued.token,
        expires_at: issued.expires_at,
    }))
}

#[derive(Deserialize)]
struct LoginStartBody {
    phone_e164: String,
}

#[derive(Serialize)]
struct LoginStartResponse {
    ceremony_id: Uuid,
    challenge: RequestChallengeResponse,
}

async fn login_start(
    State(state): State<AppState>,
    Json(body): Json<LoginStartBody>,
) -> ApiResult<Json<LoginStartResponse>> {
    let user = sqlx::query!("select id from users where phone_e164 = $1", body.phone_e164)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;

    let rows = sqlx::query!(
        "select public_key from webauthn_credentials where user_id = $1",
        user.id,
    )
    .fetch_all(&state.db)
    .await?;

    // No registered passkeys — client should fall back to OTP.
    if rows.is_empty() {
        return Err(ApiError::NotFound);
    }

    let passkeys: Vec<Passkey> = rows
        .iter()
        .map(|r| serde_json::from_slice::<Passkey>(&r.public_key))
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;

    let (challenge, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;

    let ceremony_id = Uuid::new_v4();
    state.webauthn_ceremonies.authentications.insert(
        ceremony_id,
        AuthCeremony { user_id: user.id, state: auth_state },
    );

    Ok(Json(LoginStartResponse { ceremony_id, challenge }))
}

#[derive(Deserialize)]
struct LoginFinishBody {
    ceremony_id: Uuid,
    credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<AppState>,
    Json(body): Json<LoginFinishBody>,
) -> ApiResult<Json<SessionResponse>> {
    let (_, ceremony) = state
        .webauthn_ceremonies
        .authentications
        .remove(&body.ceremony_id)
        .ok_or_else(|| ApiError::BadRequest("unknown or expired ceremony".into()))?;

    let result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &ceremony.state)
        .map_err(|_| ApiError::Unauthorized)?;

    let credential_id = result.cred_id().as_ref().to_vec();

    if result.needs_update() {
        // Re-fetch, patch the stored Passkey in place (counter/backup
        // state), and write both the serialized blob and the denormalized
        // sign_count column back.
        let row = sqlx::query!(
            "select public_key from webauthn_credentials where credential_id = $1",
            credential_id,
        )
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::Unauthorized)?;

        let mut passkey: Passkey =
            serde_json::from_slice(&row.public_key).map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;
        passkey.update_credential(&result);
        let public_key =
            serde_json::to_vec(&passkey).map_err(|e| ApiError::Other(anyhow::anyhow!(e)))?;

        sqlx::query!(
            r#"
            update webauthn_credentials
            set public_key = $2, sign_count = $3, last_used_at = now()
            where credential_id = $1
            "#,
            credential_id,
            public_key,
            result.counter() as i64,
        )
        .execute(&state.db)
        .await?;
    } else {
        sqlx::query!(
            "update webauthn_credentials set last_used_at = now() where credential_id = $1",
            credential_id,
        )
        .execute(&state.db)
        .await?;
    }

    let issued =
        session_token::issue_session(&state.db, ceremony.user_id, None, state.config.session_ttl)
            .await?;
    Ok(Json(SessionResponse {
        token: issued.token,
        expires_at: issued.expires_at,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/passkey/register/start", post(register_start))
        .route("/auth/passkey/register/finish", post(register_finish))
        .route("/auth/passkey/login/start", post(login_start))
        .route("/auth/passkey/login/finish", post(login_finish))
}
