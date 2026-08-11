// UAE Pass — UAE's national digital-identity SSO, OIDC-based. We have no
// sandbox credentials this pass, so this module implements the real flow
// shape (authorize redirect -> callback with `code` -> exchange for a
// profile) against a `StubUaePassProvider` that fabricates a deterministic
// profile. Swap in a real OIDC client (authorization-code exchange against
// UAE Pass's token endpoint, id_token signature verification against their
// JWKS) before this handles real traffic — see the DEV STUB note below.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::session_token;

#[derive(Debug, Clone)]
pub struct UaePassProfile {
    /// UAE Pass's stable subject identifier for this person.
    pub sub: String,
    pub full_name: Option<String>,
    pub phone_e164: Option<String>,
}

#[axum::async_trait]
pub trait UaePassProvider: Send + Sync {
    /// Build the URL the client should redirect the user to in order to
    /// start the UAE Pass login. `state` is an opaque CSRF token the
    /// caller should round-trip and verify on callback.
    fn authorize_url(&self, state: &str) -> String;

    /// Exchange an authorization `code` (from the OIDC callback) for the
    /// authenticated user's profile.
    async fn exchange_code(&self, code: &str) -> anyhow::Result<UaePassProfile>;
}

/// DEV STUB — returns a deterministic fake profile for any code, without
/// ever calling out to a real IdP. Replace with a real UAE Pass OIDC
/// client (token endpoint call + id_token verification against UAE Pass's
/// JWKS) before production. Do not point `authorize_base` at real UAE Pass
/// endpoints while this stub backs `exchange_code` — it will silently
/// "authenticate" anyone who completes the redirect.
pub struct StubUaePassProvider {
    pub authorize_base: String,
    pub client_id: String,
    pub redirect_uri: String,
}

#[axum::async_trait]
impl UaePassProvider for StubUaePassProvider {
    fn authorize_url(&self, state: &str) -> String {
        format!(
            "{base}?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&state={state}&scope=urn:uae:digitalid:profile:general",
            base = self.authorize_base,
            client_id = self.client_id,
            redirect_uri = self.redirect_uri,
        )
    }

    async fn exchange_code(&self, code: &str) -> anyhow::Result<UaePassProfile> {
        // Deterministic so the same `code` always maps to the same fake
        // identity in dev/testing.
        Ok(UaePassProfile {
            sub: format!("stub-uae-pass-{code}"),
            full_name: Some("Stub UAE Pass User".to_string()),
            phone_e164: None,
        })
    }
}

#[derive(Serialize)]
struct StartResponse {
    redirect_url: String,
}

async fn start(State(state): State<AppState>) -> ApiResult<Json<StartResponse>> {
    let csrf_state = Uuid::new_v4().to_string();
    // TODO: persist `csrf_state` (short-lived server-side cache or a
    // signed cookie) and verify it round-trips on `/callback` before
    // trusting the exchange. Left as a TODO since there's no real IdP to
    // round-trip against yet with only a stub provider.
    let redirect_url = state.uae_pass_provider.authorize_url(&csrf_state);
    Ok(Json(StartResponse { redirect_url }))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    #[serde(default)]
    #[allow(dead_code)] // wired up once CSRF-state verification (see TODO above) lands
    state: Option<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: DateTime<Utc>,
}

async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Json<SessionResponse>> {
    let profile = state
        .uae_pass_provider
        .exchange_code(&query.code)
        .await
        .map_err(ApiError::Other)?;

    let user_id = sqlx::query_scalar!(
        r#"
        insert into users (uae_pass_sub, display_name, phone_e164)
        values ($1, $2, $3)
        on conflict (uae_pass_sub) do update
            set display_name = coalesce(excluded.display_name, users.display_name)
        returning id
        "#,
        profile.sub,
        profile.full_name,
        profile.phone_e164,
    )
    .fetch_one(&state.db)
    .await?;

    let issued = session_token::issue_session(&state.db, user_id, None, state.config.session_ttl).await?;
    Ok(Json(SessionResponse {
        token: issued.token,
        expires_at: issued.expires_at,
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/uae-pass/start", get(start))
        .route("/auth/uae-pass/callback", get(callback))
}
