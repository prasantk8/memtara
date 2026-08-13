mod auth;
mod config;
mod db;
mod disclosure;
mod domain;
mod error;
mod state;
mod vault_sync;
mod verify;

// Each engineer adds their module here as it's built:
// mod orgs;
// mod audit;

use auth::otp::{LoggingOtpProvider, OtpProvider};
use auth::uae_pass::{StubUaePassProvider, UaePassProvider};
use auth::webauthn::WebauthnCeremonies;
use axum::routing::get;
use axum::Router;
use state::AppState;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "memtara_api=debug,tower_http=debug".into()),
        )
        .init();

    let config = config::Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // Generate any missing per-circuit verification keys (see
    // verify/mod.rs for why this happens once at boot rather than lazily).
    // Fails fast: if `bb` isn't installed/on PATH, or circuits/target/ is
    // missing compiled bytecode, the server should not come up half-working.
    verify::ensure_vkeys(&config).await?;

    let webauthn = auth::webauthn::build(&config)?;
    let otp_provider: Arc<dyn OtpProvider> = Arc::new(LoggingOtpProvider);
    let uae_pass_provider: Arc<dyn UaePassProvider> = Arc::new(StubUaePassProvider {
        authorize_base: config.uae_pass_authorize_url.clone(),
        client_id: config.uae_pass_client_id.clone(),
        redirect_uri: config.uae_pass_redirect_uri.clone(),
    });

    let state = AppState {
        db: pool,
        config: Arc::new(config.clone()),
        webauthn: Arc::new(webauthn),
        webauthn_ceremonies: Arc::new(WebauthnCeremonies::default()),
        otp_provider,
        uae_pass_provider,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(auth::router())
        .merge(vault_sync::router())
        .merge(disclosure::router())
        .merge(verify::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("memtara-api listening on {}", config.bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}
