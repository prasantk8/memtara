// Operational surface: health, metrics, rate limiting.
//
// Kept out of the feature modules because these three are the only things in
// the codebase whose audience is an operator rather than a bank, and because
// a health check that lives inside the module it checks tends to end up
// asserting that its own code compiled.

pub mod health;
pub mod metrics;
pub mod rate_limit;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::health))
        .route("/metrics", get(metrics_handler))
}

/// `GET /metrics` — Prometheus exposition.
///
/// Unauthenticated, like `/healthz` and the JWKS endpoint, because that is
/// how scrapers work and putting an API key in a Prometheus config is worse
/// for everyone. The safety of that decision rests on the labels carrying
/// nothing tenant-identifying — see the header of `ops::metrics` for the
/// argument, and the test that enforces it.
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    // Read at scrape time rather than tracked in the process, so the gauge is
    // right after a restart and identical across replicas. A failed count
    // reports -1 rather than 0: a silent zero would look like an empty
    // registry, which is a real and alarming state, and confusing the two
    // would send someone looking for the wrong problem.
    let registry_size = sqlx::query_scalar!(r#"select count(*) as "count!" from products"#)
        .fetch_one(&state.db)
        .await
        .unwrap_or(-1);

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(registry_size),
    )
}
