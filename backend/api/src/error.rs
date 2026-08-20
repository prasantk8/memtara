// Central error type: every handler returns Result<T, ApiError>, and this
// is the single place that decides what an internal failure looks like to
// a caller (never leak internals — message text here is what a bank's or
// AI platform's client actually sees).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,

    /// A 404 that says *what* was not found. `NotFound` on its own is fine
    /// when a route has one lookup; `issue-wealth-request` has three (user,
    /// product, vault) and a bare "not found" leaves the caller guessing
    /// which. Same status, more information — and no information a caller
    /// with a valid org key doesn't already have, since it only ever names
    /// something inside that caller's own tenant.
    #[error("not found: {0}")]
    NotFoundDetail(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    /// A 403 that says *why*. `Forbidden` on its own is right when the
    /// caller simply lacks the tenant relationship a route requires;
    /// `issue_wealth_request`'s consent gate needs more, because "forbidden"
    /// alone leaves an integrator unable to tell "you have never granted
    /// consent for this" from "you granted it and then revoked it" from "you
    /// granted consent, but not for this purpose" — three different fixes.
    /// Same reasoning as `NotFoundDetail` beside it, and the same care about
    /// what the detail may say: it names only facts the caller's own org
    /// already has (a consent id or its absence), never another tenant's.
    #[error("forbidden: {0}")]
    ForbiddenDetail(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited")]
    RateLimited,

    /// A 429 that tells the caller when to come back. A rate limit without a
    /// `Retry-After` is an invitation to retry immediately, which is how a
    /// limiter turns a busy client into a hot loop.
    #[error("rate limited: {message}")]
    RateLimitedRetryAfter { retry_after_seconds: u64, message: String },

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Handled before the common path because it is the one error that
        // carries a header, not just a body.
        if let ApiError::RateLimitedRetryAfter { retry_after_seconds, message } = &self {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry_after_seconds.to_string())],
                Json(json!({ "error": message })),
            )
                .into_response();
        }

        let (status, message) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::NotFoundDetail(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::ForbiddenDetail(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            ApiError::RateLimitedRetryAfter { .. } => unreachable!("handled above, with its header"),
            ApiError::Database(err) => {
                tracing::error!(error = ?err, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            ApiError::Other(err) => {
                tracing::error!(error = ?err, "unhandled error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
