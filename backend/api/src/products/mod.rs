// The product registry: a bank's catalogue of structured products and the
// suitability terms each one is sold against.
//
// -------------------------------------------------------------------
// WHAT THIS TABLE IS ACTUALLY DEFENDING AGAINST
// -------------------------------------------------------------------
// `wealth::submit_wealth_proof` already refuses any proof whose public
// inputs disagree with the terms its request was opened with. That closes
// the attack from the *client*: a holder cannot prove suitability against a
// `min_income` of their own choosing, because the server compares every
// submitted threshold to the one on record.
//
// It does nothing about the *advisor*. Whoever holds the org API key could
// open an assessment with `min_income = 0`, `max_concentration_percent = 100`
// and `product_risk_level = 5`, hand the client a request that anyone alive
// would pass, and receive back a signed, cryptographically impeccable
// attestation of suitability. The proof would be real. The assessment would
// be theatre.
//
// The terms therefore have to come from somewhere the person making the
// recommendation does not control at recommendation time. That is what this
// module is: terms are registered against an instrument, in advance, under
// product governance, and every change to them is an audited event. The
// suitability endpoint reads them and refuses to be told them.
//
// -------------------------------------------------------------------
// SCOPING
// -------------------------------------------------------------------
// Every row belongs to exactly one org, and every route here is `OrgAuth`ed
// and filtered by that org. A bank cannot see, amend or assess against
// another bank's catalogue. See migrations/0004_products.sql for why the key
// is `(org_id, product_isin)` rather than the bare ISIN the brief specified.

pub(crate) mod isin;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/products", post(create_product).get(list_products))
        .route(
            "/api/v1/products/:isin",
            get(get_product).patch(amend_product),
        )
}

// ---------------------------------------------------------------------
// Shared row shape
// ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct ProductResponse {
    pub id: Uuid,
    pub org_id: Uuid,
    pub product_isin: String,
    pub product_name: String,
    pub risk_level: i16,
    pub min_income: i64,
    pub min_liquidity: i64,
    pub max_concentration_percent: i16,
    /// Whether this instrument may be assessed against at all.
    /// `issue-wealth-request` returns 409 while this is false.
    pub approved_by_risk_committee: bool,
    /// The ISO 6166 check digit result. Reported rather than enforced — see
    /// `isin::check_digit_ok`. A deployment fed by a real product master
    /// should treat `false` here as a data-quality alarm.
    pub check_digit_valid: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The one place a `products` row becomes a response. Every route below goes
/// through it, so `check_digit_valid` cannot be present on one endpoint and
/// quietly missing from another.
macro_rules! product_response {
    ($row:expr) => {{
        let row = $row;
        ProductResponse {
            check_digit_valid: isin::check_digit_ok(&row.product_isin),
            id: row.id,
            org_id: row.org_id,
            product_isin: row.product_isin,
            product_name: row.product_name,
            risk_level: row.risk_level,
            min_income: row.min_income,
            min_liquidity: row.min_liquidity,
            max_concentration_percent: row.max_concentration_percent,
            approved_by_risk_committee: row.approved_by_risk_committee,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }};
}

/// Normalise an ISIN the way every route here must: trim, upper-case, and
/// reject anything that isn't structurally an ISO 6166 identifier. Done at
/// the boundary so a lookup can never miss because of casing.
pub(crate) fn normalise_isin(raw: &str) -> ApiResult<String> {
    let isin = raw.trim().to_ascii_uppercase();
    if !isin::structure_ok(&isin) {
        return Err(ApiError::BadRequest(format!(
            "product_isin '{isin}' is not a well-formed ISO 6166 identifier \
             (2 letters, 9 alphanumerics, 1 check digit — 12 characters total)"
        )));
    }
    Ok(isin)
}

fn validate_terms(
    risk_level: i16,
    min_income: i64,
    min_liquidity: i64,
    max_concentration_percent: i16,
) -> ApiResult<()> {
    // These bounds are also CHECK constraints on the table and, for the risk
    // scale, an assertion inside the circuit. Checking here as well means a
    // mis-keyed product fails at registration with a readable message rather
    // than at proof time as an unsatisfiable constraint the client's device
    // cannot diagnose.
    if !(1..=5).contains(&risk_level) {
        return Err(ApiError::BadRequest("risk_level must be between 1 and 5".into()));
    }
    if min_income < 0 || min_liquidity < 0 {
        return Err(ApiError::BadRequest("min_income and min_liquidity must not be negative".into()));
    }
    if !(0..=100).contains(&max_concentration_percent) {
        return Err(ApiError::BadRequest("max_concentration_percent must be between 0 and 100".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// POST /api/v1/products
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateProductBody {
    pub product_isin: String,
    pub product_name: String,
    pub risk_level: i16,
    pub min_income: i64,
    pub min_liquidity: i64,
    pub max_concentration_percent: i16,
    /// Defaults to false. A product is not assessable until someone says the
    /// committee approved it, which is the safe default for a field whose
    /// whole purpose is to gate assessment.
    #[serde(default)]
    pub approved_by_risk_committee: bool,
}

async fn create_product(
    OrgAuth(org_id): OrgAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateProductBody>,
) -> ApiResult<(StatusCode, Json<ProductResponse>)> {
    let product_isin = normalise_isin(&body.product_isin)?;
    let product_name = body.product_name.trim().to_string();
    if product_name.is_empty() {
        return Err(ApiError::BadRequest("product_name must not be empty".into()));
    }
    validate_terms(body.risk_level, body.min_income, body.min_liquidity, body.max_concentration_percent)?;

    if !isin::check_digit_ok(&product_isin) {
        tracing::warn!(
            isin = %product_isin,
            "registered product fails its ISO 6166 check digit — accepted, reported as \
             check_digit_valid=false; see products::isin::check_digit_ok"
        );
    }

    let mut tx = state.db.begin().await?;

    // `on conflict do nothing` rather than an upsert. Re-registering an ISIN
    // that already exists is far more likely to be a mistake than an intent
    // to silently rewrite the terms every in-flight assessment quotes, so it
    // is a 409 with a pointer at PATCH, which audits the change.
    let row = sqlx::query!(
        r#"
        insert into products (
            org_id, product_isin, product_name, risk_level,
            min_income, min_liquidity, max_concentration_percent, approved_by_risk_committee
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8)
        on conflict (org_id, product_isin) do nothing
        returning id, org_id, product_isin, product_name, risk_level, min_income, min_liquidity,
                  max_concentration_percent, approved_by_risk_committee, created_at, updated_at
        "#,
        org_id,
        product_isin,
        product_name,
        body.risk_level,
        body.min_income,
        body.min_liquidity,
        body.max_concentration_percent,
        body.approved_by_risk_committee,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "product '{product_isin}' is already registered for this organisation; \
             use PATCH /api/v1/products/{product_isin} to amend its terms (which is audited)"
        ))
    })?;

    // Same transaction as the insert. A product that exists without the
    // governance event that created it is the gap the registry is meant to
    // close, not one it should open.
    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "product_registered",
        Some(row.id),
        serde_json::json!({
            "product_isin": row.product_isin,
            "product_name": row.product_name,
            "risk_level": row.risk_level,
            "min_income": row.min_income,
            "min_liquidity": row.min_liquidity,
            "max_concentration_percent": row.max_concentration_percent,
            "approved_by_risk_committee": row.approved_by_risk_committee,
            "isin_check_digit_valid": isin::check_digit_ok(&row.product_isin),
        }),
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(product_response!(row))))
}

// ---------------------------------------------------------------------
// GET /api/v1/products
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListProductsQuery {
    /// `?approved_only=true` — what an advisor-facing product picker should
    /// ask for, so an unapproved instrument never appears as recommendable.
    #[serde(default)]
    pub approved_only: bool,
}

async fn list_products(
    OrgAuth(org_id): OrgAuth,
    Query(query): Query<ListProductsQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ProductResponse>>> {
    let rows = sqlx::query!(
        r#"
        select id, org_id, product_isin, product_name, risk_level, min_income, min_liquidity,
               max_concentration_percent, approved_by_risk_committee, created_at, updated_at
        from products
        where org_id = $1
          and ($2::boolean is not true or approved_by_risk_committee)
        order by product_isin asc
        "#,
        org_id,
        query.approved_only,
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(|row| product_response!(row)).collect()))
}

// ---------------------------------------------------------------------
// GET /api/v1/products/:isin
// ---------------------------------------------------------------------

async fn get_product(
    OrgAuth(org_id): OrgAuth,
    Path(isin_param): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<ProductResponse>> {
    let product_isin = normalise_isin(&isin_param)?;
    let row = load(&state.db, org_id, &product_isin).await?;
    Ok(Json(product_response!(row)))
}

// ---------------------------------------------------------------------
// PATCH /api/v1/products/:isin
//
// Not in the commissioning brief, which specified `updated_at` but no route
// that could ever change it. Two things make an amendment path necessary
// rather than nice: risk-committee approval is a state transition that
// happens after registration in every real governance process, and a
// product's terms genuinely do get revised. The alternative — deleting and
// re-registering — would lose the very history a CRO needs.
//
// Every field is optional; only what is supplied changes. The event records
// the before and after of each changed field, because "who lowered the
// minimum income, and when" is the first question anyone reviewing a
// mis-sold product asks.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AmendProductBody {
    #[serde(default)]
    pub product_name: Option<String>,
    #[serde(default)]
    pub risk_level: Option<i16>,
    #[serde(default)]
    pub min_income: Option<i64>,
    #[serde(default)]
    pub min_liquidity: Option<i64>,
    #[serde(default)]
    pub max_concentration_percent: Option<i16>,
    #[serde(default)]
    pub approved_by_risk_committee: Option<bool>,
}

async fn amend_product(
    OrgAuth(org_id): OrgAuth,
    Path(isin_param): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<AmendProductBody>,
) -> ApiResult<Json<ProductResponse>> {
    let product_isin = normalise_isin(&isin_param)?;
    let before = load(&state.db, org_id, &product_isin).await?;

    let product_name = match &body.product_name {
        Some(n) if n.trim().is_empty() => {
            return Err(ApiError::BadRequest("product_name must not be empty".into()))
        }
        Some(n) => n.trim().to_string(),
        None => before.product_name.clone(),
    };
    let risk_level = body.risk_level.unwrap_or(before.risk_level);
    let min_income = body.min_income.unwrap_or(before.min_income);
    let min_liquidity = body.min_liquidity.unwrap_or(before.min_liquidity);
    let max_concentration_percent =
        body.max_concentration_percent.unwrap_or(before.max_concentration_percent);
    let approved = body.approved_by_risk_committee.unwrap_or(before.approved_by_risk_committee);

    validate_terms(risk_level, min_income, min_liquidity, max_concentration_percent)?;

    // The diff, computed before the write so the event describes the actual
    // transition rather than restating the new state twice.
    let mut changes = serde_json::Map::new();
    let mut note = |key: &str, from: serde_json::Value, to: serde_json::Value| {
        if from != to {
            changes.insert(key.to_string(), serde_json::json!({ "from": from, "to": to }));
        }
    };
    note("product_name", before.product_name.clone().into(), product_name.clone().into());
    note("risk_level", before.risk_level.into(), risk_level.into());
    note("min_income", before.min_income.into(), min_income.into());
    note("min_liquidity", before.min_liquidity.into(), min_liquidity.into());
    note(
        "max_concentration_percent",
        before.max_concentration_percent.into(),
        max_concentration_percent.into(),
    );
    note("approved_by_risk_committee", before.approved_by_risk_committee.into(), approved.into());

    if changes.is_empty() {
        // No write, and no audit entry. A chain full of "nothing changed"
        // events is noise that makes the entries that do matter harder to
        // find.
        return Ok(Json(product_response!(before)));
    }

    let mut tx = state.db.begin().await?;

    let row = sqlx::query!(
        r#"
        update products
           set product_name = $3, risk_level = $4, min_income = $5, min_liquidity = $6,
               max_concentration_percent = $7, approved_by_risk_committee = $8, updated_at = now()
         where org_id = $1 and product_isin = $2
        returning id, org_id, product_isin, product_name, risk_level, min_income, min_liquidity,
                  max_concentration_percent, approved_by_risk_committee, created_at, updated_at
        "#,
        org_id,
        product_isin,
        product_name,
        risk_level,
        min_income,
        min_liquidity,
        max_concentration_percent,
        approved,
    )
    .fetch_one(&mut *tx)
    .await?;

    crate::audit::record_in_tx(
        &mut tx,
        Some(org_id),
        "product_terms_amended",
        Some(row.id),
        serde_json::json!({
            "product_isin": row.product_isin,
            "changes": changes,
            // Stated explicitly because it is the question this event
            // invites: amending a product does not reach back into
            // assessments already opened against it. `wealth_requests`
            // snapshots the terms at request time, and
            // `submit_wealth_proof` checks against that snapshot.
            "applies_to": "assessments opened after this change only",
        }),
    )
    .await?;

    tx.commit().await?;

    Ok(Json(product_response!(row)))
}

// ---------------------------------------------------------------------
// Lookup shared with `wealth::issue_wealth_request`
// ---------------------------------------------------------------------

/// One product row, as the database has it.
pub(crate) struct ProductRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub product_isin: String,
    pub product_name: String,
    pub risk_level: i16,
    pub min_income: i64,
    pub min_liquidity: i64,
    pub max_concentration_percent: i16,
    pub approved_by_risk_committee: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fetch one of `org_id`'s products by ISIN, or 404.
///
/// Scoped by `org_id` in the WHERE clause rather than fetched-then-checked:
/// a query that can only ever return this tenant's rows cannot leak the
/// existence of another tenant's product through a timing or error-shape
/// difference.
pub(crate) async fn load(db: &sqlx::PgPool, org_id: Uuid, product_isin: &str) -> ApiResult<ProductRow> {
    sqlx::query_as!(
        ProductRow,
        r#"
        select id, org_id, product_isin, product_name, risk_level, min_income, min_liquidity,
               max_concentration_percent, approved_by_risk_committee, created_at, updated_at
        from products
        where org_id = $1 and product_isin = $2
        "#,
        org_id,
        product_isin,
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| {
        ApiError::NotFound
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_upper_cases_and_trims() {
        assert_eq!(normalise_isin("  xs1234567890 ").unwrap(), "XS1234567890");
    }

    #[test]
    fn normalise_rejects_a_non_isin() {
        // The brief's demo identifier, which is 14 characters. Registering it
        // would make every downstream lookup fail with a 404 that looks like
        // a missing product rather than a malformed one.
        let err = normalise_isin("TEST1234567890").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn terms_validation_matches_the_circuits_own_bounds() {
        // The 1-5 risk scale and the 0-100 percentage are asserted inside
        // circuits/wealth_suitability. If these drift apart, a product that
        // registers cleanly produces proofs that cannot be generated at all —
        // the worst failure mode available, because it surfaces on the
        // holder's device with no diagnostic.
        assert!(validate_terms(1, 0, 0, 0).is_ok());
        assert!(validate_terms(5, i64::MAX, i64::MAX, 100).is_ok());
        assert!(validate_terms(0, 0, 0, 0).is_err(), "risk level 0 is off-scale");
        assert!(validate_terms(6, 0, 0, 0).is_err(), "risk level 6 is off-scale");
        assert!(validate_terms(3, -1, 0, 0).is_err());
        assert!(validate_terms(3, 0, -1, 0).is_err());
        assert!(validate_terms(3, 0, 0, 101).is_err());
        assert!(validate_terms(3, 0, 0, -1).is_err());
    }
}
