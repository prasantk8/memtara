// Structured-product suitability predicates (DFSA COB 3.1).
//
// These deliberately RETURN a bool rather than `assert`-ing, unlike
// `attribute_predicates`. The distinction matters and is not stylistic:
//
//   An asserting circuit can only ever produce a proof for the "yes" case.
//   That is the right shape for `verify_range` (a tax bracket disclosure is
//   pointless if the answer is no), but it is the wrong shape for
//   suitability. A bank that *declines* to recommend a product needs
//   evidence of the assessment just as much as one that proceeds — DFSA COB
//   3.1's obligation is to *have assessed*, not to have approved. A circuit
//   that is unsatisfiable on "not suitable" can produce no such evidence:
//   the absence of a proof is indistinguishable from never having run the
//   assessment at all.
//
// So the four checks below are computed as booleans, ANDed, and surfaced as
// the circuit's public output. The relying party reads that output; it does
// not infer suitability from the mere existence of a proof.
//
// The structural constraints (risk scale bounds, percentage bounds) DO
// assert — those are well-formedness of the request, not the answer to it.

/// Concentration limit: after this purchase the client's existing holdings
/// must not exceed `max_concentration_percent` of their total investable
/// position.
///
/// Stated in the product brief as
/// `existing / (liquid + existing) * 100 <= max_pct`. That form cannot be
/// evaluated as written in a circuit — Noir's `/` on `Field` is
/// multiplication by the modular inverse, not integer division, so
/// `existing / total` would produce a field element bearing no relation to a
/// ratio, and the comparison would be meaningless (and `Field` has no
/// ordering anyway). Cross-multiplied it becomes exact integer arithmetic
/// with no division and no rounding:
///
///     existing * 100 <= max_pct * (liquid + existing)
///
/// which is equivalent for all non-negative values and additionally
/// well-defined when the denominator is zero: a client with no liquid assets
/// and no holdings trivially has 0% concentration, and `0 <= 0` says so
/// rather than dividing by zero.
///
/// Widened to u128 for the multiplication only. Noir constrains integer
/// arithmetic against overflow, so a u64 product would make an *honest*
/// proof over a large-but-legitimate portfolio unprovable rather than
/// unsound — a liveness bug, not a soundness one, but still a bug.
pub fn concentration_within_limit(
    existing_holdings_value: u64,
    liquid_assets: u64,
    max_concentration_percent: u64,
) -> bool {
    let existing = existing_holdings_value as u128;
    let total = (liquid_assets as u128) + existing;
    existing * 100 <= (max_concentration_percent as u128) * total
}

/// The full DFSA COB 3.1 suitability assessment, as one boolean.
///
/// Asserts only the well-formedness of the scale: a risk tolerance or
/// product risk level outside 1-5, or a concentration cap above 100%, is a
/// malformed request rather than an unsuitable client, and must not be
/// silently reported as "not suitable" — that would let a mis-configured
/// product masquerade as a client who failed the assessment.
pub fn assess_suitability(
    income: u64,
    liquid_assets: u64,
    risk_tolerance: u64,
    existing_holdings_value: u64,
    min_income: u64,
    min_liquidity: u64,
    max_concentration_percent: u64,
    product_risk_level: u64,
) -> bool {
    assert(risk_tolerance >= 1);
    assert(risk_tolerance <= 5);
    assert(product_risk_level >= 1);
    assert(product_risk_level <= 5);
    assert(max_concentration_percent <= 100);

    let income_ok = income >= min_income;
    let liquidity_ok = liquid_assets >= min_liquidity;
    let risk_ok = risk_tolerance >= product_risk_level;
    let concentration_ok =
        concentration_within_limit(existing_holdings_value, liquid_assets, max_concentration_percent);

    income_ok & liquidity_ok & risk_ok & concentration_ok
}

#[test]
fn test_concentration_exactly_at_limit_passes() {
    // 300k existing against 700k liquid = 30% of a 1M total. The boundary
    // is inclusive ("<=" in the rule), so this must pass, not fail.
    assert(concentration_within_limit(300_000, 700_000, 30));
}

#[test]
fn test_concentration_one_unit_over_limit_fails() {
    // 300_001 / 1_000_001 = 30.0000...% — over by a rounding hair. Integer
    // cross-multiplication catches it; floating-point would not.
    assert(!concentration_within_limit(300_001, 700_000, 30));
}

#[test]
fn test_concentration_zero_denominator_is_zero_percent() {
    // No assets at all: 0% concentration, not a division by zero.
    assert(concentration_within_limit(0, 0, 30));
}

#[test]
fn test_concentration_large_portfolio_does_not_overflow() {
    // 5bn fils-scale values: the u64 product would be fine here, but this
    // pins the widening so a future edit back to u64 fails loudly.
    assert(concentration_within_limit(1_000_000_000_000, 9_000_000_000_000, 30));
    assert(!concentration_within_limit(4_000_000_000_000, 9_000_000_000_000, 30));
}

#[test]
fn test_suitable_client_passes_all_four() {
    // income 750k >= 500k, liquid 2m >= 1m, tolerance 4 >= risk 3,
    // 200k/(2m+200k) = 9.09% <= 30%.
    assert(assess_suitability(750_000, 2_000_000, 4, 200_000, 500_000, 1_000_000, 30, 3));
}

#[test]
fn test_income_below_threshold_is_not_suitable() {
    assert(!assess_suitability(400_000, 2_000_000, 4, 200_000, 500_000, 1_000_000, 30, 3));
}

#[test]
fn test_illiquid_client_is_not_suitable() {
    assert(!assess_suitability(750_000, 900_000, 4, 200_000, 500_000, 1_000_000, 30, 3));
}

#[test]
fn test_risk_tolerance_below_product_is_not_suitable() {
    // The one check that protects the client from the bank rather than the
    // bank from the client.
    assert(!assess_suitability(750_000, 2_000_000, 2, 200_000, 500_000, 1_000_000, 30, 3));
}

#[test]
fn test_overconcentrated_client_is_not_suitable() {
    // 5m existing against 2m liquid = 71%.
    assert(!assess_suitability(750_000, 2_000_000, 4, 5_000_000, 500_000, 1_000_000, 30, 3));
}

#[test(should_fail)]
fn test_risk_tolerance_outside_scale_is_rejected_not_reported_unsuitable() {
    let _ = assess_suitability(750_000, 2_000_000, 9, 200_000, 500_000, 1_000_000, 30, 3);
}

#[test(should_fail)]
fn test_zero_risk_tolerance_is_rejected() {
    let _ = assess_suitability(750_000, 2_000_000, 0, 200_000, 500_000, 1_000_000, 30, 3);
}

#[test(should_fail)]
fn test_product_risk_level_outside_scale_is_rejected() {
    let _ = assess_suitability(750_000, 2_000_000, 4, 200_000, 500_000, 1_000_000, 30, 7);
}

#[test(should_fail)]
fn test_concentration_cap_above_100_percent_is_rejected() {
    // A "cap" above 100% is not a lenient policy, it is a broken one — and
    // silently accepting it would make the check unfalsifiable.
    let _ = assess_suitability(750_000, 2_000_000, 4, 200_000, 500_000, 1_000_000, 150, 3);
}
