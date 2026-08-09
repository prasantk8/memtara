// Attribute predicate circuits for selective disclosure.
//
// Numeric predicates (age, income, experience) take the real witness value
// and compare it with native integer comparisons. Noir's `Field` type does
// not support ordering operators directly, so any value that needs a range
// check must be typed as an integer (u64 here), not `Field`.

use poseidon::poseidon::bn254::hash_1;

/// Verify equality between two field elements (e.g. blood type commitments).
pub fn verify_equality(a: Field, b: Field) {
    assert(a == b);
}

/// Range proof: `min <= value <= max`, over the real witness value.
pub fn verify_range(value: u64, min: u64, max: u64) {
    assert(value >= min);
    assert(value <= max);
}

/// Set membership: `value` must equal one of `allowed_values`.
pub fn verify_set_membership<let N: u32>(value: Field, allowed_values: [Field; N]) {
    let mut found = false;
    for i in 0..N {
        found |= value == allowed_values[i];
    }
    assert(found);
}

/// Verify a medication commitment is one of the medications the record
/// actually claims to have, by set membership over the disclosed hashes.
pub fn verify_medication<let N: u32>(medication_hash: Field, disclosed_meds: [Field; N]) {
    verify_set_membership(medication_hash, disclosed_meds);
}

/// Verify a blood type commitment matches the required type.
/// `blood_type` is encoded as a small integer (A=0, B=1, AB=2, O=3, ...).
pub fn verify_blood_type(blood_type_hash: Field, required_type: u8) {
    let expected = hash_1([required_type as Field]);
    assert(blood_type_hash == expected);
}

/// Verify age falls within [min_age, max_age] using the real witness age,
/// not a hardcoded stand-in.
pub fn verify_age_range(age: u64, min_age: u64, max_age: u64) {
    verify_range(age, min_age, max_age);
}

/// Verify a claimed income falls within [min_required, max_allowed].
/// `max_allowed` is optional (no upper bound when `Option::none()`).
pub fn verify_income_range(income: u64, min_required: u64, max_allowed: Option<u64>) {
    assert(income >= min_required);
    if max_allowed.is_some() {
        assert(income <= max_allowed.unwrap());
    }
}

/// Verify years of experience meets a minimum, over the real witness value.
pub fn verify_experience(years_experience: u64, min_years: u64) {
    assert(years_experience >= min_years);
}

#[test]
fn test_blood_type_verification() {
    let required_type: u8 = 1; // Type A
    let hash = hash_1([required_type as Field]);
    verify_blood_type(hash, required_type);
}

#[test(should_fail)]
fn test_blood_type_rejects_mismatch() {
    let hash = hash_1([1 as Field]);
    verify_blood_type(hash, 2);
}

#[test]
fn test_medication_verification() {
    let disclosed: [Field; 3] = [100, 200, 300];
    verify_medication(disclosed[0], disclosed);
}

#[test(should_fail)]
fn test_medication_rejects_unlisted() {
    let disclosed: [Field; 3] = [100, 200, 300];
    verify_medication(999, disclosed);
}

#[test]
fn test_range_verification() {
    verify_range(50, 0, 100);
}

#[test(should_fail)]
fn test_range_rejects_out_of_bounds() {
    verify_range(150, 0, 100);
}

#[test]
fn test_income_range_no_upper_bound() {
    verify_income_range(80000, 50000, Option::none());
}

#[test(should_fail)]
fn test_income_range_rejects_below_minimum() {
    verify_income_range(10000, 50000, Option::none());
}

#[test]
fn test_experience_verification() {
    verify_experience(5, 3);
}

#[test(should_fail)]
fn test_experience_rejects_insufficient_years() {
    verify_experience(1, 3);
}
