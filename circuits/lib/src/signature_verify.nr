// EdDSA signature verification over Baby Jubjub, native to the BN254 proving
// curve used by this project's backend. True Ed25519 (Curve25519) or BLS
// (BLS12-381) verification would require expensive non-native field
// emulation inside the circuit, so vault records that will be proven use a
// Baby Jubjub keypair instead. See ARCHITECTURE.md for the accepted
// deviation from "Ed25519" in the original design notes.
//
// Implementation follows Noir's own reference eddsa/poseidon benchmark
// (noir-lang/noir test_programs/benchmarks/bench_eddsa_poseidon), which
// verifies: S * B8 = R8 + H(R8, A, m) * A8

use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
use poseidon::poseidon::PoseidonHasher;
use std::default::Default;
use std::hash::Hasher;

// Baby Jubjub subgroup order.
global SUBORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

// Generator * 8 (cofactor-cleared base point).
global BASE8_X: Field =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
global BASE8_Y: Field =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;

pub struct EddsaSignature {
    pub r8_x: Field,
    pub r8_y: Field,
    pub s: Field,
}

pub struct EddsaPublicKey {
    pub x: Field,
    pub y: Field,
}

/// Verify an EdDSA/Baby Jubjub signature over `message`.
pub fn eddsa_verify(public_key: EddsaPublicKey, signature: EddsaSignature, message: Field) -> bool {
    let pub_key = BabyJubJub::new(public_key.x, public_key.y);
    let signature_r8 = BabyJubJub::new(signature.r8_x, signature.r8_y);

    // Ensure S is in the valid scalar range.
    assert(signature.s.lt(SUBORDER));

    // h = H(R8, A, msg)
    let mut hasher = PoseidonHasher::default();
    hasher.write(signature.r8_x);
    hasher.write(signature.r8_y);
    hasher.write(public_key.x);
    hasher.write(public_key.y);
    hasher.write(message);
    let hash: Field = hasher.finish();

    // A8 = 8 * A (also ensures A8 is in the prime-order subgroup).
    let pub_key_mul_8 = pub_key.dbl().dbl().dbl();
    assert(!pub_key_mul_8.is_zero());

    // right = R8 + h * A8
    let right = signature_r8 + pub_key_mul_8.mul(ScalarField::<64>::from(hash));
    // left = S * B8
    let base8: BabyJubJub = Curve { x: BASE8_X, y: BASE8_Y };
    let left = base8.mul(ScalarField::<63>::from(signature.s));

    left == right
}

/// Verify that a vault record commitment was signed by the user's key.
pub fn verify_vault_item_signature(
    record_hash: Field,
    signature: EddsaSignature,
    public_key: EddsaPublicKey,
) -> bool {
    eddsa_verify(public_key, signature, record_hash)
}

/// Multi-signature verification: at least `required_signers` of the given
/// signatures over `message` must be valid.
pub fn verify_multi_signature<let N: u32>(
    message: Field,
    signatures: [EddsaSignature; N],
    public_keys: [EddsaPublicKey; N],
    required_signers: u32,
) {
    let mut valid_count: u32 = 0;
    for i in 0..N {
        if eddsa_verify(public_keys[i], signatures[i], message) {
            valid_count += 1;
        }
    }
    assert(valid_count >= required_signers);
}

// Constructing a genuine valid EdDSA signature requires scalar arithmetic
// modulo the Baby Jubjub subgroup order (a different, smaller prime than
// the circuit's native BN254 field), which is done off-circuit by a signer
// (see vault/ for the Rust side). The primitive itself is covered by
// noir-lang/noir-edwards and noir-lang/poseidon's own test suites. What we
// test here is that this wrapper genuinely rejects malformed input rather
// than rubber-stamping it, since `BabyJubJub::new` constrains its argument
// to be a valid curve point.
#[test(should_fail)]
fn test_verify_vault_item_signature_rejects_off_curve_point() {
    let record_hash = 42;
    let sig = EddsaSignature { r8_x: 1, r8_y: 1, s: 1 };
    let pk = EddsaPublicKey { x: 1, y: 1 }; // (1, 1) is not on the Baby Jubjub curve
    let _ = verify_vault_item_signature(record_hash, sig, pk);
}

#[test(should_fail)]
fn test_multi_signature_rejects_all_invalid() {
    let message = 42;
    let sig = EddsaSignature { r8_x: 1, r8_y: 1, s: 1 };
    let pk = EddsaPublicKey { x: 1, y: 1 };
    verify_multi_signature(message, [sig], [pk], 1);
}
