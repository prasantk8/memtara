// Emergency Share: time-bound selective disclosure of blood type, key
// medications, and allergies, with proof the disclosed data is exactly what
// the vault committed to and that the user authorized this exact disclosure.

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::merkle_inclusion::verify_merkle_inclusion;
use memtara_circuits::signature_verify::{EddsaPublicKey, EddsaSignature, eddsa_verify};
use memtara_circuits::time_bound::verify_emergency_window;
use poseidon::poseidon::bn254::{hash_4, hash_7};

global EMERGENCY_MAX_DURATION_SECONDS: u64 = 3600;

fn main(
    current_time: pub u64,
    creation_time: u64,
    vault_root: pub Field,
    record_index: Field,
    record_hash_path: [Field; MERKLE_DEPTH],
    blood_type_hash: pub Field,
    key_meds_hash: pub Field,
    allergies_commitment: pub Field,
    user_public_key_x: pub Field,
    user_public_key_y: pub Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    signature_s: Field,
    nonce: pub Field,
) {
    // 1. Session is within the (short) emergency window.
    verify_emergency_window(current_time, creation_time, EMERGENCY_MAX_DURATION_SECONDS);

    // 2. The disclosed blood type / meds / allergies are exactly the record
    //    committed in the vault at `record_index` — not independent,
    //    unconnected claims.
    let record_leaf = hash_4([
        blood_type_hash,
        key_meds_hash,
        allergies_commitment,
        creation_time as Field,
    ]);
    verify_merkle_inclusion(vault_root, record_leaf, record_index, record_hash_path);

    // 3. The user authorized disclosing exactly this policy (bound to the
    //    disclosed data, the vault state, and a nonce for the verifier's
    //    off-circuit replay registry).
    let policy_commitment = hash_7([
        current_time as Field,
        creation_time as Field,
        vault_root,
        blood_type_hash,
        key_meds_hash,
        allergies_commitment,
        nonce,
    ]);

    let public_key = EddsaPublicKey { x: user_public_key_x, y: user_public_key_y };
    let signature = EddsaSignature { r8_x: signature_r8_x, r8_y: signature_r8_y, s: signature_s };
    assert(eddsa_verify(public_key, signature, policy_commitment));
}

mod tests {
    use crate::EMERGENCY_MAX_DURATION_SECONDS;
    use memtara_circuits::merkle_inclusion::{compute_merkle_root, hash_leaf};
    use poseidon::poseidon::bn254::hash_4;

    // Fixed depth-4 authentication path; contents don't need to be "real"
    // sibling hashes for a test — only self-consistent with the root we
    // derive from them below.
    fn dummy_path() -> [Field; 4] {
        [1, 2, 3, 4]
    }

    fn build_record(
        blood_type_hash: Field,
        key_meds_hash: Field,
        allergies_commitment: Field,
        creation_time: u64,
        index: Field,
    ) -> (Field, [Field; 4]) {
        let leaf = hash_4([blood_type_hash, key_meds_hash, allergies_commitment, creation_time as Field]);
        let path = dummy_path();
        let root = compute_merkle_root(hash_leaf(leaf), index, path);
        (root, path)
    }

    #[test(should_fail)]
    fn test_rejects_expired_window() {
        let creation_time: u64 = 1_723_000_000;
        let current_time: u64 = creation_time + EMERGENCY_MAX_DURATION_SECONDS + 1;
        let (root, path) = build_record(10, 20, 30, creation_time, 0);

        crate::main(
            current_time,
            creation_time,
            root,
            0,
            path,
            10,
            20,
            30,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_record_not_in_vault() {
        let creation_time: u64 = 1_723_000_000;
        let current_time: u64 = creation_time + 100;
        let (_correct_root, path) = build_record(10, 20, 30, creation_time, 0);
        let wrong_root: Field = 0xdead;

        crate::main(
            current_time,
            creation_time,
            wrong_root,
            0,
            path,
            10,
            20,
            30,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    // A correct time window and correct Merkle inclusion still must not pass
    // without a valid EdDSA signature over the policy commitment.
    #[test(should_fail)]
    fn test_rejects_invalid_signature_after_valid_window_and_inclusion() {
        let creation_time: u64 = 1_723_000_000;
        let current_time: u64 = creation_time + 100;
        let (root, path) = build_record(10, 20, 30, creation_time, 0);

        crate::main(
            current_time,
            creation_time,
            root,
            0,
            path,
            10,
            20,
            30,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }
}
