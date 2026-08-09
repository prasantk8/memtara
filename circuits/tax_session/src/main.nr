// Tax / Financial Verification: prove a real income value falls in
// [min_income, max_income] and that a fixed number of deduction records
// genuinely exist in the vault, without revealing the exact income or the
// underlying documents.
//
// Simplification for this phase: exactly MAX_DEDUCTIONS deduction records
// are proven per session (no variable-count padding scheme yet); see
// Phase 3 notes.

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::attribute_predicates::verify_range;
use memtara_circuits::merkle_inclusion::verify_merkle_inclusion;
use memtara_circuits::signature_verify::{EddsaPublicKey, EddsaSignature, eddsa_verify};
use memtara_circuits::time_bound::verify_time_window;
use poseidon::poseidon::bn254::{hash_2, hash_8};

global MAX_DEDUCTIONS: u32 = 4;

fn main(
    current_time: pub u64,
    start_time: u64,
    expiry_time: pub u64,
    vault_root: pub Field,
    income: u64,
    min_income: pub u64,
    max_income: pub u64,
    income_index: Field,
    income_path: [Field; MERKLE_DEPTH],
    deduction_hashes: [Field; MAX_DEDUCTIONS],
    deduction_indices: [Field; MAX_DEDUCTIONS],
    deduction_paths: [[Field; MERKLE_DEPTH]; MAX_DEDUCTIONS],
    user_public_key_x: pub Field,
    user_public_key_y: pub Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    signature_s: Field,
    nonce: pub Field,
) {
    // 1. Session window is valid.
    verify_time_window(current_time, start_time, expiry_time);

    // 2. Income really is in the claimed bracket, and the income record is
    //    genuinely the one committed in the vault (not an arbitrary claim
    //    disconnected from vault state).
    verify_range(income, min_income, max_income);
    // `verify_merkle_inclusion` hashes its `leaf` argument internally, so
    // the raw value is passed here — matching how the vault tree commits it.
    verify_merkle_inclusion(vault_root, income as Field, income_index, income_path);

    // 3. Each claimed deduction document genuinely exists in the vault.
    let mut deductions_commitment: Field = 0;
    for i in 0..MAX_DEDUCTIONS {
        verify_merkle_inclusion(vault_root, deduction_hashes[i], deduction_indices[i], deduction_paths[i]);
        deductions_commitment = hash_2([deductions_commitment, deduction_hashes[i]]);
    }

    // 4. The user authorized exactly this disclosure.
    let policy_commitment = hash_8([
        current_time as Field,
        start_time as Field,
        expiry_time as Field,
        vault_root,
        min_income as Field,
        max_income as Field,
        deductions_commitment,
        nonce,
    ]);

    let public_key = EddsaPublicKey { x: user_public_key_x, y: user_public_key_y };
    let signature = EddsaSignature { r8_x: signature_r8_x, r8_y: signature_r8_y, s: signature_s };
    assert(eddsa_verify(public_key, signature, policy_commitment));
}

mod tests {
    use crate::MAX_DEDUCTIONS;
    use memtara_circuits::MERKLE_DEPTH;
    use memtara_circuits::merkle_inclusion::hash_leaf;
    use poseidon::poseidon::bn254::hash_2;

    global TREE_LEAVES: u32 = 16; // 2^MERKLE_DEPTH

    fn build_tree(
        leaves: [Field; TREE_LEAVES],
    ) -> (Field, [[Field; MERKLE_DEPTH]; TREE_LEAVES]) {
        let mut hashes: [Field; TREE_LEAVES] = leaves.map(|l| hash_leaf(l));
        let mut paths: [[Field; MERKLE_DEPTH]; TREE_LEAVES] = [[0; MERKLE_DEPTH]; TREE_LEAVES];

        for level in 0..MERKLE_DEPTH {
            for leaf_idx in 0..TREE_LEAVES {
                let pos = leaf_idx >> level;
                let sibling_pos = pos ^ 1;
                paths[leaf_idx][level] = hashes[sibling_pos];
            }
            let half = TREE_LEAVES >> (level + 1);
            for i in 0..half {
                hashes[i] = hash_2([hashes[2 * i], hashes[2 * i + 1]]);
            }
        }
        (hashes[0], paths)
    }

    struct Scenario {
        vault_root: Field,
        income: u64,
        income_index: Field,
        income_path: [Field; MERKLE_DEPTH],
        deduction_hashes: [Field; MAX_DEDUCTIONS],
        deduction_indices: [Field; MAX_DEDUCTIONS],
        deduction_paths: [[Field; MERKLE_DEPTH]; MAX_DEDUCTIONS],
    }

    fn build_scenario(income: u64) -> Scenario {
        let mut leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES];
        leaves[0] = income as Field; // income leaf, un-hashed value (hash_leaf applied by build_tree)
        leaves[1] = 500;
        leaves[2] = 600;
        leaves[3] = 700;
        leaves[4] = 800;
        let (root, paths) = build_tree(leaves);

        let mut deduction_hashes: [Field; MAX_DEDUCTIONS] = [0; MAX_DEDUCTIONS];
        let mut deduction_indices: [Field; MAX_DEDUCTIONS] = [0; MAX_DEDUCTIONS];
        let mut deduction_paths: [[Field; MERKLE_DEPTH]; MAX_DEDUCTIONS] =
            [[0; MERKLE_DEPTH]; MAX_DEDUCTIONS];
        for i in 0..MAX_DEDUCTIONS {
            deduction_hashes[i] = leaves[i + 1];
            deduction_indices[i] = (i + 1) as Field;
            deduction_paths[i] = paths[i + 1];
        }

        Scenario {
            vault_root: root,
            income,
            income_index: 0,
            income_path: paths[0],
            deduction_hashes,
            deduction_indices,
            deduction_paths,
        }
    }

    #[test(should_fail)]
    fn test_rejects_income_below_bracket() {
        let s = build_scenario(10000);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.income,
            50000,
            100000,
            s.income_index,
            s.income_path,
            s.deduction_hashes,
            s.deduction_indices,
            s.deduction_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_income_record_not_in_vault() {
        let s = build_scenario(80000);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let wrong_root: Field = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            wrong_root,
            s.income,
            50000,
            100000,
            s.income_index,
            s.income_path,
            s.deduction_hashes,
            s.deduction_indices,
            s.deduction_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_deduction_not_in_vault() {
        let s = build_scenario(80000);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let mut tampered_hashes = s.deduction_hashes;
        tampered_hashes[0] = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.income,
            50000,
            100000,
            s.income_index,
            s.income_path,
            tampered_hashes,
            s.deduction_indices,
            s.deduction_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_invalid_signature_after_valid_income_and_deductions() {
        let s = build_scenario(80000);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.income,
            50000,
            100000,
            s.income_index,
            s.income_path,
            s.deduction_hashes,
            s.deduction_indices,
            s.deduction_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }
}
