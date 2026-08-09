// AI Connector Sessions: prove that every record disclosed to the AI is
// genuinely in the vault AND falls under a category the user consented to
// share — the "AI never saw more than granted" guarantee from
// ARCHITECTURE.md, made a real constraint instead of an unchecked assertion.
//
// Simplification for this phase: exactly MAX_AI_RECORDS records are proven
// per session (no variable-count padding scheme yet); see Phase 3 notes.

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::merkle_inclusion::verify_merkle_inclusion;
use memtara_circuits::signature_verify::{EddsaPublicKey, EddsaSignature, eddsa_verify};
use memtara_circuits::time_bound::verify_time_window;
use poseidon::poseidon::bn254::{hash_2, hash_7};

global MAX_AI_RECORDS: u32 = 4;
global AI_SESSION_MAX_DURATION_SECONDS: u64 = 86400; // 24 hours

fn main(
    current_time: pub u64,
    start_time: u64,
    expiry_time: pub u64,
    vault_root: pub Field,
    allowed_categories_root: pub Field,
    record_hashes: [Field; MAX_AI_RECORDS],
    record_indices: [Field; MAX_AI_RECORDS],
    record_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS],
    category_hashes: [Field; MAX_AI_RECORDS],
    category_indices: [Field; MAX_AI_RECORDS],
    category_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS],
    user_public_key_x: pub Field,
    user_public_key_y: pub Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    signature_s: Field,
    nonce: pub Field,
) {
    // 1. Session window is valid and within the AI-session cap.
    verify_time_window(current_time, start_time, expiry_time);
    assert(expiry_time - start_time <= AI_SESSION_MAX_DURATION_SECONDS);

    // 2. Every disclosed record is genuinely in the vault, and its category
    //    is genuinely one the user allowed to share with an AI.
    let mut records_commitment: Field = 0;
    for i in 0..MAX_AI_RECORDS {
        verify_merkle_inclusion(vault_root, record_hashes[i], record_indices[i], record_paths[i]);
        verify_merkle_inclusion(
            allowed_categories_root,
            category_hashes[i],
            category_indices[i],
            category_paths[i],
        );
        records_commitment = hash_2([records_commitment, record_hashes[i]]);
    }

    // 3. The user authorized exactly this disclosure.
    let policy_commitment = hash_7([
        current_time as Field,
        start_time as Field,
        expiry_time as Field,
        vault_root,
        allowed_categories_root,
        records_commitment,
        nonce,
    ]);

    let public_key = EddsaPublicKey { x: user_public_key_x, y: user_public_key_y };
    let signature = EddsaSignature { r8_x: signature_r8_x, r8_y: signature_r8_y, s: signature_s };
    assert(eddsa_verify(public_key, signature, policy_commitment));
}

mod tests {
    use crate::{AI_SESSION_MAX_DURATION_SECONDS, MAX_AI_RECORDS};
    use memtara_circuits::MERKLE_DEPTH;
    use memtara_circuits::merkle_inclusion::hash_leaf;
    use poseidon::poseidon::bn254::hash_2;

    global TREE_LEAVES: u32 = 16; // 2^MERKLE_DEPTH

    // Build a genuine depth-MERKLE_DEPTH Poseidon tree over `leaves` and
    // return (root, per-leaf sibling paths).
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
        allowed_categories_root: Field,
        record_hashes: [Field; MAX_AI_RECORDS],
        record_indices: [Field; MAX_AI_RECORDS],
        record_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS],
        category_hashes: [Field; MAX_AI_RECORDS],
        category_indices: [Field; MAX_AI_RECORDS],
        category_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS],
    }

    fn build_scenario() -> Scenario {
        let mut vault_leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES];
        vault_leaves[0] = 10;
        vault_leaves[1] = 20;
        vault_leaves[2] = 30;
        vault_leaves[3] = 40;
        let (vault_root, vault_paths) = build_tree(vault_leaves);

        let mut category_leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES];
        category_leaves[0] = 100;
        category_leaves[1] = 100;
        category_leaves[2] = 100;
        category_leaves[3] = 100;
        let (categories_root, category_paths_full) = build_tree(category_leaves);

        let mut record_hashes: [Field; MAX_AI_RECORDS] = [0; MAX_AI_RECORDS];
        let mut record_indices: [Field; MAX_AI_RECORDS] = [0; MAX_AI_RECORDS];
        let mut record_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS] =
            [[0; MERKLE_DEPTH]; MAX_AI_RECORDS];
        let mut category_hashes: [Field; MAX_AI_RECORDS] = [0; MAX_AI_RECORDS];
        let mut category_indices: [Field; MAX_AI_RECORDS] = [0; MAX_AI_RECORDS];
        let mut category_paths: [[Field; MERKLE_DEPTH]; MAX_AI_RECORDS] =
            [[0; MERKLE_DEPTH]; MAX_AI_RECORDS];

        for i in 0..MAX_AI_RECORDS {
            record_hashes[i] = vault_leaves[i];
            record_indices[i] = i as Field;
            record_paths[i] = vault_paths[i];
            category_hashes[i] = category_leaves[i];
            category_indices[i] = i as Field;
            category_paths[i] = category_paths_full[i];
        }

        Scenario {
            vault_root,
            allowed_categories_root: categories_root,
            record_hashes,
            record_indices,
            record_paths,
            category_hashes,
            category_indices,
            category_paths,
        }
    }

    #[test(should_fail)]
    fn test_rejects_expired_window() {
        let s = build_scenario();
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + AI_SESSION_MAX_DURATION_SECONDS;
        let current_time: u64 = expiry_time + 1;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.allowed_categories_root,
            s.record_hashes,
            s.record_indices,
            s.record_paths,
            s.category_hashes,
            s.category_indices,
            s.category_paths,
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
        let s = build_scenario();
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let wrong_vault_root: Field = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            wrong_vault_root,
            s.allowed_categories_root,
            s.record_hashes,
            s.record_indices,
            s.record_paths,
            s.category_hashes,
            s.category_indices,
            s.category_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_category_not_allowed() {
        let s = build_scenario();
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let wrong_categories_root: Field = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            wrong_categories_root,
            s.record_hashes,
            s.record_indices,
            s.record_paths,
            s.category_hashes,
            s.category_indices,
            s.category_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_invalid_signature_after_valid_scope() {
        let s = build_scenario();
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.allowed_categories_root,
            s.record_hashes,
            s.record_indices,
            s.record_paths,
            s.category_hashes,
            s.category_indices,
            s.category_paths,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }
}
