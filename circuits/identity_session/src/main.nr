// Identity / Career: prove years of experience meets a minimum and that a
// fixed number of achievement records genuinely exist in the vault, without
// revealing the full record set. Remote-work preference is disclosed
// directly (not a sensitive value worth hiding behind a proof).
//
// Simplification for this phase: exactly MAX_ACHIEVEMENTS records are
// proven per session (no variable-count padding scheme yet); see Phase 3
// notes.

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::attribute_predicates::verify_experience;
use memtara_circuits::merkle_inclusion::verify_merkle_inclusion;
use memtara_circuits::signature_verify::{EddsaPublicKey, EddsaSignature, eddsa_verify};
use memtara_circuits::time_bound::verify_time_window;
use poseidon::poseidon::bn254::{hash_2, hash_8};

global MAX_ACHIEVEMENTS: u32 = 4;

fn main(
    current_time: pub u64,
    start_time: u64,
    expiry_time: pub u64,
    vault_root: pub Field,
    years_experience: u64,
    min_years: pub u64,
    experience_index: Field,
    experience_path: [Field; MERKLE_DEPTH],
    achievement_hashes: [Field; MAX_ACHIEVEMENTS],
    achievement_indices: [Field; MAX_ACHIEVEMENTS],
    achievement_paths: [[Field; MERKLE_DEPTH]; MAX_ACHIEVEMENTS],
    remote_preference: pub bool,
    user_public_key_x: pub Field,
    user_public_key_y: pub Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    signature_s: Field,
    nonce: pub Field,
) {
    // 1. Session window is valid.
    verify_time_window(current_time, start_time, expiry_time);

    // 2. Experience really meets the minimum, and the experience record is
    //    genuinely the one committed in the vault.
    verify_experience(years_experience, min_years);
    verify_merkle_inclusion(vault_root, years_experience as Field, experience_index, experience_path);

    // 3. Each claimed achievement genuinely exists in the vault.
    let mut achievements_commitment: Field = 0;
    for i in 0..MAX_ACHIEVEMENTS {
        verify_merkle_inclusion(
            vault_root,
            achievement_hashes[i],
            achievement_indices[i],
            achievement_paths[i],
        );
        achievements_commitment = hash_2([achievements_commitment, achievement_hashes[i]]);
    }

    // 4. The user authorized exactly this disclosure.
    let remote_field: Field = if remote_preference { 1 } else { 0 };
    let policy_commitment = hash_8([
        current_time as Field,
        start_time as Field,
        expiry_time as Field,
        vault_root,
        min_years as Field,
        achievements_commitment,
        remote_field,
        nonce,
    ]);

    let public_key = EddsaPublicKey { x: user_public_key_x, y: user_public_key_y };
    let signature = EddsaSignature { r8_x: signature_r8_x, r8_y: signature_r8_y, s: signature_s };
    assert(eddsa_verify(public_key, signature, policy_commitment));
}

mod tests {
    use crate::MAX_ACHIEVEMENTS;
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
        years_experience: u64,
        experience_index: Field,
        experience_path: [Field; MERKLE_DEPTH],
        achievement_hashes: [Field; MAX_ACHIEVEMENTS],
        achievement_indices: [Field; MAX_ACHIEVEMENTS],
        achievement_paths: [[Field; MERKLE_DEPTH]; MAX_ACHIEVEMENTS],
    }

    fn build_scenario(years_experience: u64) -> Scenario {
        let mut leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES];
        leaves[0] = years_experience as Field;
        leaves[1] = 111;
        leaves[2] = 222;
        leaves[3] = 333;
        leaves[4] = 444;
        let (root, paths) = build_tree(leaves);

        let mut achievement_hashes: [Field; MAX_ACHIEVEMENTS] = [0; MAX_ACHIEVEMENTS];
        let mut achievement_indices: [Field; MAX_ACHIEVEMENTS] = [0; MAX_ACHIEVEMENTS];
        let mut achievement_paths: [[Field; MERKLE_DEPTH]; MAX_ACHIEVEMENTS] =
            [[0; MERKLE_DEPTH]; MAX_ACHIEVEMENTS];
        for i in 0..MAX_ACHIEVEMENTS {
            achievement_hashes[i] = leaves[i + 1];
            achievement_indices[i] = (i + 1) as Field;
            achievement_paths[i] = paths[i + 1];
        }

        Scenario {
            vault_root: root,
            years_experience,
            experience_index: 0,
            experience_path: paths[0],
            achievement_hashes,
            achievement_indices,
            achievement_paths,
        }
    }

    #[test(should_fail)]
    fn test_rejects_insufficient_experience() {
        let s = build_scenario(1);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.years_experience,
            5,
            s.experience_index,
            s.experience_path,
            s.achievement_hashes,
            s.achievement_indices,
            s.achievement_paths,
            true,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_experience_record_not_in_vault() {
        let s = build_scenario(10);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let wrong_root: Field = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            wrong_root,
            s.years_experience,
            5,
            s.experience_index,
            s.experience_path,
            s.achievement_hashes,
            s.achievement_indices,
            s.achievement_paths,
            true,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_achievement_not_in_vault() {
        let s = build_scenario(10);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;
        let mut tampered = s.achievement_hashes;
        tampered[0] = 0xdead;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.years_experience,
            5,
            s.experience_index,
            s.experience_path,
            tampered,
            s.achievement_indices,
            s.achievement_paths,
            true,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_invalid_signature_after_valid_experience_and_achievements() {
        let s = build_scenario(10);
        let start_time: u64 = 1_723_000_000;
        let expiry_time: u64 = start_time + 3600;
        let current_time: u64 = start_time + 100;

        crate::main(
            current_time,
            start_time,
            expiry_time,
            s.vault_root,
            s.years_experience,
            5,
            s.experience_index,
            s.experience_path,
            s.achievement_hashes,
            s.achievement_indices,
            s.achievement_paths,
            true,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }
}
