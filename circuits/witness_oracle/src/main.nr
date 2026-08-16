// Witness oracle: the hashes a client-side prover needs, computed by the
// same library the circuits use.
//
// This is NOT a proving circuit. Nothing verifies a proof of it and no
// verification key is generated for it. It exists to be run with
// `nargo execute`, which prints its public output — a deterministic way for
// an off-device prover to obtain Poseidon-BN254 values that are correct
// *by construction* rather than by a second implementation happening to
// agree.
//
// The alternative was to reimplement Poseidon-BN254 (round constants, MDS
// matrix, the sponge) plus the Merkle convention in Python. That is a few
// hundred lines of transcribed constants whose only failure mode is silent:
// a wrong constant produces a plausible-looking hash, an honest witness, and
// a proof that fails to verify with no indication of which of the two
// implementations is wrong. Shelling out to the circuits' own Poseidon
// removes that entire class of bug — and if this file and `lib` ever
// disagree, they disagree because the library changed, which is exactly when
// you want to be told.
//
// A production client does the same thing in-process via noir_wasm. This is
// the CLI-shaped equivalent for a repo that has no mobile app yet.
//
// Usage (see clients/wealth_client.py, which drives it):
//
//   op = 0  Merkle tree over 16 leaves.
//           inputs = the 16 raw leaf values (hashed internally by
//           `hash_leaf`, matching `verify_merkle_inclusion`).
//           out[0]      = vault root
//           out[1..5]   = authentication path for leaf 0
//           out[5..9]   = leaf 1
//           out[9..13]  = leaf 2
//           out[13..17] = leaf 3
//
//   op = 1  Suitability policy commitment, exactly as
//           circuits/wealth_suitability/src/main.nr composes it.
//           inputs[0..8] = current_time, start_time, expiry_time, vault_root,
//                          product_ref, min_income, min_liquidity,
//                          max_concentration_percent
//           inputs[8]    = product_risk_level
//           inputs[9]    = nonce
//           out[0]       = the commitment the user's key must sign
//
//   op = 2  The EdDSA challenge hash, exactly as
//           `signature_verify::eddsa_verify` computes it.
//           inputs[0..5] = r8_x, r8_y, public_key_x, public_key_y, message
//           out[0]       = h

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::merkle_inclusion::hash_leaf;
use poseidon::poseidon::PoseidonHasher;
use poseidon::poseidon::bn254::{hash_2, hash_8};
use std::default::Default;
use std::hash::Hasher;

global TREE_LEAVES: u32 = 16; // 2^MERKLE_DEPTH
global OUT_LEN: u32 = 17;
global IN_LEN: u32 = 16;

// Only the first four leaves get authentication paths: those are the slots
// the wealth vault category uses (income, liquid assets, risk tolerance,
// existing holdings). Widening this is a one-line change if another circuit
// needs more.
global PATHS_RETURNED: u32 = 4;

fn main(op: u32, inputs: [Field; IN_LEN]) -> pub [Field; OUT_LEN] {
    let mut out: [Field; OUT_LEN] = [0; OUT_LEN];

    if op == 0 {
        let (root, paths) = build_tree(inputs);
        out[0] = root;
        for leaf in 0..PATHS_RETURNED {
            for level in 0..MERKLE_DEPTH {
                out[1 + leaf * MERKLE_DEPTH + level] = paths[leaf][level];
            }
        }
    } else if op == 1 {
        let terms = hash_8([
            inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], inputs[6], inputs[7],
        ]);
        out[0] = hash_2([hash_2([terms, inputs[8]]), inputs[9]]);
    } else {
        assert(op == 2, "unknown oracle op");
        let mut hasher = PoseidonHasher::default();
        hasher.write(inputs[0]);
        hasher.write(inputs[1]);
        hasher.write(inputs[2]);
        hasher.write(inputs[3]);
        hasher.write(inputs[4]);
        out[0] = hasher.finish();
    }

    out
}

/// Byte-for-byte the tree construction used in every circuit's own test
/// module: leaves are `hash_leaf`'d, then paired bottom-up with `hash_2`,
/// and the sibling at each level is recorded as the authentication path.
fn build_tree(leaves: [Field; TREE_LEAVES]) -> (Field, [[Field; MERKLE_DEPTH]; TREE_LEAVES]) {
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

mod tests {
    use memtara_circuits::MERKLE_DEPTH;
    use memtara_circuits::merkle_inclusion::compute_merkle_root;
    use memtara_circuits::merkle_inclusion::hash_leaf;

    /// The oracle's whole reason to exist is that a client can rebuild the
    /// root from what it returns. If `build_tree`'s path convention and
    /// `compute_merkle_root`'s index-bit convention ever diverge, every
    /// honest client would produce unverifiable proofs — so check the two
    /// against each other directly.
    #[test]
    fn returned_paths_reconstruct_the_returned_root() {
        let mut leaves: [Field; 16] = [0; 16];
        leaves[0] = 750_000;
        leaves[1] = 2_000_000;
        leaves[2] = 4;
        leaves[3] = 200_000;

        let out = crate::main(0, leaves);
        let root = out[0];

        for leaf in 0..4 {
            let mut path: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
            for level in 0..MERKLE_DEPTH {
                path[level] = out[1 + leaf * MERKLE_DEPTH + level];
            }
            let recomputed = compute_merkle_root(hash_leaf(leaves[leaf]), leaf as Field, path);
            assert(recomputed == root);
        }
    }

    #[test]
    fn different_leaves_give_different_roots() {
        let mut a: [Field; 16] = [0; 16];
        a[0] = 750_000;
        let mut b: [Field; 16] = [0; 16];
        b[0] = 750_001;
        assert(crate::main(0, a)[0] != crate::main(0, b)[0]);
    }

    #[test]
    fn the_commitment_binds_every_term_it_is_given() {
        // A commitment that ignored one of its inputs would let a client
        // re-present a signature across different product terms.
        let mut base: [Field; 16] = [0; 16];
        for i in 0..10 {
            base[i] = (i + 1) as Field;
        }
        let reference = crate::main(1, base)[0];

        for i in 0..10 {
            let mut altered = base;
            altered[i] = 0xbeef;
            assert(crate::main(1, altered)[0] != reference);
        }
    }

    #[test(should_fail)]
    fn unknown_op_is_rejected() {
        let _ = crate::main(9, [0; 16]);
    }
}
