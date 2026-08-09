// Merkle tree inclusion proofs over Poseidon-BN254, for the category-based
// vault tree described in ARCHITECTURE.md.

use poseidon::poseidon::bn254::{hash_1, hash_2};

/// Poseidon commitment for a single leaf value.
pub fn hash_leaf(leaf: Field) -> Field {
    hash_1([leaf])
}

/// Recompute the Merkle root for `leaf_hash` at `index` given its authentication path.
/// `index` is decomposed into bits (LSB first) to pick left/right ordering at each level,
/// matching the convention used when the tree was built.
pub fn compute_merkle_root<let DEPTH: u32>(
    leaf_hash: Field,
    index: Field,
    hash_path: [Field; DEPTH],
) -> Field {
    let index_bits: [bool; DEPTH] = index.to_le_bits();
    let mut current = leaf_hash;
    for i in 0..DEPTH {
        let (left, right) = if index_bits[i] {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = hash_2([left, right]);
    }
    current
}

/// Verify that `leaf` is included in the tree committed to by `root`.
pub fn verify_merkle_inclusion<let DEPTH: u32>(
    root: Field,
    leaf: Field,
    index: Field,
    hash_path: [Field; DEPTH],
) {
    let computed = compute_merkle_root(hash_leaf(leaf), index, hash_path);
    assert(computed == root);
}

fn build_test_tree() -> (Field, Field, [Field; 2], Field, Field, Field, Field) {
    let leaf0 = 10;
    let leaf1 = 20;
    let leaf2 = 30;
    let leaf3 = 40;

    let h0 = hash_leaf(leaf0);
    let h1 = hash_leaf(leaf1);
    let h2 = hash_leaf(leaf2);
    let h3 = hash_leaf(leaf3);

    let node_left = hash_2([h0, h1]);
    let node_right = hash_2([h2, h3]);
    let root = hash_2([node_left, node_right]);

    (root, leaf0, [h1, node_right], leaf1, leaf2, leaf3, h0)
}

#[test]
fn test_merkle_inclusion_leaf0() {
    let (root, leaf0, path, _, _, _, _) = build_test_tree();
    verify_merkle_inclusion(root, leaf0, 0, path);
}

#[test]
fn test_merkle_inclusion_leaf1() {
    let (root, _, _, leaf1, _, _, h0) = build_test_tree();
    let node_right = hash_2([hash_leaf(30), hash_leaf(40)]);
    verify_merkle_inclusion(root, leaf1, 1, [h0, node_right]);
}

#[test(should_fail)]
fn test_merkle_inclusion_rejects_wrong_leaf() {
    let (root, _, path, _, _, _, _) = build_test_tree();
    // A different leaf value must not verify against the same path/root.
    verify_merkle_inclusion(root, 999, 0, path);
}

#[test(should_fail)]
fn test_merkle_inclusion_rejects_tampered_path() {
    let (root, leaf0, path, _, _, _, _) = build_test_tree();
    let mut tampered = path;
    tampered[0] = tampered[0] + 1;
    verify_merkle_inclusion(root, leaf0, 0, tampered);
}
