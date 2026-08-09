// Minimal SHA-256 Merkle tree for category-based vault commitments.
//
// TODO(Phase 3): this must be switched to Poseidon-BN254 to match what the
// Noir circuits under circuits/lib/src/merkle_inclusion.nr actually verify.
// SHA-256 works fine as an internal vault commitment today, but a proof
// generated against a SHA-256 root will not verify against these circuits
// until both sides use the same hash over the same field.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct MerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        let base = if leaves.is_empty() { vec![[0u8; 32]] } else { leaves };
        let mut layers = vec![base];

        while layers.last().unwrap().len() > 1 {
            let current = layers.last().unwrap();
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair.get(1).unwrap_or(&pair[0]));
                next.push(hasher.finalize().into());
            }
            layers.push(next);
        }

        Self { layers }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = [7u8; 32];
        let tree = MerkleTree::new(vec![leaf]);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn different_leaf_sets_produce_different_roots() {
        let tree_a = MerkleTree::new(vec![[1u8; 32], [2u8; 32]]);
        let tree_b = MerkleTree::new(vec![[1u8; 32], [3u8; 32]]);
        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn odd_number_of_leaves_does_not_panic() {
        let tree = MerkleTree::new(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_ne!(tree.root(), [0u8; 32]);
    }
}
