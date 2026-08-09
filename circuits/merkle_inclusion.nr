// Merkle Tree Inclusion Proof Circuit for Memtara ZKP System
// This circuit proves that a record exists in the category-based sparse Merkle tree

use std::hash::poseidon;

/// Verifies a Merkle inclusion proof
/// 
/// Arguments:
/// - root: The root of the Merkle tree (public)
/// - leaf: The hash of the leaf being proved (private witness)
/// - index: The index position in the tree (private witness)
/// - path: The authentication path from leaf to root (private witness)
pub fn verify_merkle_inclusion(
    root: Field,
    leaf: Field,
    index: u32,
    path: Vec<Field>,
    max_depth: usize
) -> bool {
    // Verify the number of path elements matches tree depth
    assert(path.len() == max_depth);
    
    // Start with the leaf hash and traverse up the tree
    let mut current_hash = poseidon(leaf);
    let mut current_index = index;
    
    for i in 0..max_depth {
        let path_element = path[i];
        
        // Determine if this is a left or right child based on bit at position i
        let is_left = (current_index % 2) == 0;
        
        if is_left {
            // Current node is left child, path element is right sibling
            current_hash = poseidon([current_hash, path_element]);
        } else {
            // Current node is right child, path element is left sibling
            current_hash = poseidon([path_element, current_hash]);
        }
        
        // Move up one level
        current_index = current_index / 2;
    }
    
    // The final hash should match the root
    assert(current_hash == root);
    
    true
}

/// Sparse Merkle tree inclusion with default values for non-existent nodes
pub fn verify_sparse_merkle_inclusion(
    root: Field,
    leaf: Field,
    index: u32,
    path: Vec<Field>,
    max_depth: usize,
    default_hash: Field  // Hash of the default/convention value for empty slots
) -> bool {
    assert(path.len() == max_depth);
    
    let mut current_hash = poseidon(leaf);
    let mut current_index = index;
    
    for i in 0..max_depth {
        let path_element = if path[i] == default_hash || path[i] == 0 {
            // Empty slot, use default hash
            default_hash
        } else {
            path[i]
        };
        
        let is_left = (current_index % 2) == 0;
        
        if is_left {
            current_hash = poseidon([current_hash, path_element]);
        } else {
            current_hash = poseidon([path_element, current_hash]);
        }
        
        current_index = current_index / 2;
    }
    
    assert(current_hash == root);
    true
}

#[test]
fn test_merkle_inclusion() {
    // Simple test case - in real implementation, this would use actual field elements
    let leaf: Field = 42;
    let index: u32 = 5;
    
    // Mock path (in reality, these would be computed from the tree structure)
    let path: Vec<Field> = vec![1, 2, 3, 4];
    let root: Field = poseidon([leaf] + path.clone());
    
    assert(verify_merkle_inclusion(root, leaf, index, path, 4));
}