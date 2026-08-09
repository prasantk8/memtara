pub mod merkle_inclusion;
pub mod attribute_predicates;
pub mod signature_verify;
pub mod time_bound;

// Poseidon-BN254 Merkle proof depth shared by every session circuit.
// Fixed at compile time because Noir array/loop sizes must be known at
// compile time. 4 (16 leaves) is a placeholder sized for this phase's tests;
// tune to the vault's real per-category record count in Phase 3.
pub global MERKLE_DEPTH: u32 = 4;
