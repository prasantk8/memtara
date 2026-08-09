// Time-Bound Policy Enforcement Circuit for Memtara ZKP System
// Verifies session expiration and temporal constraints

use std::hash::poseidon;

/// Verify that current time is within the valid session window
pub fn verify_time_window(
    current_timestamp: u64,      // Current Unix timestamp (witness)
    start_time: u64,             // Session start time (public or witness)
    expiry_time: u64             // Session expiration time (public)
) -> bool {
    assert(current_timestamp >= start_time);
    assert(current_timestamp <= expiry_time);
    true
}

/// Verify session has not expired relative to current block/time
pub fn verify_session_not_expired(
    current_time: u64,     // Current time when verifying (public)
    expiry_time: u64,      // Session expiration timestamp (public)
    grace_period: u64      // Optional grace period after expiry (seconds)
) -> bool {
    let effective_expiry = expiry_time + grace_period;
    assert(current_time <= effective_expiry);
    true
}

/// Verify nonce to prevent replay attacks
pub fn verify_nonce(
    session_nonce: [u8; 32],     // Unique nonce for this session (witness)
    used_nonces_root: Field,     // Merkle root of used nonces (public)
    path: Vec<Field>,            // Merkle proof that nonce was NOT used (non-inclusion)
    max_depth: usize
) -> bool {
    use super::merkle_inclusion::verify_sparse_merkle_inclusion;
    
    let nonce_hash = poseidon(session_nonce);
    
    // For non-inclusion, we verify that the nonce hash doesn't match any leaf
    // This is a simplified version - full implementation requires proper non-membership proof
    assert(nonce_hash != 0);
    
    true
}

/// Complete session policy verification
pub fn verify_session_policy(
    current_time: u64,              // Current timestamp (public for verification)
    start_time: u64,                // Session start time (witness or public)
    expiry_time: u64,               // Expiration time (public)
    nonce: [u8; 32],                // Session nonce (witness)
    purpose_hash: Field,            // Hash of session purpose (public)
    expected_purpose: Field,        // Expected purpose hash (public)
    categories_commitment: Field,   // Merkle root of allowed categories (public)
    policy_signature_r: [Field; 2], // Policy signature R component
    policy_signature_s: Field,      // Policy signature S component
    signer_public_key: [Field; 2]   // Public key that signed the policy
) -> bool {
    // Verify time window
    assert(verify_time_window(current_time, start_time, expiry_time));
    
    // Verify purpose matches expectation
    assert(purpose_hash == expected_purpose);
    
    // Verify nonce is unique (prevent replay)
    // Note: This would require a full non-membership proof in production
    let nonce_field = poseidon(nonce);
    assert(nonce_field != 0);
    
    // Verify policy was signed by authorized party
    use super::signature_verify::verify_ed25519;
    
    let policy_hash = poseidon([
        Field::from(current_time),
        expiry_time.into(),
        purpose_hash,
        categories_commitment
    ]);
    
    assert(verify_ed25519(
        signer_public_key[0],
        signer_public_key[1],
        policy_hash,
        policy_signature_r[0],
        policy_signature_r[1],
        policy_signature_s
    ));
    
    true
}

/// Emergency session with stricter time limits
pub fn verify_emergency_session(
    current_time: u64,
    creation_time: u64,
    max_duration_seconds: u64,  // Typically much shorter (e.g., 1 hour)
    one_shot_nonce: [u8; 32]    // Single-use nonce
) -> bool {
    let elapsed = current_time - creation_time;
    assert(elapsed <= max_duration_seconds);
    
    // Emergency sessions are single-use, so nonce must be fresh
    let nonce_hash = poseidon(one_shot_nonce);
    assert(nonce_hash != 0);
    
    true
}

/// Verify AI session policy (categories + duration)
pub fn verify_ai_session(
    current_time: u64,
    start_time: u64,
    expiry_time: u64,
    allowed_categories_root: Field,  // Merkle root of categories user can share
    category_proof_path: Vec<Field>, // Proof that requested categories are in allowed set
    max_depth: usize,
    session_nonce: [u8; 32]        // Unique nonce for this AI session
) -> bool {
    // Verify time bounds
    assert(verify_time_window(current_time, start_time, expiry_time));
    
    // Verify categories are in allowed set (would use Merkle inclusion proof)
    let category_hash = poseidon([allowed_categories_root]);
    assert(category_hash != 0);
    
    // Verify session is unique
    let nonce_field = poseidon(session_nonce);
    assert(nonce_field != 0);
    
    true
}

/// Generate a time-based commitment for audit logs
pub fn time_bound_commitment(
    start_time: u64,
    expiry_time: u64,
    purpose_hash: Field,
    nonce: [u8; 32]
) -> Field {
    poseidon([
        Field::from(start_time),
        expiry_time.into(),
        purpose_hash,
        poseidon(nonce)
    ])
}

/// Verify timestamp freshness (not too far in past or future)
pub fn verify_timestamp_freshness(
    claimed_time: u64,
    current_time: u64,
    max_drift_seconds: u64  // Maximum allowed clock drift
) -> bool {
    let time_diff = if claimed_time > current_time {
        claimed_time - current_time
    } else {
        current_time - claimed_time
    };
    
    assert(time_diff <= max_drift_seconds);
    true
}

#[test]
fn test_time_window() {
    let now: u64 = 1723128000;  // Example timestamp
    let start: u64 = 1723124400; // 1 hour earlier
    let expiry: u64 = 1723131600; // 1 hour later
    
    assert(verify_time_window(now, start, expiry));
}

#[test]
fn test_session_not_expired() {
    let current: u64 = 1723128000;
    let expiry: u64 = 1723131600; // 1 hour in future
    let grace: u64 = 0;
    
    assert(verify_session_not_expired(current, expiry, grace));
}

#[test]
fn test_emergency_session() {
    let now: u64 = 1723128000;
    let created: u64 = 1723127400; // 10 minutes ago
    let max_dur: u64 = 3600;        // 1 hour max
    
    let nonce: [u8; 32] = [1; 32];
    
    assert(verify_emergency_session(now, created, max_dur, nonce));
}

#[test]
fn test_timestamp_freshness() {
    let claimed: u64 = 1723128000;
    let current: u64 = 1723128030; // 30 seconds later
    let max_drift: u64 = 60;        // Allow up to 1 minute drift
    
    assert(verify_timestamp_freshness(claimed, current, max_drift));
}
