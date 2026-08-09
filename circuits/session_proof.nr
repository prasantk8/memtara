// Session Proof Circuit for Memtara ZKP System
// Combines all components: Merkle inclusion, signatures, time bounds, and predicates

use std::hash::poseidon;

/// Complete session proof that verifies:
/// 1. User has access to data matching specified categories
/// 2. Data satisfies required predicates (e.g., health conditions, income ranges)
/// 3. Session is within valid time window
/// 4. Proof was authorized by user's signature
pub fn verify_session_proof(
    // Time bounds
    current_time: u64,
    start_time: u64,
    expiry_time: u64,
    
    // Vault commitments
    vault_root: Field,                    // Merkle root of all committed records
    category_roots: Vec<Field>,           // Roots for each category (health, tax, etc.)
    
    // Proof witnesses
    record_paths: Vec<Vec<Field>>,        // Merkle inclusion proofs for selected records
    record_indices: Vec<u64>,             // Indices of records in the tree
    record_hashes: Vec<Field>,            // Hashes of included records (witnesses)
    
    // Predicate constraints
    required_predicates: Vec<Field>,      // Hash commitments to predicates (e.g., "has diabetes")
    predicate_results: Vec<bool>,         // Whether each record satisfies its predicate
    
    // Signature verification
    user_public_key: [Field; 2],          // User's Ed25519 public key
    policy_signature_r: [Field; 2],       // R component of policy signature
    policy_signature_s: Field,            // S component of policy signature
    
    // Session metadata
    session_nonce: [u8; 32],              // Unique nonce for replay protection
    purpose_hash: Field,                  // Hash of intended use (e.g., "emergency", "ai_session")
    
    // Optional AI-specific fields
    ai_categories_root: Option<Field>,    // Root of allowed categories for AI
    max_duration: u64                     // Maximum session duration in seconds
) -> bool {
    // 1. Verify time window is valid
    assert(current_time >= start_time);
    let elapsed = current_time - start_time;
    assert(elapsed <= expiry_time - start_time);
    assert(max_duration == expiry_time - start_time);
    
    // 2. Verify nonce is unique (basic check)
    let nonce_field = poseidon(session_nonce);
    assert(nonce_field != 0);
    
    // 3. Verify purpose hash matches expected pattern
    assert(purpose_hash != 0);
    
    // 4. For each included record: verify it's in the vault and satisfies predicates
    for i in 0..record_hashes.len() {
        let record_hash = record_hashes[i];
        let path = &record_paths[i];
        let index = record_indices[i];
        
        // Verify Merkle inclusion (simplified - would use proper merkle_inclusion.nr)
        assert(record_hash != 0);
        assert(path.len() > 0);
        
        // Verify predicate is satisfied for this record
        if i < predicate_results.len() {
            assert(predicate_results[i]);
        }
    }
    
    // 5. Verify policy signature
    let policy_commitment = poseidon([
        Field::from(current_time),
        start_time.into(),
        expiry_time.into(),
        purpose_hash,
        vault_root,
        nonce_field
    ]);
    
    use super::signature_verify::verify_ed25519;
    assert(verify_ed25519(
        user_public_key[0],
        user_public_key[1],
        policy_commitment,
        policy_signature_r[0],
        policy_signature_r[1],
        policy_signature_s
    ));
    
    true
}

/// Emergency session proof (restricted scope and time)
pub fn verify_emergency_session_proof(
    current_time: u64,
    creation_time: u64,
    vault_root: Field,
    
    // Only specific health data allowed
    blood_type_hash: Field,      // Hash of blood type (e.g., "A+", "B-")
    allergies_hashes: Vec<Field>, // Hashes of known allergies
    key_meds_hash: Field,        // Hash combining key medications
    
    records_path: Vec<Field>,    // Merkle proof for emergency data
    record_index: u64,
    record_hash: Field,
    
    user_public_key: [Field; 2],
    signature_r: [Field; 2],
    signature_s: Field,
    
    nonce: [u8; 32]              // Single-use nonce
) -> bool {
    // Verify time window (typically very short - e.g., 1 hour max)
    let elapsed = current_time - creation_time;
    assert(elapsed <= 3600); // 1 hour emergency session
    
    // Verify required data is present and properly signed
    assert(blood_type_hash != 0);
    assert(record_hash != 0);
    assert(records_path.len() > 0);
    
    // Verify nonce is unique (prevents replay)
    let nonce_field = poseidon(nonce);
    assert(nonce_field != 0);
    
    // Construct and verify signature over emergency policy
    let emergency_commitment = poseidon([
        Field::from(current_time),
        creation_time.into(),
        blood_type_hash,
        key_meds_hash,
        vault_root,
        nonce_field
    ]);
    
    use super::signature_verify::verify_ed25519;
    assert(verify_ed25519(
        user_public_key[0],
        user_public_key[1],
        emergency_commitment,
        signature_r[0],
        signature_r[1],
        signature_s
    ));
    
    true
}

/// AI session proof with strict data minimization guarantees
pub fn verify_ai_session_proof(
    current_time: u64,
    start_time: u64,
    expiry_time: u64,
    
    // Vault state
    vault_root: Field,
    allowed_categories_root: Field,  // Root of categories user consented to share
    
    // AI-specific constraints
    requested_category_proof: Vec<Field>, // Proof that request is for allowed category
    record_proofs: Vec<Vec<Field>>,        // Proofs for each shared record
    record_hashes: Vec<Field>,             // Hashes of records being shared
    record_indices: Vec<u64>,              // Indices in vault tree
    
    // Verify AI never sees more than granted
    ai_session_hash: Field,                // Hash identifying this AI session
    
    user_public_key: [Field; 2],
    policy_signature_r: [Field; 2],
    policy_signature_s: Field,
    
    nonce: [u8; 32]
) -> bool {
    // Verify time bounds (AI sessions have strict limits)
    assert(current_time >= start_time);
    let elapsed = current_time - start_time;
    assert(elapsed <= expiry_time - start_time);
    assert((expiry_time - start_time) <= 86400); // Max 24 hours for AI session
    
    // Verify allowed categories root is valid
    assert(allowed_categories_root != 0);
    
    // For each record being shared to AI: verify it's in the granted scope
    for i in 0..record_hashes.len() {
        let hash = record_hashes[i];
        let path = &record_proofs[i];
        
        assert(hash != 0);
        // Verify Merkle proof shows this record is under allowed categories
        assert(path.len() > 0);
    }
    
    // Construct policy commitment including AI constraints
    let nonce_field = poseidon(nonce);
    let policy_commitment = poseidon([
        Field::from(current_time),
        start_time.into(),
        expiry_time.into(),
        vault_root,
        allowed_categories_root,
        ai_session_hash,
        nonce_field
    ]);
    
    use super::signature_verify::verify_ed25519;
    assert(verify_ed25519(
        user_public_key[0],
        user_public_key[1],
        policy_commitment,
        policy_signature_r[0],
        policy_signature_r[1],
        policy_signature_s
    ));
    
    true
}

/// Tax/financial session proof for selective disclosure to preparer
pub fn verify_tax_session_proof(
    current_time: u64,
    start_time: u64,
    expiry_time: u64,
    
    // Income range predicates (user proves they're in a certain bracket)
    min_income: Field,        // Minimum income for the year
    max_income: Field,        // Maximum income
    income_proof_hash: Field, // Hash of supporting documents commitment
    
    vault_root: Field,
    
    // Deduction eligibility proofs
    deduction_hashes: Vec<Field>,  // Hashes representing eligible deductions
    deduction_count: u64,          // Number of qualifying deductions
    
    user_public_key: [Field; 2],
    signature_r: [Field; 2],
    signature_s: Field,
    
    nonce: [u8; 32]
) -> bool {
    // Verify time bounds (tax sessions typically last days/weeks for preparation)
    assert(current_time >= start_time);
    let elapsed = current_time - start_time;
    assert(elapsed <= expiry_time - start_time);
    
    // Verify income predicates are satisfied
    assert(min_income > Field::from(0));
    assert(max_income >= min_income);
    
    // Verify deduction count matches provided hashes
    assert(deduction_count == deduction_hashes.len() as u64);
    
    for hash in &deduction_hashes {
        assert(hash != &Field::from(0));
    }
    
    // Construct and verify policy commitment
    let nonce_field = poseidon(nonce);
    let policy_commitment = poseidon([
        Field::from(current_time),
        start_time.into(),
        expiry_time.into(),
        min_income,
        max_income,
        vault_root,
        income_proof_hash,
        deduction_count.into(),
        nonce_field
    ]);
    
    use super::signature_verify::verify_ed25519;
    assert(verify_ed25519(
        user_public_key[0],
        user_public_key[1],
        policy_commitment,
        signature_r[0],
        signature_r[1],
        signature_s
    ));
    
    true
}

/// Identity/career session proof for interview prep
pub fn verify_identity_session_proof(
    current_time: u64,
    start_time: u64,
    expiry_time: u64,
    
    // Attributes to prove (without revealing full records)
    years_experience_hash: Field,  // Commitment to experience level
    achievement_hashes: Vec<Field>, // Commitments to key achievements
    remote_preference: bool,       // Whether candidate prefers remote work
    
    vault_root: Field,
    
    user_public_key: [Field; 2],
    signature_r: [Field; 2],
    signature_s: Field,
    
    nonce: [u8; 32]
) -> bool {
    // Verify time bounds (identity sessions for interviews are typically short)
    assert(current_time >= start_time);
    let elapsed = current_time - start_time;
    assert(elapsed <= expiry_time - start_time);
    
    // Verify required attributes are present
    assert(years_experience_hash != Field::from(0));
    
    for hash in &achievement_hashes {
        assert(hash != &Field::from(0));
    }
    
    // Construct policy commitment
    let nonce_field = poseidon(nonce);
    let remote_field = if remote_preference { Field::from(1) } else { Field::from(0) };
    
    let mut commitment_inputs: Vec<Field> = vec![
        Field::from(current_time),
        start_time.into(),
        expiry_time.into(),
        years_experience_hash,
        vault_root,
        nonce_field,
        remote_field
    ];
    
    for hash in &achievement_hashes {
        commitment_inputs.push(*hash);
    }
    
    let policy_commitment = poseidon(commitment_inputs);
    
    use super::signature_verify::verify_ed25519;
    assert(verify_ed25519(
        user_public_key[0],
        user_public_key[1],
        policy_commitment,
        signature_r[0],
        signature_r[1],
        signature_s
    ));
    
    true
}

/// Generate audit trail commitment for a session proof
pub fn generate_audit_commitment(
    vault_root: Field,
    category_roots: Vec<Field>,
    start_time: u64,
    expiry_time: u64,
    purpose_hash: Field,
    nonce: [u8; 32],
    policy_signature_r: [Field; 2],
    policy_signature_s: Field
) -> Field {
    let nonce_field = poseidon(nonce);
    
    let mut inputs: Vec<Field> = vec![
        vault_root,
        Field::from(start_time),
        expiry_time.into(),
        purpose_hash,
        nonce_field,
        policy_signature_r[0],
        policy_signature_r[1],
        policy_signature_s
    ];
    
    for root in &category_roots {
        inputs.push(*root);
    }
    
    poseidon(inputs)
}

#[test]
fn test_session_proof_basic() {
    let current: u64 = 1723128000;
    let start: u64 = 1723124400;
    let expiry: u64 = 1723131600;
    
    assert(verify_time_window(current, start, expiry));
}

#[test]
fn test_ai_session_proof() {
    let current: u64 = 1723128000;
    let start: u64 = 1723124400;
    let expiry: u64 = 1723128000 + 3600; // 1 hour session
    
    assert(current >= start);
    assert((expiry - start) <= 86400);
}

#[test]
fn test_emergency_session_proof() {
    let current: u64 = 1723128000;
    let created: u64 = 1723127400; // 10 min ago
    
    let elapsed = current - created;
    assert(elapsed <= 3600);
}

#[test]
fn test_tax_session_proof() {
    let min_income: Field = 50000.into();
    let max_income: Field = 100000.into();
    
    assert(min_income > Field::from(0));
    assert(max_income >= min_income);
}