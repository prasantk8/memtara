# Memtara Zero-Knowledge Proof Architecture

## Overview
End-to-end architecture for implementing ZKPs in Memtara's local-first vault system with scoped temporary access, selective disclosure, and auditability.

## High-Value Use Cases

### 1. Doctor Visit / Health Context
- **What**: Prove possession of specific meds, allergies, conditions, or lab ranges without sending full history
- **Who**: AI assistant or doctor receives only minimal verified facts + proof
- **ZKP Enables**: Selective disclosure with cryptographic verification

### 2. Emergency Share
- **What**: Time-bound selective disclosure of blood type, allergies, key meds, insurance
- **Benefit**: Hospital verifies authenticity and completeness without full vault access or persistent storage

### 3. Tax / Financial
- **What**: Prove income ranges, deduction eligibility, or "I have supporting documents for these claims"
- **Benefit**: Preparer gets structured summary + cryptographic assurance without raw docs

### 4. Identity / Career
- **What**: Prove attributes (years of experience, specific achievements, remote preference) or membership in a set of notes
- **Benefit**: Interview prep AI or third parties get verified claims only

### 5. AI Connector Sessions
- **What**: Prove the context payload is a correct redaction/subset of the committed vault and respects session policy (categories + duration)
- **Benefit**: Stronger trust that AI never saw more than granted; audit log becomes cryptographically meaningful

## Recommended Implementation Stack: Noir (Aztec)

### Why Noir?
- Developer experience best for application-level circuits (Rust-like syntax)
- Strong client-side/browser/mobile support via NoirJS, Barretenberg (UltraHonk), Mopro, native bindings
- Teams have moved production systems from Halo2 to Noir for speed of iteration
- Good fit for required circuits: Merkle inclusion, Poseidon hashing, predicates, signature verification

### Cryptographic Primitives
- **Commitments**: Poseidon or Pedersen over vault items / category Merkle roots
- **Selective Disclosure**: Attribute-based or redactable signatures + ZK
- **Signatures**: Ed25519 or BLS for user ownership (provable in circuits)
- **Time-binding**: Include expiry timestamps and nonces in statements

## Architecture Components

### 1. Vault Layer (Local-First)
```
┌─────────────────────────────────────┐
│           Encrypted Data            │
│  ┌───────────┬───────────┬───────┐  │
│  │ Record 1  │ Record 2  │ ...   │  │
│  └───────────┴───────────┴───────┘  │
└─────────────────────────────────────┘
            ↓
┌─────────────────────────────────────┐
│        Merkle Tree Structure        │
│  • Category-based sparse Merkle tree │
│  • Poseidon hashing for commitments│
│  • Root committed to blockchain      │
└─────────────────────────────────────┘
```

### 2. Scoped Session Creation Flow
```
User → Specify: categories, purpose, duration
     ↓
System builds public statement:
"There exist records under categories C that satisfy predicates P,
signed by key K, and session expires at T"
     ↓
Generate ZKP of knowledge of witnesses (actual records)
     ↓
Optionally attach short-lived encrypted payload
```

### 3. Verification Layer
- Any party with verification key can check proof in milliseconds
- No interaction with user device after generation
- Audit log records: public statement + proof hash

### 4. Emergency Mode
- Pre-authorized or one-click generation of narrow attribute proof
- Time-limited and single-use
- Automatic cleanup after expiration

## Circuit Design (Noir)

### Core Circuits Needed:

1. **Merkle Inclusion Proof**
   - Verify record exists in category tree at specific index
   - Range checks for value constraints
   
2. **Attribute Predicate Verification**
   - Equality checks for specific values
   - Range proofs for numeric attributes (age, income ranges)
   - Set membership proofs

3. **Signature Verification**
   - Ed25519/BLS signature validity in circuit
   - Link to committed records

4. **Time-Bound Policy Enforcement**
   - Timestamp validation within circuit
   - Nonce inclusion for replay protection

5. **Redaction Proof**
   - Prove subset relationship between full vault and disclosed payload
   - Verify all constraints satisfied

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
- Set up Noir development environment
- Create basic Merkle tree circuits
- Implement Poseidon hashing integration
- Build vault data structure prototype

### Phase 2: Core ZKP Circuits (Weeks 3-4)
- Attribute predicate verification circuit
- Signature verification in circuit
- Time-binding proof circuit
- Test with simple health records

### Phase 3: Session Management (Weeks 5-6)
- Scoped session creation flow
- Proof generation API
- Verification endpoint
- Audit logging system

### Phase 4: Emergency Mode & Advanced Features (Weeks 7-8)
- Emergency share circuit
- Redaction proof for AI sessions
- Multi-signature support
- Performance optimization

## Technical Specifications

### Data Structures
```rust
// Vault Item Structure
struct VaultItem {
    id: u32,
    category: String,        // "health", "financial", "identity"
    data_hash: [u8; 32],     // Poseidon commitment of encrypted data
    timestamp: u64,          // Creation time
    predicates: Vec<Condition>
}

// Session Policy Structure
struct SessionPolicy {
    categories: Vec<String>,
    duration_seconds: u64,
    purpose: String,
    nonce: [u8; 32]
}

// ZKP Statement Structure
struct ZKPStatement {
    merkle_root: [u8; 32],
    public_inputs: Vec<[u8; 32]>,
    expiry_timestamp: u64,
    policy_hash: [u8; 32]
}
```

### Circuit Interface (Noir)
```rust
// Example circuit signature for health attribute proof
pub fn prove_health_attributes(
    merkle_root: Field,
    record_index: Field,
    record_path: Vec<Field>, // Merkle path
    meds: Vec<Field>,        // Medications as field elements
    allergies: Vec<Field>,   // Allergies as field elements
    conditions: Vec<Field>,  // Conditions as field elements
    signature: [Field; 2],   // Ed25519 signature (R, S)
    public_key: [Field; 2],  // Public key (X, Y)
    expiry: Field,
    nonce: Field
) -> bool {
    // Verify Merkle inclusion
    assert(merkle_verify(merkle_root, record_index, record_path));
    
    // Verify predicates (meds present, etc.)
    for med in meds {
        assert(set_membership(med, allowed_medications));
    }
    
    // Verify signature
    assert(verify_ed25519(public_key, signature, record_hash));
    
    // Verify time bounds
    assert(current_time < expiry);
    assert(nonce == expected_nonce);
    
    true
}
```

### API Endpoints (REST/GraphQL)

#### Proof Generation
```http
POST /api/v1/proofs/generate
Content-Type: application/json

{
  "categories": ["health"],
  "predicates": {
    "has_medication": ["aspirin", "insulin"],
    "blood_type": "<A>"
  },
  "duration_seconds": 3600,
  "purpose": "emergency_sharing"
}

Response:
{
  "proof": <base64-encoded-proof>,
  "public_inputs": [...],
  "verification_key": "..."
}
```

#### Proof Verification
```http
POST /api/v1/proofs/verify
Content-Type: application/json

{
  "proof": <received-proof>,
  "public_inputs": [...]
}

Response:
{
  "valid": true,
  "verified_at": "2026-08-09T00:15:30Z"
}
```

## Implementation Notes (Phase 1/2, as built)

Two deliberate deviations from the plan above, made when `circuits/` was
turned from placeholder `.nr` files into a real, compiling Nargo workspace:

- **Signatures: EdDSA/Baby Jubjub, not Ed25519/BLS.** True Ed25519
  (Curve25519) or BLS (BLS12-381) verification inside a Noir circuit over
  BN254 requires expensive non-native field emulation. EdDSA over Baby
  Jubjub is native to the proving curve and is what Noir's own reference
  implementation uses (`noir-lang/noir-edwards` + `noir-lang/poseidon`, see
  `circuits/lib/src/signature_verify.nr`). Vault records destined for a ZK
  proof need a Baby Jubjub keypair, separate from any Ed25519 identity key
  used elsewhere.
- **Replay protection is off-circuit.** The original design had a nonce
  non-membership check inside the circuit; that logic never actually
  verified non-membership (see git history). A real in-circuit
  non-membership proof is possible but heavy. Instead, `nonce` is a public
  input on every session circuit, bound into the signed policy commitment —
  a verifier-side registry is responsible for rejecting a nonce it has
  already seen. This matches how production ZK session systems actually do
  it and is the standard tradeoff, not a shortcut specific to this project.

Also: `circuits/lib` fixes a compile-time Merkle depth (`MERKLE_DEPTH = 4`)
and each session circuit proves a fixed record count
(`MAX_AI_RECORDS`/`MAX_DEDUCTIONS`/`MAX_ACHIEVEMENTS` = 4) rather than a
variable-count padding scheme — both are placeholders sized for this
phase's tests, to be tuned against the real vault's record counts in
Phase 3.

## Security Considerations

### Threat Model
1. **Malicious AI/Hospital**: May try to extract additional information from proof
   - Mitigation: Zero-knowledge proofs reveal nothing beyond validity

2. **Vault Compromise**: Attacker gains access to encrypted vault data
   - Mitigation: Data still encrypted; ZKP only proves possession of keys

3. **Replay Attacks**: Reusing old proofs for new sessions
   - Mitigation: Nonce is a public input bound into the signed policy
     commitment; an off-circuit verifier registry rejects a nonce it has
     already seen (see Implementation Notes above)

4. **Quantum Threats**: Future quantum computers breaking current crypto
   - Mitigation: Plan for post-quantum migration (Lattice-based signatures)

### Privacy Properties
- **Local-First**: All sensitive data never leaves user device
- **Minimal Disclosure**: Only necessary attributes revealed
- **Forward Secrecy**: Session keys derived per-session, not reusable
- **Auditability**: Proofs can be independently verified without revealing data

## Testing Strategy

### Unit Tests (Phase 1)
- Merkle tree operations with Poseidon hashing
- Basic predicate verification circuits
- Signature verification in circuit context

### Integration Tests (Phase 2)
- End-to-end session creation flow
- Cross-platform proof generation/verification
- Performance benchmarks (proving time, proof size)

### Security Audits (Phase 3)
- Formal verification of critical circuits
- Penetration testing of API endpoints
- Third-party cryptographic review

## Success Metrics

1. **Performance**: Proof generation < 5 seconds on mobile device
2. **Proof Size**: < 10KB for typical health record proofs
3. **Verification Time**: < 100ms on server-side
4. **User Experience**: Single-click emergency share in < 3 seconds
5. **Security**: Zero data leakage from ZKPs, independent verification

## Next Steps

1. Initialize Noir project structure
2. Implement basic Merkle inclusion circuit
3. Set up vault encryption/decryption layer
4. Create proof generation API prototype
5. Build verification endpoint