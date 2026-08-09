# Memtara ZKP Implementation TODO List

## Overall Goal
Implement end-to-end zero-knowledge proof system for Memtara's local-first vault with scoped temporary access, selective disclosure, and auditability.

---

## Phase 1: Project Foundation & Environment Setup (Days 1-2)

### [x] Day 1: Initialize Development Environment
- [x] Create Noir project structure (`memtara_circuits`) — `circuits/` is now a
      real Nargo workspace (lib + 4 bin packages), not flat placeholder `.nr` files
- [x] Set up Rust workspace for vault layer — `vault/` compiles and its tests pass
- [ ] Configure Node.js monorepo for web frontend — `web/`, `cli/`, `packages/` still empty
- [x] Install required dependencies:
  - Noir toolchain (nargo 1.0.0-beta.26 via noirup)
  - Barretenberg/UltraHonk prover (bundled with nargo)
  - Poseidon hash implementations (`noir-lang/poseidon` v0.3.0)
  - Signature library — **EdDSA/Baby Jubjub** (`noir-lang/noir-edwards` v0.2.5),
    not Ed25519/BLS; see ARCHITECTURE.md note on why

### [x] Day 2: Core Infrastructure Setup
- [x] Create basic vault data structure with encryption (AES-256-GCM, caller-supplied key)
- [x] Implement Merkle tree utilities — SHA-256 in `vault/` (Rust side, not yet
      Poseidon-matched to circuits — tracked as Phase 3 work), Poseidon-BN254
      in `circuits/lib/src/merkle_inclusion.nr` (Noir side)
- [x] Set up test framework for circuits — `nargo test`, 24 lib tests passing
- [ ] Configure CI/CD pipeline skeleton
- [x] Write README with project overview

**Status**: ✅ circuits + vault done; Node/web/cli scaffolding not started

---

## Phase 2: Core ZKP Circuits Development (Days 3-6)

### [x] Days 3-4: Merkle Inclusion & Hash Circuits
- [x] Implement basic Merkle tree proof circuit in Noir
- [x] Add Poseidon hash function integration
- [ ] Create sparse Merkle tree for category-based structure — dropped; the
      original sparse-inclusion logic had a soundness hole (see git history),
      plain inclusion only for this phase
- [x] Write tests for inclusion/exclusion proofs
- [ ] Benchmark proving times

### [x] Days 5-6: Predicate Verification Circuits
- [x] Implement equality checks for attributes
- [x] Build range proof circuits (numeric predicates, real witness values not
      hardcoded stand-ins)
- [x] Add set membership verification
- [x] Create signature verification circuit — EdDSA/Baby Jubjub, not Ed25519/BLS
- [x] Integrate time-binding logic into circuits — nonce is a public input,
      verified off-circuit (see ARCHITECTURE.md); no in-circuit replay check

**Status**: ✅ Done for this pass. All 4 use-case circuits
(`emergency_session`, `ai_session`, `tax_session`, `identity_session`)
compile to ACIR and have passing `nargo test` coverage, including
`should_fail` tests per constraint. Known simplifications: fixed
`MERKLE_DEPTH` (4) and fixed per-circuit record counts
(`MAX_AI_RECORDS`/`MAX_DEDUCTIONS`/`MAX_ACHIEVEMENTS` = 4), no variable-count
padding scheme yet.

---

## Phase 3: Vault & Session Management Layer (Days 7-10)

### [ ] Days 7-8: Local-First Vault Implementation
- [ ] Build encrypted vault data structure
- [ ] Implement category-based Merkle tree storage
- [ ] Add record commitment generation
- [ ] Create backup/export functionality
- [ ] Test cross-platform compatibility (mobile, web, desktop)

### [ ] Days 9-10: Session Creation Flow
- [ ] Design session policy specification format
- [ ] Build public statement generator
- [ ] Implement proof generation API (Rust backend)
- [ ] Create encrypted payload attachment mechanism
- [ ] Add nonce and timestamp handling

**Status**: ⏳ Not Started

---

## Phase 4: Verification & Emergency Features (Days 11-14)

### [ ] Days 11-12: Verification Layer
- [ ] Build proof verification endpoint
- [ ] Implement audit logging system
- [ ] Create independent verification CLI tool
- [ ] Add blockchain commitment integration (optional)
- [ ] Test cross-platform verification

### [ ] Days 13-14: Emergency Mode & Advanced Features
- [ ] Implement one-click emergency share circuit
- [ ] Build redaction proof for AI sessions
- [ ] Add multi-signature support
- [ ] Optimize proving times and proof sizes
- [ ] Create emergency mode UI prototype

**Status**: ⏳ Not Started

---

## Phase 5: Testing & Security (Days 15-18)

### [ ] Days 15-16: Comprehensive Testing
- [ ] Write unit tests for all circuits
- [ ] Implement integration test suite
- [ ] Create end-to-end session flow tests
- [ ] Add performance benchmarks
- [ ] Test on mobile devices (iOS/Android)

### [ ] Days 17-18: Security Audits & Optimization
- [ ] Conduct formal verification of critical circuits
- [ ] Perform penetration testing on APIs
- [ ] Optimize proof size and generation time
- [ ] Document security considerations
- [ ] Prepare for third-party review

**Status**: ⏳ Not Started

---

## Phase 6: Documentation & Production Readiness (Days 19-20)

### [ ] Days 19-20: Final Preparations
- [ ] Write comprehensive developer documentation
- [ ] Create API reference docs
- [ ] Build user guides for each use case
- [ ] Prepare deployment scripts
- [ ] Set up monitoring and logging

**Status**: ⏳ Not Started

---

## Technical Debt & Future Work

### Post-MVP Enhancements (After Day 20)
- [ ] Add zero-knowledge range proofs for private values
- [ ] Implement lattice-based signatures for quantum resistance
- [ ] Add multi-party computation features
- [ ] Integrate with blockchain for public commitments
- [ ] Build native mobile SDKs (iOS/Android)

---

## Daily Standup Template

```
Date: YYYY-MM-DD
Yesterday: 
Today:
Blockers:
Focus Area: [Phase X - Component]
```

---

## Progress Tracking

### By Phase Completion:
- Phase 1: ⬜⬛ (0%)
- Phase 2: ⬜⬛ (0%)
- Phase 3: ⬜⬛ (0%)
- Phase 4: ⬜⬛ (0%)
- Phase 5: ⬜⬛ (0%)
- Phase 6: ⬜⬛ (0%)

### Key Metrics to Track:
- Proving time per circuit
- Proof size in bytes
- Verification time in milliseconds
- Memory usage during proving
- Mobile device performance