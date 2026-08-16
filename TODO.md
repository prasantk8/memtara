# Memtara ZKP Implementation TODO List

---

## Active workstream: CBUAE Demonstration of Compliance + AIHOOTS integration

Goal: integrate Memtara with the AIHOOTS E1 audit gateway cryptographically
(zero-latency — no synchronous REST call between the two systems), and produce
an end-to-end "Demonstration of Compliance" package against the CBUAE
*Guidance Note on Consumer Protection and the Responsible Adoption and Use of
AI and ML by LFIs* (`CBUAE_EN_6958_VER1`).

- [x] **Task 1 — Regulatory baseline.** AIHOOTS added as a submodule at
      `tests/aihoots_reference`; CBUAE PDF extracted (7 pages, 10 sections, 35
      lettered sub-clauses); every clause mapped in
      [`docs/REGULATORY_MATRIX.md`](docs/REGULATORY_MATRIX.md).
      *Note: the brief's clause numbers (`4.3`, `5.2`) don't exist in the real
      document — the matrix uses real identifiers and documents the mapping.*
- [x] **Task 2 — Cryptographic identity layer.** `backend/api/src/crypto/signer.rs`
      (Ed25519 from `MEMTARA_PRIVATE_KEY`, hand-rolled EdDSA JWS so there is no
      `alg` negotiation to confuse), `GET /.well-known/jwks.json` (RFC 8037 OKP,
      RFC 7638 `kid`), and `docs/openapi.yaml` covering the whole surface.
- [x] **Task 3 — Proof issuance API.** `POST /api/v1/issue-proof` +
      `GET /api/v1/predicates`. Two paths, both real circuit evaluations:
      *fresh* (submit proof → `bb verify` → consume nonce → issue) and
      *attested* (re-attest a proof that already passed). Reuses
      `verify::verify_against_request` rather than a second copy of the
      verification pipeline. Logs `proof_token_issued` with a
      `regulatory_audit_id` and the CBUAE clauses.
      *The endpoint never generates a proof — see the module header for why
      that is the product rather than a limitation.*
- [x] **Task 4 — End-to-end validator.** `tests/test_aihoots_handshake.py`
      (15 tests) against the real Rust server, real Postgres, real `bb`, and
      AIHOOTS's real gateway/chain/verifier from the submodule. Includes the
      forgeries a relying party must refuse and a demonstrated tamper
      detection. The reference adapter lives in
      `integrations/aihoots/memtara_claims.py`.
- [x] **Task 5 — Compliance demonstration.** `scripts/generate_regulatory_demo.py`
      → [`docs/REGULATORY_DEMO_REPORT.md`](docs/REGULATORY_DEMO_REPORT.md).
      Deterministic (byte-identical across runs, so it diffs). Real keys, real
      JWTs, real AIHOOTS hash chain, real tamper test.
- [x] **Task 6 — CI/CD and docs.** `.github/workflows/ci.yml` gates on the
      handshake test *and* fails if it skipped; README statement; `.env.example`;
      `requirements-dev.txt`.

**Status: complete.** `cargo test` 57/57, handshake 15/15, report regenerates
identically. Known gaps are named in
[`docs/REGULATORY_MATRIX.md`](docs/REGULATORY_MATRIX.md) — §3(a) bias
measurement, §3(b) training data, §4(b) bilingual disclosure, §7(c) complaints
channel, and the §6(f) proof-token revocation caveat.

---

## Workstream: Structured-product suitability (DFSA Conduct of Business)

Goal: assess a client for a structured product against the firm's registered
terms, disclose one bit, and leave evidence a regulator can re-verify years
later without trusting the firm — or Memtara.

- [x] **W1 — `wealth_suitability` circuit.** `circuits/wealth_suitability/`,
      plus `circuits/lib/src/suitability.nr` for the four limbs. Verification
      key committed at `circuits/wealth_suitability/vkey/` (the only one that
      is — an examiner needs a key published independently of the server that
      used it; CI regenerates and diffs it).
      *Two resolutions worth knowing: the brief's `existing/(liquid+existing)*100`
      is cross-multiplied, because `/` on a Noir `Field` is modular inversion
      and would produce a meaningless comparison. And the verdict is a public
      **output**, not an assert — an asserting circuit cannot produce a proof
      of "not suitable", which would make a decline indistinguishable from an
      assessment that never happened.*
- [x] **W2 — `POST /api/v1/issue-wealth-request`.** Fifth `CircuitType`,
      migration `0003`, and a `wealth_requests` table holding the terms as
      typed columns — because they are what the submitted public inputs get
      checked against, not decoration.
- [x] **W3 — `POST /api/v1/submit-wealth-proof`.** Terms check, window check,
      `vault_root` pinned to the user's synced root, `bb verify` through the
      shared pipeline, **then** public input 11 is read. `/api/v1/issue-proof`
      refuses the predicate outright, because it does neither.
- [x] **W4 — Middleware + a real device client.** `clients/wealth_client.py`
      generates genuine proofs (Baby Jubjub EdDSA, Poseidon commitments via
      `circuits/witness_oracle`, `nargo execute`, `bb prove`).
      `integrations/aihoots/memtara_wealth.py` orchestrates on demand.
      *The brief's sketch had the gateway load the client's vault; that would
      put every client's plaintext finances inside the LLM gateway. The prover
      is an injected capability instead — "ask the holder's device" — so the
      demo behaviour exists without baking the violation into the adapter.*
- [x] **W5 — `tests/test_wealth_suitability_e2e.py`** (21 tests). The only
      test here with no cryptographic stand-in anywhere. Includes the
      demonstration that a proof of *non*-suitability passes `bb verify`
      cleanly, which is why W3 reads the output.
- [x] **W6 — Documentation.** DFSA appendix in the matrix; Section E plus a
      canonical case file in the demo report.
- [x] **W7 — CI.** The suitability test is a second hard gate; the committed
      vkey is regenerated and diffed; `nargo test --workspace` now covers every
      circuit rather than just the library.

**Status: complete.** `cargo test` 72/72, `nargo test --workspace` 61/61,
handshake 15/15, suitability 21/21, report regenerates identically.

**Two clause-number corrections, both in the caller's brief.** "DFSA Conduct of
Business Rule 3.1 (Suitability)" — COB 3.1 is *Application*; suitability is
**COB 3.4** (and was 6.2 in older versions). The `dfsa_rules` claim still emits
the string `COB 3.1` because that is the contract relying parties were told to
match; changing it is one line and is the caller's call. This mirrors the CBUAE
`4.3`/`5.2` correction above. See the DFSA appendix in the matrix, including
the caveat that — unlike the CBUAE Guidance Note — the DFSA rulebook is not
vendored here and its current rule text could not be quoted.

**One gap found in existing code, not retrofitted.** The four session circuits
do not pin `vault_root` to the user's synced vault, so their Merkle limb proves
consistency with *some* tree rather than the user's. `wealth_suitability` does
pin it. Recorded in the matrix rather than silently left.

---

## Workstream: Productisation — from engine to platform

Goal: a bank can manage a product catalogue, a device can prove against it, a
compliance officer can export sealed evidence, and one command demonstrates the
whole thing to a CRO.

- [x] **P1 — Product registry.** `backend/api/src/products/`, migration `0004`.
      `POST/GET/PATCH /api/v1/products`, and `issue-wealth-request` now *reads*
      the terms instead of accepting them.
      *Three decisions worth knowing. The key is `(org_id, product_isin)`, not
      the bare ISIN the brief specified — a global key means two banks cannot
      both sell a widely-distributed note, whoever registers first fixes
      everyone's terms, and `GET /products/{isin}` answers with a competitor's
      product governance. `approved_by_risk_committee` is **enforced**, not
      stored: an assessment against an unapproved instrument produces evidence
      that a controlled process was followed when it was not. And a request
      that still supplies the four terms is **rejected** rather than having
      them ignored — an integration that sends them believes it is setting the
      bar, and silent ignoring leaves that belief latent.*
      *`PATCH` was not in the brief, which specified `updated_at` and no route
      that could ever change it. Risk-committee approval is a state transition
      in every real governance process, so the column had to be reachable; the
      event records a before-and-after diff, because "who lowered the minimum
      income, and when" is the first question a mis-selling review asks.*
- [x] **P2 — Device prover SDK.** `clients/prover/` — `memtara-prove`, a vault
      file format that refuses to load world-readable, and a README covering
      subprocess and WASM integration. `tests/test_prover_cli.py` (12 tests)
      drives it as a subprocess, which is the contract an embedder actually
      uses.
      *The brief has the CLI fetch thresholds from `GET /products/{isin}` and
      prove against them. It fetches them for display only. The values a proof
      commits to come from `issue-wealth-request`, because if the two ever
      disagreed — a PATCH between the calls, a stale cache — the proof would
      fail verification for a reason the holder could not see. The same
      endpoint also needs an org key, and a phone must never hold one, which is
      why `--request-id`/`--request-file` exists as the device-side mode.*
- [x] **P3 — AIHOOTS adapter, production shape.** Registry-backed terms, the
      product name and risk level in the injected claim, and a prompt/registry
      risk-level discrepancy promoted to its own audit event.
      `tests/test_aihoots_adapter.py` (20 tests).
- [x] **P4 — Evidence exporter.** `scripts/export_audit_evidence.py` renders
      the Canonical Case File from `GET /api/v1/wealth-assessments/{id}` and
      seals it. `scripts/pdf.py` is a dependency-free, byte-reproducible PDF
      writer — reproducibility is a requirement, not a preference, because the
      seal is a digest over the rendered bytes.
- [x] **P5 — Multi-tenancy and hardening.** `org_id` on `audit_log`
      (migration `0005`) and on `products`; every query scoped by the
      authenticated org; a fixed-window rate limiter on proof submission;
      `GET /health`; `GET /metrics`.
      *`/metrics` carries no tenant-identifying label, and there is a test that
      fails if one appears. Cardinality is the usual argument; disclosure is
      the one that decides it — an unauthenticated scrape endpoint with an
      `org_id` label is a customer directory, and a rising counter on a named
      competitor tells you when they are onboarding.*
      *A rate-limit refusal writes no audit event. `audit_log` is an
      append-only hash chain, so one event per rejected request would let an
      unauthenticated caller grow it without bound — a limiter that amplifies
      against the structure it protects.*
- [x] **P6 — CRO demo.** `scripts/demo_cro_workflow.py`: one command, its own
      server, a real proof, a sealed PDF, and a closing line a Head of Digital
      Wealth can act on.
- [x] **P7 — CI and documentation.** The prover CLI and the CRO demo are both
      gates; README carries the badges and a five-minute quick start;
      `docs/openapi.yaml` covers the registry, the evidence pack and the
      operational endpoints.

**A third identifier error in a brief, after the two clause numbers.** The demo
was specified against ISIN `TEST1234567890`. That is fourteen characters; an
ISIN is twelve, so the registry refuses it — correctly, because a registry that
accepts non-identifiers cannot be reconciled against a product master. The demo
uses `XS2500000018`, which unlike the `XS1234567890` used elsewhere here also
passes its own ISO 6166 check digit.

**Not built, and worth naming.** Org self-registration is still
unauthenticated, so anyone who can reach `POST /orgs` can mint a tenant. Rate
limiting is per process, so replicas multiply the effective limit. The case
file's seal is a detached digest and signature, not a PAdES signature a viewer
will show a green tick for.

---

## Commercial pack (S1–S8) — complete

- [x] **S1 — Landing page copy.** `docs/SALES_LANDING_PAGE.md`, including the
      two-minute CRO demo video script timed against the demo's real step
      headings. The page itself is staged at
      `marketing/aihoots-pr/public/memtara.html`.
- [x] **S2 — Pricing and ROI.** `docs/PRICING_MODEL.md`, `scripts/roi_calculator.py`.
- [x] **S3 — Pilot agreement.** `docs/PILOT_AGREEMENT_TEMPLATE.md`, with the
      data inventory written from the migrations rather than from the pitch.
- [x] **S4 — Objection handler.** `docs/SALES_OBJECTION_HANDLER.md`, eight
      objections plus a technical due-diligence sheet.
- [x] **S5 — Quickstart.** `scripts/quickstart.sh`, and the README's primary
      call to action.
- [x] **S6/S7 — Campaign and outreach.** `marketing/`.
- [x] **S8 — AIHOOTS page.** `marketing/aihoots-pr/`, staged and deliberately
      not pushed — opening a PR against another repository is not something to
      do on someone's behalf without asking.

**The ROI calculator contradicted the pricing it was written to justify.** At
$25,000/month, displaced compliance labour alone does not cover Memtara until a
bank writes roughly 4,900 structured-product recommendations a year. That is not
a mid-sized institution, and the gap between the $5,000 pilot and the $25,000
production tier is 5x — the size of cliff pilots fall off. Hence Tier 2S at
$12,000/month, and a volume band published against every tier. Reproduce it with
`python3 scripts/roi_calculator.py --tier production --products-per-year 2500`.

**Three claims in the brief that were not true, and were changed rather than
shipped.** A UAE mis-selling fine benchmarked at 10–20% of product value — no
such published figure exists, so the calculator asks for the bank's own
complaints data and tags every input with whose number it is. "Memtara processes
hashed proofs, not plaintext PII" — the `users` table holds a mobile number, and
the defensible claim is the narrower one, that the client's financial figures
never reach the server. "We have a pilot running for Q4 2026" — there are none;
the corrected outreach opens two slots instead.

**A commercial blocker found while writing the pilot agreement.** There is no
`LICENSE` file, though `README.md` states MIT. A bank's counsel checks this in
the first week. It is also a real decision — MIT is a broad grant to attach to
something licensed at $25,000 a month — so it was flagged in three places rather
than resolved unilaterally.

---

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