# Memtara Zero-Knowledge Proof System

![Real ZK Proofs (Baby Jubjub)](https://img.shields.io/badge/Real%20ZK%20Proofs-Baby%20Jubjub-2f6f4e)
![DFSA COB 3.4 Ready](https://img.shields.io/badge/DFSA%20COB%203.4-Ready-1f4e79)
![CBUAE Guidance Note](https://img.shields.io/badge/CBUAE%20Guidance%20Note-Mapped-1f4e79)

A ZKP implementation for a local-first vault with scoped temporary access,
selective disclosure, and auditability — and, on top of it, a
structured-product suitability platform for UAE banks.

> **Memtara is CBUAE-ready. It issues verifiable cryptographic proofs that plug
> directly into the AIHOOTS audit gateway.**
>
> Memtara signs a short-lived Ed25519 attestation for every verified predicate
> and publishes the public key at `/.well-known/jwks.json`. The
> [AIHOOTS E1 audit gateway](https://ai.aihoots.com) validates it locally,
> injects the verified facts into the model's context, and appends the
> `proof_hash` to its own tamper-evident SHA-256 chain — **without one
> synchronous call back to Memtara**.
>
> Read the evidence, not the claim:
> - [`docs/REGULATORY_MATRIX.md`](./docs/REGULATORY_MATRIX.md) — every clause of
>   the CBUAE *Guidance Note on Consumer Protection and the Responsible Adoption
>   and Use of AI and ML by LFIs*, mapped to what these systems actually do,
>   with the four genuine gaps named on page one.
> - [`docs/REGULATORY_DEMO_REPORT.md`](./docs/REGULATORY_DEMO_REPORT.md) — five
>   worked UAE journeys with real JWTs, a real hash chain, and a demonstrated
>   tamper detection. Deterministic, so it diffs.
> - [`tests/test_aihoots_handshake.py`](./tests/test_aihoots_handshake.py) — the
>   integration, executed against the real server, real Postgres, real
>   Barretenberg and AIHOOTS's real gateway. CI fails if it stops passing.
>
> **It is also ready for structured-product suitability under DFSA Conduct of
> Business.** A client's own
> device proves, against the bank's registered product terms, that income,
> liquidity, risk tolerance and portfolio concentration were each assessed —
> and discloses one bit. The bank gets evidence a regulator can re-verify years
> later from a published key; it holds none of the figures. See
> [`tests/test_wealth_suitability_e2e.py`](./tests/test_wealth_suitability_e2e.py),
> which is the one place in this repository where **no part of the cryptography
> is stood in for**: real Baby Jubjub signatures, real Poseidon commitments,
> real `bb prove`, real `bb verify`.
>
> One command shows the whole thing:
> `python3 scripts/demo_cro_workflow.py`.
>
> A citation note, because the number matters to anyone checking: the tokens
> emit `COB 3.1` because that is the string relying parties were told to match,
> but **COB 3.1 is "Application"** — the suitability obligation is **COB 3.4**.
> The mapping in `docs/REGULATORY_MATRIX.md` is against the substance of the
> rule; unlike the CBUAE Guidance Note, the DFSA rulebook is not vendored here.

## Try it in 5 minutes. No credit card required.

```bash
git clone --recurse-submodules https://github.com/prasantk8/memtara-zkp.git
cd memtara-zkp
./scripts/quickstart.sh
```

It checks what you have, starts Postgres in a container, installs the Noir
toolchain if you say yes, compiles the circuits, builds the server, and runs the
full CRO workflow. About five minutes on a cold machine; the workflow itself
takes roughly forty seconds. A sealed PDF opens at the end, and the script
verifies its seal in front of you before it does.

Everything in that PDF was produced by the real system — a real Baby Jubjub
signature, a real Poseidon commitment, a real `bb prove`, a real `bb verify`
inside the real server, and a real hash-chained audit entry. Nothing is
pre-recorded and nothing is stubbed.

Run `./scripts/quickstart.sh --help` first if you would rather read what it
touches before it touches anything. It creates no files outside this
repository, removes nothing, and never runs a toolchain installer without
asking. There is deliberately no `curl | bash` one-liner: piping a script from
the internet into a shell is precisely what this product exists to argue
against.

**Selling it, or being sold it:**
[landing page copy](./docs/SALES_LANDING_PAGE.md) ·
[pricing and ROI](./docs/PRICING_MODEL.md) ·
[objection handler](./docs/SALES_OBJECTION_HANDLER.md) ·
[pilot agreement](./docs/PILOT_AGREEMENT_TEMPLATE.md) ·
[campaign assets](./marketing/)

## Architecture Overview

This system implements end-to-end zero-knowledge proofs allowing users to prove statements about their private data without revealing the underlying records. Built using Noir (Aztec) for optimal developer experience and browser/mobile support.

### Key Features
- **Local-first vault**: All sensitive data remains on user device
- **Selective disclosure**: Prove only necessary attributes
- **Time-bound sessions**: Automatic expiration of access rights
- **Auditability**: Cryptographically verifiable logs without data leakage
- **Emergency mode**: One-click selective sharing with automatic cleanup

## Project Structure

```
memtara-zkp/
├── circuits/                    # Noir workspace: a shared lib + 5 binaries
│   ├── lib/                     # merkle_inclusion, attribute_predicates,
│   │                            # signature_verify, time_bound, suitability
│   ├── {emergency,ai,tax,identity}_session/
│   ├── wealth_suitability/      # DFSA COB suitability (+ its published vkey)
│   └── witness_oracle/          # dev tool: the circuits' own Poseidon, for
│                                # an off-device prover to call
├── vault/                       # Local-first encrypted vault (Rust)
│   ├── Cargo.toml              # Rust workspace config
│   └── src/                    # Vault implementation
├── backend/                     # Axum API (Rust)
│   └── api/src/
│       ├── auth/               # passkeys, OTP, UAE Pass
│       ├── vault_sync/         # encrypted blob sync (server never holds the key)
│       ├── disclosure/         # disclosure-request lifecycle + nonce registry
│       ├── verify/             # bb-backed proof verification
│       ├── crypto/             # Ed25519 issuer key + /.well-known/jwks.json
│       ├── issuance/           # POST /api/v1/issue-proof
│       ├── wealth/             # suitability endpoints + the evidence pack
│       ├── products/           # the bank's product registry (terms live here)
│       ├── orgs/               # relying-party accounts and API keys
│       ├── ops/                # /health, /metrics, rate limiting
│       └── audit/              # hash-chained append-only log
├── clients/
│   ├── wealth_client.py        # the device side: real Baby Jubjub + Poseidon
│   └── prover/                 # `memtara-prove` — the deployable CLI + SDK
├── integrations/aihoots/        # the relying-party adapter AIHOOTS adopts
├── tests/
│   ├── aihoots_reference/      # AIHOOTS submodule (gateway, chain, verifier, CBUAE PDF)
│   ├── test_aihoots_handshake.py
│   ├── test_wealth_suitability_e2e.py
│   ├── test_prover_cli.py
│   ├── test_aihoots_adapter.py
│   ├── test_evidence_exporter.py
│   └── test_pdf_writer.py
├── scripts/
│   ├── quickstart.sh           # clone to sealed PDF, one command
│   ├── demo_cro_workflow.py    # the whole product, one command
│   ├── export_audit_evidence.py# the Canonical Case File (PDF + seal)
│   ├── pdf.py                  # dependency-free PDF writer
│   ├── roi_calculator.py       # what it costs, what it displaces, payback
│   └── generate_regulatory_demo.py
├── marketing/                   # LinkedIn series, lead-gen playbook, outreach
├── cli/                        # Command-line interface (not yet implemented)
├── web/                        # Web frontend with NoirJS (not yet implemented)
├── packages/                   # Shared utilities and types (not yet implemented)
└── docs/                       # journeys, regulatory matrix, demo report,
                                # openapi.yaml, and the commercial pack
                                # (landing page, pricing, pilot, objections)
```

## Quick Start

### Prerequisites
- Rust (install via [rustup](https://rustup.rs))
- Noir toolchain (install via [noirup](https://github.com/noir-lang/noirup):
  `curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup`)
- Node.js 18+ (for the web frontend — not yet scaffolded, see `web/`)

### Vault (Rust)

```bash
cd vault
cargo build --release
cargo test
```

### Circuits (Noir)

```bash
cd circuits
nargo test --workspace

# ACIR compilation currently requires this flag due to a known upstream
# Noir compiler false-positive in noir-lang/noir-edwards' EC arithmetic
# (noir-lang/noir#6793) — the library's own asserts do constrain the
# unsafe block's outputs, the static checker just can't see it here.
nargo compile --workspace --skip-brillig-constraints-check
```

### Backend (Rust / Axum)

```bash
cp .env.example .env        # then set MEMTARA_PRIVATE_KEY
docker run -d --name memtara-postgres -e POSTGRES_USER=memtara \
  -e POSTGRES_PASSWORD=memtara -e POSTGRES_DB=memtara -p 5433:5432 postgres:15

export DATABASE_URL=postgres://memtara:memtara@localhost:5433/memtara
cd backend && cargo test && cargo run
```

`bb` (Barretenberg) must be on `PATH` and the circuits compiled — the server
generates verification keys at boot and refuses to start otherwise, rather than
coming up as a verifier that cannot verify.

### The AIHOOTS integration

```bash
git submodule update --init                  # AIHOOTS reference + the CBUAE PDF
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements-dev.txt

.venv/bin/python -m pytest tests/test_aihoots_handshake.py -v

# The suitability journey. Needs nargo and bb on PATH — it generates real
# proofs rather than seeding them, so it is the slowest and the most useful.
.venv/bin/python -m pytest tests/test_wealth_suitability_e2e.py -v

.venv/bin/python scripts/generate_regulatory_demo.py
```

`cli/`, `web/`, and `packages/` are not yet implemented (see
[TODO.md](./TODO.md)).

## Five minutes: register a product, prove suitability, export the report

Everything below is real — a real proof, a real verification, a real sealed
PDF. Nothing is seeded.

### The one-command version

```bash
python3 scripts/demo_cro_workflow.py
```

Builds and boots Memtara, registers a product under governance, onboards a
synthetic client, generates a zero-knowledge proof on her "device", verifies
it, injects the verdict into an LLM conversation through AIHOOTS's real
gateway, and writes `cro_demo/Case_File_<timestamp>.pdf`. It cleans up after
itself unless you pass `--keep-data`.

### The same thing, by hand

```bash
export MEMTARA=http://localhost:8080
KEY=$(curl -sX POST $MEMTARA/orgs -H 'content-type: application/json' \
        -d '{"name":"DIFC Wealth Desk","org_type":"bank"}' | jq -r .api_key)

# 1. The bank registers the instrument and its suitability terms.
#    Terms live here, not on the assessment request — otherwise whoever makes
#    the recommendation also chooses the bar it is measured against.
curl -sX POST $MEMTARA/api/v1/products -H "authorization: Bearer $KEY" \
  -H 'content-type: application/json' -d '{
    "product_isin":"XS2500000018",
    "product_name":"5-Year S&P 500 Principal Protected Note",
    "risk_level":3, "min_income":500000, "min_liquidity":1000000,
    "max_concentration_percent":30 }'

# 2. The risk committee approves it. Until then, assessments are refused.
curl -sX PATCH $MEMTARA/api/v1/products/XS2500000018 \
  -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"approved_by_risk_committee":true}'

# 3. The client's device. Four figures, one file, never sent anywhere.
clients/prover/memtara-prove init-vault --vault-path ~/.memtara/vault.json \
  --income 750000 --liquid-assets 2000000 --risk-tolerance 4 \
  --existing-holdings-value 250000

# 4. Assess. Exit 0 = suitable, 2 = assessed and not suitable, 1 = error.
clients/prover/memtara-prove --base-url $MEMTARA \
  --user-id "$USER_ID" --product-isin XS2500000018 \
  --vault-path ~/.memtara/vault.json --org-api-key "$KEY" --json

# 5. The evidence a CRO hands to a regulator.
scripts/memtara-export --request-id "$REQUEST_ID" --base-url $MEMTARA \
  --org-api-key "$KEY" --output ./case_file.pdf
```

See [`clients/prover/README.md`](./clients/prover/README.md) for how a mobile
developer embeds step 4 — including why a phone must never hold that org API
key.

## Operating it

```bash
curl -s $MEMTARA/health   | jq .    # deep readiness; 503 when degraded
curl -s $MEMTARA/metrics           # Prometheus exposition
```

`/health` answers the question nothing else would catch: whether the
verification key this instance uses still matches the one published in
`circuits/wealth_suitability/vkey/`. Both work perfectly well in isolation, so
a divergence has no other symptom — and it would mean every proof accepted
today is unverifiable tomorrow by the examiner holding the committed key.

## Use Cases

### 1. Doctor Visit / Health Context
Prove possession of specific medications, allergies, or lab ranges without sharing full medical history.

### 2. Emergency Share
Time-bound selective disclosure of critical health information (blood type, allergies, key meds) with cryptographic proof of authenticity.

### 3. Tax / Financial Verification
Prove income ranges or document eligibility without revealing raw financial data.

### 4. Identity Verification
Prove professional qualifications or membership in sets without disclosing full credentials.

### 5. AI Connector Sessions
Verify that AI assistants only received granted context, with cryptographic assurance for audit logs.

### 6. Structured-Product Suitability (DFSA)
Prove that income, liquid assets, risk tolerance and portfolio concentration were
each assessed against a specific instrument's registered terms, disclosing only
whether the client is suitable. Uniquely among these, the honest answer is
sometimes **no** — so the circuit publishes its verdict as an output rather than
asserting it, and a decline is issued the same signed, chained evidence as an
approval. A firm that can only evidence approvals fails the rule it is claiming
to satisfy.

## Development Roadmap

See [TODO.md](./TODO.md) for detailed implementation phases and progress tracking.

## Security Model

- **Zero-Knowledge**: proofs reveal nothing beyond validity
- **Local-First**: sensitive data never leaves the user's device
- **The backend never proves, only verifies**: generating a proof needs the
  plaintext as a witness, so a server able to prove would be a server holding
  plaintext. This is a structural property, not a policy.
- **Audit Trail**: every proof is independently re-verifiable, and both the
  Memtara and AIHOOTS logs are hash-chained

### Honest limits

- A proof token is **not revocable** inside its 300-second lifetime — the cost
  of offline validation. Revoke the disclosure request or the session instead.
  See the §6(f) caveat in the regulatory matrix.
- Memtara narrows the feature surface a model can discriminate on; it does
  **not** measure disparate impact, and a threshold can itself correlate with a
  protected class. Bias testing is a separate obligation (CBUAE §3(a)).
- A hash chain proves internal consistency, not availability. An operator can
  still delete a whole log; append-only storage and off-box replication are the
  mitigations, and neither is in this repo.
- **`bb verify` exiting 0 does not mean "approved".** For `wealth_suitability`
  it means the proof was correctly constructed; the verdict is public input 11,
  and a proof of *not suitable* verifies exactly as cleanly. Reading the exit
  code and not the output approves everyone who was assessed. Memtara's own
  `/api/v1/issue-proof` refuses this predicate rather than trusting anyone to
  remember that.
- The four session circuits do **not** pin `vault_root` to the user's synced
  vault; `wealth_suitability` does. Until that is retrofitted, their Merkle
  limb proves the figures are consistent with *some* tree rather than the
  user's committed one.
- Rate limiting is **per process**, so two replicas behind a load balancer
  permit twice the configured limit. It bounds expensive work; it is not a
  security boundary. A true global limit belongs at the edge, or behind the
  Redis implementation the `RateLimiter` seam is shaped for.
- The Canonical Case File's seal is a **detached digest and signature**, not a
  PAdES/AdES signature — no PDF viewer will show a green tick. The strongest
  authenticity claim in the pack is the Memtara-issued JWT, verifiable by
  anyone against the published JWKS.
- `audit_log.org_id` is **outside** the event hash. It is a denormalisation of
  a fact the hashed payload already carries, so a tampered column disagrees
  with a digest anyone holding the payload can recompute — but folding it into
  the hash would have invalidated every row written before that migration,
  which for a compliance log is a self-inflicted tamper alarm.
- Org self-registration is still **unauthenticated**. Anyone who can reach
  `POST /orgs` can mint a tenant. Gating it behind an allowlist is a real
  product question and is not built.

## License

MIT License - See LICENSE file for details.

> **Unresolved, and a commercial blocker.** There is no `LICENSE` file in this
> repository, so the line above points at nothing. A bank's counsel checks this
> in the first week of diligence, and an unfulfilled licence reference turns a
> technical review into a legal one.
>
> It is also a decision rather than a formality: MIT is a broad grant to attach
> to something being licensed at $25,000 a month, and a source-available or dual
> licence may serve the commercial model better. Choose deliberately, then add
> the file. Until then, `docs/PILOT_AGREEMENT_TEMPLATE.md` clause 5.6 tells the
> Memtara side to disclose the position rather than wait to be asked.