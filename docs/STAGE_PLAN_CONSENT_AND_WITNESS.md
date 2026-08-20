# Stage plan: Consent & Witness

*The stage where trust leaves the building.*

Written 2026-08-20, against `cf72e75`. This document is operational: each
workstream section is a complete brief, written to be handed to an engineer
(human or model) who has **not** read the rest of this repository's history.
If you are that engineer, your section tells you everything you need; the
shared sections (contracts, traps, verification) bind everyone.

---

## 1. Why this stage, and what it claims

The binding stage (`cf72e75`, `docs/BREAK_IT_FINDINGS.md` revision 3) ended
with 10 attacks stopped, 0 not stopped, 1 blocked. But every guarantee it
delivers terminates at the same place: **the company's own database, signed
by the company's own key.** Three facts define the frontier:

1. **Attack 8 is still BLOCKED** — not failed, *unattemptable*. There is no
   consent concept in the backend at all. `DecisionEvidence.data.consent`
   exists as a type whose every leaf is `Unpopulated`; the nearest relative,
   `SessionPolicy.purpose_hash`, is a purpose *binding* with no grant time,
   no subject acknowledgement, and no revocation path. A BLOCKED row is not
   a pass — it means the capability under attack does not exist to defend.

2. **The chain head has no witness.** `audit/checkpoint.rs` says it in its
   own header: *"NOT BUILT: an external witness. We can still delete our own
   history."* The schema is already half-ready — `audit_checkpoints` carries
   `anchor_target` / `anchor_ref` / `anchored_at`, null on every row. An
   organisation holding its own signing key can today rewrite the whole log,
   re-sign every checkpoint, and present a perfectly self-consistent lie.

3. **The proving story is incomplete.** "The vault never leaves the device"
   is documented in `ARCHITECTURE.md` and honoured by the server (it only
   verifies), but the only prover is a Python CLI (`clients/prover/`). No
   customer's device runs a Python CLI. Until a proof can be generated in a
   browser, the phrase is an architecture decision, not a product fact.

**What the stage claims when done:** break-it reports **zero BLOCKED rows**
for the first time; the chain head is **witnessed outside the organisation**
and that witness verifies **offline, inside the bundle**; the API contract
is **enforced by CI**, not described by a stale file; and a suitability
proof is generated **in a browser tab** from a vault that never leaves it.

What the stage does *not* claim — carry this into every conversation:
detection is still not prevention; attack 11's silent-swap residual (an org
that swaps a model and says nothing) is untouched by anything here, because
nothing internal can touch it; and anchoring narrows the rewrite window to
the anchor cadence — it does not close it.

---

## 2. The four workstreams at a glance

| | Workstream | Closes | Owner persona | Model | Parallel? |
|--|--|--|--|--|--|
| A | Consent lifecycle | Attack 8 (the last BLOCKED row) | Consent Engineer | sonnet | yes — day 1 |
| B | External witness | "We can delete our own history"; narrows attack 7's window | Witness Engineer | sonnet | yes — day 1 |
| C | Contract enforcement | OpenAPI drift; console fixtures for A+B | Contract Engineer | sonnet | after A and B land |
| D | Browser prover | "Vault never leaves the device" as a product fact | Browser Prover Engineer | sonnet | yes — day 1, spike-gated |

A, B, D touch disjoint files (ownership matrix in §7) and run concurrently.
C documents what A and B built, so it goes last. The coordinator (§8)
verifies between every handoff, never chains blind.

---

## 3. Workstream A — Consent lifecycle

**Persona: the Consent Engineer** — the engineer who refuses to conflate a
purpose binding with a permission. You know that `purpose_hash` looks like
consent to anyone in a hurry, and that the entire value of your work is that
nobody can make that mistake again. You treat revocation as a first-class
recorded fact, not a deleted row.

**Read first:** `backend/api/src/audit/binding.rs` (whole header — it is the
design document for everything you build), `backend/api/src/evidence/mod.rs`
(the `Consent` struct and the comment above `ModelParticipation` about why
`null` is a claim), `tests/break_it/test_attack_08_consent_revocation.py`
(your tripwire — see below), `backend/api/src/wealth/mod.rs` (the
enforcement point).

### A1. Migration `0011_consent_grants.sql`

Table `consent_grants`: `id uuid pk`, `org_id`, `user_id`, `scope jsonb`
(array of strings, non-empty, no floats anywhere — see §6 trap 2),
`consent_version text not null`, `purpose_hash text` (constrain
`^[0-9a-f]{64}$` like migration 0010 — do not repeat Finding 11's asymmetry),
`granted_at timestamptz not null`, `granted_via text not null` (e.g.
`assisted_kiosk`, `mobile_app` — the journeys doc's non-tech-savvy flows need
this), `revoked_at timestamptz`, `revocation_reason text`, `created_at`.
Revocation is an UPDATE that sets `revoked_at` exactly once; add a trigger or
`WHERE revoked_at IS NULL` guard so it can never be un-revoked or re-revoked.
Write the migration header the way 0010 does: why it exists, what it does
not claim.

### A2. Endpoints

- `POST /api/v1/consents` — grant. Refuse empty scope, refuse non-digest
  `purpose_hash`, refuse floats anywhere in the body (mirror
  `check_policy_is_bindable`).
- `POST /api/v1/consents/:id/revoke` — sets `revoked_at`, requires
  `revocation_reason`. Revoking twice is a 409, not a silent success.
- `GET /api/v1/consents/:id` and a per-user list.

### A3. Enforcement

`issue_wealth_request` must refuse (403, naming the consent id or its
absence) unless an **unrevoked** grant exists for that user whose scope
covers the request's purpose. Decisions opened before a revocation **stand**
— their evidence shows consent state *as of decision open*, and that is a
feature, not a leak: the record answers "was consent live when this was
decided," which is the question an examiner actually asks. Revocation
mid-flight means the *next* decision is refused, not that history mutates.

### A4. Binding

Two new binding event types in `audit/binding.rs`, appended to
`BINDING_EVENT_TYPES`: `consent_grant_bound` (recorded in the same
transaction as the grant) and `consent_revocation_bound` (same transaction as
the revocation). Payloads are pure functions of the `consent_grants` row,
canonical encoding, **every key always present** — a grant binding carries
`revoked_at: null` and `revocation_reason: null` explicitly, so revocation
changes bytes rather than adding keys (rejection symmetry, same argument as
the model attestation payload). Extend `rebuild_payload` accordingly.
`replay.rs` needs no verdict changes — it already replays anything in
`BINDING_EVENT_TYPES`.

### A5. Evidence, schema v1.3.0

Populate the `Consent` leaves with real provenance. Bump the schema to
`schema/decision_evidence/v1.3.0.json`, and — because you are the one forced
to bump — carry the queued rename in the same bump:
`DecisionBasis::ProofAndHumanApproved` → `ProofAndHumanConcurred`
(`evidence/mod.rs:309,1299,2131` plus schema plus any fixture that spells
it). One bump, both changes, changelog note in the schema file.

### A6. Rewrite attack 8 — this is part of your definition of done

`test_attack_08_consent_revocation.py` is built as a **tripwire**: it greps
`backend/api/src/` for `consent` and FAILS the moment the concept appears,
precisely so nobody mistakes a stale green skip for "consent revocation was
verified." Your first `cargo build` will make break-it red. That is the file
telling you to rewrite it. New shape, `BREAK_IT_STATUS_ON_PASS = "STOPPED"`:

1. Grant → open decision → 201. (No false positive: replay verdict INTACT.)
2. Revoke → next `issue-wealth-request` → 403 naming the revoked grant.
3. Direct SQL `UPDATE consent_grants SET scope = ...` → `binding_integrity`
   verdict ALTERED on the pre-revocation decision's evidence; linkage
   byte-identical (the trap from attack 4 — assert it).
4. `DELETE` the row → `source_row_missing`.
5. The pre-revocation decision's record still stands and still says consent
   was live at open — assert that explicitly, it is the claim in A3.

Then raise the CI break-it floor (`.github/workflows/ci.yml`) 10 → 11. A
floor below the current result stops guarding the moment the result improves.

**Definition of done:** all of A1–A6; `cargo test` green; full pytest green
including your rewritten attack; French and Arabic `revocation_reason` and
scope strings parametrised in the e2e suite (§6 trap 1 — non-negotiable);
break-it reports 11 stopped, 0 not stopped, 0 blocked.

---

## 4. Workstream B — External witness

**Persona: the Witness Engineer** — the engineer who assumes the
organisation will delete its own history, because `BREAK_IT_FINDINGS.md`
assumes exactly that about every other table. You are building the one
signature the org's own key cannot forge. You never block a request path on
an external HTTP call, and you treat "not yet anchored" and "anchor
mismatch" as different words for a reason.

**Read first:** `backend/api/src/audit/checkpoint.rs` — the whole header,
especially sections (3) and (4); it specifies your work and names the null
columns waiting for you. Then `scripts/bundle/verify_bundle.py` step 7c
(currently INFO) and `docs/VERIFY.md` step 7.

### B1. `AnchorProvider` trait

Same shape as `OtpProvider`: a trait with a logging mock for tests and one
real implementation — **RFC 3161 timestamping** against a configurable TSA
URL (`MEMTARA_ANCHOR_TSA_URL`; freetsa.org for dev). Input: the checkpoint
JWS digest. Output: `AnchorReceipt { target, reference, token_der, anchored_at }`.
If the receipt token needs storage (it does — offline verification needs the
DER bytes), add migration `0012_checkpoint_anchor_receipts.sql` for an
`anchor_receipt bytea` column rather than abusing `anchor_ref`. Confirm the
TSA request/response shape **empirically** against a real TSA before writing
the trait — the same rule the original plan set for `bb`: confirm
invocations, don't guess flags.

### B2. The anchoring job

A periodic sweep of unanchored checkpoints — **not** inline in checkpoint
creation. Checkpointing must never fail because a TSA is down; anchoring is
eventually consistent, and the sweep retries. Fill `anchor_target`,
`anchor_ref`, `anchored_at` on success. Expose anchor state wherever
checkpoint state is already exposed, distinguishing three cases: anchored
(with receipt), pending (younger than the sweep interval), and overdue
(older — this one is a finding, and the reporting must say so).

### B3. Offline verification — step 7c becomes real

The bundle gains the anchor receipts and the TSA's certificate chain, and
`verify_bundle.py` step 7c graduates from INFO to a real check: verify the
RFC 3161 token cryptographically, offline, air-gapped — the TSA cert chain
ships *in* the bundle for exactly this reason. Use a pure-Python ASN.1 path
(`asn1crypto` / `rfc3161ng`) — the bundle's verifier must not grow a
compiled dependency. Update `docs/VERIFY.md` step 7 and the auditor console
if it surfaces checkpoint state. State plainly in both what the anchor
proves (this head existed by this time, witnessed externally) and what it
does not (nothing about rows between anchors).

### B4. Attack 12 — rewrite history

New module `test_attack_12_rewrite_history.py`, `BREAK_IT_STATUS_ON_PASS =
"STOPPED"`. The attack the header of `checkpoint.rs` admits to: with DB
access and the org's signing key, rewrite the log from genesis, recompute
every hash, re-sign the head. Before this stage that produces a
self-consistent forgery every internal check passes. After: the anchored
receipt pins the *old* head, and re-verification fails against the anchor.
Assert both halves — that the forgery passes linkage+head (the trap), and
that the anchor betrays it. State the residual honestly in `BREAK_IT_NOTE`:
rows appended and rewritten *between* anchors, inside the cadence window,
are still forgeable; the window shrank from "all of history" to the anchor
interval. Raise the floor to 12 once green.

**Definition of done:** B1–B4; anchoring survives a dead TSA (test with the
mock refusing); bundle rebuilt from a live server and verified offline with
step 7c PASS; attack 12 green three consecutive runs; floor raised.

---

## 5. Workstream C — Contract enforcement

**Persona: the Contract Engineer** — the engineer who treats `openapi.yaml`
as a test that happens to be readable, not documentation that happens to be
wrong. Your enemy is drift, and your instrument is CI.

**Runs after A and B land.** Read first: `docs/openapi.yaml`,
`backend/api/src/main.rs` (router assembly), `clients/auditor-console/check_fixtures.mjs`.

1. **Truth first:** update `openapi.yaml` to cover everything it currently
   omits — `/review`, `/decision-evidence`, `/model-corrections` — plus
   workstream A's consent endpoints and whatever B exposed. Response schemas
   included: `binding_integrity` on evidence reads, the three-state anchor
   status.
2. **Then the ratchet:** a CI drift test that enumerates the live router's
   paths and diffs against `openapi.yaml`, both directions, so the file can
   never rot again. A route without a spec entry fails CI; a spec entry
   without a route fails CI.
3. **Console fixtures:** add fixtures for a consent-revocation ALTERED
   verdict and an anchored-vs-overdue checkpoint, wire into
   `check_fixtures.mjs`.
4. **Housekeeping with sharp edges:** `scripts/bundle/evidence_ops.py:365`
   docstring still says v1.1.0; the bundle schema `x_schema_version` bumps
   if its shape changed under B3.

**Definition of done:** drift test green and demonstrably bidirectional
(prove it by temporarily deleting a spec entry and watching it fail);
console 22 → 26+ fixtures green; no stale version strings under `scripts/`.

---

## 6. Workstream D — Browser prover

**Persona: the Browser Prover Engineer** — the engineer who makes "the vault
never leaves the device" true in a browser tab, and who would rather report
an ACIR version mismatch than paper over one. You verify claims empirically
before building on them; you never upgrade shared toolchain versions to make
your corner work without coordinator sign-off.

**Spike gate (do this before writing any product code):** confirm that
`@noir-lang/noir_js` + `@aztec/bb.js`, at pinned versions compatible with
the nargo version this workspace compiled with, can (1) execute
`circuits/wealth_suitability/target/*.json` ACIR to a witness and (2)
produce an UltraHonk proof that the *backend's* existing `bb verify` path
accepts against the *existing* vkey. If versions mismatch, **stop and
report** — recompiling all circuits is a workspace-wide decision, not yours.
The spike's deliverable is a one-page note: exact versions, exact
invocations, proof accepted (or the precise incompatibility).

**Then build `clients/web-prover/`:** one self-contained page, no framework.
Vault JSON arrives via file input and is read locally; witnesses are built
in-page; only `{proof, public_inputs}` is POSTed to `/submit-wealth-proof`.
The page states, in its own UI copy, what left the device — because the user
this exists for will be shown it by a bank.

**Definition of done:** an automated e2e (headless browser or node harness)
in which a test proxy records every request body and the test asserts **no
witness value appears in any of them** — the guarantee as an assertion, not
a sentence; the produced proof accepted by a live server; the spike note
committed alongside the client.

---

## 7. Shared contracts, ownership, and the traps

### File ownership (conflict avoidance)

| Path | Owner |
|--|--|
| `backend/api/src/{consents}/`, `evidence/mod.rs`, `schema/`, migration 0011, attack 8 | A |
| `backend/api/src/audit/checkpoint.rs`, anchor module, migration 0012, `scripts/bundle/verify_bundle.py`, attack 12 | B |
| `docs/openapi.yaml`, drift test, console fixtures | C |
| `clients/web-prover/` | D |
| `audit/binding.rs` | A (B does not touch it) |
| `.github/workflows/ci.yml` floor | whoever's attack lands, coordinated through the coordinator |

### The traps — every one of these was hit, at cost, in previous stages

1. **Non-ASCII is not an edge case; it is the target market.** Finding 9: a
   guard comparing two JSON encodings 500'd on every non-ASCII character —
   `modèle-de-risque` → 500, `نموذج` → 500 — and the entire English-only
   test suite passed while a DIFC/CBUAE deployment was unusable. Any new
   text field gets French and Arabic values in a parametrised test. No
   exceptions.
2. **No floats in anything that will be canonically hashed.** Floats have no
   canonical form Python and Rust render alike. Refuse them at the API
   boundary (400) before the row exists — after the row exists, the failure
   is a 500 on a decision that is already open. See
   `check_policy_is_bindable`.
3. **Binding payloads: pure function of rows, unstored, every key always
   present, `PayloadEncoding::Canonical`.** Storing the payload silently
   undoes the entire mechanism — verification would hash a stored copy the
   attacker's UPDATE never touched. Read `binding.rs`'s header before
   touching anything near it.
4. **Two clocks.** Postgres and the API process disagree by ~130ms. Any
   comparison between a DB-generated and an API-generated timestamp needs
   the `MAX_CLOCK_SKEW_SECONDS` allowance (`wealth/review.rs`). Finding 10
   survived because a test helper added two seconds — never accommodate a
   defect in the test.
5. **Constrain your own column, then report asymmetry.** Finding 11 was
   found because an engineer constrained their new column and *reported*
   that the older sibling wasn't, instead of quietly matching the weaker
   side. That behaviour is the expectation.
6. **`BREAK_IT_STATUS_ON_PASS` is per-module and deliberate** — a test can
   pass by verifying an attack *succeeds*. Declare what a pass means.
7. **A test can pass while lying.** Attack 8's tripwire design — fail loudly
   when the world changes rather than skip forever — is the house style for
   "not applicable yet" tests.
8. **Use `.venv/bin/python`**, never system python — pytest silently skips
   everything that needs pg8000 otherwise. `scripts/break_it.sh` already
   does this.
9. **Do not touch the `apex-postgres` / `apex-*` Docker containers.** They
   belong to a different project.
10. **Before committing:** `git status` first; grep the staged diff for
    `token|secret|key|password|authenticity`; review any suspicious file's
    contents before pushing.

### Prose standards (they are load-bearing here)

Module headers argue *why*, in full sentences, naming rejected alternatives
— `binding.rs` and migration 0010 are the exemplars. Findings docs state
residuals plainly; "detection, not prevention" appears wherever it is true.
Nothing in this codebase claims more than it can defend, and a reviewer will
hold new prose to that bar.

## 8. Coordinator protocol

Whoever runs this stage (any Claude model, given this doc):

1. Spawn A, B, D concurrently (sonnet, one Task each, brief = the persona
   section + §7 verbatim + "read first" files). C waits for A and B.
2. Between every handoff: `cargo test` in `backend/`, full
   `.venv/bin/python -m pytest`, `scripts/break_it.sh` three consecutive
   runs (one flake was observed last stage — three greens is the bar),
   console `check_fixtures.mjs`, and a bundle rebuild verified offline.
3. Agents report findings in others' code rather than working around them
   (that instinct produced Findings 9, 10, 11 — the most valuable output of
   the last stage). The coordinator routes each finding to its owner.
4. Floors ratchet only upward, only when green three times.
5. Commit per workstream, not per stage; each message argues the why, like
   `cf72e75` does.

### Stage-done checklist

- [ ] break-it: **12 stopped / 0 not stopped / 0 blocked** (11/0/0 if attack
      12 slips — then attack 12 is the top of the next stage, stated as such)
- [ ] CI floor matches the result
- [ ] Bundle verifies offline including the anchor receipt (7c PASS)
- [ ] OpenAPI drift test green, bidirectional
- [ ] Browser proof accepted by a live server; no-witness-leaves-device
      asserted by a machine, not a sentence
- [ ] `BREAK_IT_FINDINGS.md` revision 4: attack 8 and 12 rows, residuals
      restated, including the ones this stage does **not** touch (attack 11's
      silent swap, the anchor-cadence window)
- [ ] French/Arabic parametrisation on every new text field

## 9. Explicitly out of scope, so nobody drifts into it

- The analyst console / consumer mobile frontends (wireframes remain
  reference; next stage candidate once the browser prover proves the
  client-side story).
- Real UAE Pass / SMS provider credentials (stubs remain stubs).
- Closing attack 11's silent-swap residual — nothing internal can; only
  process (attestation cadence, contractual audit rights) narrows it, and
  that is a sales/legal artifact, not code.
- Marketing-site copy of any kind — the copy deck is the source of truth,
  and repositioning requires an explicit deck-v2 decision from the founder.
