# Security FAQ

Pre-answers to the questions a bank's security review asks. Every answer
below is grounded in what the codebase actually does, verifiable against the
cited files. Where the honest answer is "we don't have that yet," it is
written exactly that way — not omitted, not softened. A reviewer who catches
one evasion in a document like this discounts everything else in it, and is
right to.

This document describes the platform, Memtara — the cryptographic evidence
layer. It is verifiable AI decision evidence infrastructure: it produces
independently verifiable evidence that defined governance checks were
applied to a specific decision. It does not make an institution compliant,
and does not claim any control "operated" or that governance was
"effective" — those are judgments for the institution and its regulator, not
claims this platform makes.

---

## 1. Architecture

**What is it, in one paragraph?** A Rust/Axum backend (`backend/api/`)
backed by a single Postgres 15 database, plus a set of Noir zero-knowledge
circuits compiled to ACIR and proved/verified with Barretenberg (`bb`), an
open-source tool from the Noir/Aztec ecosystem that Memtara does not control
or license. The design goal: a client proves, on their own device, that
their private figures satisfy a bank-registered threshold — without those
figures ever being transmitted.

**How many decision types does this actually cover today?** Five circuits
are registered (`ALL_CIRCUITS`, `backend/api/src/verify/mod.rs`):
`emergency_session`, `ai_session`, `tax_session`, `identity_session`,
`wealth_suitability`. Only `wealth_suitability` has a complete pipeline — a
product registry, a dedicated evidence module, and a Canonical Case File
exporter. The other four verify proofs but have no equivalent evidence-pack
tooling built around them. Scope any security review to the specific
circuit(s) in your pilot, not the whole list.

**Is there a single point of trust in the middle?** For the cryptographic
verdict, no: the verification key for `wealth_suitability` is committed to
the repository (`circuits/wealth_suitability/vkey/vk`) specifically so an
examiner can re-verify a proof with `bb verify` without trusting Memtara's
build pipeline — and CI regenerates the key from the circuit on every run
and fails the build if it drifts. For the surrounding regulatory claim
(consent, human review, which policy version applied), yes today — those
facts currently live only in Memtara's Postgres and are fetched live. See
§8 for what closes that gap.

## 2. Where does data live

**Databases:** one Postgres instance. No analytics pipeline, no data
warehouse, no second data store. `backend/api/migrations/0001_init.sql`
is short enough to read end to end; every table is there.

**What is actually stored, table by table:**

| Data | Stored? | Where |
|---|---|---|
| Client name | No (default) | Pilot configuration leaves `display_name` null |
| Client phone / email | Yes / optional | `users.phone_e164`, `users.email` |
| Pseudonymous client identifier | Yes | `user_id` (UUID), used throughout |
| Passkey / device credentials | Yes, if used | `webauthn_credentials` |
| Session tokens | Yes, hashed | `sessions` |
| **Client income, liquid assets, risk tolerance, holdings value** | **No, never** | Proof witnesses that exist only on the client's device |
| Encrypted vault contents | Yes, ciphertext only | `vault_blobs.ciphertext` |
| Vault commitment (Poseidon hash) | Yes | `vault_blobs.vault_root` |
| Product/threshold registry | Yes | `products`, `wealth_requests` — the bank's data, not the client's |
| Suitability verdict | Yes | one bit, proof public inputs |
| Proof bytes and public inputs | Yes | `proofs` |
| Audit chain entries | Yes | `audit_log` — event type, pseudonymous `user_id`, timestamps, SHA-256 chain |

**The claim we make, precisely.** Memtara never receives the client's
financial figures. This is structural, not policy: generating a proof of
`income >= X` requires the plaintext income as a witness, and the server
never generates proofs — it only verifies them. A server that could produce
these proofs would, by definition, be a server holding plaintext, and this
one cannot.

**The claim we do not make, and you should reject from any vendor who
does.** That Memtara "holds no personal data." It holds the identifiers in
the table above. Anyone selling you a system with a `users` table and
telling you it holds no personal data has not read their own schema.

## 3. What leaves the customer's boundary

**Hosted deployment.** Data flows to Memtara's Postgres: tenant/org data,
product thresholds, proof bytes and public inputs, audit-log entries, and
the identifiers in the table above. Client financial figures never leave
the client's device by construction — there is no endpoint that accepts
them and no column that stores them.

**On-premise deployment.** Nothing leaves — the platform runs entirely on
your infrastructure. There is currently **no container image, no Helm
chart, and no packaged installer**; on-prem is a real engineering
engagement (Rust build toolchain, Postgres 15, `nargo`/`bb` on the host,
your own TLS termination and patching), measured in weeks, not a config
flag. Say this plainly rather than implying it is a checkbox.

**Telemetry, analytics, third-party calls.** None exist in the backend
dependency list — not disabled by a flag, absent. `grep -ri
"telemetry|analytics|sentry|posthog" backend/api/Cargo.toml` returns no
hits. The only external host in default configuration is the UAE Pass
identity provider, and that URL is one you set.

**Monitoring exposure.** `/metrics` (Prometheus) carries no tenant-
identifying label — no `org_id`, `user_id`, or product identifier — and a
test fails if one is ever added. Your monitoring scrape does not export a
tenant directory.

## 4. Key management

- **Issuer signing key.** Ed25519, loaded from `MEMTARA_PRIVATE_KEY`. The
  public half is published at `/.well-known/jwks.json`. `GET /health`
  returns 503 if the signing key's `kid` is not present in the JWKS the
  server itself publishes — it will not silently issue tokens nobody can
  verify.
- **Circuit verification keys.** Generated at boot into
  `backend/api/vkeys/` (gitignored, regenerated per deployment) for four of
  the five circuits. `wealth_suitability`'s key is additionally **committed
  to the repository** and CI-checked against a fresh build every run —
  this is the one key an examiner can check without trusting any build
  pipeline, ours included.
- **Client-side signing key (Baby Jubjub).** Lives in `vault.json` on the
  client/advisor device today, protected only by file-mode permissions.
  This is correct for an advisor terminal and wrong for a consumer phone —
  on a phone this key belongs in the Secure Enclave or Android Keystore.
  **That port is specified, not built** (`clients/prover/README.md`).
- **OTP codes.** Hashed with Argon2, never stored or logged in plaintext —
  **except** the default OTP provider, which is explicitly labelled
  dev-only in source and logs codes rather than sending them. **This must
  be replaced before any deployment carrying real client authentication.**
  Confirm at kickoff that it has been.
- **API keys.** Hashed at rest.
- **Vkey drift detection.** `GET /health` compares the running verification
  key against the published one and reports `DIVERGED` (503) if they
  differ — a drifted key verifies proofs perfectly well in isolation while
  silently making every proof it accepts today unverifiable by an examiner
  tomorrow, which is exactly why there is an automated check rather than a
  log line nobody reads.

## 5. Fail-closed behaviour

- **Boot time.** The server calls `verify::ensure_vkeys()` before it will
  start (`main.rs`); if `bb` is missing or a verification key fails to
  generate, the process does not come up half-working — it fails to start
  at all.
- **Per request.** If the verifier can't be spawned or a key is missing,
  the request errors (5xx); the server itself stays up, and no attestation
  or evidence is produced for that attempt.
- **`vault_root` mismatch.** If a submitted proof's committed vault root
  doesn't match what the client actually synced, the submission is
  rejected outright — no token minted, no attestation issued. This is
  deliberate: failing open here would mean issuing signed, hash-chained
  evidence of an assessment that measured the wrong person's figures.
- **Invalid proof does not burn the legitimate holder's nonce.** A failed
  submission doesn't consume the one-shot request nonce, so a third party
  can't grief a real user's single-use grant by submitting garbage first.
- **What is not built today.** There is no queue-and-replay, no degrade-to-
  human-with-marked-record mode, and no secondary/redundant verifier. Today
  is a single fail-closed path: block the request, record nothing for the
  attempt beyond a metric. A more graduated continuity model (explicit
  "deferred, service unavailable" evidence state) is designed but not
  implemented.
- **Multi-tenant isolation.** Every table is scoped by `org_id`; the
  product registry is keyed `(org_id, product_isin)` so two banks can list
  the same instrument with independent terms. There is an automated test
  that fails if one tenant can read another's registry or evidence
  (`test_one_banks_registry_is_invisible_to_another`,
  `tests/test_wealth_suitability_e2e.py`).

## 6. Dependencies and pinning

- **Noir toolchain — exactly pinned.** `nargo 1.0.0-beta.26`, `bb 5.1.0`,
  pinned identically in CI (`.github/workflows/ci.yml`) and
  `scripts/quickstart.sh`. The verifier target is fixed to `noir-recursive`
  in source, not configurable per deployment.
- **Rust crate dependencies — not exactly pinned.** `backend/api/Cargo.toml`
  specifies minor-version ranges (e.g. `axum = "0.7"`, `tokio = "1.35"`),
  and **there is no committed `Cargo.lock` in this repository.** This means
  the exact patch versions of Axum, Tokio, sqlx, `webauthn-rs`,
  `ed25519-dalek`, and the rest can float between builds in a way the
  cryptographic toolchain deliberately does not. **We don't have
  reproducible-build pinning at the Rust dependency layer yet** — the
  Noir/`bb` discipline has not been extended to `cargo`. If your review
  requires a signed SBOM or exact-hash dependency pinning across the whole
  stack, this is a real, open gap.
- **No telemetry/analytics/crash-reporting crate** in the dependency list
  (verified by grep, not just asserted).
- **Core dependency list:** Axum, Tokio, `tower`/`tower-http`, `sqlx`
  (Postgres 15), `webauthn-rs`, `ed25519-dalek`, `sha2`, `argon2`, `rand`,
  `chrono`, `uuid`. External binaries: `nargo`, `bb`.

## 7. Incident response

**We don't have a formal, written incident response plan yet.** There is a
contractual commitment we can offer — data-breach notification within a
stated window (a matter for the pilot agreement, not a standing policy
document) — but that is a promise, not evidence of a tested process.

**We don't have a production track record.** No prior production
deployment exists, therefore no uptime history, no status page, and no
incident log to point to. Any availability commitment offered in a
commercial agreement is a contractual promise with service credits, not a
measurement — say this explicitly rather than letting an SLA table imply
otherwise.

**What does exist:** an append-only, SHA-256 hash-chained audit log
(`audit_log`) that makes tampering with a record detectable — it proves
internal consistency, not availability. An operator with database access
can still delete the whole log; append-only storage and off-box
replication are the mitigations, and **neither is deployed in this
repository today** — they are the customer's to run, or a joint scoping
item for an on-prem deployment.

## 8. Known gaps — named plainly, not softened

This section exists because a security reviewer trusts a document more, not
less, for naming its own limits.

- **No SOC 2, no ISO 27001 certification, no independent penetration test.**
  We can commission a scoped, independent security review during a pilot
  and share the findings — that converts this from a permanent gap into a
  dated deliverable with your name on the scope, but it does not exist yet.
- **No container image, Helm chart, or packaged installer.** On-prem
  deployment is a genuine engineering engagement today, not a config flag.
- **Organisation self-registration is unauthenticated.** Anyone who can
  reach `POST /orgs` can mint a tenant. In any real deployment this
  endpoint must sit behind network controls or an allowlist — it is not
  gated in the product today.
- **The default OTP provider logs codes instead of sending them**, and is
  explicitly labelled dev-only in source. It must be replaced before any
  deployment handling real client authentication.
- **Rate limiting is per-process, not a security boundary.** Horizontally
  scaled instances multiply the effective limit. It bounds cost on the one
  genuinely expensive operation the server performs; a true global limit
  belongs at the edge or behind a shared store, and is not built.
- **No committed `Cargo.lock`; Rust dependencies are not exactly pinned.**
  See §6.
- **The exported case file's seal is unsigned today** — a detached SHA-256
  digest that is tamper-*evident* (any byte change is detectable) but not
  origin-*authenticated* (nothing proves who produced it). The strongest
  authenticity claim in a current export is the separate Ed25519 JWT
  attestation, verifiable against the published JWKS — not the PDF seal
  itself. Signing the seal is a scoped, buildable fix, not yet shipped.
  The exported pack states this limit on its own page rather than
  implying otherwise.
- **The published JWKS is not snapshotted into an offline evidence
  bundle today.** An examiner verifying a case file years from now, with
  no live AIHOOTS/Memtara service reachable, needs a pinned copy of the
  JWKS that was valid at issuance — this is designed but not yet built into
  the standard export. See `marketing/pilot/PILOT_OFFER.md`'s success
  criteria for the commitment to close this for pilot-scope decisions.
- **No per-decision `model` or `human_review` capture.** The evidence
  pipeline captures the cryptographic proof and the regulatory mapping
  strongly; it does not yet capture which AI model/version produced an
  upstream recommendation, or record a named human reviewer's
  approve/reject/override action per decision. This is the largest
  structural gap in the evidence schema today and is scoped, not built.
- **Only `wealth_suitability` pins the vault commitment to the client's
  actual synced vault.** The four older session circuits' Merkle proof
  shows consistency with *some* tree, not necessarily the client's
  committed one — a known, documented weakness of the older path.
- **Bias and disparate-impact measurement is not performed by this
  platform.** Narrowing what a model receives narrows what it can
  discriminate on directly; it does not detect a threshold that itself
  correlates with a protected class. This is a separate obligation the
  platform does not discharge.
- **No formal incident-response plan, no business-continuity/disaster-
  recovery plan, no production uptime history.** See §7.

---

*This document should be re-verified against the codebase before any
specific claim in it is relied on in a signed agreement — file paths and
line references are current as of this writing and will drift as the
codebase changes. Companion documents: `docs/REGULATORY_MATRIX.md`,
`docs/SALES_OBJECTION_HANDLER.md`, `docs/PILOT_AGREEMENT_TEMPLATE.md`,
`marketing/pilot/PILOT_AGREEMENT_OUTLINE.md`.*
