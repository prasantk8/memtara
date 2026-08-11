# Memtara — Handoff

You're continuing a build already in progress. Previous sessions hit context/
session limits, not dead ends — everything described as "done" below is
verified working, not just written. Read this whole file before touching
anything; it front-loads everything the earlier work had to discover the
hard way (exact crate versions, exact APIs, environment quirks) so you don't
have to rediscover it.

## What Memtara is

A zero-knowledge-proof identity vault. The core idea: someone should be able
to prove a specific fact about themselves — "I'm over 21," "my income is
above X," "I'm not on a sanctions list," "this is my blood type" — to a bank,
an AI assistant, a hospital, or a government counter, **without handing over
the underlying document or database record**. The proof is generated
entirely on the person's own device from their locally-encrypted vault; the
backend never sees plaintext.

Two real product surfaces are wireframed at
`web/reference/memtara_wireframes.tsx` (React/TSX, not wired to anything —
pure design reference): a bank compliance-analyst console and a consumer
mobile app. Read it — it's what the `disclosure`/`orgs` modules below exist
to serve, and it's the visual language (`docs/vision-flow.html` is the
published version of that same language, "confidential dossier" aesthetic —
warm paper, redaction bars, a verified stamp) later frontend work should
match.

Full product narrative: `ARCHITECTURE.md`, `README.md`, `TODO.md` at repo
root. `docs/vision-flow.html` is a design-team-facing artifact explaining the
proof flow with a worked example — worth a skim for the mental model.

## How to work

1. **One module at a time, in the order below.** Each has a real dependency
   on the last (disclosure needs auth's `AuthUser`; orgs needs disclosure's
   types). Don't parallelize across modules in one sitting.
2. **Verify before you call anything done**: `cargo build` with zero errors,
   `cargo test` passing, and for anything touching the database, a real test
   against the live Postgres (see Environment below) — not just a unit test
   that mocks the DB away. `backend/api/src/vault_sync/mod.rs` is the bar to
   match: it has actual concurrent-write tests that prove the
   optimistic-concurrency logic rejects a stale writer, not just that the
   code compiles.
3. **Don't guess library APIs.** Every crate version pinned in
   `backend/api/Cargo.toml` is already confirmed to compile (see exact
   versions below). If you add a new dependency or call something you're not
   sure about, either read the vendored source in
   `~/.cargo/registry/src/.../<crate>-<version>/` or fetch it from its
   GitHub repo at the matching tag — don't hallucinate a plausible-looking
   API and hope. This project's Noir/circuits work earlier hit real
   consequences from guessing (see `circuits/lib/src/signature_verify.nr`'s
   comment history) — empirical confirmation is faster than the
   compile-fail-guess-fail loop.
4. **Commit at the end of each completed module**, not before. Look at
   `git log` for the message style already established (what changed, why,
   what's verified — not just a file list).
5. **Report incrementally.** After each module: what you built, exact route
   list, exact build/test output, anything you deviated from this brief and
   why, anything you deliberately left as a TODO. Don't wait until
   everything is done to say anything.
6. **Don't touch**: `circuits/` or `vault/` (both complete, tested, and out
   of scope — the backend depends on `vault` by path, read it, don't edit
   it), the existing migration `backend/api/migrations/0001_init.sql`
   (schema is final for this pass — if you genuinely need a new column,
   stop and write a new migration file, never edit an applied one), anything
   under `docs/vision-flow.html` (published artifact, not this session's
   concern).

## Environment

```bash
# Rust toolchain
export PATH="$HOME/.cargo/bin:$PATH"
cargo --version   # 1.97.1 last confirmed

# Noir toolchain (for circuits/ — shouldn't need this for backend work,
# except the Verification Engineer needs the compiled circuit artifacts
# it produces)
export PATH="$HOME/.nargo/bin:$PATH"
nargo --version   # 1.0.0-beta.26 last confirmed

# Postgres — a DEDICATED container, already running, already migrated.
# Do not touch the OTHER running containers (apex-postgres on 5432,
# apex-redis, apex-orchestrator, etc.) — unrelated project, different port.
docker ps --filter name=memtara-postgres
# If it's not running: docker start memtara-postgres
# If it doesn't exist at all:
#   docker run -d --name memtara-postgres -e POSTGRES_USER=memtara \
#     -e POSTGRES_PASSWORD=memtara -e POSTGRES_DB=memtara -p 5433:5432 postgres:15

export DATABASE_URL="postgres://memtara:memtara@localhost:5433/memtara"

cd backend
cargo build   # must be zero errors before you move on from any module
cargo test    # 10/10 passing as of this handoff
sqlx migrate run   # only needed if you add a new migration file
```

Confirmed dependency versions (resolved, in `backend/Cargo.lock` — don't
fight the resolver into something else without reason):
`axum 0.7.9`, `sqlx 0.8.6`, `webauthn-rs 0.5.5`, `dashmap 6.2.1`,
`tokio 1.x`, `tower-http 0.5`, `argon2 0.5`, `base64 0.22`.

**Barretenberg (`bb`) is NOT installed yet** — the Verification Engineer
role needs it and will need to install it first (Aztec's installer, same
pattern as `noirup`/`nargo`):
```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup
bb --version   # confirm, don't assume
```
Confirm the exact `bb write_vk` / `bb verify` invocation empirically against
one of the compiled circuits before wiring the whole module around assumed
flags.

## Established conventions (follow these, don't reinvent)

- **Errors**: everything returns `ApiResult<T>` (`backend/api/src/error.rs`).
  Add new `ApiError` variants there if you need one; don't build a parallel
  error type.
- **"Enums" backed by Postgres TEXT + CHECK constraint, not native PG enum
  types.** Rust side: a plain enum with hand-written `as_str()` / `parse()`
  methods (see `backend/api/src/domain.rs` — `OrgType`, `CircuitType`,
  `DisclosureStatus`, `OtpChannel`). This was a deliberate choice over
  `sqlx::Type` derive macros to avoid depending on exact macro-attribute
  behavior for this sqlx version. Follow the same pattern for any new fixed
  set of string values.
- **Auth**: every handler that needs a logged-in user takes
  `AuthUser(user_id): AuthUser` as an argument (`backend/api/src/auth/`,
  re-exported as `auth::AuthUser`). It's an axum `FromRequestParts`
  extractor — just add it to your handler's signature, don't write your own
  auth check.
- **Session tokens are opaque and revocable, not JWTs** — random bytes,
  only `SHA-256(token)` stored server-side. This was a deliberate choice:
  the product needs instant revocation (e.g. "auto-expires in 14:59" in the
  wireframe) and JWT revocation is awkward. `disclosure_requests` and
  `proofs` should follow the same "can be killed by deleting/flagging a row"
  philosophy, not a signed-token-with-embedded-expiry philosophy.
- **Base64**: `base64::engine::general_purpose::URL_SAFE_NO_PAD`
  consistently (see `vault_sync/mod.rs`'s `encode_b64`/`decode_b64`). Match
  this in any new module that encodes bytes for JSON — don't introduce a
  second base64 convention.
- **Shared state**: `AppState` (`backend/api/src/state.rs`) — extend it,
  don't build a second parallel state struct. It already carries `db`,
  `config`, `webauthn`, `webauthn_ceremonies`, `otp_provider`,
  `uae_pass_provider`.
- **Policy format**: disclosure requests should serialize policy as
  `memtara_vault::session::SessionPolicy` (re-exported from
  `backend/api/src/domain.rs`) — this is the exact type `vault/` and the
  Noir circuits already agree on the shape of. Don't invent a second policy
  DTO; if `SessionPolicy` is missing a field you need, that's a real
  cross-cutting decision — surface it, don't route around it.
- **Tests**: prefer a real test against the live Postgres over a mock,
  where it's cheap to do (see `vault_sync`'s `mod db { ... }` tests — they
  skip gracefully if `DATABASE_URL` isn't reachable rather than failing the
  whole suite in an unconfigured environment).

## Status: verified done

- **`circuits/`** — 4 real Noir ZK circuits (`emergency_session`,
  `ai_session`, `tax_session`, `identity_session`) + shared `lib` (Merkle
  inclusion, predicates, EdDSA/Baby Jubjub signatures, time bounds). 39
  tests passing, all compile to real ACIR. Not touched by backend work.
- **`vault/`** — local-first encrypted vault (Rust). 14 tests passing. The
  backend depends on this crate by path for `session::SessionPolicy` et al.
  — not for storage (the backend stores opaque ciphertext the client
  already produced; it doesn't call `vault::encrypt`/`decrypt` itself).
- **`backend/` schema** — `backend/api/migrations/0001_init.sql`. All 10
  tables live and migrated: `users`, `webauthn_credentials`, `otp_codes`,
  `sessions`, `vault_blobs`, `organizations`, `disclosure_requests`,
  `proofs`, `used_nonces`, `audit_log`.
- **`backend/api/src/auth/`** — passkey register/login (webauthn-rs),
  WhatsApp/SMS OTP fallback (provider trait + dev-logging impl), UAE Pass
  OIDC login (provider trait + stub adapter — no real sandbox credentials
  available), opaque session tokens. Every route smoke-tested end-to-end
  with curl against a live server + Postgres, not just unit-tested.
- **`backend/api/src/vault_sync/mod.rs`** — `GET/PUT/DELETE /vault`,
  `GET /vault/root`. Optimistic concurrency (`expected_version`) verified
  with real concurrent writes against Postgres (8 racing writers, exactly 1
  wins — see `concurrent_cas_writes_only_one_winner_survives` test).

`cargo test` from `backend/`: **10/10 passing** as of this handoff.

## Status: remaining work, in order

### 1. Disclosure & Verification Engineer

Two modules, build together since verification is meaningless without a
request to verify against.

**`backend/api/src/disclosure/mod.rs`** — the `disclosure_requests` +
`used_nonces` lifecycle. Routes (org-authenticated — see note below on org
auth, which doesn't exist yet: for this module, stub org auth as a
`X-Org-Id: <uuid>` header you trust for now, and leave a clear `TODO: real
org API-key auth, see orgs/ module` comment; don't block this module on
orgs/ existing first):

- `POST /disclosure-requests` — org creates one: `{ user_id, circuit_type,
  policy: SessionPolicy, ttl_seconds }`. Generate a random nonce, set
  `expires_at = now + ttl_seconds`, `status = 'pending'`.
- `GET /disclosure-requests/:id` — fetch one (org that created it, or the
  user it's for — `AuthUser` for the user path, the header stub for the org
  path).
- `GET /disclosure-requests?user_id=...&status=pending` — a user's pending
  requests (this is what powers the wireframe's "Pending Request" card).
- `POST /disclosure-requests/:id/revoke` — mark `revoked`, only by the org
  that created it or the user it's for.
- A background sweep or lazy-check that flips `pending` → `expired` past
  `expires_at` (lazy check-on-read is fine for this pass — don't build a
  cron job).

**`backend/api/src/verify/mod.rs`** — proof verification.
- `POST /disclosure-requests/:id/proofs` — body: `{ public_inputs: [...],
  proof: base64 }`. Steps: look up the request (must be `pending`, not
  expired), extract the nonce from `public_inputs` per that circuit's
  public-input layout (see `circuits/<circuit_type>/src/main.nr` — the
  `fn main(...)` signature tells you the public input order; e.g.
  `emergency_session` has `current_time, vault_root, blood_type_hash,
  key_meds_hash, allergies_commitment, user_public_key_x, user_public_key_y,
  nonce` all marked `pub`), check `used_nonces` for `(org_id, nonce)` —
  reject as `ApiError::Conflict` if already used (this IS the replay
  defense `circuits/lib/src/time_bound.nr`'s design already commits to —
  read that file's comment block, it explains exactly why this table exists
  and what it's standing in for), shell out to `bb verify` against the
  right circuit's verification key, insert into `used_nonces` and `proofs`,
  flip the request to `fulfilled` on success.
- You'll need a vkey per circuit — generate once at startup or on first use
  via `bb write_vk` from each `circuits/<name>/target/<name>.json`, cache
  the vkey files somewhere sane (e.g. `backend/api/vkeys/`, gitignored,
  regenerated from `circuits/` rather than committed — they're a build
  artifact of `circuits/`, not source).
- Confirm the actual `bb` CLI surface empirically first (`bb --help`,
  `bb write_vk --help`, `bb verify --help`) rather than assuming flag names.

### 2. Orgs & Audit Engineer

**`backend/api/src/orgs/mod.rs`** — relying-party accounts (banks, AI
platforms, hospitals, government counters — matches `organizations.org_type`
CHECK constraint). Real API-key auth this time (replace the disclosure
module's header stub — go back and wire disclosure's routes to use this once
it exists, note that explicitly in your report). Routes: create an org
(returns a one-time-shown API key, store only its hash), an org-auth
extractor (`OrgAuth` or similar, mirroring `AuthUser`'s pattern — read
`auth/session_token.rs` for the extractor shape to match), list an org's
disclosure requests + proof results (this is the data
`EnterpriseBankView` in the wireframe needs — "Compliance Analyst Portal").

**`backend/api/src/audit/mod.rs`** — hash-chained append-only log
(`audit_log` table). `event_hash = H(event_type || ref_id || prev_hash ||
payload)`, `prev_hash` = the previous row's `event_hash` (global chain, or
per-org chain — your call, document which and why). Write an entry on every
meaningful event from the modules above (disclosure created, proof verified,
session revoked, etc. — go back and add the call sites in `disclosure/` and
`verify/`, note that as part of this module's diff even though the files
touched are elsewhere). Expose `GET /orgs/:id/audit-log` for the org to pull
its own trail (backs the wireframe's STR-narrative audit story).

### 3. Journeys writer

`docs/journeys.md` — spec (not code) for UAE-resident user journeys beyond
the two wireframed ones (bank AML/STR clearance, mortgage pre-approval).
Format per journey: actor → trigger → disclosed predicate → which circuit
(`emergency_session`/`ai_session`/`tax_session`/`identity_session`) → auth
path → UI touchpoint. Cover both tech-savvy HNWI journeys (Golden Visa /
investor compliance proof, real-estate proof-of-funds, accredited-investor
certification, family-office succession disclosure) and non-tech-savvy
journeys (assisted emergency card via physical NFC/QR, government-counter
staff-assisted proof at an Amer/Tasheel-style center — Arabic-first,
icon/voice-guided, minimal reading required). This is a writing task, not an
implementation task — sonnet-tier effort is fine, don't overthink model
choice here.

### 4. End-to-end verification pass

Once all of the above compiles and its own tests pass: register a fake org →
create a disclosure request → hand-craft a proof using one of the circuits'
own test fixtures (`circuits/*/src/main.nr` `mod tests` blocks have working
examples — don't try to build a real client-side prover for this, that's
explicitly out of scope, see below) → POST it to `verify/` → confirm
`valid=true`, a `used_nonces` row exists, an `audit_log` entry was written →
POST the same proof again → confirm it's rejected as a replay. Report the
exact commands and output.

## Explicitly out of scope (don't drift into these)

- Any actual web/mobile frontend — `web/reference/memtara_wireframes.tsx` is
  reference only.
- Real UAE Pass / SMS-provider credentials — stub adapters stay stubs.
- **Client-side proof generation** (NoirJS/WASM or native) — the backend
  only ever verifies. If you find yourself writing code that generates a
  proof from plaintext vault data server-side, stop — that breaks the
  zero-knowledge guarantee the whole product is built on. Test proofs come
  from the circuits' own fixed test vectors, not from live-generating one
  server-side.
