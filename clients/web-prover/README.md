# `web-prover` — the browser device prover

Generates a real zero-knowledge structured-product suitability proof inside a
browser tab, and submits it. This is `clients/prover/` (the Python CLI) ported
to the shape a consumer's actual device runs — see
`clients/prover/README.md`'s "WASM (the route a consumer app should take)"
section, which specifies exactly this port before it existed.

Before this directory existed, "the vault never leaves the device"
(`ARCHITECTURE.md`) was an architecture decision honoured only by a Python CLI
nobody's phone runs. `clients/web-prover/` is what makes it a product fact:
one HTML page, the four financial figures read from a local file and never
uploaded, a real Noir witness executed in-page, a real Barretenberg UltraHonk
proof generated in-page, and only `{request_id, public_inputs, proof}` ever
crossing the network.

Read `SPIKE.md` first — it records the versions this was built against and
why they were confirmed compatible with this workspace's pinned `nargo`/`bb`
before any of the code below was written.

## Layout

| Path | What |
|---|---|
| `index.html` | The page. Static HTML/CSS, one `<script type="module">`. |
| `src/babyjubjub.js` | Baby Jubjub EdDSA — a BigInt port of `clients/wealth_client.py`'s arithmetic. |
| `src/oracle.js` | Runs `circuits/witness_oracle`'s compiled ACIR via `noir_js` for every Poseidon value — see its header for why nothing here reimplements Poseidon. |
| `src/vault.js` | Reads and validates a vault file (same JSON shape `clients/prover/vault.py` writes) via `FileReader`, never `fetch`. |
| `src/request.js` | Parses the (non-secret) `issue-wealth-request` response a bank hands the device out of band. |
| `src/prove.js` | The pipeline: vault + request → witness → `noir_js` execute → `bb.js` UltraHonk proof. |
| `src/app.js` | DOM wiring. The only module that calls `fetch`, and it sends exactly one body shape. |
| `build.mjs` | Bundles `src/app.js` (and `noir_js`/`bb.js`) into `vendor/app.bundle.js` — see its header for why a bundler is needed here and not in `clients/auditor-console`. |
| `test/` | The e2e test — see below. |

## Build and run it

```bash
cd clients/web-prover
npm install
npm run build          # writes vendor/app.bundle.js (gitignored — a build artifact)
```

Then serve this directory and `circuits/target/` at `/circuits/` alongside it
— `test/static-server.mjs` does exactly that for the e2e test, and is a
reasonable thing to point a real static file server at too.

Open the page, choose a vault file (the format `clients/prover/memtara-prove
init-vault` writes), choose the JSON body a bank's
`POST /api/v1/issue-wealth-request` returned, paste a session token, and
generate.

## The e2e test

```bash
npm run test:e2e
```

Builds the bundle, builds and boots a real `memtara-api` against the Postgres
this repo's other tests use (`DATABASE_URL`, default
`postgres://memtara:memtara@localhost:5433/memtara`), registers a bank and a
product and a client with a synced vault through the real HTTP API, drives
the real page in a headless Chromium through Playwright, and asserts:

1. The proof is accepted — the live server's `/api/v1/submit-wealth-proof`
   (which itself runs `bb verify`) returns success, and the `wealth_requests`
   row in Postgres independently agrees.
2. **No witness value leaves the device.** Every request the page makes
   during the run is recorded by a Playwright network-level route handler,
   and the test asserts none of the recorded bodies contain any of the
   witness values this run's vault actually held (the four figures, the
   signing key, the Merkle authentication paths) — see `test/e2e.spec.mjs`'s
   header for exactly what that assertion does and does not claim.

Real proving inside the browser's same-thread WASM backend takes about 20
seconds for this circuit — most of this test's generous timeout budget is
`cargo build` and server boot, not proving. See `SPIKE.md`'s secondary
findings for why the backend is explicitly `BackendType.Wasm` rather than the
library's own default, and what that trades away (a blocked main thread; no
multi-threading).
