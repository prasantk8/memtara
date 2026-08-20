# Spike: can a browser tab produce a proof `bb verify` accepts?

Written before any product code in this directory, per the stage plan's
spike gate for workstream D. The question: at versions of `@noir-lang/noir_js`
and `@aztec/bb.js` compatible with the `nargo`/`bb` this workspace's
`circuits/wealth_suitability/vkey/vk` was compiled and written with, can a
browser-shaped JS runtime (1) execute the committed
`circuits/wealth_suitability` ACIR to a witness, and (2) produce an UltraHonk
proof that the server's own `bb verify -t noir-recursive` invocation
(`backend/api/src/verify/mod.rs`) accepts?

## Versions

Pinned toolchain this workspace compiled against (`scripts/quickstart.sh`):

```
NARGO_VERSION="1.0.0-beta.26"
BB_VERSION="5.1.0"
```

Confirmed installed and on `PATH` during this spike:

```
$ nargo --version
nargo version = 1.0.0-beta.26
noirc version = 1.0.0-beta.26+40d6574f851d926f93e0c3a271bac3e6e82ac905

$ bb --version
5.1.0
```

npm packages used, at **exact** matching versions (not `^`-ranged — both
exist on the registry at exactly the nargo/bb version strings above, so no
approximation was needed):

```
@noir-lang/noir_js@1.0.0-beta.26
@aztec/bb.js@5.1.0
```

`@noir-lang/noir_js@1.0.0-beta.26`'s own `dependencies` pin
`@noir-lang/acvm_js`, `@noir-lang/noirc_abi` and `@noir-lang/types` to the
identical `1.0.0-beta.26` — i.e. npm's own dependency resolution agrees this
is the matching JS toolchain for `nargo 1.0.0-beta.26`, not just a version
string picked by hand.

## What was tried

A witness for `circuits/wealth_suitability` requires a genuine Baby Jubjub
EdDSA signature and several Poseidon-BN254 hashes (the Merkle tree, the
policy commitment, the EdDSA challenge) — there is no way to produce a valid
proof without them; an all-zero signature is what `main.nr`'s own test module
uses precisely because it is rejected. The spike therefore had to port
`clients/wealth_client.py`'s Baby Jubjub arithmetic to JS (`src/babyjubjub.js`
does this in the shipped client — see its header for why this is a safe port:
the field/curve arithmetic is ordinary BigInt math, copied from the same
`circuits/lib/src/signature_verify.nr` constants `wealth_client.py` copies
from) and, for Poseidon, execute `circuits/witness_oracle`'s compiled ACIR
through `noir_js` — the exact WASM substitution
`clients/prover/README.md`'s porting table names for `nargo execute over
witness_oracle`.

Script: a standalone Node harness (not committed — this is what it did,
reproduced here for the record):

1. `new Noir(witness_oracle.json).execute({op: "0", inputs: [...16 leaves]})`
   → Merkle root + authentication paths for the four wealth-vault slots.
2. `new Noir(witness_oracle.json).execute({op: "1", inputs: [...]})` → the
   policy commitment, exactly as `wealth_suitability::main` composes it.
3. Baby Jubjub sign the commitment (JS port), then
   `new Noir(witness_oracle.json).execute({op: "2", inputs: [...]})` for the
   EdDSA challenge hash `h`.
4. `new Noir(wealth_suitability.json).execute({...the full 26-parameter
   witness...})` → a real witness and the circuit's own `suitable` return
   value.
5. `const api = await Barretenberg.new({threads: 4});`
   `const backend = new UltraHonkBackend(wealthCircuit.bytecode, api);`
   `const proofData = await backend.generateProof(witness, {verifierTarget:
   'noir-recursive'});`
   — `verifierTarget: 'noir-recursive'` in `@aztec/bb.js@5.1.0`'s
   `UltraHonkBackendOptions` is the exact same named target as the CLI's
   `-t noir-recursive` (`UltraHonkBackendOptions`'s own doc comment gives
   `'noir-recursive'` as "For recursive verification in Noir" — the string is
   not a guess, it is read out of `node_modules/@aztec/bb.js/dest/node/
   barretenberg/backend.d.ts`).
6. `proofData.proof` (raw bytes) and `proofData.publicInputs` (12 hex
   strings, circuit order) written to `proof` / `public_inputs` files in
   **exactly** the layout `backend/api/src/verify/mod.rs::run_bb_verify_inner`
   writes them (32-byte big-endian fields, concatenated, no framing).
7. Shelled out to the **real, installed** `bb 5.1.0` binary:
   `bb verify -i public_inputs -p proof -k circuits/wealth_suitability/vkey/vk
   -t noir-recursive` — the committed vkey, not a regenerated one, per that
   directory's own README on why it's committed (an examiner must be able to
   check a proof against a key that never touched Memtara's build pipeline).

## Result

```
Scheme is: ultra_honk, num threads: 16 (mem: 11.08 MiB)
Proof verified successfully (mem: 13.12 MiB)
```

**Accepted.** Exit code 0, the same success line `bb verify` prints for any
proof it accepts. `@aztec/bb.js@5.1.0`'s own native `backend.verifyProof(...)`
also returned `true` on the same proof before it was ever handed to the CLI,
so this was checked twice by two independent code paths (bb.js's own WASM
verifier, then the real native `bb` binary) and agreed both times.

Witness execution: `noir_js@1.0.0-beta.26` executed both
`circuits/target/witness_oracle.json` and
`circuits/target/wealth_suitability.json` — the same compiled ACIR the
backend and `clients/prover` use, not a recompiled copy — without error, and
the circuit's own return value (`suitable = 1`) matched an independent
Python-shaped evaluation of the same four limbs (mirrors the cross-check
`clients/prover/cli.py` performs before submitting).

## What this means for the rest of workstream D

The spike succeeded outright: no version mismatch, no ACIR incompatibility,
no proving-target disagreement. `clients/web-prover/` was built on top of
this exact pipeline — same circuit files, same `noir-recursive` target, same
public-input byte layout — ported into `src/oracle.js`, `src/babyjubjub.js`
and `src/prove.js`, and driven from a browser tab (not Node) in
`test/e2e.spec.mjs`, where it is proven against a **live** backend server
rather than only the CLI.

Three secondary findings surfaced while building the browser page, none of
which is a version incompatibility and none of which blocks anything —
all three are resolved in the code that ships in this directory:

1. **`acvm_js`/`noirc_abi`'s WASM binaries load via `new URL('foo_bg.wasm',
   import.meta.url)`** — a *bare* relative reference (no leading `./`) that
   `esbuild`'s static asset pipeline does not rewrite (confirmed empirically:
   `grep "new URL(" vendor/app.bundle.js` after a build shows both left
   untouched). Because that resolves at runtime relative to the bundle's own
   URL, the fix is to place the two `.wasm` files as siblings of
   `vendor/app.bundle.js` rather than teach esbuild the pattern — `build.mjs`
   does this by copying them from `node_modules` at build time. This is a
   packaging detail, not a cryptographic one.
2. **The default browser backend looked hung, not slow.**
   `Barretenberg.new({threads: 1})` with no explicit `backend` still
   defaulted to `BackendType.WasmWorker` — a Web Worker driven over
   `SharedArrayBuffer` — and `SharedArrayBuffer` is only available when the
   page is served with `Cross-Origin-Opener-Policy`/
   `Cross-Origin-Embedder-Policy` isolation headers, which this static page
   does not require of its host. Without those headers the worker path still
   runs, but every call marshals a copy across a `postMessage` boundary
   instead of sharing memory: a full end-to-end run (vault → witness → proof
   → submit) that should take well under a minute was still going at
   **5+ minutes** and climbing when killed. Measured directly, not guessed at
   — see the timestamps in this repository's work log for that run. Passing
   `backend: BackendType.Wasm` explicitly (same-thread, no worker at all)
   fixed it outright: the identical run, same circuit, same browser,
   completed in **~20 seconds**. `src/prove.js` sets this explicitly, with
   the reasoning recorded in its own comment, rather than leaving a future
   reader to rediscover it by killing a "hung" process.
3. **Multi-threaded proving needs its own worker bundle**, which is now moot
   for the reason above — `BackendType.Wasm` never spawns a worker, so there
   is no `main.worker.js`/`thread.worker.js` bundling gap to close. A future
   pass that wants multi-threaded proving (faster, at the cost of requiring
   COOP/COEP isolation headers from whatever serves this page, plus bundling
   the two worker entry points) would need to revisit this — recorded here so
   that work starts from the actual reason single-threaded was chosen, not
   a guess at one.

No coordinator escalation was needed: nothing here required recompiling a
circuit or bumping a pinned toolchain version.
