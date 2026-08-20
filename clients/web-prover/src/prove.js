// The proving pipeline — the in-browser counterpart of
// `clients/wealth_client.py`'s `generate_proof`. Given a parsed vault and a
// parsed assessment request, this produces exactly the two things
// `POST /api/v1/submit-wealth-proof` needs: `public_inputs` and `proof`.
// Every witness value (the four figures, the signing key, the Merkle paths)
// stays inside this module's call stack and is never returned, logged, or
// serialized — see `app.js` for the boundary that enforces that only
// `{request_id, public_inputs, proof}` crosses into a `fetch` call.
//
// Same circuit, same verifier target, same public-input layout as the
// server checks (`backend/api/src/verify/mod.rs::public_input_layout` /
// `wealth::mod.rs::submit_wealth_proof`) — this module does not choose any
// of those independently; it is bound to match them or every proof it
// produces fails `bb verify`.

import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';

import { WitnessOracle } from './oracle.js';
import * as bjj from './babyjubjub.js';
import { vaultLeaves, expectedVerdict } from './vault.js';

export class ProvingError extends Error {}

// Fixed protocol choice — see backend/api/src/verify/mod.rs's
// `BB_VERIFIER_TARGET` comment. A proof produced under any other target
// verifies nothing this system accepts.
const VERIFIER_TARGET = 'noir-recursive';

function hex32(value) {
  return '0x' + value.toString(16).padStart(64, '0');
}

/** Progress callback shape: `onProgress(stepName)`, called before each named
 * stage so the page can show something better than a spinner during the
 * several seconds real proof generation takes. */
export async function generateProof({ vault, request, oracleCircuit, wealthCircuit, onProgress = () => {} }) {
  const step = (name) => {
    onProgress(name);
    return name;
  };

  step('building the Merkle tree over your vault (in this tab, via a compiled Noir circuit)');
  const oracle = new WitnessOracle(oracleCircuit);
  const leaves = vaultLeaves(vault.figures);
  const { root: vaultRoot, pathFor } = await oracle.merkle(leaves);

  const now = BigInt(Math.floor(Date.now() / 1000));
  const currentTime = now >= request.windowStart && now <= request.windowEnd ? now : request.windowStart;
  if (currentTime < request.windowStart || currentTime > request.windowEnd) {
    throw new ProvingError(
      `this assessment's window [${request.windowStart}, ${request.windowEnd}] has already closed; ` +
        'ask the bank to open a new one',
    );
  }

  step('computing the policy commitment');
  const commitment = await oracle.policyCommitment({
    currentTime,
    startTime: request.windowStart,
    expiryTime: request.windowEnd,
    vaultRoot,
    productRef: request.productRef,
    minIncome: request.minIncome,
    minLiquidity: request.minLiquidity,
    maxConcentrationPercent: request.maxConcentrationPercent,
    productRiskLevel: request.productRiskLevel,
    nonce: request.nonce,
  });

  step('signing the commitment with your device key (the key never leaves this tab)');
  const keypair = bjj.keypairFromSeed(vault.signingKeySeed);
  const signingNonce = bjj.randomScalar();
  const { r8, s } = await bjj.sign(keypair, commitment, signingNonce, (...args) => oracle.eddsaChallenge(...args));

  const inputs = {
    current_time: currentTime.toString(),
    start_time: request.windowStart.toString(),
    expiry_time: request.windowEnd.toString(),
    vault_root: vaultRoot.toString(),
    product_ref: request.productRef.toString(),
    income: BigInt(vault.figures.income).toString(),
    liquid_assets: BigInt(vault.figures.liquid_assets).toString(),
    risk_tolerance: BigInt(vault.figures.risk_tolerance).toString(),
    existing_holdings_value: BigInt(vault.figures.existing_holdings_value).toString(),
    income_index: '0',
    income_path: pathFor(0).map(String),
    liquid_assets_index: '1',
    liquid_assets_path: pathFor(1).map(String),
    risk_tolerance_index: '2',
    risk_tolerance_path: pathFor(2).map(String),
    existing_holdings_index: '3',
    existing_holdings_path: pathFor(3).map(String),
    min_income: request.minIncome.toString(),
    min_liquidity: request.minLiquidity.toString(),
    max_concentration_percent: request.maxConcentrationPercent.toString(),
    product_risk_level: request.productRiskLevel.toString(),
    user_public_key_x: keypair.public[0].toString(),
    user_public_key_y: keypair.public[1].toString(),
    signature_r8_x: r8[0].toString(),
    signature_r8_y: r8[1].toString(),
    signature_s: s.toString(),
    nonce: request.nonce.toString(),
  };

  step('executing the suitability circuit over your vault (nothing leaves this tab)');
  const wealthNoir = new Noir(wealthCircuit);
  let witness, returnValue;
  try {
    ({ witness, returnValue } = await wealthNoir.execute(inputs));
  } catch (e) {
    // An unsatisfied constraint here means the witness genuinely does not
    // satisfy the circuit (a figure not in the vault, a bad signature, a
    // closed window) — not a tooling problem. Surface noir_js's own message,
    // mirroring wealth_client.py's `_execute_and_prove`.
    throw new ProvingError(`circuit execution failed: ${e.message || e}`);
  }
  const suitableField = BigInt(returnValue);
  if (suitableField !== 0n && suitableField !== 1n) {
    throw new ProvingError(`circuit output was ${suitableField}, expected a boolean`);
  }
  const suitable = suitableField === 1n;

  // Cross-check against an independent evaluation of the same four limbs,
  // computed without touching the circuit at all — mirrors
  // `clients/prover/cli.py`'s check before it will submit anything. Two
  // independent implementations agreeing is weak evidence; two disagreeing
  // is conclusive, and here is the right place to find out: before anything
  // is signed or sent.
  const expected = expectedVerdict(vault.figures, {
    minIncome: Number(request.minIncome),
    minLiquidity: Number(request.minLiquidity),
    maxConcentrationPercent: Number(request.maxConcentrationPercent),
    productRiskLevel: Number(request.productRiskLevel),
  });
  if (expected !== suitable) {
    throw new ProvingError(
      `the circuit answered ${suitable} but an independent evaluation of the same terms answered ` +
        `${expected}. Refusing to submit — this would be a bug in the circuit or in this page's ` +
        'independent check, and it must not reach the bank unresolved.',
    );
  }

  step('generating the zero-knowledge proof (this can take several seconds)');
  // `backend: BackendType.Wasm` explicitly, not the default. `Barretenberg
  // .new()`'s default backend order in a browser tries `WasmWorker` first —
  // a Web Worker driven over `SharedArrayBuffer` — even with `threads: 1`,
  // and `SharedArrayBuffer` is only available when the page is served with
  // `Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy` isolation
  // headers, which this static page does not require its host to set.
  // Without it, the worker path still "works" but every call marshals
  // copies across a `postMessage` boundary instead of sharing memory —
  // confirmed empirically to be dramatically slower than the plain
  // same-thread `Wasm` backend for this circuit, to the point of looking
  // hung rather than merely slow. `BackendType.Wasm` runs on the page's own
  // thread with no worker at all, which also sidesteps the separate
  // `main.worker.js`/`thread.worker.js` bundling gap noted in SPIKE.md.
  // The honest cost: the page's main thread blocks for the duration of
  // proving, same as `WasmWorker` would if isolation headers were present
  // and it were actually fast — a UI-responsiveness follow-up, not a
  // correctness one.
  const api = await Barretenberg.new({ threads: 1, backend: BackendType.Wasm });
  let proofData;
  try {
    const backend = new UltraHonkBackend(wealthCircuit.bytecode, api);
    proofData = await backend.generateProof(witness, { verifierTarget: VERIFIER_TARGET });
  } finally {
    await api.destroy();
  }

  // `bb.js` returns public inputs as decimal/hex strings already in circuit
  // order; re-render each to the fixed-width `0x`-prefixed hex the server's
  // `parse_field_hex` expects (backend/api/src/verify/mod.rs), rather than
  // trust the library's own formatting to already match.
  const publicInputs = proofData.publicInputs.map((s) => hex32(BigInt(s)));

  return {
    publicInputs,
    proofBytes: proofData.proof,
    suitable,
    vaultRoot,
  };
}

/** Base64url, no padding — the encoding `submit_wealth_proof` expects for
 * `proof` (backend/api/src/wealth/mod.rs's `SubmitWealthProofBody`). */
export function encodeProofBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
