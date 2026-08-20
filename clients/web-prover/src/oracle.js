// The witness oracle, run in-page.
//
// `circuits/witness_oracle` exists so an off-device prover never has to
// reimplement Poseidon-BN254 — see that circuit's own header for the full
// argument, and `clients/wealth_client.py`'s `NargoOracle` for the CLI-shaped
// version of exactly this idea, which shells out to `nargo execute`. There is
// no shell in a browser tab, so this module gets the same deterministic
// Poseidon values by executing the identical compiled ACIR through
// `noir_js`'s `Noir.execute` instead — the WASM substitution
// `clients/prover/README.md`'s porting table describes for `nargo execute`.
// Same circuit, same bytecode, same answers; only the host differs.

import { Noir } from '@noir-lang/noir_js';

/** Wraps one compiled `witness_oracle` circuit (the parsed
 * `circuits/target/witness_oracle.json`). `op` and `inputs` mirror
 * `circuits/witness_oracle/src/main.nr`'s own `main(op: u32, inputs: [Field;
 * 16]) -> pub [Field; 17]` exactly — see that file's header comment for what
 * each op means. */
export class WitnessOracle {
  constructor(compiledCircuit) {
    this._noir = new Noir(compiledCircuit);
  }

  async _run(op, inputs) {
    if (inputs.length > 16) {
      throw new Error(`witness oracle takes at most 16 inputs, got ${inputs.length}`);
    }
    const padded = inputs.concat(Array(16 - inputs.length).fill(0n));
    const { returnValue } = await this._noir.execute({
      op: op.toString(),
      inputs: padded.map((v) => v.toString()),
    });
    return returnValue.map((v) => BigInt(v));
  }

  /** op 0: the Poseidon Merkle root over 16 leaves, plus the authentication
   * paths for the first four (the wealth vault's reserved slots). Returns
   * `{root, pathFor(slot)}`, mirroring `NargoOracle.merkle`'s
   * `(root, paths)` return shape. */
  async merkle(leaves) {
    if (leaves.length !== 16) {
      throw new Error(`the vault tree has 16 leaves, got ${leaves.length}`);
    }
    const out = await this._run(0, leaves);
    const root = out[0];
    const pathFor = (slot) => out.slice(1 + slot * 4, 5 + slot * 4);
    return { root, pathFor };
  }

  /** op 1: the suitability policy commitment, exactly as
   * `wealth_suitability`'s `main` composes it — see that circuit's header,
   * "WHAT BINDS THE WITNESSES DOWN". */
  async policyCommitment(terms) {
    const [commitment] = await this._run(1, [
      terms.currentTime,
      terms.startTime,
      terms.expiryTime,
      terms.vaultRoot,
      terms.productRef,
      terms.minIncome,
      terms.minLiquidity,
      terms.maxConcentrationPercent,
      terms.productRiskLevel,
      terms.nonce,
    ]);
    return commitment;
  }

  /** op 2: the EdDSA challenge hash `h = Poseidon(R8.x, R8.y, A.x, A.y,
   * message)`, exactly as `signature_verify::eddsa_verify` computes it. Bound
   * as `babyjubjub.js`'s `sign()`'s `challenge` callback. */
  async eddsaChallenge(r8x, r8y, pkx, pky, message) {
    const [h] = await this._run(2, [r8x, r8y, pkx, pky, message]);
    return h;
  }
}
