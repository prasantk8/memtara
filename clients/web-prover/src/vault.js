// The in-browser reading of a vault file — the JS-side counterpart of
// `clients/prover/vault.py`. Same format, same four figures, same signing
// key, same refusal to guess at a malformed field: a vault carrying
// `liquid_asets` fails loudly here exactly as it does there, rather than
// silently proving against a liquid_assets of zero.
//
// The one thing this module does that the Python one cannot: it never touches
// a filesystem. The caller hands it the `File` object straight from an
// `<input type="file">`, it is read with `FileReader` entirely in page
// memory, and the parsed figures and signing key never leave this module
// except as arguments to the local proving pipeline in `prove.js`. See
// `app.js` for the file input wiring and the UI copy that says as much.

export const VAULT_VERSION = 1;
export const FIGURE_NAMES = ['income', 'liquid_assets', 'risk_tolerance', 'existing_holdings_value'];

// Leaf slots in the wealth category of the vault tree — fixed positions,
// matching circuits/wealth_suitability/src/main.nr's test module and
// clients/wealth_client.py's INCOME_SLOT / LIQUID_SLOT / RISK_SLOT /
// HOLDINGS_SLOT.
export const INCOME_SLOT = 0;
export const LIQUID_SLOT = 1;
export const RISK_SLOT = 2;
export const HOLDINGS_SLOT = 3;
export const TREE_LEAVES = 16;

export class VaultError extends Error {}

function isPlainInteger(v) {
  return typeof v === 'number' && Number.isInteger(v);
}

function validateFigures({ income, liquid_assets, existing_holdings_value, risk_tolerance }) {
  for (const [name, value] of [
    ['income', income],
    ['liquid_assets', liquid_assets],
    ['existing_holdings_value', existing_holdings_value],
  ]) {
    if (value < 0) throw new VaultError(`\`${name}\` must not be negative`);
    // The circuit takes u64. A figure above that is not a vault a proof can
    // be generated from — caught here, exactly as vault.py's
    // `_validate_figures` catches it, rather than several seconds into
    // circuit execution.
    if (BigInt(value) >= 2n ** 64n) throw new VaultError(`\`${name}\` exceeds the u64 the circuit accepts`);
  }
  if (!(risk_tolerance >= 1 && risk_tolerance <= 5)) {
    throw new VaultError('`risk_tolerance` must be between 1 and 5 (the scale the circuit asserts)');
  }
}

/** Parse and validate a vault document already decoded from JSON (the
 * `{version, user_id, signing_key_seed, figures}` shape `clients/prover/
 * vault.py` writes). Returns `{userId, figures, signingKeySeed}` with
 * `signingKeySeed` as a BigInt, ready for `babyjubjub.keypairFromSeed`. */
export function parseVaultDocument(document) {
  if (document.version !== VAULT_VERSION) {
    throw new VaultError(`vault declares version ${JSON.stringify(document.version)}; this page understands ${VAULT_VERSION}`);
  }
  const figures = document.figures;
  if (typeof figures !== 'object' || figures === null || Array.isArray(figures)) {
    throw new VaultError('vault has no `figures` object');
  }
  const present = Object.keys(figures);
  const unknown = present.filter((k) => !FIGURE_NAMES.includes(k));
  if (unknown.length > 0) {
    throw new VaultError(`vault has unknown figures: ${unknown.sort().join(', ')}`);
  }
  const missing = FIGURE_NAMES.filter((k) => !present.includes(k));
  if (missing.length > 0) {
    throw new VaultError(`vault is missing figures: ${missing.sort().join(', ')}`);
  }
  const values = {};
  for (const name of FIGURE_NAMES) {
    const v = figures[name];
    if (!isPlainInteger(v)) {
      throw new VaultError(`vault: \`${name}\` must be an integer, got ${JSON.stringify(v)}`);
    }
    values[name] = v;
  }
  validateFigures(values);

  const seedHex = document.signing_key_seed;
  if (typeof seedHex !== 'string' || seedHex.length === 0) {
    throw new VaultError('vault has no `signing_key_seed`');
  }
  let signingKeySeed;
  try {
    signingKeySeed = BigInt('0x' + seedHex.replace(/^0x/i, ''));
  } catch {
    throw new VaultError('vault: `signing_key_seed` is not hexadecimal');
  }

  return {
    userId: document.user_id ?? null,
    figures: values,
    signingKeySeed,
  };
}

/** Read a `File` (from a file input or drag-and-drop) with `FileReader` and
 * parse it as a vault document. Never touches `fetch`/`XMLHttpRequest` — the
 * bytes go from disk into page memory and no further, which is the whole
 * point of this function existing separately from a generic JSON fetch. */
export function readVaultFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new VaultError(`could not read ${file.name}: ${reader.error}`));
    reader.onload = () => {
      let document;
      try {
        document = JSON.parse(reader.result);
      } catch (e) {
        reject(new VaultError(`${file.name} is not valid JSON: ${e.message}`));
        return;
      }
      try {
        resolve(parseVaultDocument(document));
      } catch (e) {
        reject(e);
      }
    };
    reader.readAsText(file);
  });
}

/** The 16-leaf array the vault tree commits to: the four wealth figures in
 * their reserved slots, zero everywhere else — mirrors
 * `WealthVault.leaves()`. */
export function vaultLeaves(figures) {
  const leaves = new Array(TREE_LEAVES).fill(0n);
  leaves[INCOME_SLOT] = BigInt(figures.income);
  leaves[LIQUID_SLOT] = BigInt(figures.liquid_assets);
  leaves[RISK_SLOT] = BigInt(figures.risk_tolerance);
  leaves[HOLDINGS_SLOT] = BigInt(figures.existing_holdings_value);
  return leaves;
}

/** What the circuit should conclude, evaluated independently of it —
 * mirrors `WealthVault.expected_verdict`. Used the same way
 * `clients/prover/cli.py` uses the Python original: as a second opinion the
 * proving pipeline refuses to disagree with silently. */
export function expectedVerdict(figures, terms) {
  const total = figures.liquid_assets + figures.existing_holdings_value;
  return (
    figures.income >= terms.minIncome &&
    figures.liquid_assets >= terms.minLiquidity &&
    figures.risk_tolerance >= terms.productRiskLevel &&
    figures.existing_holdings_value * 100 <= terms.maxConcentrationPercent * total
  );
}
