// Baby Jubjub EdDSA — a line-for-line port of clients/wealth_client.py's
// arithmetic (`point_add`, `point_mul`, `Keypair`, `sign`) to browser
// BigInt.
//
// Why a port rather than a shared implementation: `wealth_client.py` shells
// out to nothing for this part (see its own header — the curve arithmetic is
// "integer maths in the standard library"), precisely so a second language
// can reproduce it without a native dependency. That is exactly the
// situation this module is in. The constants below are the same Baby Jubjub
// parameters, copied from the same source of truth
// (`circuits/lib/src/signature_verify.nr`) that `wealth_client.py` copies
// them from — not re-derived, so the two implementations cannot drift by
// transcription error in only one of them.
//
// What is NOT ported here: Poseidon. `wealth_client.py` refuses to
// reimplement Poseidon-BN254 in Python and delegates every hash to the
// circuits' own library via `nargo execute` over `witness_oracle`
// (see that circuit's header for the full argument). This module makes the
// same choice, delegating to `oracle.js`, which runs the identical
// `witness_oracle` ACIR through `noir_js` instead of a subprocess — the WASM
// substitution `clients/prover/README.md` describes as "the route a
// consumer app should take."

// Baby Jubjub base field modulus (BN254 scalar field).
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const A = 168700n;
const D = 168696n;

// Generator * 8 (cofactor-cleared base point) and the prime subgroup order.
// Copied from circuits/lib/src/signature_verify.nr's BASE8_X / BASE8_Y /
// SUBORDER — the verifier's own constants, not re-derived.
export const BASE8 = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];
export const SUBORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function invmod(a, m) {
  // Extended Euclidean algorithm. `a` is always invertible here: `m` is
  // prime (P or SUBORDER) and `a` is a nonzero residue by construction of
  // every call site below.
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return mod(oldS, m);
}

/** Twisted Edwards addition. Complete — no special case for doubling or the
 * identity, which is why this curve (rather than, say, Ed25519's Edwards
 * form used the ordinary way) is convenient for in-circuit work; ported
 * unchanged from `wealth_client.py`'s `point_add`. */
export function pointAdd([x1, y1], [x2, y2]) {
  const x1x2 = mod(x1 * x2, P);
  const y1y2 = mod(y1 * y2, P);
  const dxy = mod(D * x1x2 * y1y2, P);
  const x3 = mod((x1 * y2 + y1 * x2) * invmod(1n + dxy, P), P);
  const y3 = mod((y1y2 - A * x1x2) * invmod(1n - dxy, P), P);
  return [x3, y3];
}

/** Double-and-add. Not constant-time, and — exactly as `wealth_client.py`
 * notes at `point_mul` — it does not need to be: this runs on the holder's
 * own device over the holder's own key, with no attacker-observable timing
 * channel between them. */
export function pointMul(p, k) {
  let result = [0n, 1n]; // the identity on a twisted Edwards curve
  let addend = p;
  k = mod(k, SUBORDER);
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

export function onCurve([x, y]) {
  return mod(A * x * x + y * y - 1n - ((D * x * x * y * y) % P), P) === 0n;
}

/** A Baby Jubjub signing key. `scalar` is the value the verifier's equation
 * uses (`S*B8 = R8 + h*A8`); `public` is `B8 * seed`, because `eddsa_verify`
 * multiplies the public key by the cofactor 8 before using it. Keeping that
 * factor of 8 explicit here, exactly as `wealth_client.py.Keypair.from_seed`
 * does, is deliberate: it is the single easiest thing to get wrong when
 * porting this arithmetic, and getting it wrong produces a signature that
 * fails inside the circuit with no diagnostic beyond "unsatisfied
 * constraint". */
export function keypairFromSeed(seed) {
  const k = mod(BigInt(seed), SUBORDER);
  if (k === 0n) throw new Error('signing key seed must not be a multiple of the Baby Jubjub subgroup order');
  const pub = pointMul(BASE8, k);
  return { scalar: mod(8n * k, SUBORDER), public: pub };
}

/** EdDSA over Baby Jubjub, in the form `eddsa_verify` (circuits/lib/src/
 * signature_verify.nr) checks: returns `[R8, S]` such that
 * `S*B8 == R8 + h*A8` where `h = Poseidon(R8.x, R8.y, A.x, A.y, message)`.
 * `challenge` is supplied by the caller (`oracle.eddsaChallenge`) rather
 * than computed here, because Poseidon is deliberately not reimplemented in
 * this module — see the file header. `signingNonce` must be single-use per
 * message: reusing one across two different messages leaks the private
 * scalar (the classic EdDSA/ECDSA nonce-reuse break), so a caller should
 * draw it from a fresh CSPRNG per signature. */
export async function sign(keypair, message, signingNonce, challenge) {
  const r8 = pointMul(BASE8, signingNonce);
  const h = await challenge(r8[0], r8[1], keypair.public[0], keypair.public[1], message);
  const s = mod(signingNonce + h * keypair.scalar, SUBORDER);
  return { r8, s };
}

/** A fresh scalar below SUBORDER, drawn from the browser's CSPRNG. Used both
 * for the EdDSA signing nonce and nowhere else — reuse across two purposes
 * is exactly the mistake `sign`'s docstring warns about. */
export function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  // Reduce into [1, SUBORDER) rather than SUBORDER's own range, so 0 (which
  // `pointMul` treats as the identity and which would leak nothing useful
  // as a signing nonce) is never produced.
  return (v % (SUBORDER - 1n)) + 1n;
}
