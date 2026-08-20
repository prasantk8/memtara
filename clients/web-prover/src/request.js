// Parsing the assessment request — the JSON body a bank's
// `POST /api/v1/issue-wealth-request` returns, and which the bank hands to
// the holder's device out of band (a push notification payload, in a real
// deployment). See `backend/api/src/wealth/mod.rs`'s module header, "Two
// endpoints, deliberately separate from the generic issuance surface", and
// `clients/prover/cli.py`'s `_resume_request` docstring for why the device
// receives this file rather than fetching it itself: the read-back endpoint
// is org-scoped, and a holder's device must never hold an org API key.
//
// Nothing in this file is secret. Every value here is a public input the
// proof will publish anyway (see `wealth::mod.rs::public_input_template`) —
// the terms, the nonce, the product reference, the assessment window. That is
// what makes it safe for this page to accept it over a file input with no
// authentication of its own.

export class RequestError extends Error {}

const REQUIRED_FIELDS = [
  'request_id',
  'nonce',
  'product_ref',
  'product_isin',
  'min_income',
  'min_liquidity',
  'max_concentration_percent',
  'product_risk_level',
  'window_start',
  'window_end',
];

function base64UrlToBigInt(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  let v = 0n;
  for (let i = 0; i < binary.length; i++) {
    v = (v << 8n) | BigInt(binary.charCodeAt(i));
  }
  return v;
}

function isoToEpochSeconds(iso) {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new RequestError(`not a valid timestamp: ${iso}`);
  return BigInt(Math.floor(ms / 1000));
}

/** Parse the `issue-wealth-request` response JSON into the terms
 * `prove.js` needs, all as BigInts/strings ready for circuit execution.
 * Mirrors the field reads at the top of `wealth_client.py.generate_proof`. */
export function parseAssessmentRequest(document) {
  const missing = REQUIRED_FIELDS.filter((f) => !(f in document));
  if (missing.length > 0) {
    throw new RequestError(`assessment request is missing required field(s): ${missing.join(', ')}`);
  }

  const windowStart = isoToEpochSeconds(document.window_start);
  const windowEnd = isoToEpochSeconds(document.window_end);
  if (windowEnd < windowStart) {
    throw new RequestError('window_end is before window_start');
  }

  const productRefHex = String(document.product_ref);
  const productRef = productRefHex.startsWith('0x') ? BigInt(productRefHex) : BigInt('0x' + productRefHex);

  return {
    requestId: document.request_id,
    productIsin: document.product_isin,
    productName: document.product_name ?? null,
    nonce: base64UrlToBigInt(document.nonce),
    productRef,
    minIncome: BigInt(document.min_income),
    minLiquidity: BigInt(document.min_liquidity),
    maxConcentrationPercent: BigInt(document.max_concentration_percent),
    productRiskLevel: BigInt(document.product_risk_level),
    windowStart,
    windowEnd,
  };
}
