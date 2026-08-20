// Test-only setup: a bank, a registered product, and a client with a synced
// vault — the JS-side counterpart of tests/test_wealth_suitability_e2e.py's
// `desk` fixture. Everything that can go through the real HTTP API does
// (`POST /orgs`, `POST /api/v1/products`, `PUT /vault`,
// `POST /api/v1/issue-wealth-request`); only `users` and `sessions` are
// written directly, because there is no self-serve HTTP endpoint for either
// in this codebase (the real onboarding path is a passkey/OTP/UAE Pass
// ceremony, which is not what this test is about) — the same choice
// `conftest.py`'s fixture makes, for the same reason.

import crypto from 'node:crypto';
import { Client } from 'pg';

import { WitnessOracle } from '../src/oracle.js';

function hashToken(token) {
  // Mirrors auth::session_token::hash_token — base64url-no-pad SHA-256.
  return crypto.createHash('sha256').update(token).digest('base64url');
}

function randomPhone() {
  const suffix = String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
  return `+9715${suffix}`;
}

/** Registers an org and a product, creates a user + live session directly in
 * Postgres, computes the vault's Merkle root via the same `WitnessOracle`
 * the browser page uses, and registers it with `PUT /vault`. Returns
 * everything the e2e test needs to hand the page: a session token and a
 * vault whose root the server already has on record. */
export async function seedDesk({ baseUrl, databaseUrl, oracleCircuit, terms, vaultFigures }) {
  const orgRes = await fetch(`${baseUrl}/orgs`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: `e2e web-prover bank ${crypto.randomUUID().slice(0, 8)}`, org_type: 'bank' }),
  });
  if (!orgRes.ok) throw new Error(`POST /orgs failed: ${orgRes.status} ${await orgRes.text()}`);
  const org = await orgRes.json();

  const productRes = await fetch(`${baseUrl}/api/v1/products`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${org.api_key}` },
    body: JSON.stringify({
      product_isin: terms.productIsin,
      product_name: terms.productName,
      risk_level: terms.productRiskLevel,
      min_income: terms.minIncome,
      min_liquidity: terms.minLiquidity,
      max_concentration_percent: terms.maxConcentrationPercent,
      approved_by_risk_committee: true,
    }),
  });
  if (productRes.status !== 201) {
    throw new Error(`POST /api/v1/products failed: ${productRes.status} ${await productRes.text()}`);
  }

  const pg = new Client({ connectionString: databaseUrl });
  await pg.connect();
  const userId = crypto.randomUUID();
  const sessionToken = `web-prover-e2e-${crypto.randomUUID()}`;
  try {
    await pg.query('insert into users (id, phone_e164) values ($1, $2)', [userId, randomPhone()]);
    await pg.query(
      "insert into sessions (user_id, token_hash, expires_at) values ($1, $2, now() + interval '1 hour')",
      [userId, hashToken(sessionToken)],
    );
  } finally {
    await pg.end();
  }

  // The Merkle root the vault commits to — computed here with the identical
  // `WitnessOracle` module `src/prove.js` uses inside the browser, so this
  // harness cannot silently register a different root than the one the page
  // will actually prove against.
  const oracle = new WitnessOracle(oracleCircuit);
  const leaves = [
    BigInt(vaultFigures.income),
    BigInt(vaultFigures.liquid_assets),
    BigInt(vaultFigures.risk_tolerance),
    BigInt(vaultFigures.existing_holdings_value),
    ...Array(12).fill(0n),
  ];
  const { root: vaultRoot } = await oracle.merkle(leaves);
  const vaultRootBytes = Buffer.from(vaultRoot.toString(16).padStart(64, '0'), 'hex');

  const vaultPut = await fetch(`${baseUrl}/vault`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({
      ciphertext: Buffer.from('e2e-web-prover-ciphertext-the-server-cannot-read').toString('base64url'),
      vault_root: vaultRootBytes.toString('base64url'),
      expected_version: 0,
    }),
  });
  if (vaultPut.status !== 200) {
    throw new Error(`PUT /vault failed: ${vaultPut.status} ${await vaultPut.text()}`);
  }

  // A live, unrevoked consent grant covering the wealth flow's business
  // process. Must match `wealth::BUSINESS_PROCESS`
  // (backend/api/src/wealth/mod.rs) — see tests/break_it/conftest.py's
  // `make_desk` for why every desk needs one: `issue_wealth_request` has
  // refused every assessment with no covering grant since
  // migrations/0011_consent_grants.sql landed.
  const consentRes = await fetch(`${baseUrl}/api/v1/consents`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${org.api_key}` },
    body: JSON.stringify({
      user_id: userId,
      scope: ['wealth.suitability_recommendation'],
      consent_version: 'web-prover-e2e-suite-default-v1',
      granted_via: 'mobile_app',
    }),
  });
  if (consentRes.status !== 201) {
    throw new Error(`POST /api/v1/consents failed: ${consentRes.status} ${await consentRes.text()}`);
  }

  const requestRes = await fetch(`${baseUrl}/api/v1/issue-wealth-request`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${org.api_key}` },
    body: JSON.stringify({ user_id: userId, product_isin: terms.productIsin, ttl_seconds: 3600 }),
  });
  if (requestRes.status !== 201) {
    throw new Error(`POST /api/v1/issue-wealth-request failed: ${requestRes.status} ${await requestRes.text()}`);
  }
  const assessmentRequest = await requestRes.json();

  return {
    orgId: org.id,
    orgApiKey: org.api_key,
    userId,
    sessionToken,
    vaultRoot,
    assessmentRequest,
  };
}
