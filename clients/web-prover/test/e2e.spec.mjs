// End-to-end proof of the claim this directory exists to make: a real
// UltraHonk suitability proof, generated entirely inside a headless browser
// tab from a vault file that is never uploaded, accepted by a REAL,
// separately-running `memtara-api` server's `/api/v1/submit-wealth-proof`
// (which itself shells out to the real `bb verify`).
//
// The load-bearing assertion is not "the page shows a success message" — a
// page can show that and still leak the vault. Every request the page makes
// during the run is recorded by a Playwright network-level route handler
// (a request-recording proxy in every sense but the name: it intercepts
// each request before it goes out, same as an external mitmproxy would, just
// in-process), and the test asserts none of the recorded request bodies —
// not just the one to `/submit-wealth-proof` — contain any of the witness
// values this run's vault actually holds: the four financial figures, the
// signing key material, or the Merkle authentication paths. What this proves
// is scoped exactly that far: no witness value appeared in any request body
// this run observed. It does not prove no such value could ever leak by some
// other channel (a cookie, a WebSocket, a timing side channel) — those are
// out of scope for this assertion and this comment says so rather than
// implying more than was checked.

import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { Client } from 'pg';

import { buildBackend, startBackend } from './backend.mjs';
import { startServer } from './static-server.mjs';
import { seedDesk } from './seed.mjs';
import { WitnessOracle } from '../src/oracle.js';
import * as bjj from '../src/babyjubjub.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, '..', '..', '..');
const CIRCUITS_TARGET = path.join(REPO_ROOT, 'circuits', 'target');

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://memtara:memtara@localhost:5433/memtara';

const TERMS = {
  productIsin: 'XS1234567890',
  productName: '5-year capital-protected note, USD (web-prover e2e)',
  minIncome: 500_000,
  minLiquidity: 1_000_000,
  maxConcentrationPercent: 30,
  productRiskLevel: 3,
};

// The `wealth_demo` profile the rest of this repo's suitability tests use
// (tests/test_wealth_suitability_e2e.py's SUITABLE_VAULT) — comfortably
// clears all four COB 3.1 limbs.
const VAULT_FIGURES = {
  income: 750_000,
  liquid_assets: 2_000_000,
  risk_tolerance: 4,
  existing_holdings_value: 200_000,
};

// A fixed, reproducible seed — test-only; a real vault draws this from a
// CSPRNG (clients/prover/vault.py's `create()` does exactly the same thing
// for the same reason: a demo/test needs a repeatable client).
const SIGNING_KEY_SEED = 0x5ea51dec0den;

function loadCircuit(name) {
  return JSON.parse(fs.readFileSync(path.join(CIRCUITS_TARGET, `${name}.json`), 'utf8'));
}

test('a suitability proof generated in the browser is accepted by a live server, and no witness value leaves the device', async ({
  page,
  context,
}) => {
  // -----------------------------------------------------------------
  // 1. Independently compute every witness value this run's vault holds,
  //    using the SAME modules the browser page uses (not a re-derivation),
  //    so the leak assertion below checks against the exact bytes that were
  //    at risk of leaking — not an approximation of them.
  // -----------------------------------------------------------------
  const oracleCircuit = loadCircuit('witness_oracle');
  const oracle = new WitnessOracle(oracleCircuit);
  const leaves = [
    BigInt(VAULT_FIGURES.income),
    BigInt(VAULT_FIGURES.liquid_assets),
    BigInt(VAULT_FIGURES.risk_tolerance),
    BigInt(VAULT_FIGURES.existing_holdings_value),
    ...Array(12).fill(0n),
  ];
  const { pathFor } = await oracle.merkle(leaves);
  const keypair = bjj.keypairFromSeed(SIGNING_KEY_SEED);

  const witnessValues = [
    String(VAULT_FIGURES.income),
    String(VAULT_FIGURES.liquid_assets),
    String(VAULT_FIGURES.existing_holdings_value),
    SIGNING_KEY_SEED.toString(16).padStart(64, '0'),
    keypair.scalar.toString(),
    ...[0, 1, 2, 3].flatMap((slot) => pathFor(slot).map(String)),
  ];
  // risk_tolerance is deliberately excluded from this list: it is a single
  // digit (1-5), and asserting its absence as a raw substring would produce
  // false failures from unrelated digits inside uuids/hex digests elsewhere
  // in a request body — exactly the false positive
  // tests/test_wealth_suitability_e2e.py's own comment on this warns about.
  // Every other witness value here is large enough (a six-figure sum, a
  // 254-bit field element, a 32-byte key) that an accidental substring
  // collision is not a realistic concern.
  expect(witnessValues.every((v) => v.length >= 6)).toBe(true);

  // -----------------------------------------------------------------
  // 2. A real backend, a real bank, a real registered client.
  // -----------------------------------------------------------------
  const binary = buildBackend();
  const backend = await startBackend(binary);
  test.info().annotations.push({ type: 'backend', description: backend.baseUrl });

  let desk;
  try {
    desk = await seedDesk({
      baseUrl: backend.baseUrl,
      databaseUrl: DATABASE_URL,
      oracleCircuit,
      terms: TERMS,
      vaultFigures: VAULT_FIGURES,
    });
  } catch (e) {
    backend.stop();
    throw e;
  }

  // -----------------------------------------------------------------
  // 3. The vault file and the assessment request file — exactly what a
  //    holder's device would be handed: a local vault, and the bank's
  //    issue-wealth-request response, out of band (see request.js's header).
  // -----------------------------------------------------------------
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'memtara-web-prover-e2e-'));
  const vaultPath = path.join(tmpDir, 'vault.json');
  const requestPath = path.join(tmpDir, 'request.json');
  fs.writeFileSync(
    vaultPath,
    JSON.stringify({
      version: 1,
      user_id: desk.userId,
      signing_key_seed: SIGNING_KEY_SEED.toString(16).padStart(64, '0'),
      figures: VAULT_FIGURES,
    }),
  );
  fs.writeFileSync(requestPath, JSON.stringify(desk.assessmentRequest));

  // -----------------------------------------------------------------
  // 4. Serve the page itself, and record every request it makes.
  // -----------------------------------------------------------------
  const { server: staticServer, baseUrl: pageBaseUrl } = await startServer({ port: 0 });

  /** @type {Array<{url: string, method: string, postData: string | null}>} */
  const recordedRequests = [];
  let submitRequestBody = null;
  await context.route('**/*', async (route) => {
    const req = route.request();
    const postData = req.postData();
    recordedRequests.push({ url: req.url(), method: req.method(), postData });
    if (req.url().includes('/api/v1/submit-wealth-proof')) {
      submitRequestBody = postData ? JSON.parse(postData) : null;
    }
    await route.continue();
  });

  const consoleErrors = [];
  page.on('pageerror', (err) => consoleErrors.push(String(err)));

  try {
    await page.goto(`${pageBaseUrl}/index.html`);
    await page.setInputFiles('#vault-file', vaultPath);
    await page.setInputFiles('#request-file', requestPath);
    await page.fill('#base-url', backend.baseUrl);
    await page.fill('#session-token', desk.sessionToken);
    await page.click('#go');

    await expect(page.locator('#status')).toHaveAttribute('data-kind', 'success', { timeout: 5 * 60 * 1000 });

    // -----------------------------------------------------------------
    // 5. The proof was accepted by the real, live server.
    // -----------------------------------------------------------------
    expect(consoleErrors).toEqual([]);
    const resultText = await page.locator('#result').innerText();
    expect(resultText).toContain('SUITABLE');
    expect(resultText).not.toContain('NOT SUITABLE');
    expect(resultText).toContain(TERMS.productIsin);

    expect(submitRequestBody, 'the page must have called /api/v1/submit-wealth-proof').toBeTruthy();
    expect(Object.keys(submitRequestBody).sort()).toEqual(['proof', 'public_inputs', 'request_id']);
    expect(submitRequestBody.request_id).toBe(desk.assessmentRequest.request_id);
    expect(submitRequestBody.public_inputs).toHaveLength(12);

    // Independent confirmation straight from Postgres: the row the server
    // wrote records a suitable assessment against this exact request — not
    // only that the page's own UI says so.
    const pg = new Client({ connectionString: DATABASE_URL });
    await pg.connect();
    try {
      const { rows } = await pg.query('select suitable from wealth_requests where request_id = $1', [
        desk.assessmentRequest.request_id,
      ]);
      expect(rows).toHaveLength(1);
      expect(rows[0].suitable).toBe(true);
    } finally {
      await pg.end();
    }

    // -----------------------------------------------------------------
    // 6. The guarantee this test exists to make, as a machine assertion:
    //    no witness value this run's vault held appears in ANY recorded
    //    request body — not only the submission, every request the page
    //    made (loading the circuits, fetching WASM, everything).
    // -----------------------------------------------------------------
    expect(recordedRequests.length).toBeGreaterThan(0);
    const bodiesWithData = recordedRequests.filter((r) => r.postData);
    expect(bodiesWithData.length, 'at least the submission itself must have a body').toBeGreaterThan(0);

    const leaks = [];
    for (const req of bodiesWithData) {
      for (const value of witnessValues) {
        if (req.postData.includes(value)) {
          leaks.push({ url: req.url, value });
        }
      }
    }
    expect(leaks, `witness values must not appear in any request body: ${JSON.stringify(leaks)}`).toEqual([]);
  } finally {
    staticServer.close();
    backend.stop();
  }
});
