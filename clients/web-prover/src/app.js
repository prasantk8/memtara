// DOM wiring for the web prover page. This is the one module allowed to
// touch `fetch` for the submission call, and it sends exactly one request
// body: `{request_id, public_inputs, proof}`. Nothing else defined in this
// file — not the vault figures, not the signing key, not a Merkle path —
// is ever passed to `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, or any
// other network primitive. `test/e2e.spec.mjs` asserts that boundary by
// recording every HTTP request body a real run makes and checking none of
// them contain a witness value.

import { readVaultFile, VaultError } from './vault.js';
import { parseAssessmentRequest, RequestError } from './request.js';
import { generateProof, encodeProofBase64Url, ProvingError } from './prove.js';

const $ = (id) => document.getElementById(id);

// Where the compiled circuits are served from. These are build artifacts of
// `circuits/` (gitignored there — see circuits/README and
// backend/api/src/verify/mod.rs's `ensure_vkeys`), not source, so this page
// does not vendor a copy; it fetches them from whatever origin is serving it,
// same as any other static asset. Overridable via `?circuits=` for the e2e
// test and for a deployment that serves them from a different path.
const CIRCUITS_BASE =
  new URLSearchParams(location.search).get('circuits') || 'circuits';

let oracleCircuitPromise = null;
let wealthCircuitPromise = null;

async function fetchCircuit(name) {
  const url = `${CIRCUITS_BASE}/${name}.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(
      `could not load ${url} (HTTP ${res.status}). This page needs the compiled circuit — run ` +
        '`nargo compile --workspace --skip-brillig-constraints-check` under circuits/, and serve ' +
        'circuits/target/ at the path this page was given (see --circuits or the `circuits` query param).',
    );
  }
  return res.json();
}

function circuits() {
  oracleCircuitPromise ??= fetchCircuit('witness_oracle');
  wealthCircuitPromise ??= fetchCircuit('wealth_suitability');
  return Promise.all([oracleCircuitPromise, wealthCircuitPromise]);
}

function setStatus(message, kind = 'info') {
  const el = $('status');
  el.textContent = message;
  el.dataset.kind = kind;
}

function setResult(html) {
  $('result').innerHTML = html;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

async function readJsonFile(file) {
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${file.name} is not valid JSON: ${e.message}`);
  }
}

async function onGenerateAndSubmit() {
  const vaultFile = $('vault-file').files[0];
  const requestFile = $('request-file').files[0];
  const baseUrl = $('base-url').value.trim().replace(/\/+$/, '');
  const sessionToken = $('session-token').value.trim();

  setResult('');

  if (!vaultFile) return setStatus('choose a vault file first — it never leaves this tab.', 'error');
  if (!requestFile) return setStatus('choose the assessment request file (from the bank).', 'error');
  if (!sessionToken) return setStatus('paste your session token — it authorizes the submission, nothing else.', 'error');

  try {
    setStatus('reading your vault (locally — this file is never uploaded)…');
    const vault = await readVaultFile(vaultFile);

    setStatus('reading the assessment request…');
    const requestDocument = await readJsonFile(requestFile);
    const request = parseAssessmentRequest(requestDocument);

    setStatus('loading the compiled suitability circuit…');
    const [oracleCircuit, wealthCircuit] = await circuits();

    const proof = await generateProof({
      vault,
      request,
      oracleCircuit,
      wealthCircuit,
      onProgress: (step) => setStatus(step + '…'),
    });

    setStatus('submitting the proof — only the proof and the public terms leave this device…');
    const proofBase64 = encodeProofBase64Url(proof.proofBytes);
    const response = await fetch(`${baseUrl}/api/v1/submit-wealth-proof`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        request_id: request.requestId,
        public_inputs: proof.publicInputs,
        proof: proofBase64,
      }),
    });
    const body = await response.json().catch(() => ({}));

    if (!response.ok) {
      setStatus(`the bank refused the submission (HTTP ${response.status}).`, 'error');
      setResult(`<pre>${escapeHtml(JSON.stringify(body, null, 2))}</pre>`);
      return;
    }

    setStatus('done.', 'success');
    setResult(`
      <p><strong>Verdict:</strong> ${body.suitable ? 'SUITABLE' : 'NOT SUITABLE'}
         (a decline is a complete, valid assessment — not an error)</p>
      <p><strong>Product:</strong> ${escapeHtml(body.product_name || '')} (${escapeHtml(body.product_isin)})</p>
      <p><strong>Regulatory audit id:</strong> ${escapeHtml(body.regulatory_audit_id)}</p>
      <p><strong>Proof token expires in:</strong> ${escapeHtml(body.expires_in)}s</p>
      <details><summary>proof_token (JWT)</summary><pre>${escapeHtml(body.proof_token)}</pre></details>
    `);
  } catch (e) {
    const kind =
      e instanceof VaultError || e instanceof RequestError || e instanceof ProvingError ? 'refused' : 'error';
    setStatus(e.message || String(e), kind === 'error' ? 'error' : 'refused');
  }
}

function wire() {
  $('go').addEventListener('click', () => {
    onGenerateAndSubmit().catch((e) => setStatus(String(e && e.message ? e.message : e), 'error'));
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', wire);
} else {
  wire();
}

// Exposed for the e2e test harness only (Playwright drives the page through
// the real DOM, not through this export — but the test uses it to wait for
// "the module finished loading" without depending on a UI string).
window.__memtaraWebProverReady = true;
