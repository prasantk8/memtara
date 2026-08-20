// Boots a real `memtara-api` for the e2e test — the JS-side counterpart of
// `tests/conftest.py`'s `memtara_binary` / `memtara_server` fixtures, kept
// in step with them deliberately (same env vars, same health check, same
// "skip with a reason" philosophy) so this test exercises the same server
// every Python integration test does, not a second, drifting definition of
// "the server under test."

import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, '..', '..', '..');
const BACKEND_DIR = path.join(REPO_ROOT, 'backend');

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://memtara:memtara@localhost:5433/memtara';

// Same fixed test key `tests/conftest.py` uses (`bytes(range(32))`,
// base64-encoded) — reproducible across runs, test-only. A real deployment
// reads a secret from the environment; see backend/.env.example.
const TEST_PRIVATE_KEY_B64 = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64');

function extraPath() {
  const home = process.env.HOME;
  return [`${home}/.cargo/bin`, `${home}/.bb`, `${home}/.nargo/bin`, process.env.PATH].join(':');
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function waitForHealthy(baseUrl, deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/healthz`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

/** Build `memtara-api` (mirrors `cargo build --bin memtara-api` in
 * `tests/conftest.py::memtara_binary`) and return the binary path. Throws
 * with cargo's own stderr on failure — this test should fail loudly if the
 * backend does not build, never silently skip (trap 7: a test must fail
 * loudly when its precondition changes). */
export function buildBackend() {
  const env = { ...process.env, DATABASE_URL, PATH: extraPath() };
  const result = spawnSync('cargo', ['build', '--bin', 'memtara-api'], {
    cwd: BACKEND_DIR,
    env,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`cargo build --bin memtara-api failed:\n${result.stderr}`);
  }
  const binary = path.join(BACKEND_DIR, 'target', 'debug', 'memtara-api');
  return binary;
}

/** Start the built binary and wait for `/healthz`. Returns
 * `{baseUrl, stop()}`. First boot generates a verification key per circuit
 * (`verify::ensure_vkeys`), which is why the deadline is generous. */
export async function startBackend(binary) {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    DATABASE_URL,
    BIND_ADDR: `127.0.0.1:${port}`,
    MEMTARA_PRIVATE_KEY: TEST_PRIVATE_KEY_B64,
    MEMTARA_ISSUER_BASE_URL: baseUrl,
    RUST_LOG: 'memtara_api=warn',
    // See tests/conftest.py's comment on the same variable: the production
    // default (10/min) would start refusing partway through a multi-proof
    // run. This e2e test submits exactly one proof, but matching the
    // convention here keeps this harness's server indistinguishable from the
    // Python suite's, which is the point.
    MEMTARA_PROOF_RATE_LIMIT: '10000',
    PATH: extraPath(),
  };

  const child = spawn(binary, [], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (d) => (output += d.toString()));
  child.stderr.on('data', (d) => (output += d.toString()));

  let exited = false;
  child.on('exit', () => {
    exited = true;
  });

  const healthy = await waitForHealthy(baseUrl, 120_000);
  if (!healthy) {
    child.kill();
    throw new Error(
      exited
        ? `memtara-api exited during boot:\n${output.slice(-4000)}`
        : `memtara-api did not become healthy within 120s:\n${output.slice(-4000)}`,
    );
  }

  return {
    baseUrl,
    stop() {
      child.kill();
    },
  };
}
