// Real proving inside the browser's same-thread WASM backend measures ~20s
// for this circuit (see SPIKE.md's secondary finding #2) — fast enough that
// this timeout is about `cargo build` + server boot + CRS download on a cold
// cache, not about proving. Generous rather than tuned to "usually passes":
// a flaky e2e test that occasionally times out on a slow CI runner is worse
// than a slow one that reliably finishes.
export default {
  testDir: './test',
  timeout: 10 * 60 * 1000,
  expect: { timeout: 8 * 60 * 1000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    headless: true,
  },
};
