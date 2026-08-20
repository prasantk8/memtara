// Bundles src/app.js (and the noir_js / bb.js it imports) into a single
// browser-ready ES module at vendor/app.bundle.js.
//
// Why a bundler at all, on a page that is otherwise deliberately
// dependency-free (see clients/auditor-console, which ships as raw
// index.html + a .js file with no build step): `@noir-lang/noir_js` and
// `@aztec/bb.js` are npm packages whose published browser output still
// contains bare imports of their own dependencies (pako, comlink, idb-keyval,
// msgpackr) and Node-only branches (fs, worker_threads) that a browser's
// native ES module loader cannot resolve unbundled. esbuild's job here is
// narrow and mechanical — inline those dependencies and let the WASM
// binaries it references be fetched as ordinary same-origin assets — not to
// introduce an application framework.
//
// Run with `node build.mjs`. Output is gitignored, like every other build
// artifact in this repository (circuits/target/, backend/api/vkeys/): commit
// clients/web-prover/src/, not clients/web-prover/vendor/.

import * as esbuild from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vendorDir = path.join(here, 'vendor');

await esbuild.build({
  entryPoints: [path.join(here, 'src', 'app.js')],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  outfile: path.join(vendorDir, 'app.bundle.js'),
  sourcemap: true,
  logLevel: 'info',
});

// acvm_js and noirc_abi's wasm-bindgen glue loads its .wasm binary at
// runtime via `new URL('acvm_js_bg.wasm', import.meta.url)` — a bare
// (non-"./") relative reference, which esbuild's static asset pipeline does
// not rewrite (confirmed empirically: `grep new URL( vendor/app.bundle.js`
// after a build shows it passes through unchanged). That resolves, at
// runtime, relative to the bundle's OWN url — i.e. a sibling file in this
// same `vendor/` directory — so the fix is exactly that: copy the two wasm
// binaries next to the bundle rather than teach esbuild a bundling trick for
// a pattern it does not recognise.
for (const [pkg, file] of [
  ['@noir-lang/acvm_js/web/acvm_js_bg.wasm', 'acvm_js_bg.wasm'],
  ['@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm', 'noirc_abi_wasm_bg.wasm'],
]) {
  const src = path.join(here, 'node_modules', pkg);
  fs.copyFileSync(src, path.join(vendorDir, file));
}

console.log('copied acvm_js_bg.wasm and noirc_abi_wasm_bg.wasm into vendor/');
