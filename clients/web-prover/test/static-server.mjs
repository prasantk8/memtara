// A minimal static file server for the e2e test: serves this directory
// (index.html, vendor/) at `/`, and the repo's compiled circuit artifacts
// (a gitignored build output of `circuits/`, per circuits/README) at
// `/circuits/`. No framework, no dependency — `node:http` and `node:fs`
// are enough for "serve two directories of static files."

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const WEB_PROVER_ROOT = path.resolve(here, '..');
const CIRCUITS_TARGET = path.resolve(here, '..', '..', '..', 'circuits', 'target');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.map': 'application/json; charset=utf-8',
};

function safeJoin(root, urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const resolved = path.resolve(root, '.' + decoded);
  if (!resolved.startsWith(root)) return null; // no path traversal out of root
  return resolved;
}

export function startServer({ port = 0 } = {}) {
  const server = http.createServer((req, res) => {
    let root = WEB_PROVER_ROOT;
    let urlPath = req.url;
    if (urlPath.startsWith('/circuits/')) {
      root = CIRCUITS_TARGET;
      urlPath = urlPath.slice('/circuits'.length);
    }
    const filePath = urlPath === '/' ? path.join(root, 'index.html') : safeJoin(root, urlPath);
    if (!filePath) {
      res.writeHead(400).end('bad path');
      return;
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404).end('not found: ' + urlPath);
        return;
      }
      const ext = path.extname(filePath);
      res.writeHead(200, { 'content-type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const { port: boundPort } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${boundPort}` });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { baseUrl } = await startServer({ port: 8787 });
  console.log(`web-prover static server listening at ${baseUrl}`);
}
