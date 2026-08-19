// Runs the console's real verification engine over every fixture, under node,
// and asserts the properties that matter. The page and this harness load the
// SAME verify.js — there is no second implementation to drift.
//
//   node clients/auditor-console/check_fixtures.mjs
//
// The assertion that earns its keep is the rejection one. A cryptographically
// clean proof that a client was NOT suitable is a correctly evidenced decline.
// A console that rolled the two findings into one badge would print it as an
// approval, in front of an auditor. So: integrity and outcome are asserted
// separately, and the decline fixture must show a good integrity finding
// alongside a NOT-approved outcome.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// verify.js is a classic script that attaches to a global.
globalThis.window = globalThis;
const src = readFileSync(join(here, 'verify.js'), 'utf8');
new Function(src)();
const AC = globalThis.AuditorConsole;
if (!AC) throw new Error('verify.js did not export AuditorConsole');

function loadBundle(dir) {
  const root = join(here, 'fixtures', dir);
  return readdirSync(root)
    .filter((n) => statSync(join(root, n)).isFile())
    .map((n) => ({ path: n, bytes: new Uint8Array(readFileSync(join(root, n))) }));
}

let failures = 0;
function assert(label, cond, detail) {
  if (cond) {
    console.log(`  [+] ${label}`);
  } else {
    failures++;
    console.log(`  [X] ${label}${detail ? ' — ' + detail : ''}`);
  }
}

function stateOfRow(report, blockId, labelStartsWith) {
  const block = report.blocks.find((b) => b.id === blockId);
  if (!block) return null;
  const row = (block.rows || []).find((r) => r.label.toLowerCase().startsWith(labelStartsWith));
  return row ? row.state : null;
}

const results = {};

for (const dir of ['approval', 'rejection', 'broken', 'no-ai']) {
  const report = await AC.analyse(loadBundle(dir));
  results[dir] = report;
  console.log(`\n${dir}`);
  if (!report.loaded) {
    console.log(`  could not load: ${report.error}`);
    failures++;
    continue;
  }
  console.log(`  case                 ${report.caseId}`);
  console.log(`  EVIDENCE INTEGRITY   ${report.integrity.verdict}`);
  console.log(`  DECISION OUTCOME     ${report.outcome.verdict}`);
  console.log(`  unrecorded fields    ${report.gapCount}`);
}

console.log('\nassertions');

// 1. The two findings are separate objects and neither is derived from the other.
assert('integrity and outcome are reported as two independent findings',
  results.rejection.integrity.verdict !== undefined &&
  results.rejection.outcome.verdict !== undefined &&
  results.rejection.integrity.verdict !== results.rejection.outcome.verdict);

// 2. THE ONE THAT MATTERS. A clean decline must not read as an approval.
assert('a decline reports a NOT-SUITABLE/REJECTED outcome, never an approval',
  results.rejection.outcome.sense === 'decline',
  `sense was ${results.rejection.outcome.sense}`);

assert('the decline is not reported as invalid merely because it was declined',
  results.rejection.integrity.verdict !== 'INVALID',
  `integrity was ${results.rejection.integrity.verdict}`);

// 3. Approval and decline reach opposite outcomes from the same integrity path.
assert('an approval reports an approving outcome',
  results.approval.outcome.sense === 'approve',
  `sense was ${results.approval.outcome.sense}`);

assert('approval and decline share the same integrity verdict',
  results.approval.integrity.verdict === results.rejection.integrity.verdict,
  `${results.approval.integrity.verdict} vs ${results.rejection.integrity.verdict}`);

// 4. `model: null` (a signed assertion that no AI took part) must be visibly
//    different from a missing model block (a hole in the record).
const noAiState = stateOfRow(results['no-ai'], 'model', 'provider')
               ?? results['no-ai'].blocks.find((b) => b.id === 'model')?.headline?.state;
const brokenState = stateOfRow(results.broken, 'model', 'provider')
               ?? results.broken.blocks.find((b) => b.id === 'model')?.headline?.state;

assert('model: null and a missing model block render as different states',
  noAiState !== null && brokenState !== null && noAiState !== brokenState,
  `no-ai=${noAiState} broken=${brokenState}`);

assert('a record with no AI declared is not counted as having more gaps than a record missing the block entirely',
  results['no-ai'].gapCount <= results.broken.gapCount,
  `no-ai=${results['no-ai'].gapCount} broken=${results.broken.gapCount}`);

// 5. A tampered digest must surface as an integrity failure, not an outcome one.
assert('a mismatched proof digest degrades integrity, not the outcome',
  results.broken.integrity.verdict !== 'VALID');

// 6. The working paper must carry both findings and say they are separate.
const paper = AC.workingPaper(results.rejection);
assert('the exported working paper states the two findings must not be combined',
  /MUST NOT BE COMBINED/i.test(paper));
assert('the exported working paper names the decline',
  /REJECT|NOT SUITABLE|DECLINE/i.test(paper));

console.log(`\n${failures === 0 ? 'all assertions passed' : failures + ' assertion(s) failed'}`);
process.exit(failures === 0 ? 0 : 1);
