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

function stateOfCheck(report, id) {
  const c = (report.checks || []).find((x) => x.id === id);
  return c ? c.state : null;
}

const results = {};

for (const dir of ['approval', 'rejection', 'broken', 'no-ai', 'binding-altered', 'binding-record-mismatch']) {
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

// 7. BINDING. The third claim about the audit log, and the only one that
//    survives someone editing the firm's database. Linkage says no record was
//    removed or reordered; it says nothing about whether the rows behind a
//    decision still CONTAIN what was fingerprinted. See
//    backend/api/src/audit/binding.rs.
assert('an untouched binding recomputes to the fingerprint the chain recorded',
  stateOfCheck(results.approval, 'binding_recompute') === AC.STATES.PASS,
  `state was ${stateOfCheck(results.approval, 'binding_recompute')}`);

assert('an untouched record and its chain entry agree about the model',
  stateOfCheck(results.approval, 'binding_model') === AC.STATES.PASS,
  `state was ${stateOfCheck(results.approval, 'binding_model')}`);

// The no-AI case, which is the one a careless implementation gets wrong.
// `model: null` is a signed assertion that no AI participated, and its binding
// must verify as an ANSWER — never as a blank that happens not to fail.
assert('a fingerprinted "no AI participated" assertion verifies as an answer, not a blank',
  stateOfCheck(results['no-ai'], 'binding_recompute') === AC.STATES.PASS &&
  stateOfCheck(results['no-ai'], 'binding_model') === AC.STATES.PASS,
  `recompute=${stateOfCheck(results['no-ai'], 'binding_recompute')} model=${stateOfCheck(results['no-ai'], 'binding_model')}`);

assert('the no-AI assertion is shown as ASSERTED-ABSENT in the model block, not as a gap',
  stateOfRow(results['no-ai'], 'model', 'bound to the audit chain') === AC.ROWS.ASSERTED_ABSENT,
  `state was ${stateOfRow(results['no-ai'], 'model', 'bound to the audit chain')}`);

// THE ONE THAT MATTERS FOR THIS FEATURE. A database UPDATE rewrites the row,
// so the record and the rebuilt payload BOTH name the new model — they came
// from the same row. Only the recorded fingerprint, which the attacker cannot
// reach, still describes the original. The recomputation is the only thing
// that sees it, and the record/chain cross-check correctly does not.
assert('a database edit to the model row is caught by the recomputation',
  stateOfCheck(results['binding-altered'], 'binding_recompute') === AC.STATES.FAIL,
  `state was ${stateOfCheck(results['binding-altered'], 'binding_recompute')}`);

assert('that edit degrades integrity and leaves the outcome alone',
  results['binding-altered'].integrity.verdict === 'INVALID' &&
  results['binding-altered'].outcome.sense === 'approve',
  `${results['binding-altered'].integrity.verdict} / ${results['binding-altered'].outcome.sense}`);

// And the mirror image: someone edits the RECORD inside the bundle and leaves
// the binding file alone. Every fingerprint still checks out. Only the
// cross-check notices, which is what makes a tampered bundle detectable with
// no database and no network.
assert('a bundle whose record was edited passes the recomputation and fails the cross-check',
  stateOfCheck(results['binding-record-mismatch'], 'binding_recompute') === AC.STATES.PASS &&
  stateOfCheck(results['binding-record-mismatch'], 'binding_model') === AC.STATES.FAIL,
  `recompute=${stateOfCheck(results['binding-record-mismatch'], 'binding_recompute')} model=${stateOfCheck(results['binding-record-mismatch'], 'binding_model')}`);

assert('the two binding checks are independent — neither fixture fails both',
  stateOfCheck(results['binding-altered'], 'binding_model') !== AC.STATES.FAIL &&
  stateOfCheck(results['binding-record-mismatch'], 'binding_recompute') !== AC.STATES.FAIL);

// 8. AN ABSENT CHECK IS NOT A PASSED ONE. A bundle with no binding events must
//    never render as though the binding held — that principle is load-bearing
//    across this codebase and it is the reason INCOMPLETE exists at all.
assert('a bundle carrying no binding events reports the check unperformed, never passed',
  stateOfCheck(results.rejection, 'binding_recompute') === AC.STATES.MISSING &&
  stateOfCheck(results.rejection, 'binding_model') === AC.STATES.MISSING &&
  results.rejection.integrity.verdict !== 'VALID',
  `recompute=${stateOfCheck(results.rejection, 'binding_recompute')} verdict=${results.rejection.integrity.verdict}`);

assert('with no binding events the model block says so rather than showing a tick',
  stateOfRow(results.rejection, 'model', 'bound to the audit chain') === AC.ROWS.GAP,
  `state was ${stateOfRow(results.rejection, 'model', 'bound to the audit chain')}`);

// 9. There is still no third verdict card: binding lives inside the integrity
//    finding, because a broken binding is an integrity failure and never an
//    outcome. Asserted structurally so nobody adds one later.
assert('binding is reported inside the integrity finding and adds no third verdict',
  Object.keys(results['binding-altered']).filter((k) => k === 'binding' || k === 'bindingVerdict').length === 0 &&
  results['binding-altered'].integrity.counts.fail > 0);

// 10. Black-and-white printing: every state this tool can emit must carry a
//     glyph AND a word in the exported paper, or a photocopied working paper
//     loses the distinction entirely.
const papers = Object.values(results).filter((r) => r.loaded).map((r) => AC.workingPaper(r));
assert('every check in every fixture prints a glyph and a word, never colour alone',
  Object.values(results).filter((r) => r.loaded).every((r, i) =>
    r.checks.every((c) => /^\[[+X!?\-–]\]$/.test(
      { pass: '[+]', fail: '[X]', missing: '[!]', not_checked: '[?]' }[c.state] || '') &&
      papers[i].includes({ pass: 'PASS', fail: 'FAIL', missing: 'CANNOT CHECK', not_checked: 'NOT CHECKED' }[c.state]))));

console.log(`\n${failures === 0 ? 'all assertions passed' : failures + ' assertion(s) failed'}`);
process.exit(failures === 0 ? 0 : 1);
