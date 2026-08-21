/* ===========================================================================
   Memtara Auditor Console — offline verification engine.

   Loaded by index.html with a relative <script src>, so it works from
   file:// on a USB stick. Also loadable under node (see tools/run-fixtures.mjs)
   so the verdict logic can be executed against fixtures without a browser.
   There is exactly one copy of this logic; the node harness runs THIS file.

   NO NETWORK. This file contains no fetch, no XHR, no import(), no URL
   constructor pointed at anything remote. Every check is computed from bytes
   the auditor supplied.

   ---------------------------------------------------------------------------
   THE TWO VERDICTS

   This engine returns TWO findings and never combines them:

     report.integrity  VALID | INVALID | INCOMPLETE
                       Did the cryptography check out?
     report.outcome    The decision itself (suitable / not suitable /
                       approved / rejected / modified), read from the record
                       AND from public input index 11.

   A cryptographically perfect record of a DECLINE verifies clean. That is a
   correctly-formed rejection, not an approval. Any caller that renders these
   two as one badge has reintroduced the defect this file exists to prevent.
   =========================================================================== */

(function (global) {
  'use strict';

  /* ---------------------------------------------------------------------
     0. Constants
     --------------------------------------------------------------------- */

  // circuits/wealth_suitability/vkey/README.md — 12 field elements, index 11
  // is the return value. "A verifier that skips index 11 accepts a valid
  // proof of unsuitability as an approval."
  var PI = {
    COUNT: 12,
    CURRENT_TIME: 0, EXPIRY_TIME: 1, VAULT_ROOT: 2, PRODUCT_REF: 3,
    MIN_INCOME: 4, MIN_LIQUIDITY: 5, MAX_CONCENTRATION: 6, RISK_LEVEL: 7,
    PUBKEY_X: 8, PUBKEY_Y: 9, NONCE: 10, SUITABLE: 11
  };

  // Check states. `not_checked` is NOT a failure and NOT a pass — it is the
  // honest third thing, and it never silently becomes a tick.
  var PASS = 'pass', FAIL = 'fail', MISSING = 'missing', NOT_CHECKED = 'not_checked';

  // Field/row states.
  var RECORDED = 'recorded';               // a real value from a real source
  var ASSERTED_ABSENT = 'asserted_absent'; // signed assertion that it does not apply
  var GAP = 'gap';                         // unrecorded. NOT an answer.
  var CONFLICT = 'conflict';

  /* ---------------------------------------------------------------------
     1. Bytes, hex, digests
     --------------------------------------------------------------------- */

  function subtle() {
    var c = global.crypto || (typeof crypto !== 'undefined' ? crypto : null);
    if (!c || !c.subtle) throw new Error('WebCrypto unavailable in this environment');
    return c.subtle;
  }

  function toHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  }

  function fromHex(s) {
    var h = String(s || '').replace(/^0x/i, '');
    if (h.length % 2) h = '0' + h;
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    var out = [];
    for (var i = 0; i < str.length; i++) out.push(str.charCodeAt(i) & 0xff);
    return new Uint8Array(out);
  }

  function sha256Hex(bytes) {
    return subtle().digest('SHA-256', bytes).then(function (d) {
      return toHex(new Uint8Array(d));
    });
  }

  function concatBytes(parts) {
    var total = 0, i;
    for (i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), at = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], at); at += parts[i].length; }
    return out;
  }

  // An 8-byte big-endian length, then the bytes. The exact framing
  // backend/api/src/audit/mod.rs::write_framed applies before hashing, and it
  // is not decoration: without it, event_type "ab" + payload "cd" and
  // event_type "a" + payload "bcd" hash identically, so the boundary between
  // two adjacent fields becomes forgeable.
  function framed(bytes) {
    var out = new Uint8Array(8 + bytes.length);
    var n = bytes.length;
    // Length written a byte at a time rather than through a DataView with a
    // BigInt: this file targets old browsers on an auditor's locked-down
    // laptop, and a payload long enough to need more than 53 bits of length
    // is not a payload that fits in memory anyway.
    for (var i = 7; i >= 0; i--) { out[i] = n & 0xff; n = Math.floor(n / 256); }
    out.set(bytes, 8);
    return out;
  }

  // A UUID's 16 raw bytes — `Uuid::as_bytes()` on the Rust side, never its
  // printed form. Returns null (not an empty array) for anything that is not a
  // UUID, so a caller reports "this cannot be reproduced" rather than hashing
  // something plausible-looking instead.
  function uuidBytes(value) {
    if (value === null || value === undefined || value === '') return new Uint8Array(0);
    var hex = String(value).trim().replace(/^urn:uuid:/i, '').replace(/-/g, '');
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) return null;
    return fromHex(hex);
  }

  // Compare digests without leaking case/whitespace/0x differences into a
  // false FAIL. A digest that differs only in presentation is not tampering.
  function normDigest(s) {
    return String(s == null ? '' : s).trim().toLowerCase().replace(/^0x/, '');
  }
  function digestsEqual(a, b) {
    var x = normDigest(a), y = normDigest(b);
    return x.length > 0 && x === y;
  }

  function b64urlToBytes(s) {
    var t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) t += '=';
    var bin = (global.atob ? global.atob(t) : Buffer.from(t, 'base64').toString('binary'));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* ---------------------------------------------------------------------
     2. Canonical JSON

     Byte-identical to scripts/export_audit_evidence.py:200
       json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
     and to backend/api/src/evidence/canonical.rs, which transliterates
     CPython's c_encode_basestring_ascii. Floats are refused here for the same
     reason they are refused there: Python and JS disagree on exponent
     formatting, so a float would produce a digest only one verifier of a
     sealed pack could reproduce.
     --------------------------------------------------------------------- */

  function canonicalString(value) {
    var out = [];
    writeValue(value, out);
    return out.join('');
  }

  function writeValue(v, out) {
    if (v === null) { out.push('null'); return; }
    var t = typeof v;
    if (t === 'boolean') { out.push(v ? 'true' : 'false'); return; }
    if (t === 'number') {
      if (!isFinite(v) || Math.floor(v) !== v) {
        throw new Error('canonical form permits integers only; found ' + v);
      }
      out.push(String(v)); return;
    }
    if (t === 'string') { writeJsonString(v, out); return; }
    if (Object.prototype.toString.call(v) === '[object Array]') {
      out.push('[');
      for (var i = 0; i < v.length; i++) { if (i) out.push(','); writeValue(v[i], out); }
      out.push(']'); return;
    }
    if (t === 'object') {
      // Sorted by codepoint, as Python's sort_keys does.
      var keys = Object.keys(v).sort(function (a, b) { return a < b ? -1 : a > b ? 1 : 0; });
      out.push('{');
      for (var k = 0; k < keys.length; k++) {
        if (k) out.push(',');
        writeJsonString(keys[k], out);
        out.push(':');
        writeValue(v[keys[k]], out);
      }
      out.push('}'); return;
    }
    throw new Error('not serialisable: ' + t);
  }

  var SHORT_ESC = { 0x22: '\\"', 0x5c: '\\\\', 0x08: '\\b', 0x0c: '\\f', 0x0a: '\\n', 0x0d: '\\r', 0x09: '\\t' };

  function writeJsonString(s, out) {
    out.push('"');
    for (var i = 0; i < s.length; i++) {
      // Iterating UTF-16 code units is exactly right here: CPython emits
      // surrogate pairs for astral codepoints, which is what these units are.
      var cu = s.charCodeAt(i);
      if (SHORT_ESC[cu] !== undefined) out.push(SHORT_ESC[cu]);
      else if (cu >= 0x20 && cu <= 0x7e) out.push(s.charAt(i));
      else out.push('\\u' + ('0000' + cu.toString(16)).slice(-4));
    }
    out.push('"');
  }

  /* ---------------------------------------------------------------------
     3. Bundle indexing

     The auditor drops a folder. We identify files by basename, tolerating
     the nesting in the published bundle layout (spec §2.1) and the flat
     unzip an auditor may produce instead.
     --------------------------------------------------------------------- */

  function basename(path) {
    var p = String(path || '').replace(/\\/g, '/');
    return p.slice(p.lastIndexOf('/') + 1);
  }

  var ROLES = [
    ['evidence',   function (n) { return n === 'decision_evidence.json'; }],
    ['seal',       function (n) { return /\.seal\.json$/i.test(n); }],
    ['pdf',        function (n) { return /\.pdf$/i.test(n); }],
    ['vk',         function (n) { return /\.vk$/i.test(n) || n === 'vk'; }],
    ['vk_hash',    function (n) { return n === 'vk_hash'; }],
    ['proof',      function (n) { return /\.proof$/i.test(n); }],
    ['public_inputs', function (n) { return n === 'public_inputs'; }],
    // Before the generic .jsonl matcher, or the binding file would be read as
    // the chain segment and its events silently checked for linkage they were
    // never meant to have. Two files, two claims, two roles.
    ['binding',    function (n) { return /binding.*\.jsonl$/i.test(n); }],
    ['checkpoint', function (n) { return n === 'audit_chain_checkpoint.json'; }],
    ['chain',      function (n) { return /\.jsonl$/i.test(n); }],
    ['jwks',       function (n) { return /^jwks.*\.json$/i.test(n); }],
    ['schema',     function (n) { return /^v\d+\.\d+\.\d+\.json$/i.test(n) || /decision_evidence.*schema.*\.json$/i.test(n); }],
    ['jwt',        function (n) { return /^(issuance_)?jwt(\.txt)?$/i.test(n); }],
    ['verify_md',  function (n) { return /^verify\.md$/i.test(n); }]
  ];

  function classify(name) {
    var n = basename(name).toLowerCase();
    for (var i = 0; i < ROLES.length; i++) if (ROLES[i][1](n)) return ROLES[i][0];
    return null;
  }

  /**
   * files: [{ path, bytes: Uint8Array }]
   * Returns { byRole: {role: entry}, all: [...], unrecognised: [...] }
   */
  function indexBundle(files) {
    var byRole = {}, all = [], unrecognised = [];
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var entry = { path: f.path, name: basename(f.path), bytes: f.bytes, role: classify(f.path) };
      entry.size = f.bytes ? f.bytes.length : 0;
      all.push(entry);
      if (!entry.role) { unrecognised.push(entry); continue; }
      // decision_evidence.json wins over the generic schema matcher etc.
      if (!byRole[entry.role]) byRole[entry.role] = entry;
    }
    return { byRole: byRole, all: all, unrecognised: unrecognised };
  }

  function textOf(entry) {
    if (!entry || !entry.bytes) return null;
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(entry.bytes);
    var s = '';
    for (var i = 0; i < entry.bytes.length; i++) s += String.fromCharCode(entry.bytes[i]);
    return s;
  }

  function jsonOf(entry) {
    var t = textOf(entry);
    if (t == null) return null;
    try { return JSON.parse(t); } catch (e) { return { __parse_error: e.message }; }
  }

  /* ---------------------------------------------------------------------
     4. Field provenance

     backend/api/src/evidence/provenance.rs defines a three-key envelope
     { state, value, unpopulated_reason } with state in
     recorded | not_applicable | unpopulated. Its whole point is that
     "we never built consent capture" must not read as "no consent was
     required here". This function preserves that distinction, and adds the
     two cases the envelope cannot express because the key is not there at
     all, or is a bare null with no stated reason.
     --------------------------------------------------------------------- */

  function readField(container, key) {
    if (container === undefined || container === null || typeof container !== 'object') {
      return { state: GAP, value: null, reason: null, why: 'absent_container' };
    }
    if (!Object.prototype.hasOwnProperty.call(container, key)) {
      return { state: GAP, value: null, reason: null, why: 'absent_key' };
    }
    var v = container[key];
    if (v && typeof v === 'object' && !Array.isArray(v) &&
        typeof v.state === 'string' &&
        Object.prototype.hasOwnProperty.call(v, 'value')) {
      if (v.state === 'recorded') return { state: RECORDED, value: v.value, reason: null, why: 'provenanced_recorded' };
      if (v.state === 'not_applicable') return { state: ASSERTED_ABSENT, value: null, reason: v.unpopulated_reason || null, why: 'provenanced_not_applicable' };
      return { state: GAP, value: null, reason: v.unpopulated_reason || null, why: 'provenanced_unpopulated' };
    }
    if (v === null) {
      // A bare null with no envelope. This tool cannot tell a deliberate
      // assertion of absence from a field nobody filled in, and says so
      // rather than guessing in either direction.
      return { state: GAP, value: null, reason: null, why: 'bare_null' };
    }
    if (v === '') return { state: GAP, value: null, reason: null, why: 'empty_string' };
    return { state: RECORDED, value: v, reason: null, why: 'plain_value' };
  }

  var WHY_TEXT = {
    absent_container: 'The block containing this field is not present in the record.',
    absent_key: 'The record does not contain this field at all. Absence is not a negative answer.',
    provenanced_unpopulated: 'The record explicitly states this field was not populated.',
    bare_null: 'The field is present but null, with no stated reason. This tool cannot tell a deliberate assertion of absence from a field nobody filled in, so it is reported as a gap.',
    empty_string: 'The field is present but empty. An empty string is not a recorded value.'
  };

  /* ---------------------------------------------------------------------
     5. Outcome reading — the second verdict
     --------------------------------------------------------------------- */

  // Vocabulary the record may use. Two axes, deliberately not merged:
  // suitability (what the circuit proved) and disposition (what the
  // institution did about it).
  var DECLINE = /^(not_suitable|unsuitable|not-suitable|rejected|reject|declined|decline|refused)$/i;
  var APPROVE = /^(suitable|approved|approve|accepted|accept)$/i;
  var MODIFY  = /^(modified|modify|amended|approved_with_conditions)$/i;

  function senseOf(word) {
    var w = String(word == null ? '' : word).trim();
    if (!w) return null;
    if (DECLINE.test(w)) return 'decline';
    if (APPROVE.test(w)) return 'approve';
    if (MODIFY.test(w)) return 'modify';
    return 'other';
  }

  // Public input 11 is a 32-byte big-endian field element: 1 or 0.
  function suitableFromPublicInputs(pis) {
    if (!pis || pis.length !== PI.COUNT) return null;
    var raw = normDigest(pis[PI.SUITABLE]);
    if (!/^[0-9a-f]+$/.test(raw)) return null;
    var stripped = raw.replace(/^0+/, '');
    if (stripped === '') return false;
    if (stripped === '1') return true;
    return null; // not a boolean field element; caller reports it as unreadable
  }

  /* ---------------------------------------------------------------------
     6. Record accessors

     The v1 spec (§1.1) and the shape wealth/evidence.rs emits today are not
     identical. Rather than pick one and fail loudly on the other, each
     accessor tries the spec name first and the current backend name second.
     Divergences are recorded in report.notes so they are visible, not silent.
     --------------------------------------------------------------------- */

  function firstOf(obj, names) {
    for (var i = 0; i < names.length; i++) {
      if (obj && Object.prototype.hasOwnProperty.call(obj, names[i])) return obj[names[i]];
    }
    return undefined;
  }

  function proofRecord(ev) {
    var arr = firstOf(ev, ['cryptographic_proofs', 'proofs']);
    if (!arr || !arr.length) return null;
    // The last proof attempt is the operative one; earlier entries are
    // rejected attempts, which the backend deliberately keeps.
    return arr[arr.length - 1];
  }

  function proofDigestOf(p) {
    return p ? firstOf(p, ['proof_digest', 'proof_sha256', 'proof_hash']) : undefined;
  }

  function publicInputsOf(ev) {
    var p = proofRecord(ev);
    var pis = p ? firstOf(p, ['public_inputs']) : undefined;
    if (!pis) pis = firstOf(ev, ['public_inputs']);
    return Array.isArray(pis) ? pis : null;
  }

  /* ---------------------------------------------------------------------
     7. Checks

     Every check returns:
       { id, label, state, plain, notMean, detail }
     `plain`   — one sentence: what passing means, for a compliance officer.
     `notMean` — one sentence: what it still does not mean. Never omitted.
     --------------------------------------------------------------------- */

  function chk(id, label, state, plain, notMean, detail) {
    return { id: id, label: label, state: state, plain: plain || '', notMean: notMean || '', detail: detail || '' };
  }

  function missingArtifact(id, label, filename, why) {
    return chk(id, label, MISSING,
      '',
      '',
      'Not checked: `' + filename + '` is not in this bundle. ' + why);
  }

  function runChecks(ctx) {
    var checks = [];
    var ev = ctx.evidence, byRole = ctx.byRole;
    var jobs = [];

    /* --- 7.1 canonical digest of the evidence file against the seal --- */
    (function () {
      var sealEntry = byRole.seal, evEntry = byRole.evidence;
      if (!sealEntry) {
        checks.push(missingArtifact('canonical_digest', 'Sealed digest of the record', 'case_file.pdf.seal.json',
          'Without the seal there is nothing to compare the record against, so this tool cannot tell whether the record was edited after export.'));
        return;
      }
      var seal = ctx.seal || {};
      var expected = seal.canonical_evidence_sha256;
      jobs.push(sha256Hex(evEntry.bytes).then(function (rawHex) {
        var recanon = null, recanonErr = null;
        try { recanon = canonicalString(ev); } catch (e) { recanonErr = e.message; }
        var p2 = recanon == null ? Promise.resolve(null) : sha256Hex(utf8(recanon));
        return p2.then(function (canonHex) {
          var rawMatch = digestsEqual(rawHex, expected);
          var canonMatch = canonHex != null && digestsEqual(canonHex, expected);
          if (rawMatch || canonMatch) {
            checks.push(chk('canonical_digest', 'Sealed digest of the record', PASS,
              'The record in this bundle is byte-for-byte the record the seal was taken over, so nothing in it has been edited since it was exported.',
              'It does not show who produced the record, and it does not show the record is true — only that it is unchanged.',
              'SHA-256 ' + rawHex + (rawMatch ? ' (raw file bytes)' : ' (raw bytes differ in formatting; re-canonicalised form matches: ' + canonHex + ')')
              + '\nseal.canonical_evidence_sha256 = ' + normDigest(expected)));
          } else {
            checks.push(chk('canonical_digest', 'Sealed digest of the record', FAIL,
              '', '',
              'MISMATCH. The record does not hash to the value the seal records.\n'
              + '  computed (raw bytes)      ' + rawHex + '\n'
              + '  computed (canonical form) ' + (canonHex || 'n/a — ' + recanonErr) + '\n'
              + '  seal says                 ' + normDigest(expected) + '\n'
              + 'Either the record or the seal was changed after export. Do not rely on this record until that is explained.'));
          }
        });
      }));
    })();

    /* --- 7.2 PDF digest --- */
    (function () {
      var seal = ctx.seal, pdf = byRole.pdf;
      if (!seal || !seal.pdf || !seal.pdf.sha256) {
        checks.push(missingArtifact('pdf_digest', 'PDF rendering matches its seal', 'case_file.pdf.seal.json',
          'The seal does not record a PDF digest, so the human-readable rendering cannot be tied to this record.'));
        return;
      }
      if (!pdf) {
        checks.push(missingArtifact('pdf_digest', 'PDF rendering matches its seal', 'case_file.pdf',
          'The seal names a PDF that is not in this bundle.'));
        return;
      }
      jobs.push(sha256Hex(pdf.bytes).then(function (h) {
        if (digestsEqual(h, seal.pdf.sha256)) {
          checks.push(chk('pdf_digest', 'PDF rendering matches its seal', PASS,
            'The PDF in this bundle is the exact file the seal recorded, so the printed case file and the machine-readable record belong together.',
            'It does not show the PDF is a faithful rendering of the record; it shows the two files have not been swapped or edited.',
            'SHA-256 ' + h + '  (' + pdf.name + ', ' + pdf.size + ' bytes)'));
        } else {
          checks.push(chk('pdf_digest', 'PDF rendering matches its seal', FAIL, '', '',
            'MISMATCH.\n  computed  ' + h + '\n  seal says ' + normDigest(seal.pdf.sha256)
            + '\nThe PDF in this bundle is not the one that was sealed.'));
        }
      }));
    })();

    /* --- 7.3 verification key against its published digest --- */
    (function () {
      var vk = byRole.vk, vkh = byRole.vk_hash;
      if (!vk || !vkh) {
        checks.push(missingArtifact('vkey_digest', 'Verification key is the published one',
          (!vk ? 'vkey/wealth_suitability.vk' : 'vkey/vk_hash'),
          'Without both files this tool cannot tell whether the key in this bundle is the key Memtara published or a substituted one.'));
        return;
      }
      var published = (textOf(vkh) || '').trim().split(/\s+/)[0];
      jobs.push(sha256Hex(vk.bytes).then(function (h) {
        if (digestsEqual(h, published)) {
          checks.push(chk('vkey_digest', 'Verification key is the published one', PASS,
            'The verification key in this bundle matches the digest Memtara published for this circuit, so the key an examiner would check the proof against has not been substituted.',
            'It does not show the proof verifies against that key. That check needs the `bb` verifier and was not run here — see the next line.',
            'SHA-256 ' + h + '\nvk_hash  ' + normDigest(published)));
        } else {
          checks.push(chk('vkey_digest', 'Verification key is the published one', FAIL, '', '',
            'MISMATCH.\n  computed ' + h + '\n  vk_hash  ' + normDigest(published)
            + '\nThe key shipped in this bundle is not the published key. A proof checked against it proves nothing about the published circuit.'));
        }
      }));
    })();

    /* --- 7.4 proof bytes against the digest in the record --- */
    (function () {
      var p = proofRecord(ev), recorded = proofDigestOf(p), file = byRole.proof;
      if (!recorded) {
        checks.push(missingArtifact('proof_digest', 'Proof file matches the record', 'decision_evidence.json',
          'The record does not carry a proof digest, so the proof file cannot be tied to it.'));
        return;
      }
      if (!file) {
        checks.push(missingArtifact('proof_digest', 'Proof file matches the record', 'proof/*.proof',
          'The record refers to a proof that is not in this bundle. Nothing here can be checked against it.'));
        return;
      }
      jobs.push(sha256Hex(file.bytes).then(function (h) {
        if (digestsEqual(h, recorded)) {
          checks.push(chk('proof_digest', 'Proof file matches the record', PASS,
            'The proof file in this bundle is the proof this record refers to.',
            'It does not show the proof is valid. A digest match on a forged proof matches just as well; validity is the `bb verify` check below.',
            'SHA-256 ' + h + '  (' + file.name + ', ' + file.size + ' bytes)'));
        } else {
          checks.push(chk('proof_digest', 'Proof file matches the record', FAIL, '', '',
            'MISMATCH.\n  computed    ' + h + '\n  record says ' + normDigest(recorded)
            + '\nThe proof in this bundle is not the proof this record was written about.'));
        }
      }));
    })();

    /* --- 7.5 the ZK proof itself. NEVER checked here. ------------------ */
    checks.push(chk('zk_pairing', 'Zero-knowledge proof verifies', NOT_CHECKED,
      '',
      '',
      'This tool did NOT check the zero-knowledge proof, and cannot: verifying it requires the `bb` verifier binary, which does not run in a browser.\n'
      + 'Run this yourself, from the bundle directory:\n'
      + '  bb verify -i proof/public_inputs -p proof/wealth_suitability.proof \\\n'
      + '            -k vkey/wealth_suitability.vk -t noir-recursive\n'
      + 'Exit code 0 with "Proof verified successfully" means the assessment was performed correctly against the published circuit.\n'
      + 'It does NOT mean the client was suitable. The answer is public input index 11, shown under Decision outcome. '
      + 'A verifier that stops at exit code 0 accepts a valid proof of unsuitability as an approval.'));

    /* --- 7.6 public inputs: shape, binding to this case, and the answer - */
    (function () {
      var pis = publicInputsOf(ev);
      if (!pis) {
        checks.push(missingArtifact('public_inputs', 'Public inputs bound to this case', 'decision_evidence.json',
          'The record carries no public inputs, so the circuit\'s own answer cannot be read and the second finding rests on the record\'s prose alone.'));
        return;
      }
      if (pis.length !== PI.COUNT) {
        checks.push(chk('public_inputs', 'Public inputs bound to this case', FAIL, '', '',
          'Expected ' + PI.COUNT + ' field elements for wealth_suitability (see circuits/wealth_suitability/vkey/README.md); found ' + pis.length + '.\n'
          + 'A public-input vector of the wrong length cannot be the one this circuit was proved over.'));
        return;
      }
      var productRef = firstOf(ev.product || {}, ['product_ref']);
      if (productRef === undefined) productRef = firstOf(ev, ['product_ref']);
      var nonce = firstOf(ev, ['nonce']);
      var bad = [];
      if (productRef !== undefined && !digestsEqual(pis[PI.PRODUCT_REF], productRef)) {
        bad.push('  index 3 (product_ref) ' + normDigest(pis[PI.PRODUCT_REF]) + ' != record ' + normDigest(productRef));
      }
      if (nonce !== undefined && !digestsEqual(pis[PI.NONCE], nonce)) {
        bad.push('  index 10 (nonce)      ' + normDigest(pis[PI.NONCE]) + ' != record ' + normDigest(nonce));
      }
      if (bad.length) {
        checks.push(chk('public_inputs', 'Public inputs bound to this case', FAIL, '', '',
          'The public inputs do not belong to this case:\n' + bad.join('\n')
          + '\nA valid proof over inputs from a different case is still a valid proof — of that other case.'));
      } else {
        var checked = [];
        if (productRef !== undefined) checked.push('product reference');
        if (nonce !== undefined) checked.push('nonce');
        checks.push(chk('public_inputs', 'Public inputs bound to this case', PASS,
          checked.length
            ? 'The ' + checked.join(' and ') + ' inside the public inputs match this record, so the proof this bundle carries is about this case and not another one.'
            : 'The public inputs are the right shape for this circuit (' + PI.COUNT + ' field elements).',
          'It does not show the proof over those inputs is valid, and it does not show the values fed into the circuit were true.',
          pis.map(function (v, i) {
            var names = ['current_time','expiry_time','vault_root','product_ref','min_income','min_liquidity','max_concentration_percent','product_risk_level','user_public_key_x','user_public_key_y','nonce','suitable'];
            return '  [' + (i < 10 ? ' ' : '') + i + '] ' + names[i] + ' = ' + normDigest(v).replace(/^0+(?=.)/, '0x…');
          }).join('\n')));
      }
    })();

    /* --- 7.7 the record's decision vs public input 11 ------------------- */
    (function () {
      var pis = publicInputsOf(ev);
      var circuit = pis ? suitableFromPublicInputs(pis) : null;
      var fd = ev.final_decision || {};
      var recorded = firstOf(fd, ['outcome']);
      if (recorded === undefined) recorded = firstOf((ev.outcome || {}), ['suitable']);
      var recordedSense = typeof recorded === 'boolean'
        ? (recorded ? 'approve' : 'decline')
        : senseOf(recorded);

      if (circuit === null) {
        checks.push(chk('outcome_binding', 'Recorded decision matches the circuit\'s answer', MISSING, '', '',
          'Public input index 11 could not be read as 1 or 0, so the circuit\'s own answer is unavailable. '
          + 'The decision shown under finding 2 rests on the record\'s own wording alone, with nothing cryptographic behind it.'));
        return;
      }
      var circuitWord = circuit ? 'SUITABLE (1)' : 'NOT SUITABLE (0)';
      if (recordedSense === 'approve' || recordedSense === 'decline') {
        var agree = (circuit && recordedSense === 'approve') || (!circuit && recordedSense === 'decline');
        if (agree) {
          checks.push(chk('outcome_binding', 'Recorded decision matches the circuit\'s answer', PASS,
            'The decision written in the record is the same decision the circuit returned: public input index 11 reads ' + circuitWord + '.',
            'It does not show that answer was correct, and — for a NOT SUITABLE answer — it does not mean anything failed. A clean proof of unsuitability is a correctly-formed decline.',
            'record.final_decision.outcome = ' + JSON.stringify(recorded) + '\npublic_inputs[11] = ' + circuitWord));
        } else {
          checks.push(chk('outcome_binding', 'Recorded decision matches the circuit\'s answer', FAIL, '', '',
            'CONTRADICTION. The record states an outcome the circuit did not return.\n'
            + '  record.final_decision.outcome = ' + JSON.stringify(recorded) + '\n'
            + '  public_inputs[11]             = ' + circuitWord + '\n'
            + 'One of the two was changed. Do not report either as the decision until this is resolved.'));
        }
      } else {
        checks.push(chk('outcome_binding', 'Recorded decision matches the circuit\'s answer', MISSING, '', '',
          'The record\'s outcome value ' + JSON.stringify(recorded) + ' is not in a vocabulary this tool recognises as an approval or a decline, '
          + 'so it cannot be compared with public input index 11, which reads ' + circuitWord + '. Both are shown under finding 2, uncombined.'));
      }
    })();

    /* --- 7.8 audit chain linkage --------------------------------------- */
    (function () {
      var entries = ctx.chain;
      if (!entries || !entries.length) {
        checks.push(missingArtifact('chain_linkage', 'Audit chain is unbroken', 'audit_chain_segment.jsonl',
          'Without the chain slice this tool cannot tell whether a record in this range was altered or removed after the fact.'));
        return;
      }
      if (entries.length === 1) {
        checks.push(chk('chain_linkage', 'Audit chain is unbroken', MISSING, '', '',
          'The bundle carries a single chain entry (seq ' + entries[0].seq + '). Linkage is a property of consecutive entries, so one entry proves nothing about adjacency.'));
        return;
      }
      var breaks = [], gaps = [];
      for (var i = 1; i < entries.length; i++) {
        var prev = entries[i - 1], cur = entries[i];
        if (typeof cur.seq === 'number' && typeof prev.seq === 'number' && cur.seq !== prev.seq + 1) {
          gaps.push('  seq ' + prev.seq + ' -> ' + cur.seq + ' is not consecutive');
          continue; // linkage across a gap is not expected to hold
        }
        if (!digestsEqual(cur.prev_hash, prev.event_hash)) {
          breaks.push('  entry seq ' + cur.seq + ' declares prev_hash ' + normDigest(cur.prev_hash).slice(0, 16) + '…'
            + '\n    but seq ' + prev.seq + ' hashes to ' + normDigest(prev.event_hash).slice(0, 16) + '…');
        }
      }
      var lo = entries[0].seq, hi = entries[entries.length - 1].seq;
      if (breaks.length) {
        checks.push(chk('chain_linkage', 'Audit chain is unbroken', FAIL, '', '',
          'BROKEN. The chain does not link across records ' + lo + ' to ' + hi + ':\n' + breaks.join('\n')
          + '\nAt least one record in this range was altered, removed, or reordered after it was written.'));
      } else if (gaps.length) {
        checks.push(chk('chain_linkage', 'Audit chain is unbroken', MISSING, '', '',
          'The slice is not contiguous, so linkage cannot be checked across it:\n' + gaps.join('\n')
          + '\nThis is expected of a per-organisation view: backend/api/src/audit/mod.rs keeps ONE global chain, and a filtered view shows non-consecutive seq with prev_hash values pointing at rows the viewer cannot see. '
          + 'Such a view proves membership and position, not adjacency. Obtain a contiguous slice to check linkage.'));
      } else {
        checks.push(chk('chain_linkage', 'Audit chain is unbroken', PASS,
          'The audit chain is unbroken from record ' + lo + ' to record ' + hi + '. This shows no record in that range was altered or removed after the fact.',
          'It does not show that the decision was correct, and it says nothing about records outside that range.',
          entries.map(function (e) {
            return '  seq ' + e.seq + '  ' + (e.event_type || '?') + '  hash ' + normDigest(e.event_hash).slice(0, 16) + '…';
          }).join('\n')));
      }
    })();

    /* --- 7.9 chain entry hashes cannot be recomputed here --------------- */
    if (ctx.chain && ctx.chain.length) {
      checks.push(chk('chain_recompute', 'Each chain entry recomputed from its payload', NOT_CHECKED, '', '',
        'Not possible for audit_chain_segment.jsonl, by design. backend/api/src/audit/mod.rs computes\n'
        + '  event_hash = SHA256(framed(event_type) || framed(ref_id) || framed(prev_hash) || framed(payload))\n'
        + 'but deliberately does not store `payload`, which makes the chain a commitment scheme rather than a record store. '
        + 'Given a claimed payload the hash can be checked, and that is exactly what the binding check below does with the one file that carries payloads. '
        + 'For the chain segment itself, no payloads travel, so linkage (checked above) is the strongest statement available here.'));
    }

    /* --- 7.9b the binding events, re-hashed here ------------------------ */
    jobs.push(checkBinding(ctx, checks));

    /* --- 7.10 issuance JWT against the pinned JWKS ---------------------- */
    jobs.push(checkJwt(ctx, checks));

    /* --- 7.11 origin of the seal --------------------------------------- */
    (function () {
      var seal = ctx.seal;
      if (!seal) return;
      if (seal.signature == null) {
        checks.push(chk('seal_origin', 'Origin of the seal', NOT_CHECKED, '', '',
          'The seal is unsigned (`"signature": null`). Editing the sealed bytes is detectable, but the seal itself does not evidence who created it. '
          + 'The strongest origin claim in this bundle is the issuance token checked above, not this seal.'));
      } else {
        checks.push(chk('seal_origin', 'Origin of the seal', NOT_CHECKED, '', '',
          'The seal carries a signature, but this tool does not know which key should have produced it and will not guess. Check it against the issuer key you independently trust.'));
      }
    })();

    /* --- 7.11b the chain-head checkpoint's external anchor --------------
       audit/checkpoint.rs signs a checkpoint over the chain head, and
       audit/anchor.rs (this stage) witnesses it outside the organisation
       via RFC 3161. Both are strong claims — a JWS signature and a
       timestamp-authority receipt — and this console deliberately does not
       re-verify either cryptographically. That is scripts/bundle/
       verify_bundle.py step 7c's job, in a tool that ships asn1crypto and
       can spend the code weight a browser page should not carry for a
       feature most auditors will see once. What this DOES do, honestly,
       is show which of the three anchor states audit/anchor.rs::classify
       reported — anchored / pending / overdue — since even an unverified
       label is more than the previous stage's console showed: no anchor
       concept existed here at all. Report the label as what the server
       said, not as this tool's own finding. */
    (function () {
      var file = byRole.checkpoint;
      if (!file) {
        checks.push(chk('checkpoint_anchor', 'The chain-head checkpoint, and its external anchor', MISSING, '', '',
          'Not checked: no `audit_chain_checkpoint.json` in this bundle. Without it, the newest record in audit_chain_segment.jsonl is unprotected — see 7.9\'s note above — and there is no anchor state to report at all. '
          + 'Ask for a bundle rebuilt against a live server (scripts/bundle/build_bundle.py fetches one automatically), or GET /audit/checkpoints/covering/:seq directly.'));
        return;
      }
      var cp = jsonOf(file);
      if (!cp || cp.__parse_error) {
        checks.push(chk('checkpoint_anchor', 'The chain-head checkpoint, and its external anchor', FAIL, '', '',
          '`audit_chain_checkpoint.json` is present but not valid JSON: ' + (cp ? cp.__parse_error : 'empty file') + '.'));
        return;
      }
      var anchor = cp.external_anchor;
      var lines = [
        'checkpoint_no ' + JSON.stringify(cp.checkpoint_no),
        'head_seq      ' + JSON.stringify(cp.head_seq),
        'signed_at     ' + JSON.stringify(cp.signed_at)
      ];
      if (!anchor || !anchor.status) {
        checks.push(chk('checkpoint_anchor', 'The chain-head checkpoint, and its external anchor', MISSING,
          '', '',
          lines.concat(['This checkpoint carries no `external_anchor` state at all — either it predates anchoring, or the bundle was built by a builder that does not know about it.']).join('\n')));
        return;
      }
      lines.push('anchor status ' + JSON.stringify(anchor.status) + '  (as reported by the server — see the note above)');
      if (anchor.target) lines.push('anchor target ' + JSON.stringify(anchor.target));
      if (anchor.reference) lines.push('anchor ref    ' + JSON.stringify(anchor.reference));
      if (anchor.anchored_at) lines.push('anchored_at   ' + JSON.stringify(anchor.anchored_at));
      var plain, notMean;
      if (anchor.status === 'anchored') {
        plain = 'The server reports this checkpoint was witnessed outside the organisation, and names when.';
        notMean = 'This tool did not verify the JWS signature or the RFC 3161 receipt — it is reporting the server\'s own label, the same caution 7.11 above applies to the seal. For a cryptographic answer, use scripts/bundle/verify_bundle.py step 7c against a bundle carrying the receipt and the TSA certificate chain.';
      } else if (anchor.status === 'overdue') {
        plain = 'The server reports this checkpoint is overdue for anchoring — older than the sweep interval and still unwitnessed outside the organisation.';
        notMean = 'This is the server\'s own finding, not a failure of this tool\'s making. It means the "narrows the rewrite window to the anchor cadence" guarantee is not yet in force for this checkpoint: until it is anchored, an insider with database access and the signing key has the same reach the pre-anchoring stage always had over rows this checkpoint covers.';
      } else {
        plain = 'The server reports this checkpoint as ' + JSON.stringify(anchor.status) + ' — younger than the sweep interval, on its way to being anchored.';
        notMean = 'Not anchored yet is not a defect; the sweep is deliberately eventually-consistent (checkpointing must not block on a timestamp authority being reachable). Re-check after the sweep interval if this needs to be current.';
      }
      checks.push(chk('checkpoint_anchor', 'The chain-head checkpoint, and its external anchor',
        anchor.status === 'anchored' ? NOT_CHECKED : (anchor.status === 'overdue' ? FAIL : NOT_CHECKED),
        plain, notMean, lines.join('\n')));
    })();

    /* --- 7.12 schema ---------------------------------------------------- */
    (function () {
      var declared = firstOf(ev, ['evidence_schema_version']);
      var file = byRole.schema;
      if (declared === undefined) {
        checks.push(chk('schema', 'Record declares the schema it follows', MISSING, '', '',
          'The record carries no `evidence_schema_version`. An examiner reading it years from now has no way to know which shape it was written to.'));
        return;
      }
      if (!file) {
        checks.push(missingArtifact('schema', 'Record declares the schema it follows', 'evidence_schema/v' + declared + '.json',
          'The record declares schema version ' + declared + ', but that schema is not in the bundle, so its structure cannot be confirmed against the definition it claims.'));
        return;
      }
      var want = 'v' + String(declared) + '.json';
      if (file.name.toLowerCase() === want.toLowerCase()) {
        checks.push(chk('schema', 'Record declares the schema it follows', PASS,
          'The record declares schema version ' + declared + ' and that exact schema file travels with it, so its structure can be read without access to Memtara.',
          'This tool compared the declared version to the filename; it did not validate every field against the schema.',
          'evidence_schema_version = ' + declared + '\nbundled schema = ' + file.path));
      } else {
        checks.push(chk('schema', 'Record declares the schema it follows', FAIL, '', '',
          'The record declares schema version ' + declared + ' but the bundled schema is `' + file.name + '`. The record and its definition disagree.'));
      }
    })();

    return Promise.all(jobs).then(function () { return checks; });
  }

  /* ---------------------------------------------------------------------
     7.9b BINDING — the third claim, and the only one that survives an edit
          to the firm's database.

     Three separable claims live in Memtara's log and conflating them is how a
     system ends up describing itself as tamper-evident when one of the three
     holds:

       LINKAGE  no record was removed or reordered.        7.8, above.
       HEAD     the newest record, which nothing follows,
                is committed to from outside the log.      a signed checkpoint.
       BINDING  the mutable rows this decision is judged
                on STILL SAY what was hashed.              here, and nowhere else.

     backend/api/src/audit/binding.rs exists because a single UPDATE against
     `decision_model_attestations` rewrote the model identity the sealed record
     served and left the log BYTE-IDENTICAL either side of it. Not a chain that
     failed to notice — there was nothing in it to notice with.

     Memtara's own verdict on these events is deliberately NOT in the bundle.
     It carries the inputs; this file computes the answer. A console that
     displayed a supplier's opinion of the supplier's own evidence would have
     added nothing.
     --------------------------------------------------------------------- */

  var MODEL_ATTESTATION_BOUND = 'decision_model_attestation_bound';

  // Payload key -> the leaf of the record's `model` block it must agree with.
  var BOUND_MODEL_LEAVES = {
    model_provider: 'provider',
    model_name: 'model_name',
    model_version: 'model_version',
    prompt_version: 'prompt_version',
    model_environment: 'environment',
    model_config_fingerprint: 'config_fingerprint',
    model_system_prompt_or_policy_id: 'system_prompt_or_policy_id',
    model_timestamp: 'timestamp'
  };

  function parseBindingEvents(ctx) {
    var out = [], f = ctx.byRole.binding;
    if (!f) return null;                      // no file at all: a different state from an empty one
    var lines = (textOf(f) || '').split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim();
      if (!l) continue;
      try { out.push(JSON.parse(l)); } catch (e) { out.push({ __parse_error: e.message }); }
    }
    return out;
  }

  function bindingEventHash(event) {
    var ref = uuidBytes(event.ref_id);
    if (ref === null) return Promise.resolve({ error: 'ref_id ' + JSON.stringify(event.ref_id) + ' is not a UUID, and audit/mod.rs hashes the identifier\'s 16 raw bytes — there is no defensible way to fold this value in' });
    var prev = (event.prev_hash === null || event.prev_hash === undefined || event.prev_hash === '')
      ? new Uint8Array(0) : b64urlToBytes(event.prev_hash);
    var payload;
    try { payload = utf8(canonicalString(event.rebuilt_payload)); }
    catch (e) { return Promise.resolve({ error: 'the payload could not be canonicalised: ' + e.message }); }
    var message = concatBytes([
      framed(utf8(String(event.event_type || ''))),
      framed(ref),
      framed(prev),
      framed(payload)
    ]);
    return sha256Hex(message).then(function (h) { return { hex: h }; });
  }

  function checkBinding(ctx, checks) {
    var events = parseBindingEvents(ctx);
    ctx.binding = { state: null, events: events || [], modelState: null, note: '' };

    if (events === null) {
      ctx.binding.state = MISSING;
      checks.push(chk('binding_recompute', 'Bound rows still say what was fingerprinted', MISSING, '', '',
        'Not checked: no `audit_binding_events.jsonl` in this bundle.\n'
        + 'This is NOT the same as a clean result. The chain-linkage check above proves no record was removed or reordered; it says nothing about whether the rows this decision is judged on still CONTAIN what was fingerprinted. '
        + 'A single database UPDATE against decision_model_attestations rewrites the model identity the sealed record serves and leaves the chain byte-identical — see backend/api/src/audit/binding.rs. Obtain a bundle that carries the binding events.'));
      checks.push(chk('binding_model', 'Record and chain agree on the model', MISSING, '', '',
        'Not checked: without the binding events there is no fingerprinted model identity to compare the record against. '
        + 'The record\'s model block — including a `model: null` assertion that no AI participated — rests on the seal alone here. The seal shows it was not edited since export; it cannot show it agrees with what was fingerprinted when the decision was opened.'));
      return Promise.resolve();
    }

    if (!events.length) {
      ctx.binding.state = MISSING;
      checks.push(chk('binding_recompute', 'Bound rows still say what was fingerprinted', MISSING, '', '',
        '`audit_binding_events.jsonl` is present and carries no events.\n'
        + 'That is a finding rather than a clean result: every assessment opened since binding events landed writes them in the same transaction as the request row, so an assessment with none either predates that change or had them removed — and a removal breaks linkage, which is the check above.'));
      checks.push(chk('binding_model', 'Record and chain agree on the model', MISSING, '', '',
        'Not checked: the binding file carries no events, so there is no fingerprinted model identity to compare the record against.'));
      return Promise.resolve();
    }

    return Promise.all(events.map(function (e) {
      if (e.__parse_error) return Promise.resolve({ event: e, error: 'the line is not valid JSON: ' + e.__parse_error });
      if (!Object.prototype.hasOwnProperty.call(e, 'rebuilt_payload')) {
        return Promise.resolve({ event: e, error: 'the event carries no `rebuilt_payload` key at all, so there is nothing to fingerprint' });
      }
      if (e.rebuilt_payload === null) {
        return Promise.resolve({ event: e, gone: true });
      }
      return bindingEventHash(e).then(function (r) { return { event: e, error: r.error, hex: r.hex }; });
    })).then(function (results) {
      var lines = [], bad = 0, unresolved = 0;
      lines.push('event_hash = SHA256(framed(event_type) || framed(ref_id) || framed(prev_hash) || framed(payload))');
      lines.push('  framed(x) is an 8-byte big-endian length then x; ref_id is the identifier\'s 16 raw bytes;');
      lines.push('  prev_hash is the raw fingerprint bytes; payload is the canonical JSON of rebuilt_payload.');
      results.forEach(function (r) {
        var e = r.event;
        var head = '  ' + (e.event_type || '(no event_type)') + '  seq ' + (e.seq === undefined ? '?' : e.seq);
        if (r.gone) {
          unresolved++;
          lines.push(head + '  ->  SOURCE ROW GONE');
          lines.push('    The rows this event commits to no longer existed when the bundle was built. The event survives as a commitment that they did and to what they said; there is nothing left here to compare it against.');
          return;
        }
        if (r.error) {
          unresolved++;
          lines.push(head + '  ->  CANNOT RECOMPUTE');
          lines.push('    ' + r.error);
          return;
        }
        var recordedHex = toHex(b64urlToBytes(e.event_hash || ''));
        if (digestsEqual(r.hex, recordedHex)) {
          lines.push(head + '  ->  INTACT');
          lines.push('    recomputed ' + r.hex.slice(0, 32) + '…  matches the fingerprint the chain recorded');
        } else {
          bad++;
          lines.push(head + '  ->  ALTERED');
          lines.push('    recomputed ' + r.hex);
          lines.push('    recorded   ' + recordedHex);
        }
      });

      if (bad) {
        ctx.binding.state = FAIL;
        checks.push(chk('binding_recompute', 'Bound rows still say what was fingerprinted', FAIL, '', '',
          lines.join('\n')
          + '\nThe details in this bundle do not fingerprint to the value the chain recorded. Either the rows changed after the event was written, or this file was edited afterwards.'
          + '\nNote that the chain-linkage check above will very likely still show as unbroken. That is the point of this check existing: linkage cannot see an edit to a row\'s contents.'));
      } else if (unresolved) {
        ctx.binding.state = MISSING;
        checks.push(chk('binding_recompute', 'Bound rows still say what was fingerprinted', MISSING, '', '',
          lines.join('\n')
          + '\nNothing here is shown to be broken and not everything could be checked. Neither state is an accusation: a vanished source row is a real incident this file cannot settle, and an event this tool cannot reproduce is a defect in the tool until it is explained.'));
      } else {
        ctx.binding.state = PASS;
        checks.push(chk('binding_recompute', 'Bound rows still say what was fingerprinted', PASS,
          'The rows behind this decision — the model that was declared and the policy it was measured against — still contain exactly what was fingerprinted into the audit chain when the decision was opened. Nobody has edited them since.',
          'It does not show those rows were TRUE when written: the model attestation is a forward declaration made before the proof existed and before anyone reviewed the decision. And it is not a linkage check — each event is re-fingerprinted against the previous fingerprint it carries, so a run of records rewritten consistently would pass here and fail the check above.',
          lines.join('\n')));
      }

      checkBindingModel(ctx, results, checks);
    });
  }

  /**
   * Does the record tell the same story as the chain about the model?
   *
   * THE CHECK THAT CATCHES A TAMPERED BUNDLE. The recomputation above proves
   * the carried payload fingerprints to the carried value; it says nothing
   * about the record beside it. Someone holding only the bundle edits the
   * record's model block and leaves the binding file alone — every fingerprint
   * still checks out, and only this comparison notices.
   *
   * `model: null` is its own case and never blurs into "no model named". It is
   * a signed statement that no AI system participated. A record making it for a
   * decision whose fingerprinted declaration names a model is the worst shape
   * this failure takes, and it is reported as a contradiction.
   */
  function checkBindingModel(ctx, results, checks) {
    var ev = ctx.evidence;
    var usable = results.filter(function (r) {
      return r.event && r.event.event_type === MODEL_ATTESTATION_BOUND
        && r.event.rebuilt_payload && typeof r.event.rebuilt_payload === 'object';
    });
    if (!usable.length) {
      ctx.binding.modelState = MISSING;
      checks.push(chk('binding_model', 'Record and chain agree on the model', MISSING, '', '',
        'This bundle carries no usable `' + MODEL_ATTESTATION_BOUND + '` event, so there is no fingerprinted model identity to compare the record against.\n'
        + 'The record\'s model block — whatever it says, including a `model: null` assertion that no AI participated — rests on the seal alone here.'));
      return;
    }

    var payload = usable[0].event.rebuilt_payload;
    var declaration = payload.declaration;
    var present = ev && Object.prototype.hasOwnProperty.call(ev, 'model');
    var model = present ? ev.model : undefined;
    var detail = ['chain-bound declaration  ' + JSON.stringify(declaration)];

    if (!present) {
      ctx.binding.modelState = MISSING;
      checks.push(chk('binding_model', 'Record and chain agree on the model', MISSING, '', '',
        detail.concat([
          'The record carries no `model` key at all, so there is nothing to compare. An absent key is NOT the `model: null` assertion: absence says nothing, null says — inside the sealed bytes — that no AI took part.'
        ]).join('\n')));
      return;
    }

    var assertsNoAi = model === null;
    detail.push('record\'s model block     ' + (assertsNoAi ? 'null — a signed assertion that no AI participated' : (typeof model)));

    if (declaration === 'no_ai_participated' && !assertsNoAi) {
      return contradiction(detail.concat([
        'CONTRADICTION. The chain committed to a declaration that no AI participated, and the record serves a model block anyway. One of the two was changed after the binding event was written.'
      ]));
    }
    if (declaration && declaration !== 'no_ai_participated' && assertsNoAi) {
      return contradiction(detail.concat([
        'CONTRADICTION, and it is the worst shape this failure takes. The record serves `model: null` — the strongest claim the record can make, a signed assertion that no AI system took part — for a decision the chain committed to as ' + JSON.stringify(declaration) + '.',
        'Do not rely on the no-AI assertion in this record.'
      ]));
    }
    if (assertsNoAi) {
      ctx.binding.modelState = ASSERTED_ABSENT;
      checks.push(chk('binding_model', 'Record and chain agree on the model', PASS,
        'The record\'s statement that no AI system participated in this decision is the statement the audit chain fingerprinted when the decision was opened. It was not added, removed or altered afterwards.',
        'It does not show the statement was true. It is the firm\'s own declaration about its own process, made when the assessment was opened, and nothing in this bundle can check it against what actually ran.',
        detail.concat(['stated to have decided instead: ' + JSON.stringify(payload.no_ai_attestation)]).join('\n')));
      return;
    }

    var disagreements = [], compared = 0;
    Object.keys(BOUND_MODEL_LEAVES).sort().forEach(function (boundKey) {
      var leafKey = BOUND_MODEL_LEAVES[boundKey];
      var bound = payload[boundKey];
      var f = readField(model, leafKey);
      var boundAbsent = bound === null || bound === undefined;
      var recordAbsent = f.state !== RECORDED;
      if (boundAbsent && recordAbsent) return;
      compared++;
      if (boundAbsent !== recordAbsent || String(bound) !== String(f.value)) {
        disagreements.push('  ' + leafKey + '\n    chain-bound ' + JSON.stringify(bound === undefined ? null : bound)
          + '\n    record says ' + JSON.stringify(recordAbsent ? null : f.value));
      }
    });

    if (disagreements.length) {
      return contradiction(detail.concat([
        disagreements.length + ' of ' + compared + ' compared model fields disagree:'
      ]).concat(disagreements));
    }
    ctx.binding.modelState = RECORDED;
    checks.push(chk('binding_model', 'Record and chain agree on the model', PASS,
      'The model identity written in this record is the identity the audit chain fingerprinted when the decision was opened, so neither the record nor the chain entry was edited to agree with the other.',
      'It does not show the identity was correct. It is the firm\'s own declaration about its own software, and nothing in this bundle can check it against the model that actually ran.',
      detail.concat([compared + ' model field(s) compared, all in agreement']).join('\n')));

    function contradiction(lines) {
      ctx.binding.modelState = CONFLICT;
      checks.push(chk('binding_model', 'Record and chain agree on the model', FAIL, '', '',
        lines.concat([
          'The record and the audit chain do not tell the same story about which model produced this decision. Whichever side was edited, the identity in the record is not the identity that was fingerprinted. Do not report either until it is explained.'
        ]).join('\n')));
    }
  }

  /* --- JWT / JWKS ----------------------------------------------------- */

  function checkJwt(ctx, checks) {
    var ev = ctx.evidence, byRole = ctx.byRole;
    var token = null;
    var iss = firstOf(ev, ['issuance']) || {};
    token = firstOf(iss, ['jwt', 'token']);
    if (!token && byRole.jwt) token = (textOf(byRole.jwt) || '').trim();
    if (!token) {
      checks.push(chk('jwt', 'Issuance token signature', MISSING, '', '',
        'No issuance token was found in the record or the bundle, so nothing here carries an origin claim from the issuer.'));
      return Promise.resolve();
    }
    var parts = String(token).split('.');
    if (parts.length !== 3) {
      checks.push(chk('jwt', 'Issuance token signature', FAIL, '', '',
        'The issuance token is not a well-formed compact JWS (expected three dot-separated segments, found ' + parts.length + ').'));
      return Promise.resolve();
    }
    var header, claims;
    try {
      header = JSON.parse(textOf({ bytes: b64urlToBytes(parts[0]) }));
      claims = JSON.parse(textOf({ bytes: b64urlToBytes(parts[1]) }));
    } catch (e) {
      checks.push(chk('jwt', 'Issuance token signature', FAIL, '', '',
        'The issuance token\'s header or claims are not valid JSON: ' + e.message));
      return Promise.resolve();
    }
    ctx.jwtClaims = claims;

    var jwks = ctx.jwks;
    if (!jwks || !jwks.keys || !jwks.keys.length) {
      checks.push(chk('jwt', 'Issuance token signature', MISSING, '', '',
        'A token is present but `jwks_snapshot.json` is not in this bundle. Its signature cannot be checked offline.\n'
        + 'This tool will not fetch the issuer\'s live JWKS: a bundle whose verified stamp depended on what DNS answered would be asserting something it cannot evidence, and would stop working the day the issuer does.'));
      return Promise.resolve();
    }
    var kid = header.kid;
    var jwk = null;
    for (var i = 0; i < jwks.keys.length; i++) {
      if (!kid || jwks.keys[i].kid === kid) { jwk = jwks.keys[i]; break; }
    }
    if (!jwk) {
      checks.push(chk('jwt', 'Issuance token signature', FAIL, '', '',
        'The token names key `' + kid + '`, which is not in the pinned JWKS snapshot. The snapshot does not contain the key that signed this token.'));
      return Promise.resolve();
    }
    if (header.alg !== 'EdDSA' || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      checks.push(chk('jwt', 'Issuance token signature', NOT_CHECKED, '', '',
        'The token uses alg=' + header.alg + ' with a ' + jwk.kty + '/' + jwk.crv + ' key. This tool checks Ed25519 (EdDSA) only, and will not attempt an algorithm it cannot verify correctly.'));
      return Promise.resolve();
    }

    var signed = utf8(parts[0] + '.' + parts[1]);
    var sig = b64urlToBytes(parts[2]);
    return subtle().importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify'])
      .then(function (key) { return subtle().verify({ name: 'Ed25519' }, key, sig, signed); })
      .then(function (ok) {
        if (ok) {
          checks.push(chk('jwt', 'Issuance token signature', PASS,
            'The issuance token was signed by the key pinned in this bundle\'s JWKS snapshot, so the record carries a claim of origin that survives without any contact with Memtara.',
            'It does not show that the pinned snapshot holds the issuer\'s real key. That is a trust decision about where you obtained this bundle, not a calculation this tool can perform.',
            'alg=EdDSA kid=' + (kid || '(unnamed)') + '\niss=' + (claims.iss || '?') + '  sub=' + (claims.sub || '?')
            + (claims.proof_hash ? '\nproof_hash claim = ' + claims.proof_hash : '')));
          // Does the signed token commit to the same proof as the record?
          var recorded = proofDigestOf(proofRecord(ev));
          if (claims.proof_hash && recorded) {
            if (digestsEqual(claims.proof_hash, recorded)) {
              checks.push(chk('jwt_binding', 'Token is about this proof', PASS,
                'The signed token commits to the same proof digest the record names, so the signature covers this case and not another one.',
                'It does not show the proof is valid — only that the issuer signed a statement about this particular proof.',
                'claim ' + normDigest(claims.proof_hash) + '\nrecord ' + normDigest(recorded)));
            } else {
              checks.push(chk('jwt_binding', 'Token is about this proof', FAIL, '', '',
                'The signed token is about a different proof than the record.\n  token claim ' + normDigest(claims.proof_hash) + '\n  record      ' + normDigest(recorded)));
            }
          }
        } else {
          checks.push(chk('jwt', 'Issuance token signature', FAIL, '', '',
            'The issuance token\'s signature does not verify against the pinned JWKS snapshot. Either the token or the snapshot was altered.'));
        }
      })
      .catch(function (e) {
        checks.push(chk('jwt', 'Issuance token signature', NOT_CHECKED, '', '',
          'This environment could not perform an Ed25519 verification (' + e.message + '). '
          + 'Ed25519 in WebCrypto is not available in every browser. The signature is neither confirmed nor refuted here — check it with any standard JOSE tool against `jwks_snapshot.json`, offline.'));
      });
  }

  /* ---------------------------------------------------------------------
     8. The six blocks
     --------------------------------------------------------------------- */

  function row(label, f, opts) {
    opts = opts || {};
    var r = {
      label: label,
      state: f.state,
      value: f.value,
      reason: f.reason,
      note: f.state === RECORDED ? (opts.note || '') : (f.reason || WHY_TEXT[f.why] || '')
    };
    if (f.state === GAP && opts.meaning) {
      r.note = (r.note ? r.note + ' ' : '') + opts.meaning;
    }
    r.mono = !!opts.mono;
    return r;
  }

  function fmt(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'string') return v;
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (typeof v === 'number') return String(v);
    if (Array.isArray(v)) {
      return v.map(function (x) {
        if (x && typeof x === 'object') {
          if (x.framework || x.clause) return [x.framework, x.clause].filter(Boolean).join(' ');
          return JSON.stringify(x);
        }
        return String(x);
      }).join(', ');
    }
    return JSON.stringify(v);
  }

  function buildBlocks(ctx) {
    var ev = ctx.evidence;
    var blocks = [];

    /* ---- Decision ---- */
    var fd = ev.final_decision || {};
    blocks.push({
      id: 'decision', title: 'Decision', rows: [
        row('Decision ID', readField(ev, 'decision_id'), { mono: true, meaning: 'Without an identifier this record cannot be tied to a case file.' }),
        row('Business process', readField(ev, 'business_process'), { meaning: 'It is not recorded what kind of decision this was.' }),
        row('Outcome', readField(fd, 'outcome'), { meaning: 'The record does not state what was decided. Read finding 2 for what the circuit returned.' }),
        row('Decided at', readField(fd, 'decided_at'), { mono: true, meaning: 'It is not recorded when this decision was taken.' }),
        row('Decision basis', readField(fd, 'decision_basis'), { meaning: 'It is not recorded whether this rested on the proof alone, on the proof plus a human approval, or on an override.' }),
        row('Institution', readField(ev.institution || {}, 'org_name'), { meaning: 'The institution accountable for this decision is not recorded.' })
      ]
    });

    /* ---- Policy ---- */
    var pol = ev.policy || {};
    blocks.push({
      id: 'policy', title: 'Policy', rows: [
        row('Policy', readField(pol, 'policy_id'), { mono: true, meaning: 'The rule set this decision was taken under is not identified.' }),
        row('Policy version', readField(pol, 'policy_version'), { mono: true, meaning: 'Which version of the policy applied cannot be established, so this decision cannot be re-tested against the rules that were live at the time.' }),
        row('Policy source', readField(pol, 'source'), { meaning: 'Where the policy text came from is not recorded.' }),
        row('Regulatory clauses', readField(ev, 'regulatory_control_mapping'), { meaning: 'This decision is not mapped to any regulatory clause.' })
      ]
    });

    /* ---- Data ---- */
    var cust = ev.customer || {}, cons = ev.consent || {}, thr = ev.thresholds || {};
    blocks.push({
      id: 'data', title: 'Data', rows: [
        row('Subject', readField(cust, 'subject_id'), { mono: true, meaning: 'The person this decision was about is not identified.' }),
        row('Provenance', readField(cust, 'data_provenance'), { meaning: 'Where the data behind this decision came from is not recorded.' }),
        row('Provenance version', readField(cust, 'data_provenance_version'), { mono: true, meaning: 'The version of the data schema is not recorded, so the fields cannot be interpreted with certainty later.' }),
        row('Consent', readField(cons, 'consent_id'), { mono: true, meaning: 'No consent record is referenced. This does not show consent was absent — it shows this record does not evidence it.' }),
        row('Consent version', readField(cons, 'consent_version'), { mono: true, meaning: 'Which consent terms applied is not recorded.' }),
        row('Consent scope', readField(cons, 'scope'), { meaning: 'What the subject consented to is not recorded.' }),
        row('Consent granted at', readField(cons, 'granted_at'), { mono: true, meaning: 'When consent was given is not recorded.' }),
        row('Thresholds', readField(thr, 'threshold_set_id'), { mono: true, meaning: 'The threshold set applied is not identified.' }),
        row('Threshold version', readField(thr, 'threshold_version'), { mono: true, meaning: 'Which version of the thresholds applied cannot be established, so it cannot be shown that the approved figures were the ones used.' }),
        row('Threshold values', readField(thr, 'values'), { meaning: 'The figures tested against are not recorded.' })
      ]
    });

    /* ---- Model — the block where the two absent-states must not blur ---- */
    blocks.push(buildModelBlock(ev, ctx));

    /* ---- Human ---- */
    var hr = ev.human_review;
    if (!ev || !Object.prototype.hasOwnProperty.call(ev, 'human_review')) {
      blocks.push({
        id: 'human', title: 'Human', headline: {
          state: GAP, text: 'UNRECORDED — no human review block',
          detail: 'The record does not say whether a person reviewed this decision. This is a gap, not a statement that nobody did.'
        }, rows: []
      });
    } else if (hr === null) {
      blocks.push({
        id: 'human', title: 'Human', headline: {
          state: ASSERTED_ABSENT, text: 'NO HUMAN REVIEW — signed assertion',
          detail: 'The record asserts, inside the sealed bytes, that this decision was taken without human review. That is an answer, not a gap — but it is also a statement that an automated decision went out unreviewed, which is itself a finding worth raising.'
        }, rows: []
      });
    } else {
      hr = hr || {};
      blocks.push({
        id: 'human', title: 'Human', rows: [
          row('Reviewer', readField(hr, 'reviewer_id'), { mono: true, meaning: 'No reviewer is identified, so accountability for this decision cannot be placed with a person.' }),
          row('Reviewer role', readField(hr, 'reviewer_role'), { meaning: 'The reviewer\'s authority to take this decision is not recorded.' }),
          row('Action', readField(hr, 'action'), { meaning: 'What the reviewer did is not recorded.' }),
          row('Override', readField(hr, 'override'), { meaning: 'It is not recorded whether the reviewer overrode the system.' }),
          row('Override reason', readField(hr, 'override_reason'), { meaning: 'If an override occurred, no reason was captured.' }),
          row('Reviewed at', readField(hr, 'reviewed_at'), { mono: true, meaning: 'When the review took place is not recorded.' })
        ]
      });
    }

    return blocks;
  }

  /**
   * MODEL — the distinction the console must not get wrong.
   *
   *   model absent from the record   -> GAP. Unrecorded. Says nothing either way.
   *   model === null                 -> ASSERTED ABSENT. A signed statement that
   *                                     no AI system took part. An ANSWER.
   *   model is a Provenanced envelope with state not_applicable
   *                                  -> ASSERTED ABSENT, with the reason shown.
   *   model is a Provenanced envelope with state unpopulated
   *                                  -> GAP, with the reason shown.
   *   model is an object             -> render its fields, each with its own state.
   */
  /**
   * One row, in the Model block, saying whether the audit chain committed to
   * the identity above it.
   *
   * Put here rather than only in the checks table because this is where a
   * reader looks when they want to know what the model was, and "the chain
   * agrees" and "nothing checks this" have to be legible in the same glance as
   * the identity itself. It is also the one row whose ASSERTED-ABSENT state is
   * reachable — a fingerprinted `no_ai_participated` declaration — so it is
   * where the fifth glyph, [-], appears on a printed page.
   */
  function bindingRow(ctx) {
    var s = ctx && ctx.binding ? ctx.binding.modelState : null;
    if (s === RECORDED) {
      return { label: 'Bound to the audit chain', state: RECORDED, value: 'yes — the chain committed to this identity',
        reason: null, mono: false,
        note: 'The identity above is the one fingerprinted into the audit chain when this decision was opened. It has not been edited since.' };
    }
    if (s === ASSERTED_ABSENT) {
      return { label: 'Bound to the audit chain', state: ASSERTED_ABSENT, value: null, reason: null, mono: false,
        note: 'The chain committed to a declaration that no AI system participated. The assertion in this record is the assertion that was fingerprinted, not one added afterwards.' };
    }
    if (s === CONFLICT) {
      return { label: 'Bound to the audit chain', state: CONFLICT, value: null, reason: null, mono: false,
        note: 'The record and the chain disagree about which model produced this decision. See the binding check for the fields that differ. Do not report either identity until it is explained.' };
    }
    return { label: 'Bound to the audit chain', state: GAP, value: null, reason: null, mono: false,
      note: 'Nothing in this bundle fingerprints the identity above. A database edit to the model this decision was recorded against would leave the audit chain unchanged and would not be visible anywhere in this pack. Obtain a bundle carrying audit_binding_events.jsonl.' };
  }

  function buildModelBlock(ev, ctx) {
    var present = ev && Object.prototype.hasOwnProperty.call(ev, 'model');
    if (!present) {
      return {
        id: 'model', title: 'Model', headline: {
          state: GAP,
          text: 'UNRECORDED — no model block',
          detail: 'The record is silent on whether an AI or model system took part in this decision. '
                + 'This is a gap, not a denial. Nothing here shows that no model was involved — only that, if one was, this record does not identify it. '
                + 'Treat any claim about model governance for this case as unevidenced.'
        }, rows: [bindingRow(ctx)]
      };
    }
    var m = ev.model;
    if (m === null) {
      return {
        id: 'model', title: 'Model', headline: {
          state: ASSERTED_ABSENT,
          text: 'NO AI SYSTEM PARTICIPATED — signed assertion',
          detail: 'The record states, inside the sealed and signed bytes, that no AI or model system took part in this decision. '
                + 'This is an answer, not a gap: the assertion is covered by the same digest as the rest of the record, so it could not be added or removed afterwards without breaking the seal. '
                + 'No model governance evidence is expected for this case.'
        }, rows: [bindingRow(ctx)]
      };
    }
    if (m && typeof m === 'object' && typeof m.state === 'string' && Object.prototype.hasOwnProperty.call(m, 'value')) {
      if (m.state === 'not_applicable') {
        return {
          id: 'model', title: 'Model', headline: {
            state: ASSERTED_ABSENT,
            text: 'NO AI SYSTEM PARTICIPATED — signed assertion',
            detail: 'The record asserts this block does not apply to this decision. Stated reason: ' + (m.unpopulated_reason || '(none given)')
                  + ' This is an answer, not a gap.'
          }, rows: [bindingRow(ctx)]
        };
      }
      if (m.state === 'unpopulated') {
        return {
          id: 'model', title: 'Model', headline: {
            state: GAP,
            text: 'UNRECORDED — the record admits it does not know',
            detail: 'The record explicitly states this block was not populated. Stated reason: ' + (m.unpopulated_reason || '(none given)')
                  + ' This is a gap, not a denial: it does not show that no model was involved.'
          }, rows: [bindingRow(ctx)]
        };
      }
      m = m.value || {};
    }
    return {
      id: 'model', title: 'Model', rows: [
        row('Provider', readField(m, 'provider'), { meaning: 'The supplier of the model is not recorded.' }),
        row('Model', readField(m, 'model_name'), { mono: true, meaning: 'Which model produced this is not recorded, so it cannot be established what was actually running.' }),
        row('Model version', readField(m, 'model_version'), { mono: true, meaning: 'The exact version is not recorded, so this decision cannot be reproduced or attributed to a known build.' }),
        row('Environment', readField(m, 'environment'), { meaning: 'It is not recorded whether this ran in production or in a test environment.' }),
        row('Config fingerprint', readField(m, 'config_fingerprint'), { mono: true, meaning: 'The model configuration is not fingerprinted, so a change of settings between decisions would not be detectable.' }),
        row('System prompt / policy', readField(m, 'system_prompt_or_policy_id'), { mono: true, meaning: 'The instructions given to the model are not identified.' }),
        row('Model invoked at', readField(m, 'timestamp'), { mono: true, meaning: 'When the model was called is not recorded.' }),
        row('Input context fingerprint', readField(ev, 'input_context_fingerprint'), { mono: true, meaning: 'What the model was shown is not fingerprinted, so it cannot be shown which inputs produced this output.' }),
        row('Output fingerprint', readField(ev, 'output_fingerprint'), { mono: true, meaning: 'The model\'s output is not fingerprinted, so the recorded decision cannot be tied to what the model actually returned.' }),
        bindingRow(ctx)
      ]
    };
  }

  /* ---------------------------------------------------------------------
     9. The two verdicts
     --------------------------------------------------------------------- */

  function rollUpIntegrity(checks) {
    var counts = { pass: 0, fail: 0, missing: 0, not_checked: 0 };
    for (var i = 0; i < checks.length; i++) counts[checks[i].state]++;

    var verdict, headline, meaning;
    if (counts.fail > 0) {
      verdict = 'INVALID';
      headline = counts.fail + ' of ' + checks.length + ' checks FAILED.';
      meaning = 'At least one part of this record does not match what it is sealed against. '
              + 'Treat the record as unreliable until every failure below has been explained. '
              + 'This finding is about the record, not about the decision: it does not tell you what was decided.';
    } else if (counts.missing > 0) {
      verdict = 'INCOMPLETE';
      headline = counts.missing + ' check' + (counts.missing === 1 ? '' : 's') + ' could not be performed because this bundle does not contain what they need.';
      meaning = 'Nothing here is shown to be broken. Something here is shown to be unverifiable as delivered. '
              + 'Do not record this as verified; obtain the missing files and run it again.';
    } else {
      verdict = 'VALID';
      headline = counts.pass + ' of ' + checks.length + ' checks passed; the remaining ' + counts.not_checked + ' cannot be performed by any browser and are listed below.';
      meaning = 'Every check this tool can perform passed, and every artefact those checks needed was present. '
              + 'This finding is about the record\'s integrity only. It does not tell you what was decided, and it does not tell you the decision was right.';
    }
    return {
      verdict: verdict, counts: counts, headline: headline, meaning: meaning,
      notChecked: checks.filter(function (c) { return c.state === NOT_CHECKED; }).map(function (c) { return c.label; })
    };
  }

  function readOutcome(ctx) {
    var ev = ctx.evidence;
    var fd = ev.final_decision || {};
    var recorded = firstOf(fd, ['outcome']);
    var pis = publicInputsOf(ev);
    var circuit = pis ? suitableFromPublicInputs(pis) : null;
    var hr = (ev.human_review && typeof ev.human_review === 'object') ? ev.human_review : null;
    var action = hr ? firstOf(hr, ['action']) : undefined;

    var sources = [];
    sources.push({
      label: 'Recorded in the evidence file',
      where: 'final_decision.outcome',
      value: recorded === undefined ? null : fmt(recorded),
      state: recorded === undefined ? GAP : RECORDED
    });
    sources.push({
      label: 'Returned by the circuit',
      where: 'public input index 11 (`suitable`)',
      value: circuit === null ? null : (circuit ? 'SUITABLE (1)' : 'NOT SUITABLE (0)'),
      state: circuit === null ? GAP : RECORDED
    });
    sources.push({
      label: 'Taken by the human reviewer',
      where: 'human_review.action',
      value: action === undefined ? null : fmt(action),
      state: action === undefined ? GAP : RECORDED
    });

    var recSense = senseOf(recorded);
    var conflict = (circuit !== null && (recSense === 'approve' || recSense === 'decline'))
      && !((circuit && recSense === 'approve') || (!circuit && recSense === 'decline'));

    var verdict, sense, note;
    if (conflict) {
      verdict = 'CONFLICTING';
      sense = CONFLICT;
      note = 'The evidence file and the circuit do not agree on what was decided. Until that is resolved, this console will not name an outcome, because either answer it printed could be the wrong one.';
    } else if (recorded !== undefined && recSense) {
      verdict = String(recorded).toUpperCase().replace(/_/g, ' ');
      sense = recSense;
      note = sense === 'decline'
        ? 'This decision was a DECLINE. A clean integrity finding on a decline means the institution correctly recorded a decision NOT to proceed. It does not mean anything was approved.'
        : sense === 'approve'
          ? 'This decision was an APPROVAL. Check finding 1 separately: an approval recorded in a record that fails its integrity checks is not evidence of anything.'
          : 'This decision was recorded as "' + fmt(recorded) + '". Read the source rows below before summarising it.';
    } else if (circuit !== null) {
      verdict = circuit ? 'SUITABLE' : 'NOT SUITABLE';
      sense = circuit ? 'approve' : 'decline';
      note = 'The evidence file does not state an outcome in words. This is the circuit\'s own answer, read from public input index 11, and nothing more.';
    } else {
      verdict = 'NOT RECORDED';
      sense = null;
      note = 'This record does not state what was decided, and no circuit answer could be read. The decision is unknown from this bundle. That is not the same as a decline.';
    }

    // Human action diverging from the circuit is legitimate (a reviewer may
    // decline a technically-suitable product) — reported, never merged.
    var divergence = null;
    if (circuit !== null && action !== undefined) {
      var aSense = senseOf(action);
      if ((circuit && aSense === 'decline') || (!circuit && aSense === 'approve')) {
        divergence = 'The human reviewer\'s action (' + fmt(action) + ') runs the other way from the circuit\'s answer ('
          + (circuit ? 'SUITABLE' : 'NOT SUITABLE') + '). That is permitted — a reviewer may decline a product the model found suitable — '
          + 'but it means the outcome rests on the reviewer\'s judgement, not on the proof. Look for an override reason under Human.';
      }
    }

    return { verdict: verdict, sense: sense, note: note, sources: sources, conflict: conflict, divergence: divergence };
  }

  /* ---------------------------------------------------------------------
     10. analyse()
     --------------------------------------------------------------------- */

  function parseChain(ctx) {
    var out = [];
    var f = ctx.byRole.chain;
    if (f) {
      var lines = (textOf(f) || '').split(/\r?\n/);
      for (var i = 0; i < lines.length; i++) {
        var l = lines[i].trim();
        if (!l) continue;
        try { out.push(JSON.parse(l)); } catch (e) { /* a malformed line is reported by linkage failing */ }
      }
    }
    if (!out.length) {
      var inline = firstOf(ctx.evidence || {}, ['audit_chain_excerpt', 'audit_chain']);
      if (Array.isArray(inline)) out = inline.slice();
    }
    out.sort(function (a, b) { return (a.seq || 0) - (b.seq || 0); });
    return out;
  }

  /**
   * files: [{ path, bytes: Uint8Array }]
   * returns Promise<report>
   */
  function analyse(files) {
    var idx = indexBundle(files || []);
    var ctx = { byRole: idx.byRole, all: idx.all, unrecognised: idx.unrecognised, notes: [] };

    if (!ctx.byRole.evidence) {
      return Promise.resolve({
        loaded: false,
        error: 'No `decision_evidence.json` in what you loaded. That file is the record; everything else in a bundle is evidence about it.',
        files: idx.all
      });
    }
    var parsed = jsonOf(ctx.byRole.evidence);
    if (!parsed || parsed.__parse_error) {
      return Promise.resolve({
        loaded: false,
        error: '`decision_evidence.json` is not valid JSON: ' + (parsed ? parsed.__parse_error : 'empty file') + '. A record that cannot be read cannot be relied on.',
        files: idx.all
      });
    }
    ctx.evidence = parsed;
    ctx.seal = ctx.byRole.seal ? jsonOf(ctx.byRole.seal) : null;
    if (ctx.seal && ctx.seal.__parse_error) ctx.seal = null;
    ctx.jwks = ctx.byRole.jwks ? jsonOf(ctx.byRole.jwks) : null;
    if (ctx.jwks && ctx.jwks.__parse_error) ctx.jwks = null;
    ctx.chain = parseChain(ctx);

    if (!Object.prototype.hasOwnProperty.call(parsed, 'evidence_schema_version')) {
      ctx.notes.push('This record does not carry `evidence_schema_version`. The v1 spec makes it a first-class field inside the signed bytes.');
    }
    if (!parsed.final_decision && parsed.outcome) {
      ctx.notes.push('This record uses the current backend shape (`outcome`) rather than the v1 spec shape (`final_decision`). Both were read.');
    }

    return runChecks(ctx).then(function (checks) {
      // Stable order regardless of which promise settled first.
      var order = ['canonical_digest', 'pdf_digest', 'vkey_digest', 'proof_digest', 'zk_pairing',
        'public_inputs', 'outcome_binding', 'chain_linkage', 'chain_recompute',
        'binding_recompute', 'binding_model', 'checkpoint_anchor',
        'jwt', 'jwt_binding', 'seal_origin', 'schema'];
      checks.sort(function (a, b) {
        var ia = order.indexOf(a.id), ib = order.indexOf(b.id);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      });
      var blocks = buildBlocks(ctx);
      var gaps = 0;
      blocks.forEach(function (b) {
        if (b.headline && b.headline.state === GAP) gaps++;
        (b.rows || []).forEach(function (r) { if (r.state === GAP) gaps++; });
      });
      return {
        loaded: true,
        caseId: firstOf(ctx.evidence, ['decision_id', 'request_id', 'case_id']) || '(no decision id in record)',
        schemaVersion: firstOf(ctx.evidence, ['evidence_schema_version']) || null,
        integrity: rollUpIntegrity(checks),
        outcome: readOutcome(ctx),
        checks: checks,
        blocks: blocks,
        gapCount: gaps,
        notes: ctx.notes,
        files: idx.all,
        generatedAt: new Date().toISOString()
      };
    });
  }

  /* ---------------------------------------------------------------------
     11. Working-paper export — plain text, for a working-paper file.
     --------------------------------------------------------------------- */

  var GLYPH = {}; GLYPH[PASS] = '[+]'; GLYPH[FAIL] = '[X]'; GLYPH[MISSING] = '[!]'; GLYPH[NOT_CHECKED] = '[?]';
  var RGLYPH = {}; RGLYPH[RECORDED] = '[+]'; RGLYPH[ASSERTED_ABSENT] = '[-]'; RGLYPH[GAP] = '[!]'; RGLYPH[CONFLICT] = '[X]';
  var RWORD = {}; RWORD[RECORDED] = 'RECORDED'; RWORD[ASSERTED_ABSENT] = 'NOT APPLICABLE (asserted)'; RWORD[GAP] = 'GAP - UNRECORDED'; RWORD[CONFLICT] = 'CONFLICT';
  var CWORD = {}; CWORD[PASS] = 'PASS'; CWORD[FAIL] = 'FAIL'; CWORD[MISSING] = 'CANNOT CHECK - FILE MISSING'; CWORD[NOT_CHECKED] = 'NOT CHECKED BY THIS TOOL';

  function wrap(text, width, indent) {
    var words = String(text).split(/\s+/), lines = [], cur = indent;
    for (var i = 0; i < words.length; i++) {
      if (cur.length + words[i].length + 1 > width && cur.trim()) { lines.push(cur); cur = indent; }
      cur += (cur === indent ? '' : ' ') + words[i];
    }
    if (cur.trim()) lines.push(cur);
    return lines.join('\n');
  }

  function workingPaper(report) {
    var L = [];
    var rule = '='.repeat(78), thin = '-'.repeat(78);
    L.push(rule);
    L.push('MEMTARA AUDITOR CONSOLE - VERIFICATION WORKING PAPER');
    L.push('Produced offline. No network call was made in producing this document.');
    L.push(rule, '');
    if (!report.loaded) { L.push('COULD NOT READ THIS BUNDLE'); L.push(wrap(report.error, 78, '  ')); return L.join('\n'); }

    L.push('CASE                ' + report.caseId);
    L.push('Schema version      ' + (report.schemaVersion || '(not declared)'));
    L.push('Examined at         ' + report.generatedAt);
    L.push('Files loaded        ' + report.files.length);
    L.push('');
    L.push(thin);
    L.push('TWO SEPARATE FINDINGS. THEY MUST NOT BE COMBINED.');
    L.push(thin);
    L.push('');
    L.push('FINDING 1 OF 2 - EVIDENCE INTEGRITY   (did the cryptography check out?)');
    L.push('  ' + GLYPH[report.integrity.counts.fail ? FAIL : (report.integrity.counts.missing ? MISSING : PASS)]
      + ' ' + report.integrity.verdict);
    L.push(wrap(report.integrity.headline, 78, '      '));
    L.push(wrap(report.integrity.meaning, 78, '      '));
    L.push('');
    L.push('FINDING 2 OF 2 - DECISION OUTCOME     (what was decided about the client?)');
    L.push('  ' + (report.outcome.sense === 'decline' ? '[X]' : report.outcome.sense === 'approve' ? '[+]' : '[!]')
      + ' ' + report.outcome.verdict);
    L.push(wrap(report.outcome.note, 78, '      '));
    report.outcome.sources.forEach(function (s) {
      L.push('      ' + RGLYPH[s.state] + ' ' + s.label + ' (' + s.where + '): ' + (s.value == null ? 'NOT RECORDED' : s.value));
    });
    if (report.outcome.divergence) L.push(wrap('NOTE: ' + report.outcome.divergence, 78, '      '));
    L.push('');
    L.push(wrap('A cryptographically valid record of a decline verifies exactly as cleanly as a '
      + 'valid record of an approval. Finding 1 says whether the paperwork is sound. Finding 2 says '
      + 'what was decided. Reading finding 1 as an approval is the error this tool exists to prevent.', 78, '  '));
    L.push('');

    L.push(rule);
    L.push('THE RECORD  (' + report.gapCount + ' unrecorded field' + (report.gapCount === 1 ? '' : 's') + ')');
    L.push(rule);
    report.blocks.forEach(function (b) {
      L.push('');
      L.push(b.title.toUpperCase());
      if (b.headline) {
        L.push('  ' + RGLYPH[b.headline.state] + ' ' + b.headline.text);
        L.push(wrap(b.headline.detail, 78, '      '));
      }
      (b.rows || []).forEach(function (r) {
        var v = r.state === RECORDED ? fmt(r.value) : RWORD[r.state];
        L.push('  ' + RGLYPH[r.state] + ' ' + (r.label + ' ').padEnd(26, '.') + ' ' + v);
        if (r.note) L.push(wrap(r.note, 78, '        '));
      });
    });
    L.push('');
    L.push(rule);
    L.push('CRYPTOGRAPHIC CHECKS');
    L.push(rule);
    report.checks.forEach(function (c) {
      L.push('');
      L.push(GLYPH[c.state] + ' ' + CWORD[c.state] + ' - ' + c.label);
      if (c.plain) L.push(wrap('What this shows: ' + c.plain, 78, '      '));
      if (c.notMean) L.push(wrap('What it does NOT show: ' + c.notMean, 78, '      '));
      if (c.detail) c.detail.split('\n').forEach(function (d) { L.push('      ' + d); });
    });
    if (report.notes.length) {
      L.push('');
      L.push(rule);
      L.push('NOTES ON THIS RECORD\'S SHAPE');
      L.push(rule);
      report.notes.forEach(function (n) { L.push(wrap('- ' + n, 78, '  ')); });
    }
    L.push('');
    L.push(thin);
    L.push('END OF WORKING PAPER');
    return L.join('\n');
  }

  global.AuditorConsole = {
    // exported for the node harness and for unit-testing from the page
    _internals: {
      toHex: toHex, fromHex: fromHex, sha256Hex: sha256Hex,
      canonicalString: canonicalString, indexBundle: indexBundle,
      readField: readField, senseOf: senseOf,
      framed: framed, uuidBytes: uuidBytes, bindingEventHash: bindingEventHash,
      suitableFromPublicInputs: suitableFromPublicInputs,
      digestsEqual: digestsEqual, PI: PI
    },
    analyse: analyse,
    workingPaper: workingPaper,
    STATES: { PASS: PASS, FAIL: FAIL, MISSING: MISSING, NOT_CHECKED: NOT_CHECKED },
    ROWS: { RECORDED: RECORDED, ASSERTED_ABSENT: ASSERTED_ABSENT, GAP: GAP, CONFLICT: CONFLICT }
  };

})(typeof globalThis !== 'undefined' ? globalThis : this);
