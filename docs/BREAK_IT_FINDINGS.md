# Break-it run — findings

Run: `./scripts/break_it.sh`. Eleven attacks against the real server, real
`bb` 5.1.0, real Postgres. No mocks anywhere in the attack path.

Revision 2, 19 Aug 2026. Revision 1 was written before the chain-head
checkpoint landed and before the model and human capture paths existed; six
of its claims were challenged by the engineer who implemented the fix and
five of those challenges were correct. Corrections are marked below rather
than silently applied, because a findings document that quietly rewrites
itself is worth less than one that shows where it was wrong.

## Result

    6 stopped   4 not stopped   1 blocked

Three of the four NOT STOPPED rows are attacks 4, 10 and 11: their capture
paths landed with migration `0006_decision_capture`, their tripwires fired
exactly as designed, and the real attacks are owed. They are not defects —
they are placeholders that have correctly stopped being able to pass.

The fourth, attack 3, is a genuine unguarded surface and is Finding 5 below.
It was reported as STOPPED until this revision, wrongly. See that finding for
why, because the cause was in the harness rather than the product.

A BLOCKED row is not a pass. It means the capability under attack does not
exist, so the attack cannot be run. The harness cannot render one as a pass.

| # | Attack | Result |
|---|---|---|
| 1 | Change the customer's data after the fact | STOPPED |
| 2 | Change a threshold mid-flight | STOPPED |
| 3 | Change the policy version mid-flight | **NOT STOPPED** — see Finding 5 |
| 4 | Change the model identity | NOT STOPPED — tripwire, real attack owed |
| 5 | Change or substitute the verification key | STOPPED |
| 6 | Remove the proof service | STOPPED |
| 7 | Modify the evidence record | **STOPPED — with a stated residual window** |
| 8 | Revoke consent | BLOCKED — no consent concept |
| 9 | Attempt an unauthorised data category | STOPPED |
| 10 | Bypass human review | NOT STOPPED — tripwire, real attack owed |
| 11 | Swap the model without recording it | NOT STOPPED — tripwire, real attack owed |

---

## Finding 1 — the terminal row of the audit chain was unprotected. Now closed, with a window.

`backend/api/src/audit/mod.rs` computes

    event_hash = SHA256( framed(event_type) || framed(ref_id)
                       || framed(prev_hash)  || framed(payload) )

and folds `payload` into the hash while **deliberately not storing it**, so
that either the event happened with exactly this payload in exactly this
position, or the chain breaks. That reasoning is correct and unchanged.

It held for every row with a successor and not for the last row: nothing
committed to its `event_hash`, and with no stored payload the hash could not
be recomputed either. A direct `update audit_log set event_hash = …` on the
terminal row was undetectable from the database alone.

**Closed by a signed chain-head checkpoint** (`0008_audit_checkpoints.sql`,
`audit/checkpoint.rs`). Demonstrated against a live server: pin the head,
verify the checkpoint outside the process against the published JWKS, forge
real bytes over the terminal row by raw SQL, and then —

- chain linkage: **blind**, 0 broken adjacencies. The original finding is
  still true.
- the checkpoint: **caught**. `GET /audit/integrity` returns
  `head_hash_mismatch` with the signed and observed hashes side by side, and
  calls it *"a signed contradiction, not a warning"*.

### Four corrections to revision 1

1. **Revision 1 described a test that did not exist.** It said the harness
   forged 32 bytes and adjacency still held. The prose was right; the test
   asserted the *opposite* (`assert not _adjacent_links_hold(...)`), which is
   why it failed. The finding was real, the cited demonstration was not.
   Attack 7 is now four tests that do what the prose claimed.

2. **Truncation was omitted, and it is the sibling attack.** A `(seq, hash)`
   pair does not catch it: delete rows 900–1000 and the surviving prefix is
   still internally consistent. Anyone implementing from revision 1's fix
   paragraph would have shipped a checkpoint with no row count. The
   checkpoint therefore signs `covered_row_count`, a monotonic
   `checkpoint_no`, and `prev_checkpoint_hash` — respectively catching
   deletion inside the range, replay of an older checkpoint as current, and
   removal of a checkpoint from the middle of the run.

3. **"The terminal row inherits the same protection as every other row" was
   wrong.** Rows with successors are protected continuously and instantly, by
   a hash anyone holding the chain can recompute. The terminal row is
   protected after a lag, by a signature that must be fetched — and the moment
   a new row is appended, the new terminal row is unprotected again. It is
   *comparable* protection, not the same protection, and the difference is
   precisely the number a customer will ask for.

4. **"Publishing removes our own ability to rewrite history" was an
   overclaim** — and it is the sentence a security reviewer would have pulled
   on. Publishing means third parties *may* hold contradicting copies. It
   removes our ability to rewrite history *undetectably, to anyone who
   fetched one*. It removes nothing from a party who never fetched, and it
   does not remove our write access to our own database. Until an external
   anchor exists we can still delete our own checkpoints; what stands in the
   way is possession of the signing key and whatever copies counterparties
   already hold.

### The residual window, stated plainly

**At most 65 seconds** — a 60-second interval plus a 5-second poll — or
within 5 seconds of crossing 64 pending events, whichever comes first.
`POST /audit/checkpoints` closes it to a round trip on demand, which is what
should happen before any export or dispute.

What to say to a customer: *every audit record older than the checkpoint
interval is committed to by an Ed25519 signature you can fetch and verify
yourself, so we cannot alter it without contradicting a statement you already
hold; the newest records are protected by the chain the moment a further
record follows them, and by signature within 65 seconds; before any export
you can call one endpoint and close that window.*

What not to say: that the window is zero, or that we can no longer rewrite
history. It cannot be zero — a checkpoint is necessarily made after the event
it pins. And a checkpoint pins whatever the row contained when it was signed;
it does not repair a forgery that already happened.

**Still not caught:** delete-and-replace inside the covered range, where a row
is reinserted at the same `seq` carrying the same `event_hash` but different
content. Count and linkage both hold. That is not a new hole — it is the same
blind spot as content tamper, because the hash commits to a payload nobody
kept.

**Not built:** the external half. `anchor_target` / `anchor_ref` /
`anchored_at` ship nullable with a CHECK refusing a half-written claim, and
the endpoint returns `external_anchor: null` explicitly so its absence is
visible rather than implied. Publishing is what moves the trust boundary, not
the chaining — and the newest *checkpoint* has no successor either.

## Finding 2 — the chain is global, so an org-scoped export cannot be relied on for linkage

`audit/mod.rs` takes the chain head across all rows, not per organisation. In
an org-filtered export, adjacent rows are therefore **not guaranteed** to be
chain-adjacent: their `prev_hash` may point at other tenants' rows, which must
not be in the bundle.

*Correction to revision 1:* it claimed the auditor gets "0 linkable pairs".
That is the worst case, not the general case — in a single-tenant or quiet
deployment consecutive rows frequently *are* chain-adjacent. The accurate
claim is that adjacency is not guaranteed and must not be assumed. Attack 7's
first test deliberately walks the global chain from the database rather than
the org endpoint for exactly this reason.

The bundle's verifier reports this honestly rather than papering over it.

## Finding 3 — four attacks were blocked; three are now owed as real tests

Attacks 4, 10 and 11 waited on the same two capture paths — model identity
and per-decision human review. Those landed, the tripwires fired, and the
placeholders can no longer pass. That is the mechanism working.

The tripwires themselves needed correcting once. They originally keyed on the
*type* existing, so when `DecisionEvidence` v1 introduced `model.*` and
`human_review.*` as explicitly-unpopulated placeholders they fired early: a
field carrying `state: "unpopulated"` cannot be attacked, because there is no
way to submit a value and therefore nothing to tamper with. They now key on a
**capture path** — a migration giving the value somewhere to live, or a route
that accepts one — which is the thing that changes what an attacker can reach.

Attack 8 is different in kind and should not be reported alongside the other
three. Model and human review were missing *fields*. Consent is a missing
*concept*: the nearest relative is `SessionPolicy.purpose_hash`, a fixed,
non-revocable purpose binding. There is nothing to revoke, so there is
nothing to test.

## Finding 4 — two honesty defects in our own tooling, both fixed

`/health` never ran the prover. Every check read a file or a config value;
`bb_bin` appeared zero times in the module. During attack 6's exact scenario —
`bb` removed, every verification correctly failing closed — `/health` went on
reporting `ok`, because the vkey *files* were still on disk. A health check
that stays green through its own failure scenario is worse than none. Fixed:
it now executes `bb --version` and degrades the instance.

`break_it.sh` reported a failed `cargo build` as BLOCKED. BLOCKED is a claim
about the product, and a broken compiler is not one; a tree that simply did
not build printed a table of calm-looking rows. `COULD NOT RUN` is now its own
state and fails the run. The same script also suppressed notes on STOPPED
rows, which would have let attack 7's 65-second residual window vanish from
the table it appears in. Notes now travel with every row.

## Finding 5 — the policy snapshot is unguarded, and the harness was hiding it

`disclosure_requests.policy` is written once when a request is opened and
never again by anything in `backend/api/src`. It carries no version marker of
any kind. A direct write to that column — an operator or insider with database
access, since no HTTP surface reaches it — is caught by nothing: the request
endpoint serves the tampered policy without error, and the organisation's own
hash-chained audit trail shows unbroken adjacency across the tamper, because
**the `policy` column is never folded into any audit event's hashed payload**.
Both `issue_wealth_request` and `create_disclosure_request` hash the user,
circuit type, terms and TTL, and not the policy.

The chain protects the *events about* a request. It does not protect this
column's content. That is a narrower finding than the missing model, consent
and human-review capabilities, and in one way a worse one: here there **is** a
live column carrying governance-relevant content, and it is simply unguarded.

### Why it read STOPPED until now

Every attack module declares `BREAK_IT_STATUS_ON_PASS`, and attack 3 has
always declared `NOT STOPPED` — because its test passes by *verifying that the
attack succeeds*. `scripts/break_it.sh` never read that constant. A passing
test was rendered as STOPPED unconditionally, so a documented, verified
vulnerability printed as a defence in the table intended for a bank.

The test was honest. The runner was not. This is precisely the false green the
harness exists to prevent, and it was in the harness rather than in the
product — which is a good argument for pointing an adversarial suite at your
own tooling as well as at your system. The runner now honours the declared
verdict.

**Fix:** fold `policy` into the hashed payload of the events that write it, and
give it a `policy_id` and `policy_version` so a named-version mismatch becomes
expressible at all. Both are already required by `DecisionEvidence`, where they
remain among the ten honestly-unpopulated fields.
