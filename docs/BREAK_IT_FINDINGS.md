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

    7 stopped   3 not stopped   1 blocked

All three NOT STOPPED rows are real, reproduced findings against the running
system, not placeholders. Attack 4 is the most serious result of the whole
exercise and is Finding 6.

A BLOCKED row is not a pass. It means the capability under attack does not
exist, so the attack cannot be run. The harness cannot render one as a pass.

| # | Attack | Result |
|---|---|---|
| 1 | Change the customer's data after the fact | STOPPED |
| 2 | Change a threshold mid-flight | STOPPED |
| 3 | Change the policy version mid-flight | **NOT STOPPED** — see Finding 5 |
| 4 | Change the model identity | **NOT STOPPED** — see Finding 6 |
| 5 | Change or substitute the verification key | STOPPED |
| 6 | Remove the proof service | STOPPED |
| 7 | Modify the evidence record | **STOPPED — with a stated residual window** |
| 8 | Revoke consent | BLOCKED — no consent concept |
| 9 | Attempt an unauthorised data category | STOPPED |
| 10 | Bypass human review | STOPPED — handler *and* database |
| 11 | Swap the model without recording it | **NOT STOPPED** — see Finding 7 |

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

## Finding 3 — four attacks were blocked; three are now real tests

Attacks 4, 10 and 11 waited on the same two capture paths — model identity
and per-decision human review. Those landed, the tripwires fired, the
placeholders stopped being able to pass, and all three have since been
implemented as real attacks. Two of them found something (Findings 6 and 7);
the third, human review, holds at both layers.

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

## Finding 6 — the eight model fields are committed to nothing

**Severity: this is the most serious result of the exercise.** It sits directly
under the product's central claim.

The intake contract in `wealth/model_intake.rs` is genuinely careful, and the
attack proves it rather than assuming it: a second attestation is refused by
the primary key; the review endpoint is `deny_unknown_fields` and rejects a
smuggled `model_name` outright; there is no PATCH, no PUT and no per-decision
model route — 405, 405, 404. Re-opening produces a different decision and
leaves the original untouched. The whole HTTP surface holds.

The values it validates so carefully are then stored where **nothing commits
to them**. `audit_log` has no payload column at all, and the one event that
mentions AI participation hashes the *declaration* — that a model was named —
never the provider, model name, version or config fingerprint. So a single
`update decision_model_attestations set …` rewrites the identity the sealed
record serves, and the organisation's hash chain is **byte-identical before
and after**. This is not a chain that failed to notice. There was nothing for
it to notice.

**The escalation is the part to show a buyer.** The same single UPDATE can set
`declaration = 'no_ai_participated'`. The record then serves `model: null` —
which both `schema/decision_evidence/v1.1.0.json` and `model_intake.rs` define
as a *signed assertion that no AI system participated* — for a decision opened
with a fully identified model. Every defence in the intake contract exists to
stop that assertion being reached by accident through the API. None of it
applies to a database write, and the surrounding record stays undisturbed.

**Fix:** put a digest of the attestation inside the
`wealth_suitability_requested` hashed payload, or seal the record at decision
time. Either makes the swap detectable. Choosing between them is a design
decision and not a test's to make. Until one lands, the honest description of
what we evidence about the model is: *that a declaration was made*, not *which
model ran*.

## Finding 7 — the model attestation is a forward declaration nothing can rebind

Distinct from Finding 6, and not fixed by fixing it: a control that detected
Finding 6 perfectly would not touch this one. Here no recorded value changes
at all. Every field stays exactly as written, internally consistent, and
wrong.

`decision_model_attestations` is written once, in the same transaction as the
assessment, by `POST /issue-wealth-request` — before the device has proved
anything, before the verdict exists, before any human has reviewed it. It is
therefore a declaration about a decision that has not happened yet, and the
record presents it with `state: "recorded"`, the same provenance a fact
observed at decision time would carry. Asserted from the rows rather than from
the source: `decision_model_attestations.created_at < wealth_requests.assessed_at`.

Nothing reconfirms it, and nothing can. `request_id` is that table's primary
key, there is no PATCH or PUT, and the review endpoint rejects model fields.
**The rule that makes Finding 6's API surface safe is the same rule that makes
the honest correction impossible**: an organisation that discovers mid-flight
that a different model served the request has no route, row or field in which
to say so, and the system keeps serving the first declaration.

`model.timestamp` is unvalidated and would be the one field capable of
exposing a stale attestation. A model call timestamped **2023** was accepted
for an assessment opened in 2026.

The contrast that makes this a design gap rather than an oversight: this
system already does the right thing one field over. `products.terms_version`
is bumped by a database trigger when thresholds change, snapshotted onto each
assessment at open, and surfaced as `policy.thresholds.threshold_version`, so
an examiner can see that a later decision ran under version 2 while this one
is pinned to version 1. The model block has no version, no snapshot
discipline, and no rebind.

## Finding 8 — human review holds at both layers, and the residual is a consistent lie

Attack 10 is the one clean result among the three. Seven forgeries were
attempted through the real endpoint and refused, leaving no row; the same
seven were then written straight into the table with the API removed from the
path, and each was refused by Postgres by name —
`decision_reviews_override_requires_reason`,
`decision_reviews_duration_needs_a_source`,
`decision_reviews_review_duration_source_check`,
`decision_reviews_action_check`, and `decision_reviews_pkey` for the second
review. A control that lives only in a request handler is bypassed by anyone
with a connection string; this one does not.

An unreviewed decision also cannot be made to read like a reviewed one: every
reviewer field is `not_applicable` — a signed assertion that there was no
review step — rather than `unpopulated`, which would be an admission that a
reviewer's name was lost. And an accepted override keeps the verdict it
overrode: `final_decision.outcome` stays with what the circuit proved while
`status` carries what the human did. An override that rewrote the
cryptographic verdict would erase the thing it was overriding.

**The residual, stated because it is real:** CHECK constraints stop an
internally *inconsistent* forged review. They cannot stop a consistent *lie* —
a fabricated row naming a real reviewer with a plausible duration and a real
source is accepted, because no constraint can know whether a human was at the
desk. It buys nothing on an undecided assessment, where the evidence endpoint
still refuses to produce a record. What it can do is attach a fabricated
reviewer to a genuine decision. The only thing distinguishing it from a real
review is the missing `decision_human_reviewed` entry in the hash chain — a
contradiction the `DecisionEvidence` record does not carry and nothing
cross-checks. The raw material for that check exists; the check does not.
