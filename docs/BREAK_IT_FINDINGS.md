# Break-it run — findings

Run: `./scripts/break_it.sh`. Result on 19 Aug 2026, against the real server,
real `bb` 5.1.0, real Postgres — no mocks anywhere in the attack path.

    6 stopped   1 not stopped   4 blocked

A BLOCKED row is not a pass. It means the capability under attack does not
exist yet, so the attack cannot be run at all. Each blocked row names what
would unblock it.

| # | Attack | Result |
|---|---|---|
| 1 | Change the customer's data after the fact | STOPPED |
| 2 | Change a threshold mid-flight | STOPPED |
| 3 | Change the policy version mid-flight | STOPPED |
| 4 | Change the model identity | BLOCKED — no capture path |
| 5 | Change or substitute the verification key | STOPPED |
| 6 | Remove the proof service | STOPPED |
| 7 | Modify the evidence record | **NOT STOPPED (scoped — see below)** |
| 8 | Revoke consent | BLOCKED — no consent concept |
| 9 | Attempt an unauthorised data category | STOPPED |
| 10 | Bypass human review | BLOCKED — no per-decision review |
| 11 | Swap the model without recording it | BLOCKED — no capture path |

---

## Finding 1 — the terminal row of the audit chain is unprotected

**Severity: material. This is the row most likely to be disputed.**

`backend/api/src/audit/mod.rs` computes

    event_hash = SHA256( framed(event_type) || framed(ref_id)
                       || framed(prev_hash)  || framed(payload) )

and the module says, in its own words, that `payload` is folded into
`event_hash` but **deliberately not stored** — so that either the event
happened with exactly this payload in exactly this position, or the chain
breaks. That reasoning is correct, and for every row that has a successor it
holds: the next row's `prev_hash` commits to this row's `event_hash`, so an
edit is detected.

It does not hold for the **last row in the chain**. Nothing succeeds it, so
nothing commits to its `event_hash`; and because the payload is not stored,
the hash cannot be recomputed from the database either. A direct
`update audit_log set event_hash = …` on the terminal row is therefore
undetectable from the database alone.

The break-it harness demonstrates this against a live server: it completes a
real assessment, confirms the chain is healthy, forges 32 bytes over the
`proof_verified` event's `event_hash`, and adjacency still holds.

Why it matters commercially rather than only theoretically: the newest record
is the one a regulator or a claimant asks about. "Everything except the most
recent decision is tamper-evident" is not a sentence that survives a security
review.

**Fix (standard, small): anchor the head.** Periodically sign and publish the
latest `event_hash` — a signed checkpoint, emitted on a timer and included in
the offline verification bundle. Once the head is committed to by something
outside the chain, the terminal row inherits the same protection as every
other row, and the window of exposure shrinks to the checkpoint interval.
Publishing the checkpoint externally also removes our own ability to rewrite
history, which is a stronger claim than the one we make today.

Until that lands, `docs/VERIFY.md` and any pilot material must not describe
the audit chain as making every record tamper-evident. The accurate statement
is: every record **that has been followed by another record** is tamper-evident.

## Finding 2 — the chain is global, so an org-scoped export cannot be linked

Independently found while building the offline verification bundle, and
consistent with the above. `audit/mod.rs` takes the chain head with

    select event_hash from audit_log order by seq desc limit 1

across all rows, not per organisation. So in any org-filtered export, adjacent
rows are not chain-adjacent — their `prev_hash` values point at other tenants'
rows, which must not be in the bundle. An auditor holding an exported segment
gets 0 linkable pairs and cannot verify the segment's internal linkage at all.

The bundle's verifier reports this honestly rather than papering over it, and
`docs/VERIFY.md` states that a claim that this segment independently proves
what happened would be an overstatement. Both remain true until the chain is
either partitioned per organisation or accompanied by inclusion proofs.

## Finding 3 — four attacks cannot be run because the capability does not exist

Attacks 4, 8, 10 and 11 are blocked, and the pattern is worth stating plainly:
three of the four wait on the **same two capture paths** — model identity and
per-decision human review. Those are Gate 2 of the 90-day plan.

A note on how these are reported. `DecisionEvidence` v1 landed on 19 Aug and
introduced `model.*`, `human_review.*` and consent fields as typed,
explicitly-unpopulated placeholders. The first version of these tripwires
grepped for the *type* and therefore fired, reporting the capability as
present. It is not: a field carrying `state: "unpopulated"` cannot be
attacked, because there is no way to submit a value and so no way to tamper
with one. The tripwires now key on a **capture path** — a migration giving the
value somewhere to live, or a route through which one can be supplied — which
is the thing that actually changes what an attacker can reach.

Attack 8 is different from the other three and should not be grouped with
them when reporting progress. Model and human review are missing *fields*.
Consent is a missing *concept*: the nearest relative in the codebase is
`SessionPolicy.purpose_hash`, a fixed, non-revocable purpose binding. There is
nothing to revoke, so there is nothing to test.
