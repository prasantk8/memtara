# Business continuity when the proof service is down

Board point 19: the system fails closed in two places today, and there is no
defined continuity mode behind either of them. Every regulated buyer's
security review asks the same question — "what happens to our business when
your proof service is down?" — and today the honest answer is "nothing
proceeds, and we don't durably record that it didn't." This document defines
four modes, picks a pilot default, and specifies it precisely enough to build.

Audience: an engineer implementing Mode B next week, and a CISO deciding
whether to accept it. Every claim about current behaviour is cited
`file:line`. Where I could not verify something in the code, it says
"unverified" rather than guessing.

---

## 1. What actually happens today

Fail-closed happens at two layers, and they fail differently.

### 1.1 Boot-time — `main.rs:47`

```rust
verify::ensure_vkeys(&config).await?;
```

`ensure_vkeys` (`backend/api/src/verify/mod.rs:70-114`) generates any missing
per-circuit verification key via `bb write_vk`. If `bb` isn't on `PATH`
(`verify/mod.rs:101-103`, spawn error) or `bb write_vk` exits non-zero
(`verify/mod.rs:105-111`), it returns `Err`. The `?` at `main.rs:47`
propagates that out of `main()`, which is declared `async fn main() ->
anyhow::Result<()>` (`main.rs:30`) — a top-level `Err` return prints the error
and exits the process non-zero. The port never binds.

**Measured, not theoretical.** `tests/break_it/test_attack_06_proof_service_removed.py::test_boot_fails_hard_without_bb`
runs a real `memtara-api` binary against a nonexistent `BB_BIN` path and
confirms: the process exits non-zero within the boot timeout, the stderr tail
names `bb` as the cause, and `GET /healthz` refuses the connection outright
(`ConnectError`, not a slow or wrong answer) — the port never came up at all.
Recorded as **STOPPED** in `docs/BREAK_IT_FINDINGS.md` (row 6).

**Customer experience:** total outage. Every tenant, every circuit, the
service simply isn't there. No partial availability, no degraded mode. This
is correct and should stay this way — a server that starts without a working
verifier would issue proof-token responses it cannot back.

### 1.2 Per-request — `verify/mod.rs:157-208`

`run_bb_verify_inner` returns `Err(ApiError::Other(...))` in two cases: the
vkey file is missing from disk (`verify/mod.rs:163-169`) or the `bb verify`
subprocess itself fails to spawn (`verify/mod.rs:204-205`, the `spawn_result`
`map_err`). The caller, `run_bb_verify` (`verify/mod.rs:137-155`), records
this as `VerificationResult::Errored` — deliberately distinct from
`VerificationResult::Rejected`, which is a genuine cryptographic "no"
(`ops/metrics.rs:60-66`: `Errored` "means we do not know whether the proof
was good, which operationally is nothing like the proof was bad").

That `Err` then propagates via `?` at `verify/mod.rs:577`
(`let valid = run_bb_verify(...).await?;`) straight out of
`verify_against_request`, and again via `?` at `submit_proof`
(`verify/mod.rs:446`). `ApiError::Other` maps to `StatusCode::INTERNAL_SERVER_ERROR`
(`error.rs:79-82`) with a generic `"internal error"` body — no internals
leaked, but also nothing that tells the caller "retry, this is transient."

**Measured.** `test_a_request_in_flight_when_bb_disappears_fails_closed`
proves a real proof, deletes the verifier binary between proof generation and
submission, and confirms: the response is a 5xx, not 2xx
(`resp.status_code >= 500`); the disclosure request stays `pending`
(`request_status(...) == "pending"`); the nonce is not consumed
(`used_nonce_count(...) == 0`); and — restoring the binary and resubmitting
the *identical* proof — recovery succeeds and the request flips to
`fulfilled`. **STOPPED**, per `docs/BREAK_IT_FINDINGS.md` row 6.

**Customer experience:** one request gets a 500. The server stays up; every
other tenant's traffic is unaffected. Nothing is recorded as approved,
rejected, or attempted.

### 1.3 The gap that matters: no durable record of the attempt

This is the part the spec doc undersells and worth stating precisely, because
it is the entire justification for Mode B.

Follow the `Err` path in `verify_against_request` (`verify/mod.rs:492-624`)
to the end: `run_bb_verify` errors at line 577, the `?` returns immediately.
Execution never reaches the `if !valid` block at line 582 (which inserts into
`proofs` and calls `audit::record`) and never reaches `record_valid_proof`
at line 618. **Neither the `proofs` table nor `audit_log` gets a row.** The
only thing that changes anywhere in the system is one atomic increment to an
in-process Prometheus counter, `errored` (`ops/metrics.rs:49-52`, exposed as
`memtara_proof_verification_total{result="error"}` at `ops/metrics.rs:141`).

Concretely: if `bb` goes down for an hour and 500 proof submissions error
out, the honest answer to "which decisions were affected, and when" is: *we
cannot tell you, per decision.* We can tell you a counter went up by some
amount during some window, and only if no process restart reset it since
(the counter is in-memory, not persisted). No `decision_id`, no
`request_id`, no timestamp per attempt, nothing joinable to a customer's
case file.

Compare this to the one place the codebase gets the analogous case right:
a *cryptographic* rejection is recorded (`verify/mod.rs:588-599` inserts
`proofs.valid = false`) and audited (`verify/mod.rs:606-613`, with the
comment *"An audit trail that only logs successes isn't an audit trail"*)
specifically so a rejected decision produces the same evidentiary trail as an
accepted one. That discipline was applied to *cryptographic* failure and not
to *infrastructure* failure — an inconsistency, not a deliberate design
choice (nothing in the comments at `verify/mod.rs:124-136` or `157-162`
argues for the asymmetry; it reads as the case nobody got to).

**This is the concrete difference between today's behaviour and Mode B.**
Today: silent gap, defensible only by reconstructing incident timelines from
logs and a volatile counter. Mode B: a timestamped, hash-chained
`audit_log` row exists for the *attempt* itself, written at the moment of
failure, before anyone knows whether the retry will succeed — a positive
record of the gap, not an absence.

---

## 2. The four modes

Each mode is described against a proof-service outage that lasts long enough
to matter — seconds don't need a mode, that's why nonces persist and clients
retry naturally. These modes are for outages measured in minutes to hours.

### A — Hard block (today's behaviour)

- **Customer-visible behaviour:** synchronous 5xx on every in-flight
  submission; the disclosure request stays `pending`, retriable once the
  service returns (§1.2). Boot-time outages are a total service outage
  (§1.1).
- **Evidence consequence:** none created for the attempt, per §1.3 — only a
  volatile counter.
- **Cost to build:** zero — this is shipped.
- **Cost to operate:** zero incremental — but every minute of `bb` downtime is
  a minute of the product's core function unavailable, with no operator
  lever to pull except "wait" or "restore `bb`."
- **Failure mode it introduces:** **the silent gap.** Not a security failure
  — a governance-evidence failure. A regulator or the org's own compliance
  team asking "what happened between 14:02 and 14:47 on the 9th" gets
  nothing durable to point to.

### B — Queue and replay (recommended pilot default; specified in §6)

- **Customer-visible behaviour:** the org's system receives an explicit
  "deferred, will retry" signal instead of a bare 500 (§6.2); the decision
  resolves — approved, rejected, or expired — once `bb` recovers or the
  queue's bound is hit.
- **Evidence consequence:** a `verification_deferred` audit event at attempt
  time (new), followed by the normal `proof_verified` /
  `proof_verification_failed` event on replay — the *same* evidentiary shape
  as a same-time verification, plus one extra row showing the gap.
- **Cost to build:** the smallest of the three unbuilt modes. The
  hard part — invalid/errored proofs never touching status or the nonce — is
  already implemented and tested (§3). Needs: persist-on-attempt (not just
  persist-on-outcome), one new table, a replay worker, and the metrics in
  §6.5.
- **Cost to operate:** a queue to monitor, a worker process to run, and a
  new alert surface (§6.5). Materially more than A, materially less than D.
- **Failure mode it introduces:** **stale evidence race.** Between the
  moment a decision is queued and the moment it is sealed, the *business*
  may already have acted on it — an advisor already told a client
  "approved," a downstream system already released funds — on human
  judgement, not on the proof. If replay later says the proof was invalid,
  the record is honest but the business action already happened and cannot
  be evidenced as proof-backed after the fact. §3 and §6.4 address this
  directly; it is not eliminated, only bounded and made visible.

### C — Degrade to human, marked

- **Customer-visible behaviour:** a human decides, no proof behind the
  decision at the time it's made; the record says so permanently.
- **Evidence consequence:** would carry a field such as
  `proof_status: "unavailable_human_override"` — honest, but a strictly
  weaker claim than a cryptographic verdict. Requires the `human_review`
  table from Task 1 of the DecisionEvidence spec to exist at all; today
  there is no per-decision human-review concept to mark this state with
  (confirmed: zero matches for "reviewer" in `backend/api/src/`, cited in
  `decision_evidence_spec.md` Task 1, row `human_review.reviewer_id/role`).
  Until that lands, this mode is **indistinguishable from Mode A's silent
  gap** — there is nowhere to write the marker.
- **Cost to build:** blocked on Task 1's L-sized `human_review` work — not a
  6-week item.
- **Cost to operate:** a review/override workflow, an audit surface for
  override *rate* (not just override *existence* — see §4), and a governance
  process for who is allowed to invoke it.
- **Failure mode it introduces:** **the override becomes the default.**
  Argued in full in §4.

### D — Secondary verifier

- **Customer-visible behaviour:** no visible gap, if the secondary succeeds —
  verification retries against a second, independent `bb` instance / vkey
  mirror before falling back to A or B.
- **Evidence consequence:** the record must additionally state *which*
  verifier instance produced the verdict, or the "Memtara-independent
  re-verification" claim (`decision_evidence_spec.md` §2.4) gets murkier —
  two verifiers means two things an examiner would need to trust matched.
- **Cost to build:** an infrastructure project, not a code change. Today
  there is exactly one verifier path — `config.bb_bin`, a single binary path
  (`verify/mod.rs` test harness constructs `Config` with one `bb_bin` field,
  `verify/mod.rs:983`) — no verifier pool, no health-based routing, no
  quorum logic.
- **Cost to operate:** running (and keeping vkey-synchronised, see
  `ops/health.rs:131-165`'s `DIVERGED` check) a second verification path,
  indefinitely.
- **Failure mode it introduces:** **quiet divergence.** Two verifiers that
  can disagree is a new failure surface the single-verifier design doesn't
  have today: `ops/health.rs:135-165` already exists specifically because a
  vkey that drifts between "published" and "runtime" produces proofs that
  verify locally but not against the examiner's copy — with a second live
  verifier, that drift can now happen *between the two verifiers themselves*,
  silently, since nothing today compares verifier A's and verifier B's vkeys
  against each other, only each against the published one.

---

## 3. Why Mode B, from the code

The nonce invariant is the entire safety argument for replay, so it was
verified directly rather than assumed.

**Claim: a failed or errored verification attempt never consumes the nonce
or advances the request's status.** True, confirmed at the following lines:

- `verify/mod.rs:582-587` — the comment states the rule explicitly
  ("Invalid proofs are recorded... but do NOT consume the nonce or touch
  request status"), and the code backing it: the `if !valid` block inserts
  into `proofs` with `valid = false` (`verify/mod.rs:588-599`) and never
  touches `used_nonces` or `disclosure_requests.status`.
- `record_valid_proof` (`verify/mod.rs:344-411`) — the *only* function in
  the module that writes to `used_nonces` or flips a request to
  `fulfilled` — is called from exactly one place, `verify/mod.rs:618`,
  reached only after `valid == true`. There is no other call site
  (confirmed by reading the whole file; `record_valid_proof` is
  private/`async fn`, not `pub`, so no other module can reach it either).
- The infra-error (`Errored`) path returns before reaching either branch at
  all (§1.3) — so it is *stricter* than the invalid-proof path: it doesn't
  even write the `proofs` row, let alone touch the nonce.
- **Tested against real Postgres, not asserted from reading:**
  `second_submission_of_same_nonce_is_rejected_as_replay`
  (`verify/mod.rs:810-860`) proves a second attempt against an
  already-consumed nonce is rejected and leaves exactly one `used_nonces`
  row and one `proofs` row — not two.
  `concurrent_replay_attempts_exactly_one_winner`
  (`verify/mod.rs:870-927`) fires 8 concurrent racing submissions of the
  *same* nonce and proves exactly one wins, because the atomicity is the
  database's own `primary key (org_id, nonce)` constraint plus
  `on conflict do nothing` (`verify/mod.rs:357-360`), not
  application-level check-then-act logic that a race could defeat.
  `different_nonce_same_org_is_independent` (`verify/mod.rs:933-954`)
  proves the scoping is exactly `(org_id, nonce)`, not something broader
  that would false-positive-block an unrelated request.
- The measured attack (§1.2) confirms this end-to-end against a live
  server: the nonce count is `0` after the errored attempt, and the
  *identical* proof resubmitted later succeeds — proof there was no
  hidden state that would have made the retry behave differently the
  second time.

**Verdict: the invariant genuinely holds, and it is exactly the property
that makes "queue now, verify later" safe rather than merely convenient.**
A request that failed to verify today can be resubmitted tomorrow with the
same guarantees a first-ever submission has. Nothing about a queued state is
special-cased or weaker.

### What Mode B does not solve

Being honest about the limits matters more here than the pitch:

1. **It does not make the business wait.** Mode B guarantees the *evidence*
   is eventually correct and honestly timestamped. It does nothing to stop
   an org's own process from acting on a decision before the proof clears —
   that has to be a contractual/operational constraint on the org, not
   something this system can enforce (§6.4).
2. **It does not extend past a request's TTL.** `expires_at` is fixed at
   creation (`disclosure/mod.rs:217`, `Utc::now() + ttl_seconds`) and there
   is no renew/extend function anywhere in `backend/api/src` (confirmed:
   `grep -rni "extend|renew"` returns no relevant matches). An outage longer
   than a queued request's remaining TTL makes that specific decision
   unrecoverable — not silently wrong, but unrecoverable and requiring a
   fresh request. See §6.4.
3. **It does not, on its own, protect the newest queued row from insider
   tampering during the outage.** This is the sharpest limitation and is
   addressed on its own in §6.3, because it interacts with a second,
   independently-found gap in the audit chain.
4. **It does not replace Mode A.** For a genuinely time-critical decision —
   one where "come back in twenty minutes" is not an acceptable answer —
   Mode B degrades to exactly Mode A's customer experience once the queue
   bound is hit (§6.4). Mode B is a strictly better default than Mode A, not
   a strictly sufficient one.

---

## 4. Why we resist Mode C — steelmanned

**The strongest version of the CRO's argument**, as it will actually be made
in a room:

> "You're describing a system that, during any outage — a bad `bb` upgrade,
> a disk full on the wrong box, anything — simply stops doing business for
> our customers, or makes them wait an indeterminate amount of time. We are
> a bank. We have a suitability decision to make *right now*, in front of a
> client, and 'the vendor's verifier is down' is not a sentence any of our
> relationship managers can say out loud. Every other control we run —
> KYC screening, sanctions checks, credit decisioning — has a manual
> override for exactly this reason, logged and reviewed after the fact.
> That's not a weakness in those controls, it's how every control that
> touches a live customer interaction actually survives contact with
> production. You're asking us to be the one process in the building that
> has no escape hatch. That's not rigor, that's naivety about how a bank
> actually runs, and it will get this product killed in security review for
> being unusable, not adopted for being pure."

This is a real argument, made by people who are right about how banks
operate. It deserves a real answer, not a dismissal.

**The answer:**

Every other override the CRO named — KYC, sanctions, credit — has a
property this one doesn't: the control being overridden is a *check on
inputs* (is this person who they claim, are they on a list, can they
service this debt). A human overriding it is a human asserting "I have
information the automated check didn't." That's a legitimate exercise of
judgement *within the same evidentiary frame* the control operates in.

This control is different in kind. It is not a check on an input — it is
the thing that lets Memtara say, to an examiner two years from now, *"a
specific set of governance thresholds were cryptographically applied to this
specific decision, and here is the proof, verifiable without trusting us."*
A human override doesn't supplement that claim with different information.
It replaces the claim entirely, with a different and weaker one: "a human
says this was fine." That's not two paths to the same evidentiary standard —
it's the product's core sentence, quietly downgraded to a sentence every
vendor already sells.

And the CRO's own framing gives away why it becomes the default within a
quarter, not an exception: "come back in twenty minutes" is unacceptable in
front of a client — true — which means the override isn't reserved for the
outage, it's reached for the moment the honest cost of verification (whether
that's latency, an outage, or just an impatient afternoon) exceeds the
appetite to wait for it. The failure mode named in §2 for Mode C — "the
override becomes the default" — isn't a hypothetical about bad actors; it's
the predictable outcome of stacking a low-friction human path next to a
higher-friction cryptographic one and asking a busy person, under time
pressure, every single time, to choose the harder one voluntarily. Nobody
has to be dishonest for that to happen. They just have to be busy on a
Tuesday, which every relationship manager in every bank is.

At that point, the thing Memtara sells — an independently verifiable claim
that governance was actually applied — becomes a claim that's true only when
nobody was in a hurry. That is not a control a security review should pass,
and it is not a claim this company can make in a pack an examiner reads two
years later without knowing how often the override was actually the path
taken.

**We are not wrong to resist an unbounded version of Mode C.** We may be
wrong to resist *any* version of it — §5 specifies exactly the bounded form
in which it is defensible, because refusing to ever discuss it is its own
failure to survive a CRO pushing back. The answer to "we need an escape
hatch" is not "no." It's "yes, exactly this one, no wider."

---

## 5. The bounded exception

If Mode C is ever permitted, it is permitted only in this shape. An
unbounded override is not a mode — it's the absence of one, wearing a label.

- **Conditions.** Available only when the proof service is confirmed down —
  driven by the same signal that triggers Mode A/B fallback (§6.5's health
  probe), not by an individual's claim that it's slow or inconvenient. Not
  available as a substitute for a Mode B queue wait; must be shown that the
  decision cannot wait for the queue (a defined, short list of eligible
  business processes — e.g. a client physically present and time-boxed —
  not "any decision the desk feels is urgent").
- **Expiry.** The override authority itself expires with the outage. The
  moment the health probe reports the verifier healthy again, no new C-mode
  decision may be recorded — automatically enforced by the same flag Mode
  B's fallback logic reads (§6.5), not by policy alone. A specific override
  instance also expires forward: it must be reconciled — proof attempted
  against the exact terms in force at the time — the moment the service is
  back, and the record updated to show whether the eventual proof matched
  the human's call or not.
- **Authorisation.** Not the relationship manager who is under the time
  pressure the override exists to relieve. A named second party — e.g. a
  compliance officer or desk head, on a role checked at override time, not
  self-declared — with their own identity captured in the record, distinct
  from the person requesting it. No self-approval.
- **What it writes into the record, permanently and non-optionally** (per
  the DecisionEvidence discipline in `decision_evidence_spec.md` §1.3 — no
  field is `Option` just because the path was irregular):
  - `proof_status: "unavailable_human_override"` — never silently merged
    with a normal approval; visually and structurally distinct in every
    downstream report and export.
  - The authorising identity and role, timestamp of authorisation, and the
    specific outage/incident it was invoked under (joinable to the
    `verification_deferred` audit trail from §6, so an examiner can see the
    override wasn't invented after the fact).
  - The reconciliation outcome once the proof is later run: matched or
    diverged. A **diverged** reconciliation — human said proceed, the proof
    would have said no — is itself a reportable event, not a closed loop;
    it is exactly the metric the CRO's own quarterly review should be
    watching, because a rising divergence rate is the empirical version of
    "the override became the default."
  - A running, org-visible count of how many overrides were invoked in the
    rolling 90 days, surfaced back to the org's own compliance function —
    not just retained for Memtara's records — so the org that asked for the
    escape hatch also owns watching how often it's used.

If this shape is ever judged too restrictive to be useful in practice, that
is itself the signal the argument in §4 was right and the mode should stay
closed, not a reason to widen it.

---

## 6. Implementation plan — Mode B

### 6.1 What's already there vs. what's new

Already correct and reusable, not to be reimplemented:

- Non-consuming rejection/error semantics (§3).
- `verify_against_request` as the single verification code path
  (`verify/mod.rs:481-491`'s own reasoning against a second copy applies
  identically to a replay worker — it must call the same function, not a
  parallel implementation).
- `expires_at` enforcement via `effective_status`
  (`disclosure/mod.rs:130-147`) — already correctly rejects a
  verification attempt against an expired request with `Conflict`
  (`verify/mod.rs:515-518`). A replay worker that reuses
  `verify_against_request` gets TTL enforcement for free; a replay worker
  that reimplements verification against the DB directly would not, and
  must not be built that way.
- The atomic, race-proof nonce consumption (§3).
- The audit chain's append/lock/hash-chain machinery (`audit/mod.rs`),
  unchanged — Mode B adds new *event types* through the existing `record`/
  `record_in_tx` functions, not a new mechanism.

New, needed for Mode B specifically:

1. **Persist the attempt before verifying, not only the outcome.** Today,
   an errored attempt leaves no trace anywhere (§1.3) — the submitted
   `public_inputs`/`proof_bytes` exist only in the failed request's memory
   and are lost the instant the 500 is returned. For replay to work without
   depending on the client having cached and being willing to resend the
   exact same bytes (a mobile session may be gone by the time `bb`
   recovers), the server must durably store the submission at attempt time.
   Concretely: a new table, e.g. `deferred_verifications` —
   `(id, request_id, org_id, user_id, circuit_type, public_inputs jsonb,
   proof_bytes bytea, submitted_at, attempt_count, last_attempted_at,
   resolved_at, resolution text null, callback_url text null)`. Written
   the moment `run_bb_verify` returns `Err` (the exact point currently at
   `verify/mod.rs:577` where the error propagates and nothing is recorded).
2. **A `verification_deferred` audit event**, written in the same
   transaction as the `deferred_verifications` insert, via
   `audit::record_in_tx` — the same atomicity discipline
   `record_valid_proof` already uses (`verify/mod.rs:393-399`'s own comment
   explains why: "the one event in this module where 'the action happened
   but the audit entry didn't get written' would actually matter"). Payload:
   `{request_id, org_id, user_id, circuit_type, error_class}`.
3. **A replay worker.** A background loop (in-process scheduled task or a
   separate small binary — either is fine; keep it a single writer to avoid
   a second `pg_advisory_xact_lock` contender) that polls
   `deferred_verifications where resolved_at is null order by submitted_at
   asc` — oldest first, both because it's the fairest ordering and because
   it's the ordering that makes "queue age" a meaningful, monotonic metric.
   For each row, it calls `verify_against_request` (or the shared inner
   logic factored out of it) with the stored inputs. Do not reimplement
   verification in the worker.
4. **A distinguishable response for the synchronous path**, reusing an
   existing precedent rather than inventing one: `ApiError` already has a
   variant carrying a machine-readable retry signal —
   `RateLimitedRetryAfter { retry_after_seconds, message }`
   (`error.rs:44`, handled specially at `error.rs:57-64` with a `Retry-After`
   header). Add an analogous `ApiError::Deferred { request_id, message }`
   mapping to `503 Service Unavailable` (matching the convention
   `ops/health.rs:168` already uses for "not ready, don't route here") with
   a body identifying the `deferred_verifications` row, so a calling system
   can distinguish "we don't know yet, we're retrying" from a genuine 4xx/5xx
   client-visible failure.

### 6.2 Customer-facing contract for the synchronous call

A `submit_proof` call that lands in Mode B returns `503` with
`{"status": "deferred", "request_id": ..., "deferred_id": ...}` rather than
today's opaque `500`. This is the single customer-visible change to the
existing endpoint: same URL, same auth, a distinguishable response instead
of an indistinguishable one. No new endpoint is required for the caller to
*submit*; the org's system polls `GET /disclosure-requests/:id` (existing
route) or registers `callback_url` at submission time for a push notification
when `resolved_at` is set.

### 6.3 What protects a queued decision before it's sealed

This is the part that must be stated precisely, because a second,
independently-confirmed gap in the audit chain bears directly on it.
`docs/BREAK_IT_FINDINGS.md` Finding 1: the *terminal* row of the audit chain
is unprotected. `audit/mod.rs`'s hash chain (`compute_event_hash`,
`audit/mod.rs:96-108`) makes every row tamper-evident *once a successor
exists*, because the successor's `prev_hash` commits to it — but the payload
itself is deliberately not stored (`audit/mod.rs:39-47`), so there is no way
to recompute a row's hash independently of the chain. The row currently at
the head of the chain — the newest one — has no successor yet, so a direct
`UPDATE audit_log SET event_hash = …` against it is undetectable from the
database alone. The break-it harness demonstrated this against a live
server: forge the head row's `event_hash`, and adjacency still holds.

Mode B makes this concrete and larger, not just theoretical: **queue-and-
replay means a decision is sealed later than it was taken.** During an
outage, every `verification_deferred` event (§6.1.2) written for a newly
queued decision *is*, briefly, the new chain head — exactly the exposed row
Finding 1 describes — until the next event of any kind (from this decision
or any other tenant's, since the chain is global, `audit/mod.rs:8-18`)
supersedes it. In a busy outage that's seconds; in a quiet one, it can be
longer. Either way, the newest, least-reviewed rows in the system are
exactly the ones an outage produces the most of.

**What the checkpoint (in progress, assume it exists per Finding 1's fix)
covers:** a periodic, externally-published, signed commitment to the current
chain head. Once published, every row up to and including that head is
tamper-evident to something *outside* Memtara's own database — closing the
gap for everything the checkpoint has already seen, and removing Memtara's
own unilateral ability to rewrite that history.

**What it does not cover, specifically for queued work:** rows appended
*after* the last published checkpoint and *before* the next one. During an
active outage, the `verification_deferred` rows are, by construction, the
freshest rows in the system — they sit inside exactly that window. Until the
next checkpoint fires, their tamper-evidence is internal-chain-linkage only:
protected from silent editing once a later row supersedes them (ordinary
operation), but not yet anchored outside Memtara's control. This is a real,
bounded gap, not a resolved one, and it should not be described as closed in
any customer-facing material.

**Operational consequence for Mode B, concretely:**

- The checkpoint publisher must run independently of `bb`'s health — it is
  signing the audit chain, unrelated to the verifier — and Mode B's runbook
  must not assume "the replay worker is alive" implies "the checkpoint is
  being published." Alert on checkpoint lag separately (§6.5).
- During a *declared* Mode B episode (bb confirmed down, queue actively
  growing), the checkpoint interval should tighten — publish more often,
  not on the steady-state cadence — precisely because this is when the
  exposed window is accumulating the rows that matter most. This is a
  config knob on the checkpoint publisher, not a change to this codebase's
  verification logic, and is out of scope to build here, but must be a
  named requirement handed to whoever owns that publisher.
- What is told to the customer: a queued decision's `verification_deferred`
  record is tamper-evident from the moment a subsequent chain event is
  written (typically seconds), and is anchored outside Memtara's own
  infrastructure from the moment the next checkpoint publishes (bounded by
  the checkpoint interval, tightened during a declared outage). It is not
  instantaneously externally anchored. Do not claim otherwise.

### 6.4 The interesting case: a queued decision fails verification on replay

The business may already have acted — a decision "in the queue" is not
necessarily a decision the org treated as pending internally, especially
under the time pressure §4 describes. When replay runs and `bb verify`
genuinely rejects the proof (a true cryptographic no, not an error):

1. `deferred_verifications.resolved_at` is set, `resolution = 'rejected'`.
2. The normal `proof_verification_failed` audit event fires
   (`verify/mod.rs:606-613`'s existing pattern, unchanged) — the decision's
   evidentiary trail now shows: request created → verification deferred
   (outage) → verification attempted and failed. Nothing about this path is
   silent.
3. **The org must be told, actively, not left to poll.** This is why
   `callback_url` exists in the schema (§6.1.1) — a decision resolving to
   "rejected" after the business may have already acted needs to interrupt
   someone, not wait for the next scheduled poll.
4. **This is not a system-level problem this codebase can fully solve, and
   the pilot agreement must say so explicitly.** Mode B guarantees the
   *evidence* is eventually correct. It cannot unwind a wire transfer or a
   verbal "you're approved" already given to a client. The contractual
   requirement for an org adopting Mode B: while a decision shows
   `deferred`, the org's own process must not treat it as approved for any
   action that depends on the proof. An org whose business process
   genuinely cannot wait for that resolution — cannot hold a wire, cannot
   ask a client to sit tight — is not a Mode B candidate; that org needs
   either the discipline of Mode A (wait, full stop) or the narrow,
   authorised Mode C described in §5. Mode B being available is not
   permission to treat "queued" as "approved."

### 6.5 Queue growth bound and fallback to Mode A

Three independent bounds, whichever triggers first:

1. **Depth.** `count(*) from deferred_verifications where resolved_at is
   null` exceeds a configured ceiling (recommend starting at 500, tuned
   against real pilot volume — no existing traffic baseline in this repo to
   derive a number from, so treat this as a starting point, not a derived
   constant). Past the ceiling, stop accepting new submissions into the
   queue; return the plain Mode A response (today's 5xx, or the clearer
   `503 Deferred` body carrying `"queue_full": true` so the caller can tell
   "we won't even try to queue this" apart from "queued, wait").
2. **Age.** The oldest unresolved row's age approaches the *shortest*
   remaining `expires_at` among currently-queued requests for that org
   (recall: TTL is fixed at creation, 1 second to 7 days,
   `disclosure/mod.rs:34-35`, and there is no extend/renew path — §3, point
   2). An org that queues requests with short TTLs gets a correspondingly
   short window before those specific decisions become unrecoverable
   regardless of overall queue depth. Alert on this per-request, not just
   in aggregate, since it's a per-decision cliff, not a system-wide one.
3. **Wall-clock outage duration.** `bb` confirmed unavailable (via the
   health probe recommended in §6.5's alert list, not inferred from
   accumulating `Errored` counts alone) for longer than a configured
   threshold (recommend 30 minutes as a starting point pending pilot data).
   Past this, declare a Mode B episode "escalated": tighten the checkpoint
   interval (§6.3), and consider whether Mode A should become the explicit
   posture for new submissions even if the depth/age bounds haven't been
   hit yet, since a long outage changes the operational calculus (queue
   is likely to keep growing, not resolve soon).

### 6.6 Metrics and alerts needed

New Prometheus series (extending the existing hand-rolled exposition in
`ops/metrics.rs`, same reasoning already documented there against pulling in
a client library):

- `memtara_deferred_verifications_pending` (gauge) — current unresolved
  queue depth. Alert: exceeds the depth bound in §6.5.1.
- `memtara_deferred_verifications_oldest_age_seconds` (gauge) — age of the
  oldest unresolved row. Alert: approaching the shortest queued request's
  remaining TTL (§6.5.2) — this alert needs to be computed per-org/per-
  request, not just as one global gauge, or it will fire too late for a
  short-TTL org and never for a long-TTL one.
- `memtara_deferred_verifications_resolved_total{resolution="accepted"|"rejected"|"expired"}`
  (counter) — replay outcomes. A rising `rejected` share after a Mode B
  episode is the metric §6.4 point 4 depends on for the org's own
  post-incident review.
- `memtara_bb_available` (gauge, 0/1) — driven by an **active** probe, not
  inferred (see the defect noted in §7: today's `/health` does not actually
  invoke `bb` at all). Alert: any transition to 0, and duration past the
  §6.5.3 threshold.
- `memtara_checkpoint_lag_seconds` (gauge, owned by the checkpoint publisher,
  not this module — named here because Mode B's alerting depends on it per
  §6.3). Alert: lag exceeding twice the configured interval, and
  independently, lag continuing to grow *during* a declared Mode B episode
  (the case §6.3 says must not be silently assumed fine).

---

## 7. Test plan

Each test named for what specific claim it proves and what it would catch if
that claim stopped being true.

1. **`nonce_never_consumed_on_infra_error`** (new; extends the pattern at
   `verify/mod.rs:810-860`) — submit a well-formed proof against a request,
   force `run_bb_verify_inner` to return `Err` (point `bb_bin` at a path
   that exists but isn't executable, or a similar controlled failure
   distinct from "garbage proof"), assert `used_nonces` gains zero rows and
   `disclosure_requests.status` stays `pending`. **Catches:** any future
   change that moves nonce consumption earlier in the pipeline, or any
   refactor of the error path that accidentally routes through
   `record_valid_proof`.
2. **`deferred_attempt_is_durably_recorded`** (new) — same setup as above,
   assert a `deferred_verifications` row exists with the exact
   `public_inputs`/`proof_bytes` submitted, and a `verification_deferred`
   audit row exists chained correctly (`prev_hash` matches whatever
   preceded it). **Catches:** the exact defect named in §1.3/§7 —
   regression to "errored attempts leave no trace."
3. **`replay_of_a_durable_valid_proof_succeeds_and_matches_synchronous_path`**
   (new) — queue a proof, run the replay worker, assert the resulting
   `proofs`/`used_nonces`/audit rows are byte-for-byte the same *shape* as
   the synchronous success path produces (reuse the assertions from
   `record_valid_proof`'s existing tests). **Catches:** a replay
   implementation that duplicates rather than reuses `verify_against_request`
   and silently diverges from it over time.
4. **`replay_of_expired_queued_request_is_rejected_not_silently_fulfilled`**
   (new) — queue a request with a short TTL, let it expire while "queued,"
   run the replay worker, assert `Conflict`/expired, and assert
   `disclosure_requests.status` never becomes `fulfilled`. **Catches:** a
   replay path that bypasses `effective_status` and fulfills a request past
   its TTL — the single most likely correctness bug in this design, per §6.1.
5. **`replay_rejection_after_deferral_writes_the_full_trail_and_fires_callback`**
   (new) — queue a proof that is genuinely invalid, run replay, assert the
   `proof_verification_failed` event exists, `resolution = 'rejected'`, and
   (if a `callback_url` was registered) the callback fired exactly once.
   **Catches:** §6.4's "business already acted" case going silent — the
   scenario this whole mode exists to make visible.
6. **`queue_depth_bound_falls_back_to_mode_a`** (new) — fill
   `deferred_verifications` past the configured ceiling, submit one more,
   assert it is rejected with `queue_full: true` rather than queued.
   **Catches:** an unbounded queue — the failure mode that would turn Mode B
   into an outage amplifier (Postgres growth, replay worker falling further
   behind) instead of a bounded degradation.
7. **`terminal_row_forgery_is_undetectable_until_next_event_or_checkpoint`**
   (adapt the existing break-it harness for attack #7) — run the exact
   forgery already demonstrated, but this time also assert that appending
   one more event (any tenant, any type) afterward *does* make the forged
   row detectable via `prev_hash` mismatch, and that a published checkpoint
   covering the forged row also makes it detectable, isolating "still
   undetectable" to precisely the window described in §6.3 — not before
   it, not after it. **Catches:** either an accidental fix that changes
   this boundary without anyone noticing (worth knowing either way) or a
   regression that widens the window further.
8. **`bb_health_probe_reflects_binary_execution_not_just_vkey_presence`**
   (new; see the defect in §8/§1) — delete or corrupt the `bb` binary while
   leaving vkey files on disk untouched, hit `/health`, assert it reports
   `degraded`/`memtara_bb_available == 0`. **Catches:** the current gap
   where `/health` would report `ok` throughout an outage identical to the
   one `test_attack_06...` demonstrates being fail-closed at the request
   layer.

---

## 8. What to say to a customer

> If our verifier is temporarily unavailable, we don't approve decisions on
> faith and we don't let them vanish either — the request is held, the fact
> that it's held gets its own timestamped record the moment it happens, and
> it's verified for real the moment we're back. If your process genuinely
> can't wait a few minutes for that, tell us and we'll design the block
> around a hard stop instead — but the queue is honest either way: nothing
> gets marked approved that wasn't actually proven.

---

## Appendix — file:line index of every current-behaviour claim in this document

- Boot-time gate: `main.rs:30,47`; `verify/mod.rs:70-114`.
- Per-request error path: `verify/mod.rs:137-155,157-208,163-169,204-205,577`.
- `ApiError::Other` → 500: `error.rs:79-82`. `Conflict` → 409: `error.rs:72`.
  `BadRequest` → 400: `error.rs:71`. `RateLimitedRetryAfter` precedent:
  `error.rs:44,57-64`.
- No audit/`proofs` row on infra error: `verify/mod.rs:577,582,618` (control
  flow), contrast with the invalid-proof path `verify/mod.rs:582-613`.
- `VerificationResult::Errored` distinct from `Rejected`:
  `ops/metrics.rs:49-52,60-66,141`.
- Nonce invariant: `verify/mod.rs:344-411` (`record_valid_proof`),
  `582-587` (comment + non-consuming code), single call site at `618`.
  Tests: `verify/mod.rs:810-860` (replay rejected),
  `870-927` (concurrency), `933-954` (scoping).
- `effective_status`/TTL: `disclosure/mod.rs:34-35,130-147,217`; enforced in
  the verify path at `verify/mod.rs:515-518`. No renew/extend function
  exists (grep confirmed, no citation possible for an absence).
- Audit chain hashing and the unprotected terminal row: `audit/mod.rs:8-18`
  (global scope), `39-47` (payload not stored), `96-108`
  (`compute_event_hash`), `143-146` (head lookup by `seq desc limit 1`);
  Finding 1 in `docs/BREAK_IT_FINDINGS.md`.
- Break-it evidence: `tests/break_it/test_attack_06_proof_service_removed.py`
  (Mode A, STOPPED); `docs/BREAK_IT_FINDINGS.md` (Finding 1, terminal row;
  summary table for all 11 attacks).
- Health check gaps: `ops/health.rs:39-45,62-183` — checks DB, JWKS/`kid`
  membership, and vkey **file presence**; never invokes `state.config.bb_bin`
  anywhere in this file (confirmed by reading the full file — no
  `bb_bin`/`Command::new` reference exists in `ops/health.rs`).
