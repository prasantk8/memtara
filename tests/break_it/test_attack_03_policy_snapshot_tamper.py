"""Attack #3 — change the policy version mid-flight.

    ATTACK: an assessment is opened under one governing policy. While it is
    still in flight, the policy changes (different scope, different rules).
    The evidence produced for the assessment must either reflect the policy
    it was actually opened under, or the mismatch must surface somewhere.

    There is still no live policy registry or endpoint to amend a policy —
    `disclosure_requests.policy` is written once at open, by
    `wealth::issue_wealth_request` and `disclosure::create_disclosure_request`,
    and nothing else in `backend/api/src/` ever writes that column. So the
    closest real-world analogue remains a direct database write, standing in
    for the operator or insider who is the only actor that can reach it.

    ---------------------------------------------------------------------
    THIS MODULE PREVIOUSLY REPORTED THIS ATTACK AS NOT STOPPED
    ---------------------------------------------------------------------
    Half of that finding has been closed and half has not, and the two
    halves were always separable — they are separated here rather than
    averaged into one verdict.

    CLOSED — the tamper is no longer invisible. The `policy` column was in
    no event's hashed payload; both open-time events listed
    `user_id`/`circuit_type`/terms/`ttl_seconds` and never the policy itself,
    so an edit to it left the chain unbroken and unbothered.
    `backend/api/src/audit/binding.rs` added a `disclosure_policy_bound`
    event whose payload is rebuilt from the row at verification time, so an
    edit now makes the rebuilt digest disagree with the recorded one.

    STILL OPEN — there is no named version to mismatch AGAINST. The binding
    proves the snapshot changed; it cannot say what it changed FROM, because
    the payload is not stored (deliberately — see `binding.rs`) and no
    version marker exists on the policy at all. An examiner learns "this
    policy is not the one the decision was opened under" and must then
    reconstruct the original from elsewhere. That is a materially better
    position than silence and materially worse than a version history, and
    `BREAK_IT_NOTE` says so.

    WHAT THIS TEST PROVES:

      1. The policy snapshot still carries no version marker of any name —
         checked against the real live row, not read off the source.
      2. An untouched request's policy binding reports INTACT, asserted
         before any tampering. A detector that fires on an undisturbed
         database detects nothing.
      3. A direct tamper of the column is caught: the rebuilt payload no
         longer hashes to the recorded digest, and the replay verdict is
         ALTERED naming the row.
      4. The hash chain's own linkage is STILL unbroken across the tamper.
         Asserted deliberately, because it is the trap: an auditor walking
         `prev_hash`/`event_hash` adjacency — the exact check
         `scripts/export_audit_evidence.py` performs — sees a healthy chain
         and would have concluded the policy was untouched. Linkage and
         binding are different claims.
      5. The ordinary read path `GET /disclosure-requests/:id` still serves
         the tampered policy with no flag. That is a real residual and it is
         asserted rather than omitted: only the decision-evidence envelope
         and the replay endpoint carry the verdict today.

    HONEST STATUS FOR THE BREAK-IT TABLE: STOPPED — detected, with the
    version gap stated as the residual. Nothing prevents a database write;
    what changed is that this one now leaves the record disagreeing with the
    chain.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 3
BREAK_IT_ATTACK_TITLE = "Change the policy version mid-flight"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "detected, not prevented, and only half-answered: the policy snapshot is now inside a hashed "
    "payload that verification rebuilds from the live row, so a mid-flight edit makes the replay "
    "verdict ALTERED while chain linkage stays unbroken. Residual: no version marker exists on "
    "the policy, so an examiner learns THAT it changed, not what it changed from; and "
    "GET /disclosure-requests/:id still serves the tampered content unflagged"
)

import json

import httpx

from conftest import audit_log, binding_replay, db_connect, open_assessment

POLICY_BOUND = "disclosure_policy_bound"


def _adjacent_links_hold(entries: list[dict]) -> bool:
    """The exact check an external auditor can perform from
    `GET /orgs/:id/audit-log` alone (seq order, event_hash/prev_hash) — see
    `backend/api/src/audit/mod.rs`'s own module docstring on why a filtered
    per-org view still has meaningful (if non-adjacent-by-seq) linkage, and
    `scripts/export_audit_evidence.py`'s chain-verification section, which
    performs the same adjacency walk.
    """
    by_seq = sorted(entries, key=lambda e: e["seq"])
    for i in range(1, len(by_seq)):
        if by_seq[i]["prev_hash"] != by_seq[i - 1]["event_hash"]:
            return False
    return True


def _policy_binding(report: dict) -> dict:
    events = [e for e in report["events"] if e["event_type"] == POLICY_BOUND]
    assert len(events) == 1, f"expected exactly one {POLICY_BOUND} event, got {events}"
    return events[0]


def test_a_policy_snapshot_tamper_is_caught_by_the_binding_though_the_chain_stays_unbroken(
    memtara_server, make_desk
):
    desk = make_desk(memtara_server, isin="XS0000000077")
    request = open_assessment(memtara_server, desk)
    request_id = request["request_id"]

    conn = db_connect()
    try:
        rows = conn.run("select policy::text from disclosure_requests where id = :id", id=str(request_id))
        assert rows, "the request must have a row"
        original_policy = json.loads(rows[0][0])
    finally:
        conn.close()

    # 1. Still unversioned. Verified against the real, live snapshot.
    assert "policy_version" not in original_policy
    assert "version" not in original_policy, (
        "no version marker of any name exists on the policy snapshot today — the half of this "
        "finding the binding does not answer"
    )

    baseline_chain = audit_log(memtara_server, desk)
    assert any(e["ref_id"] == request_id for e in baseline_chain), "sanity: the open event is in the trail"
    assert _adjacent_links_hold(baseline_chain), "sanity: the chain is healthy before any tamper"

    # 2. No false positive, asserted before the attack.
    before = binding_replay(memtara_server, desk, ref_id=request_id)
    clean = _policy_binding(before)
    assert clean["result"] == "intact", clean
    assert clean["recomputed_event_hash"] == clean["recorded_event_hash"]
    assert clean["rebuilt_payload"]["policy"] == original_policy, (
        "the bound payload must carry the predicate set itself — the fact whose absence from "
        "every hashed payload was this finding"
    )

    # The attack: an out-of-band change to the policy snapshot, mid-flight.
    tampered_policy = dict(original_policy)
    tampered_policy["categories"] = ["financial", "everything_else_too"]
    tampered_policy["duration_seconds"] = 999_999_999

    conn = db_connect()
    try:
        conn.run(
            "update disclosure_requests set policy = :policy where id = :id",
            policy=json.dumps(tampered_policy),
            id=str(request_id),
        )
    finally:
        conn.close()

    # 3. Caught.
    after = binding_replay(memtara_server, desk, ref_id=request_id)
    assert after["verdict"] == "ALTERED", after
    altered = _policy_binding(after)
    assert altered["result"] == "altered"
    assert altered["recomputed_event_hash"] != altered["recorded_event_hash"], (
        "the policy is inside the hashed payload now, so rebuilding it from the edited row must "
        "produce a different digest"
    )
    assert "disclosure_requests" in altered["detail"]
    assert altered["rebuilt_payload"]["policy"]["duration_seconds"] == 999_999_999, (
        "and the rebuilt payload is exported as it stands now, disagreement and all, so a party "
        "holding it recomputes the digest themselves rather than believing our verdict"
    )

    # 4. The trap: linkage is still perfectly healthy.
    after_chain = audit_log(memtara_server, desk)
    assert _adjacent_links_hold(after_chain), (
        "the hash chain shows no break across this tamper, and never would have: it commits to "
        "the sequence of events, not to the mutable rows they are about. An auditor who checked "
        "only adjacency would have signed this off"
    )
    assert after_chain == baseline_chain, (
        "no rows were added or changed either — the entire difference is in what the rows the "
        "chain committed to now say"
    )

    # 5. The residual, asserted so it cannot rot into an unstated assumption.
    served = httpx.get(
        f"{memtara_server}/disclosure-requests/{request_id}",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=10.0,
    )
    assert served.status_code == 200, served.text
    assert served.json()["policy"]["categories"] == ["financial", "everything_else_too"], (
        "this read path serves the tampered policy with no flag. The binding verdict reaches a "
        "reader through the decision-evidence envelope and the replay endpoint, and not through "
        "here — a consumer of this route alone is still unwarned"
    )
