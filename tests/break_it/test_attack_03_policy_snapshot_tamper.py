"""Attack #3 — change the policy version mid-flight.

    ATTACK: an assessment is opened under one governing policy. While it is
    still in flight, the policy changes (a new named version, different
    scope, different rules). The evidence produced for the assessment should
    either reflect the policy version it was actually opened under, or the
    mismatch should surface somewhere.

    STATUS UP FRONT — this attack is only PARTIALLY runnable today, and this
    test is written to be honest about exactly where the line falls, per
    `decision_evidence_spec.md` Task 4, item 3: "there is no `policy_version`
    field — the test can check 'did the snapshot change,' not 'which named
    version.'" There is no live policy registry or endpoint to legitimately
    amend a policy's version at all (confirmed: `disclosure_requests.policy`
    is written once at request-open time in
    `backend/api/src/wealth/mod.rs::issue_wealth_request` and
    `backend/api/src/disclosure/mod.rs::create_disclosure_request`, and
    nothing else in `backend/api/src/` ever writes that column). So the
    closest real-world analogue this test can exercise is a direct database
    write to that column — standing in for an operator/insider with direct
    DB access, since there is no HTTP surface that would let anyone else
    reach it.

    WHAT THIS TEST PROVES (a real, verified finding, not a hypothetical):

      1. The request-time policy snapshot carries no `policy_version` (or
         any version marker at all) — checked against the real, live row,
         not asserted from reading the source.
      2. A direct tamper of that column is NOT caught by anything the system
         currently checks. Specifically: `GET /disclosure-requests/:id`
         (`authorize_org_or_user`-gated) returns the tampered policy with no
         error, and the org's own hash-chained audit trail
         (`GET /orgs/:id/audit-log`) shows unbroken `prev_hash`/`event_hash`
         adjacency before and after the tamper — because the `policy` column
         is never included in ANY audit event's hashed payload (confirmed by
         reading `issue_wealth_request`'s and `create_disclosure_request`'s
         `audit::record(_in_tx)` calls: both list `user_id`/`circuit_type`/
         terms/`ttl_seconds`, never `policy`). The hash chain protects the
         EVENTS about a request; it does not protect this particular
         column's content.

    WHAT THIS TEST DOES NOT PROVE: it does not prove a named-version mismatch
    is refused, because there is no named version to mismatch against yet —
    that is Task 1's `policy.id/version` gap
    (decision_evidence_spec.md §1.2). It also does not claim this is the
    intended long-term design; it demonstrates today's actual behaviour so
    the gap is documented against real system output rather than left as an
    assumption.

    HONEST STATUS FOR THE BREAK-IT TABLE: NOT STOPPED (a real, narrower
    finding than the four fully-blocked attacks: unlike those, there IS a
    real column being snapshotted here — it is just unguarded).
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 3
BREAK_IT_ATTACK_TITLE = "Change the policy version mid-flight"
BREAK_IT_STATUS_ON_PASS = "NOT STOPPED"
BREAK_IT_NOTE = (
    "no policy_version field exists yet; a direct tamper of the policy snapshot is served "
    "as-is and invisible to the audit chain (real, narrower finding than #4/#8/#10/#11 — "
    "there IS a live column here, it just isn't guarded or versioned)"
)

import json

import httpx

from conftest import audit_log, db_connect, open_assessment


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


def test_policy_snapshot_has_no_version_field_and_a_direct_tamper_goes_undetected(memtara_server, make_desk):
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

    # Finding 1/2: verified against the real, live snapshot, not the source.
    assert "policy_version" not in original_policy
    assert "version" not in original_policy, (
        "no version marker of any name exists on the policy snapshot today"
    )

    baseline_chain = audit_log(memtara_server, desk)
    assert any(e["ref_id"] == request_id for e in baseline_chain), "sanity: the open event is in the trail"
    assert _adjacent_links_hold(baseline_chain), "sanity: the chain is healthy before any tamper"

    # The attack: an out-of-band change to the policy snapshot, mid-flight.
    # There is no endpoint for this — direct DB write stands in for the only
    # actor who could do it today.
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

    # Finding 2, made concrete: the ordinary, authorized read path serves
    # the tampered content with no error and no flag.
    served = httpx.get(
        f"{memtara_server}/disclosure-requests/{request_id}",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=10.0,
    )
    assert served.status_code == 200, served.text
    assert served.json()["policy"]["categories"] == ["financial", "everything_else_too"], (
        "the tampered policy is served as-is — nothing rejects or flags it"
    )

    # And the audit trail — the mechanism that DOES catch tampering
    # elsewhere in this system (see attack #7) — is silent here, because the
    # `policy` column was never part of any event's hashed payload.
    after_chain = audit_log(memtara_server, desk)
    assert _adjacent_links_hold(after_chain), (
        "the hash chain shows no break: this specific tamper is invisible to it, "
        "which is the finding this test exists to demonstrate — NOT a false negative"
    )
