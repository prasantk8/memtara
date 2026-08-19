"""Attack #7 — modify the evidence record after the fact.

    ATTACK: after a decision's audit trail has been written, someone with
    database access edits it — either the tamper-evidence machinery itself
    (a hash-chain column) or the human-readable content of an event (what
    it says happened).

    EXPECTED DEFENSIVE BEHAVIOUR (per `backend/api/src/audit/mod.rs`'s own
    design doc): `audit_log` is a hash-chained, append-only commitment
    scheme — SHA-256 over
    `event_type || ref_id || prev_hash || payload`, framed to avoid
    concatenation ambiguity — such that editing any row breaks the chain's
    internal linkage for everything after it.

    WHAT THIS TEST PROVES — TWO DISTINCT, REAL FINDINGS, against a real
    running server, real Postgres, and the real `GET /orgs/:id/audit-log`
    endpoint (not a reimplementation of the hashing in this test):

      1. STOPPED (as designed): editing a row's OWN hash-chain columns
         (`event_hash`/`prev_hash` — simulating a row being replaced
         wholesale) breaks `prev_hash`/`event_hash` adjacency for every
         later row, and that break is visible purely from what
         `GET /orgs/:id/audit-log` already returns — exactly the check
         `scripts/export_audit_evidence.py` and an external auditor would
         perform (decision_evidence_spec.md Task 2 §2.2, step 4).

      2. NOT STOPPED (a real, verified defect, not a hypothetical): editing
         a row's `event_type` — e.g. quietly turning a recorded
         `proof_verification_failed` into `proof_verified`, laundering a
         REJECTED decision into one that reads as accepted — WITHOUT also
         recomputing `event_hash`/`prev_hash`, is invisible to the same
         endpoint. `event_hash` is computed over `event_type` at insert
         time and never recomputed or re-checked afterwards; the public
         audit-log endpoint returns the (now-falsified) `event_type`
         column directly, and adjacency to neighbouring rows is completely
         unaffected because neither hash column was touched. There is
         nowhere in the current system — not this endpoint, not
         `scripts/export_audit_evidence.py`'s adjacency check, since
         `payload` (which WOULD have caught this) is deliberately never
         persisted or exposed (`audit/mod.rs`'s own comment: "there's no
         column for it, schema is final") — that would catch this specific
         edit today.

    WHY THIS MATTERS MORE THAN A SINGLE PASS/FAIL: the honest reading of
    "modify the evidence record → hash chain must break" is that it is
    TRUE for structural tampering and FALSE for the content tamper an
    attacker would actually prefer (it's simpler, and it's the one that
    survives). The break-it table reports this attack as NOT STOPPED on
    that basis — reporting only finding 1 would overstate what the system
    guarantees today.

    WHAT THIS TEST DOES NOT PROVE: it does not evaluate the (not-yet-built)
    offline verification bundle from decision_evidence_spec.md Task 2, which
    is designed to ship `payload` alongside each event specifically to close
    this gap for third-party verification — that is future work, not
    today's live API.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 7
BREAK_IT_ATTACK_TITLE = "Modify the evidence record"
BREAK_IT_STATUS_ON_PASS = "NOT STOPPED"
BREAK_IT_NOTE = (
    "hash-column tamper (event_hash/prev_hash) breaks chain adjacency and IS caught; "
    "event_type tamper alone (hash columns left untouched) is invisible to GET /orgs/:id/audit-log "
    "(real, verified finding — see test docstring)"
)

import uuid

import wealth_client as wc

from conftest import audit_log, db_connect, open_assessment


def _adjacent_links_hold(entries: list[dict]) -> bool:
    by_seq = sorted(entries, key=lambda e: e["seq"])
    for i in range(1, len(by_seq)):
        if by_seq[i]["prev_hash"] != by_seq[i - 1]["event_hash"]:
            return False
    return True


def test_hash_column_tamper_breaks_the_chain_but_event_type_tamper_does_not(memtara_server, make_desk):
    desk = make_desk(memtara_server, isin="XS0000000088")
    request = open_assessment(memtara_server, desk)
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    result = wc.submit_assessment(memtara_server, desk.session_token, request["request_id"], proof)
    assert result["suitable"] is True

    baseline = audit_log(memtara_server, desk)
    ref_rows = sorted([e for e in baseline if e["ref_id"] == request["request_id"]], key=lambda e: e["seq"])
    assert len(ref_rows) >= 2, "expected at least the 'requested' and 'proof_verified' events"
    assert _adjacent_links_hold(baseline), "sanity: the chain is healthy before any tamper"

    target = ref_rows[-1]  # the "proof_verified" event
    target_id = target["id"]

    # ------------------------------------------------------------------
    # Finding 1 (STOPPED): tamper with a hash-chain column directly, as if
    # the row had been replaced wholesale.
    # ------------------------------------------------------------------
    conn = db_connect()
    try:
        forged_hash = uuid.uuid4().bytes + uuid.uuid4().bytes  # 32 bytes of garbage, same shape as a real hash
        conn.run(
            "update audit_log set event_hash = :h where id = :id",
            h=forged_hash,
            id=str(target_id),
        )
    finally:
        conn.close()

    after_hash_tamper = audit_log(memtara_server, desk)
    assert not _adjacent_links_hold(after_hash_tamper), (
        "a direct edit to event_hash must break prev_hash/event_hash adjacency for later rows"
    )

    # Restore, so finding 2 starts from a clean, healthy chain and isolates
    # its own variable.
    conn = db_connect()
    try:
        conn.run(
            "update audit_log set event_hash = :h where id = :id",
            h=_b64_to_bytes(target["event_hash"]),
            id=str(target_id),
        )
    finally:
        conn.close()
    assert _adjacent_links_hold(audit_log(memtara_server, desk)), "restore must bring the chain back to healthy"

    # ------------------------------------------------------------------
    # Finding 2 (NOT STOPPED): tamper with event_type alone, hash columns
    # untouched — laundering a failed/verified label without recomputing
    # anything.
    # ------------------------------------------------------------------
    conn = db_connect()
    try:
        conn.run(
            "update audit_log set event_type = :t where id = :id",
            t="proof_verification_falsified_by_break_it_test",
            id=str(target_id),
        )
    finally:
        conn.close()

    after_content_tamper = audit_log(memtara_server, desk)
    tampered_row = next(e for e in after_content_tamper if e["id"] == target_id)
    assert tampered_row["event_type"] == "proof_verification_falsified_by_break_it_test", (
        "sanity: the tamper actually took effect"
    )
    assert _adjacent_links_hold(after_content_tamper), (
        "THE FINDING: event_type can be rewritten in place, with the hash columns left exactly as "
        "they were, and prev_hash/event_hash adjacency — the only integrity check the live "
        "GET /orgs/:id/audit-log endpoint supports — does not notice. This is a real gap, not "
        "the expected behaviour of a tamper-evident log."
    )


def _b64_to_bytes(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "==")
