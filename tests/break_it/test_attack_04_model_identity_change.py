"""Attack #4 — change the model identity an assessment was recorded against.

    ATTACK: an AI-mediated recommendation is made by model A, and model A is
    properly declared and recorded. Later — before an export, after a
    complaint, the morning a model is found to have been misbehaving — the
    recorded identity is changed to model B, by the only actor who can do it
    at all: someone holding a database connection. The evidence must not
    silently serve whichever identity was written last.

    This is the companion to attack #11 and NOT the same attack. #4 attacks a
    value that IS recorded. #11 attacks the absence of a rebind.

    ---------------------------------------------------------------------
    THIS MODULE PREVIOUSLY REPORTED THIS ATTACK AS NOT STOPPED
    ---------------------------------------------------------------------
    It was, and the finding was real. `audit_log` has no payload column; the
    one event that mentioned AI participation —
    `wealth_suitability_requested` — hashed `ai_participation_declared`,
    i.e. THAT a declaration was made, and never which model was named. So a
    single UPDATE rewrote the identity the sealed record served and the hash
    chain was byte-identical before and after. Not a chain that failed to
    notice: there was nothing for it to notice.

    `backend/api/src/audit/binding.rs` closed it, and the mechanism matters
    for reading the assertions below. A binding event's payload is a pure
    function of the rows it commits to, and the payload is deliberately still
    not stored — so verification has no choice but to REBUILD it from the
    live rows and re-hash. An UPDATE changes the rebuilt bytes and therefore
    the comparison. Storing the payload instead would have re-opened the
    hole one table over: the stored copy is untouched by the attacker's
    UPDATE, so hashing it would still succeed.

    WHAT THIS TEST PROVES:

      1. The whole HTTP surface refuses to restate a model identity — a
         second attestation is refused by the primary key, the review
         endpoint is `deny_unknown_fields` and rejects a smuggled
         `model_name`, and there is no PATCH, PUT or per-decision model
         route. Re-opening produces a DIFFERENT decision and leaves the
         original untouched. Unchanged, and still asserted, because a fix at
         the chain layer is not a reason to stop checking the layer above it.
      2. An untouched decision reports its binding INTACT. Asserted FIRST and
         deliberately: a detector that fires on everything detects nothing,
         and this is the assertion that would catch a rebuild that had
         drifted from the write path.
      3. The UPDATE still lands — it is a database write and no application
         can prevent one — and the served record's `model` block does change.
         But the record is no longer served as unqualified fact: the
         `binding_integrity` envelope on the very same response reports
         ALTERED and names the event, on every read, without the reader
         having to know a second endpoint exists.
      4. The org's own audit log is STILL byte-identical across the swap.
         Asserted, not glossed: linkage was never the thing that broke, and
         a reader who takes an intact chain as proof the record is intact is
         making exactly the mistake this finding exposed. Linkage and binding
         are different claims and this suite checks both separately.
      5. The escalation — the same UPDATE moving the row to `declaration =
         'no_ai_participated'`, so the record serves `model: null`, which the
         pinned schema and `model_intake.rs` both define as a SIGNED
         ASSERTION that no AI participated — is caught too. That was the
         worst version of this finding and it is the one to re-check hardest,
         because the escalation reaches it by NULLING columns rather than by
         writing them, and a binding that only covered non-null values would
         miss it.

    HONEST STATUS FOR THE BREAK-IT TABLE: STOPPED — detected, not prevented,
    and the difference is stated in `BREAK_IT_NOTE` rather than buried here.
    Nothing in this system can stop an UPDATE. What it can do is make one
    that leaves the record disagreeing with the chain, and this now does.

    THE RESIDUAL, stated because an unstated residual is how a control gets
    over-sold:

      - Detection requires reading `binding_integrity` (or the replay
        endpoint). A consumer that parses `decision_evidence` and ignores the
        envelope around it sees the swapped identity and no warning. The
        record itself cannot carry the verdict — it is canonicalised and
        sealed, and a field whose value depends on when you ask cannot live
        in bytes that must be identical every time. See `respond` in
        `backend/api/src/wealth/evidence.rs` for that argument.
      - An attacker who can UPDATE can also DELETE the binding event from
        `audit_log`. That breaks linkage rather than binding, which is
        attack #7's subject and is caught by the chain walk and, for the
        terminal rows, by the signed checkpoint. The two controls compose;
        neither is complete alone.
      - The rebuild reads the live row. It therefore proves the row is
        unchanged since the event; it does not prove the row was TRUE when
        written. That is attack #11, and it is a different problem.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 4
BREAK_IT_ATTACK_TITLE = "Change the model identity"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "detected, not prevented: the UPDATE still lands, but the eight model leaves are now inside "
    "a hashed payload that verification rebuilds from the live row, so the swap — including the "
    "escalation to the signed 'no AI participated' assertion — makes the record disagree with "
    "the chain, and every read of the record carries that verdict. Residual: a consumer that "
    "ignores the binding_integrity envelope still sees the swapped identity unwarned"
)

import datetime as dt

import httpx
import wealth_client as wc

from conftest import audit_log, binding_replay, db_connect

MODEL_A = {
    "declaration": "model_identified",
    "provider": "anthropic",
    "model_name": "claude-opus-4",
    "model_version": "20260514",
    "prompt_version": "suitability-v7",
    "environment": "production",
    "config_fingerprint": "ab" * 32,
    "system_prompt_or_policy_id": "policy/suitability/7",
}

MODEL_B = {
    "declaration": "model_identified",
    "provider": "a-different-vendor",
    "model_name": "a-different-model",
}

MODEL_ATTESTATION_BOUND = "decision_model_attestation_bound"


def _open(base_url, desk, *, ai_participation=None):
    body = {"user_id": desk.user_id, "product_isin": desk.product_isin, "ttl_seconds": 900}
    if ai_participation is not None:
        body["ai_participation"] = ai_participation
    response = httpx.post(
        f"{base_url}/api/v1/issue-wealth-request",
        json=body,
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _evidence(base_url, desk, request_id):
    return httpx.get(
        f"{base_url}/api/v1/wealth-assessments/{request_id}/decision-evidence",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _recorded_leaves(record) -> dict:
    """The model block flattened to `{leaf: value}`, or `None` for the
    `model: null` case — the signed assertion that no AI participated.
    """
    model = record["model"]
    if model is None:
        return None
    return {leaf: field["value"] for leaf, field in model.items()}


def _attestation_binding(payload: dict) -> dict:
    """The one `decision_model_attestation_bound` event for this decision.

    Asserted to be exactly one rather than picked with `[0]`: the primary key
    on `decision_model_attestations` means a decision has one attestation, so
    two binding events for it would itself be a finding, and a test that took
    the first would hide it.
    """
    events = [e for e in payload["events"] if e["event_type"] == MODEL_ATTESTATION_BOUND]
    assert len(events) == 1, f"expected exactly one {MODEL_ATTESTATION_BOUND} event, got {events}"
    return events[0]


def _just_after(timestamp: str) -> str:
    """Two seconds after the assessment's own `assessed_at` — read from the
    record, not from this machine's clock, because Postgres's `now()` (which
    stamps the verdict) and the server process's clock (which bounds the
    review) run in different containers here and are observably tens of
    milliseconds apart.
    """
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z")


def test_a_recorded_model_identity_cannot_be_rewritten_without_the_record_disagreeing_with_the_chain(
    memtara_server, make_desk
):
    desk = make_desk(memtara_server, isin="XS0000000104")

    # A complete, fully identified, review-bearing decision. Nothing about
    # this assessment is degraded: the model leaves are supplied, the proof
    # is real, the human review is real.
    request = _open(memtara_server, desk, ai_participation=MODEL_A)
    assert request["ai_participation_recorded"] == "model_identified"
    request_id = request["request_id"]

    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert wc.submit_assessment(memtara_server, desk.session_token, request_id, proof)["suitable"] is True

    original = _evidence(memtara_server, desk, request_id)
    assert original.status_code == 200, original.text
    original_body = original.json()
    original_record = original_body["decision_evidence"]
    assert _recorded_leaves(original_record)["provider"] == "anthropic"
    assert _recorded_leaves(original_record)["model_name"] == "claude-opus-4"

    # -----------------------------------------------------------------
    # 2. NO FALSE POSITIVE. Asserted before any tampering, because a
    #    detector that fires on an untouched database is worse than none:
    #    it teaches an operator to dismiss the one real alarm. This is also
    #    the assertion that fails if the rebuild in `binding.rs` ever drifts
    #    from the payload the write path hashed.
    # -----------------------------------------------------------------
    assert original_body["binding_integrity"]["verdict"] == "INTACT", original_body["binding_integrity"]
    clean = _attestation_binding(original_body["binding_integrity"])
    assert clean["result"] == "intact"
    assert clean["recomputed_event_hash"] == clean["recorded_event_hash"], (
        "the rows this decision's binding event commits to must re-hash to the recorded digest "
        "on an untouched database"
    )
    # The bound payload names the model. This is the fact whose absence was
    # the entire finding, so it is checked directly rather than inferred
    # from the verdict.
    assert clean["rebuilt_payload"]["model_name"] == "claude-opus-4"
    assert clean["rebuilt_payload"]["model_provider"] == "anthropic"
    assert clean["rebuilt_payload"]["declaration"] == "model_identified"

    reviewed_at = _just_after(original_record["decision"]["timestamps"]["assessed_at"])

    # -----------------------------------------------------------------
    # 1. Every HTTP path that might accept a second or altered attestation.
    #    All four are refused — this half was always a real defence and is
    #    still asserted as one.
    # -----------------------------------------------------------------
    smuggled = httpx.post(
        f"{memtara_server}/api/v1/wealth-assessments/{request_id}/review",
        json={
            "reviewer_id": "emp-4417",
            "reviewer_role": "senior_suitability_officer",
            "action": "approved",
            "human_review_protocol_version": "cob-review-2026.2",
            "reviewed_at": reviewed_at,
            "model_name": "a-different-model",
        },
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )
    assert smuggled.status_code == 422, smuggled.text
    assert "unknown field `model_name`" in smuggled.text

    for method, path in [
        ("PATCH", f"/api/v1/wealth-assessments/{request_id}"),
        ("PUT", f"/api/v1/wealth-assessments/{request_id}/decision-evidence"),
        ("POST", f"/api/v1/wealth-assessments/{request_id}/model"),
    ]:
        attempt = httpx.request(
            method,
            f"{memtara_server}{path}",
            json=MODEL_B,
            headers={"Authorization": f"Bearer {desk.api_key}"},
            timeout=30.0,
        )
        assert attempt.status_code in (404, 405), (
            f"{method} {path} answered {attempt.status_code}: there must be no route that restates "
            f"a decision's model identity"
        )

    # Re-opening under a different model produces a DIFFERENT decision, not a
    # rebind of this one — and leaves this one alone, binding and all.
    rebranded = _open(memtara_server, desk, ai_participation=MODEL_B)
    assert rebranded["request_id"] != request_id
    untouched = _evidence(memtara_server, desk, request_id).json()
    assert _recorded_leaves(untouched["decision_evidence"]) == _recorded_leaves(original_record)
    assert untouched["binding_integrity"]["verdict"] == "INTACT"

    # The genuine review, so the decision is final and review-bearing before
    # anyone touches it.
    review = httpx.post(
        f"{memtara_server}/api/v1/wealth-assessments/{request_id}/review",
        json={
            "reviewer_id": "emp-4417",
            "reviewer_role": "senior_suitability_officer",
            "action": "approved",
            "human_review_protocol_version": "cob-review-2026.2",
            "reviewed_at": reviewed_at,
            "review_duration_ms": 214_000,
        },
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )
    assert review.status_code == 201, review.text

    conn = db_connect()
    try:
        # A second attestation row is refused by the primary key — the API
        # has no way to reach this table twice for one decision.
        try:
            conn.run(
                "insert into decision_model_attestations (request_id, org_id, declaration, "
                "model_provider, model_name) values (:rid, :org, 'model_identified', 'x', 'y')",
                rid=str(request_id),
                org=str(desk.org_id),
            )
            raise AssertionError("a decision must carry exactly one model attestation")
        except Exception as exc:
            detail = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
            assert detail.get("n") == "decision_model_attestations_pkey", detail

        # Still no payload column: the chain stores a digest of each event
        # and nothing else. Checked live, because the fix depends on this
        # staying true — a stored payload would be hashed instead of the
        # live rows, and the swap would become invisible again. See
        # `binding.rs`, "WHY THE PAYLOAD IS STILL NOT STORED".
        payload_columns = conn.run(
            "select column_name from information_schema.columns "
            "where table_name = 'audit_log' and column_name = 'payload'"
        )
        assert payload_columns == [], (
            "audit_log stores event hashes, not payloads. If that has changed, the binding check "
            "must be re-examined: hashing a stored copy of the payload would succeed after the "
            "very UPDATE this attack makes"
        )

        chain_before = audit_log(memtara_server, desk)

        # -----------------------------------------------------------------
        # 3. THE ATTACK. One UPDATE, by the only actor who can make it.
        # -----------------------------------------------------------------
        conn.run(
            "update decision_model_attestations set model_provider = 'openai', "
            "model_name = 'gpt-4o-mini', model_version = '2024-07-18', "
            "model_config_fingerprint = :fingerprint where request_id = :rid",
            fingerprint="99" * 32,
            rid=str(request_id),
        )

        swapped = _evidence(memtara_server, desk, request_id)
        assert swapped.status_code == 200, swapped.text
        swapped_body = swapped.json()

        # The write landed. Said plainly, because the claim being made here
        # is detection, not prevention, and a test that pretended the row
        # had not changed would be overselling it.
        assert _recorded_leaves(swapped_body["decision_evidence"])["model_name"] == "gpt-4o-mini"

        # THE DEFENCE. Same response, same request, no second call needed.
        assert swapped_body["binding_integrity"]["verdict"] == "ALTERED", (
            "the record must not be served as unqualified fact after the rows behind it changed"
        )
        altered = _attestation_binding(swapped_body["binding_integrity"])
        assert altered["result"] == "altered"
        assert altered["recomputed_event_hash"] != altered["recorded_event_hash"], (
            "the model leaves are inside the hashed payload now, so rebuilding it from the "
            "rewritten row must produce a different digest"
        )
        assert altered["ref_id"] == str(request_id)
        assert "decision_model_attestations" in altered["detail"], (
            "and the finding must name the table an examiner has to go and look at, not just "
            "report a mismatch"
        )

        # 4. Linkage is STILL byte-identical, and that is the point. The
        #    chain proves rows were not removed or reordered; it never
        #    claimed their contents were unchanged. Reporting an intact
        #    chain as proof of an intact record is the specific error this
        #    finding exposed, so the two are asserted separately, here,
        #    against the same tamper.
        assert audit_log(memtara_server, desk) == chain_before, (
            "the audit trail is unchanged across the swap — linkage was never what broke, and "
            "the binding check is what closed the gap"
        )
        org_wide = binding_replay(memtara_server, desk, ref_id=request_id)
        assert org_wide["verdict"] == "ALTERED"
        assert _attestation_binding(org_wide)["result"] == "altered", (
            "and the org-level replay agrees with the per-record envelope — they are the same "
            "code path (`replay_scoped`), which is why they must never disagree"
        )

        # -----------------------------------------------------------------
        # 5. The escalation. The same UPDATE reaching the strongest claim in
        #    the schema: a signed assertion that no AI participated. It gets
        #    there by NULLING the model columns, so this re-checks that the
        #    binding covers absence and not only presence.
        # -----------------------------------------------------------------
        conn.run(
            "update decision_model_attestations set declaration = 'no_ai_participated', "
            "no_ai_attestation = :attestation, model_provider = null, model_name = null, "
            "model_version = null, prompt_version = null, model_environment = null, "
            "model_config_fingerprint = null, model_system_prompt_or_policy_id = null, "
            "model_timestamp = null where request_id = :rid",
            attestation="suitability produced by the deterministic rules engine; no model in the path",
            rid=str(request_id),
        )
        denied = _evidence(memtara_server, desk, request_id)
        assert denied.status_code == 200, denied.text
        denied_body = denied.json()

        assert _recorded_leaves(denied_body["decision_evidence"]) is None, (
            "the row still reaches model = null — nothing prevents the write"
        )
        assert denied_body["binding_integrity"]["verdict"] == "ALTERED", (
            "but the strongest assertion in the schema — that no AI system participated, reached "
            "here for a decision opened with a fully identified model — is now a claim the chain "
            "contradicts. Every key of the binding payload is present in both branches "
            "(binding.rs, 'WHY EVERY KEY IS ALWAYS PRESENT'), so nulling the model columns "
            "changes the hashed bytes rather than shrinking them"
        )
        escalated = _attestation_binding(denied_body["binding_integrity"])
        assert escalated["result"] == "altered"
        assert escalated["rebuilt_payload"]["declaration"] == "no_ai_participated"
        assert escalated["rebuilt_payload"]["model_name"] is None, (
            "the rebuilt payload is exported as it stands NOW, disagreement included — that is "
            "what lets a party holding it recompute the digest themselves instead of believing "
            "our verdict"
        )
        assert denied_body["decision_evidence"]["decision"]["status"] == "approved", (
            "and the rest of the record is untouched: the decision, the proof and the human "
            "review all still stand, so nothing about the surrounding evidence looks disturbed. "
            "The binding verdict is the only thing that gives it away"
        )
    finally:
        conn.close()
