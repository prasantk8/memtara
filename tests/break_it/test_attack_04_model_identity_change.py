"""Attack #4 — change the model identity an assessment was recorded against.

    ATTACK: an AI-mediated recommendation is made by model A, and model A is
    properly declared and recorded. Later — before an export, after a
    complaint, the morning a model is found to have been misbehaving — the
    recorded identity is changed to model B. The evidence should not silently
    serve whichever identity was written last.

    This is the companion to attack #11 and NOT the same attack. #4 attacks a
    value that IS recorded. #11 attacks the absence of a rebind. Both are now
    runnable: the capture path landed in
    `backend/api/migrations/0006_decision_capture.sql` and
    `backend/api/src/wealth/model_intake.rs`.

    WHERE THE VALUE LIVES, checked rather than assumed. The eight model
    leaves exist in exactly one place: the columns of
    `decision_model_attestations`. `audit_log` stores an event's HASH and no
    payload column at all (verified live below), and the one event that
    mentions AI participation — `wealth_suitability_requested` — hashes only
    the *declaration* (`ai_participation_declared` in
    `backend/api/src/wealth/mod.rs`), never the provider, the model name, the
    version or the config fingerprint. So the chain that catches tampering
    everywhere else in this system commits to the fact that a model was
    named; it does not commit to WHICH.

    WHAT THIS TEST PROVES:

      1. The whole HTTP surface refuses to restate a model identity. A second
         attestation for the same decision is refused by the primary key; the
         review endpoint — the only write that happens after a decision — is
         `deny_unknown_fields` and rejects a smuggled `model_name` outright;
         there is no PATCH, no PUT and no per-decision model route to reach.
         Re-opening the assessment produces a DIFFERENT decision and leaves
         the original untouched. This half is a genuine, verified defence.
      2. One `update decision_model_attestations set ...` — the attacker with
         a database connection, which is the only actor who can do this at
         all — rewrites the sealed record's model block. The endpoint returns
         200 and serves `openai` / `gpt-4o-mini` with `state: "recorded"`,
         byte-identical in shape to the truth it replaced.
      3. The org's hash-chained audit log is UNCHANGED and unbroken across
         the swap: same entries, same `event_hash`, same `prev_hash`. This is
         not a chain that failed to notice; there is nothing for it to
         notice, because no model value was ever in a hashed payload.
      4. The escalation, which is the one to show a buyer: the same single
         UPDATE can move the row to `declaration = 'no_ai_participated'`.
         The record then serves `model: null` — which
         `schema/decision_evidence/v1.1.0.json` and
         `wealth/model_intake.rs` both define as a SIGNED ASSERTION that no
         AI system participated, not as "we did not record it". Every
         defence in `model_intake` exists to stop that assertion being
         reached by accident through the API. None of it applies to an
         UPDATE.

    HONEST STATUS FOR THE BREAK-IT TABLE: NOT STOPPED — declared in
    `BREAK_IT_STATUS_ON_PASS`, because this module PASSES by demonstrating
    that the attack SUCCEEDS. The defence would be any one of: refusing to
    serve a record whose attestation changed after the decision, continuing
    to serve the original identity, or surfacing the mismatch in the record.
    None of them exist, so the assertions below assert what actually
    happens. If a future change adds any of those three, this module will
    FAIL rather than quietly keep reporting the finding — at which point the
    row is wrong and owes a rewrite, which is the intended and only safe
    failure mode for a test written this way.

    WHAT THIS TEST DOES NOT PROVE: it does not claim the API is unguarded —
    point 1 above verifies the opposite, and the intake contract in
    `model_intake.rs` is genuinely careful about which declarations are
    reachable. The finding is narrower and worse: the values it so carefully
    validates are then stored somewhere nothing commits to. It also does not
    prove the fix. A digest of the attestation inside the
    `wealth_suitability_requested` payload, or a seal over the record at
    decision time, would each make this attack detectable; choosing between
    them is a design decision, not a test's to make.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 4
BREAK_IT_ATTACK_TITLE = "Change the model identity"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "NOT STOPPED"
BREAK_IT_NOTE = (
    "the API refuses every restatement of a recorded model identity, but the eight model leaves "
    "are committed nowhere — no audit payload carries them — so one UPDATE swaps the identity "
    "the sealed record serves, and can move it to the signed 'no AI participated' assertion, "
    "with the hash chain unchanged and unbroken"
)

import datetime as dt

import httpx
import wealth_client as wc

from conftest import audit_log, db_connect

MODEL_A = {
    "declaration": "model_identified",
    "provider": "anthropic",
    "model_name": "claude-opus-4",
    "model_version": "20260514",
    "prompt_version": "suitability-v7",
    "environment": "production",
    "config_fingerprint": "ab" * 32,
    "system_prompt_or_policy_id": "policy/suitability/7",
    "timestamp": "2026-08-19T09:00:00Z",
}

MODEL_B = {
    "declaration": "model_identified",
    "provider": "a-different-vendor",
    "model_name": "a-different-model",
}


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


def _just_after(timestamp: str) -> str:
    """Two seconds after the assessment's own `assessed_at` — read from the
    record, not from this machine's clock, because Postgres's `now()` (which
    stamps the verdict) and the server process's clock (which bounds the
    review) run in different containers here and are observably tens of
    milliseconds apart.
    """
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z")


def test_a_recorded_model_identity_is_rewritten_underneath_a_completed_decision_and_nothing_notices(
    memtara_server, make_desk
):
    desk = make_desk(memtara_server, isin="XS0000000104")

    # A complete, fully identified, review-bearing decision. Nothing about
    # this assessment is degraded: all eight model leaves are supplied, the
    # proof is real, the human review is real.
    request = _open(memtara_server, desk, ai_participation=MODEL_A)
    assert request["ai_participation_recorded"] == "model_identified"
    request_id = request["request_id"]

    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert wc.submit_assessment(memtara_server, desk.session_token, request_id, proof)["suitable"] is True

    original = _evidence(memtara_server, desk, request_id)
    assert original.status_code == 200, original.text
    original_record = original.json()["decision_evidence"]
    assert _recorded_leaves(original_record)["provider"] == "anthropic"
    assert _recorded_leaves(original_record)["model_name"] == "claude-opus-4"

    reviewed_at = _just_after(original_record["decision"]["timestamps"]["assessed_at"])

    # -----------------------------------------------------------------
    # 1. Every HTTP path that might accept a second or altered attestation.
    #    All four are refused — this half is a real defence and is asserted
    #    as one.
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
    # rebind of this one — and leaves this one alone.
    rebranded = _open(memtara_server, desk, ai_participation=MODEL_B)
    assert rebranded["request_id"] != request_id
    assert _recorded_leaves(_evidence(memtara_server, desk, request_id).json()["decision_evidence"]) == \
        _recorded_leaves(original_record)

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

        # The audit log has no payload column at all: the chain stores a
        # digest of each event and nothing else. Verified live, because the
        # whole finding below rests on it.
        payload_columns = conn.run(
            "select column_name from information_schema.columns "
            "where table_name = 'audit_log' and column_name = 'payload'"
        )
        assert payload_columns == [], (
            "audit_log stores event hashes, not payloads — if that has changed, re-examine "
            "whether the model identity is now recoverable from the chain"
        )

        chain_before = audit_log(memtara_server, desk)

        # -----------------------------------------------------------------
        # 2. THE ATTACK. One UPDATE, by the only actor who can make it: an
        #    attacker, insider or operator holding a database connection.
        # -----------------------------------------------------------------
        conn.run(
            "update decision_model_attestations set model_provider = 'openai', "
            "model_name = 'gpt-4o-mini', model_version = '2024-07-18', "
            "model_config_fingerprint = :fingerprint where request_id = :rid",
            fingerprint="99" * 32,
            rid=str(request_id),
        )

        # THE FINDING. Each assertion below states what the system actually
        # does. Any of them failing would mean a defence has appeared and
        # this row is out of date — see the docstring.
        swapped = _evidence(memtara_server, desk, request_id)
        assert swapped.status_code == 200, (
            "the record is served without complaint after its model identity was rewritten; "
            f"a refusal here would be a defence, and would mean this finding is stale: {swapped.text}"
        )
        swapped_record = swapped.json()["decision_evidence"]
        swapped_leaves = _recorded_leaves(swapped_record)
        assert swapped_leaves["provider"] == "openai"
        assert swapped_leaves["model_name"] == "gpt-4o-mini", (
            "the evidence serves the identity that was written last, as fact"
        )
        assert "claude-opus-4" not in swapped.text, (
            "and nothing in the served record names, or even hints at, the identity it replaced — "
            "there is no mismatch for a reader to surface"
        )

        # 3. The chain is untouched and intact. It has nothing to say about
        #    this, because no model value was ever inside a hashed payload.
        assert audit_log(memtara_server, desk) == chain_before, (
            "the audit trail is byte-identical across the swap — this attack leaves the mechanism "
            "that catches tampering everywhere else in this system with nothing to detect"
        )
        assert swapped_record["model"] is not None
        assert all(field["state"] == "recorded" for field in swapped_record["model"].values()), (
            "and the rewritten identity is served with exactly the provenance the true one had: "
            "there is no 'recorded, but possibly altered' state for a reader to notice"
        )

        # -----------------------------------------------------------------
        # 4. The escalation. The same UPDATE can reach the strongest claim
        #    in the schema: a signed assertion that no AI participated.
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
        ai_free_record = denied.json()["decision_evidence"]
        assert _recorded_leaves(ai_free_record) is None, (
            "the escalation lands: the record now serves model = null, which "
            "schema/decision_evidence/v1.1.0.json and wealth/model_intake.rs both define as a "
            "SIGNED ASSERTION that no AI system participated — reached here for a decision that "
            "was opened with a fully identified model, by one UPDATE, with every route that could "
            "make the same claim through the API verified refused above"
        )
        assert ai_free_record["decision"]["status"] == "approved", (
            "and the rest of the record is untouched: the decision, the proof and the human "
            "review all still stand, so nothing about the surrounding evidence looks disturbed"
        )
    finally:
        conn.close()
