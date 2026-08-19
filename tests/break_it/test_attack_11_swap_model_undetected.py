"""Attack #11 — swap the model without recording it.

    ATTACK: an assessment is attested under model A. The recommendation the
    decision is actually built on is then produced under different
    circumstances — a different deployment, a different version, a different
    vendor entirely — and NOTHING recorded changes. The evidence should
    either refuse to finalise, or visibly flag that its model attestation may
    no longer describe the system that decided.

    This is NOT attack #4 restated. #4 rewrites a value that is recorded, and
    is stopped or not stopped by whether anything commits to that value.
    This one changes no recorded value at all: every field in the record
    stays exactly as written, internally consistent, and wrong. A control
    that detected #4 perfectly would not touch this.

    WHY THE ATTACK IS FREE. `decision_model_attestations` is written once, in
    the same transaction as the assessment, by
    `POST /api/v1/issue-wealth-request` — that is, BEFORE the client's device
    has proved anything, before the verdict exists, and before any human has
    reviewed it. The attestation is therefore a FORWARD DECLARATION about a
    decision that has not happened yet, and the record presents it with
    `state: "recorded"`, which is the same provenance a fact observed at
    decision time would carry. Nothing reconfirms it afterwards, and nothing
    can: `request_id` is the primary key of that table, there is no PATCH,
    no PUT and no per-decision model route, and the review endpoint — the
    only write that happens after a decision — is `deny_unknown_fields`.
    The rule that makes attack #4's API surface safe is the same rule that
    makes this one unfixable from inside the product: an org that discovers
    mid-flight that a different model served the request has no way to say
    so, and the system will keep serving the first declaration.

    The one field that could expose a stale attestation is
    `model.timestamp`, and it is unvalidated: this test declares a model
    timestamp three years before the assessment was even opened and the
    server accepts it, stores it verbatim, and serves it as `recorded`.

    WHAT THIS TEST PROVES, against a real server, a real proof and a real
    Postgres:

      1. A complete, reviewed decision carries model A with every leaf
         `state: "recorded"`.
      2. The attestation was written BEFORE the decision it describes —
         asserted from the rows themselves
         (`decision_model_attestations.created_at < wealth_requests.
         assessed_at`), not from reading the source.
      3. The swap then really happens: the same client, the same product,
         the same desk, declaring a different provider and model — accepted,
         `model_identified`, with a model call timestamp three years before
         the request, which nothing objects to.
      4. There is no route, no row and no field through which the first
         decision can be rebound: PATCH/PUT/POST all 404 or 405, a second
         attestation is refused by the primary key, and the review endpoint
         rejects a model field outright. The honest correction is as
         impossible as the dishonest one.
      5. The first decision's record is byte-for-byte unchanged in its model
         block and flags nothing.
      6. CONTRAST, and the reason this is a design gap rather than an
         oversight: this system already knows how to do exactly what is
         missing. `products.terms_version` is bumped by a database trigger
         whenever the compared thresholds change, snapshotted onto each
         assessment at open, and surfaced in the record as
         `policy.thresholds.threshold_version` — so an examiner can see that
         a later decision ran under version 2 while this one is pinned to
         version 1. The model block has no version, no snapshot discipline
         and no rebind.

    HONEST STATUS FOR THE BREAK-IT TABLE: NOT STOPPED — declared in
    `BREAK_IT_STATUS_ON_PASS`, because this module PASSES by demonstrating
    that the attack SUCCEEDS. Nothing today would notice. The defence would
    be either a refusal to finalise a record whose attestation was never
    reconfirmed after the decision, or a marker distinguishing a forward
    declaration from a fact observed at decision time; neither exists, so
    the assertions below assert what actually happens. If either appears,
    this module FAILS rather than quietly keeping the finding alive, and the
    row owes a rewrite. A green row here would be worse than a red one: this
    is a genuine gap in a control that is about to be sold.

    WHAT THIS TEST DOES NOT PROVE: it does not show a model being swapped
    inside an LLM gateway, because there is no gateway in this repository and
    the scope decision says there will not be one this quarter — the model
    identity is an assertion made by the calling system, and this test
    attacks it exactly where it lives. It also does not claim the intake
    contract in `wealth/model_intake.rs` is careless: that file is rigorous
    about which declarations are reachable and never lets silence become the
    flattering answer. The gap is downstream of it — a declaration made
    before the fact is never checked against the fact.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 11
BREAK_IT_ATTACK_TITLE = "Swap the model without recording it"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "NOT STOPPED"
BREAK_IT_NOTE = (
    "the model attestation is a forward declaration written before the decision exists and never "
    "reconfirmed; no route, row or field can rebind it, model.timestamp is unvalidated, and the "
    "record serves the pre-decision declaration as state=recorded — nothing would notice a swap"
)

import datetime as dt

import httpx
import wealth_client as wc

from conftest import db_connect

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


def _model_a() -> dict:
    """Model A, declared as honestly as this API allows: all eight leaves
    supplied, and a call timestamp that is genuinely contemporaneous with the
    assessment. Nothing about this attestation is degraded — the finding is
    not that a careless caller produces a weak record.
    """
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return dict(MODEL_A, timestamp=now.isoformat().replace("+00:00", "Z"))

# The model that actually served the recommendation after the swap —
# different vendor, different model, and a call timestamp three years before
# the assessment it claims to describe.
MODEL_B = {
    "declaration": "model_identified",
    "provider": "a-different-vendor",
    "model_name": "a-different-model",
    "model_version": "2023.1",
    "environment": "production",
    "timestamp": "2023-01-05T04:00:00Z",
}


def _open(base_url, desk, *, ai_participation=None):
    body = {"user_id": desk.user_id, "product_isin": desk.product_isin, "ttl_seconds": 900}
    if ai_participation is not None:
        body["ai_participation"] = ai_participation
    return httpx.post(
        f"{base_url}/api/v1/issue-wealth-request",
        json=body,
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _evidence(base_url, desk, request_id):
    return httpx.get(
        f"{base_url}/api/v1/wealth-assessments/{request_id}/decision-evidence",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _just_after(timestamp: str) -> str:
    """Two seconds after the assessment's own `assessed_at`, read from the
    record — Postgres stamps the verdict and the server process bounds the
    review, and here those two clocks live in different containers and are
    observably tens of milliseconds apart.
    """
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z")


def test_a_model_swapped_after_the_attestation_leaves_no_trace_and_cannot_even_be_recorded_honestly(
    memtara_server, make_desk
):
    desk = make_desk(memtara_server, isin="XS0000000111")

    # -----------------------------------------------------------------
    # 1. A complete decision, honestly attested under model A.
    # -----------------------------------------------------------------
    opened = _open(memtara_server, desk, ai_participation=_model_a())
    assert opened.status_code == 201, opened.text
    request = opened.json()
    assert request["ai_participation_recorded"] == "model_identified"
    request_id = request["request_id"]

    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert wc.submit_assessment(memtara_server, desk.session_token, request_id, proof)["suitable"] is True

    assessed = _evidence(memtara_server, desk, request_id)
    assert assessed.status_code == 200, assessed.text
    assessed_at = assessed.json()["decision_evidence"]["decision"]["timestamps"]["assessed_at"]
    reviewed_at = _just_after(assessed_at)

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

    original = _evidence(memtara_server, desk, request_id)
    assert original.status_code == 200, original.text
    original_record = original.json()["decision_evidence"]
    original_model = original_record["model"]
    assert original_model["provider"]["value"] == "anthropic"
    assert all(field["state"] == "recorded" for field in original_model.values())
    assert original_record["human_review"]["performed"] is True

    conn = db_connect()
    try:
        # -----------------------------------------------------------------
        # 2. The attestation predates the decision it describes. Read from
        #    the rows, so this is a fact about the running system and not a
        #    claim about the source.
        # -----------------------------------------------------------------
        ordering = conn.run(
            "select a.created_at < w.assessed_at, a.created_at, w.assessed_at "
            "from decision_model_attestations a join wealth_requests w on w.request_id = a.request_id "
            "where a.request_id = :rid",
            rid=str(request_id),
        )
        assert ordering and ordering[0][0] is True, (
            "the model attestation is written by issue-wealth-request, in the same transaction as "
            "the assessment — so it is a declaration about a decision that has not happened yet: "
            f"attested {ordering[0][1] if ordering else '?'}, decided {ordering[0][2] if ordering else '?'}"
        )

        # -----------------------------------------------------------------
        # 3. The swap. Same client, same product, same desk — a different
        #    model, declared with a call timestamp three years before the
        #    request it belongs to. Nothing objects to either.
        # -----------------------------------------------------------------
        after_swap = _open(memtara_server, desk, ai_participation=MODEL_B)
        assert after_swap.status_code == 201, after_swap.text
        swapped_request_id = after_swap.json()["request_id"]
        assert after_swap.json()["ai_participation_recorded"] == "model_identified"
        stored = conn.run(
            "select model_provider, model_name, model_timestamp from decision_model_attestations "
            "where request_id = :rid",
            rid=str(swapped_request_id),
        )
        assert stored[0][0] == "a-different-vendor"
        assert stored[0][2].year == 2023, (
            "a model call timestamped three years before the assessment was opened is stored "
            "verbatim: the one leaf that could date a model call against its decision is "
            f"unvalidated, got {stored[0][2]}"
        )

        # -----------------------------------------------------------------
        # 4. Nothing can rebind the first decision — including its owner,
        #    acting honestly.
        # -----------------------------------------------------------------
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
            assert attempt.status_code in (404, 405), f"{method} {path} answered {attempt.status_code}"

        corrected = httpx.post(
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
        assert corrected.status_code == 422 and "unknown field `model_name`" in corrected.text

        try:
            conn.run(
                "insert into decision_model_attestations (request_id, org_id, declaration, "
                "model_provider, model_name) values (:rid, :org, 'model_identified', :provider, :name)",
                rid=str(request_id),
                org=str(desk.org_id),
                provider=MODEL_B["provider"],
                name=MODEL_B["model_name"],
            )
            raise AssertionError("a decision must carry exactly one model attestation")
        except Exception as exc:
            detail = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
            assert detail.get("n") == "decision_model_attestations_pkey", (
                "the one-attestation rule is what keeps attack #4's API surface safe, and it is "
                f"the same rule that makes an honest correction impossible: {detail}"
            )

        # -----------------------------------------------------------------
        # 6. The contrast. Thresholds move the same way a model does, and
        #    this system versions, snapshots and surfaces those.
        # -----------------------------------------------------------------
        amended = httpx.patch(
            f"{memtara_server}/api/v1/products/{desk.product_isin}",
            json={"min_income": 400_000},
            headers={"Authorization": f"Bearer {desk.api_key}"},
            timeout=30.0,
        )
        assert amended.status_code == 200, amended.text
        later = _open(memtara_server, desk)
        assert later.status_code == 201, later.text
        assert later.json()["threshold_version"] == 2, (
            "the trigger in migrations/0007 bumps products.terms_version when the compared "
            "thresholds change; a later assessment is measured under version 2"
        )
    finally:
        conn.close()

    # -----------------------------------------------------------------
    # 5. And the first decision's record, after all of it. THE FINDING:
    #    each assertion states what the system actually does, and any of
    #    them failing means a defence has appeared and this row is stale.
    # -----------------------------------------------------------------
    final = _evidence(memtara_server, desk, request_id)
    assert final.status_code == 200, (
        "the record finalises and is served as complete, with an attestation that was made before "
        f"the decision existed and never reconfirmed: {final.text}"
    )
    final_record = final.json()["decision_evidence"]
    assert final_record["model"] == original_model, (
        "the model block is byte-for-byte what was declared at open time — the swap changed no "
        "recorded field, which is exactly what makes this distinct from attack #4"
    )
    assert all(field["state"] == "recorded" for field in final_record["model"].values()), (
        "and every leaf carries the same provenance a fact observed at decision time would carry. "
        "There is no state that distinguishes a forward declaration from a confirmed one, so a "
        "reader cannot tell a stale attestation from a contemporaneous one"
    )
    assert not any(
        marker in final.text
        for marker in ("reconfirm", "attested_at", "declared_at", "declared_before")
    ), "nothing in the record says when the attestation was made or whether it was ever rechecked"

    # The contrast, in the same record: thresholds drift too, and this system
    # versions, snapshots and surfaces that drift. The model block has no
    # equivalent, which is what turns this from an oversight into a gap with
    # a known shape.
    assert final_record["policy"]["thresholds"]["threshold_version"]["value"] == "1", (
        "the thresholds this decision was measured against are pinned to the version that was "
        "live when it opened, and the record says which — that is the discipline the model block "
        "does not have"
    )
