"""Attack #11 — swap the model without recording it.

    ATTACK: an assessment is attested under model A. The recommendation the
    decision is actually built on is then produced under different
    circumstances — a different deployment, a different version, a different
    vendor entirely — and NOTHING recorded changes. The evidence should
    either refuse to finalise, or visibly flag that its model attestation may
    no longer describe the system that decided.

    This is NOT attack #4 restated. #4 rewrites a value that IS recorded.
    This one changes no recorded value at all: every field stays exactly as
    written, internally consistent, and wrong. A control that detected #4
    perfectly would not touch this — and `audit/binding.rs`, which closed #4,
    does not close this one. It proves a row is unchanged since it was
    written; it says nothing about whether the row was true when written.

    ---------------------------------------------------------------------
    THIS MODULE PREVIOUSLY REPORTED THIS ATTACK AS NOT STOPPED
    ---------------------------------------------------------------------
    The finding had three parts and all three are now answered, though not
    all of them fully — the residual is stated in `BREAK_IT_NOTE` and
    asserted at the end of this test rather than left to be discovered.

      WAS: `model.timestamp` is unvalidated — this test declared a model call
      three years before the assessment was opened and the server stored it
      verbatim and served it as `recorded`.
      NOW: refused, against a window anchored on the assessment's own open
      time (`wealth/model_intake.rs`). Asserted below with the exact payload
      that used to be accepted.

      WAS: no route, row or field could rebind a decision. The one-attestation
      primary key that makes #4's API surface safe was the same rule that made
      the honest correction impossible — an org that discovered a swap had
      nowhere to say so.
      NOW: `POST /api/v1/wealth-assessments/:id/model-corrections`
      (migrations/0009). Append-only, numbered densely from 1 so a deleted
      correction reads as a gap, each one separately bound to the audit chain.

      WAS: the record served a forward declaration with `state: "recorded"`,
      the same provenance a fact observed at decision time carries, and
      nothing said when the declaration was made.
      NOW: `model_provenance` (schema v1.2.0) carries `declared_at`, the
      original `as_declared_at_open` preserved verbatim, `corrected`,
      `correction_count`, `corrections[]`, and a statement telling the reader
      to compare `declared_at` against `decision.timestamps.assessed_at`.

    WHAT THIS TEST PROVES, against a real server, a real proof and a real
    Postgres:

      1. A complete, reviewed decision under model A, with the attestation
         still written BEFORE the decision exists — asserted from the rows,
         because that fact has not changed and must not be papered over. What
         changed is that the record now says so.
      2. The impossible model-call timestamp is refused, and a contemporaneous
         one is accepted, so the check discriminates rather than blocks.
      3. The honest correction now lands, and the record changes: `model`
         serves the corrected identity while `as_declared_at_open` still
         holds the original, verbatim.
      4. The correction is bound to the chain — an UPDATE to the correction
         row is reported ALTERED, and a DELETE is reported as a missing
         source row, which are different incidents and are reported in
         different words.
      5. The dishonest correction is refused: a correction may weaken or
         re-point an org's AI claim but may never strengthen it into
         `no_ai_participated`. A correction is filed after the verdict, after
         the review, possibly after a complaint — exactly when a firm most
         wants the flattering answer and has the weakest claim to it.
      6. The contrast that made this a design gap rather than an oversight is
         now closed on both sides. `products.terms_version` is bumped by a
         trigger, snapshotted at open and surfaced as
         `policy.thresholds.threshold_version`; the model block now has its
         own snapshot-and-supersede discipline in `model_provenance`.

    HONEST STATUS FOR THE BREAK-IT TABLE: STOPPED — against the defence this
    module's previous revision named, which was "a marker distinguishing a
    forward declaration from a fact observed at decision time". That marker
    exists and a reader cannot miss it.

    THE RESIDUAL, which is large and is the reason the note is worded the way
    it is: an organisation that swaps a model and SAYS NOTHING still produces
    a record in which nothing changed. Nothing internal can prevent that. The
    model identity is an assertion made by the calling system, there is no
    LLM gateway in this repository and the scope decision says there will not
    be one this quarter, so there is nothing to compare the assertion
    against. What this system can now do is make the honest correction
    possible, commit it, refuse an assertion that is impossible on its face,
    and tell every reader that the declaration predates the decision. It
    cannot establish which model ran. A test asserting otherwise would be
    asserting a capability the product does not have.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 11
BREAK_IT_ATTACK_TITLE = "Swap the model without recording it"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "the forward declaration is now visible as one: model_provenance carries when it was made, "
    "preserves it verbatim, and an impossible model-call timestamp is refused. An org that "
    "discovers a swap has an append-only correction path, each correction bound to the chain. "
    "Residual, and it is the large one: an org that swaps a model and says nothing still "
    "produces a record in which nothing changed — the model identity is the calling system's "
    "assertion and there is nothing in this repository to check it against"
)

import datetime as dt

import httpx
import wealth_client as wc

from conftest import binding_replay, db_connect

CORRECTION_BOUND = "decision_model_attestation_correction_bound"

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

# The model that actually served the recommendation after the swap.
MODEL_B = {
    "declaration": "model_identified",
    "provider": "a-different-vendor",
    "model_name": "a-different-model",
    "model_version": "2023.1",
    "environment": "production",
}

# Three years before any assessment this test opens. This exact payload was
# accepted, stored and served as `recorded` by the previous revision.
IMPOSSIBLE_TIMESTAMP = "2023-01-05T04:00:00Z"


def _model_a() -> dict:
    """Model A, declared as honestly as this API allows: every leaf supplied
    and a call timestamp genuinely contemporaneous with the assessment. The
    finding was never that a careless caller produces a weak record.
    """
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return dict(MODEL_A, timestamp=now.isoformat().replace("+00:00", "Z"))


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


def _correct(base_url, desk, request_id, body):
    return httpx.post(
        f"{base_url}/api/v1/wealth-assessments/{request_id}/model-corrections",
        json=body,
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _just_after(timestamp: str) -> str:
    """Two seconds after the assessment's own `assessed_at`, read from the
    record.

    Kept even though `review.rs` now carries a clock-skew allowance in both
    directions — Postgres stamps the verdict, the server process bounds the
    review, and here those two clocks live in different containers. Deriving
    the value from the record rather than from this machine is right
    regardless of how forgiving the server is.
    """
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z")


def test_a_model_swap_can_now_be_recorded_honestly_and_a_stale_declaration_is_visible_as_one(
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

    review = httpx.post(
        f"{memtara_server}/api/v1/wealth-assessments/{request_id}/review",
        json={
            "reviewer_id": "emp-4417",
            "reviewer_role": "senior_suitability_officer",
            "action": "approved",
            "human_review_protocol_version": "cob-review-2026.2",
            "reviewed_at": _just_after(assessed_at),
            "review_duration_ms": 214_000,
        },
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )
    assert review.status_code == 201, review.text

    original = _evidence(memtara_server, desk, request_id).json()["decision_evidence"]
    original_model = original["model"]
    assert original_model["provider"]["value"] == "anthropic"
    assert original["human_review"]["performed"] is True

    conn = db_connect()
    try:
        # -----------------------------------------------------------------
        # The fact that made this attack free is UNCHANGED, and is asserted
        # from the rows rather than from the source: the attestation is
        # written by issue-wealth-request, in the same transaction as the
        # assessment, before the device has proved anything. No control
        # could change that without moving the declaration to a point where
        # the calling system no longer has it. What changed is that the
        # record now discloses it.
        # -----------------------------------------------------------------
        ordering = conn.run(
            "select a.created_at < w.assessed_at, a.created_at, w.assessed_at "
            "from decision_model_attestations a join wealth_requests w on w.request_id = a.request_id "
            "where a.request_id = :rid",
            rid=str(request_id),
        )
        assert ordering and ordering[0][0] is True, (
            "the model attestation is still a declaration about a decision that has not happened "
            f"yet: attested {ordering[0][1] if ordering else '?'}, decided "
            f"{ordering[0][2] if ordering else '?'}"
        )

        provenance = original["model_provenance"]
        assert provenance["declared_at"]["state"] == "recorded", provenance["declared_at"]
        assert provenance["declared_at"]["value"] < assessed_at, (
            "and a reader can now make that comparison from the record alone, without a database "
            "and without being told the declaration is a forward one — which is precisely the "
            "defence the previous revision of this module named as absent"
        )
        assert provenance["corrected"] is False
        assert provenance["correction_count"] == 0
        assert provenance["corrections"] == []
        assert provenance["as_declared_at_open"]["identity"]["model_name"] == "claude-opus-4"

        # -----------------------------------------------------------------
        # 2. The impossible timestamp. This exact payload was accepted,
        #    stored verbatim and served as `recorded` before.
        # -----------------------------------------------------------------
        stale = _open(
            memtara_server, desk, ai_participation=dict(MODEL_B, timestamp=IMPOSSIBLE_TIMESTAMP)
        )
        assert stale.status_code == 400, (
            "a model call timestamped three years before the assessment it belongs to must be "
            f"refused; got {stale.status_code}: {stale.text}"
        )
        assert "timestamp" in stale.text.lower()

        # The check discriminates rather than blocks: the same declaration
        # with a contemporaneous timestamp is accepted. Without this the
        # assertion above would also pass on a server that refused every
        # timestamp, or every request.
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        fresh = _open(
            memtara_server,
            desk,
            ai_participation=dict(MODEL_B, timestamp=now.isoformat().replace("+00:00", "Z")),
        )
        assert fresh.status_code == 201, fresh.text

        # -----------------------------------------------------------------
        # 3. The honest correction — the thing an org discovering a swap
        #    previously had no route, row or field in which to say.
        # -----------------------------------------------------------------
        correction = _correct(
            memtara_server,
            desk,
            request_id,
            {
                "asserted_by": "emp-9002",
                "asserted_by_role": "head_of_model_risk",
                "correction_reason": (
                    "post-incident review established that the suitability gateway was serving "
                    "the fallback deployment during this window; the model named at open did not "
                    "produce the recommendation this decision was built on"
                ),
                "corrected_model": MODEL_B,
            },
        )
        assert correction.status_code == 201, correction.text
        correction_body = correction.json()
        assert correction_body["correction_no"] == 1
        correction_id = correction_body["correction_id"]

        corrected_record = _evidence(memtara_server, desk, request_id).json()["decision_evidence"]
        assert corrected_record["model"]["model_name"]["value"] == "a-different-model", (
            "the record must serve the identity the organisation now stands behind. Leaving "
            "`model` pinned to the retracted declaration with a footnote elsewhere would hand "
            "every reader — and every tool written against v1.1.0 — an identity its own owner "
            "has withdrawn"
        )
        corrected_provenance = corrected_record["model_provenance"]
        assert corrected_provenance["corrected"] is True
        assert corrected_provenance["correction_count"] == 1
        assert corrected_provenance["as_declared_at_open"]["identity"]["model_name"] == "claude-opus-4", (
            "and the original declaration is preserved verbatim. An organisation that declared "
            "model A and later corrected to model B has said two things, and an examiner is "
            "entitled to both — the first one is what it believed at the time it decided"
        )
        assert corrected_provenance["corrections"][0]["asserted_by"] == "emp-9002"

        # -----------------------------------------------------------------
        # 4. The correction is bound. Append-only is a property of the code
        #    that writes the table, and attack #4 is the demonstration that
        #    such a property is worth nothing to someone with a connection
        #    string.
        # -----------------------------------------------------------------
        before = binding_replay(memtara_server, desk, ref_id=correction_id)
        bound = [e for e in before["events"] if e["event_type"] == CORRECTION_BOUND]
        assert len(bound) == 1, bound
        assert bound[0]["result"] == "intact", bound[0]

        conn.run(
            "update decision_model_attestation_corrections set correction_reason = :reason "
            "where id = :cid",
            reason="a materially different account of why this correction was filed, written later",
            cid=str(correction_id),
        )
        after_edit = binding_replay(memtara_server, desk, ref_id=correction_id)
        edited = [e for e in after_edit["events"] if e["event_type"] == CORRECTION_BOUND][0]
        assert edited["result"] == "altered", (
            "rewriting a correction's stated reason must be detectable — the reason is the whole "
            "substance of a correction, and one that can be rewritten later is a retraction with "
            "an editable motive"
        )

        conn.run(
            "delete from decision_model_attestation_corrections where id = :cid", cid=str(correction_id)
        )
        after_delete = binding_replay(memtara_server, desk, ref_id=correction_id)
        deleted = [e for e in after_delete["events"] if e["event_type"] == CORRECTION_BOUND][0]
        assert deleted["result"] == "source_row_missing", (
            "and removing it entirely is a DIFFERENT incident from editing it — a deleted "
            "correction returns the record to serving an identity its owner withdrew, and an "
            "operator told only 'altered' would go looking for the wrong thing"
        )

        # -----------------------------------------------------------------
        # 5. The dishonest correction. A correction is filed after the
        #    verdict, after the review, possibly after a complaint.
        # -----------------------------------------------------------------
        flattering = _correct(
            memtara_server,
            desk,
            request_id,
            {
                "asserted_by": "emp-9002",
                "asserted_by_role": "head_of_model_risk",
                "correction_reason": (
                    "on further review we consider that the deterministic rules engine produced "
                    "this recommendation and no model was in the path at all"
                ),
                "corrected_model": {
                    "declaration": "no_ai_participated",
                    "attestation": "produced by the deterministic rules engine, no model in the path",
                },
            },
        )
        assert flattering.status_code == 400, (
            "a correction may weaken or re-point an AI claim and must never strengthen it into "
            f"the signed assertion that no AI participated; got {flattering.status_code}: "
            f"{flattering.text}"
        )

        # -----------------------------------------------------------------
        # 6. The contrast, now closed on both sides.
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
        assert later.json()["threshold_version"] == 2
    finally:
        conn.close()

    # -----------------------------------------------------------------
    # THE RESIDUAL. Asserted, not merely described: an org that swaps a
    # model and says nothing produces a record in which nothing changed,
    # and no assertion in this file should be read as claiming otherwise.
    # -----------------------------------------------------------------
    silent = _open(memtara_server, desk, ai_participation=_model_a())
    assert silent.status_code == 201, silent.text
    silent_id = silent.json()["request_id"]
    silent_proof = wc.generate_proof(silent.json(), desk.vault, oracle=desk.oracle)
    wc.submit_assessment(memtara_server, desk.session_token, silent_id, silent_proof)

    silent_record = _evidence(memtara_server, desk, silent_id).json()
    assert silent_record["binding_integrity"]["verdict"] == "INTACT", (
        "a decision whose declared model was quietly not the one that ran is byte-identical to "
        "one that was — the binding proves the row is unchanged since it was written, never that "
        "it was true when written"
    )
    assert silent_record["decision_evidence"]["model_provenance"]["corrected"] is False, (
        "and silence still reads as 'not corrected', because it is. What the record can tell an "
        "examiner is that this identity was declared before the decision existed and has not "
        "been reconfirmed since; establishing which model actually ran requires evidence from "
        "the calling system, which this repository does not have and does not pretend to"
    )
