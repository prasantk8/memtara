"""Attack #8 — revoke consent.

    ATTACK: a customer revokes consent for their data to be used after a
    decision was already opened under it. Anything opened AFTER the
    revocation should be refused; anything opened BEFORE it should stand —
    the record answers "was consent live when this was decided", not "is it
    live now".

    ---------------------------------------------------------------------
    THIS MODULE PREVIOUSLY REPORTED THIS ATTACK AS BLOCKED
    ---------------------------------------------------------------------
    It was, more fundamentally than attacks #4/#10/#11: those three were
    missing a RECORD (model identity, a per-decision human review). This one
    was missing the CONCEPT — there was no representation of consent
    anywhere in the backend to revoke. `vault::session::SessionPolicy.
    purpose_hash` was the nearest relative, and it is a fixed hash of a
    hardcoded purpose string bound once at session-creation time: a purpose
    BINDING, not a consent RECORD, with no id, no grant time, no scope and no
    revocation path.

    `migrations/0011_consent_grants.sql`, `backend/api/src/consents/` and the
    enforcement wired into `wealth::issue_wealth_request` close that gap.
    This file is the tripwire's own instruction, followed: the concept now
    exists, so the BLOCKED skip is retired and the real attack is run.

    ---------------------------------------------------------------------
    THE NUANCE THAT MAKES THE MIDDLE OF THIS TEST WORTH READING
    ---------------------------------------------------------------------
    `audit/binding.rs` binds a consent grant with ONE payload function
    (`consent_grant_payload`) shared by TWO event types — `consent_grant_
    bound`, written at grant time, and `consent_revocation_bound`, written
    at revoke time — because migrations/0011 makes revocation an UPDATE to
    the SAME row rather than a second table (a grant that is contradicted,
    not replaced). The consequence, which this test asserts rather than
    glosses over: after an ORDINARY, LEGITIMATE revocation, replaying the
    ORIGINAL `consent_grant_bound` event reports ALTERED — not because
    anyone attacked it, but because the row it commits to has, correctly,
    moved on (`revoked_at` is no longer the null it was hashed against).
    That is by design, not the finding. The signal a reader actually wants
    is `consent_revocation_bound`, whose own recorded hash was computed
    against the POST-revocation row and therefore stays INTACT until
    something ELSE changes the row again — which is exactly what step 3
    below does, and exactly what flips `consent_revocation_bound` from
    INTACT to ALTERED alongside the (already-altered, already-explained)
    grant event. An examiner who reads both events together, and reads
    their `detail` strings, can tell "this grant was revoked" apart from
    "and then someone edited it after that" — which is the whole point of
    having two event types share one payload function instead of one.

    WHAT A LOUD SKIP WOULD MEAN HERE, CONCRETELY: this module used to fail
    outright if the consent concept ever appeared, so that nobody could
    mistake a stale green skip for "consent revocation was verified". It has
    appeared, this file is the verification, and the retired tripwire's own
    grep is kept below as a sanity check that the module it is testing is
    the one that landed.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 8
BREAK_IT_ATTACK_TITLE = "Revoke consent"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "detected, not prevented, exactly like attack 4: a direct SQL UPDATE against consent_grants "
    "still lands, but consent_revocation_bound's rebuild disagrees with it on every read. "
    "Residual worth stating plainly: after ANY legitimate revocation, consent_grant_bound alone "
    "(not consent_revocation_bound) reads ALTERED against an untouched row, because the row it "
    "commits to genuinely changed — a reader who only checks one of the two consent binding "
    "events per grant, or who does not read the detail text, cannot tell a routine revocation "
    "from a tamper by that event's verdict word alone"
)

import httpx
import pytest
import wealth_client as wc

from conftest import audit_log, binding_replay, db_connect, grep_backend

BUSINESS_PROCESS = "wealth.suitability_recommendation"
CONSENT_GRANT_BOUND = "consent_grant_bound"
CONSENT_REVOCATION_BOUND = "consent_revocation_bound"


def _grant_consent(base_url: str, desk, *, scope: list[str], granted_via: str = "assisted_kiosk") -> dict:
    response = httpx.post(
        f"{base_url}/api/v1/consents",
        json={
            "user_id": desk.user_id,
            "scope": scope,
            "consent_version": "consent-policy-2026.3",
            "granted_via": granted_via,
        },
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=30.0,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _revoke_consent(base_url: str, desk, consent_id: str, *, reason: str) -> httpx.Response:
    return httpx.post(
        f"{base_url}/api/v1/consents/{consent_id}/revoke",
        json={"revocation_reason": reason},
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=30.0,
    )


def _evidence(base_url: str, desk, request_id: str) -> httpx.Response:
    return httpx.get(
        f"{base_url}/api/v1/wealth-assessments/{request_id}/decision-evidence",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=30.0,
    )


def _consent_events(binding_integrity: dict, consent_id: str) -> dict[str, dict]:
    """This grant's binding events, by type. Asserts there is at most one of
    each — the primary key on `consent_grants` plus one grant/one revoke
    means there can never be two `consent_grant_bound` events for one id.
    """
    events = [e for e in binding_integrity["events"] if e["ref_id"] == consent_id]
    by_type: dict[str, dict] = {}
    for e in events:
        assert e["event_type"] not in by_type, f"duplicate {e['event_type']} for {consent_id}"
        by_type[e["event_type"]] = e
    return by_type


# ---------------------------------------------------------------------
# Trap 1 (non-negotiable): French and Arabic are the target market, not an
# edge case. Both `scope` and `revocation_reason` are parametrised across
# English/French/Arabic — the two free-text-adjacent fields this stage adds
# — and run through the REAL server, not a unit test's canonicaliser call.
# ---------------------------------------------------------------------
LANGUAGE_CASES = [
    pytest.param(
        "wealth.suitability_recommendation.pilot_note",
        "the customer withdrew consent at the branch counter, citing a change of advisor",
        id="english",
    ),
    pytest.param(
        "évaluation.pertinence_patrimoniale",
        "le client a retiré son consentement lors du rendez-vous en agence",
        id="french",
    ),
    pytest.param(
        "تقييم_الملاءمة_المالية",
        "سحب العميل موافقته أثناء زيارته لمكتب البنك",
        id="arabic",
    ),
]


@pytest.mark.parametrize("extra_scope,revocation_reason", LANGUAGE_CASES)
def test_revoking_consent_refuses_the_next_decision_and_the_prior_one_stands(
    memtara_server, make_desk, extra_scope, revocation_reason
):
    # `grant_consent=False`: this test controls its desk's consent
    # lifecycle itself — see conftest.py's `make_desk` for why the default
    # auto-granted consent would otherwise mask the very revocation this
    # test exists to demonstrate.
    desk = make_desk(memtara_server, isin="XS0000000108", grant_consent=False)

    # -----------------------------------------------------------------
    # Confirm the retired tripwire's own claim about the pre-image, so this
    # test does not silently start proving something about a different
    # codebase than the one the header describes: the capability it is
    # about to attack really is the one `migrations/0011`/`consents::` add.
    # -----------------------------------------------------------------
    assert grep_backend([r"struct\s+Consent\b", r"consent_grant_bound"]), (
        "expected the consent concept (evidence::Consent, audit::binding::EVENT_CONSENT_GRANT_BOUND) "
        "to exist in backend/api/src/ — if this no longer matches, this test is exercising the "
        "wrong codebase"
    )

    # -----------------------------------------------------------------
    # 1. Grant -> open decision -> 201. No false positive, asserted before
    #    any tampering: replay verdict INTACT.
    # -----------------------------------------------------------------
    grant = _grant_consent(memtara_server, desk, scope=[BUSINESS_PROCESS, extra_scope])
    consent_id = grant["id"]
    assert grant["scope"] == [BUSINESS_PROCESS, extra_scope]
    assert grant["revoked_at"] is None

    request = wc.open_assessment(
        memtara_server, desk.api_key, user_id=desk.user_id, product_isin=desk.product_isin
    )
    request_id = request["request_id"]
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assessed = wc.submit_assessment(memtara_server, desk.session_token, request_id, proof)
    assert assessed["suitable"] is True

    original = _evidence(memtara_server, desk, request_id)
    assert original.status_code == 200, original.text
    original_body = original.json()
    assert original_body["binding_integrity"]["verdict"] == "INTACT", original_body["binding_integrity"]

    original_consent = original_body["decision_evidence"]["data"]["consent"]
    assert original_consent["consent_id"]["value"] == consent_id
    assert original_consent["scope"]["value"] == [BUSINESS_PROCESS, extra_scope]
    assert original_consent["consent_version"]["value"] == "consent-policy-2026.3"

    before_events = _consent_events(original_body["binding_integrity"], consent_id)
    assert before_events[CONSENT_GRANT_BOUND]["result"] == "intact"
    assert CONSENT_REVOCATION_BOUND not in before_events, "nothing has been revoked yet"

    # -----------------------------------------------------------------
    # 2. Revoke -> next issue-wealth-request -> 403 naming the revoked
    #    grant. Revoking twice is a 409, not a silent success.
    # -----------------------------------------------------------------
    revoke = _revoke_consent(memtara_server, desk, consent_id, reason=revocation_reason)
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["revocation_reason"] == revocation_reason
    assert revoke.json()["revoked_at"] is not None

    twice = _revoke_consent(memtara_server, desk, consent_id, reason="a second, unrelated reason entirely")
    assert twice.status_code == 409, twice.text

    with pytest.raises(wc.MemtaraApiError) as exc_info:
        wc.open_assessment(memtara_server, desk.api_key, user_id=desk.user_id, product_isin=desk.product_isin)
    assert exc_info.value.status == 403, exc_info.value
    assert consent_id in exc_info.value.body, (
        f"a 403 for a revoked grant must name the grant it refused against, not just say "
        f"'forbidden': {exc_info.value.body}"
    )

    # -----------------------------------------------------------------
    # 5 (checked here, not after the destructive steps below, because this
    # is the only point at which the claim is checkable): the pre-revocation
    # decision's record still stands and still says consent was live at
    # open. The revocation above is real and already recorded — and this
    # decision's evidence has not moved: same consent_id, same scope, same
    # decision status. Revoking consent refuses the NEXT decision; it does
    # not retroactively unmake this one.
    # -----------------------------------------------------------------
    after_revoke = _evidence(memtara_server, desk, request_id)
    assert after_revoke.status_code == 200, after_revoke.text
    after_revoke_body = after_revoke.json()
    still_consent = after_revoke_body["decision_evidence"]["data"]["consent"]
    assert still_consent == original_consent, (
        "a decision's served consent block must not change shape or value just because the "
        "grant it cites was later revoked — the record answers 'was consent live at open', and "
        "that answer does not move"
    )
    assert after_revoke_body["decision_evidence"]["decision"]["status"] == "approved"
    assert after_revoke_body["decision_evidence"]["decision"]["final_decision"]["outcome"] == "affirmative"

    # The nuance from the module header, asserted rather than described: the
    # ORIGINAL grant binding now reads ALTERED — the row it commits to
    # really did change, legitimately — while the REVOCATION binding, which
    # was written against the post-revoke row, reads INTACT. Two different
    # verdicts for two different claims about the same row, and this is the
    # pair an examiner reads to tell "revoked" from "revoked, then also
    # tampered".
    after_revoke_events = _consent_events(after_revoke_body["binding_integrity"], consent_id)
    assert after_revoke_events[CONSENT_GRANT_BOUND]["result"] == "altered", (
        "the grant event commits to revoked_at=null; it is expected to disagree with the row "
        "once the row is legitimately revoked — that is not this attack's finding"
    )
    assert after_revoke_events[CONSENT_REVOCATION_BOUND]["result"] == "intact", (
        "the revocation event was written against the post-revoke row and must still match it"
    )

    # -----------------------------------------------------------------
    # 3. Direct SQL UPDATE consent_grants SET scope = ... -> binding_
    #    integrity verdict ALTERED on the pre-revocation decision's
    #    evidence; linkage byte-identical (the trap from attack 4).
    # -----------------------------------------------------------------
    chain_before = audit_log(memtara_server, desk)

    conn = db_connect()
    try:
        conn.run(
            "update consent_grants set scope = :scope where id = :id",
            scope='["tampered.purpose.not_what_was_granted"]',
            id=consent_id,
        )

        tampered = _evidence(memtara_server, desk, request_id)
        assert tampered.status_code == 200, tampered.text
        tampered_body = tampered.json()
        assert tampered_body["binding_integrity"]["verdict"] == "ALTERED", tampered_body["binding_integrity"]

        # The write landed — nothing in this system can stop a direct
        # UPDATE. Said plainly, per house style: detection, not prevention.
        assert tampered_body["decision_evidence"]["data"]["consent"]["scope"]["value"] == [
            "tampered.purpose.not_what_was_granted"
        ]

        tampered_events = _consent_events(tampered_body["binding_integrity"], consent_id)
        # Both now disagree with the row: the grant event still does (it
        # never stopped), and the revocation event — the one that was
        # INTACT a moment ago — now ALSO disagrees, because THIS is the
        # write that actually changed what it committed to.
        assert tampered_events[CONSENT_GRANT_BOUND]["result"] == "altered"
        assert tampered_events[CONSENT_REVOCATION_BOUND]["result"] == "altered", (
            "this is the event that was INTACT before the scope tamper and must not be after it "
            "— that transition is the attack's actual signature"
        )
        for event in tampered_events.values():
            assert event["recomputed_event_hash"] != event["recorded_event_hash"]

        # Linkage is STILL byte-identical — the attack is invisible to the
        # chain walk, exactly as it is in attack 4, and for the same reason:
        # a binding event's payload is never stored, so an UPDATE to the row
        # it describes cannot touch any `audit_log` bytes at all.
        assert audit_log(memtara_server, desk) == chain_before, (
            "the audit trail is unchanged across the tamper — linkage was never what broke"
        )
        org_wide = binding_replay(memtara_server, desk)
        wide_events = _consent_events(org_wide, consent_id)
        assert wide_events[CONSENT_REVOCATION_BOUND]["result"] == "altered", (
            "the org-level replay agrees with the per-record envelope — they are the same code "
            "path (replay_scoped), and must never disagree"
        )

        # -------------------------------------------------------------
        # 4. DELETE the row -> source_row_missing.
        # -------------------------------------------------------------
        conn.run("delete from consent_grants where id = :id", id=consent_id)

        deleted = _evidence(memtara_server, desk, request_id)
        assert deleted.status_code == 200, deleted.text
        deleted_body = deleted.json()
        assert deleted_body["binding_integrity"]["verdict"] == "ALTERED", deleted_body["binding_integrity"]

        deleted_events = _consent_events(deleted_body["binding_integrity"], consent_id)
        assert deleted_events[CONSENT_GRANT_BOUND]["result"] == "source_row_missing"
        assert deleted_events[CONSENT_REVOCATION_BOUND]["result"] == "source_row_missing"
        for event in deleted_events.values():
            assert event["rebuilt_payload"] is None
            assert event["recomputed_event_hash"] is None

        # The other half of point 5: the DECISION survives the grant's
        # deletion. `wealth_requests.consent_grant_id on delete set null`
        # (migrations/0011) is why — the decision is not cascaded away with
        # the row it cites. Its consent block now reads unpopulated, WITH a
        # reason naming what happened, rather than silently vanishing or
        # quietly re-showing stale values.
        assert deleted_body["decision_evidence"]["decision"]["status"] == "approved"
        assert deleted_body["decision_evidence"]["decision"]["final_decision"]["outcome"] == "affirmative"
        deleted_consent = deleted_body["decision_evidence"]["data"]["consent"]
        assert deleted_consent["consent_id"]["state"] == "unpopulated"
        assert "no longer exists" in deleted_consent["consent_id"]["unpopulated_reason"]
    finally:
        conn.close()
