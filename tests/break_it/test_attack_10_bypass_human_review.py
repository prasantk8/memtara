"""Attack #10 — bypass human review.

    ATTACK: a decision that is supposed to carry a human reviewer's sign-off
    is finalised without one — or the review step is skipped, forged,
    overridden silently, or quietly replaced by a second, friendlier verdict.

    The obvious version ("finalise with no review at all") is the least
    interesting one, and it is not how this control fails in practice. The
    three that matter are the subtle ones, and each has a real precedent:

      1. `override: true` with no stated reason — an override with nothing
         behind it is the absence of evidence wearing a boolean.
      2. a `review_duration_ms` with no `review_duration_source` — the Cigna
         field. In that litigation every denial had a named reviewer, a
         timestamp and an action; what ended the argument was a duration
         (~1.2 seconds each, in batches) whose provenance was checkable. A
         number with no provenance is admissible as neither an assertion nor
         a measurement.
      3. a SECOND review on a decision that already has one — the escalation
         that quietly supersedes an inconvenient verdict, after the record
         it belongs to was already exported.

    EXPECTED DEFENSIVE BEHAVIOUR, IN TWO LAYERS. The handler
    (`backend/api/src/wealth/review.rs`) refuses all three, and so does the
    database (`backend/api/migrations/0006_decision_capture.sql`:
    `decision_reviews_override_requires_reason`,
    `decision_reviews_duration_needs_a_source`, and `request_id` as the
    PRIMARY KEY). The second layer is the one this test exists for. A control
    that lives only in a request handler is bypassed by anyone who can reach
    the database — a DBA, a migration, a backfill script, an attacker with a
    connection string — and "we validate that in the API" is exactly the
    sentence that precedes every one of those. So every refusal below is
    attempted TWICE: once through the real HTTP endpoint, and once as a
    direct `insert into decision_reviews`, with the constraint that fired
    named explicitly.

    WHAT THIS TEST PROVES, against a real server, a real proof and a real
    Postgres:

      1. A decision with no review does not claim one. `human_review.
         performed` is false and every reviewer field is `not_applicable`
         (a signed assertion that there was no review step) rather than
         `unpopulated` (an admission that we lost the reviewer's name), and
         `decision_basis` is `proof_only`. There is no state in which an
         unreviewed decision reads like a reviewed one.
      2. Seven handler-level forgeries are refused and leave no row.
      3. Seven direct-to-database forgeries are refused BY POSTGRES, each by
         a named CHECK constraint, with the API not in the path at all.
      4. The gate is a gate and not a wall: a properly declared and explained
         override is accepted, produces `decision_basis =
         proof_and_human_override` — the variant a supervisor greps for, and
         one that is derived rather than assigned — and writes a
         `decision_human_reviewed` entry into the hash-chained audit log.
      5. The verdict the human contradicted is still in the record.
         `final_decision.outcome` stays `affirmative` (what the circuit
         proved) while `status` becomes `rejected` (what the human did). An
         override that rewrote the cryptographic verdict would erase the
         thing it was overriding.
      6. A second review is refused by the endpoint (409) AND by the primary
         key, and the first reviewer's name survives the attempt.
      7. A review cannot be attached to a decision that has not been made:
         the endpoint refuses (409), and — the interesting half — even when
         a row IS forced straight into the table for an undecided
         assessment, the evidence record still refuses to exist. The forged
         review buys the attacker nothing, because there is no decision to
         evidence.

    WHAT THIS TEST DOES NOT PROVE, and the residual is worth stating
    plainly: the CHECK constraints stop a direct writer from producing an
    INTERNALLY INCONSISTENT review. They cannot stop one from producing a
    consistent LIE — a fabricated row naming a real reviewer, with a
    plausible duration and a real source, is accepted by the database,
    because no constraint can know whether a human was ever at the desk.
    Point 7 above is the limit of what is enforced: such a row still cannot
    manufacture a decision. What it CAN do is attach a fabricated reviewer
    to a genuine decision, and the only thing that distinguishes it from a
    real review is the absence of a `decision_human_reviewed` event in the
    hash chain — a contradiction that exists in the audit log but that the
    `DecisionEvidence` record does not carry and nothing in the product
    currently cross-checks. Point 4 asserts that the chain entry is written
    for a real review, so the raw material for that check exists; the check
    itself does not. That is a narrower finding than this attack, and it is
    recorded here rather than left for someone to discover.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 10
BREAK_IT_ATTACK_TITLE = "Bypass human review"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "an unreviewed decision says so and cannot be made to claim otherwise; the unexplained "
    "override, the sourceless duration and the second review are each refused by the handler "
    "AND by a named CHECK constraint / primary key, so a direct database write cannot do what "
    "the API forbids"
)

import datetime as dt

import httpx
import wealth_client as wc

from conftest import db_connect, open_assessment

ORG_REVIEW_ROUTE = "/api/v1/wealth-assessments/{rid}/review"

# One statement, parameterised, so that every direct-write forgery below
# differs ONLY in the columns under attack. A per-case hand-written INSERT
# would let a typo in an unrelated column trip a different constraint and
# make this test look like it proved something it did not.
FORGED_REVIEW_INSERT = (
    'insert into decision_reviews ('
    '  request_id, org_id, reviewer_id, reviewer_role, action, "override", override_reason,'
    '  review_duration_ms, review_duration_source, human_review_protocol_version, reviewed_at'
    ') values ('
    '  :rid, :org, :reviewer, :role, :action, :overridden, :reason,'
    '  :duration_ms, :duration_source, :protocol, now()'
    ')'
)


def _completed_assessment(base_url, desk):
    """A real, decided assessment: real request, real `bb` proof, real
    verdict. Returns `(request_id, suitable)`.
    """
    request = open_assessment(base_url, desk)
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    result = wc.submit_assessment(base_url, desk.session_token, request["request_id"], proof)
    return request["request_id"], result["suitable"]


def _evidence(base_url, desk, request_id):
    return httpx.get(
        f"{base_url}/api/v1/wealth-assessments/{request_id}/decision-evidence",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _post_review(base_url, desk, request_id, *, reviewed_at, **overrides):
    body = {
        "reviewer_id": "emp-4417",
        "reviewer_role": "senior_suitability_officer",
        "action": "approved",
        "human_review_protocol_version": "cob-review-2026.2",
        "reviewed_at": reviewed_at,
    }
    body.update(overrides)
    return httpx.post(
        f"{base_url}{ORG_REVIEW_ROUTE.format(rid=request_id)}",
        json=body,
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=60.0,
    )


def _just_after(timestamp: str) -> str:
    """Two seconds after the assessment's own `assessed_at`.

    Read from the record rather than taken from this machine's clock on
    purpose: `wealth_requests.assessed_at` comes from Postgres's `now()`,
    the handler's bound checks come from the server process's clock, and the
    database here runs in a container whose clock is observably tens of
    milliseconds ahead. A review timed from the local clock is therefore
    intermittently refused for `reviewed_at` preceding the verdict — a real
    refusal, but of the test's own clumsiness rather than of an attack.
    """
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + dt.timedelta(seconds=2)).isoformat().replace("+00:00", "Z")


def _forge_directly(conn, request_id, org_id, **columns):
    """Attempt a forged `decision_reviews` row with the API entirely out of
    the picture. Returns the name of the constraint that refused it, or
    `None` if Postgres accepted the write.
    """
    params = {
        "rid": str(request_id),
        "org": str(org_id),
        "reviewer": "emp-9999",
        "role": "head_of_compliance",
        "action": "approved",
        "overridden": False,
        "reason": None,
        "duration_ms": None,
        "duration_source": None,
        "protocol": "cob-review-2026.2",
    }
    params.update(columns)
    try:
        conn.run(FORGED_REVIEW_INSERT, **params)
        return None
    except Exception as exc:  # pg8000 surfaces the server error fields as a dict
        detail = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
        return detail.get("n") or detail.get("M")


def _review_row_count(conn, request_id) -> int:
    return int(conn.run("select count(*) from decision_reviews where request_id = :rid", rid=str(request_id))[0][0])


def _audit_event_types(conn, request_id) -> list[str]:
    return [
        row[0]
        for row in conn.run("select event_type from audit_log where ref_id = :rid order by seq", rid=str(request_id))
    ]


def test_a_human_review_can_be_neither_skipped_nor_forged_through_the_api_or_the_database(
    memtara_server, make_desk
):
    desk = make_desk(memtara_server, isin="XS0000000110")
    request_id, suitable = _completed_assessment(memtara_server, desk)
    assert suitable is True, "sanity: this client genuinely clears the registered terms"

    conn = db_connect()
    try:
        # -----------------------------------------------------------------
        # 1. A decision nobody reviewed does not claim a review.
        # -----------------------------------------------------------------
        before = _evidence(memtara_server, desk, request_id)
        assert before.status_code == 200, before.text
        record = before.json()["decision_evidence"]
        assert record["human_review"]["performed"] is False
        for field in ("reviewer_id", "reviewer_role", "reviewed_at", "human_review_protocol_version",
                      "review_duration_ms", "review_duration_source"):
            assert record["human_review"][field]["state"] == "not_applicable", (
                f"{field} must assert that no review step happened, not admit that the reviewer's "
                f"details were lost — those are different claims and an examiner has to be able to "
                f"tell them apart"
            )
        assert record["decision"]["final_decision"]["decision_basis"]["value"] == "proof_only"
        assert _review_row_count(conn, request_id) == 0

        reviewed_at = _just_after(record["decision"]["timestamps"]["assessed_at"])

        # -----------------------------------------------------------------
        # 2. Seven forgeries through the real endpoint. Each must be refused,
        #    and none may leave a row behind.
        # -----------------------------------------------------------------
        handler_attempts = [
            ("an override with no reason", {"override": True}, 400),
            ("an override with a token reason", {"override": True, "override_reason": "n/a"}, 400),
            ("a reason attached to a non-override",
             {"override_reason": "the desk was comfortable with it"}, 400),
            # The quiet one. Contradict the cryptographic verdict and leave
            # the flag alone: without a server-side check this reads as
            # routine concurrence and the override flag becomes a
            # self-assessment.
            ("contradicting the verdict without declaring an override", {"action": "rejected"}, 400),
            # The provenance label is not the caller's to choose. If it were,
            # a client-asserted 1.2-second review could be filed as a
            # measurement.
            ("choosing the duration's own provenance",
             {"review_duration_ms": 1_200, "review_duration_source": "independently_measured"}, 422),
            ("supplying both duration inputs at once",
             {"review_duration_ms": 1_200, "review_started_at": reviewed_at}, 400),
            ("an action outside the closed set", {"action": "pending"}, 400),
        ]
        for label, overrides, expected in handler_attempts:
            response = _post_review(memtara_server, desk, request_id, reviewed_at=reviewed_at, **overrides)
            assert response.status_code == expected, f"{label}: {response.status_code} {response.text}"

        assert _review_row_count(conn, request_id) == 0, "a refused review must not leave a row behind"

        # -----------------------------------------------------------------
        # 3. The same forgeries, with the API removed from the picture.
        #
        #    This is the half that decides whether the control is real. A
        #    check that lives only in a handler is bypassed by everyone who
        #    can open a database connection.
        # -----------------------------------------------------------------
        direct_attempts = [
            ("an override with no reason",
             {"overridden": True, "reason": None},
             "decision_reviews_override_requires_reason"),
            ("an override with a token reason",
             {"overridden": True, "reason": "n/a"},
             "decision_reviews_override_requires_reason"),
            ("a reason attached to a non-override",
             {"overridden": False, "reason": "the desk was comfortable with it"},
             "decision_reviews_override_requires_reason"),
            ("a duration with no source",
             {"duration_ms": 1_200, "duration_source": None},
             "decision_reviews_duration_needs_a_source"),
            ("a source with no duration",
             {"duration_ms": None, "duration_source": "reviewer_client_asserted"},
             "decision_reviews_duration_needs_a_source"),
            ("a duration whose source is an invented one",
             {"duration_ms": 1_200, "duration_source": "independently_measured"},
             "decision_reviews_review_duration_source_check"),
            ("an action outside the closed set",
             {"action": "pending"},
             "decision_reviews_action_check"),
        ]
        for label, columns, expected_constraint in direct_attempts:
            refused_by = _forge_directly(conn, request_id, desk.org_id, **columns)
            assert refused_by == expected_constraint, (
                f"a direct database write of {label} must be refused by Postgres itself, by "
                f"{expected_constraint}; got {refused_by!r}. The API is not in this path: if this "
                f"row lands, every guarantee this control makes holds only for callers who chose "
                f"to use the endpoint"
            )

        assert _review_row_count(conn, request_id) == 0, (
            "no forged row may survive; the constraints must refuse the write, not merely be "
            "consulted afterwards"
        )

        # -----------------------------------------------------------------
        # 4. The gate is a gate, not a wall: the same override, declared and
        #    explained, is accepted.
        # -----------------------------------------------------------------
        accepted = _post_review(
            memtara_server,
            desk,
            request_id,
            reviewed_at=reviewed_at,
            action="rejected",
            override=True,
            override_reason=(
                "concentration risk in an adjacent holding is not visible to the circuit; "
                "declined on file under case 2026-0841"
            ),
            review_duration_ms=214_000,
        )
        assert accepted.status_code == 201, accepted.text
        reviewed = accepted.json()["decision_evidence"]
        assert reviewed["human_review"]["performed"] is True
        assert reviewed["human_review"]["override"] is True
        assert reviewed["human_review"]["review_duration_source"]["value"] == "reviewer_client_asserted", (
            "a duration the reviewing client timed itself must never be presentable as a measurement"
        )
        assert reviewed["decision"]["final_decision"]["decision_basis"]["value"] == "proof_and_human_override", (
            "the basis names the override, and it is derived from the review rather than assigned "
            "by the caller — so no code path can reach an override without the variant a "
            "supervisor searches on"
        )
        # 5. The verdict that was overridden is still in the record.
        assert reviewed["decision"]["final_decision"]["outcome"] == "affirmative", (
            "the circuit proved this client suitable; a human override must change the decision's "
            "status, not retroactively rewrite what was proved"
        )
        assert reviewed["decision"]["status"] == "rejected"

        assert "decision_human_reviewed" in _audit_event_types(conn, request_id), (
            "the review must land in the hash-chained audit log in the same transaction as the "
            "row, or the row is the only record of it"
        )

        # -----------------------------------------------------------------
        # 6. One review per decision — through the endpoint and through the
        #    table. A deliberately VALID second review, so that what refuses
        #    it is the one-review rule and not some other validation.
        # -----------------------------------------------------------------
        second = _post_review(
            memtara_server, desk, request_id, reviewed_at=reviewed_at, reviewer_id="emp-0002"
        )
        assert second.status_code == 409, second.text
        assert _forge_directly(conn, request_id, desk.org_id) == "decision_reviews_pkey"
        surviving = conn.run("select reviewer_id from decision_reviews where request_id = :rid", rid=str(request_id))
        assert surviving[0][0] == "emp-4417", (
            "the first review must survive both attempts: the record is sealed, and a silent "
            "overwrite would change what an already-exported record said"
        )

        # -----------------------------------------------------------------
        # 7. A review cannot manufacture a decision that was never made.
        #
        #    The endpoint refuses outright. The database does NOT constrain
        #    this pairing — there is no cross-table CHECK, and one cannot be
        #    written — so the forged row lands. It buys nothing: the evidence
        #    record still refuses to exist, because no verdict was ever
        #    reached for it to be evidence of.
        # -----------------------------------------------------------------
        undecided = open_assessment(memtara_server, desk)["request_id"]
        premature = _post_review(memtara_server, desk, undecided, reviewed_at=reviewed_at)
        assert premature.status_code == 409, premature.text

        assert _forge_directly(conn, undecided, desk.org_id) is None, (
            "documenting the true state: no CHECK constraint can span two tables, so this write "
            "is expected to land — the assertion below is where it is stopped"
        )
        no_record = _evidence(memtara_server, desk, undecided)
        assert no_record.status_code == 409, (
            "a review forced onto an undecided assessment must not conjure an evidence record: "
            f"got {no_record.status_code} {no_record.text}"
        )
        assert "has not been decided yet" in no_record.text
        assert "decision_human_reviewed" not in _audit_event_types(conn, undecided), (
            "and the forged row leaves no entry in the hash chain, which is the only thing that "
            "distinguishes it from a review that really happened"
        )
    finally:
        conn.close()
