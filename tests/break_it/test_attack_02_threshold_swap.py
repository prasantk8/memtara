"""Attack #2 — change a threshold after an assessment is open, then try to
use the new one.

    ATTACK: An assessment is opened against a product's registered terms
    (e.g. `min_income = 500,000`). The client's real income does not clear
    that bar. Before the client proves, whoever holds the org's API key
    amends the product in the registry — lowers `min_income` to something
    the client DOES clear — and the client proves suitability against the
    freshly-lowered figure instead of the one the request was actually
    opened with, hoping the already-open request accepts it.

    EXPECTED DEFENSIVE BEHAVIOUR: `wealth_requests` snapshots the terms at
    OPEN time (`backend/api/src/wealth/mod.rs::issue_wealth_request`), and
    `submit_wealth_proof` compares every submitted public input against that
    snapshot, never against the live `products` row
    (`wealth/mod.rs`, the `expect_u64(4, "min_income", terms.min_income)`
    check and neighbours). A threshold change must not reach back into an
    assessment that is already in flight, in either direction: not to
    tighten it retroactively, and — the more dangerous direction, tested
    here — not to loosen it retroactively either.

    WHAT THIS TEST PROVES: with a real, income-short client (300,000 against
    a 500,000 floor — genuinely NOT suitable under the terms the request was
    opened with), a real `PATCH /api/v1/products/:isin` that lowers
    `min_income` to 100,000, and a real proof built against the LOWERED
    figure (internally consistent, cryptographically valid, `suitable=True`
    by construction), the server refuses to accept that proof against the
    original request. It also proves the system is not simply "broken" —
    the same amendment legitimately applies to a fresh assessment opened
    AFTER it.

    WHAT THIS TEST DOES NOT PROVE: this is the same code path exercised by
    the pre-existing `tests/test_wealth_suitability_e2e.py::
    test_a_client_cannot_choose_the_thresholds_it_is_measured_against` and
    `::test_amending_a_product_does_not_reach_back_into_open_assessments`.
    Those tests earn their keep already; this one is additive because it
    frames the SAME defence against the SPECIFIC adversarial scenario board
    reviewers asked about (a threshold changed mid-flight to launder an
    otherwise-unsuitable client through), rather than an arbitrary
    self-chosen value.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 2
BREAK_IT_ATTACK_TITLE = "Change a threshold mid-flight"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = "a freshly-lowered registry threshold cannot be retroactively applied to an already-open request"

import httpx
import wealth_client as wc

from conftest import open_assessment, request_status, used_nonce_count


def test_a_mid_flight_threshold_amendment_cannot_be_applied_to_an_already_open_request(
    memtara_server, make_desk
):
    desk = make_desk(
        memtara_server,
        isin="XS0000000099",
        terms=dict(min_income=500_000, min_liquidity=1_000_000, max_concentration_percent=30, product_risk_level=3),
        income=300_000,  # genuinely short of the 500k floor
        liquid_assets=2_000_000,
        existing_holdings_value=0,
    )

    request = open_assessment(memtara_server, desk)
    assert int(request["min_income"]) == 500_000

    # The advisor (or an attacker holding the org key) amends the product
    # AFTER the assessment opened.
    patch = httpx.patch(
        f"{memtara_server}/api/v1/products/{desk.product_isin}",
        json={"min_income": 100_000},
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=10.0,
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["min_income"] == 100_000

    # A real proof, built against the request's real nonce/product_ref, but
    # with min_income rewritten to the freshly-lowered figure. This IS a
    # valid proof — of suitability against 100,000, not against what the
    # bank actually opened this assessment with.
    forged = dict(request, min_income=100_000)
    proof = wc.generate_proof(forged, desk.vault, oracle=desk.oracle)
    assert proof.suitable is True, "internally consistent against the forged floor — that's the trap"

    try:
        wc.submit_assessment(memtara_server, desk.session_token, request["request_id"], proof)
        assert False, "a proof measured against a post-hoc-lowered threshold must not be accepted"
    except wc.MemtaraApiError as exc:
        assert exc.status == 400, exc.body
        assert "min_income" in exc.body, exc.body
        assert "registered terms" in exc.body, exc.body

    assert request_status(request["request_id"]) == "pending"
    assert used_nonce_count(desk.org_id, request["nonce"]) == 0

    # Control: the amendment is not fake — a NEW assessment opened after it
    # legitimately gets the new floor, and this same (short-of-500k, but
    # now-qualifying-at-100k) client can be honestly, freshly reassessed.
    after = open_assessment(memtara_server, desk)
    assert int(after["min_income"]) == 100_000
    honest_proof = wc.generate_proof(after, desk.vault, oracle=desk.oracle)
    result = wc.submit_assessment(memtara_server, desk.session_token, after["request_id"], honest_proof)
    assert result["suitable"] is True
