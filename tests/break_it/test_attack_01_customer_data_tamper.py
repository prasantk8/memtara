"""Attack #1 — change the customer's data after the fact.

    ATTACK: A client's vault is proved suitable against the figures it held
    at time T. Before that proof reaches the bank, the customer's committed
    data changes (re-synced, corrected, or tampered with) to something
    different — T+1's vault, not T's. The old proof, built against T, is
    then submitted as if it still describes the customer.

    EXPECTED DEFENSIVE BEHAVIOUR: the proof must be refused. `vault_root` is
    a public input baked into the signed commitment the circuit verifies
    (`circuits/wealth_suitability/src/main.nr`), and
    `submit_wealth_proof` (`backend/api/src/wealth/mod.rs`, the
    `registered_root` check right before `verify_and_consume`) additionally
    binds it to whatever root is CURRENTLY registered for that user in
    `vault_blobs` — not whatever root the proof happens to carry. A proof
    about yesterday's vault must not be accepted as evidence about today's.

    WHAT THIS TEST PROVES: going through the real HTTP API, a real
    `nargo execute` + `bb prove` proof generated honestly against the
    customer's ORIGINAL vault is rejected once that vault is re-synced to
    different figures before submission — and that the rejection is a true
    fail-closed (the disclosure request stays `pending`, the nonce is never
    consumed — checked directly against Postgres, not inferred from the HTTP
    response alone).

    WHAT THIS TEST DOES NOT PROVE: it does not exercise a case where the
    attacker also forges a NEW valid proof against the NEW vault claiming
    the OLD terms, nor does it test the four session circuits' equivalent
    binding (`verify::verify_against_request` does not pin `vault_root` the
    way `submit_wealth_proof` does for wealth_suitability — see
    decision_evidence_spec.md Task 1, `customer.data_provenance` row, and
    Task 4 attack #1's note; that is a real, narrower gap, tracked there, not
    re-proven here).
"""

from __future__ import annotations

# Read by scripts/break_it.sh's table renderer (tests/break_it/_render_table.py).
BREAK_IT_ATTACK_NUMBER = 1
BREAK_IT_ATTACK_TITLE = "Change the customer's data after the fact"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = "real proof rejected once the customer's vault changed; status/nonce confirmed untouched"

import httpx
import wealth_client as wc

from conftest import request_status, resync_vault, used_nonce_count


def test_proof_is_rejected_after_the_underlying_vault_changes(memtara_server, make_desk):
    desk = make_desk(memtara_server)

    request = wc.open_assessment(
        memtara_server, desk.api_key, user_id=desk.user_id, product_isin=desk.product_isin
    )

    # The proof is generated honestly, against the customer's real,
    # currently-registered vault. This is a genuine ZK proof: real
    # `nargo execute`, real `bb prove`.
    stale_proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert stale_proof.suitable is True, "sanity: the original vault is suitable under these terms"

    # Now the customer's data changes — a re-sync with a materially
    # different vault (lower income, different holdings), which produces a
    # genuinely different Merkle root. This models "the underlying data was
    # changed after the fact," not "the client tried to invent a vault from
    # nothing" (a related but different, and already-covered, attack — see
    # `tests/test_wealth_suitability_e2e.py::test_a_client_cannot_prove_against_a_vault_it_invented`).
    changed_vault = wc.WealthVault(
        keypair=desk.vault.keypair,
        income=50_000,
        liquid_assets=10_000,
        risk_tolerance=1,
        existing_holdings_value=0,
    )
    resync_vault(memtara_server, desk, changed_vault, expected_version=1)

    # The stale proof — real, valid, and about a customer who no longer has
    # the vault it describes — is submitted.
    try:
        wc.submit_assessment(memtara_server, desk.session_token, request["request_id"], stale_proof)
        assert False, "a proof built against a superseded vault must not be accepted"
    except wc.MemtaraApiError as exc:
        assert exc.status == 400, exc.body
        assert "vault_root" in exc.body, exc.body

    # Fail-closed, not just "the HTTP call returned an error": nothing was
    # silently recorded as fulfilled, and the one-shot nonce was not burned
    # — the legitimate holder can still complete the (re-)assessment.
    assert request_status(request["request_id"]) == "pending"
    assert used_nonce_count(desk.org_id, request["nonce"]) == 0
