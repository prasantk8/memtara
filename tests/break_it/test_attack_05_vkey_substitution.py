"""Attack #5 — change or substitute the verification key.

    ATTACK: the on-disk verification key a server checks proofs against is
    swapped for a different one — an operational mistake (wrong circuit's
    key deployed) or a deliberate substitution. A proof genuinely valid
    under the real key is checked against the wrong one.

    EXPECTED DEFENSIVE BEHAVIOUR: `bb verify` must reject the proof, because
    a Groth16/UltraHonk-style proof is only valid against the exact key it
    was constructed for. Nothing in `run_bb_verify_inner`
    (`backend/api/src/verify/mod.rs`) trusts the key's identity beyond "the
    file that happens to be at `vkeys_dir/<circuit>/vk` right now" — which is
    exactly what makes this attack meaningful to test empirically rather
    than argue about.

    WHAT THIS TEST PROVES: on a DEDICATED, disposable server (never the
    shared session server other test files use — see `tests/break_it/
    conftest.py`'s module docstring for why), a real proof (real
    `nargo execute` + real `bb prove` against the committed
    `circuits/wealth_suitability/vkey/vk`) is submitted twice against the
    SAME request:

      1. After `wealth_suitability`'s on-disk vk is swapped for a
         DIFFERENT, ALSO REAL, `bb`-generated vkey (`emergency_session`'s) —
         real cryptographic material, not corrupted bytes — the server
         refuses the proof: no 2xx, no `proof_token`, the disclosure request
         stays `pending`, and the nonce is never consumed.
      2. After the original vk is restored, the IDENTICAL proof bytes ARE
         accepted. This differential is what isolates the vkey swap as the
         actual cause of the rejection, rather than some unrelated defect in
         the test's own setup.

    WHAT THIS TEST DOES NOT PROVE: it substitutes a whole, valid vkey for a
    DIFFERENT circuit, not a bit-flipped/corrupted one — a stronger and more
    realistic attack than random corruption, but it does not separately
    characterise `bb`'s behaviour on truncated or malformed key files (that
    is `bb_verify_rejects_garbage_proof_against_real_vkey` in
    `backend/api/src/verify/mod.rs`'s own test module, already covered
    there). It also does not test the production drift detector
    (`ops/health.rs`'s `DIVERGED` check) — that catches an accidentally-
    stale key at `/health`-poll time, a different control than this one.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 5
BREAK_IT_ATTACK_TITLE = "Change/substitute the verification key"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = "real proof rejected against a substituted (but genuine, bb-generated) wrong-circuit vkey; recovers once restored"

import shutil

import httpx
import wealth_client as wc

from conftest import open_assessment, request_status, used_nonce_count


def test_a_proof_valid_under_the_real_key_is_rejected_once_the_key_is_swapped(
    dedicated_server_factory, make_desk
):
    handle = dedicated_server_factory()

    desk = make_desk(handle.base_url, isin="XS0000000055")
    request = open_assessment(handle.base_url, desk)
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert proof.suitable is True

    wealth_vk = handle.vkeys_dir / "wealth_suitability" / "vk"
    emergency_vk = handle.vkeys_dir / "emergency_session" / "vk"
    assert wealth_vk.exists() and emergency_vk.exists(), "ensure_vkeys should have generated both at boot"

    original_bytes = wealth_vk.read_bytes()
    substitute_bytes = emergency_vk.read_bytes()
    assert original_bytes != substitute_bytes, "sanity: the two circuits' keys are genuinely different"

    # The substitution: a different circuit's real, bb-generated key, in
    # place of the one the proof was actually built against.
    shutil.copy2(emergency_vk, wealth_vk)

    resp = httpx.post(
        f"{handle.base_url}/api/v1/submit-wealth-proof",
        json={
            "request_id": request["request_id"],
            "public_inputs": proof.public_inputs,
            "proof": proof.proof_b64,
        },
        headers={"Authorization": f"Bearer {desk.session_token}"},
        timeout=60.0,
    )
    assert resp.status_code not in (200, 201), (
        f"a proof checked against the WRONG verification key must not be accepted "
        f"(got {resp.status_code}: {resp.text})"
    )
    assert "proof_token" not in resp.text

    assert request_status(request["request_id"]) == "pending", "fail-closed: nothing was recorded as fulfilled"
    assert used_nonce_count(desk.org_id, request["nonce"]) == 0, "fail-closed: the nonce was not burned"

    # Restore the real key and prove the SAME proof bytes now succeed —
    # isolating the swap as the actual cause of the earlier rejection.
    wealth_vk.write_bytes(original_bytes)

    recovered = wc.submit_assessment(handle.base_url, desk.session_token, request["request_id"], proof)
    assert recovered["suitable"] is True
    assert request_status(request["request_id"]) == "fulfilled"
