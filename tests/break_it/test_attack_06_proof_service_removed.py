"""Attack #6 — remove the proof service.

    ATTACK: `bb` (the Barretenberg verifier binary this system's entire
    trust model rests on) becomes unavailable — either it was never there
    when the server tried to boot, or it disappears while the server is
    already up and serving requests.

    EXPECTED DEFENSIVE BEHAVIOUR: fail CLOSED, not open. No degraded mode
    that accepts unverified proofs, no silent success. Per
    `decision_evidence_spec.md` Task 3: boot-time, `main.rs`'s call to
    `verify::ensure_vkeys` must abort startup entirely if `bb` can't be
    found or a vkey can't be generated; per-request,
    `run_bb_verify_inner` (`backend/api/src/verify/mod.rs`) must return an
    error distinct from a cryptographic rejection
    (`VerificationResult::Errored`, not `Rejected` —
    `backend/api/src/ops/metrics.rs`) and must NOT consume the nonce or mark
    anything fulfilled.

    WHAT THIS TEST PROVES — both sub-cases, both against a real compiled
    `memtara-api` binary and a real (temporarily broken) `bb`:

      (a) BOOT-TIME: pointing `BB_BIN` at a path that does not exist, with a
          fresh (never-generated) `VKEYS_DIR`, makes the server process exit
          non-zero before ever binding its port — not start in a degraded
          mode, not silently listen with no working verifier.

      (b) PER-REQUEST: a server boots successfully (against a private,
          disposable COPY of the real `bb`, so this test can delete it
          without touching the shared toolchain any other test relies on),
          proves a real client-side proof, THEN the copy is deleted before
          submission. The submission fails (no 2xx, no `proof_token`), the
          disclosure request stays `pending`, and the nonce is never
          consumed — checked directly against Postgres. Restoring the
          binary and resubmitting the IDENTICAL proof then succeeds,
          isolating "the verifier was briefly gone" as the actual cause
          rather than some unrelated defect.

    WHAT THIS TEST DOES NOT PROVE: it does not test any of the four
    continuity modes decision_evidence_spec.md Task 3 proposes beyond
    today's Mode A ("hard block") — Mode B (queue-and-replay) and the rest
    are explicitly not built yet, and this test does not pretend otherwise.
    It also does not prove WHICH HTTP status the per-request case returns is
    the ideal one for API consumers (it is a 500 today, since
    `ApiError::Other` maps to `INTERNAL_SERVER_ERROR` — see
    `backend/api/src/error.rs`) — only that it is not a success.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 6
BREAK_IT_ATTACK_TITLE = "Remove the proof service"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = "boot-time: server exits non-zero without bb. per-request: bb disappearing mid-flight fails closed (no fulfil, nonce unburned), recovers once restored"

import os
import time

import httpx
import wealth_client as wc

from conftest import open_assessment, request_status, used_nonce_count


def test_boot_fails_hard_without_bb(dedicated_server_factory):
    handle = dedicated_server_factory(
        bb_bin="/definitely/not/a/real/path/memtara-break-it-missing-bb",
        wait_healthy=False,
        boot_timeout=30.0,
    )

    deadline = time.time() + 60.0
    while time.time() < deadline and handle.process.poll() is None:
        time.sleep(0.5)

    exit_code = handle.process.poll()
    assert exit_code is not None, "the server must not still be running with no working `bb`"
    assert exit_code != 0, "the server must exit non-zero, not boot in a degraded mode"

    output = handle.output_tail()
    assert "bb" in output.lower(), f"the failure should name the missing verifier; got:\n{output}"

    # And the port genuinely never came up — not "healthy but wrong."
    try:
        httpx.get(f"{handle.base_url}/healthz", timeout=1.0)
        assert False, "a server that failed to boot must not be accepting connections at all"
    except httpx.ConnectError:
        pass


def test_a_request_in_flight_when_bb_disappears_fails_closed(
    dedicated_server_factory, private_bb_copy, make_desk
):
    handle = dedicated_server_factory(bb_bin=str(private_bb_copy))

    desk = make_desk(handle.base_url, isin="XS0000000066")
    request = open_assessment(handle.base_url, desk)
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    assert proof.suitable is True

    # The verifier disappears mid-flight — after the proof exists, before it
    # is submitted.
    original_bb_bytes = private_bb_copy.read_bytes()
    os.remove(private_bb_copy)

    resp = httpx.post(
        f"{handle.base_url}/api/v1/submit-wealth-proof",
        json={
            "request_id": request["request_id"],
            "public_inputs": proof.public_inputs,
            "proof": proof.proof_b64,
        },
        headers={"Authorization": f"Bearer {desk.session_token}"},
        timeout=30.0,
    )
    assert resp.status_code not in (200, 201), (
        f"the server must not accept a proof it could not actually verify (got {resp.status_code}: {resp.text})"
    )
    assert resp.status_code >= 500, (
        "a genuine infrastructure failure (verifier missing), not a well-formed rejection, "
        f"should surface as a server error, not a 4xx that reads like a client mistake; got {resp.status_code}"
    )
    assert "proof_token" not in resp.text

    assert request_status(request["request_id"]) == "pending", "fail-closed: nothing recorded as fulfilled"
    assert used_nonce_count(desk.org_id, request["nonce"]) == 0, "fail-closed: the nonce was not burned"

    # Recovery: restore the verifier and prove the SAME proof now succeeds —
    # isolating "the verifier was briefly unavailable" as the real cause.
    private_bb_copy.write_bytes(original_bb_bytes)
    private_bb_copy.chmod(0o755)

    recovered = wc.submit_assessment(handle.base_url, desk.session_token, request["request_id"], proof)
    assert recovered["suitable"] is True
    assert request_status(request["request_id"]) == "fulfilled"
