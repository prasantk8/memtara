"""Attack #7 — modify the evidence record after the fact.

    ATTACK: after a decision's audit trail has been written, someone with
    direct database access edits the tamper-evidence machinery itself —
    `update audit_log set event_hash = <32 forged bytes>` — so that the
    record of what happened no longer says what happened.

    THE ROW THAT MATTERS IS THE LAST ONE. `backend/api/src/audit/mod.rs`
    builds a hash chain: row N+1's `prev_hash` commits to row N's
    `event_hash`, so editing row N breaks a link anybody can check. That
    argument is airtight for every row that HAS a successor and says
    nothing whatsoever about the terminal row. Nothing succeeds it, so
    nothing commits to its hash; and `payload` is deliberately never stored
    (audit/mod.rs: "there's no column for it, schema is final"), so the hash
    cannot be recomputed from the database either. The newest decision — the
    one a regulator or a claimant actually asks about — was the one row that
    could be rewritten silently.

    WHAT CLOSED IT: signed checkpoints over the chain head
    (`backend/api/src/audit/checkpoint.rs`, migration 0008). A checkpoint is
    an Ed25519-signed statement, made outside the chain, that at checkpoint
    C the head was `event_hash` H at `seq` S over N rows. It is served
    unauthenticated at `GET /audit/checkpoints/latest` as a compact JWS and
    verifies against `/.well-known/jwks.json` with any JOSE library — so a
    third party who fetched it can hold the terminal row to it without our
    cooperation and without this database.

    WHAT THIS FILE PROVES, against a real running server, a real Postgres,
    and forged bytes written by real SQL — THREE facts, the third of which
    is a limitation and is asserted rather than described:

      1. STOPPED, by chain linkage: a tamper on a row that HAS a successor
         breaks `prev_hash`/`event_hash` adjacency, exactly as designed.
         This is the property that already held and it is still checked here,
         because a fix that quietly broke it would otherwise go unnoticed.

      2. STOPPED, by the checkpoint: a tamper on the TERMINAL row inside a
         checkpointed range is caught. This test deliberately proves both
         halves — that chain linkage does NOT catch it (the original
         finding, still true) and that the signed checkpoint DOES. The
         checkpoint's signature is verified in this file against the
         published JWKS with `cryptography`, not taken on the server's word.

      3. NOT STOPPED, and stated plainly: a tamper on the terminal row
         AFTER the most recent checkpoint is still undetectable. Rows
         appended since the last checkpoint are outside its covered range by
         construction. That residual window is the checkpoint interval —
         `MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS` (default 60s) or
         `MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS` (default 64) events,
         whichever binds first, and driveable to near zero on demand via
         `POST /audit/checkpoints`. Test 3 performs that attack and asserts
         it SUCCEEDS. If someone later closes this window, test 3 starts
         failing and the claim gets updated with the code.

    WHY THE TABLE SAYS STOPPED WITH (3) OUTSTANDING: the attack as posed —
    "modify the evidence record" — is refused for every record the system
    has committed to, which is every record older than one checkpoint
    interval. What remains is a bounded, quotable window, not an open door,
    and `POST /audit/checkpoints` closes it on demand before any export or
    dispute. `scripts/break_it.sh` prints a note only for BLOCKED and NOT
    STOPPED rows, so this caveat does not reach the table; it must be
    carried into any pilot material by hand.

    WHAT THIS FILE DOES NOT PROVE, and must not be read as proving:
    CONTENT tamper. `event_hash` commits to `event_type` and `payload`, but
    `payload` is not stored, so rewriting `event_type` in place while leaving
    the hash columns untouched remains invisible to anyone who does not
    independently hold the payload. A head checkpoint does not address that
    and was never meant to; the fix is shipping payloads in the offline
    verification bundle. It is a separate finding with a separate owner.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 7
BREAK_IT_ATTACK_TITLE = "Modify the evidence record"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "a tamper on any row with a successor is caught by chain linkage; a tamper on the terminal "
    "row is caught by the signed checkpoint (migration 0008, audit/checkpoint.rs) once that row "
    "is checkpointed. RESIDUAL: rows appended since the last checkpoint are not covered — the "
    "window is MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS (60s default) or "
    "MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS (64 default), whichever comes first, closeable on "
    "demand with POST /audit/checkpoints. Test 3 in this file performs that attack and asserts "
    "it still succeeds."
)

import base64
import json
import uuid

import httpx
import wealth_client as wc

from conftest import audit_log, db_connect, open_assessment

FORGED = b"\xab" * 32  # 32 bytes, the shape of a real SHA-256, none of the content


# ---------------------------------------------------------------------------
# Reading the chain the way an auditor with the whole log would — directly,
# globally, ordered by seq.
#
# NOT through `GET /orgs/:id/audit-log`: that endpoint returns a FILTERED
# view of one global chain (audit/mod.rs is explicit about this), so
# consecutive rows in it are normally not chain-adjacent and checking
# `prev_hash == previous.event_hash` across the response would be checking
# something that was never true. The linkage property lives in the global
# log, so that is where it gets checked.
# ---------------------------------------------------------------------------


def _linkage_breaks(from_seq: int) -> int:
    """Number of places in the global chain at or after `from_seq` where a
    row's `prev_hash` is not its predecessor's `event_hash`.

    Counted rather than asserted-zero because a shared development database
    legitimately contains holes: other break-it modules and other test files
    delete their own audit rows in cleanup (see conftest.py), and a deleted
    row leaves the survivors non-adjacent. Comparing a count before and after
    a tamper isolates the tamper from that pre-existing noise.
    """
    conn = db_connect()
    try:
        rows = conn.run(
            "select seq, event_hash, prev_hash from audit_log where seq >= :s order by seq asc",
            s=from_seq,
        )
    finally:
        conn.close()
    return sum(1 for i in range(1, len(rows)) if rows[i][2] != rows[i - 1][1])


def _terminal_row() -> tuple[int, bytes]:
    """`(seq, event_hash)` of the global chain's last row — the row with no
    successor, which is the whole subject of this attack."""
    conn = db_connect()
    try:
        rows = conn.run("select seq, event_hash from audit_log order by seq desc limit 1")
    finally:
        conn.close()
    assert rows, "the audit log is empty; there is nothing to attack"
    return int(rows[0][0]), bytes(rows[0][1])


def _row_hash(seq: int) -> bytes | None:
    conn = db_connect()
    try:
        rows = conn.run("select event_hash from audit_log where seq = :s", s=seq)
    finally:
        conn.close()
    return bytes(rows[0][0]) if rows else None


def _set_event_hash(seq: int, value: bytes) -> None:
    conn = db_connect()
    try:
        conn.run("update audit_log set event_hash = :h where seq = :s", h=value, s=seq)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The checkpoint surface.
# ---------------------------------------------------------------------------


def _b64url(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _force_checkpoint(base_url: str, desk) -> dict:
    """`POST /audit/checkpoints` — pin the head right now rather than waiting
    out the interval. Returns the checkpoint that now covers the head,
    whether this call created it or an earlier one already had."""
    resp = httpx.post(
        f"{base_url}/audit/checkpoints",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=15.0,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checkpoint"] is not None, body["note"]
    return body["checkpoint"]


def _latest_checkpoint(base_url: str) -> dict:
    resp = httpx.get(f"{base_url}/audit/checkpoints/latest", timeout=15.0)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _covering(base_url: str, seq: int) -> dict:
    resp = httpx.get(f"{base_url}/audit/checkpoints/covering/{seq}", timeout=15.0)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _integrity(base_url: str, desk) -> dict:
    resp = httpx.get(
        f"{base_url}/audit/integrity",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=15.0,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _verify_checkpoint_signature(checkpoint: dict) -> dict:
    """Verify the checkpoint's compact JWS against the PUBLISHED JWKS, here,
    with `cryptography` — not by asking the server whether its own signature
    is good.

    This is the assertion that makes a checkpoint evidence rather than a
    log line: the same three lines an auditor's own tooling runs, using
    nothing but bytes the server hands to anybody who asks. Returns the
    decoded claims.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    jwks = httpx.get(checkpoint["jwks_url"], timeout=15.0).json()
    key = next(k for k in jwks["keys"] if k["kid"] == checkpoint["kid"])
    assert key["kty"] == "OKP" and key["crv"] == "Ed25519", key

    header_b64, payload_b64, signature_b64 = checkpoint["jws"].split(".")
    Ed25519PublicKey.from_public_bytes(_b64url(key["x"])).verify(
        _b64url(signature_b64), f"{header_b64}.{payload_b64}".encode()
    )

    header = json.loads(_b64url(header_b64))
    assert header["alg"] == "EdDSA", header
    # `typ` is the RFC 8725 §3.11 defence: the same key also signs proof
    # tokens, and a relying party must not be able to be handed one where it
    # asked for the other.
    assert header["typ"] == "memtara-audit-checkpoint+jwt", header

    return json.loads(_b64url(payload_b64))


def _advance_the_chain(base_url: str, desk) -> None:
    """Append one real audited event — a product registration — so the chain
    head moves. Used only to leave the deployment in a state where the newest
    checkpoint agrees with the log; a fabricated `insert into audit_log`
    would bypass the very code path whose output this file is judging."""
    resp = httpx.post(
        f"{base_url}/api/v1/products",
        json={
            "product_isin": "XS%010d" % (uuid.uuid4().int % 10**10),
            "product_name": "break-it chain advance",
            "risk_level": 3,
            "min_income": 500_000,
            "min_liquidity": 1_000_000,
            "max_concentration_percent": 30,
            "approved_by_risk_committee": True,
        },
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=15.0,
    )
    assert resp.status_code == 201, resp.text


def _run_assessment(base_url: str, desk) -> dict:
    request = open_assessment(base_url, desk)
    proof = wc.generate_proof(request, desk.vault, oracle=desk.oracle)
    result = wc.submit_assessment(base_url, desk.session_token, request["request_id"], proof)
    assert result["suitable"] is True
    return request


# ---------------------------------------------------------------------------
# 1. STOPPED — the property that already held, still holding.
# ---------------------------------------------------------------------------


def test_a_tamper_on_a_row_with_a_successor_breaks_chain_linkage(memtara_server, make_desk):
    desk = make_desk(memtara_server, isin="XS0000000088")
    request = _run_assessment(memtara_server, desk)

    org_rows = sorted(
        [e for e in audit_log(memtara_server, desk) if e["ref_id"] == request["request_id"]],
        key=lambda e: e["seq"],
    )
    assert len(org_rows) >= 2, "expected at least the 'requested' and 'proof_verified' events"

    window_start = org_rows[0]["seq"]
    terminal_seq, _ = _terminal_row()

    # Pick a row that definitely has a successor. Its successor's prev_hash
    # commits to it, so editing it must break something.
    target_seq = org_rows[0]["seq"]
    assert target_seq < terminal_seq, "this test needs a row that is not the chain head"

    before = _linkage_breaks(window_start)
    original = _row_hash(target_seq)
    assert original is not None

    _set_event_hash(target_seq, FORGED)
    try:
        after = _linkage_breaks(window_start)
        assert after > before, (
            "editing a row that has a successor must break prev_hash/event_hash adjacency — "
            f"breaks went {before} -> {after}"
        )
    finally:
        _set_event_hash(target_seq, original)

    assert _linkage_breaks(window_start) == before, "restore must return the chain to its prior state"


# ---------------------------------------------------------------------------
# 2. STOPPED — the finding, closed. The terminal row, inside a checkpoint.
# ---------------------------------------------------------------------------


def test_a_tamper_on_the_checkpointed_terminal_row_is_caught_by_the_checkpoint(memtara_server, make_desk):
    desk = make_desk(memtara_server, isin="XS0000000089")
    _run_assessment(memtara_server, desk)

    # Pin the head now rather than waiting out the interval. This is the same
    # call a bank would make immediately before exporting evidence.
    checkpoint = _force_checkpoint(memtara_server, desk)
    claims = _verify_checkpoint_signature(checkpoint)

    terminal_seq, original = _terminal_row()
    assert claims["head_seq"] == terminal_seq, (
        "the checkpoint must pin the row that currently has no successor — that is the row "
        f"under attack (checkpoint head_seq {claims['head_seq']}, chain head {terminal_seq})"
    )
    assert _b64url(claims["head_event_hash"]) == original
    assert _covering(memtara_server, terminal_seq)["covered"] is True

    baseline_breaks = _linkage_breaks(terminal_seq - 1 if terminal_seq > 1 else 1)
    assert _integrity(memtara_server, desk)["intact"] is True, "sanity: intact before the tamper"

    # THE ATTACK: 32 forged bytes over the terminal row's event_hash.
    _set_event_hash(terminal_seq, FORGED)
    try:
        assert _row_hash(terminal_seq) == FORGED, "sanity: the forgery actually landed"

        # Half one, and it is the original finding restated: chain linkage
        # cannot see this. Nothing succeeds the terminal row, so no
        # prev_hash disagrees with anything. Asserting this rather than
        # skipping it keeps the test honest about WHY the checkpoint is
        # needed instead of implying linkage was ever enough.
        assert _linkage_breaks(terminal_seq - 1 if terminal_seq > 1 else 1) == baseline_breaks, (
            "the terminal row has no successor, so linkage is blind to this edit — that is the "
            "gap the checkpoint exists to cover, and if it ever stops being true this test's "
            "reasoning needs revisiting"
        )

        # Half two: the checkpoint catches it, and an outsider holding only
        # the signed JWS can see it without asking us anything. This is the
        # detection computed HERE, from the verified claims and one SELECT.
        assert _b64url(claims["head_event_hash"]) != _row_hash(terminal_seq), (
            "a checkpoint fetched before the tamper now contradicts the database: the signed "
            "head_event_hash is not what the row at head_seq says. This is detection by "
            "something the database cannot rewrite."
        )

        # And the server reports the same verdict through its own surface,
        # naming the failure rather than returning a bare false.
        verdict = _integrity(memtara_server, desk)
        assert verdict["intact"] is False, verdict
        failures = verdict["checkpoint"]["failures"]
        assert any(f["failure"] == "head_hash_mismatch" for f in failures), failures
    finally:
        _set_event_hash(terminal_seq, original)

    assert _integrity(memtara_server, desk)["intact"] is True, "restore must clear the alarm"


# ---------------------------------------------------------------------------
# 3. NOT STOPPED — the residual window, attacked and asserted.
# ---------------------------------------------------------------------------


def test_a_tamper_after_the_last_checkpoint_is_still_undetectable(memtara_server, make_desk):
    """The honest half. Rows appended since the last checkpoint are outside
    its covered range, so the newest one can still be rewritten silently.

    This test performs that attack and asserts it SUCCEEDS. It is written
    that way on purpose: a harness that quietly stopped attacking the
    uncovered window would report a stronger guarantee than the system has.
    If a future change closes this window, this test fails loudly and the
    claim in the module docstring, in `audit/checkpoint.rs`, and in
    `docs/BREAK_IT_FINDINGS.md` all have to be revised together.
    """
    desk = make_desk(memtara_server, isin="XS0000000090")
    _run_assessment(memtara_server, desk)

    # Pin the head, then generate activity AFTER it.
    #
    # Every hard assertion below is made against THIS checkpoint — the one
    # the test holds and has verified — and never against "whatever the
    # server currently calls latest". That is not defensive coding for its
    # own sake: a checkpoint is a statement by a specific signer at a
    # specific position, and "is this row covered by the checkpoint I hold?"
    # is the question an auditor actually has. It also makes the test immune
    # to a second checkpointer running against the same database (a second
    # replica, or a developer's stray server), which is a real configuration
    # and must not be able to turn this file green or red by accident.
    pinned = _force_checkpoint(memtara_server, desk)
    claims = _verify_checkpoint_signature(pinned)
    pinned_head = claims["head_seq"]

    _run_assessment(memtara_server, desk)
    terminal_seq, original = _terminal_row()
    assert terminal_seq > pinned_head, (
        f"the new decision (seq {terminal_seq}) must land after the checkpoint (head_seq "
        f"{pinned_head}) — otherwise there is no uncovered row to attack"
    )
    assert _row_hash(pinned_head) == _b64url(claims["head_event_hash"]), (
        "sanity: the checkpoint we hold matches the row it pins, before any tamper"
    )

    baseline_breaks = _linkage_breaks(pinned_head)
    _set_event_hash(terminal_seq, FORGED)
    try:
        assert _row_hash(terminal_seq) == FORGED, "sanity: the forgery landed"

        # The attack succeeds. Say so, in the two ways it is visible.
        assert _linkage_breaks(pinned_head) == baseline_breaks, (
            "no successor, so no linkage break — as in test 2"
        )
        assert _row_hash(pinned_head) == _b64url(claims["head_event_hash"]), (
            "RESIDUAL EXPOSURE, ASSERTED NOT ASSUMED: the newest row was appended after this "
            f"checkpoint (its seq {terminal_seq} > head_seq {pinned_head}), so the checkpoint "
            "says nothing about it. Its event_hash has just been rewritten and the checkpoint "
            "is STILL perfectly satisfied — there is no contradiction for anyone to find. The "
            "window is MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS (60s default) or "
            "MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS (64 default) of activity, whichever comes "
            "first. If this assertion has started failing, the window has been closed and "
            "every claim about it needs updating."
        )

        # The window closes on demand — but note precisely what that buys.
        # A checkpoint taken now freezes whatever is in the row, forgery
        # included. It bounds how long a rewrite stays possible; it does not
        # repair one that already happened, which is exactly why the interval
        # is the number a customer should be quoted.
        closed = _force_checkpoint(memtara_server, desk)
        assert closed["head_seq"] >= terminal_seq
        # Monotone once true, so this cannot race: a row that is covered
        # stays covered.
        assert _covering(memtara_server, terminal_seq)["covered"] is True
        assert _row_hash(terminal_seq) == FORGED, "sanity: still forged at the moment of pinning"
        assert _b64url(closed["head_event_hash"]) == FORGED, (
            "a checkpoint pins what is there at the time; it does not validate it retroactively, "
            "and this is why the interval — not the checkpoint's existence — is the number that "
            "matters to a customer"
        )
    finally:
        # Put the row back, then leave the deployment reporting the truth.
        #
        # Restoring alone is not enough, and the reason is worth stating: the
        # checkpoint taken above committed to the FORGED value, so once the
        # row is restored that checkpoint permanently contradicts the
        # database. It is right that it does — the row did change — but it
        # must not be left as the NEWEST checkpoint, or every later reader of
        # `GET /audit/integrity` inherits an alarm raised by this test rather
        # than by an attacker. So: restore, append one real audited event to
        # move the head, and pin that. The contradicting checkpoint stays on
        # record where it belongs, in the middle of the run.
        _set_event_hash(terminal_seq, original)
        try:
            _advance_the_chain(memtara_server, desk)
            _force_checkpoint(memtara_server, desk)
        except Exception:  # pragma: no cover - best-effort tidy-up
            pass


def test_the_published_checkpoint_is_verifiable_without_this_server(memtara_server, make_desk):
    """"Published" is the word doing the work in "signed, published
    checkpoint". This asserts the published half is real: the checkpoint is
    reachable with NO credential, carries its own signed bytes, and names
    where to get the key — so a counterparty can pin the head today and
    contradict us tomorrow.

    UPDATED FOR THE ANCHORING STAGE: this test used to assert
    `published["external_anchor"] is None` — true when nothing anchored
    checkpoints yet (`audit_checkpoints.anchor_target` was null on every
    row, migration 0008). That capability now exists
    (`backend/api/src/audit/anchor.rs`, migration 0012,
    `tests/break_it/test_attack_12_rewrite_history.py`), so a bare `is None`
    would be asserting the OLD absence of a feature that has since landed —
    exactly the "world changed, test kept lying" trap the stage plan warns
    about. `external_anchor` is a required object now, never `None`
    (`checkpoint.rs::ExternalAnchorResponse`); what this test asserts is
    the shape it always carries and the fact that a JUST-signed checkpoint
    is honestly reported `pending` rather than silently invented an
    anchor — the anchoring sweep is deliberately not inline with checkpoint
    creation (`anchor.rs`'s header explains why), so "pending" immediately
    after `POST /audit/checkpoints` is the correct, honest answer, not a
    residual gap in this test.
    """
    desk = make_desk(memtara_server, isin="XS0000000091")
    _run_assessment(memtara_server, desk)
    _force_checkpoint(memtara_server, desk)

    # No Authorization header anywhere in this call, deliberately.
    published = _latest_checkpoint(memtara_server)
    claims = _verify_checkpoint_signature(published)

    assert claims["chain"] == "memtara.audit_log.global.v1"
    assert claims["head_seq"] == published["head_seq"]
    assert claims["covered_row_count"] == published["covered_row_count"]
    assert claims["checkpoint_no"] == published["checkpoint_no"], (
        "the monotonic counter is inside the signature, so an older checkpoint cannot be "
        "renumbered and replayed as the current one"
    )

    anchor = published["external_anchor"]
    assert anchor is not None, (
        "external_anchor is a required field now (one of anchored/pending/overdue) — a bare "
        "absence would blur 'not yet anchored' back into 'no such capability', which is exactly "
        "the distinction B2 exists to keep visible"
    )
    assert anchor["status"] in ("anchored", "pending", "overdue"), anchor
    if anchor["status"] == "pending":
        # The expected case immediately after POST /audit/checkpoints: the
        # background sweep (or an explicit POST /audit/anchors/sweep, which
        # this test does not call) has not necessarily reached this
        # checkpoint yet, and that is not a finding — see anchor.rs's
        # header on why anchoring is deliberately not inline.
        assert "age_seconds" in anchor
    elif anchor["status"] == "anchored":
        # Also a legitimate outcome (a concurrent sweep from another actor
        # against this shared deployment could have reached it first); if
        # so, the receipt must actually be there.
        assert anchor.get("receipt_der_base64"), anchor
