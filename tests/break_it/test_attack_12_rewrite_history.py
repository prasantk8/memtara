"""Attack #12 — rewrite history, from genesis, and re-sign the head.

    ATTACK: `audit/checkpoint.rs`'s own header names it: "with DB access and
    the org's signing key, rewrite the log from genesis, recompute every
    hash, re-sign the head." Before the anchoring work in this stage, that
    produced a self-consistent forgery every internal check passed — the
    checkpoint mechanism (migration 0008) is itself signed with the SAME key
    the attacker holds, so a checkpoint over a rewritten log is just as
    validly signed as a checkpoint over the real one. Attack #7 closed
    "delete our own checkpoints and present an old one as current"; it did
    nothing about "delete our own checkpoints AND write a new, correctly
    signed one over a rewritten log", because nothing before this stage held
    a copy of anything outside the organisation's own database and key.

    WHAT CLOSES IT: external anchoring (`backend/api/src/audit/anchor.rs`,
    migration 0012). A checkpoint's digest is timestamped by an RFC 3161
    authority the attacker does not control. The attacker can rewrite the
    database and mint a new, validly-signed checkpoint over the rewritten
    head — that part of the attack still WORKS, and this test asserts that
    explicitly rather than skipping past it. What the attacker cannot do is
    make the ORIGINAL timestamp authority backdate a receipt for the NEW,
    rewritten head — the original anchor's `messageImprint` is a fixed
    SHA-256 of the ORIGINAL checkpoint's bytes, obtained and held before the
    attack, and a rewritten head hashes to something else.

    THIS TEST PROVES, against a real server, a real Postgres, and a real
    freetsa.org RFC 3161 exchange — TWO facts, in this order on purpose:

      1. THE TRAP: after rewriting audit_log rows via direct SQL and minting
         a new checkpoint signed with the deployment's own key over the
         rewritten head, `GET /audit/integrity` reports the chain INTACT —
         linkage holds, the head hash matches the (also forged) new
         checkpoint, the row count matches. Every check that does not reach
         outside this database is fooled. Asserted explicitly, not implied,
         because a test that jumped straight to "and then it's caught"
         would be quietly overstating what internal checks can see — the
         same trap `test_attack_07`'s test 2 names for the terminal-row
         forgery this checkpoint mechanism was built to catch, one level up.

      2. THE BETRAYAL: the ORIGINAL checkpoint — signed and anchored BEFORE
         the attack, held independently the way a real auditor would hold
         it (its JWS, and its RFC 3161 receipt, fetched and verified here
         with this test's own cryptography, not asked of the now-compromised
         server) — disagrees with the post-attack database at the exact row
         it pinned. The anchor receipt is independently re-verified against
         the pinned TSA root (the same check `scripts/bundle/rfc3161.py`
         performs offline for a bundle) and shown to commit to the ORIGINAL
         head, which the rewritten chain no longer produces.

    THE RESIDUAL, stated plainly because it is real and it is not zero:
    rows appended AND rewritten entirely BETWEEN the last anchor and the
    next one — inside the combined checkpoint-then-anchoring-sweep cadence
    window — are still forgeable, exactly as `test_attack_07`'s test 3
    proves for the checkpoint-only case one layer down. Anchoring does not
    close the window; it narrows it from "all of history, indefinitely,
    until someone happens to check" to "one anchoring cadence". The second
    test in this file performs that narrower attack and asserts it still
    succeeds, for the same reason attack #7 keeps its own honest failure on
    the record rather than letting the header's claim run ahead of the code.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 12
BREAK_IT_ATTACK_TITLE = "Rewrite history, from genesis, and re-sign the head"
BREAK_IT_KIND = "runnable"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = (
    "a rewritten log with a freshly re-signed checkpoint over it passes every internal check "
    "(linkage, head hash, row count) — asserted explicitly as the trap, not skipped past. What "
    "stops it: the ORIGINAL checkpoint, anchored via RFC 3161 before the attack and held "
    "independently, disagrees with the rewritten chain at the exact row it pinned, and its "
    "anchor receipt verifies against a pinned TSA root the attacker's database access cannot "
    "touch. RESIDUAL: rows appended and rewritten entirely between the last anchor and the "
    "next sweep are still forgeable — the window shrank from all of history to one anchoring "
    "cadence, not to zero."
)

import base64
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.bundle.jwks import okp_thumbprint
from scripts.bundle.rfc3161 import verify_token as verify_rfc3161_token

from conftest import db_connect

DEFAULT_ANCHOR_CA_FILE = REPO_ROOT / "scripts" / "bundle" / "pinned_anchors" / "freetsa_root_ca.pem"

CHAIN_ID = "memtara.audit_log.global.v1"
CHECKPOINT_TYP = "memtara-audit-checkpoint+jwt"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _advance_the_chain(base_url: str, desk) -> None:
    """One cheap, real audited event — a product registration, needing
    neither `bb` nor `nargo` — so the chain head moves without the cost of a
    full proof. Mirrors attack #7's identical helper.
    """
    resp = httpx.post(
        f"{base_url}/api/v1/products",
        json={
            "product_isin": "XS%010d" % (uuid.uuid4().int % 10**10),
            "product_name": "attack 12 chain advance",
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


def _force_checkpoint(base_url: str, desk) -> dict:
    resp = httpx.post(
        f"{base_url}/audit/checkpoints", headers={"Authorization": f"Bearer {desk.api_key}"}, timeout=15.0
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checkpoint"] is not None, body["note"]
    return body["checkpoint"]


def _sweep_until_anchored(base_url: str, desk, head_seq: int, *, attempts: int = 5) -> dict:
    """`POST /audit/anchors/sweep` is a real call to freetsa.org — this test
    does not mock the TSA, per the house rule that break-it attacks run
    against the real system. A retry loop around a single external service
    call is resilience against an ordinary network hiccup, not an
    accommodation of a product defect (trap #4's distinction) — the anchor
    mechanism's own retry story (`anchor.rs`'s header) is exactly "the sweep
    retries", so this loop is that same behaviour, driven on demand instead
    of waiting out the background interval.

    `head_seq` (not `checkpoint_no`) identifies the checkpoint to watch,
    via `GET /audit/checkpoints/covering/:seq` — the checkpoint whose
    `head_seq` exactly equals the seq asked for is the checkpoint that
    pinned it (`checkpoint::covering`'s "earliest checkpoint whose head_seq
    >= seq" rule picks it uniquely), which stays correct even after later
    checkpoints exist.
    """
    last_status = None
    for _ in range(attempts):
        resp = httpx.post(
            f"{base_url}/audit/anchors/sweep", headers={"Authorization": f"Bearer {desk.api_key}"}, timeout=30.0
        )
        assert resp.status_code == 200, resp.text
        covering = httpx.get(f"{base_url}/audit/checkpoints/covering/{head_seq}", timeout=15.0).json()
        assert covering["covered"] is True, covering
        checkpoint = covering["checkpoint"]
        assert checkpoint["head_seq"] == head_seq, checkpoint
        last_status = checkpoint["external_anchor"]["status"]
        if last_status == "anchored":
            return checkpoint
        time.sleep(1.0)
    pytest.fail(
        f"the checkpoint over seq {head_seq} did not reach 'anchored' after {attempts} sweeps "
        f"against a real TSA (last status: {last_status}). This is a real network dependency "
        "(freetsa.org) and a genuine outage would fail this loudly rather than silently skip, "
        "per house style — if freetsa.org is down, that is the finding."
    )


def _sign_checkpoint_jws(claims: dict, *, seed: bytes, kid: str) -> str:
    """Build a compact JWS exactly the way `IssuerKey::sign_compact_jws`
    does (`backend/api/src/crypto/signer.rs`): EdDSA over
    `base64url(header) + "." + base64url(payload)`. This is the forging
    step of the attack — the attacker holds the seed (this test's known
    `TEST_PRIVATE_KEY_B64`, standing in for a stolen `MEMTARA_PRIVATE_KEY`)
    and can sign anything.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    header = {"alg": "EdDSA", "typ": CHECKPOINT_TYP, "kid": kid}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(signing_input)
    return f"{signing_input.decode('ascii')}.{_b64url(signature)}"


def _rewrite_chain_from_seq(from_seq: int, to_seq: int) -> dict[int, bytes]:
    """THE ATTACK'S DATABASE HALF: recompute a NEW, internally-consistent
    hash chain over `audit_log` rows `from_seq..=to_seq`, direct SQL, no
    application code involved. Each row's `prev_hash` is set to the row
    immediately before it's NEW `event_hash` — exactly what
    `append_locked_encoded` would have produced had this fabricated history
    actually happened. Returns `{seq: new_event_hash}`.

    The attacker does not need to know any row's original payload (it was
    never stored, by design — `audit/mod.rs`) to do this: linkage only
    checks that hashes point at each other, not that they are a function of
    real content nobody outside the process ever sees.
    """
    conn = db_connect()
    try:
        rows = conn.run(
            "select seq from audit_log where seq >= :a and seq <= :b order by seq asc",
            a=from_seq, b=to_seq,
        )
        seqs = [int(r[0]) for r in rows]
        assert seqs, f"no audit_log rows in [{from_seq}, {to_seq}] to rewrite"

        prev_hash: bytes | None = None
        # The row immediately before the rewritten window keeps its real,
        # untouched event_hash — the forged chain re-links to genuine
        # history at its boundary, the same way a real "rewrite everything
        # after some point" attack would.
        boundary = conn.run("select event_hash from audit_log where seq < :s order by seq desc limit 1", s=from_seq)
        if boundary:
            prev_hash = bytes(boundary[0][0])

        new_hashes: dict[int, bytes] = {}
        for seq in seqs:
            forged = hashlib.sha256(f"attack-12-forged-row-{seq}-{uuid.uuid4()}".encode()).digest()
            conn.run(
                "update audit_log set event_hash = :h, prev_hash = :p where seq = :s",
                h=forged, p=prev_hash, s=seq,
            )
            new_hashes[seq] = forged
            prev_hash = forged
        return new_hashes
    finally:
        conn.close()


def _covered_row_count(head_seq: int) -> int:
    conn = db_connect()
    try:
        rows = conn.run("select count(*) from audit_log where seq <= :s", s=head_seq)
        return int(rows[0][0])
    finally:
        conn.close()


def _insert_forged_checkpoint(*, jws: str, claims: dict) -> None:
    conn = db_connect()
    try:
        checkpoint_hash = hashlib.sha256(jws.encode("ascii")).digest()
        conn.run(
            """
            insert into audit_checkpoints
                (checkpoint_no, head_seq, head_event_hash, covered_row_count,
                 prev_checkpoint_hash, checkpoint_hash, signed_jws, kid, signed_at)
            values (:no, :head_seq, :head_hash, :count, :prev, :cphash, :jws, :kid, now())
            """,
            no=claims["checkpoint_no"],
            head_seq=claims["head_seq"],
            head_hash=_b64url_decode(claims["head_event_hash"]),
            count=claims["covered_row_count"],
            prev=_b64url_decode(claims["prev_checkpoint_hash"]) if claims.get("prev_checkpoint_hash") else None,
            cphash=checkpoint_hash,
            jws=jws,
            kid=claims["_kid"],
        )
    finally:
        conn.close()


@pytest.fixture()
def signer_material():
    """The deployment's own signing key, as the attacker would hold it —
    `TEST_PRIVATE_KEY_B64` from the root conftest is the fixed 32-byte seed
    every fixture in this suite already boots the server with
    (`bytes(range(32))`), so this is not a second, separately-invented key:
    it IS the key `MEMTARA_PRIVATE_KEY` is set to for every server this
    suite runs against.
    """
    seed = bytes(range(32))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes_raw()
    x = _b64url(public_bytes)
    kid = okp_thumbprint(x)
    return seed, kid


def test_a_rewritten_and_resigned_history_passes_local_checks_but_the_anchor_betrays_it(
    memtara_server, make_desk, signer_material
):
    seed, kid = signer_material
    desk = make_desk(memtara_server, isin="XS0000000120")

    # --- honest history, checkpointed and anchored -------------------------
    _advance_the_chain(memtara_server, desk)
    original_checkpoint = _force_checkpoint(memtara_server, desk)
    original_head_seq = original_checkpoint["head_seq"]
    original_head_hash = original_checkpoint["head_event_hash"]
    original_jws = original_checkpoint["jws"]

    anchored = _sweep_until_anchored(memtara_server, desk, original_head_seq)
    assert anchored["external_anchor"]["status"] == "anchored", anchored
    original_receipt_b64 = anchored["external_anchor"]["receipt_der_base64"]
    assert original_receipt_b64, "an 'anchored' checkpoint must carry receipt_der_base64"

    # More activity after the anchor, so the rewrite below covers rows both
    # inside and outside the anchored range — "from genesis" in spirit: the
    # attacker rewrites everything they can reach, not just the newest row.
    _advance_the_chain(memtara_server, desk)
    conn = db_connect()
    try:
        terminal_seq = int(conn.run("select max(seq) from audit_log")[0][0])
    finally:
        conn.close()
    assert terminal_seq > original_head_seq, "there must be activity after the anchored checkpoint too"

    # --- THE ATTACK: direct SQL, no application code ------------------------
    #
    # Scoped to THIS test's own window (`original_head_seq..terminal_seq`),
    # not the whole global chain back to row 1: the attacker COULD reach
    # further back — nothing about `_rewrite_chain_from_seq` stops at any
    # particular row, which is the point — but `audit_log` is a single chain
    # shared with every other tenant and every other concurrently-running
    # test in this suite (audit/mod.rs's header explains why it is global).
    # Rewriting the row the ORIGINAL anchor pinned is sufficient to prove
    # the mechanism; rewriting a live neighbour's history to prove it would
    # be an unrelated, avoidable act of collateral damage.
    #
    # Snapshotted first so the whole attack — forgery, assertions, and a
    # forged checkpoint row that would otherwise become "latest" for every
    # subsequent request against this shared deployment — is undone in a
    # `finally`, the same restore discipline `test_attack_07`'s test 3 uses.
    conn = db_connect()
    try:
        snapshot_rows = conn.run(
            "select seq, event_hash, prev_hash from audit_log where seq >= :a and seq <= :b order by seq asc",
            a=original_head_seq, b=terminal_seq,
        )
        snapshot = {int(r[0]): (bytes(r[1]), bytes(r[2]) if r[2] is not None else None) for r in snapshot_rows}
    finally:
        conn.close()

    forged_checkpoint_no: int | None = None
    try:
        new_hashes = _rewrite_chain_from_seq(original_head_seq, terminal_seq)
        forged_terminal_hash = new_hashes[terminal_seq]
        forged_covered_row_count = _covered_row_count(terminal_seq)

        latest_before_forgery = httpx.get(f"{memtara_server}/audit/checkpoints/latest", timeout=15.0).json()
        forged_checkpoint_no = latest_before_forgery["checkpoint_no"] + 1
        forged_claims = {
            "iss": memtara_server,
            "chain": CHAIN_ID,
            "checkpoint_no": forged_checkpoint_no,
            "head_seq": terminal_seq,
            "head_event_hash": _b64url(forged_terminal_hash),
            "covered_row_count": forged_covered_row_count,
            "prev_checkpoint_hash": latest_before_forgery["checkpoint_hash"],
            "iat": int(time.time()),
        }
        forged_jws = _sign_checkpoint_jws(forged_claims, seed=seed, kid=kid)
        _insert_forged_checkpoint(jws=forged_jws, claims={**forged_claims, "_kid": kid})

        # -------------------------------------------------------------
        # 1. THE TRAP, asserted explicitly: every internal check is fooled.
        # -------------------------------------------------------------
        integrity = httpx.get(
            f"{memtara_server}/audit/integrity", headers={"Authorization": f"Bearer {desk.api_key}"}, timeout=15.0
        ).json()
        assert integrity["checkpoint"]["checkpoint_no"] == forged_claims["checkpoint_no"], (
            "the forged checkpoint must be the one the server now calls latest"
        )
        assert integrity["intact"] is True, (
            f"THE TRAP: a rewritten log with a freshly re-signed checkpoint over it must pass "
            f"every internal check — linkage, head hash, row count — because nothing inside this "
            f"database can distinguish a real history from a self-consistent fake one. Got: {integrity}"
        )
        assert integrity["checkpoint"]["failures"] == [], integrity["checkpoint"]["failures"]
        latest_after_forgery = httpx.get(f"{memtara_server}/audit/checkpoints/latest", timeout=15.0).json()
        assert latest_after_forgery["head_event_hash"] == _b64url(forged_terminal_hash), (
            "the server's own unauthenticated /latest endpoint now serves the forged head as "
            "current — this is the whole point: an insider with DB + key access owns the "
            "deployment's own story"
        )

        # -------------------------------------------------------------
        # 2. THE BETRAYAL: the ORIGINAL, anchored checkpoint — held
        #    independently, from BEFORE the attack — disagrees with the
        #    current database, and its anchor verifies against a pinned TSA
        #    root the attack never touched.
        # -------------------------------------------------------------
        # Re-verify the original checkpoint's own signature (it is still a
        # validly signed statement — the attacker didn't need to and
        # couldn't un-sign it) and then check it against the CURRENT
        # (rewritten) chain.
        header_b64, payload_b64, sig_b64 = original_jws.split(".")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        jwks = httpx.get(original_checkpoint["jwks_url"], timeout=15.0).json()
        key = next(k for k in jwks["keys"] if k["kid"] == original_checkpoint["kid"])
        Ed25519PublicKey.from_public_bytes(_b64url_decode(key["x"])).verify(
            _b64url_decode(sig_b64), f"{header_b64}.{payload_b64}".encode()
        )

        conn = db_connect()
        try:
            rows = conn.run("select event_hash from audit_log where seq = :s", s=original_head_seq)
        finally:
            conn.close()
        current_event_hash_at_original_head = bytes(rows[0][0])
        assert _b64url(current_event_hash_at_original_head) != original_head_hash, (
            "sanity: the rewrite must have touched the row the original checkpoint pinned, or "
            "this test is not exercising the attack it claims to"
        )

        # This is the contradiction an auditor who kept only the original
        # checkpoint (no anchor needed yet) can already see: a
        # validly-signed statement about seq `original_head_seq` that the
        # current database no longer agrees with. Attack #7 already stops
        # here for a BARE rewrite. What #12 adds is that the attacker did
        # not stop at a bare rewrite — they also replaced /latest with a
        # new, validly-signed checkpoint that says the NEW state is fine.
        # An auditor asking the (compromised) server "is your latest
        # checkpoint intact?" gets "yes" (see part 1). The anchor is what
        # lets them not have to ask the server at all.
        token_der = base64.b64decode(original_receipt_b64)
        expected_digest = hashlib.sha256(original_jws.encode("ascii")).digest()
        pinned_ca_pem = DEFAULT_ANCHOR_CA_FILE.read_bytes()
        finding = verify_rfc3161_token(
            token_der,
            expected_digest=expected_digest,
            expected_digest_algorithm="sha256",
            pinned_ca_pem=pinned_ca_pem,
        )
        assert finding.ok, (
            f"the ORIGINAL checkpoint's anchor receipt must independently verify against the "
            f"pinned TSA root — the attacker never touched freetsa.org, so this must hold "
            f"regardless of anything the compromised server now claims: {finding}"
        )
        assert finding.message_imprint_matches is True
    finally:
        # Undo the attack: delete the forged checkpoint (or it becomes
        # "latest" for every request against this shared deployment from
        # here on) and restore every rewritten row's original event_hash
        # and prev_hash — this suite runs against a database other engines'
        # concurrent work and future test runs both depend on.
        conn = db_connect()
        try:
            if forged_checkpoint_no is not None:
                conn.run("delete from audit_checkpoints where checkpoint_no = :no", no=forged_checkpoint_no)
            for seq, (event_hash, prev_hash) in snapshot.items():
                conn.run(
                    "update audit_log set event_hash = :h, prev_hash = :p where seq = :s",
                    h=event_hash, p=prev_hash, s=seq,
                )
        finally:
            conn.close()

    # The externally-witnessed fact and the compromised server's current
    # story are about the SAME position (original_head_seq / same
    # checkpoint_no) and DISAGREE. That disagreement is unreachable by
    # anything the attacker's database access or stolen key can silence —
    # neither touches freetsa.org's copy.
    assert latest_after_forgery["checkpoint_no"] != original_checkpoint["checkpoint_no"] or (
        latest_after_forgery["head_event_hash"] != original_head_hash
    )
    server_now_claims_head_hash_at_original_position = _b64url(current_event_hash_at_original_head)
    assert server_now_claims_head_hash_at_original_position != original_head_hash, (
        "THE BETRAYAL: the externally-anchored original head_event_hash "
        f"({original_head_hash}) does not match what the database — under the attacker's "
        f"control — now says was at that position "
        f"({server_now_claims_head_hash_at_original_position}). An auditor holding nothing but "
        "the original checkpoint's JWS and its RFC 3161 receipt, obtained before the attack, "
        "detects the rewrite without asking the compromised server anything."
    )


def test_a_rewrite_strictly_inside_the_anchoring_cadence_is_still_undetectable(memtara_server, make_desk):
    """THE RESIDUAL, attacked and asserted rather than merely described.

    A row created AND rewritten entirely between one anchor and the next —
    inside the combined checkpoint-then-sweep window — has never been
    checkpointed at all, so nothing (not linkage, not a checkpoint, not an
    anchor that does not exist yet) commits to it. This is exactly
    `test_attack_07`'s test 3, one layer up: anchoring narrows the window
    from "all of history" to "one cadence", and this test proves the
    narrower window is still real rather than letting the header's claim
    outrun what the code does.
    """
    desk = make_desk(memtara_server, isin="XS0000000121")
    _advance_the_chain(memtara_server, desk)
    checkpoint = _force_checkpoint(memtara_server, desk)
    pinned_head = checkpoint["head_seq"]

    # A decision arrives after the checkpoint — outside its covered range by
    # construction, and (by never anchoring this tick) outside any anchor's
    # coverage either.
    _advance_the_chain(memtara_server, desk)
    conn = db_connect()
    try:
        terminal_seq = int(conn.run("select max(seq) from audit_log")[0][0])
    finally:
        conn.close()
    assert terminal_seq > pinned_head

    conn = db_connect()
    try:
        original_hash = bytes(conn.run("select event_hash from audit_log where seq = :s", s=terminal_seq)[0][0])
    finally:
        conn.close()

    forged = hashlib.sha256(f"attack-12-residual-{uuid.uuid4()}".encode()).digest()
    conn = db_connect()
    try:
        conn.run("update audit_log set event_hash = :h where seq = :s", h=forged, s=terminal_seq)
    finally:
        conn.close()

    try:
        integrity = httpx.get(
            f"{memtara_server}/audit/integrity", headers={"Authorization": f"Bearer {desk.api_key}"}, timeout=15.0
        ).json()
        assert integrity["intact"] is True, (
            "RESIDUAL, ASSERTED NOT ASSUMED: a row appended and forged strictly after the last "
            f"checkpoint (and therefore never anchored) is still undetectable: {integrity}"
        )
        assert integrity["uncovered_rows"] >= 1
    finally:
        # Restore, advance, and checkpoint again so this test does not leave
        # the deployment reporting a stale contradiction to the next reader
        # — same discipline as attack #7's test 3.
        conn = db_connect()
        try:
            conn.run("update audit_log set event_hash = :h where seq = :s", h=original_hash, s=terminal_seq)
        finally:
            conn.close()
        try:
            _advance_the_chain(memtara_server, desk)
            _force_checkpoint(memtara_server, desk)
        except Exception:  # pragma: no cover - best-effort tidy-up
            pass
