"""End-to-end proof that Memtara and AIHOOTS integrate without talking to each other.

The claim under test, stated precisely:

    A bank's LLM front door can establish that a consumer satisfies a
    regulated predicate, inject that fact into the model's context, and write
    a tamper-evident record of having done so — using nothing but Memtara's
    published public key. No synchronous call to Memtara. No shared secret.

Everything below runs against real components. The Memtara server is the
actual compiled Rust binary against a real Postgres, serving a real JWKS from a
real Ed25519 key and signing real tokens. The AIHOOTS side is the actual
`src.gateway.main` app, the actual `AuditChain`, and the actual
`src.verifier.cli.verify` — all imported from the pinned submodule at
`tests/aihoots_reference`, not reimplemented here.

Two seams are deliberate and documented rather than hidden:

1.  **The upstream model is stubbed.** That is AIHOOTS's own testing policy
    (their ADR-004: stubbed upstream in CI, real SLM locally) and this test
    follows it rather than inventing a different one. Nothing about the
    handshake depends on what the model replies.

2.  **The verified proof row is seeded directly into Postgres.** Producing a
    genuinely valid Barretenberg proof requires client-side witness generation
    and Baby Jubjub EdDSA signing — explicitly out of scope for this backend
    (`ARCHITECTURE.md`, `HANDOFF.md`), because a server that could generate
    proofs would be a server holding plaintext. The seed stands in for the
    device-side prover at exactly the boundary the architecture already draws,
    and it is the same stand-in `verify::tests::db` uses in Rust.

    Note what is NOT stubbed by that seam: the token is minted by the real
    server, signed by the real key, and validated against the real published
    JWKS. Every assertion below is about the attestation layer, and the
    attestation layer is entirely real.

Run:
    DATABASE_URL=postgres://memtara:memtara@localhost:5433/memtara \\
    PATH="$HOME/.cargo/bin:$HOME/.bb:$PATH" \\
    .venv/bin/pytest tests/test_aihoots_handshake.py -v
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import httpx
import pytest

# Path setup, the compiled binary and the running server all live in
# conftest.py, shared with test_wealth_suitability_e2e.py so both files
# exercise one definition of "the server under test".
from conftest import TEST_PRIVATE_KEY_B64, db_connect  # noqa: F401

from integrations.aihoots.memtara_claims import (  # noqa: E402
    PROOF_HEADER,
    JwksCache,
    MemtaraAttestationMiddleware,
    ProofTokenError,
    validate_proof_token,
)

PREDICATE = "income_gte_threshold"
EXPECTED_CIRCUIT = "tax_session"

# Stand-in for the proof a device-side prover would produce (see module
# docstring, seam 2). Its *bytes* are what the issuer hashes into the
# `proof_hash` claim, so the test can compute the expected hash independently.
FAKE_PROOF_BYTES = b"memtara-handshake-test-proof-bytes"


# ---------------------------------------------------------------------------
# Environment probing — every prerequisite skips with a specific reason rather
# than failing, so a missing local tool never looks like a broken integration.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def seeded(memtara_server: str):
    """An org, a user, and a fulfilled disclosure request with a verified proof.

    The org is created through the real API (so its API key is a real one,
    hashed the real way). Only the proof row — the thing an out-of-scope
    device-side prover would produce — is seeded directly.
    """
    org = httpx.post(
        f"{memtara_server}/orgs",
        json={"name": f"CBUAE Demo Bank {uuid.uuid4().hex[:8]}", "org_type": "bank"},
        timeout=10.0,
    )
    assert org.status_code == 201, org.text
    org_body = org.json()

    conn = db_connect()
    user_id = uuid.uuid4()
    request_id = uuid.uuid4()
    try:
        conn.run(
            "insert into users (id, phone_e164) values (:id, :phone)",
            id=str(user_id),
            phone=f"+9715{uuid.uuid4().int % 10**8:08d}",
        )
        conn.run(
            """
            insert into disclosure_requests
                (id, org_id, user_id, circuit_type, policy, status, nonce, expires_at)
            values
                (:id, :org_id, :user_id, :circuit, :policy, 'fulfilled', :nonce, now() + interval '1 hour')
            """,
            id=str(request_id),
            org_id=org_body["id"],
            user_id=str(user_id),
            circuit=EXPECTED_CIRCUIT,
            policy=json.dumps({"session_type": "TaxSession", "constraints": []}),
            nonce=bytes(32),
        )
        conn.run(
            """
            insert into proofs (request_id, public_inputs, proof_bytes, valid)
            values (:request_id, :public_inputs, :proof, true)
            """,
            request_id=str(request_id),
            public_inputs=json.dumps(["0x01"]),
            proof=FAKE_PROOF_BYTES,
        )

        yield {
            "org_id": org_body["id"],
            "api_key": org_body["api_key"],
            "user_id": str(user_id),
            "request_id": str(request_id),
            "issuer": memtara_server,
        }
    finally:
        for statement, params in [
            ("delete from audit_log where ref_id = :rid", {"rid": str(request_id)}),
            ("delete from proofs where request_id = :rid", {"rid": str(request_id)}),
            ("delete from disclosure_requests where id = :rid", {"rid": str(request_id)}),
            ("delete from users where id = :uid", {"uid": str(user_id)}),
            ("delete from organizations where id = :oid", {"oid": org_body["id"]}),
        ]:
            try:
                conn.run(statement, **params)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        conn.close()


def issue_token(memtara_server: str, seeded: dict) -> dict:
    """Ask the real server for a real attestation."""
    response = httpx.post(
        f"{memtara_server}/api/v1/issue-proof",
        json={"user_id": seeded["user_id"], "predicate": PREDICATE},
        headers={"Authorization": f"Bearer {seeded['api_key']}"},
        timeout=30.0,
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture()
def token(memtara_server: str, seeded: dict) -> dict:
    return issue_token(memtara_server, seeded)


@pytest.fixture()
def jwks(memtara_server: str) -> JwksCache:
    cache = JwksCache(f"{memtara_server}/.well-known/jwks.json")
    cache.load()
    return cache


# ---------------------------------------------------------------------------
# The AIHOOTS side: the real gateway, plus the Memtara middleware this repo
# ships, writing into the real hash chain.
# ---------------------------------------------------------------------------


@pytest.fixture()
def gateway(tmp_path, monkeypatch, jwks: JwksCache, memtara_server: str):
    """AIHOOTS's real gateway app with Memtara attestation wired in.

    The middleware rewrites the request body before it reaches AIHOOTS's own
    handler, so the injected system message is genuinely part of what the
    gateway forwards upstream — asserted below by capturing the forwarded
    payload, not by inspecting our own middleware's variables.
    """
    from fastapi.testclient import TestClient

    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AIHOOTS_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("AIHOOTS_UPSTREAM_BASE_URL", "http://stub-upstream")

    import importlib

    import src.gateway.config as gateway_config

    importlib.reload(gateway_config)
    import src.gateway.main as gateway_main

    importlib.reload(gateway_main)
    from src.gateway.audit.chain import new_event

    forwarded: list[dict] = []

    async def fake_post(self, url, json=None, **kwargs):  # noqa: A002
        forwarded.append(json)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "stub reply"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    # The integration, wired exactly as a bank would wire it: AIHOOTS's real
    # app, its real hash chain, and the middleware this repo ships. Nothing in
    # the gateway is modified — it is wrapped.
    wrapped = MemtaraAttestationMiddleware(
        gateway_main.app,
        jwks=jwks,
        expected_issuer=memtara_server,
        audit_append=gateway_main._chain.append,
        event_factory=new_event,
        seen_jti=set(),
    )

    yield {
        "client": TestClient(wrapped),
        "audit_path": audit_path,
        "forwarded": forwarded,
    }


def read_audit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# 1. Memtara issues an attestation that verifies against its published key
# ---------------------------------------------------------------------------


def test_jwks_publishes_an_ed25519_key(memtara_server: str):
    response = httpx.get(f"{memtara_server}/.well-known/jwks.json", timeout=10.0)
    assert response.status_code == 200
    key = response.json()["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert key["alg"] == "EdDSA"
    assert key["use"] == "sig"
    assert len(base64.urlsafe_b64decode(key["x"] + "==")) == 32


def test_issued_token_validates_against_the_published_jwks(token, jwks, memtara_server):
    assert token["expires_in"] == 300

    proof = validate_proof_token(
        token["proof_token"], jwks, expected_issuer=memtara_server
    )

    assert proof.predicate == PREDICATE
    assert proof.circuit == EXPECTED_CIRCUIT
    assert proof.raw_claims["verified"] is True
    assert proof.regulatory_audit_id == token["regulatory_audit_id"]

    # The proof_hash must be the SHA-256 of the exact bytes that were verified,
    # computed here from the seed rather than read back from the token — so
    # this asserts the binding, not just self-consistency.
    import hashlib

    assert proof.proof_hash == hashlib.sha256(FAKE_PROOF_BYTES).hexdigest()

    # The clauses the matrix says this predicate is evidence for.
    assert "5(c)" in proof.cbuae_clauses


def test_issuance_is_recorded_in_memtaras_own_hash_chain(memtara_server, seeded, token):
    log = httpx.get(
        f"{memtara_server}/orgs/{seeded['org_id']}/audit-log",
        headers={"Authorization": f"Bearer {seeded['api_key']}"},
        timeout=10.0,
    )
    assert log.status_code == 200
    entries = log.json()
    assert any(e["event_type"] == "proof_token_issued" for e in entries)

    # Each entry must carry the previous entry's hash — Memtara's chain, read
    # through its own API, before AIHOOTS is involved at all.
    for previous, current in zip(entries, entries[1:]):
        assert current["prev_hash"] == previous["event_hash"]


# ---------------------------------------------------------------------------
# 2. The handshake itself
# ---------------------------------------------------------------------------


def test_end_to_end_handshake(gateway, token, jwks, memtara_server):
    """Memtara issues, AIHOOTS validates offline, injects, and audits."""
    response = gateway["client"].post(
        "/v1/chat/completions",
        headers={PROOF_HEADER: token["proof_token"], "x-caller-id": "mortgage-desk"},
        json={
            "model": "qwen2.5:3b-instruct",
            "messages": [{"role": "user", "content": "Can this applicant proceed to pre-approval?"}],
        },
    )
    assert response.status_code == 200, response.text
    assert "aihoots_request_id" in response.json()

    # (a) The claims reached the model. Asserted against what the gateway
    #     actually forwarded upstream, captured in the stubbed transport.
    assert gateway["forwarded"], "nothing was forwarded upstream"
    forwarded_messages = gateway["forwarded"][0]["messages"]
    assert forwarded_messages[0]["role"] == "system"
    preamble = forwarded_messages[0]["content"]
    assert PREDICATE in preamble
    assert "NOT disclosed" in preamble
    # The original user turn survives, unmodified and still attributed to them.
    assert forwarded_messages[-1] == {
        "role": "user",
        "content": "Can this applicant proceed to pre-approval?",
    }

    # (b) The proof hash and the correlation id are in AIHOOTS's chain.
    events = read_audit(gateway["audit_path"])
    attestations = [e for e in events if e["event_type"] == "attestation"]
    assert len(attestations) == 1
    detail = attestations[0]["detail"]
    assert detail["memtara_verified"] is True
    assert detail["proof_hash"]
    assert detail["regulatory_audit_id"] == token["regulatory_audit_id"]
    assert detail["cbuae_clauses"]

    # (c) AIHOOTS's own policy and response events are there too — the
    #     attestation joined the existing trail rather than replacing it.
    assert any(e["event_type"] == "decision" for e in events)
    assert any(e["event_type"] == "response" for e in events)

    # (d) The chain is intact, according to AIHOOTS's own verifier.
    from src.verifier.cli import verify

    assert verify(str(gateway["audit_path"])) == []


def test_validation_makes_no_call_to_memtara(gateway, memtara_server, seeded, jwks):
    """The zero-latency claim, tested rather than asserted.

    Ten attestations are validated after the JWKS has been cached. If any
    validation reached back to Memtara, the cache's fetch counter would move.
    """
    tokens = [issue_token(memtara_server, seeded) for _ in range(10)]
    fetches_before = jwks.fetch_count

    for issued in tokens:
        response = gateway["client"].post(
            "/v1/chat/completions",
            headers={PROOF_HEADER: issued["proof_token"]},
            json={"model": "m", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert response.status_code == 200

    assert jwks.fetch_count == fetches_before, "validation must not re-fetch the JWKS"


def test_offline_validation_survives_memtara_being_unreachable(token, memtara_server):
    """A relying party with a cached JWK Set does not need Memtara to exist.

    Simulated by pointing the cache at an address nothing listens on and
    loading it from configuration instead — the deployment shape a bank that
    forbids outbound calls from its gateway would actually use.
    """
    published = httpx.get(f"{memtara_server}/.well-known/jwks.json", timeout=10.0).json()

    offline = JwksCache("http://127.0.0.1:1/.well-known/jwks.json")
    offline.load(jwks=published)

    proof = validate_proof_token(token["proof_token"], offline, expected_issuer=memtara_server)
    assert proof.predicate == PREDICATE
    assert offline.fetch_count == 0


# ---------------------------------------------------------------------------
# 3. The forgeries a relying party must refuse
# ---------------------------------------------------------------------------


def _resegment(token_str: str, claims: dict) -> str:
    """Rebuild a token with altered claims, keeping the original signature."""
    header, _, signature = token_str.split(".")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"


def _claims_of(token_str: str) -> dict:
    payload = token_str.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_flipping_verified_to_false_breaks_the_signature(token, jwks, memtara_server):
    claims = _claims_of(token["proof_token"])
    claims["verified"] = False
    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            _resegment(token["proof_token"], claims), jwks, expected_issuer=memtara_server
        )


def test_promoting_a_predicate_breaks_the_signature(token, jwks, memtara_server):
    """The attack that matters commercially: upgrading what was proven."""
    claims = _claims_of(token["proof_token"])
    claims["predicate"] = "accredited_investor"
    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            _resegment(token["proof_token"], claims), jwks, expected_issuer=memtara_server
        )


def test_alg_none_is_refused_before_any_signature_work(token, jwks, memtara_server):
    claims = _claims_of(token["proof_token"])
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT", "kid": "whatever"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(ProofTokenError, match="unsupported alg"):
        validate_proof_token(f"{header}.{payload}.", jwks, expected_issuer=memtara_server)


def test_expired_token_is_refused(token, jwks, memtara_server):
    claims = _claims_of(token["proof_token"])
    with pytest.raises(ProofTokenError, match="expired"):
        validate_proof_token(
            token["proof_token"],
            jwks,
            expected_issuer=memtara_server,
            now=claims["exp"] + 3600,
        )


def test_token_from_a_different_issuer_is_refused(token, jwks):
    with pytest.raises(ProofTokenError, match="is not the expected"):
        validate_proof_token(
            token["proof_token"], jwks, expected_issuer="https://not-memtara.example"
        )


def test_unknown_kid_does_not_trigger_a_refetch(token, jwks):
    """An attacker-chosen kid must not be able to make us call out."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": "attacker-chosen"}).encode()
    ).rstrip(b"=").decode()
    _, payload, signature = token["proof_token"].split(".")
    before = jwks.fetch_count
    with pytest.raises(ProofTokenError, match="unknown kid"):
        validate_proof_token(
            f"{header}.{payload}.{signature}", jwks, expected_issuer="anything"
        )
    assert jwks.fetch_count == before


def test_replayed_jti_is_refused_when_a_seen_set_is_kept(token, jwks, memtara_server):
    seen: set[str] = set()
    validate_proof_token(token["proof_token"], jwks, expected_issuer=memtara_server, seen_jti=seen)
    with pytest.raises(ProofTokenError, match="already been used"):
        validate_proof_token(
            token["proof_token"], jwks, expected_issuer=memtara_server, seen_jti=seen
        )


def test_gateway_blocks_and_audits_a_forged_attestation(gateway, token):
    claims = _claims_of(token["proof_token"])
    claims["predicate"] = "accredited_investor"
    forged = _resegment(token["proof_token"], claims)

    response = gateway["client"].post(
        "/v1/chat/completions",
        headers={PROOF_HEADER: forged},
        json={"model": "m", "messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 403

    events = read_audit(gateway["audit_path"])
    attestations = [e for e in events if e["event_type"] == "attestation"]
    assert len(attestations) == 1
    assert attestations[0]["detail"]["memtara_verified"] is False
    assert "signature" in attestations[0]["detail"]["memtara_rejection_reason"]

    # Nothing was forwarded to the model, and the chain still verifies.
    assert not gateway["forwarded"]
    from src.verifier.cli import verify

    assert verify(str(gateway["audit_path"])) == []


# ---------------------------------------------------------------------------
# 4. The record itself is tamper-evident
# ---------------------------------------------------------------------------


def test_editing_the_audit_log_is_detected_by_aihoots_verifier(gateway, token):
    """Rewrite history, and AIHOOTS's own verifier names the record.

    This is what makes the whole package evidence rather than logging: the
    operator of the gateway cannot quietly change what a proof said after the
    fact.
    """
    gateway["client"].post(
        "/v1/chat/completions",
        headers={PROOF_HEADER: token["proof_token"]},
        json={"model": "m", "messages": [{"role": "user", "content": "hello"}]},
    )

    from src.verifier.cli import verify

    path = gateway["audit_path"]
    assert verify(str(path)) == []

    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["detail"]["proof_hash"] = "0" * 64  # claim a different proof was seen
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    errors = verify(str(path))
    assert errors, "tampering with a proof_hash must be detected"
    assert any("altered" in str(e) or "chain broken" in str(e) for e in errors)
