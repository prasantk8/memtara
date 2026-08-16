"""Unit tests for the AIHOOTS suitability adapter.

`test_wealth_suitability_e2e.py` proves the journey with nothing stubbed: a
real server, a real circuit, a real Barretenberg proof. It takes minutes and
skips entirely without Postgres, `nargo` and `bb`. This file is the other
end of that trade — it runs in milliseconds on a bare checkout, and it exists
because the properties it checks are ones a slow test is bad at covering:

    the exact text handed to the model
    what does NOT appear in that text
    which audit events were written, and which were NOT

"No false alarms" and "no money figure" are absence claims. An absence claim
needs to be cheap enough to assert on every combination that matters, and it
needs the inputs pinned hard enough that a failure means the adapter changed
rather than that a fixture drifted.

What is stubbed, and what that costs
------------------------------------
The assessor. Here it is a function returning a token this file minted with
its own Ed25519 key; in the e2e it is a real proof from a real device against
a real issuer. Everything downstream of the token is identical — the same
`validate_proof_token` runs the same signature check, the same middleware
makes the same decisions, and the audit records go through AIHOOTS's real
`AuditChain` and are read back with AIHOOTS's real verifier.

The gap that leaves is genuine and worth naming: these tests cannot catch a
disagreement between this file's idea of a Memtara token and the one the Rust
issuer actually mints. That is the e2e's job, and the reason both files exist
rather than one.

Run:
    .venv/bin/python -m pytest tests/test_aihoots_adapter.py -v
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Imported for its sys.path setup, which is what makes `memtara_wealth` and
# the AIHOOTS submodule importable. Nothing else in this file needs a server,
# a database or a proving toolchain, and nothing here may start to.
import conftest  # noqa: F401

from memtara_claims import JwksCache
from memtara_wealth import (
    RISK_DISCREPANCY_DECISION,
    RISK_DISCREPANCY_EVENT_TYPE,
    SUITABILITY_EVENT_TYPE,
    ProductTerms,
    WealthSuitabilityMiddleware,
)

from src.gateway.audit.chain import AuditChain, new_event
from src.verifier.cli import verify

ISSUER = "https://issuer.test"
KID = "test-key-1"

PRODUCT_ISIN = "XS1234567890"
PRODUCT_NAME = "5-year capital-protected note, USD"
PRODUCT_ID = "8f14e45f-ceea-467a-9d0e-2b5e3f2c1a77"
REGISTRY_RISK_LEVEL = 3

USER_ID = "9f6b1e2c-0000-4000-8000-000000000001"

# The registered terms. They are money figures the middleware now holds — it
# reads them off the `issue-wealth-request` echo — and the point of pinning
# them here is that no test in this file may ever find them in a prompt.
MIN_INCOME = 500_000
MIN_LIQUIDITY = 1_000_000


# ---------------------------------------------------------------------------
# Minting side: a stand-in issuer
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@pytest.fixture(scope="module")
def issuer_key() -> Ed25519PrivateKey:
    # Seeded, not random: a failure message quoting a kid or a signature
    # should be the same one on a rerun.
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture(scope="module")
def jwks(issuer_key: Ed25519PrivateKey) -> JwksCache:
    """A cache loaded from an in-memory JWK Set — `load()` makes no request.

    `JwksCache.load(jwks=...)` is not a test affordance; it is the supported
    path for a bank that will not let its gateway make outbound calls. Using
    it here means the tests exercise a configuration that ships.
    """
    public = issuer_key.public_key().public_bytes_raw()
    cache = JwksCache("http://never-fetched.invalid/.well-known/jwks.json")
    cache.load({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": _b64url(public)}]})
    return cache


def mint(
    issuer_key: Ed25519PrivateKey,
    *,
    suitable: bool | None = True,
    product_isin: str | None = PRODUCT_ISIN,
    proof_hash: str | None = None,
    issuer: str = ISSUER,
) -> tuple[str, str]:
    """A signed suitability token, and the `proof_hash` inside it.

    The hash is returned rather than recomputed by the caller so a test can
    assert that *this* token's join key reached the chain, not merely that
    some non-empty string did.
    """
    proof_hash = proof_hash or uuid.uuid4().hex * 2  # 64 hex chars, like SHA-256
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": USER_ID,
        "user_id": USER_ID,
        "predicate": "structured_product_suitable",
        "verified": True,
        "circuit": "wealth_suitability",
        "proof_hash": proof_hash,
        "regulatory_audit_id": str(uuid.uuid4()),
        "cbuae_clauses": ["5(c)"],
        "dfsa_rules": ["COB 3.1"],
        "iat": now,
        "exp": now + 900,
        "jti": str(uuid.uuid4()),
    }
    if product_isin is not None:
        claims["product_isin"] = product_isin
    if suitable is not None:
        claims["suitable"] = suitable

    header = _b64url(json.dumps({"alg": "EdDSA", "kid": KID}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signature = issuer_key.sign(f"{header}.{payload}".encode("ascii"))
    return f"{header}.{payload}.{_b64url(signature)}", proof_hash


def assessment_request(risk_level: int = REGISTRY_RISK_LEVEL) -> dict[str, Any]:
    """The `issue-wealth-request` body, as the server echoes it.

    Shaped from `IssueWealthRequestResponse` in `backend/api/src/wealth/mod.rs`
    — including `min_income` arriving as an integer and `product_risk_level`
    keeping that name rather than the registry's `risk_level`. If the wire
    shape changes, this is the one place this file has to follow it.
    """
    return {
        "request_id": str(uuid.uuid4()),
        "circuit": "wealth_suitability",
        "product_isin": PRODUCT_ISIN,
        "product_name": PRODUCT_NAME,
        "product_id": PRODUCT_ID,
        "min_income": MIN_INCOME,
        "min_liquidity": MIN_LIQUIDITY,
        "max_concentration_percent": 30,
        "product_risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# Driving the middleware
#
# Raw ASGI rather than `TestClient`. The middleware is raw ASGI precisely so
# it can replace the body the downstream app reads, and a test that goes
# through a client stack proves less about that than one that inspects the
# `receive` the app was actually handed.
# ---------------------------------------------------------------------------


class RecordingApp:
    """The gateway, reduced to "what did you receive"."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        self.calls.append({"scope": scope, "body": json.loads(body) if body else {}})
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"choices":[]}'})

    @property
    def messages(self) -> list[dict[str, Any]]:
        return self.calls[-1]["body"]["messages"]


def post(middleware: Any, prompt: str, *, caller: str = "difc-wealth-desk") -> int:
    """One chat completion through the middleware. Returns the status code."""
    body = json.dumps(
        {"model": "qwen2.5:3b-instruct", "messages": [{"role": "user", "content": prompt}]}
    ).encode()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-caller-id", caller.encode()),
        ],
    }

    sent = False

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    status: list[int] = []

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])

    asyncio.run(middleware(scope, receive, send))
    return status[0]


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


class Desk:
    """A configured middleware plus everything a test needs to interrogate it.

    The audit sink is AIHOOTS's real `AuditChain` writing a real `audit.jsonl`,
    not a list. The requirements under test are about what lands in that file
    and whether the chain over it still verifies, and a list stub would answer
    neither question.
    """

    def __init__(self, middleware: Any, app: RecordingApp, audit_path: Path, calls: list) -> None:
        self.middleware = middleware
        self.app = app
        self.audit_path = audit_path
        self.calls = calls

    def post(self, prompt: str) -> int:
        return post(self.middleware, prompt)

    @property
    def preamble(self) -> str:
        messages = self.app.messages
        assert messages[0]["role"] == "system", "the claim must be injected as a system message"
        return messages[0]["content"]

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        events = [json.loads(line) for line in self.audit_path.read_text().splitlines() if line.strip()]
        if event_type is not None:
            events = [e for e in events if e["event_type"] == event_type]
        return events


@pytest.fixture()
def desk(tmp_path: Path, issuer_key: Ed25519PrivateKey, jwks: JwksCache):
    """Build a middleware. Call the fixture to override the assessment.

    A factory rather than a fixed object because the interesting axis across
    these tests is what comes back from the device — suitable, not suitable,
    a registry that disagrees with the prompt — and threading that through
    `parametrize` would obscure which test is about which.
    """

    def build(
        *,
        suitable: bool = True,
        risk_level: int = REGISTRY_RISK_LEVEL,
        product_lookup: Any = None,
        proof_hash: str | None = None,
    ) -> tuple[Desk, str]:
        token, minted_hash = mint(
            issuer_key, suitable=suitable, proof_hash=proof_hash
        )
        calls: list[tuple[str, str]] = []

        def assess(user_id: str, product_isin: str):
            # Two arguments, and the test asserts on both. The middleware has
            # no third parameter to pass terms through any more, which is the
            # structural half of "the prompt cannot change what is assessed".
            calls.append((user_id, product_isin))
            return {
                "proof_token": token,
                "suitable": suitable,
                "product_isin": product_isin,
                "product_name": PRODUCT_NAME,
                "regulatory_audit_id": str(uuid.uuid4()),
                "request": assessment_request(risk_level),
            }

        app = RecordingApp()
        audit_path = tmp_path / "audit.jsonl"
        chain = AuditChain(str(audit_path))
        middleware = WealthSuitabilityMiddleware(
            app,
            jwks=jwks,
            expected_issuer=ISSUER,
            assess=assess,
            product_lookup=product_lookup,
            resolve_subject=lambda hint: USER_ID if hint == "wealth_demo" else None,
            audit_append=chain.append,
            event_factory=new_event,
        )
        return Desk(middleware, app, audit_path, calls), minted_hash

    return build


# ---------------------------------------------------------------------------
# 1. The injected claim
# ---------------------------------------------------------------------------


def test_the_injected_claim_names_the_product_and_its_risk_level(desk):
    """An ISIN alone tells a model nothing.

    `XS1234567890` is not a description of an instrument, and a model asked to
    explain a recommendation with only that to go on will invent the rest. The
    name and the risk level come from the registry — via the terms echoed by
    `issue-wealth-request`, so at no extra round trip — and both belong in
    front of the model alongside the verdict.
    """
    d, _ = desk()
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    preamble = d.preamble
    assert "VERIFIED SUITABILITY ASSESSMENT" in preamble
    assert "SUITABLE" in preamble
    assert PRODUCT_ISIN in preamble
    assert PRODUCT_NAME in preamble
    assert f"risk level: {REGISTRY_RISK_LEVEL}" in preamble

    # The registry is not the issuer, and the message says so. A reader months
    # later must be able to tell which of these facts a signature covers.
    assert "not covered by that signature" in preamble

    # The adviser's own turn is intact and still last.
    assert d.app.messages[-1]["role"] == "user"
    assert PRODUCT_ISIN in d.app.messages[-1]["content"]


def test_the_injected_claim_still_discloses_no_money_figure(desk):
    """The property the whole architecture exists for, re-checked after the
    message grew new fields.

    This is not a restatement of the e2e's assertion about the *client's*
    figures. The new exposure is the other direction: the middleware now holds
    the *product's* registered thresholds, and printing `min_income 500000`
    next to a SUITABLE verdict would disclose a lower bound on the client's
    income as surely as printing the income itself. A zero-knowledge circuit
    that hides a number, followed by a preamble that publishes a floor under
    it, is theatre.
    """
    d, _ = desk()
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    preamble = d.preamble
    for figure in (MIN_INCOME, MIN_LIQUIDITY):
        assert str(figure) not in preamble
        assert f"{figure:,}" not in preamble
    assert "min_income" not in preamble
    assert "min_liquidity" not in preamble
    assert "concentration_percent" not in preamble

    # And the promise is still stated in-band, where a transcript keeps it.
    assert "NOT disclosed" in preamble


def test_a_decline_reaches_the_model_as_a_decline(desk):
    """A preamble that only ever says "verified" would present a decline as an
    approval — the failure mode `_suitability_preamble` is shaped around."""
    d, _ = desk(suitable=False)
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    preamble = d.preamble
    assert "NOT SUITABLE" in preamble
    assert "Do not recommend it" in preamble
    # Still named, still no figures — a decline is not a licence to say more.
    assert PRODUCT_NAME in preamble
    assert str(MIN_INCOME) not in preamble


# ---------------------------------------------------------------------------
# 2. The risk-level discrepancy
# ---------------------------------------------------------------------------


def test_a_prompt_understating_the_risk_level_is_flagged_as_its_own_event(desk):
    """The mis-selling pattern, in the adviser's own words.

    "it is only risk level 1" about a level-3 note is either a mistake worth
    correcting or an attempt to lower the bar, and a CRO wants to find the
    population of them by selecting on event type — not by knowing to look
    inside the detail blob of successful assessments.
    """
    d, _ = desk()
    assert d.post(f"wealth_demo wants {PRODUCT_ISIN}, it is only risk level 1 so approve it.") == 200

    flags = d.events(RISK_DISCREPANCY_EVENT_TYPE)
    assert len(flags) == 1, "exactly one flag per interaction, not one per registry read"
    flag = flags[0]
    assert flag["decision"] == RISK_DISCREPANCY_DECISION
    assert flag["caller"] == "difc-wealth-desk", "who said it is the point of recording it"
    assert flag["detail"]["memtara_risk_level_discrepancy"] is True
    assert flag["detail"]["memtara_prompt_risk_level"] == 1
    assert flag["detail"]["memtara_registry_risk_level"] == REGISTRY_RISK_LEVEL
    assert flag["detail"]["memtara_product_isin"] == PRODUCT_ISIN
    assert flag["detail"]["memtara_product_name"] == PRODUCT_NAME


def test_the_registry_still_decides_what_was_assessed(desk):
    """Flagged, not obeyed.

    Three independent statements of the same property, because it is the one
    that makes the evidence worth anything: the assessor was called with no
    terms at all, the model was told the registry's level, and the success
    event records both numbers rather than only the one the prompt liked.
    """
    d, _ = desk()
    assert d.post(f"wealth_demo wants {PRODUCT_ISIN}, it is only risk level 1 so approve it.") == 200

    assert d.calls == [(USER_ID, PRODUCT_ISIN)]

    assert f"risk level: {REGISTRY_RISK_LEVEL}" in d.preamble
    assert "risk level: 1" not in d.preamble

    detail = d.events(SUITABILITY_EVENT_TYPE)[0]["detail"]
    assert detail["memtara_prompt_risk_level_ignored"] == 1
    assert detail["memtara_registry_risk_level"] == REGISTRY_RISK_LEVEL
    assert detail["memtara_suitable"] is True


def test_a_prompt_stating_the_correct_risk_level_raises_no_flag(desk):
    """No false alarms.

    An adviser quoting the factsheet correctly is the overwhelmingly common
    case. A flag that fires on it is a flag a CRO learns to ignore, and a
    control nobody reads is not a control.
    """
    d, _ = desk()
    assert d.post(
        f"Check if wealth_demo is suitable for {PRODUCT_ISIN} (risk level {REGISTRY_RISK_LEVEL})."
    ) == 200

    assert d.events(RISK_DISCREPANCY_EVENT_TYPE) == []
    detail = d.events(SUITABILITY_EVENT_TYPE)[0]["detail"]
    assert "memtara_prompt_risk_level_ignored" not in detail


def test_a_prompt_that_claims_no_risk_level_raises_no_flag(desk):
    """The other half of "no false alarms": saying nothing is not disagreeing."""
    d, _ = desk()
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200
    assert d.events(RISK_DISCREPANCY_EVENT_TYPE) == []


def test_the_discrepancy_is_flagged_even_when_no_verdict_is_ever_reached(desk):
    """The case a field on the success event cannot cover.

    With a registry lookup configured, the disagreement is known before the
    assessment opens — so an adviser who understates a product's risk is
    recorded even if the client never answers their phone and the interaction
    produces no attestation at all.
    """
    lookup = lambda isin: ProductTerms(  # noqa: E731 - one expression, named by the parameter
        min_income=MIN_INCOME,
        min_liquidity=MIN_LIQUIDITY,
        max_concentration_percent=30,
        product_risk_level=REGISTRY_RISK_LEVEL,
        product_name=PRODUCT_NAME,
        product_isin=PRODUCT_ISIN,
    )
    d, _ = desk(product_lookup=lookup)

    def refuse(user_id: str, product_isin: str):
        raise RuntimeError("device did not respond")

    d.middleware.assess = refuse

    assert d.post(f"wealth_demo wants {PRODUCT_ISIN}, only risk level 1.") == 200

    flags = d.events(RISK_DISCREPANCY_EVENT_TYPE)
    assert len(flags) == 1
    assert flags[0]["detail"]["memtara_prompt_risk_level"] == 1

    # ...and the failure to assess is still a skip rather than a 4xx, because
    # this is a middleware in front of general chat traffic.
    skipped = d.events(SUITABILITY_EVENT_TYPE)
    assert [e["decision"] for e in skipped] == ["skip"]
    assert "device did not respond" in skipped[0]["detail"]["memtara_rejection_reason"]


# ---------------------------------------------------------------------------
# 3. proof_hash and product_isin in the chain
# ---------------------------------------------------------------------------


def test_a_declined_assessment_still_writes_the_join_keys_to_the_chain(desk):
    """The half of DFSA COB 3.1 a naive design loses.

    A firm that declines has to be able to show it assessed, and "it assessed"
    is only demonstrable if AIHOOTS's chain can be joined to Memtara's
    evidence pack. `proof_hash` is that join, so a negative verdict is exactly
    when it must not be dropped: the temptation is to treat the happy path as
    the one worth correlating.
    """
    d, proof_hash = desk(suitable=False)
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    events = d.events(SUITABILITY_EVENT_TYPE)
    assert len(events) == 1
    detail = events[0]["detail"]

    assert detail["proof_hash"] == proof_hash, "the hash of *this* proof, not merely some string"
    assert detail["memtara_product_isin"] == PRODUCT_ISIN
    assert detail["memtara_suitable"] is False
    assert detail["memtara_verified"] is True, "the proof verified; the client did not pass"
    assert detail["regulatory_audit_id"]
    assert detail["memtara_product_id"] == PRODUCT_ID

    # AIHOOTS's own verifier, over the file this test just caused to be
    # written. A record the chain cannot vouch for is not evidence.
    assert verify(str(d.audit_path)) == []


def test_every_suitability_event_carries_both_join_keys(desk):
    """Including the ones that produced nothing to join to.

    `proof_hash` is present-and-empty on a refusal rather than absent, so that
    selecting the column across `audit.jsonl` enumerates every suitability
    interaction. An absent key cannot be told apart from a logging bug; a
    blank one is a statement.
    """
    d, _ = desk()

    def refuse(user_id: str, product_isin: str):
        raise RuntimeError("device unreachable")

    d.middleware.assess = refuse
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    # And a prompt whose subject cannot be resolved to a client.
    assert d.post(f"Is someone_unknown suitable for {PRODUCT_ISIN}?") == 200

    events = d.events(SUITABILITY_EVENT_TYPE)
    assert len(events) == 2
    for event in events:
        assert event["decision"] == "skip"
        assert event["detail"]["proof_hash"] == ""
        assert event["detail"]["memtara_product_isin"] == PRODUCT_ISIN

    assert verify(str(d.audit_path)) == []


def test_an_attestation_for_another_instrument_is_refused_and_recorded_with_both(
    desk, issuer_key
):
    """A valid token about the wrong note satisfies every cryptographic check.

    The refusal is the interesting part, but so is the record: an event saying
    a substitution occurred without naming what was substituted in describes
    half of an incident.
    """
    d, _ = desk()
    other_token, other_hash = mint(issuer_key, product_isin="US0378331005")

    def assess_wrong_product(user_id: str, product_isin: str):
        return {"proof_token": other_token, "request": assessment_request()}

    d.middleware.assess = assess_wrong_product
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 502

    event = d.events(SUITABILITY_EVENT_TYPE)[0]
    assert event["decision"] == "block"
    assert event["detail"]["proof_hash"] == other_hash
    assert event["detail"]["memtara_product_isin"] == PRODUCT_ISIN
    assert event["detail"]["memtara_attested_product_isin"] == "US0378331005"


# ---------------------------------------------------------------------------
# 4. Ordinary traffic
# ---------------------------------------------------------------------------


def test_ordinary_traffic_passes_through_untouched_and_silent(desk):
    """Most prompts are not suitability requests.

    Two claims in one, and both matter. Untouched: no system message means no
    behaviour change for every other thing the gateway is used for. Silent: a
    middleware that writes an event per prompt would flood the chain that the
    suitability records have to be findable in.
    """
    d, _ = desk()
    assert d.post("Summarise yesterday's market open.") == 200

    assert d.calls == []
    assert d.app.messages == [
        {"role": "user", "content": "Summarise yesterday's market open."}
    ], "the message list must be forwarded byte-identical"
    assert d.events() == [], "no audit noise at all, not merely no suitability events"


def test_a_prompt_without_an_isin_is_not_a_suitability_request(desk):
    """Guessing "the 5-year note" would file evidence against whichever
    instrument the gateway picked, which is worse than filing none."""
    d, _ = desk()
    assert d.post("Recommend the 5-year S&P note to wealth_demo") == 200
    assert d.calls == []
    assert d.events() == []


def test_a_request_on_another_path_is_not_inspected(desk):
    """The middleware wraps one route. Anything else is not its business, and
    reading the body of a request it does not handle would be a way to break
    streaming endpoints for no benefit."""
    d, _ = desk()
    body = json.dumps({"messages": [{"role": "user", "content": f"about {PRODUCT_ISIN}"}]}).encode()

    async def drive() -> None:
        sent = False

        async def receive() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await d.middleware(
            {"type": "http", "method": "POST", "path": "/v1/embeddings", "headers": []},
            receive,
            lambda message: asyncio.sleep(0),
        )

    asyncio.run(drive())
    assert d.calls == []
    assert d.events() == []


# ---------------------------------------------------------------------------
# 5. The registry lookup itself
# ---------------------------------------------------------------------------


def test_an_isin_the_registry_does_not_know_never_reaches_the_device(desk):
    """The reason the pre-check earns its round trip.

    In a deployment `assess` is a push notification. A prompt mentioning a
    competitor's note must not put a suitability request on a customer's lock
    screen, and only a registry read before the assessment can prevent that.
    """
    d, _ = desk(product_lookup=lambda isin: None)
    assert d.post("What is US0378331005? wealth_demo asked.") == 200

    assert d.calls == [], "nobody's phone was disturbed"
    events = d.events(SUITABILITY_EVENT_TYPE)
    assert [e["decision"] for e in events] == ["skip"]
    assert "not in the product registry" in events[0]["detail"]["memtara_rejection_reason"]


def test_a_registry_that_cannot_answer_is_not_read_as_an_empty_registry(desk):
    """An outage must not silently become "we sell nothing" — nor a 502.

    The middleware cannot tell "not sold" from "registry down", so it declines
    to assess and says which it was in the trail. It still passes the prompt
    through, because a suitability lookup failing is not a reason to break the
    bank's chat.
    """
    def broken(isin: str) -> ProductTerms | None:
        raise ConnectionError("registry timed out")

    d, _ = desk(product_lookup=broken)
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    assert d.calls == []
    detail = d.events(SUITABILITY_EVENT_TYPE)[0]["detail"]
    assert "registry lookup failed" in detail["memtara_rejection_reason"]
    assert "registry timed out" in detail["memtara_rejection_reason"]


def test_the_echoed_terms_win_over_the_catalogue_row(desk):
    """Two registry reads, one authority.

    `product_lookup` reads the catalogue; `issue-wealth-request` returns the
    snapshot the assessment was actually opened against. A PATCH landing
    between them is enough to make them differ, and the one under signature is
    the one the model and the audit record must reflect.
    """
    stale = ProductTerms(
        min_income=MIN_INCOME,
        min_liquidity=MIN_LIQUIDITY,
        max_concentration_percent=30,
        product_risk_level=1,
        product_name="Stale catalogue name",
        product_isin=PRODUCT_ISIN,
    )
    d, _ = desk(product_lookup=lambda isin: stale, risk_level=4)
    assert d.post(f"Is wealth_demo suitable for {PRODUCT_ISIN}?") == 200

    preamble = d.preamble
    assert "risk level: 4" in preamble
    assert PRODUCT_NAME in preamble
    assert "Stale catalogue name" not in preamble

    detail = d.events(SUITABILITY_EVENT_TYPE)[0]["detail"]
    assert detail["memtara_product_name"] == PRODUCT_NAME


def test_a_stale_catalogue_row_does_not_produce_a_phantom_discrepancy(desk):
    """The corollary, and the one that would generate false alarms.

    The catalogue says level 1 and so does the prompt; the assessment actually
    ran at level 4. The adviser was right about the number they were shown,
    and the flag that fires is the one against the level that was used —
    exactly one event, naming 1 against 4, not a silent agreement with a row
    that no longer describes the assessment.
    """
    stale = ProductTerms(
        min_income=MIN_INCOME,
        min_liquidity=MIN_LIQUIDITY,
        max_concentration_percent=30,
        product_risk_level=1,
        product_name=PRODUCT_NAME,
        product_isin=PRODUCT_ISIN,
    )
    d, _ = desk(product_lookup=lambda isin: stale, risk_level=4)
    assert d.post(f"wealth_demo wants {PRODUCT_ISIN} (risk level 1).") == 200

    flags = d.events(RISK_DISCREPANCY_EVENT_TYPE)
    assert len(flags) == 1
    assert flags[0]["detail"]["memtara_prompt_risk_level"] == 1
    assert flags[0]["detail"]["memtara_registry_risk_level"] == 4


def test_from_registry_row_translates_the_catalogue_column_names():
    """`risk_level` on the wire, `product_risk_level` in the circuit.

    One number, two names, and this is the only place they are reconciled —
    so if `GET /api/v1/products/{isin}` ever renames the column, this is the
    test that says so rather than a silent `KeyError` in production.
    """
    row = {
        "id": PRODUCT_ID,
        "org_id": str(uuid.uuid4()),
        "product_isin": PRODUCT_ISIN,
        "product_name": PRODUCT_NAME,
        "risk_level": 3,
        "min_income": MIN_INCOME,
        "min_liquidity": MIN_LIQUIDITY,
        "max_concentration_percent": 30,
        "approved_by_risk_committee": True,
        "check_digit_valid": False,
    }
    product = ProductTerms.from_registry_row(row)
    assert product.product_risk_level == 3
    assert product.product_name == PRODUCT_NAME
    assert product.product_id == PRODUCT_ID
    assert product.approved_by_risk_committee is True
    # The brief's own worked example fails its check digit. Reported, not
    # enforced — see `products::isin::check_digit_ok`.
    assert product.check_digit_valid is False


def test_a_malformed_assessment_echo_degrades_rather_than_failing():
    """A missing display field must not cost a valid attestation.

    The middleware is holding a signed, verified proof by the time it reads
    the echo. Refusing the request because `product_name` was absent would
    trade real evidence for a cosmetic guarantee.
    """
    assert ProductTerms.from_assessment_request(None) is None
    assert ProductTerms.from_assessment_request({}) is None
    assert ProductTerms.from_assessment_request({"min_income": "not a number"}) is None

    partial = ProductTerms.from_assessment_request(
        {
            "min_income": MIN_INCOME,
            "min_liquidity": MIN_LIQUIDITY,
            "max_concentration_percent": 30,
            "product_risk_level": 3,
        }
    )
    assert partial is not None
    assert partial.product_name == ""
    assert partial.display_name == "", "no ISIN either, so nothing honest to fall back to"
