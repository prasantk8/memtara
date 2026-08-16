"""Memtara proof-token validation and claim injection for the AIHOOTS gateway.

This is the *relying-party* half of the Memtara ↔ AIHOOTS integration, written
to be dropped into `aihoots-e1-audit-gateway` (or any OpenAI-compatible front
door). It lives in the Memtara repo rather than the AIHOOTS one because Memtara
is the issuer: the token format, the clause mapping and the offline-validation
rules are Memtara's contract to specify, and shipping the reference validator
next to the issuer is what stops the two drifting apart.

Why the integration has no REST call in it
------------------------------------------
A relying party could ask Memtara "is this user's income above the threshold?"
on every request. That would put Memtara in the latency path of every LLM call
and make it an availability dependency of the bank's AI front door — and it
would leak, to Memtara, which consumer the bank is looking at and when.

Instead Memtara signs a short-lived attestation with Ed25519 and publishes the
public half at `/.well-known/jwks.json`. The relying party fetches that once,
caches it by `kid`, and from then on validates tokens with local arithmetic.
Steady-state cost of a validation: one Ed25519 signature check. No network, no
shared secret, no correlation leak.

What this module does NOT do
----------------------------
It does not decide policy. Whether a `residency_valid` attestation is
sufficient for a given product is the institution's call, made in the
institution's own rules. This module answers exactly one question — "is this
token a genuine, unexpired Memtara attestation, and what does it say?" — and
records the answer in the audit chain either way.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Header the relying party reads the attestation from. A dedicated header
# rather than `Authorization`, because the gateway's own caller
# authentication (if any) belongs in `Authorization` and the two credentials
# answer different questions.
PROOF_HEADER = "x-memtara-proof"

# Only algorithm accepted. Fixed, not negotiated from the token's own header:
# reading `alg` from the untrusted token is the root of the classic JWT
# algorithm-confusion and `alg: "none"` bugs. A token that asks for anything
# else is rejected before any signature work happens.
REQUIRED_ALG = "EdDSA"

# A token whose `iat` is slightly in the future is normal (clock skew between
# issuer and relying party), and rejecting it would produce mystery failures
# in production. A token whose `exp` has passed is not negotiable, but the
# same skew allowance applies so a 300-second token does not become a
# 297-second one on a slightly-fast clock.
CLOCK_SKEW_SECONDS = 30


class ProofTokenError(Exception):
    """A token was not a genuine, unexpired Memtara attestation.

    Deliberately one exception type with a specific message rather than a
    hierarchy: every failure here has the same consequence (the request is
    treated as unattested), and the distinction that matters — *why* — is
    carried in the message and written to the audit trail.
    """


@dataclass(frozen=True)
class VerifiedProof:
    """The claims of a token that passed every check."""

    user_id: str
    predicate: str
    circuit: str
    proof_hash: str
    regulatory_audit_id: str
    cbuae_clauses: tuple[str, ...]
    issuer: str
    jti: str
    expires_at: int
    raw_claims: dict[str, Any] = field(repr=False, default_factory=dict)
    # Suitability attestations only. `None` means "this token made no
    # suitability assessment", which is a different fact from "assessed and
    # found unsuitable" — hence a tri-state rather than a bool defaulting to
    # False.
    product_isin: str | None = None
    suitable: bool | None = None
    dfsa_rules: tuple[str, ...] = ()

    def as_prompt_preamble(
        self, *, product_name: str | None = None, risk_level: int | None = None
    ) -> str:
        """The claims, rendered for injection ahead of the user's prompt.

        Phrased as verified facts with an explicit provenance line, because a
        model that cannot tell an attested fact from an asserted one will
        happily act on either. The preamble also states what was *not*
        disclosed — that is the property the consumer was promised, and
        restating it in-band means a transcript read months later still shows
        that the underlying attribute never entered the context window.

        `product_name` and `risk_level` are keyword arguments rather than
        fields on this object for a reason that matters more than tidiness:
        they are NOT in the signed token. Memtara's suitability token carries
        `product_isin` and the verdict, and nothing else about the instrument
        (see `ProofTokenClaims` in `backend/api/src/crypto/signer.rs`). The
        name and the risk level come from the bank's own product registry.
        Both are worth putting in front of the model — an ISIN alone tells it
        nothing, and a model that does not know a product is level 5 will
        happily describe it as conservative — but they arrive by a different
        route and with different guarantees, so the preamble says so rather
        than quietly folding them in among the attested facts.

        Nothing else from the registry is rendered here, and specifically not
        the registered thresholds. `min_income = 500000` printed next to a
        SUITABLE verdict is a disclosure: it tells the reader the client earns
        at least that much. It would be a strange system that spent a
        zero-knowledge circuit hiding the income and then published a lower
        bound on it in the same message.
        """
        if self.suitable is not None:
            return self._suitability_preamble(product_name=product_name, risk_level=risk_level)

        clauses = ", ".join(self.cbuae_clauses) if self.cbuae_clauses else "n/a"
        return (
            "[VERIFIED ATTRIBUTES — cryptographically attested by Memtara, "
            f"issuer {self.issuer}]\n"
            f"- subject: {self.user_id}\n"
            f"- verified predicate: {self.predicate} = true\n"
            f"- evidence: zero-knowledge proof, circuit {self.circuit}, "
            f"proof_hash {self.proof_hash}\n"
            f"- regulatory_audit_id: {self.regulatory_audit_id} "
            f"(CBUAE clauses: {clauses})\n"
            "- NOT disclosed: the underlying attribute value. Only the "
            "predicate above was proven. Do not infer, estimate or ask for "
            "the underlying value.\n"
        )

    def _suitability_preamble(
        self, *, product_name: str | None = None, risk_level: int | None = None
    ) -> str:
        """The suitability variant.

        Two things differ from the generic preamble, both deliberate.

        First, the verdict is stated as a verdict rather than as "predicate =
        true". A suitability token is the one kind this system issues where
        the honest answer is sometimes no, and a preamble that only ever says
        "verified" would present a decline as an approval.

        Second, a negative verdict carries an explicit instruction not to
        recommend. That instruction is a belt-and-braces measure, not the
        control: a model can ignore any instruction, so the actual control is
        the bank's own gate on the `suitable` claim before the request is
        ever made. It is included because the transcript is evidence, and an
        auditor reading it should see that the model was told.
        """
        clauses = ", ".join(self.cbuae_clauses) if self.cbuae_clauses else "n/a"
        rules = ", ".join(self.dfsa_rules) if self.dfsa_rules else "n/a"
        verdict = "SUITABLE" if self.suitable else "NOT SUITABLE"
        lines = [
            "[VERIFIED SUITABILITY ASSESSMENT — cryptographically attested by "
            f"Memtara, issuer {self.issuer}]",
            f"- subject: {self.user_id}",
            f"- product: {self.product_isin}",
        ]
        if product_name:
            lines.append(f"- product name: {product_name}")
        if risk_level is not None:
            # The scale is stated because "risk level 4" is meaningless
            # without knowing what the top of the scale is, and a model that
            # guesses the ceiling is 10 will read a 4 as moderate when the
            # bank means near-maximum.
            lines.append(f"- product risk level: {risk_level} (bank's 1-5 scale, 5 = highest)")
        lines += [
            f"- assessment: {verdict}",
            "- basis: income, liquid assets, risk tolerance and portfolio "
            "concentration were each evaluated against this product's "
            "registered terms inside a zero-knowledge circuit",
            f"- evidence: circuit {self.circuit}, proof_hash {self.proof_hash}",
            f"- regulatory_audit_id: {self.regulatory_audit_id} "
            f"(DFSA: {rules}; CBUAE clauses: {clauses})",
            "- NOT disclosed: the client's income, assets, holdings or risk "
            "score. Only the verdict above was disclosed. Do not infer, "
            "estimate or ask for any of the underlying figures.",
        ]
        if product_name or risk_level is not None:
            # Said out loud because the two routes have different strengths
            # and a transcript read later should not have to guess which
            # facts were signed. Someone who can edit the registry can change
            # the name and the risk level in this message; nobody without
            # Memtara's signing key can change the verdict.
            lines.append(
                "- provenance: the subject, instrument, verdict and evidence "
                "identifiers above are from a signed Memtara attestation; the "
                "product name and risk level are from the bank's own product "
                "registry and are not covered by that signature."
            )
        if not self.suitable:
            lines.append(
                "- REQUIRED: this client did NOT pass the suitability "
                "assessment for this product. Do not recommend it, do not "
                "describe it as appropriate for them, and do not suggest "
                "workarounds. Explain that the product is unsuitable and "
                "offer to discuss alternatives."
            )
        return "\n".join(lines) + "\n"


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment that has had its padding stripped (RFC 7515 §2)."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class JwksCache:
    """Fetch-once, verify-many cache of Memtara's public signing keys.

    The whole zero-latency claim rests on this object: after the first fetch,
    `key_for` is pure local computation. `fetch_count` is public so a test can
    prove that — see `test_validation_makes_no_call_to_memtara` — rather than
    leave it as an architectural assertion nobody checks.
    """

    def __init__(self, jwks_url: str, timeout: float = 5.0) -> None:
        self.jwks_url = jwks_url
        self.timeout = timeout
        self._keys: dict[str, Ed25519PublicKey] = {}
        self.fetch_count = 0

    def load(self, jwks: dict[str, Any] | None = None) -> None:
        """Populate the cache, either from a supplied JWK Set or by fetching.

        Accepting a pre-fetched set matters operationally: a bank that will not
        let its gateway make outbound calls at all can ship the JWK Set as
        configuration and get identical behaviour.
        """
        if jwks is None:
            with urllib.request.urlopen(self.jwks_url, timeout=self.timeout) as response:
                jwks = json.loads(response.read())
            self.fetch_count += 1

        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                # Skip rather than fail: a future JWK Set may legitimately
                # carry key types this validator does not handle, and
                # refusing the whole set over one unknown entry would make
                # key rotation unnecessarily brittle.
                continue
            kid = jwk.get("kid")
            if not kid:
                continue
            keys[kid] = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))

        if not keys:
            raise ProofTokenError(f"no usable Ed25519 keys in JWK Set from {self.jwks_url}")
        self._keys = keys

    def key_for(self, kid: str) -> Ed25519PublicKey:
        if not self._keys:
            raise ProofTokenError("JWKS cache is empty — call load() first")
        try:
            return self._keys[kid]
        except KeyError:
            # Deliberately does NOT re-fetch on an unknown kid. An attacker
            # who can pick the kid could otherwise force an outbound request
            # per forged token, turning this validator into an amplifier.
            # Key rotation is an explicit `load()`, not a side effect of
            # someone else's input.
            raise ProofTokenError(
                f"unknown kid {kid!r}; cached kids are {sorted(self._keys)} "
                "(rotate keys by calling load() again)"
            ) from None


def validate_proof_token(
    token: str,
    jwks: JwksCache,
    *,
    expected_issuer: str,
    now: float | None = None,
    seen_jti: set[str] | None = None,
) -> VerifiedProof:
    """Validate a Memtara proof token entirely offline. Raises on any failure.

    Checks, in order, cheapest-and-most-structural first so a malformed or
    hostile token is rejected before any cryptography runs:

      1. three-segment compact JWS
      2. header declares EdDSA and names a cached kid
      3. Ed25519 signature over `ASCII(header "." payload)`  <- the real check
      4. `iss` matches the issuer this relying party trusts
      5. `verified` is exactly `True`
      6. `exp` has not passed (with clock-skew allowance)
      7. `jti` not already seen, if the caller keeps a seen-set

    Signature before claims is the ordering that matters: nothing in the
    payload means anything until the signature has proven the payload is
    Memtara's.
    """
    now = time.time() if now is None else now

    parts = token.split(".")
    if len(parts) != 3:
        raise ProofTokenError("not a compact JWS (expected three dot-separated segments)")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise ProofTokenError(f"unreadable JWS header: {exc}") from exc

    if header.get("alg") != REQUIRED_ALG:
        raise ProofTokenError(
            f"unsupported alg {header.get('alg')!r}; this validator only accepts {REQUIRED_ALG}"
        )
    kid = header.get("kid")
    if not kid:
        raise ProofTokenError("JWS header has no kid")

    public_key = jwks.key_for(kid)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        public_key.verify(_b64url_decode(signature_b64), signing_input)
    except (InvalidSignature, ValueError) as exc:
        raise ProofTokenError("signature does not verify against the published key") from exc

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise ProofTokenError(f"unreadable JWS payload: {exc}") from exc

    if claims.get("iss") != expected_issuer:
        raise ProofTokenError(
            f"issuer {claims.get('iss')!r} is not the expected {expected_issuer!r}"
        )

    # `is not True` rather than a falsiness check: a token carrying the string
    # "false", or 0, or a missing claim, must all be refused, and only the
    # literal boolean true may pass.
    if claims.get("verified") is not True:
        raise ProofTokenError("token does not assert verified=true")

    exp = claims.get("exp")
    if not isinstance(exp, int):
        raise ProofTokenError("token has no integer exp claim")
    if now > exp + CLOCK_SKEW_SECONDS:
        raise ProofTokenError(f"token expired at {exp} (now {int(now)})")

    jti = claims.get("jti", "")
    if seen_jti is not None:
        if jti in seen_jti:
            raise ProofTokenError(f"token jti {jti} has already been used")
        seen_jti.add(jti)

    return VerifiedProof(
        user_id=claims.get("user_id", ""),
        predicate=claims.get("predicate", ""),
        circuit=claims.get("circuit", ""),
        proof_hash=claims.get("proof_hash", ""),
        regulatory_audit_id=claims.get("regulatory_audit_id", ""),
        cbuae_clauses=tuple(claims.get("cbuae_clauses", ())),
        issuer=claims.get("iss", ""),
        jti=jti,
        expires_at=exp,
        raw_claims=claims,
        product_isin=claims.get("product_isin"),
        # `is True` / `is False`, so a string "true" or a 1 cannot pass
        # themselves off as a verdict — the same reasoning as the `verified`
        # check above, applied to the claim a bank actually acts on.
        suitable=(
            True if claims.get("suitable") is True else False if claims.get("suitable") is False else None
        ),
        dfsa_rules=tuple(claims.get("dfsa_rules", ())),
    )


def inject_claims(
    messages: Iterable[dict[str, Any]],
    proof: VerifiedProof,
    *,
    product_name: str | None = None,
    risk_level: int | None = None,
) -> list[dict[str, Any]]:
    """Prepend the attested facts to an OpenAI-style message list.

    A `system` message rather than an edit to the user's turn: the attestation
    is not something the user said, and folding it into their text would make
    the transcript misattribute it — which matters precisely when someone is
    later auditing who asserted what.

    `product_name` / `risk_level` are passed straight through to
    `as_prompt_preamble`; see its docstring for why registry-sourced facts are
    labelled rather than blended with the signed ones. Callers with no
    registry context omit them and get exactly the previous message.
    """
    return [
        {
            "role": "system",
            "content": proof.as_prompt_preamble(
                product_name=product_name, risk_level=risk_level
            ),
        },
        *messages,
    ]


def audit_event_fields(proof: VerifiedProof) -> dict[str, Any]:
    """The fields to attach to the relying party's own audit record.

    `proof_hash` and `regulatory_audit_id` are the load-bearing ones: together
    they let an auditor take a line out of AIHOOTS's `audit.jsonl`, find the
    matching `proof_token_issued` event in Memtara's `audit_log` chain, and
    confirm both independent hash chains describe the same event — without
    either system ever having called the other.
    """
    fields = {
        "memtara_verified": True,
        "memtara_user_id": proof.user_id,
        "memtara_predicate": proof.predicate,
        "memtara_circuit": proof.circuit,
        "proof_hash": proof.proof_hash,
        "regulatory_audit_id": proof.regulatory_audit_id,
        "cbuae_clauses": list(proof.cbuae_clauses),
        "memtara_issuer": proof.issuer,
    }
    if proof.suitable is not None:
        # The verdict and the instrument go into the chain together. Either
        # alone is useless as evidence: "suitable" without an ISIN does not
        # say what for, and an ISIN without a verdict does not say what was
        # decided.
        fields["memtara_suitable"] = proof.suitable
        fields["memtara_product_isin"] = proof.product_isin
        fields["dfsa_rules"] = list(proof.dfsa_rules)
    return fields


def rejection_event_fields(reason: str) -> dict[str, Any]:
    """Audit fields for a token that failed validation.

    A rejected attestation is exactly as auditable as an accepted one. An
    audit trail that only records the happy path cannot answer "was anyone
    trying to forge attestations at us", which is the question that makes the
    trail worth keeping.
    """
    return {"memtara_verified": False, "memtara_rejection_reason": reason}


class MemtaraAttestationMiddleware:
    """ASGI middleware that validates the attestation and injects its claims.

    Wrap the AIHOOTS gateway with it and every attested request arrives at the
    existing handler with the verified facts already in the message list — the
    gateway's own policy, forwarding and audit logic are untouched:

        from src.gateway.main import app, _chain
        from src.gateway.audit.chain import new_event

        app.add_middleware(
            MemtaraAttestationMiddleware,
            jwks=jwks_cache,
            expected_issuer="https://api.memtara.ai",
            audit_append=_chain.append,
            event_factory=new_event,
        )

    Raw ASGI rather than Starlette's `BaseHTTPMiddleware` for one concrete
    reason: this middleware must *replace the request body* the downstream app
    reads, and `BaseHTTPMiddleware` forwards the original `receive` callable
    from the outer scope, so a rewritten body silently never reaches the
    handler. At the ASGI layer we own `receive` and can hand the handler the
    body we mean it to see. (That failure mode is silent — the request
    succeeds, just without the claims — which is exactly why the test asserts
    on what was forwarded upstream rather than on this module's internals.)

    `audit_append` and `event_factory` are injected rather than imported so
    this module has no dependency on AIHOOTS: the same middleware works in
    front of any gateway that can supply an append-only sink.
    """

    def __init__(
        self,
        app: Any,
        *,
        jwks: JwksCache,
        expected_issuer: str,
        audit_append: Any = None,
        event_factory: Any = None,
        path: str = "/v1/chat/completions",
        seen_jti: set[str] | None = None,
        require_attestation: bool = False,
    ) -> None:
        self.app = app
        self.jwks = jwks
        self.expected_issuer = expected_issuer
        self.audit_append = audit_append
        self.event_factory = event_factory
        self.path = path
        self.seen_jti = seen_jti
        self.require_attestation = require_attestation

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") != self.path:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        body = await _read_body(receive)
        presented = headers.get(PROOF_HEADER)

        if presented is None:
            if self.require_attestation:
                await self._audit("block", rejection_event_fields("no attestation presented"), headers)
                await _send_json(send, 403, {"error": "memtara attestation required"})
                return
            # Unattested traffic is passed through untouched. Gating it is a
            # deployment decision (`require_attestation`), not something this
            # middleware should impose on every route by default.
            await self.app(scope, _replay(body), send)
            return

        try:
            proof = validate_proof_token(
                presented,
                self.jwks,
                expected_issuer=self.expected_issuer,
                seen_jti=self.seen_jti,
            )
        except ProofTokenError as exc:
            await self._audit("block", rejection_event_fields(str(exc)), headers)
            await _send_json(
                send, 403, {"error": "invalid memtara attestation", "reason": str(exc)}
            )
            return

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            # Not our error to diagnose — hand it to the gateway, which
            # already has a response shape for a malformed request.
            await self.app(scope, _replay(body), send)
            return

        payload["messages"] = inject_claims(payload.get("messages", []), proof)
        await self._audit("allow", audit_event_fields(proof), headers)

        new_body = json.dumps(payload).encode()
        # Content-Length must be corrected or a downstream server that trusts
        # it will truncate the injected preamble.
        new_headers = [
            (k, v) for k, v in scope["headers"] if k.decode("latin-1").lower() != "content-length"
        ]
        new_headers.append((b"content-length", str(len(new_body)).encode()))
        await self.app({**scope, "headers": new_headers}, _replay(new_body), send)

    async def _audit(self, decision: str, detail: dict, headers: dict) -> None:
        if self.audit_append is None or self.event_factory is None:
            return
        self.audit_append(
            self.event_factory(
                request_id=str(uuid.uuid4()),
                caller=headers.get("x-caller-id", "anonymous"),
                model=headers.get("x-model", "unknown"),
                event_type="attestation",
                decision=decision,
                detail=detail,
            )
        )


async def _read_body(receive: Any) -> bytes:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            return body


def _replay(body: bytes) -> Any:
    """A `receive` callable that yields `body` once, then blocks on disconnect.

    The trailing `http.disconnect` matters: a downstream app that keeps reading
    after the body is exhausted would otherwise await forever.
    """
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _send_json(send: Any, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
