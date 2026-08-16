"""Suitability orchestration in front of the AIHOOTS gateway.

`memtara_claims.MemtaraAttestationMiddleware` is the normal path: the caller
already holds an attestation, presents it in a header, and the gateway
validates it with one local signature check. No network hop, no shared
secret, no dependency on Memtara being up.

This module is the other shape, and the difference is worth stating plainly
because it is a real trade-off rather than a variant:

    attestation middleware   caller brings the token      0 outbound calls
    this module              gateway obtains the token    2 outbound calls
                                                          + a proof (~2s)

The commissioning brief asks for the second: a wealth adviser types
"recommend the 5-year note to <client>" into a chat box and the gateway is
expected to go and get the evidence. That is genuinely useful — the adviser
has no way to produce a proof and shouldn't need to know one exists — but it
puts Memtara and the client's device on the critical path of a chat
completion. Deploy it for advised-sales desks where that latency is
acceptable and the evidence requirement is absolute; keep the header path for
everything else.

Both paths converge: whatever obtains the token, the gateway validates it
offline with `validate_proof_token` before believing a word of it. The
orchestrator does not get to skip that check just because it fetched the
token itself — a compromised orchestrator would otherwise be able to inject
arbitrary "verified" facts into the model's context.

-------------------------------------------------------------------------
WHAT THIS MODULE DELIBERATELY DOES NOT DO
-------------------------------------------------------------------------
It does not read the client's vault. The brief's sketch has the middleware
"load the user's vault data" and generate a proof — that would put the
plaintext of every client's finances inside the LLM gateway, which is the
exact thing the vault architecture exists to prevent, and it would make the
zero-knowledge property decorative.

Instead the prover is an injected capability (`assess`): a callable that
means "ask the holder's device to answer this". In the demo and in the tests
that callable runs `clients/wealth_client.py` locally, standing in for the
mobile app. In a deployment it is a push notification. The gateway's code is
the same either way, and at no point does this module hold a figure.

It also does not take product terms from the prompt. `"(risk level 3)"` in a
user's message is attacker-controlled text; if it set the threshold, a client
could talk their way into suitability. Terms come from the bank's product
registry, and a disagreement with the prompt is recorded in the audit trail
rather than resolved in the prompt's favour.

-------------------------------------------------------------------------
WHERE THE TERMS COME FROM, AND HOW MANY CALLS THAT COSTS
-------------------------------------------------------------------------
This module used to be handed a `product_master` dict at construction: the
deployment told the gateway what each instrument's terms were. That was
always a copy of something, and a copy that drifts is worse than no copy —
evidence filed against terms the bank no longer sells is evidence of nothing.
The server now owns a product registry (`backend/api/src/products/mod.rs`)
and there are two ways to read it:

    POST /api/v1/issue-wealth-request   echoes product_name, product_id and
                                        all four terms, as a snapshot taken
                                        at the moment the assessment opened
    GET  /api/v1/products/{isin}        the full catalogue row, including
                                        approved_by_risk_committee and
                                        check_digit_valid

The authoritative source here is the first one, and it is free: opening the
assessment is a call this module has to make anyway, and the terms it echoes
are the terms the resulting proof actually commits to. Reading the catalogue
separately and rendering *that* would let the two disagree — a PATCH landing
between the two calls is enough — and the version that matters is the one
inside the signature.

`GET /api/v1/products/{isin}` therefore does not run per prompt on the strength
of "display data". It earns its round trip in exactly one place, as an
optional `product_lookup`: deciding whether an ISIN is an instrument this bank
sells at all, *before* the assessment opens. That check is not about latency.
In a deployment `assess` wakes a customer's phone with a push notification, so
a prompt that mentions US0378331005 in passing must not become a suitability
prompt on someone's lock screen. A gateway that can answer "we don't sell
that" from a cached registry row spares them. Configure it with a TTL cache
(`registry_lookup` below); a deployment that would rather not make the call
can pass `{"XS1234567890": ProductTerms(...)}.get` or omit it entirely, in
which case an unsold ISIN is caught one hop later by the server's own 404.

-------------------------------------------------------------------------
THE RISK-LEVEL DISCREPANCY IS ITS OWN EVENT
-------------------------------------------------------------------------
An adviser who writes "it is only risk level 1" about a level-4 note has
described the mis-selling pattern that DFSA COB 3.1 exists to catch, in their
own words, in a system that keeps a tamper-evident record. Recording that as
one more key inside the detail blob of a successful assessment buries it: a
CRO would have to know to look inside a success. It is written as its own
`suitability_risk_discrepancy` event so it can be found by event type, counts
independently, and survives the case where the assessment afterwards fails
and there is no success event to hang it on.

It changes nothing about what is assessed. The registry's level is the level,
always; the prompt's claim is evidence about the adviser, not input to the
circuit — and since `assess` is no longer passed any terms at all, there is no
longer a parameter through which a prompt could reach the assessment even by
mistake.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from memtara_claims import (
    JwksCache,
    ProofTokenError,
    VerifiedProof,
    _read_body,
    _replay,
    _send_json,
    audit_event_fields,
    inject_claims,
    rejection_event_fields,
    validate_proof_token,
)

# ISO 6166: two letters, nine alphanumerics, one check digit. Anchored on
# word boundaries so an ISIN embedded in a longer token isn't matched.
ISIN_RE = re.compile(r"\b([A-Z]{2}[A-Z0-9]{9}[0-9])\b")

# A risk level the prompt claims. Captured only so a disagreement with the
# registry can be recorded — never used as the threshold.
CLAIMED_RISK_RE = re.compile(r"risk\s*level\s*(\d)", re.IGNORECASE)

# The two `event_type` values this module writes into AIHOOTS's chain.
#
# AIHOOTS's own events are "request" / "decision" / "response"; both of these
# are additions, and `src/stats/analyzer.py` selects on `event_type ==
# "decision"` throughout, so neither one perturbs their block-rate or latency
# figures. Their verifier is agnostic to the value — it re-hashes whatever it
# finds — so a new type cannot break chain verification either.
SUITABILITY_EVENT_TYPE = "suitability"
RISK_DISCREPANCY_EVENT_TYPE = "suitability_risk_discrepancy"

# `decision` on a discrepancy event. Deliberately outside AIHOOTS's
# allow/redact/block/n/a vocabulary, and that is the honest weakness of this
# choice: it is a fifth value in a field their docs describe as having four.
# The alternative was "n/a", which is what the field means when nothing was
# decided — but nothing being decided is precisely what this event is not
# about. Something was noticed and deliberately not acted on, and a CRO
# filtering an export on decision should see that. Nothing downstream reads
# this value (see the note above), so the cost is a documentation mismatch
# rather than a behavioural one.
RISK_DISCREPANCY_DECISION = "flag"

# Subject identifiers this parser will pick out of a sentence. Two shapes:
# an explicit uuid, or a bare token the deployment's own resolver will map
# (the brief's examples are `wealth_demo` and `user_9981`).
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
SUBJECT_RE = re.compile(r"\b(?:user[_ ]|client[_ ])?([a-z][a-z0-9_]{2,31})\b", re.IGNORECASE)

# Words that would otherwise be picked up as a subject by SUBJECT_RE. Kept
# small on purpose: the resolver is the real filter, and a stop list that
# tries to be exhaustive would quietly start dropping legitimate client
# identifiers.
_STOPWORDS = frozenset(
    {
        "check", "if", "is", "suitable", "for", "the", "structured", "product",
        "isin", "recommend", "note", "risk", "level", "to", "a", "an", "and",
        "should", "we", "sell", "buy", "client", "user", "year", "please",
    }
)


@dataclass(frozen=True)
class WealthIntent:
    """A recognised request to recommend or assess a specific instrument."""

    product_isin: str
    subject_hint: str | None
    claimed_risk_level: int | None


def parse_wealth_intent(text: str) -> WealthIntent | None:
    """Recognise a suitability-relevant prompt, or return None.

    Intentionally conservative: an ISIN must be present. Guessing an
    instrument from "the 5-year S&P note" would mean the gateway picking
    which product a recommendation is about, and picking wrong produces
    evidence filed against the wrong instrument — worse than no evidence.
    A deployment that wants free-text product names should resolve them to
    an ISIN in its own front end, where a human can confirm the match.
    """
    isin_match = ISIN_RE.search(text)
    if not isin_match:
        return None
    isin = isin_match.group(1)

    subject: str | None = None
    uuid_match = UUID_RE.search(text)
    if uuid_match:
        subject = uuid_match.group(0)
    else:
        for candidate in SUBJECT_RE.finditer(text):
            token = candidate.group(1)
            if token.lower() in _STOPWORDS or token == isin:
                continue
            subject = token
            break

    risk_match = CLAIMED_RISK_RE.search(text)
    claimed_risk = int(risk_match.group(1)) if risk_match else None
    return WealthIntent(product_isin=isin, subject_hint=subject, claimed_risk_level=claimed_risk)


@dataclass(frozen=True)
class ProductTerms:
    """One row of the bank's product registry, as this module sees it.

    The authority on what "suitable" means for an instrument, and on what the
    instrument is called. Comes from the server, never from the prompt.

    Still called `ProductTerms` although it now carries more than terms. The
    name is what every caller and test in the repo imports, and renaming a
    type across a submodule boundary to improve a noun is not worth the churn;
    the docstring is the correction.

    Everything past `product_risk_level` is optional because the two registry
    reads return different amounts. `issue-wealth-request` echoes the terms,
    the name and the row id; `GET /api/v1/products/{isin}` adds the governance
    columns. A field being `None` means "this read did not tell us", which is
    a different fact from `False` — `approved_by_risk_committee is None` must
    never be treated as "not approved", because a product nobody asked about
    is not a product the committee rejected.
    """

    min_income: int
    min_liquidity: int
    max_concentration_percent: int
    product_risk_level: int
    description: str = ""
    product_name: str = ""
    product_isin: str | None = None
    product_id: str | None = None
    approved_by_risk_committee: bool | None = None
    check_digit_valid: bool | None = None

    @property
    def display_name(self) -> str:
        """What to call this instrument in front of a model or a person.

        Falls back to the ISIN rather than to an empty string: a message that
        says `product name:` and then nothing reads like a bug, and an ISIN is
        at least true.
        """
        return self.product_name or self.product_isin or ""

    @classmethod
    def from_assessment_request(cls, request: Any) -> "ProductTerms | None":
        """Read the registry snapshot echoed by `issue-wealth-request`.

        Returns `None` rather than raising on anything unexpected. The caller
        is mid-request with a live proof in hand at this point, and refusing
        an otherwise valid attestation because a display field was missing
        would trade real evidence for a cosmetic guarantee. A `None` here
        degrades to "no product name in the preamble", which is what the
        previous version of this module did on every request.
        """
        if not isinstance(request, Mapping):
            return None
        try:
            return cls(
                min_income=int(request["min_income"]),
                min_liquidity=int(request["min_liquidity"]),
                max_concentration_percent=int(request["max_concentration_percent"]),
                product_risk_level=int(request["product_risk_level"]),
                product_name=str(request.get("product_name") or ""),
                product_isin=request.get("product_isin"),
                product_id=(
                    str(request["product_id"]) if request.get("product_id") is not None else None
                ),
            )
        except (KeyError, TypeError, ValueError):
            return None

    @classmethod
    def from_registry_row(cls, row: Mapping[str, Any]) -> "ProductTerms":
        """Read a full `GET /api/v1/products/{isin}` response.

        Note `risk_level` on the wire becoming `product_risk_level` here: the
        catalogue column and the circuit's public input are the same number
        under two names, and this is the one place the translation happens.
        """
        return cls(
            min_income=int(row["min_income"]),
            min_liquidity=int(row["min_liquidity"]),
            max_concentration_percent=int(row["max_concentration_percent"]),
            product_risk_level=int(row["risk_level"]),
            product_name=str(row.get("product_name") or ""),
            product_isin=row.get("product_isin"),
            product_id=(str(row["id"]) if row.get("id") is not None else None),
            approved_by_risk_committee=row.get("approved_by_risk_committee"),
            check_digit_valid=row.get("check_digit_valid"),
        )


def prompt_text(messages: Iterable[Mapping[str, Any]]) -> str:
    """The user-authored text of a chat request, concatenated.

    System messages are excluded on purpose: a suitability assessment should
    be triggered by what the adviser asked for, not by anything a previous
    injection managed to place in the system slot.
    """
    parts = []
    for message in messages:
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # OpenAI multi-part content.
            parts.extend(part.get("text", "") for part in content if isinstance(part, dict))
    return "\n".join(parts)


class WealthSuitabilityMiddleware:
    """ASGI middleware that obtains a suitability attestation on demand.

    Raw ASGI for the same reason `MemtaraAttestationMiddleware` is: the
    request body handed to the downstream app has to be the rewritten one,
    and `BaseHTTPMiddleware` forwards the original `receive`.

        app.add_middleware(
            WealthSuitabilityMiddleware,
            jwks=jwks_cache,
            expected_issuer="https://api.memtara.ai",
            assess=device_assessor(...),
            product_lookup=registry_lookup(base_url, org_api_key=...),
            resolve_subject=lambda hint: directory.get(hint),
            audit_append=_chain.append,
            event_factory=new_event,
        )

    `assess` takes `(user_id, product_isin)` and nothing else. It used to take
    the terms as well; it does not, because the server reads them from the
    registry now and a parameter that can carry terms is a parameter through
    which a prompt could one day carry them. The return value is the
    `submit-wealth-proof` response, with the `issue-wealth-request` body under
    `request` — `clients/wealth_client.assess` already returns exactly that.

    Every failure mode short of "the assessment came back" ends in the
    request being passed through unchanged, with an audit entry saying why.
    That is the right default for a middleware sitting in front of general
    chat traffic: most prompts are not suitability requests, and turning an
    unrecognised one into a 4xx would break the gateway for everything else.
    Set `block_unassessed=True` on a desk where a recommendation must never
    be generated without evidence — there, a failure to assess should stop
    the request.
    """

    def __init__(
        self,
        app: Any,
        *,
        jwks: JwksCache,
        expected_issuer: str,
        assess: Callable[[str, str], Mapping[str, Any]],
        product_lookup: Callable[[str], ProductTerms | None] | None = None,
        resolve_subject: Callable[[str | None], str | None] | None = None,
        audit_append: Any = None,
        event_factory: Any = None,
        path: str = "/v1/chat/completions",
        block_unassessed: bool = False,
    ) -> None:
        self.app = app
        self.jwks = jwks
        self.expected_issuer = expected_issuer
        self.assess = assess
        # Optional. `None` means "open the assessment and let the server's own
        # 404 tell us" — correct, one hop later, and at the cost of a push
        # notification the customer did not need. See the module header.
        self.product_lookup = product_lookup
        self.resolve_subject = resolve_subject or (lambda hint: hint)
        self.audit_append = audit_append
        self.event_factory = event_factory
        self.path = path
        self.block_unassessed = block_unassessed

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") != self.path:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        body = await _read_body(receive)

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            await self.app(scope, _replay(body), send)
            return

        messages = payload.get("messages", [])
        intent = parse_wealth_intent(prompt_text(messages))
        if intent is None:
            await self.app(scope, _replay(body), send)
            return

        # From here on every audit event carries the instrument, whatever the
        # outcome. `proof_hash` is stamped by `_audit` for the same reason:
        # both are join keys, and a join key that only appears on success
        # cannot answer "show me everything that happened about this ISIN".
        detail_extra: dict[str, Any] = {
            "memtara_product_isin": intent.product_isin,
            "memtara_subject_hint": intent.subject_hint,
        }

        # The registry, read at most once and only if a lookup is configured.
        product: ProductTerms | None = None
        # The registry risk level the prompt has already been checked against,
        # so the discrepancy check runs once per interaction and not once per
        # registry read — except in the case that justifies a second look, a
        # catalogue amendment landing between the two reads and changing the
        # very number under dispute.
        checked_against: int | None = None
        if self.product_lookup is not None:
            try:
                product = self.product_lookup(intent.product_isin)
            except Exception as exc:  # noqa: BLE001 - registry unreachable
                # Not a pass-through-and-forget: we cannot tell "we don't sell
                # this" from "the registry is down", and the safe reading of
                # an unknown is that the customer's phone should stay quiet.
                await self._skip(
                    send, scope, body, headers,
                    f"product registry lookup failed for {intent.product_isin}: {exc}",
                    detail_extra,
                )
                return
            if product is None:
                await self._skip(
                    send, scope, body, headers,
                    f"{intent.product_isin} is not in the product registry",
                    detail_extra,
                )
                return
            detail_extra["memtara_product_name"] = product.display_name
            # Flagged here rather than after the assessment, when we can: an
            # adviser talking a product's risk down is worth surfacing even if
            # the client never answers their phone and no verdict ever exists.
            await self._flag_risk_discrepancy(intent, product, headers, detail_extra)
            checked_against = product.product_risk_level

        user_id = self.resolve_subject(intent.subject_hint)
        if not user_id:
            await self._skip(
                send, scope, body, headers,
                f"could not resolve a client from {intent.subject_hint!r}",
                detail_extra,
            )
            return

        try:
            # No terms argument. The server reads them from the registry and
            # binds them into the proof; this module could not override them
            # if it wanted to, which is the point.
            result = self.assess(user_id, intent.product_isin)
        except Exception as exc:  # noqa: BLE001 - any failure means "no evidence"
            await self._skip(send, scope, body, headers, f"assessment failed: {exc}", detail_extra)
            return

        # The authoritative read: the registry snapshot the assessment was
        # actually opened against, echoed back to us for free. It supersedes
        # anything `product_lookup` said, because a PATCH between the two
        # reads makes the catalogue row and the proof's terms different
        # objects and the proof's terms are the ones under signature.
        echoed = ProductTerms.from_assessment_request(result.get("request"))
        if echoed is not None:
            product = echoed
            detail_extra["memtara_product_name"] = product.display_name
            if product.product_id:
                # The catalogue row the terms came from. Memtara's evidence
                # exporter follows it to show which entry, under which
                # governance state, supplied the thresholds — so it is worth
                # the eight bytes in AIHOOTS's chain as well.
                detail_extra["memtara_product_id"] = product.product_id
            if checked_against != product.product_risk_level:
                await self._flag_risk_discrepancy(intent, product, headers, detail_extra)
                checked_against = product.product_risk_level

        token = result.get("proof_token", "")
        try:
            # The gateway validates what it was handed even though it asked
            # for it. See the module header: fetching a token is not a reason
            # to trust it.
            proof: VerifiedProof = validate_proof_token(
                token, self.jwks, expected_issuer=self.expected_issuer
            )
        except ProofTokenError as exc:
            await self._audit("block", {**rejection_event_fields(str(exc)), **detail_extra}, headers)
            await _send_json(send, 502, {"error": "memtara returned an unusable attestation", "reason": str(exc)})
            return

        if proof.suitable is None:
            await self._audit(
                "block",
                {
                    **rejection_event_fields("attestation carries no suitability verdict"),
                    # Refused, but a real proof was refused. The hash is what
                    # lets an auditor pull the corresponding issuance out of
                    # Memtara's chain and see what this token actually was.
                    "proof_hash": proof.proof_hash,
                    **detail_extra,
                },
                headers,
            )
            await _send_json(send, 502, {"error": "attestation is not a suitability assessment"})
            return

        if proof.product_isin != intent.product_isin:
            # The one substitution a signed token cannot rule out on its own:
            # a valid attestation for a *different* instrument. Checking it
            # here is what makes the evidence about the right product.
            await self._audit(
                "block",
                {
                    **rejection_event_fields(
                        f"attestation is for {proof.product_isin}, not {intent.product_isin}"
                    ),
                    "proof_hash": proof.proof_hash,
                    # Both instruments, named. `memtara_product_isin` is the
                    # one that was asked about; without the other, the record
                    # says a substitution happened but not what was
                    # substituted in, which is the only interesting half.
                    "memtara_attested_product_isin": proof.product_isin,
                    **detail_extra,
                },
                headers,
            )
            await _send_json(send, 502, {"error": "attestation is for a different product"})
            return

        payload["messages"] = inject_claims(
            messages,
            proof,
            # `product` is the registry's word, not the prompt's, in every
            # branch that can reach here — either the echo or the lookup.
            product_name=product.display_name if product else None,
            risk_level=product.product_risk_level if product else None,
        )
        await self._audit("allow", {**audit_event_fields(proof), **detail_extra}, headers)

        new_body = json.dumps(payload).encode()
        new_headers = [
            (k, v) for k, v in scope["headers"] if k.decode("latin-1").lower() != "content-length"
        ]
        new_headers.append((b"content-length", str(len(new_body)).encode()))
        await self.app({**scope, "headers": new_headers}, _replay(new_body), send)

    async def _skip(
        self,
        send: Any,
        scope: dict,
        body: bytes,
        headers: dict,
        reason: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        detail = {**rejection_event_fields(reason), **(extra or {})}
        if self.block_unassessed:
            await self._audit("block", detail, headers)
            await _send_json(send, 403, {"error": "suitability evidence required", "reason": reason})
            return
        await self._audit("skip", detail, headers)
        await self.app(scope, _replay(body), send)

    async def _flag_risk_discrepancy(
        self,
        intent: WealthIntent,
        product: ProductTerms,
        headers: dict,
        detail_extra: dict[str, Any],
    ) -> bool:
        """Record that the prompt and the registry disagree about risk level.

        Two records, not one, and both on purpose:

        * `memtara_prompt_risk_level_ignored` stays in `detail_extra`, so it
          rides along on whatever event this interaction eventually produces.
          Reading a single suitability event should not require joining to
          another one to learn that the adviser misdescribed the product.
        * a `suitability_risk_discrepancy` event of its own, so the population
          can be counted, exported and alerted on by event type — and so it
          exists even when the interaction produces no success event at all,
          which is exactly the case a "field on the success event" loses.

        Returns whether anything was flagged, so the caller can tell "checked,
        agreed" from "checked, disagreed" — a prompt that states the correct
        risk level is the overwhelmingly common case and must stay silent.
        """
        claimed = intent.claimed_risk_level
        if claimed is None or claimed == product.product_risk_level:
            return False

        detail_extra["memtara_prompt_risk_level_ignored"] = claimed
        detail_extra["memtara_registry_risk_level"] = product.product_risk_level

        await self._audit(
            RISK_DISCREPANCY_DECISION,
            {
                "memtara_risk_level_discrepancy": True,
                "memtara_prompt_risk_level": claimed,
                "memtara_registry_risk_level": product.product_risk_level,
                "memtara_product_isin": intent.product_isin,
                "memtara_product_name": product.display_name,
                "memtara_subject_hint": intent.subject_hint,
                "memtara_rejection_reason": (
                    f"prompt asserted risk level {claimed} for {intent.product_isin}; "
                    f"the registry says {product.product_risk_level}. The registry's "
                    "level was used for the assessment."
                ),
            },
            headers,
            event_type=RISK_DISCREPANCY_EVENT_TYPE,
        )
        return True

    async def _audit(
        self,
        decision: str,
        detail: dict,
        headers: dict,
        event_type: str = SUITABILITY_EVENT_TYPE,
    ) -> None:
        if self.audit_append is None or self.event_factory is None:
            return
        # `proof_hash` on every event this module writes, empty when no proof
        # was ever validated. Present-and-empty rather than absent because it
        # is the join key into Memtara's evidence pack: an auditor selecting
        # `proof_hash` across `audit.jsonl` should get one row per suitability
        # interaction, with the ones that produced no evidence visible as
        # blanks rather than silently missing from the result set. An absent
        # key cannot be distinguished from a logging bug; an empty one can.
        detail.setdefault("proof_hash", "")
        self.audit_append(
            self.event_factory(
                request_id=str(uuid.uuid4()),
                caller=headers.get("x-caller-id", "anonymous"),
                model=headers.get("x-model", "unknown"),
                event_type=event_type,
                decision=decision,
                detail=detail,
            )
        )


def _wealth_client() -> Any:
    """Import `clients/wealth_client.py` without making it an import-time cost.

    Deferred rather than top-level because importing this module must stay
    cheap for the gateway, and because a deployment that supplies its own
    `assess` and `product_lookup` should not need the device client on the
    path at all.
    """
    import sys
    from pathlib import Path

    clients_dir = Path(__file__).resolve().parents[2] / "clients"
    if str(clients_dir) not in sys.path:
        sys.path.insert(0, str(clients_dir))
    import wealth_client  # noqa: PLC0415 - see docstring

    return wealth_client


def device_assessor(
    base_url: str,
    *,
    org_api_key: str,
    user_credential: str,
    vault_for: Callable[[str], Any],
    ttl_seconds: int = 900,
) -> Callable[[str, str], Mapping[str, Any]]:
    """Build an `assess` callable backed by `clients/wealth_client.py`.

    `vault_for` is the seam that keeps this honest: it stands for "reach the
    holder's device and ask it to prove", and in a deployment it is a push
    notification and a wait, not a dictionary lookup. It is a parameter and
    not an import precisely so that swapping the local stand-in for the real
    thing changes no code in this module.

    No terms are passed. `open_assessment` reads them from the registry and
    returns them, and this closure has nothing to contribute to that decision
    — which is why the closure no longer accepts anything that could look like
    a contribution.
    """
    wealth_client = _wealth_client()

    def assess(user_id: str, product_isin: str) -> Mapping[str, Any]:
        return wealth_client.assess(
            base_url,
            org_api_key=org_api_key,
            user_credential=user_credential,
            user_id=user_id,
            product_isin=product_isin,
            vault=vault_for(user_id),
            ttl_seconds=ttl_seconds,
        )

    return assess


def registry_lookup(
    base_url: str,
    *,
    org_api_key: str,
    cache_seconds: float = 300.0,
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[str], ProductTerms | None]:
    """Build a `product_lookup` over `GET /api/v1/products/{isin}`, cached.

    The cache is the whole point. Without it this is an outbound call on every
    prompt that happens to contain twelve characters shaped like an ISIN, on a
    catalogue that changes when a product committee meets — a read pattern
    with a very high hit rate against data with a very low change rate. Five
    minutes is a compromise nobody will defend to the decimal: long enough
    that a busy desk makes one call per instrument per coffee break, short
    enough that an amendment or a withdrawal takes effect within one.

    Negative results are cached too, and that is the load-bearing half. The
    prompts that miss are the ones nobody registered — chatter about a
    competitor's note, a typo, someone pasting a research page — and they are
    unbounded in variety, so an implementation that only cached hits would
    make every unknown ISIN a round trip and hand a caller a cheap way to
    generate outbound traffic by inventing identifiers.

    What this deliberately does NOT do is supply the terms an assessment runs
    against. It answers "does this bank sell this, and what is it called". The
    terms come back from `issue-wealth-request`, under signature; see the
    module header.

    `clock` is injectable so a test can age the cache without sleeping. It
    defaults to `time.monotonic` rather than `time.time` because a wall-clock
    step backwards would otherwise pin an entry as fresh indefinitely.
    """
    wealth_client = _wealth_client()
    cache: dict[str, tuple[float, ProductTerms | None]] = {}

    def lookup(product_isin: str) -> ProductTerms | None:
        now = clock()
        cached = cache.get(product_isin)
        if cached is not None and now - cached[0] < cache_seconds:
            return cached[1]

        try:
            row = wealth_client.get_product(base_url, org_api_key, product_isin)
        except Exception as exc:  # noqa: BLE001 - narrowed below
            # A 404 is an answer: the bank does not sell this. Anything else
            # is the registry failing to answer, which must propagate — the
            # middleware refuses to assess when it cannot tell the two apart,
            # and swallowing the difference here would quietly turn an outage
            # into "we sell nothing".
            if getattr(exc, "status", None) == 404:
                cache[product_isin] = (now, None)
                return None
            raise

        product = ProductTerms.from_registry_row(row)
        cache[product_isin] = (now, product)
        return product

    return lookup


__all__ = [
    "ISIN_RE",
    "RISK_DISCREPANCY_DECISION",
    "RISK_DISCREPANCY_EVENT_TYPE",
    "SUITABILITY_EVENT_TYPE",
    "ProductTerms",
    "WealthIntent",
    "WealthSuitabilityMiddleware",
    "device_assessor",
    "parse_wealth_intent",
    "prompt_text",
    "registry_lookup",
]
