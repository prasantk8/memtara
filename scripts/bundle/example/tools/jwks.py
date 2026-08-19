"""The pinned JWKS snapshot — the cheapest high-value fix in the bundle.

The exporter is already honest that it does not verify the proof token,
because verifying it needs the issuer's key set and "a pack whose 'verified'
stamp depended on what DNS answered at export time would be asserting
something it cannot evidence" (`export_audit_evidence.py`, `decode_proof_token`).
That reasoning is right and it has a conclusion the exporter did not draw:
if the key set cannot be trusted at verification time, it must be *captured*
at issuance time and shipped inside the pack.

So this module does exactly two things, and keeps them in separate functions
on purpose:

  * `fetch_jwks()` opens a socket. It runs at BUILD time only, on the firm's
    own machine, against the firm's own issuer. It is the only function here
    that can touch a network, and nothing in `verify_bundle.py` imports it.

  * `verify_jwt_against_snapshot()` opens nothing. It takes a token and a
    snapshot dict and does one EdDSA check. Point the snapshot's recorded
    `source_url` at a host that no longer resolves and it still works, which
    is the property the whole bundle is for and which `tests/test_bundle.py`
    asserts by doing precisely that.

Pinning is by two independent identifiers, not one. `kid` is what the JWT
header names, and a key set that lies could put any `kid` on any key. The
RFC 7638 thumbprint is computed *from the key material itself*, so a
substituted key cannot keep the thumbprint. `backend/api/src/crypto/signer.rs`
derives its `kid` as that same thumbprint, so on an honest snapshot the two
agree — and `snapshot_from_jwks` records whether they did rather than
assuming it, because the day they disagree is a day an auditor needs told.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# Mirrors `ALG` in backend/api/src/crypto/signer.rs. Ed25519 only: a verifier
# that accepted whatever `alg` the token asked for would accept `none`.
EXPECTED_ALG = "EdDSA"
EXPECTED_KTY = "OKP"
EXPECTED_CRV = "Ed25519"

JWKS_PATH = "/.well-known/jwks.json"


class JwksError(Exception):
    """A snapshot or a token that cannot be used as evidence."""


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def okp_thumbprint(x: str) -> str:
    """RFC 7638 thumbprint of an OKP Ed25519 key, from `x` alone.

    Built as a literal byte string rather than by serialising a dict, for the
    same reason `signer.rs::jwk_thumbprint` does: RFC 7638 fixes the member
    order and forbids insignificant whitespace, so the value is a property of
    one exact byte string and not of "some JSON with these fields". Two
    implementations that both round-trip through a dict can still disagree;
    two that write the bytes out cannot.
    """
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'
    return _b64url_nopad(hashlib.sha256(canonical.encode("utf-8")).digest())


# ---------------------------------------------------------------------------
# BUILD time — the only place in this package that may open a socket
# ---------------------------------------------------------------------------


def jwks_url(base_url: str) -> str:
    return base_url.rstrip("/") + JWKS_PATH


def fetch_jwks(base_url: str, timeout: float = 15.0) -> dict:
    """GET the issuer's live key set. Build time only. Never called by the verifier.

    A failure here must stop the build with a message, not fall back to an
    empty key set: a bundle carrying `{"keys": []}` looks like a bundle that
    was pinned and is in fact a bundle that pinned nothing.
    """
    url = jwks_url(base_url)
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "memtara-bundle/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        raise JwksError(f"GET {url} failed: HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise JwksError(f"cannot reach {url}: {exc.reason}") from exc

    try:
        jwks = json.loads(body)
    except ValueError as exc:
        raise JwksError(f"{url} did not return JSON: {body[:200]!r}") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise JwksError(f"{url} did not return a JWK Set (no 'keys' array)")
    if not jwks["keys"]:
        raise JwksError(
            f"{url} returned an empty key set. Pinning nothing is worse than not "
            "pinning, because the bundle would claim a snapshot it does not have."
        )
    return jwks


def snapshot_from_jwks(jwks: dict, *, source_url: str, fetched_at: datetime | None = None) -> dict:
    """Wrap a key set in the provenance a verifier needs to use it offline.

    The recorded `source_url` is provenance, NOT an instruction. It says where
    these bytes came from on the day they were captured. `verify_bundle.py`
    never dereferences it, and the test suite proves that by writing an
    unreachable host into this field and verifying the token anyway.
    """
    moment = (fetched_at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)

    pinned = []
    for index, key in enumerate(jwks.get("keys", [])):
        if not isinstance(key, dict):
            raise JwksError(f"keys[{index}] is not an object")
        x = key.get("x")
        if key.get("kty") != EXPECTED_KTY or key.get("crv") != EXPECTED_CRV or not isinstance(x, str):
            # Recorded, not silently dropped. A key set that grew an RSA key
            # is a fact about the issuer an auditor should see, even though
            # this bundle cannot pin it by OKP thumbprint.
            pinned.append(
                {
                    "kid": key.get("kid"),
                    "kty": key.get("kty"),
                    "crv": key.get("crv"),
                    "thumbprint_rfc7638": None,
                    "kid_equals_thumbprint": None,
                    "note": "not an OKP Ed25519 key; this bundle cannot pin it by thumbprint",
                }
            )
            continue
        thumbprint = okp_thumbprint(x)
        pinned.append(
            {
                "kid": key.get("kid"),
                "kty": EXPECTED_KTY,
                "crv": EXPECTED_CRV,
                "alg": key.get("alg", EXPECTED_ALG),
                "thumbprint_rfc7638": thumbprint,
                "kid_equals_thumbprint": key.get("kid") == thumbprint,
            }
        )

    return {
        "jwks": jwks,
        "pinned_keys": pinned,
        "source_url": source_url,
        "fetched_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "how_to_use": (
            "Verify the token in decision_evidence.json against the keys in `jwks` and "
            "nothing else. Do not dereference source_url: it records where these bytes "
            "came from, it is not somewhere to go and look. A key set fetched today "
            "evidences today's DNS, not the issuance this pack is about."
        ),
        "what_this_does_not_prove": (
            "That this key set was the issuer's at issuance time. These bytes were "
            "captured by the exporting firm at the timestamp above; a firm that captured "
            "a key set of its own making would produce a self-consistent pack. The "
            "snapshot removes the dependency on the issuer still existing; it does not "
            "remove the need for the thumbprint below to match one an auditor obtained "
            "independently — from the firm's key register, a published fingerprint, or "
            "an earlier pack from the same issuer."
        ),
    }


# ---------------------------------------------------------------------------
# VERIFY time — no sockets, no imports that can open one
# ---------------------------------------------------------------------------


def _key_material(snapshot: dict) -> list[dict]:
    jwks = snapshot.get("jwks")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise JwksError("the snapshot carries no 'jwks.keys' array")
    return [key for key in jwks["keys"] if isinstance(key, dict)]


def verify_jwt_against_snapshot(token: str, snapshot: dict, *, now: datetime | None = None) -> dict:
    """One EdDSA check against a pinned key. Returns findings; raises nothing routine.

    Signature validity and token expiry are reported as two separate fields
    because they are two separate facts. These tokens live for a few minutes
    and every one an examiner ever sees will be long expired — treating that
    as a verification failure would train readers to ignore the only real
    failure this function can report.
    """
    finding: dict[str, Any] = {
        "checked": False,
        "signature_valid": None,
        "kid": None,
        "kid_matched_a_pinned_key": None,
        "thumbprint_rfc7638": None,
        "thumbprint_matches_kid": None,
        "expired": None,
        "expires_at": None,
        "alg": None,
        "reason": None,
    }

    parts = token.strip().split(".")
    if len(parts) != 3:
        finding["reason"] = f"not a compact JWS ({len(parts)} dot-separated parts, expected 3)"
        return finding

    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except (ValueError, TypeError) as exc:
        finding["reason"] = f"token could not be decoded: {exc}"
        return finding
    if not isinstance(header, dict) or not isinstance(claims, dict):
        finding["reason"] = "header and payload must both be JSON objects"
        return finding

    finding["alg"] = header.get("alg")
    finding["kid"] = header.get("kid")

    if header.get("alg") != EXPECTED_ALG:
        # Refused rather than attempted. Algorithm agility in a verifier is
        # how `alg: none` gets accepted; this system issues EdDSA and nothing
        # else (`signer.rs::ALG`).
        finding["reason"] = (
            f"token declares alg={header.get('alg')!r}; this bundle verifies {EXPECTED_ALG} only"
        )
        return finding

    try:
        keys = _key_material(snapshot)
    except JwksError as exc:
        finding["reason"] = str(exc)
        return finding

    kid = header.get("kid")
    candidates = [k for k in keys if k.get("kid") == kid] if kid else []
    finding["kid_matched_a_pinned_key"] = bool(candidates)
    if not candidates:
        finding["reason"] = (
            f"no key in the pinned snapshot has kid={kid!r}. The token was issued under a "
            "key this bundle did not capture, so its origin cannot be checked here."
        )
        return finding

    key = candidates[0]
    x = key.get("x")
    if key.get("kty") != EXPECTED_KTY or key.get("crv") != EXPECTED_CRV or not isinstance(x, str):
        finding["reason"] = "the pinned key with this kid is not an OKP Ed25519 key"
        return finding

    thumbprint = okp_thumbprint(x)
    finding["thumbprint_rfc7638"] = thumbprint
    finding["thumbprint_matches_kid"] = thumbprint == kid
    if thumbprint != kid:
        # Not fatal to the signature check, but it is a finding: this issuer
        # derives kid *from* the key (signer.rs::from_seed), so a mismatch
        # means the snapshot was assembled by something else.
        finding["reason"] = (
            "the pinned key's RFC 7638 thumbprint does not equal its kid. This issuer "
            "derives one from the other, so the two disagreeing means the key set was "
            "not produced by it."
        )

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover - cryptography is a declared dependency
        finding["reason"] = "the `cryptography` package is not installed, so EdDSA cannot be checked"
        return finding

    try:
        public_bytes = _b64url_decode(x)
    except (ValueError, TypeError) as exc:
        finding["reason"] = f"the pinned key's `x` is not base64url: {exc}"
        return finding

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    finding["checked"] = True
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, signing_input)
        finding["signature_valid"] = True
    except (InvalidSignature, ValueError) as exc:
        finding["signature_valid"] = False
        finding["reason"] = f"EdDSA signature does not verify against the pinned key ({exc})"
        return finding

    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires = datetime.fromtimestamp(exp, tz=timezone.utc)
        finding["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
        finding["expired"] = expires < moment

    return finding
