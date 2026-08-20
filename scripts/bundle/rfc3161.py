"""Offline, cryptographic verification of an RFC 3161 `TimeStampToken`.

This is the piece that turns `verify_bundle.py` step 7c from a stub that
reports a file's presence into an actual check. Split into its own module
for the same reason `jwks.py` is separate from `verify_bundle.py`'s control
flow: the parsing and the trust decision are a self-contained job, testable
on their own, and `verify_bundle.py`'s step functions stay about orchestration
and reporting rather than ASN.1.

WHAT THIS CHECKS, IN ORDER
---------------------------------------------------------------------------
1. The token parses as CMS `SignedData` wrapping a `TSTInfo` (RFC 3161 §2.4.2,
   RFC 5652). Anything else is refused before any cryptography runs.
2. `messageImprint` — the digest the TSA actually timestamped — equals the
   digest the CALLER says it anchored (the checkpoint's own `checkpoint_hash`,
   i.e. SHA-256 of its compact JWS). This is the check that makes "this
   receipt is FOR this checkpoint" a computed fact rather than an assumption
   from filenames lining up.
3. The `SignedAttributes` digest (`message_digest`) matches a fresh digest of
   the encapsulated `TSTInfo` bytes, and the signature over the (re-tagged)
   `SignedAttributes` verifies against the signing certificate's public key.
   RSA (PKCS#1 v1.5) and ECDSA are supported — the two families every TSA
   this codebase has been tested against uses (freetsa.org: ECDSA P-384 over
   SHA-512, confirmed empirically while writing this module; commercial TSAs
   commonly use RSA over SHA-256). An Ed25519 or DSA signing certificate is
   refused with a named reason rather than silently skipped — see
   `UnsupportedAlgorithm` below.
4. The signing certificate chains — each link's signature verified, not just
   its subject/issuer names compared — up to a certificate that is
   BYTE-IDENTICAL to the pinned trust anchor shipped in the bundle
   (`tsa_ca_chain.pem`, sourced from `scripts/bundle/pinned_anchors/`). This
   is the step that makes the check a witness rather than a tautology: the
   token embeds its own signing chain (RFC 3161 responses commonly do, and
   freetsa.org's does), so trusting whatever chain arrives WITH the token
   would let anyone who can construct a self-signed CA forge an internally
   consistent "anchor". The pinned file is independent of the token — it
   was obtained and committed before this specific token ever existed.

WHAT THIS DOES NOT CHECK
---------------------------------------------------------------------------
* Certificate revocation. No CRL/OCSP fetch is possible in an offline
  verifier by construction (`verify_bundle.py` refuses all sockets), and a
  timestamp's whole purpose is to remain checkable long after the signing
  certificate's ordinary validity window — RFC 3161 deployments generally
  do not revoke over the timeframe evidence needs to remain checkable.
  Reported as an explicit limitation, not silently absent.
* That `genTime` is "recent" in any sense. A checkpoint anchored five years
  ago and verified today is exactly the intended use.
* Anything about the checkpoint's OWN signature (that is `checkpoint.rs`'s
  JWS, checked by `verify_bundle.py` itself against the JWKS snapshot) or
  about rows the checkpoint covers (`audit_chain_segment.jsonl`, step 7).
  This module answers exactly one question: did an external, pinned witness
  attest to this exact digest by this exact time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Rfc3161Error(Exception):
    """A token (or a pinned CA file) that cannot be parsed at all."""


class UnsupportedAlgorithm(Exception):
    """A token uses a signing-key family this verifier does not implement.

    Raised rather than silently treated as a pass OR a hard failure: an
    unsupported algorithm is neither "verified good" nor "proven forged" —
    it is "this checker cannot tell", which `verify_bundle.py` reports as
    NOT RUN, the same honesty `jwks.py` applies when `cryptography` is
    missing.
    """


@dataclass
class Rfc3161Finding:
    """Every fact this module can establish about one token, whether or not
    the overall verdict is a pass. Populated incrementally so a caller can
    see exactly which check stopped the chain, rather than a bare bool.
    """

    checked: bool = False
    #: True only when this environment is missing `asn1crypto` and/or
    #: `cryptography` — an environment limitation, distinct from every other
    #: `reason` this dataclass can carry, all of which are findings ABOUT
    #: the token. `verify_bundle.py` reports this case as NOT RUN
    #: (INCOMPLETE) rather than FAIL (INVALID): the check could not be
    #: attempted, which is not the same fact as the check having been
    #: attempted and failed.
    dependency_missing: bool = False
    message_imprint_matches: bool | None = None
    signature_valid: bool | None = None
    chain_verified: bool | None = None
    chain_trusted_to_pinned_ca: bool | None = None
    gen_time: str | None = None
    policy_oid: str | None = None
    tsa_name: str | None = None
    signing_cert_subject: str | None = None
    digest_algorithm: str | None = None
    signature_algorithm: str | None = None
    chain_subjects: list[str] = field(default_factory=list)
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return (
            self.checked
            and self.message_imprint_matches is True
            and self.signature_valid is True
            and self.chain_verified is True
            and self.chain_trusted_to_pinned_ca is True
        )


def _retag_set_of(der: bytes) -> bytes:
    """CMS `SignedAttributes` is stored as `[0] IMPLICIT SET OF Attribute`,
    but RFC 5652 §5.4 requires the SIGNATURE to be computed over the
    `SET OF` (universal tag 0x31) encoding, not the implicit `[0]` (0xA0)
    encoding the structure is stored under. Both share the same
    constructed-length-and-content encoding — only the leading tag byte
    differs — so re-tagging is exactly this one byte swap. This is the
    standard, well-known fix for verifying CMS signed-attribute signatures
    with a general-purpose ASN.1 library; confirmed empirically against a
    real freetsa.org token while writing this module (a signature verified
    against the retagged bytes; verifying against the raw `[0]`-tagged bytes
    or against a naive re-encode did not).
    """
    if not der or der[0] != 0xA0:
        raise Rfc3161Error(f"expected an implicit [0] SET OF (0xa0), got {der[:1]!r}")
    return b"\x31" + der[1:]


def verify_token(
    token_der: bytes,
    *,
    expected_digest: bytes,
    expected_digest_algorithm: str,
    pinned_ca_pem: bytes,
) -> Rfc3161Finding:
    """Verify one RFC 3161 token against a digest the caller already knows
    and a CA the caller already trusts. No network, no filesystem access
    beyond what the caller passed in.

    `expected_digest` / `expected_digest_algorithm`: what the checkpoint
    claims was anchored — `sha256` of its compact JWS bytes, i.e. the same
    `checkpoint_hash` `audit/checkpoint.rs` computes and the next checkpoint
    links to.
    """
    finding = Rfc3161Finding()

    try:
        from asn1crypto import cms, x509 as asn1_x509
        # Imported for its side effect: `asn1crypto.tsp`, on import, patches
        # `cms.ContentType._map` and `cms.EncapsulatedContentInfo._oid_specs`
        # to recognise id-ct-TSTInfo (OID 1.2.840.113549.1.9.16.1.4) as
        # `'tst_info'` and parse it as `tsp.TSTInfo`. Without this import,
        # `EncapsulatedContentInfo`'s `content_type` reports the raw OID
        # string instead of the name checked below, and `.parsed` returns
        # generic bytes instead of a `TSTInfo` — confirmed the hard way
        # while writing this module, so the dependency is spelled out here
        # rather than left to be rediscovered.
        from asn1crypto import tsp as _tsp  # noqa: F401
        from asn1crypto.core import ParsableOctetString
    except ImportError as exc:
        finding.dependency_missing = True
        finding.reason = f"asn1crypto is not installed, so this token cannot be parsed: {exc}"
        return finding

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
    except ImportError as exc:
        finding.dependency_missing = True
        finding.reason = f"the `cryptography` package is not installed, so this token cannot be checked: {exc}"
        return finding

    try:
        content_info = cms.ContentInfo.load(token_der)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same finding
        finding.reason = f"not a well-formed CMS ContentInfo: {exc}"
        return finding

    if content_info["content_type"].native != "signed_data":
        finding.reason = f"ContentInfo type is {content_info['content_type'].native!r}, expected signed_data"
        return finding
    signed_data = content_info["content"]

    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        finding.reason = f"encapsulated content type is {encap['content_type'].native!r}, expected tst_info"
        return finding

    content_field = encap["content"]
    if not isinstance(content_field, ParsableOctetString) or content_field.native is None:
        finding.reason = "TSTInfo content is absent (detached) — this verifier needs it attached"
        return finding
    tst_info_bytes = content_field.contents  # the raw octets, exactly as signed
    tst_info = content_field.parsed

    finding.gen_time = tst_info["gen_time"].native.strftime("%Y-%m-%dT%H:%M:%SZ")
    finding.policy_oid = tst_info["policy"].native

    message_imprint = tst_info["message_imprint"]
    imprint_alg = message_imprint["hash_algorithm"]["algorithm"].native
    imprint_hash = message_imprint["hashed_message"].native
    finding.message_imprint_matches = (
        imprint_alg == expected_digest_algorithm and imprint_hash == expected_digest
    )
    if not finding.message_imprint_matches:
        finding.reason = (
            f"messageImprint is {imprint_alg}:{imprint_hash.hex()}, but the checkpoint's own "
            f"digest is {expected_digest_algorithm}:{expected_digest.hex()} — this token is not "
            "a witness for this checkpoint, whatever else about it is valid"
        )
        return finding

    if not signed_data["signer_infos"]:
        finding.reason = "SignedData carries no signer_infos"
        return finding
    signer_info = signed_data["signer_infos"][0]

    digest_algorithm = signer_info["digest_algorithm"]["algorithm"].native
    finding.digest_algorithm = digest_algorithm
    signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
    finding.signature_algorithm = signature_algorithm

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        finding.reason = "no signed attributes — this verifier requires RFC 5652 signed attributes"
        return finding

    try:
        import hashlib

        hasher = hashlib.new(digest_algorithm)
    except ValueError as exc:
        finding.reason = f"unrecognised digest algorithm {digest_algorithm!r}: {exc}"
        return finding
    hasher.update(tst_info_bytes)
    computed_content_digest = hasher.digest()

    message_digest_attr = None
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            message_digest_attr = attr["values"][0].native
            break
    if message_digest_attr is None:
        finding.reason = "signed attributes carry no message_digest"
        return finding
    if message_digest_attr != computed_content_digest:
        finding.reason = (
            "the signed message_digest attribute does not match a fresh digest of the "
            "encapsulated TSTInfo — the token's own internal consistency fails before any "
            "signature is even checked"
        )
        return finding

    try:
        signed_attrs_bytes = _retag_set_of(signed_attrs.dump())
    except Rfc3161Error as exc:
        finding.reason = str(exc)
        return finding

    # --- find the signing certificate ------------------------------------
    certs = list(signed_data["certificates"]) if signed_data["certificates"] else []
    if not certs:
        finding.reason = "SignedData carries no certificates — certReq must not have been honoured"
        return finding

    sid = signer_info["sid"]
    if sid.name != "issuer_and_serial_number":
        finding.reason = f"signer identified by {sid.name!r}; this verifier only follows issuer_and_serial_number"
        return finding
    target_issuer = sid.chosen["issuer"]
    target_serial = sid.chosen["serial_number"].native

    signing_cert = None
    for c in certs:
        cert = c.chosen
        if not isinstance(cert, asn1_x509.Certificate):
            continue
        if cert.serial_number == target_serial and cert.issuer == target_issuer:
            signing_cert = cert
            break
    if signing_cert is None:
        finding.reason = "no embedded certificate matches the signer's issuer+serial"
        return finding
    finding.signing_cert_subject = signing_cert.subject.human_friendly

    def _hash_for(name: str):
        return {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "sha1": hashes.SHA1(),
        }.get(name)

    def _verify_signature(pubkey: Any, signature: bytes, message: bytes, hash_alg_name: str) -> None:
        """Raises `InvalidSignature` on failure, `UnsupportedAlgorithm` for a
        key type this verifier has no branch for."""
        digest = _hash_for(hash_alg_name)
        if digest is None:
            raise UnsupportedAlgorithm(f"unsupported hash algorithm {hash_alg_name!r}")
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(signature, message, padding.PKCS1v15(), digest)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, message, ec.ECDSA(digest))
        else:
            raise UnsupportedAlgorithm(
                f"signing key type {type(pubkey).__name__} is not RSA or EC — this verifier "
                "does not implement it (see this module's header)"
            )

    try:
        signing_pubkey = load_der_x509_certificate(signing_cert.dump()).public_key()
        _verify_signature(signing_pubkey, signer_info["signature"].native, signed_attrs_bytes, digest_algorithm)
        finding.signature_valid = True
    except UnsupportedAlgorithm as exc:
        finding.reason = str(exc)
        return finding
    except InvalidSignature:
        finding.signature_valid = False
        finding.reason = "the token's signature does not verify against its own embedded signing certificate"
        return finding

    # --- walk the chain up to a self-signed certificate -------------------
    by_subject: dict[bytes, Any] = {}
    for c in certs:
        cert = c.chosen
        if isinstance(cert, asn1_x509.Certificate):
            by_subject.setdefault(cert.subject.dump(), cert)

    chain = [signing_cert]
    current = signing_cert
    seen_subjects = {current.subject.dump()}
    for _ in range(8):  # a real chain is at most a handful of certificates long
        if current.subject == current.issuer:
            break  # self-signed: this is the root
        issuer_cert = by_subject.get(current.issuer.dump())
        if issuer_cert is None:
            finding.reason = (
                f"certificate chain is incomplete: no embedded certificate issued "
                f"{current.subject.human_friendly!r}'s issuer {current.issuer.human_friendly!r}"
            )
            return finding
        if issuer_cert.subject.dump() in seen_subjects and issuer_cert is not current:
            finding.reason = "certificate chain loops without reaching a self-signed root"
            return finding
        chain.append(issuer_cert)
        seen_subjects.add(issuer_cert.subject.dump())
        current = issuer_cert
    else:
        finding.reason = "certificate chain did not terminate within 8 hops"
        return finding

    finding.chain_subjects = [c.subject.human_friendly for c in chain]

    # Verify every link's signature — not just that subject/issuer names
    # line up, which anyone assembling a fake chain could also produce.
    for child, issuer_cert in zip(chain, chain[1:] + [chain[-1]]):
        if child is chain[-1]:
            break  # the root's own self-signature is checked below
        try:
            issuer_pubkey = load_der_x509_certificate(issuer_cert.dump()).public_key()
            child_py = load_der_x509_certificate(child.dump())
            _verify_signature(
                issuer_pubkey,
                child_py.signature,
                child_py.tbs_certificate_bytes,
                child_py.signature_hash_algorithm.name if child_py.signature_hash_algorithm else "",
            )
        except UnsupportedAlgorithm as exc:
            finding.reason = f"cannot verify {child.subject.human_friendly!r}'s issuance: {exc}"
            return finding
        except InvalidSignature:
            finding.chain_verified = False
            finding.reason = (
                f"{child.subject.human_friendly!r} was NOT validly issued by "
                f"{issuer_cert.subject.human_friendly!r} — the embedded chain does not hold together"
            )
            return finding

    # The root's self-signature, for completeness (a self-signed cert that
    # doesn't even verify against its own public key is malformed).
    root = chain[-1]
    try:
        root_pubkey = load_der_x509_certificate(root.dump()).public_key()
        root_py = load_der_x509_certificate(root.dump())
        _verify_signature(
            root_pubkey,
            root_py.signature,
            root_py.tbs_certificate_bytes,
            root_py.signature_hash_algorithm.name if root_py.signature_hash_algorithm else "",
        )
    except UnsupportedAlgorithm as exc:
        finding.reason = f"cannot verify the root's self-signature: {exc}"
        return finding
    except InvalidSignature:
        finding.chain_verified = False
        finding.reason = "the embedded root certificate's self-signature does not verify"
        return finding

    finding.chain_verified = True
    finding.tsa_name = root.subject.human_friendly

    # --- the trust decision: compare against the PINNED copy, not the ------
    # --- embedded one -------------------------------------------------------
    try:
        pinned_cert = load_pem_x509_certificate(pinned_ca_pem)
    except Exception as exc:  # noqa: BLE001
        finding.reason = f"the pinned CA file in this bundle is not a valid PEM certificate: {exc}"
        return finding

    from cryptography.hazmat.primitives.serialization import Encoding

    finding.chain_trusted_to_pinned_ca = pinned_cert.public_bytes(Encoding.DER) == root.dump()
    if not finding.chain_trusted_to_pinned_ca:
        finding.reason = (
            f"the embedded chain terminates at {root.subject.human_friendly!r}, which is NOT "
            "byte-identical to the pinned trust anchor shipped in this bundle "
            "(tsa_ca_chain.pem). A token can embed any self-signed certificate it likes; only "
            "one that terminates at the PINNED copy is evidence of anything."
        )
        return finding

    finding.checked = True
    return finding
