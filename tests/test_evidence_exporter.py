"""Properties of the Canonical Case File exporter.

Almost nothing here needs a server. `scripts/export_audit_evidence.py` splits
at exactly one seam — `fetch_evidence()` does the network call, everything
after it takes a plain dict — so the document, the redaction boundary and the
seal are all testable offline against a fixture response. That is not a
convenience: a pack that a bank can only produce when its own API is up is a
pack nobody can regression-test, and the properties below are the ones whose
failure would only be discovered by a regulator.

What is asserted, and why each one earns its place:

  * **A declined assessment renders NOT SUITABLE.** This is the case the whole
    design exists for. A pack that could only be produced for approvals would
    be worthless as evidence, and "the firm assessed someone and turned them
    away" is the file a conduct examiner asks for first.

  * **No client figure reaches the rendered bytes**, even when the input dict
    is stuffed with them. Asserted on the actual PDF bytes rather than on the
    intermediate structure, because the intermediate structure is the thing
    that would be refactored.

  * **The seal round-trips, and one flipped byte breaks it.** A tamper-evident
    seal that has never been shown to detect tampering is a claim, not a
    control.

  * **The DFSA citation shows both halves.** The tokens emit `COB 3.1`; the
    rule is `COB 3.4`. A document that printed only one of them would be
    either wrong or unusable by the relying party matching on the string.

The one integration test is marked as such and skips cleanly without a server.

Run:
    .venv/bin/python -m pytest tests/test_evidence_exporter.py -v
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.export_audit_evidence import (  # noqa: E402
    PUBLIC_INPUTS,
    build_pack,
    canonical_bytes,
    collect_aihoots,
    decode_proof_token,
    export,
    load_signing_key,
    render_and_seal,
    verify_seal,
)

AS_OF = datetime(2026, 9, 16, 9, 0, 0, tzinfo=timezone.utc)

REQUEST_ID = "8f14e45f-ceea-467a-9b8e-1c1a2f6e6f11"
USER_ID = "0a3f2b7c-4d51-4b8e-9d2a-6c7e8f901234"
ORG_ID = "5c1d8e2f-7a90-4b1c-8d3e-2f4a6b8c0d1e"
PRODUCT_ISIN = "XS1234567890"

# Must match `wealth::BUSINESS_PROCESS` (backend/api/src/wealth/mod.rs) — see
# `tests/break_it/conftest.py`'s `make_desk` for why every desk needs one.
WEALTH_BUSINESS_PROCESS = "wealth.suitability_recommendation"

VKEY_SHA256 = "9c1185a5c5e9fc54612808977ee8f548b2258d31ddadef4f0c9d8b6a2f2b4e77"
ACCEPTED_PROOF_SHA256 = "b1946ac92492d2347c6235b4d2611184b3b0c94b1a9a2b1c9d0e5f6a7b8c9d01"
REJECTED_PROOF_SHA256 = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"

# Figures a client would have but Memtara never holds. They are deliberately
# seven-digit and unlike any legitimate value in the fixture (the product's
# own thresholds are 500,000 and 1,000,000), so a substring hit on one of them
# in the PDF bytes can only mean the redaction boundary leaked.
CLIENT_FIGURES = {
    "annual_income": 4812355,
    "liquid_assets": 9314722,
    "existing_holdings_value": 2640119,
    "risk_tolerance_note": "RM recorded tolerance 4 on 2026-03-02",
}


def _public_inputs(suitable: bool) -> list[str]:
    """Twelve field elements in circuit order, with the verdict in position 11."""
    values = [
        "0x0000000000000000000000000000000000000000000000000000000068c8a300",  # current_time
        "0x0000000000000000000000000000000000000000000000000000000068c8a6b8",  # expiry_time
        "0x1f3a9c02d4b5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f",  # vault_root
        "0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",  # product_ref
        "0x000000000000000000000000000000000000000000000000000000000007a120",  # min_income
        "0x00000000000000000000000000000000000000000000000000000000000f4240",  # min_liquidity
        "0x000000000000000000000000000000000000000000000000000000000000001e",  # max_concentration
        "0x0000000000000000000000000000000000000000000000000000000000000003",  # product_risk_level
        "0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",  # pubkey x
        "0x1122334455667788990011223344556677889900112233445566778899001122",  # pubkey y
        "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # nonce
    ]
    values.append("0x" + ("0" * 63 + "1" if suitable else "0" * 64))
    return values


def evidence_fixture(*, suitable: bool | None = True, with_rejected_attempt: bool = False) -> dict:
    """A response shaped exactly like `wealth/evidence.rs` produces one."""
    proofs = []
    if with_rejected_attempt:
        proofs.append(
            {
                "proof_id": "1d0b5c8e-3a2f-4e6d-8b1c-9f0a1b2c3d4e",
                "accepted_by_bb_verify": False,
                "verified_at": "2026-09-16T08:58:12Z",
                "proof_bytes": 14656,
                "proof_sha256": REJECTED_PROOF_SHA256,
                "public_inputs": _public_inputs(True),
            }
        )
    if suitable is not None:
        proofs.append(
            {
                "proof_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "accepted_by_bb_verify": True,
                "verified_at": "2026-09-16T09:00:41Z",
                "proof_bytes": 14656,
                "proof_sha256": ACCEPTED_PROOF_SHA256,
                "public_inputs": _public_inputs(suitable),
            }
        )

    return {
        "request_id": REQUEST_ID,
        "circuit": "wealth_suitability",
        "status": "verified" if suitable is not None else "pending",
        "organisation": {"id": ORG_ID, "name": "DIFC Wealth Partners", "type": "bank"},
        "subject": {
            "user_id": USER_ID,
            "disclosed_attributes": [],
            "note": (
                "Memtara holds no income, liquidity, risk-tolerance or holdings figure for "
                "this subject."
            ),
        },
        "product": {
            "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "isin": PRODUCT_ISIN,
            "name": "5-year USD capital-protected note (DIFC-distributed)",
            "product_ref": "0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
        },
        "terms_assessed_against": {
            "min_income": 500000,
            "min_liquidity": 1000000,
            "max_concentration_percent": 30,
            "product_risk_level": 3,
            "source": "product registry, snapshotted when the assessment was opened",
        },
        "window": {
            "start": "2026-09-16T08:55:00Z",
            "end": "2026-09-16T09:10:00Z",
            "expires_at": "2026-09-16T09:10:00Z",
        },
        "outcome": {
            "assessed": suitable is not None,
            "suitable": suitable,
            "assessed_at": "2026-09-16T09:00:41Z" if suitable is not None else None,
            "read_from": "public input 11 of 12",
            "note": (
                "`bb verify` succeeding means the proof is well formed, not that the client "
                "passed. The verdict is the circuit's public output and is read explicitly."
            ),
        },
        "nonce": "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "verification_key": {
            "sha256": VKEY_SHA256,
            "bytes": 1832,
            "verifier_target": "noir-recursive",
            "published_at": "circuits/wealth_suitability/vkey/vk",
        },
        "proofs": proofs,
        "audit_chain_excerpt": [
            {
                "seq": 4118,
                "event_type": "wealth_suitability_requested",
                "event_hash": "c2b7d1a0f3e4956871209a3b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f7",
                "prev_hash": "aa11bb22cc33dd44ee55ff6677889900112233445566778899aabbccddeeff00",
                "created_at": "2026-09-16T08:55:00Z",
            },
            {
                "seq": 4131,
                "event_type": "wealth_suitability_assessed",
                "event_hash": "d3c8e2b1a4f5067982310b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80",
                "prev_hash": "c2b7d1a0f3e4956871209a3b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f7",
                "created_at": "2026-09-16T09:00:41Z",
            },
        ],
        "regulatory_mapping": {"dfsa": ["COB 3.1"], "cbuae": ["5(c)", "5(d)", "4(a)"]},
        "opened_at": "2026-09-16T08:55:00Z",
    }


def render(evidence: dict, tmp_path: Path, *, name: str = "case.pdf", **kwargs) -> dict:
    return render_and_seal(build_pack(evidence, **kwargs), tmp_path / name, created_at=AS_OF)


# ---------------------------------------------------------------------------
# What the pack must say
# ---------------------------------------------------------------------------


def test_the_pack_carries_the_verdict_the_isin_and_both_digests(tmp_path):
    result = render(evidence_fixture(suitable=True), tmp_path)
    pdf = result["pdf_bytes"]

    assert b"VERDICT         SUITABLE" in pdf
    assert PRODUCT_ISIN.encode() in pdf

    # Both digests must survive as unbroken 64-character strings. They are the
    # two values an examiner copies out to re-run `bb verify` against the right
    # key, and a digest wrapped across a line break is a digest that gets
    # retyped wrong — which is why they are emitted through `preformatted`
    # (100 columns, no wrapping) rather than as prose.
    assert VKEY_SHA256.encode() in pdf
    assert ACCEPTED_PROOF_SHA256.encode() in pdf

    assert result["pack"]["outcome"]["suitable"] is True


def test_a_declined_assessment_renders_a_pack_that_says_not_suitable(tmp_path):
    """The case the whole design exists for.

    `suitable` is a public output of the circuit, not an assertion, so a proof
    of non-suitability verifies exactly as cleanly as one of suitability. If
    the exporter could only render approvals, the firm would be unable to
    evidence the decisions a conduct examiner is most interested in.
    """
    result = render(evidence_fixture(suitable=False), tmp_path)
    pdf = result["pdf_bytes"]

    assert b"VERDICT         NOT SUITABLE" in pdf
    assert result["verdict"] == "NOT SUITABLE"

    # The verdict must also be shown where it is read from, not only in the
    # summary — a reader who takes the exit code as the answer is the failure
    # this section exists to prevent.
    assert b"public input 11 of 12" in pdf
    assert b"bb verify" in pdf

    # And the same pack still carries the full evidence: a decline is not a
    # thinner document than an approval.
    assert VKEY_SHA256.encode() in pdf
    assert ACCEPTED_PROOF_SHA256.encode() in pdf


def test_an_unassessed_request_is_not_rendered_as_a_decline(tmp_path):
    """`suitable: null` is a third state and must not collapse into `false`."""
    result = render(evidence_fixture(suitable=None), tmp_path)
    assert result["verdict"] == "NOT ASSESSED"
    assert b"VERDICT         NOT ASSESSED" in result["pdf_bytes"]
    assert b"VERDICT         NOT SUITABLE" not in result["pdf_bytes"]


def test_no_client_figure_reaches_the_rendered_bytes(tmp_path):
    """The redaction boundary, asserted on the artefact that leaves the building.

    The input here is a maliciously enriched response: a future endpoint, a
    caching proxy, or a well-meaning patch that joins the firm's CRM could all
    put figures into this dict. `build_pack` copies a fixed set of fields and
    `build_document` cannot see anything else, so none of it can reach the
    paper — and the canonical digest does not cover it either, which matters
    because a digest over data the pack does not show is a digest nobody can
    reproduce.
    """
    evidence = evidence_fixture(suitable=False)
    evidence["subject"].update(CLIENT_FIGURES)
    evidence["subject"]["disclosed_attributes"] = ["annual_income", "liquid_assets"]
    evidence["client_financials"] = CLIENT_FIGURES
    evidence["product"]["client_annual_income"] = CLIENT_FIGURES["annual_income"]
    evidence["terms_assessed_against"]["client_liquid_assets"] = CLIENT_FIGURES["liquid_assets"]
    evidence["outcome"]["existing_holdings_value"] = CLIENT_FIGURES["existing_holdings_value"]
    evidence["proofs"][0]["witness"] = CLIENT_FIGURES
    evidence["audit_chain_excerpt"][0]["detail"] = CLIENT_FIGURES

    result = render(evidence, tmp_path)
    pdf = result["pdf_bytes"]
    canonical = canonical_bytes(result["pack"])

    for value in (
        CLIENT_FIGURES["annual_income"],
        CLIENT_FIGURES["liquid_assets"],
        CLIENT_FIGURES["existing_holdings_value"],
    ):
        for rendering in (str(value), f"{value:,}", f"{value:x}", f"0x{value:x}"):
            assert rendering.encode() not in pdf, f"{rendering} leaked into the PDF"
            assert rendering.encode() not in canonical, f"{rendering} leaked into the seal digest"

    assert CLIENT_FIGURES["risk_tolerance_note"].encode() not in pdf
    assert b"client_financials" not in pdf

    # The pack must still say the absence is deliberate, or a reader learns
    # nothing from it.
    assert b"holds no annual income figure" in pdf


def test_rejected_attempts_are_shown(tmp_path):
    """A pack showing only the accepted proof would hide the pattern a
    reviewer is looking for."""
    result = render(evidence_fixture(suitable=True, with_rejected_attempt=True), tmp_path)
    pdf = result["pdf_bytes"]

    assert REJECTED_PROOF_SHA256.encode() in pdf
    assert ACCEPTED_PROOF_SHA256.encode() in pdf
    assert b"REJECTED" in pdf
    assert b"1 of 2 submitted proofs were rejected" in pdf


def test_the_public_inputs_are_named_in_circuit_order(tmp_path):
    pdf = render(evidence_fixture(suitable=True), tmp_path)["pdf_bytes"]
    for name, _owner in PUBLIC_INPUTS:
        assert name.encode() in pdf, f"public input {name} is unnamed in the document"

    # Position and name together, so a reader can check the vector they were
    # given against the one that was verified.
    assert b"11  suitable" in pdf


def test_the_document_names_cob_3_4_and_explains_the_cob_3_1_claim(tmp_path):
    pdf = render(evidence_fixture(suitable=False), tmp_path)["pdf_bytes"]

    assert b"COB 3.1" in pdf, "the emitted claim value must be shown"
    assert b"COB 3.4" in pdf, "the correct citation must be shown"
    assert b"Application" in pdf, "what COB 3.1 actually is"
    assert b"Suitability" in pdf
    # The caveat carried forward from docs/REGULATORY_MATRIX.md: the rulebook
    # is not vendored here, so the mapping is against the substance of the
    # obligation and not a quotation of current text.
    assert b"vendored" in pdf


def test_a_missing_aihoots_log_is_stated_rather_than_omitted(tmp_path):
    pdf = render(evidence_fixture(suitable=True), tmp_path)["pdf_bytes"]
    assert b"AIHOOTS SHA-256 audit chain" in pdf
    assert b"No AIHOOTS audit log was supplied" in pdf


def test_a_supplied_token_is_displayed_and_not_claimed_to_be_verified(tmp_path):
    """The one artefact in the pack an examiner can check against a published
    key — shown in full, with the exporter's own non-verification stated."""
    claims = {
        "iss": "https://api.memtara.ai",
        "sub": USER_ID,
        "predicate": "structured_product_suitable",
        "verified": True,
        "suitable": False,
        "product_isin": PRODUCT_ISIN,
        "proof_hash": ACCEPTED_PROOF_SHA256,
        "dfsa_rules": ["COB 3.1"],
    }
    token = _unsigned_jwt(claims)

    result = render(evidence_fixture(suitable=False), tmp_path, token=decode_proof_token(token))
    pdf = result["pdf_bytes"]

    assert b"structured_product_suitable" in pdf
    assert b"published JWKS" in pdf
    assert b"did NOT verify its signature" in pdf
    assert result["pack"]["proof_token"]["verified_by_this_exporter"] is False


def test_without_a_token_the_pack_says_why_rather_than_inventing_one(tmp_path):
    pdf = render(evidence_fixture(suitable=True), tmp_path)["pdf_bytes"]
    assert b"No proof token was supplied" in pdf
    # Asserted on single tokens: prose is wrapped at the margin, so a phrase
    # that straddles a line break is absent from the bytes while being
    # perfectly present on the page.
    assert b"issuance/mod.rs" in pdf


def _unsigned_jwt(claims: dict) -> str:
    import base64

    def segment(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = segment({"alg": "EdDSA", "typ": "JWT", "kid": "test-kid"})
    return f"{header}.{segment(claims)}.{base64.urlsafe_b64encode(b'x' * 64).rstrip(b'=').decode()}"


# ---------------------------------------------------------------------------
# The seal
# ---------------------------------------------------------------------------


def test_the_seal_round_trips(tmp_path):
    result = render(evidence_fixture(suitable=False), tmp_path)
    ok, lines = verify_seal(result["pdf"], result["seal"])
    assert ok, "\n".join(lines)
    assert any(line.startswith("PASS  pdf sha256 matches") for line in lines)
    # Unsigned packs must announce it rather than pass quietly.
    assert any("UNSIGNED" in line for line in lines)


def test_one_flipped_byte_breaks_the_seal(tmp_path):
    result = render(evidence_fixture(suitable=False), tmp_path)
    data = bytearray(result["pdf"].read_bytes())

    # Flip a bit in the middle of the content, not in the header: a corrupted
    # header would be caught by any PDF reader, and the seal exists for the
    # alteration that still opens cleanly.
    data[len(data) // 2] ^= 0x01
    result["pdf"].write_bytes(bytes(data))

    ok, lines = verify_seal(result["pdf"], result["seal"])
    assert not ok
    assert any("pdf sha256 does NOT match" in line for line in lines)


def test_a_missing_seal_fails_rather_than_passing_silently(tmp_path):
    result = render(evidence_fixture(suitable=True), tmp_path)
    result["seal"].unlink()
    ok, lines = verify_seal(result["pdf"], result["seal"])
    assert not ok
    assert "no such seal" in lines[0]


def test_a_seal_from_a_different_pack_does_not_verify(tmp_path):
    """The digests alone would catch this, but the cross-check that the PDF
    states the seal's evidence digest is what catches a sidecar swapped
    between two packs of the same size."""
    first = render(evidence_fixture(suitable=True), tmp_path, name="approved.pdf")
    second = render(evidence_fixture(suitable=False), tmp_path, name="declined.pdf")

    ok, lines = verify_seal(first["pdf"], second["seal"])
    assert not ok
    assert first["canonical_sha256"] != second["canonical_sha256"]


def _write_key(tmp_path: Path, name: str, seed: bytes) -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pem = Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / name
    path.write_bytes(pem)
    path.chmod(0o600)
    return path


def test_a_signed_pack_verifies_with_the_right_key(tmp_path):
    key_path = _write_key(tmp_path, "cro.pem", bytes(range(32)))
    signing_key = load_signing_key(key_path)
    public_hex = signing_key.public_key().public_bytes_raw().hex()

    result = render_and_seal(
        build_pack(evidence_fixture(suitable=False)),
        tmp_path / "signed.pdf",
        created_at=AS_OF,
        signing_key=signing_key,
    )

    ok, lines = verify_seal(result["pdf"], result["seal"], expected_public_key_hex=public_hex)
    assert ok, "\n".join(lines)
    assert any("Ed25519 signature verifies" in line for line in lines)
    assert public_hex.encode() in result["pdf_bytes"], "the signing key is identified in the pack"


def test_a_signed_pack_does_not_verify_against_the_wrong_key(tmp_path):
    signing_key = load_signing_key(_write_key(tmp_path, "cro.pem", bytes(range(32))))
    impostor = load_signing_key(_write_key(tmp_path, "other.pem", bytes(range(100, 132))))

    result = render_and_seal(
        build_pack(evidence_fixture(suitable=False)),
        tmp_path / "signed.pdf",
        created_at=AS_OF,
        signing_key=signing_key,
    )

    ok, lines = verify_seal(
        result["pdf"],
        result["seal"],
        expected_public_key_hex=impostor.public_key().public_bytes_raw().hex(),
    )
    assert not ok
    assert any("signed by a different key" in line for line in lines)


def test_a_signature_over_other_bytes_does_not_verify(tmp_path):
    """The signature must be over the PDF, not merely present in the sidecar."""
    signing_key = load_signing_key(_write_key(tmp_path, "cro.pem", bytes(range(32))))
    result = render_and_seal(
        build_pack(evidence_fixture(suitable=True)),
        tmp_path / "signed.pdf",
        created_at=AS_OF,
        signing_key=signing_key,
    )

    seal = json.loads(result["seal"].read_text())
    seal["signature"]["signature_hex"] = signing_key.sign(b"a different document").hex()
    seal["pdf"]["sha256"] = result["pdf_sha256"]  # keep the digest honest so only the signature is wrong
    result["seal"].write_text(json.dumps(seal, indent=2))

    ok, lines = verify_seal(result["pdf"], result["seal"])
    assert not ok
    assert any("does not verify over the pdf bytes" in line for line in lines)


def test_an_unsigned_pack_does_not_invent_a_signer(tmp_path):
    result = render(evidence_fixture(suitable=True), tmp_path)
    seal = json.loads(result["seal"].read_text())

    assert seal["signature"] is None
    assert "UNSIGNED" in seal["authentication"]
    assert b"This pack is UNSIGNED" in result["pdf_bytes"]
    assert b"not a PAdES" in result["pdf_bytes"].replace(b"NOT a PAdES", b"not a PAdES")


def test_the_pack_states_it_is_not_an_ades_signature(tmp_path):
    for signing_key in (None, load_signing_key(_write_key(tmp_path, "k.pem", bytes(range(32))))):
        result = render_and_seal(
            build_pack(evidence_fixture(suitable=True)),
            tmp_path / "case.pdf",
            created_at=AS_OF,
            signing_key=signing_key,
        )
        pdf = result["pdf_bytes"]
        assert b"PAdES" in pdf
        assert b"green tick" in pdf
        # The honest ordering: the JWT outranks this tool's own seal.
        assert b"strongest authenticity claim" in pdf or b"strongest claim" in pdf


def test_the_evidence_digest_identifies_the_evidence_not_the_run(tmp_path):
    """Two exports of the same assessment at different times must agree.

    If the export timestamp were inside the canonical structure, every
    re-export would produce a new evidence digest and the digest would answer
    "when was this printed" rather than "did the record move" — which is the
    only question worth asking of it.
    """
    first = render_and_seal(
        build_pack(evidence_fixture(suitable=True)), tmp_path / "a.pdf", created_at=AS_OF
    )
    second = render_and_seal(
        build_pack(evidence_fixture(suitable=True)),
        tmp_path / "b.pdf",
        created_at=datetime(2027, 1, 4, 17, 30, tzinfo=timezone.utc),
    )
    assert first["canonical_sha256"] == second["canonical_sha256"]
    assert first["pdf_sha256"] != second["pdf_sha256"], "the paper differs; the evidence does not"


# ---------------------------------------------------------------------------
# The AIHOOTS chain — using AIHOOTS's own writer and its own verifier
# ---------------------------------------------------------------------------


@pytest.fixture()
def aihoots_log(tmp_path: Path) -> Path:
    chain_module = pytest.importorskip(
        "src.gateway.audit.chain",
        reason="AIHOOTS submodule not checked out (git submodule update --init)",
    )
    path = tmp_path / "audit.jsonl"
    chain = chain_module.AuditChain(str(path))
    caller = "DIFC Wealth Partners - Advised Sales"
    request_id = str(uuid.UUID(int=0x51DE))

    chain.append(
        chain_module.new_event(
            request_id=request_id,
            caller=caller,
            model="qwen2.5:3b-instruct",
            event_type="suitability",
            decision="allow",
            detail={
                "memtara_verified": True,
                "proof_hash": ACCEPTED_PROOF_SHA256,
                "regulatory_audit_id": "e4d909c2-90d0-4bd7-9d5b-1f2a3b4c5d6e",
                "memtara_suitable": False,
                "memtara_product_isin": PRODUCT_ISIN,
            },
        )
    )
    # An unrelated record, so "matched" means matched rather than "everything
    # in the file".
    chain.append(
        chain_module.new_event(
            request_id=str(uuid.UUID(int=0xBEEF)),
            caller=caller,
            model="qwen2.5:3b-instruct",
            event_type="suitability",
            decision="allow",
            detail={"proof_hash": "f" * 64},
        )
    )
    return path


def test_the_aihoots_section_links_by_proof_hash_and_quotes_the_real_verifier(aihoots_log, tmp_path):
    evidence = evidence_fixture(suitable=False)
    pack = build_pack(evidence)
    pack["aihoots"] = collect_aihoots(aihoots_log, {ACCEPTED_PROOF_SHA256})

    verify = pack["aihoots"]["audit_verify"]
    if not verify.get("available"):
        pytest.skip(verify.get("reason", "audit-verify unavailable"))

    assert len(pack["aihoots"]["matched"]) == 1, "only the linked record should appear"
    assert verify["exit_code"] == 0
    assert "audit chain intact" in verify["stdout"]

    pdf = render_and_seal(pack, tmp_path / "linked.pdf", created_at=AS_OF)["pdf_bytes"]
    assert ACCEPTED_PROOF_SHA256.encode() in pdf
    # The verifier's own words, not a paraphrase. Only the leading portion is
    # asserted because the line ends in an absolute path that `preformatted`
    # clips at the page width (marked with '>', per scripts/pdf.py).
    assert b"OK: audit chain intact" in pdf
    assert b"exit code: 0" in pdf


def test_a_tampered_aihoots_log_is_reported_in_the_verdict_not_paraphrased(aihoots_log, tmp_path):
    lines = aihoots_log.read_text().splitlines()
    record = json.loads(lines[0])
    record["detail"]["proof_hash"] = "0" * 64
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    aihoots_log.write_text("\n".join(lines) + "\n")

    pack = build_pack(evidence_fixture(suitable=False))
    pack["aihoots"] = collect_aihoots(aihoots_log, {ACCEPTED_PROOF_SHA256})
    verify = pack["aihoots"]["audit_verify"]
    if not verify.get("available"):
        pytest.skip(verify.get("reason", "audit-verify unavailable"))

    assert verify["exit_code"] == 1
    assert "TAMPERING DETECTED" in verify["stderr"]

    pdf = render_and_seal(pack, tmp_path / "tampered.pdf", created_at=AS_OF)["pdf_bytes"]
    assert b"TAMPERING DETECTED" in pdf
    # And the pack must not have quietly dropped the now-unlinked digest.
    assert ACCEPTED_PROOF_SHA256.encode() in pdf


def test_both_proof_hash_spellings_link(aihoots_log, tmp_path):
    """`memtara_claims.py` writes `detail.proof_hash`; the spec for this
    exporter called it `memtara_proof_hash`. Both link, because a relying
    party that followed either convention should get a populated section
    rather than a silently empty one."""
    chain_module = pytest.importorskip("src.gateway.audit.chain")
    chain = chain_module.AuditChain(str(aihoots_log))
    chain.append(
        chain_module.new_event(
            request_id=str(uuid.UUID(int=0xC0FFEE)),
            caller="Another Gateway",
            model="qwen2.5:3b-instruct",
            event_type="attestation",
            decision="allow",
            detail={"memtara_proof_hash": REJECTED_PROOF_SHA256},
        )
    )
    collected = collect_aihoots(aihoots_log, {ACCEPTED_PROOF_SHA256, REJECTED_PROOF_SHA256})
    matched = {entry["proof_hash"] for entry in collected["matched"]}
    assert matched == {ACCEPTED_PROOF_SHA256, REJECTED_PROOF_SHA256}


# ---------------------------------------------------------------------------
# Integration — needs a running server. Skips cleanly without one.
# ---------------------------------------------------------------------------


def test_integration_export_against_a_live_server(memtara_server, tmp_path):
    """INTEGRATION. The only test here that talks to the real API.

    It deliberately does not generate a proof: `nargo`/`bb` are exercised by
    `test_wealth_suitability_e2e.py`, and what is under test here is that the
    exporter's field names still match what `wealth/evidence.rs` actually
    emits. An assessment that was opened but never proved is enough for that,
    and it is also the un-assessed case the offline tests only simulate.
    """
    import httpx

    from conftest import db_connect

    org = httpx.post(
        f"{memtara_server}/orgs",
        json={"name": f"Evidence Export Test {uuid.uuid4().hex[:8]}", "org_type": "bank"},
        timeout=10.0,
    )
    assert org.status_code == 201, org.text
    org_body = org.json()
    auth = {"Authorization": f"Bearer {org_body['api_key']}"}

    user_id = uuid.uuid4()
    conn = db_connect()
    try:
        conn.run(
            "insert into users (id, phone_e164) values (:id, :phone)",
            id=str(user_id),
            phone=f"+9715{uuid.uuid4().int % 10**8:08d}",
        )

        product = httpx.post(
            f"{memtara_server}/api/v1/products",
            headers=auth,
            json={
                "product_isin": PRODUCT_ISIN,
                "product_name": "5-year USD capital-protected note (DIFC-distributed)",
                "risk_level": 3,
                "min_income": 500000,
                "min_liquidity": 1000000,
                "max_concentration_percent": 30,
                "approved_by_risk_committee": True,
            },
            timeout=10.0,
        )
        assert product.status_code == 201, product.text

        consent = httpx.post(
            f"{memtara_server}/api/v1/consents",
            headers=auth,
            json={
                "user_id": str(user_id),
                "scope": [WEALTH_BUSINESS_PROCESS],
                "consent_version": "evidence-export-suite-default-v1",
                "granted_via": "mobile_app",
            },
            timeout=10.0,
        )
        assert consent.status_code == 201, consent.text

        opened = httpx.post(
            f"{memtara_server}/api/v1/issue-wealth-request",
            headers=auth,
            json={"user_id": str(user_id), "product_isin": PRODUCT_ISIN, "ttl_seconds": 900},
            timeout=10.0,
        )
        assert opened.status_code == 201, opened.text
        request_id = opened.json()["request_id"]

        result = export(
            request_id=request_id,
            output=tmp_path / "live.pdf",
            base_url=memtara_server,
            api_key=org_body["api_key"],
            created_at=AS_OF,
        )

        pack = result["pack"]
        assert pack["subject"]["user_id"] == str(user_id)
        assert pack["product"]["isin"] == PRODUCT_ISIN
        assert pack["terms_assessed_against"]["min_income"] == 500000
        assert pack["terms_assessed_against"]["source"].startswith("product registry")
        assert result["verdict"] == "NOT ASSESSED"

        # The document builder must have found real values, not a page of
        # "(not recorded)" — which is what a renamed field would produce.
        pdf = result["pdf"].read_bytes()
        assert PRODUCT_ISIN.encode() in pdf
        assert str(user_id).encode() in pdf
        assert b"noir-recursive" in pdf

        ok, lines = verify_seal(result["pdf"], result["seal"])
        assert ok, "\n".join(lines)
    finally:
        for statement, params in [
            (
                "delete from audit_log where ref_id in "
                "(select id from disclosure_requests where org_id = :oid)",
                {"oid": org_body["id"]},
            ),
            (
                "delete from wealth_requests where request_id in "
                "(select id from disclosure_requests where org_id = :oid)",
                {"oid": org_body["id"]},
            ),
            ("delete from disclosure_requests where org_id = :oid", {"oid": org_body["id"]}),
            ("delete from products where org_id = :oid", {"oid": org_body["id"]}),
            ("delete from organizations where id = :oid", {"oid": org_body["id"]}),
            ("delete from users where id = :uid", {"uid": str(user_id)}),
        ]:
            try:
                conn.run(statement, **params)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        conn.close()
