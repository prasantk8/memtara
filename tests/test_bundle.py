"""Properties of the offline verification bundle.

The bundle exists so that an auditor with no network, no account and nobody
from the firm present can check a decision. Every test here is an attempt to
break one of the four claims that promise rests on:

  * **A manifest mismatch is detected.** A bundle whose manifest has never
    been shown to catch a changed byte is a list, not a control.

  * **A tampered record fails even when the manifest was updated to match.**
    The interesting attacker edits both. The seal is what catches that, and
    the test edits both on purpose.

  * **The pinned key set is used and the network is not.** Asserted by
    pointing the snapshot's recorded source at a host that cannot be reached
    and by making `socket.connect` raise for the duration — so a future edit
    that reaches for the network fails the suite instead of silently
    verifying a pack against whatever DNS said that morning.

  * **The two verdicts never merge.** The scenario tested is the one that
    would embarrass the firm in front of an examiner: `bb verify` exits 0 on a
    proof of *unsuitability*. Integrity must read VALID and the outcome must
    read NOT SUITABLE, in two separate lines, with no combined "PASS" anywhere.

Run:
    .venv/bin/python -m pytest tests/test_bundle.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _path in (REPO_ROOT, Path(__file__).resolve().parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from scripts.bundle import build_bundle as builder  # noqa: E402
from scripts.bundle import verify_bundle as verifier  # noqa: E402
from scripts.bundle.evidence_ops import (  # noqa: E402
    OUTCOME_INDEX,
    canonical_bytes,
    outcome_from_public_inputs,
    pack_public_inputs,
)
from scripts.bundle.jwks import okp_thumbprint, snapshot_from_jwks  # noqa: E402
from scripts.export_audit_evidence import (  # noqa: E402
    build_pack,
    canonical_bytes as exporter_canonical_bytes,
    decode_proof_token,
    render_and_seal,
)
from test_evidence_exporter import evidence_fixture  # noqa: E402

AS_OF = datetime(2026, 9, 16, 9, 0, 0, tzinfo=timezone.utc)

# The same fixed seed the integration tests and the CRO demo use, so the `kid`
# in every assertion is reproducible. Test material only.
ISSUER_SEED = bytes(range(32))

# Deliberately unroutable. Any step that reached for the network would hang or
# refuse, and the network guard turns that into a loud failure instead.
UNREACHABLE = "http://127.0.0.1:1/.well-known/jwks.json"

FAKE_PROOF = b"not a real Barretenberg proof, but a real 64 bytes of it" + b"\x00" * 9


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issuer_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(ISSUER_SEED)


def make_jwks_and_token(*, proof_sha256: str, suitable: bool) -> tuple[dict, str]:
    """A real Ed25519 key set and a real token signed under it.

    Real signatures rather than fixtures: a test that asserted the verifier
    accepts a hand-written 'signature' would pass against a verifier that
    checked nothing.
    """
    key = issuer_key()
    x = _b64url(key.public_key().public_bytes_raw())
    kid = okp_thumbprint(x)
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "use": "sig", "alg": "EdDSA", "kid": kid}]}

    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    claims = {
        "iss": "https://issuer.example",
        "sub": "0a3f2b7c-4d51-4b8e-9d2a-6c7e8f901234",
        "exp": 1_789_000_000,
        "verified": True,
        "suitable": suitable,
        "proof_hash": proof_sha256,
    }
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    token = f"{signing_input}.{_b64url(key.sign(signing_input.encode('ascii')))}"
    return jwks, token


def make_bundle(
    tmp_path: Path,
    *,
    suitable: bool | None = True,
    with_proof: bool = False,
    with_jwks: bool = True,
    with_token: bool = True,
    with_aihoots: bool = True,
    signing_key=None,
    name: str = "bundle",
) -> Path:
    """Build a real bundle through the real builder. Nothing here is stubbed.

    Fixture-driven parts, named so no reader mistakes them for live data: the
    evidence response is `tests/test_evidence_exporter.evidence_fixture` and
    the proof bytes are synthetic. The verification key, the AIHOOTS chain,
    the vendored verifier, the PDF, the seal and the JWT signature are all
    real artefacts from this repository.
    """
    evidence = evidence_fixture(suitable=suitable)

    # The bundle ships the real committed key, so the fixture must claim the
    # real key's digest. Leaving the exporter fixture's invented constant here
    # would make every bundle fail step 4 for a reason that has nothing to do
    # with what the test is about — and would hide a genuine step-4 regression
    # behind a permanent red.
    evidence["verification_key"]["sha256"] = hashlib.sha256(
        (builder.DEFAULT_VKEY_DIR / "vk").read_bytes()
    ).hexdigest()

    proof_digest = None
    if evidence["proofs"]:
        proof_digest = hashlib.sha256(FAKE_PROOF).hexdigest()
        evidence["proofs"][-1]["proof_sha256"] = proof_digest
        evidence["proofs"][-1]["proof_bytes"] = len(FAKE_PROOF)

    token = None
    snapshot = None
    if with_jwks or with_token:
        jwks, jwt = make_jwks_and_token(
            proof_sha256=proof_digest or "", suitable=bool(suitable)
        )
        if with_token:
            token = decode_proof_token(jwt)
        if with_jwks:
            snapshot = snapshot_from_jwks(jwks, source_url=UNREACHABLE, fetched_at=AS_OF)

    pack = build_pack(evidence, token=token)

    staging = tmp_path / f"{name}-render"
    rendered = render_and_seal(pack, staging / "case_file.pdf", created_at=AS_OF)

    proof_path = None
    if with_proof:
        proof_path = staging / "wealth_suitability.proof"
        proof_path.write_bytes(FAKE_PROOF)

    output = tmp_path / name
    builder.build_bundle(
        pack,
        output,
        pdf_path=rendered["pdf"],
        seal_path=rendered["seal"],
        jwks_snapshot=snapshot,
        proof_path=proof_path,
        aihoots_audit_path=(REPO_ROOT / "cro_demo" / "aihoots_audit.jsonl") if with_aihoots else None,
        signing_key=signing_key,
        created_at=AS_OF,
    )
    return output


def run(bundle: Path, *, bb_bin: str = "bb-absent-in-tests", expected_public_key: str | None = None):
    """Verify with a bb that is deliberately not installed, unless a stub is given.

    Pinning the binary name keeps the suite's verdicts identical on a machine
    with Barretenberg and one without. The two tests that care about step 5
    supply their own stub.
    """
    return verifier.verify_bundle(bundle, bb_bin=bb_bin, expected_public_key=expected_public_key)


def stub_bb(tmp_path: Path, exit_code: int) -> str:
    """A fake `bb` so step 5's wiring can be tested without a real proof."""
    path = tmp_path / f"bb-stub-{exit_code}"
    path.write_text(
        "#!/bin/sh\n"
        'echo "Proof verified successfully"\n'
        f"exit {exit_code}\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def statuses(report) -> dict[str, str]:
    return {finding["step"]: finding["status"] for finding in report.findings}


def failures(report) -> list[str]:
    return [f"{f['step']} {f['title']}" for f in report.findings if f["status"] == verifier.FAIL]


# ---------------------------------------------------------------------------
# The bundle is assembled and is checkable with nothing but itself
# ---------------------------------------------------------------------------


def test_a_bundle_carries_everything_the_procedure_needs(tmp_path):
    bundle = make_bundle(tmp_path)
    manifest = json.loads((bundle / "MANIFEST.json").read_text())

    listed = {entry["path"] for entry in manifest["files"]}
    for required in (
        "decision_evidence.json",
        "evidence_schema/case_file_pack.v1.schema.json",
        "proof/public_inputs",
        "vkey/wealth_suitability.vk",
        "vkey/vk_hash",
        "audit_chain_segment.jsonl",
        "institution_and_thresholds.json",
        "jwks_snapshot.json",
        "case_file.pdf",
        "case_file.pdf.seal.json",
        "VERIFY.md",
        "tools/verify_bundle.py",
    ):
        assert required in listed, f"{required} is not in the bundle"
        assert (bundle / required).exists()

    # Every listed file's digest is the digest of the file on disk.
    for entry in manifest["files"]:
        actual = hashlib.sha256((bundle / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], entry["path"]


def test_the_manifest_pins_bb_and_the_reference_verifier(tmp_path):
    """Break 4: neither dependency may be 'whatever was on the machine'."""
    bundle = make_bundle(tmp_path)
    pinned = json.loads((bundle / "MANIFEST.json").read_text())["pinned_dependencies"]

    assert pinned["bb"]["pinned_version"] == builder.DEFAULT_BB_VERSION
    assert pinned["bb"]["verifier_target"] == "noir-recursive"
    assert pinned["bb"]["install"]

    aihoots = pinned["aihoots_reference_verifier"]
    if aihoots["vendored"]:
        # Vendored means the chain cross-check needs no git and no network.
        assert (bundle / "tools/aihoots_reference/src/verifier/cli.py").exists()
        assert len(aihoots["pinned_commit"]) == 40
    else:
        assert any(item["path"].startswith("tools/aihoots_reference") for item in
                   json.loads((bundle / "MANIFEST.json").read_text())["absent"])


def test_decision_evidence_json_is_already_canonical(tmp_path):
    """`shasum -a 256 decision_evidence.json` must reproduce the sealed digest.

    If the file were pretty-printed, step 1 of VERIFY.md would be wrong: the
    auditor would have to re-serialise the JSON before the digest matched,
    which is exactly the kind of undocumented step that makes a procedure
    unusable by the person it was written for.
    """
    bundle = make_bundle(tmp_path)
    raw = (bundle / "decision_evidence.json").read_bytes()
    seal = json.loads((bundle / "case_file.pdf.seal.json").read_text())

    assert hashlib.sha256(raw).hexdigest() == seal["canonical_evidence_sha256"]
    assert canonical_bytes(json.loads(raw)) == raw


def test_the_bundles_canonicalisation_agrees_with_the_exporters(tmp_path):
    """Two copies of one convention. They must never drift."""
    pack = build_pack(evidence_fixture(suitable=False))
    assert canonical_bytes(pack) == exporter_canonical_bytes(pack)


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------


def test_a_manifest_hash_mismatch_is_detected(tmp_path):
    bundle = make_bundle(tmp_path)
    pdf = bundle / "case_file.pdf"
    data = bytearray(pdf.read_bytes())
    data[len(data) // 2] ^= 0x01  # one bit, in the middle of the document
    pdf.write_bytes(bytes(data))

    report = run(bundle)
    assert statuses(report)["1"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID

    detail = "\n".join(next(f for f in report.findings if f["step"] == "1")["detail"])
    assert "case_file.pdf" in detail
    assert "manifest" in detail and "on disk" in detail


def test_a_file_added_to_the_bundle_is_detected(tmp_path):
    """A bundle is exactly its manifest. An extra file is an unaccounted-for one."""
    bundle = make_bundle(tmp_path)
    (bundle / "addendum.txt").write_text("a note somebody slipped in\n")

    report = run(bundle)
    assert statuses(report)["1"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID


def test_a_tampered_decision_evidence_fails_even_when_the_manifest_was_updated(tmp_path):
    """The attacker who edits both files. The seal is what catches them.

    Changing the record and then recomputing the manifest entry defeats step 1
    entirely — which is why step 1 alone was never the control. The seal's
    `canonical_evidence_sha256` was fixed when the PDF was rendered and cannot
    be recomputed without re-rendering the document.
    """
    bundle = make_bundle(tmp_path)
    evidence_path = bundle / "decision_evidence.json"

    pack = json.loads(evidence_path.read_bytes())
    assert pack["outcome"]["suitable"] is True
    pack["outcome"]["suitable"] = False  # a decline rewritten as... the reverse
    tampered = canonical_bytes(pack)
    evidence_path.write_bytes(tampered)

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "decision_evidence.json":
            entry["sha256"] = hashlib.sha256(tampered).hexdigest()
            entry["bytes"] = len(tampered)
    manifest["canonical_evidence_sha256"] = hashlib.sha256(tampered).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    by_step = statuses(report)
    assert by_step["1"] == verifier.PASS, "the manifest was updated, so step 1 cannot catch this"
    assert by_step["2"] == verifier.FAIL, "the seal must catch it"
    assert by_step["6b"] == verifier.FAIL, "the record and the proof now disagree"
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID

    # And the outcome is still read from the proof, not from the edited record.
    assert report.outcome_verdict == "SUITABLE"


def test_a_swapped_verification_key_is_detected(tmp_path):
    bundle = make_bundle(tmp_path)
    vk = bundle / "vkey" / "wealth_suitability.vk"
    vk.write_bytes(b"\x00" * 3680)

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "vkey/wealth_suitability.vk":
            entry["sha256"] = hashlib.sha256(vk.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    assert statuses(report)["4"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID


def test_repacked_public_inputs_that_disagree_with_the_record_are_detected(tmp_path):
    bundle = make_bundle(tmp_path)
    inputs = bundle / "proof" / "public_inputs"
    data = bytearray(inputs.read_bytes())
    data[OUTCOME_INDEX * 32 + 31] ^= 0x01  # flip the verdict in the packed file
    inputs.write_bytes(bytes(data))

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "proof/public_inputs":
            entry["sha256"] = hashlib.sha256(inputs.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    assert statuses(report)["6c"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID


def test_the_builder_refuses_a_proof_that_does_not_match_the_record(tmp_path):
    """Refusing to build beats building something that contradicts itself."""
    evidence = evidence_fixture(suitable=True)
    pack = build_pack(evidence)
    rendered = render_and_seal(pack, tmp_path / "render" / "case_file.pdf", created_at=AS_OF)
    wrong = tmp_path / "wrong.proof"
    wrong.write_bytes(b"these are not the bytes the server hashed")

    with pytest.raises(builder.BuildError, match="Refusing to build"):
        builder.build_bundle(
            pack,
            tmp_path / "bundle",
            pdf_path=rendered["pdf"],
            seal_path=rendered["seal"],
            proof_path=wrong,
            created_at=AS_OF,
        )


# ---------------------------------------------------------------------------
# The pinned key set, and the absence of a network
# ---------------------------------------------------------------------------


def test_the_jwks_snapshot_is_used_and_the_network_is_not(tmp_path, monkeypatch):
    """Break 1, asserted rather than asserted-to.

    The snapshot records an unreachable host as its provenance, every socket
    is made to raise for the duration, and `urlopen` is replaced with a bomb.
    Step 8 must still verify a real EdDSA signature — which it can only do by
    reading the pinned bytes.
    """
    bundle = make_bundle(tmp_path)
    snapshot = json.loads((bundle / "jwks_snapshot.json").read_text())
    assert snapshot["source_url"] == UNREACHABLE

    import urllib.request

    def bomb(*args, **kwargs):
        raise AssertionError("the verifier reached for the network")

    monkeypatch.setattr(urllib.request, "urlopen", bomb)
    monkeypatch.setattr(verifier.socket.socket, "connect", bomb, raising=False)
    monkeypatch.setattr(verifier.socket, "create_connection", bomb, raising=False)

    report = run(bundle)
    step_8 = next(f for f in report.findings if f["step"] == "8")
    assert step_8["status"] == verifier.PASS
    detail = "\n".join(step_8["detail"])
    assert UNREACHABLE in detail, "the provenance URL must be shown, not followed"
    assert "did not open it" in detail


def test_the_network_guard_makes_an_outbound_call_impossible(monkeypatch):
    """The guard is a control, not a comment. It must actually raise."""
    import socket as socket_module

    monkeypatch.setattr(socket_module.socket, "connect", socket_module.socket.connect)
    monkeypatch.setattr(socket_module.socket, "connect_ex", socket_module.socket.connect_ex)
    monkeypatch.setattr(socket_module, "create_connection", socket_module.create_connection)

    verifier.install_network_guard()
    with pytest.raises(verifier.NetworkAttempted):
        socket_module.create_connection(("127.0.0.1", 1), timeout=0.1)
    with pytest.raises(verifier.NetworkAttempted):
        socket_module.socket().connect(("127.0.0.1", 1))


def test_a_token_signed_by_another_key_does_not_verify(tmp_path):
    bundle = make_bundle(tmp_path)
    snapshot_path = bundle / "jwks_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())

    # Same kid, different key material: the substitution a forged snapshot
    # would make. The thumbprint no longer matches the kid, and the signature
    # no longer verifies.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    snapshot["jwks"]["keys"][0]["x"] = _b64url(other.public_key().public_bytes_raw())
    snapshot_path.write_bytes(canonical_bytes(snapshot))

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "jwks_snapshot.json":
            entry["sha256"] = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    step_8 = next(f for f in report.findings if f["step"] == "8")
    assert step_8["status"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID


def test_a_bundle_without_a_key_set_says_so_instead_of_pointing_at_a_url(tmp_path):
    bundle = make_bundle(tmp_path, with_jwks=False)
    manifest = json.loads((bundle / "MANIFEST.json").read_text())
    assert any(item["path"] == "jwks_snapshot.json" for item in manifest["absent"])

    report = run(bundle)
    step_8 = next(f for f in report.findings if f["step"] == "8")
    assert step_8["status"] == verifier.NOT_RUN
    assert report.integrity_verdict == verifier.INTEGRITY_INCOMPLETE


# ---------------------------------------------------------------------------
# Two verdicts, always separate
# ---------------------------------------------------------------------------


def test_a_valid_proof_of_unsuitability_is_valid_integrity_and_a_decline(tmp_path):
    """The scenario a single-verdict console would get catastrophically wrong.

    `bb verify` exits 0. Everything checks out. The answer is NO. Integrity is
    VALID and the outcome is NOT SUITABLE, and the two are printed on separate
    lines with no word that covers both.
    """
    bundle = make_bundle(tmp_path, suitable=False, with_proof=True)
    report = run(bundle, bb_bin=stub_bb(tmp_path, 0))

    assert statuses(report)["5"] == verifier.PASS, "the proof itself is well formed"
    assert report.integrity_verdict == verifier.INTEGRITY_VALID
    assert report.outcome_verdict == "NOT SUITABLE"
    assert failures(report) == []

    rendered = "\n".join(verifier.render_report(report, bundle))
    assert "EVIDENCE INTEGRITY   VALID" in rendered
    assert "DECISION OUTCOME     NOT SUITABLE" in rendered
    assert "is not an approval" in rendered
    # No line may present a single overall result.
    assert "OVERALL" not in rendered.upper()


def test_the_outcome_is_read_from_index_11_not_from_the_exit_code(tmp_path):
    """A proof that fails verification does not turn a decline into an approval."""
    bundle = make_bundle(tmp_path, suitable=False, with_proof=True)
    report = run(bundle, bb_bin=stub_bb(tmp_path, 1))

    assert statuses(report)["5"] == verifier.FAIL
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID
    assert report.outcome_verdict == "NOT SUITABLE", "the reading is independent of the exit code"


def test_an_unassessed_request_is_not_reported_as_a_decline(tmp_path):
    bundle = make_bundle(tmp_path, suitable=None)
    report = run(bundle)
    assert report.outcome_verdict == "NOT ASSESSED"
    assert "NOT SUITABLE" not in report.outcome_verdict


def test_a_missing_proof_is_incomplete_and_never_valid(tmp_path):
    """NOT RUN must not be quietly counted as a pass."""
    bundle = make_bundle(tmp_path)  # no --proof-file, no bb
    report = run(bundle)

    assert statuses(report)["5"] == verifier.NOT_RUN
    assert report.integrity_verdict == verifier.INTEGRITY_INCOMPLETE
    assert failures(report) == []

    rendered = "\n".join(verifier.render_report(report, bundle))
    assert "INCOMPLETE is not a pass" in rendered

    manifest = json.loads((bundle / "MANIFEST.json").read_text())
    absent = {item["path"]: item for item in manifest["absent"]}
    assert "proof/wealth_suitability.proof" in absent
    assert absent["proof/wealth_suitability.proof"]["expected_sha256"]


# ---------------------------------------------------------------------------
# Origin, stated as weakly as it deserves
# ---------------------------------------------------------------------------


def test_an_unsigned_seal_is_reported_as_not_being_a_signature(tmp_path):
    bundle = make_bundle(tmp_path)
    assert json.loads((bundle / "case_file.pdf.seal.json").read_text())["signature"] is None

    report = run(bundle)
    step_9 = "\n".join(next(f for f in report.findings if f["step"] == "9")["detail"])
    assert "THE SEAL IS NOT A SIGNATURE" in step_9
    assert "MANIFEST.json.sig is absent" in step_9


def test_a_signed_manifest_verifies_and_a_wrong_expected_key_fails(tmp_path):
    key = issuer_key()
    bundle = make_bundle(tmp_path, signing_key=key)
    public_hex = key.public_key().public_bytes_raw().hex()

    report = run(bundle, expected_public_key=public_hex)
    assert statuses(report)["9"] == verifier.PASS

    wrong = run(bundle, expected_public_key="ab" * 32)
    assert statuses(wrong)["9"] == verifier.FAIL
    assert wrong.integrity_verdict == verifier.INTEGRITY_INVALID


def test_a_tampered_manifest_breaks_its_signature(tmp_path):
    bundle = make_bundle(tmp_path, signing_key=issuer_key())
    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["request_id"] = "00000000-0000-0000-0000-000000000000"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    assert statuses(report)["9"] == verifier.FAIL


# ---------------------------------------------------------------------------
# The exported rows, and what they can and cannot show
# ---------------------------------------------------------------------------


def test_the_audit_segment_matches_the_record_and_states_its_own_limits(tmp_path):
    bundle = make_bundle(tmp_path)
    report = run(bundle)
    step_7 = next(f for f in report.findings if f["step"] == "7")
    detail = "\n".join(step_7["detail"])

    assert step_7["status"] == verifier.PASS
    assert "identical to audit_chain_excerpt" in detail
    assert "WHAT THIS CANNOT SHOW" in detail
    assert "no payload column" in detail


def test_an_altered_audit_segment_is_detected(tmp_path):
    bundle = make_bundle(tmp_path)
    segment = bundle / "audit_chain_segment.jsonl"
    lines = segment.read_text().splitlines()
    record = json.loads(lines[0])
    record["event_type"] = "something_else"
    lines[0] = canonical_bytes(record).decode()
    segment.write_text("\n".join(lines) + "\n")

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "audit_chain_segment.jsonl":
            entry["sha256"] = hashlib.sha256(segment.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    assert statuses(report)["7"] == verifier.FAIL


def test_the_relying_partys_chain_is_checked_by_its_own_verifier(tmp_path):
    bundle = make_bundle(tmp_path)
    if not (bundle / "tools/aihoots_reference/src/verifier/cli.py").exists():
        pytest.skip("the AIHOOTS submodule is not checked out, so nothing was vendored")

    report = run(bundle)
    step = next(f for f in report.findings if f["step"] == "7b")
    detail = "\n".join(step["detail"])
    assert step["status"] == verifier.PASS
    assert "src.verifier.cli" in detail
    assert "does not mean the log is complete" in detail


def test_the_thresholds_are_exported_as_files_not_left_in_a_database(tmp_path):
    """Break 3: verification must not need Memtara's API to be up."""
    bundle = make_bundle(tmp_path)
    exported = json.loads((bundle / "institution_and_thresholds.json").read_text())
    pack = json.loads((bundle / "decision_evidence.json").read_bytes())

    assert exported["organisation"] == pack["organisation"]
    assert exported["terms_assessed_against"] == pack["terms_assessed_against"]
    assert exported["terms_assessed_against"]["min_income"] == 500000


# ---------------------------------------------------------------------------
# The packing rules the whole procedure rests on
# ---------------------------------------------------------------------------


def test_public_inputs_pack_as_32_byte_big_endian_fields():
    values = [f"0x{i:064x}" for i in range(12)]
    packed = pack_public_inputs(values)
    assert len(packed) == 12 * 32
    assert packed[11 * 32 : 12 * 32] == (11).to_bytes(32, "big")


def test_the_verdict_is_read_only_from_a_zero_or_a_one():
    suitable = [f"0x{0:064x}"] * 11 + ["0x" + "0" * 63 + "1"]
    declined = [f"0x{0:064x}"] * 12
    garbage = [f"0x{0:064x}"] * 11 + [f"0x{7:064x}"]
    short = [f"0x{0:064x}"] * 11

    assert outcome_from_public_inputs(suitable) is True
    assert outcome_from_public_inputs(declined) is False
    # Neither 0 nor 1 in the return position is not a verdict, and must not be
    # coerced into one by truthiness.
    assert outcome_from_public_inputs(garbage) is None
    assert outcome_from_public_inputs(short) is None


def test_the_schema_is_the_pack_schema_and_says_so(tmp_path):
    """Honesty about scope: this is not the DecisionEvidence v1 schema."""
    schema = json.loads(builder.SCHEMA_SOURCE.read_text())
    description = schema["description"]
    assert "not the DecisionEvidence v1 schema" in description
    assert "no model." in description and "no human_review." in description


def test_verify_md_scopes_independence_to_one_circuit(tmp_path):
    """The claim must be circuit-specific in the document AND in the manifest.

    Compared with whitespace normalised, because the wording is what matters
    and a reflowed paragraph is not a change of meaning. Asserted at all
    because "our proofs are independently verifiable" is exactly the sentence
    that grows into a systemic claim on its way to a board pack.
    """
    lines = (REPO_ROOT / "docs" / "VERIFY.md").read_text().splitlines()
    text = " ".join(" ".join(line.lstrip("> ").split()) for line in lines)
    for phrase in (
        "covers the `wealth_suitability` circuit and no other",
        "gitignored build artefacts regenerated at boot",
        "a property of one circuit, not of the system",
    ):
        assert phrase in text, phrase

    manifest = json.loads((make_bundle(tmp_path) / "MANIFEST.json").read_text())
    scope = " ".join(manifest["independence_scope"].split())
    assert "a property of one circuit, not of the system" in scope


def test_the_cli_exit_code_encodes_the_integrity_verdict_only(tmp_path, capsys):
    bundle = make_bundle(tmp_path, suitable=False, with_proof=True)
    code = verifier.main([str(bundle), "--bb", stub_bb(tmp_path, 0)])
    out = capsys.readouterr().out

    assert code == 0, "a correctly evidenced decline exits 0: integrity is what the code reports"
    assert "DECISION OUTCOME     NOT SUITABLE" in out

    bad = make_bundle(tmp_path, name="broken")
    (bad / "case_file.pdf").write_bytes(b"replaced")
    assert verifier.main([str(bad), "--bb", "bb-absent-in-tests"]) == 1

    incomplete = make_bundle(tmp_path, name="thin")
    assert verifier.main([str(incomplete), "--bb", "bb-absent-in-tests"]) == 2
