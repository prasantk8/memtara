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
import shutil
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
    BINDING_EVENTS_FILENAME,
    MODEL_ATTESTATION_BOUND,
    OUTCOME_INDEX,
    binding_event_hash,
    canonical_bytes,
    outcome_from_public_inputs,
    pack_public_inputs,
)
from scripts.bundle.jwks import okp_thumbprint, snapshot_from_jwks  # noqa: E402
from scripts.export_audit_evidence import (  # noqa: E402
    build_pack,
    canonical_bytes as exporter_canonical_bytes,
    collect_binding,
    decode_proof_token,
    render_and_seal,
)
from test_evidence_exporter import evidence_fixture  # noqa: E402

@pytest.fixture(autouse=True)
def _contain_the_network_guard():
    """Undo `install_network_guard()` after every test in this module.

    The guard is deliberately irreversible in production — it makes an
    outbound connection impossible "for the rest of this process", which is
    the correct design for a verifier whose whole claim is that it read the
    pinned files and nothing else. It patches `socket.socket.connect`,
    `connect_ex` and `socket.create_connection` at module level.

    In a pytest session that is a shared, global mutation. Any test here that
    exercises the real verification path installs it, and it then survives
    into every later test file: the run this fixture was written for reported
    2 failures and 32 errors across unrelated suites, every one of them a
    `NetworkAttempted` raised out of a test that had nothing to do with the
    bundle. The tests were fine; the session was poisoned.

    The fix belongs here rather than in the verifier. Adding an `uninstall()`
    for the convenience of tests would put a switch on a control whose value
    is that it has no switch. So this snapshots the three attributes and puts
    them back, containing the blast radius to this module without weakening
    what ships.
    """
    import socket as socket_module

    saved = (
        socket_module.socket.connect,
        socket_module.socket.connect_ex,
        socket_module.create_connection,
    )
    try:
        yield
    finally:
        socket_module.socket.connect = saved[0]
        socket_module.socket.connect_ex = saved[1]
        socket_module.create_connection = saved[2]


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


# The model this fixture's decision was opened against. One dict, used to build
# BOTH the binding payload and the record's model block, so that "they agree"
# in the default bundle is a property of the fixture rather than of two lists
# that were typed out to match.
FIXTURE_MODEL = {
    "provider": "anthropic",
    "model_name": "claude-opus-4",
    "model_version": "20260514",
    "prompt_version": "suitability-v7",
    "environment": "production",
    "config_fingerprint": "ab" * 32,
    "system_prompt_or_policy_id": "policy/suitability/7",
    "timestamp": "2026-09-16T08:54:58Z",
}

# Deliberately not the first event in the chain: `prev_hash` is an input to the
# digest, and a fixture that left it empty would never exercise the framing of
# a non-empty predecessor.
FIXTURE_PREV_HASH = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def binding_payload(request_id: str, org_id: str, *, model: dict | None, declaration: str) -> dict:
    """The payload `audit/binding.rs::model_attestation_payload` builds.

    Restated here rather than imported, for the same reason the bundle restates
    `canonical_bytes`: a Rust file is not importable from Python. What keeps
    the two honest is not this dict but
    `test_the_binding_recomputation_matches_a_real_server`, which checks the
    construction against digests a live server produced.
    """
    m = model or {}
    return {
        "binding": "decision_model_attestation_binding/v1",
        "request_id": request_id,
        "org_id": org_id,
        "declaration": declaration,
        "no_ai_attestation": None if model else
        "the deterministic suitability rules engine decided this; no model was in the path",
        "unidentified_reason": None,
        "model_provider": m.get("provider"),
        "model_name": m.get("model_name"),
        "model_version": m.get("model_version"),
        "prompt_version": m.get("prompt_version"),
        "model_environment": m.get("environment"),
        "model_config_fingerprint": m.get("config_fingerprint"),
        "model_system_prompt_or_policy_id": m.get("system_prompt_or_policy_id"),
        "model_timestamp": m.get("timestamp"),
        "input_context_fingerprint": None,
        "output_fingerprint": None,
        "attested_at": "2026-09-16T08:54:58Z",
    }


def provenanced(value):
    if value is None:
        return {"state": "unpopulated", "unpopulated_reason": "not supplied by the caller", "value": None}
    return {"state": "recorded", "value": value}


def binding_envelope(
    evidence: dict,
    *,
    model: dict | None = FIXTURE_MODEL,
    declaration: str = "model_identified",
    hash_over: dict | None = None,
) -> dict:
    """A `GET .../decision-evidence` response, with REAL digests.

    The digests are computed with the same function the verifier recomputes
    with, which would be circular if that function were only ever checked
    against itself — so it is also checked against a live server's digests in
    `test_the_binding_recomputation_matches_a_real_server`. Here the point is
    different: every tamper test below needs a bundle that starts out genuinely
    consistent, or it would be asserting that a broken thing is broken.

    `hash_over` records the digest of a DIFFERENT payload than the one carried,
    which is exactly what a database UPDATE produces: the chain keeps the
    original digest and the rebuild returns the new rows.
    """
    request_id, org_id = evidence["request_id"], evidence["organisation"]["id"]
    payload = binding_payload(request_id, org_id, model=model, declaration=declaration)
    digest = binding_event_hash(
        MODEL_ATTESTATION_BOUND, request_id, FIXTURE_PREV_HASH, hash_over or payload
    )
    return {
        "evidence_schema": "schema/decision_evidence/v1.2.0.json",
        "canonical_evidence_sha256": "0" * 64,
        "decision_evidence": {
            "evidence_schema_version": "1.2.0",
            "model": None if model is None else {k: provenanced(v) for k, v in model.items()},
            "model_provenance": {
                "declared_at": provenanced("2026-09-16T08:54:58Z"),
                "as_declared_at_open": {
                    "declaration": declaration,
                    "no_ai_attestation": payload["no_ai_attestation"],
                    "unidentified_reason": None,
                    "identity": {
                        "provider": (model or {}).get("provider"),
                        "model_name": (model or {}).get("model_name"),
                        "model_version": (model or {}).get("model_version"),
                        "prompt_version": (model or {}).get("prompt_version"),
                        "environment": (model or {}).get("environment"),
                        "config_fingerprint": (model or {}).get("config_fingerprint"),
                        "system_prompt_or_policy_id": (model or {}).get("system_prompt_or_policy_id"),
                        "timestamp": (model or {}).get("timestamp"),
                    },
                },
                "corrected": False,
                "correction_count": 0,
                "corrections": [],
                "statement": "declared when the assessment was opened; never corrected",
            },
        },
        "binding_integrity": {
            "verdict": "INTACT",
            "events": [
                {
                    "seq": 4117,
                    "event_type": MODEL_ATTESTATION_BOUND,
                    "ref_id": request_id,
                    "created_at": "2026-09-16T08:55:00Z",
                    "result": "intact",
                    "recorded_event_hash": base64.urlsafe_b64encode(digest).decode().rstrip("="),
                    "recomputed_event_hash": base64.urlsafe_b64encode(digest).decode().rstrip("="),
                    "prev_hash": FIXTURE_PREV_HASH,
                    "rebuilt_payload": payload,
                    "detail": "",
                }
            ],
        },
    }


def make_bundle(
    tmp_path: Path,
    *,
    suitable: bool | None = True,
    with_proof: bool = False,
    with_jwks: bool = True,
    with_token: bool = True,
    with_aihoots: bool = True,
    with_binding: bool = True,
    binding: dict | None = None,
    signing_key=None,
    provenance: str | None = None,
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

    envelope = None
    if with_binding:
        envelope = binding if binding is not None else binding_envelope(evidence)
    pack = build_pack(
        evidence,
        token=token,
        binding=collect_binding(
            envelope,
            evidence["request_id"],
            reason="this bundle was built without a binding report, on purpose",
        ),
    )

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
        provenance=provenance,
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


# ---------------------------------------------------------------------------
# Binding — the third claim, and the only one that survives a database write
#
# `audit_chain_segment.jsonl` lets an auditor check LINKAGE: that no row was
# removed or reordered. It cannot check that the rows a decision is JUDGED on
# still say what was hashed, because `audit_log` stores no payload column. A
# single UPDATE against `decision_model_attestations` rewrites the model
# identity the sealed record serves and leaves the chain byte-identical either
# side of it — docs/BREAK_IT_FINDINGS.md finding 4, and
# tests/break_it/test_attack_04_model_identity_change.py against a live server.
#
# The tests below are the offline half of that: an examiner with the bundle,
# no database and no network must be able to reach the same conclusions.
# ---------------------------------------------------------------------------


def test_the_binding_events_are_carried_as_inputs_and_not_as_a_verdict(tmp_path):
    """The distinction the whole file rests on.

    A bundle that carried Memtara's verdict and displayed it would have added
    nothing: Memtara built the bundle, so its opinion of the bundle is not
    evidence about it. What must travel is the material an examiner recomputes
    from — and what must NOT travel is `result`, `recomputed_event_hash` and
    `verdict`, because a reader who finds them will read them instead.
    """
    bundle = make_bundle(tmp_path)
    raw = (bundle / BINDING_EVENTS_FILENAME).read_text()
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert events, "the default bundle must carry binding events"

    for event in events:
        for required in ("event_type", "ref_id", "prev_hash", "event_hash", "rebuilt_payload"):
            assert required in event, f"{required} is an input to the digest and must travel"
        for forbidden in ("result", "recomputed_event_hash", "verdict", "detail"):
            assert forbidden not in event, (
                f"{forbidden} is Memtara's conclusion about Memtara's own evidence. Carrying it "
                "invites an examiner to read our answer instead of computing theirs"
            )

    entry = next(
        e for e in json.loads((bundle / "MANIFEST.json").read_text())["files"]
        if e["path"] == BINDING_EVENTS_FILENAME
    )
    assert "WHAT IT DOES NOT PROVE" in entry["what"], (
        "every bundle entry says what it is for AND what it does not prove; this one is the "
        "easiest in the pack to over-read"
    )


def test_an_untouched_binding_verifies_and_the_record_agrees(tmp_path):
    """No false positive, asserted before any tamper.

    A detector that fires on an untouched bundle is worse than none: it teaches
    an operator to dismiss the one real alarm. This is also the assertion that
    fails if the Python reconstruction of the digest ever drifts from what the
    Rust writer hashed.
    """
    bundle = make_bundle(tmp_path)
    report = run(bundle)
    by_step = statuses(report)
    assert by_step["7d"] == verifier.PASS
    assert by_step["7e"] == verifier.PASS

    detail = "\n".join(next(f for f in report.findings if f["step"] == "7d")["detail"])
    assert "INTACT" in detail
    assert "AND NOT LINKAGE" in detail, "a reader must not take 7d as a linkage result"
    assert "does not show" in detail.lower(), "and must not take it as proof the row was true"


def test_a_database_edit_to_the_model_row_is_caught_offline(tmp_path):
    """Attack 4, from inside a bundle, with no database and no server.

    The UPDATE rewrites the row, so a FRESH export produces a record and a
    rebuilt payload that agree with each other — they were built from the same
    rewritten row — and a manifest and a seal that are perfectly consistent,
    because the attacker used Memtara's own exporter. Steps 1, 2 and 7 all pass.
    The recorded digest is the one thing the UPDATE could not reach, and step 7d
    is the only place that shows.
    """
    evidence = evidence_fixture(suitable=True)
    swapped = dict(FIXTURE_MODEL, provider="a-different-vendor", model_name="a-different-model")
    bundle = make_bundle(
        tmp_path,
        # The payload and the record carry the NEW identity; the digest still
        # describes the old one.
        binding=binding_envelope(
            evidence,
            model=swapped,
            hash_over=binding_payload(
                evidence["request_id"], evidence["organisation"]["id"],
                model=FIXTURE_MODEL, declaration="model_identified",
            ),
        ),
    )

    report = run(bundle)
    by_step = statuses(report)
    assert by_step["1"] == verifier.PASS, "the bundle is internally consistent"
    assert by_step["2"] == verifier.PASS, "and the seal covers the record it ships"
    assert by_step["7"] == verifier.PASS, "and linkage is untouched — it always was"
    assert by_step["7d"] == verifier.FAIL, "only the binding recomputation sees this"
    assert by_step["7e"] == verifier.PASS, (
        "and the cross-check correctly does NOT fire: the record and the payload agree with "
        "each other because both were rebuilt from the same rewritten row. The two checks "
        "answer different questions and neither is the other's summary"
    )
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID
    assert report.outcome_verdict == "SUITABLE", "a broken binding is not a decline"


def test_a_bundle_whose_record_was_edited_fails_the_cross_check(tmp_path):
    """The mirror image, and the reason step 7e exists at all.

    Here nobody touched the database. Someone edited the model block in the
    bundle's own record and left the binding file alone. Every digest in step 7d
    still checks out — the payload was not touched — and only the comparison
    between the record and the chain notices.
    """
    bundle = make_bundle(tmp_path)
    path = bundle / "decision_evidence.json"
    pack = json.loads(path.read_bytes())
    pack["model_attestation"]["model"]["model_name"]["value"] = "an-entirely-different-model"
    pack["model_attestation"]["model_provenance"]["as_declared_at_open"]["identity"]["model_name"] = (
        "an-entirely-different-model"
    )
    edited = canonical_bytes(pack)
    path.write_bytes(edited)

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "decision_evidence.json":
            entry["sha256"] = hashlib.sha256(edited).hexdigest()
            entry["bytes"] = len(edited)
    manifest["canonical_evidence_sha256"] = hashlib.sha256(edited).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    by_step = statuses(report)
    assert by_step["1"] == verifier.PASS, "the manifest was updated, so step 1 cannot catch this"
    assert by_step["7d"] == verifier.PASS, "the binding file was not touched, so it still verifies"
    assert by_step["7e"] == verifier.FAIL
    detail = "\n".join(next(f for f in report.findings if f["step"] == "7e")["detail"])
    assert "chain-bound" in detail and "record says" in detail, "name the fields that differ"


def test_the_no_ai_assertion_is_bound_and_its_escalation_is_caught(tmp_path):
    """`model: null` is an answer, and it must not be reachable from a rewrite.

    Two halves, and the second is the one that matters. A record that asserts
    no AI participated, matching a chain-bound `no_ai_participated` declaration,
    must verify — it is a signed statement of fact and refusing it would make
    the field useless to the firms it was built for. And a record that asserts
    it for a decision the chain committed to as `model_identified` must be a
    contradiction, because that is the escalation of finding 4: one UPDATE, and
    the strongest claim in the schema is made about a decision opened naming a
    model.
    """
    evidence = evidence_fixture(suitable=True)

    honest = make_bundle(
        tmp_path,
        name="no-ai",
        binding=binding_envelope(evidence, model=None, declaration="no_ai_participated"),
    )
    report = run(honest)
    assert statuses(report)["7d"] == verifier.PASS
    assert statuses(report)["7e"] == verifier.PASS
    detail = "\n".join(next(f for f in report.findings if f["step"] == "7e")["detail"])
    assert "signed assertion that no AI participated" in detail

    # The escalation: the chain bound a named model; the record now says none.
    escalated = make_bundle(
        tmp_path,
        name="escalated",
        binding=binding_envelope(
            evidence,
            model=None,
            declaration="no_ai_participated",
            hash_over=binding_payload(
                evidence["request_id"], evidence["organisation"]["id"],
                model=FIXTURE_MODEL, declaration="model_identified",
            ),
        ),
    )
    path = escalated / "decision_evidence.json"
    pack = json.loads(path.read_bytes())
    # Put the chain-bound declaration back to `model_identified` in the carried
    # payload so the two disagree about the DECLARATION and not merely a leaf.
    for event in pack["binding_replay"]["events"]:
        if event["event_type"] == MODEL_ATTESTATION_BOUND:
            event["rebuilt_payload"]["declaration"] = "model_identified"
            event["rebuilt_payload"]["model_name"] = FIXTURE_MODEL["model_name"]
    rewritten = canonical_bytes(pack)
    path.write_bytes(rewritten)
    (escalated / BINDING_EVENTS_FILENAME).write_bytes(
        b"".join(canonical_bytes(e) + b"\n" for e in pack["binding_replay"]["events"])
    )
    manifest_path = escalated / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] in ("decision_evidence.json", BINDING_EVENTS_FILENAME):
            data = (escalated / entry["path"]).read_bytes()
            entry["sha256"], entry["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    manifest["canonical_evidence_sha256"] = hashlib.sha256(rewritten).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(escalated)
    assert statuses(report)["7e"] == verifier.FAIL
    detail = "\n".join(next(f for f in report.findings if f["step"] == "7e")["detail"])
    assert "worst shape this failure takes" in detail
    assert "signed assertion that no AI system took part" in detail
    assert report.integrity_verdict == verifier.INTEGRITY_INVALID


def test_a_bundle_with_no_binding_events_is_incomplete_and_never_valid(tmp_path):
    """An absent check is not a passed one, and this is where that bites hardest.

    A bundle carrying no binding events cannot say anything about whether the
    rows behind its decision still hold what was hashed. Reporting that as a
    clean result would hand a firm a clean bill of health for a property it does
    not have — the same reasoning `ReplayVerdict::Incomplete` follows on the
    server side.
    """
    bundle = make_bundle(tmp_path, with_binding=False, suitable=False, with_proof=True)
    report = run(bundle, bb_bin=stub_bb(tmp_path, 0))

    assert statuses(report)["7d"] == verifier.NOT_RUN
    assert statuses(report)["7e"] == verifier.NOT_RUN
    assert failures(report) == [], "nothing is broken; something is unchecked"
    assert report.integrity_verdict == verifier.INTEGRITY_INCOMPLETE

    absent = {item["path"]: item for item in json.loads((bundle / "MANIFEST.json").read_text())["absent"]}
    assert BINDING_EVENTS_FILENAME in absent
    assert "UNCHECKED" in absent[BINDING_EVENTS_FILENAME]["reason"]

    detail = "\n".join(next(f for f in report.findings if f["step"] == "7d")["detail"])
    assert "an absent check is not a passed one" in detail
    assert "byte-identical" in detail, "and say what step 7's PASS specifically fails to cover"


def test_the_binding_file_must_match_the_record_it_was_extracted_from(tmp_path):
    """The jsonl is a working copy, not a second source.

    Same rule `audit_chain_segment.jsonl` follows: the record's copy is inside
    the bytes the seal covers, so a divergence between the two means one of them
    was edited afterwards.
    """
    bundle = make_bundle(tmp_path)
    path = bundle / BINDING_EVENTS_FILENAME
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    events[0]["created_at"] = "1999-01-01T00:00:00Z"
    payload = events[0]["rebuilt_payload"]
    events[0]["event_hash"] = base64.urlsafe_b64encode(
        binding_event_hash(events[0]["event_type"], events[0]["ref_id"], events[0]["prev_hash"], payload)
    ).decode().rstrip("=")
    path.write_bytes(b"".join(canonical_bytes(e) + b"\n" for e in events))

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == BINDING_EVENTS_FILENAME:
            data = path.read_bytes()
            entry["sha256"], entry["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    assert statuses(report)["7d"] == verifier.FAIL
    detail = "\n".join(next(f for f in report.findings if f["step"] == "7d")["detail"])
    assert "does not match binding_replay.events" in detail


def test_a_binding_event_for_another_decision_is_not_credited(tmp_path):
    """A valid event about the wrong assessment is still the wrong assessment.

    Same reasoning as step 6's public-input binding: a valid proof over someone
    else's inputs is a valid proof of someone else's case. An event lifted from
    a neighbouring decision re-hashes perfectly, so nothing else in step 7d
    would catch it.
    """
    bundle = make_bundle(tmp_path)
    path = bundle / BINDING_EVENTS_FILENAME
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    stranger = "00000000-0000-4000-8000-000000000001"
    events[0]["ref_id"] = stranger
    events[0]["rebuilt_payload"]["request_id"] = stranger
    events[0]["event_hash"] = base64.urlsafe_b64encode(
        binding_event_hash(
            events[0]["event_type"], stranger, events[0]["prev_hash"], events[0]["rebuilt_payload"]
        )
    ).decode().rstrip("=")
    path.write_bytes(b"".join(canonical_bytes(e) + b"\n" for e in events))

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == BINDING_EVENTS_FILENAME:
            data = path.read_bytes()
            entry["sha256"], entry["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    detail = "\n".join(next(f for f in report.findings if f["step"] == "7d")["detail"])
    assert "INTACT" in detail, "the substituted event does re-hash — that is the point"
    assert statuses(report)["7d"] == verifier.FAIL
    assert stranger in detail and "not this decision" in detail


def test_the_framing_is_the_one_the_rust_writer_uses():
    """Reproduce `audit/mod.rs::compute_event_hash` from its own definition.

    Not a round-trip against this module's own output, which would pass against
    any self-consistent construction. Each component is framed by hand here, so
    a change to `framed`, to the ref_id encoding or to the field order fails.
    """
    from scripts.bundle import evidence_ops

    event_type, ref_id = MODEL_ATTESTATION_BOUND, "71386234-daae-4896-91fe-4c469cf59af2"
    prev = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    payload = {"binding": "decision_model_attestation_binding/v1", "model_name": "m"}

    expected = hashlib.sha256(
        len(event_type.encode()).to_bytes(8, "big") + event_type.encode()
        + (16).to_bytes(8, "big") + bytes.fromhex(ref_id.replace("-", ""))
        + (32).to_bytes(8, "big") + bytes(range(32))
        + len(canonical_bytes(payload)).to_bytes(8, "big") + canonical_bytes(payload)
    ).digest()
    assert binding_event_hash(event_type, ref_id, prev, payload) == expected

    # The framing has to remove concatenation ambiguity, or the boundary
    # between two adjacent fields is forgeable. Same property
    # `audit/mod.rs::framing_prevents_concatenation_ambiguity` pins in Rust.
    assert evidence_ops.framed(b"ab") + evidence_ops.framed(b"cd") != \
        evidence_ops.framed(b"a") + evidence_ops.framed(b"bcd")
    # An empty prev_hash and an absent one are the same input, and must be:
    # the first event in the chain has no predecessor.
    assert binding_event_hash(event_type, ref_id, None, payload) == \
        binding_event_hash(event_type, ref_id, "", payload)
    # A ref_id that is not a UUID is refused rather than hashed as text.
    with pytest.raises(evidence_ops.BindingError):
        binding_event_hash(event_type, "not-a-uuid", None, payload)


def test_the_binding_recomputation_matches_a_real_server():
    """The empirical check, against digests this repository did not compute.

    Everything else in this file recomputes a digest with the same function that
    produced it, which proves self-consistency and nothing else. The claim that
    matters is cross-language: Rust hashes `serde_json::to_vec(payload)` and
    Python must produce identical bytes from `canonical_bytes`. Those two
    encodings genuinely differ over part of the value domain — see the five
    divergences enumerated in backend/api/src/evidence/canonical.rs — and
    `audit/binding.rs::guard_cross_verifier_reproducible` refuses at write time
    to record a binding payload where they do. This asserts the guard's promise
    holds in practice rather than taking its word for it.

    The example bundle is the fixture because it was built against a live
    server: the digests in it came out of Postgres, computed by the Rust writer.
    """
    example = REPO_ROOT / "scripts" / "bundle" / "example" / BINDING_EVENTS_FILENAME
    if not example.exists():
        pytest.skip("no example bundle checked in")

    events = [json.loads(line) for line in example.read_text().splitlines() if line.strip()]
    assert len(events) >= 2, "the example must exercise more than one binding event type"
    assert {e["event_type"] for e in events} == {
        MODEL_ATTESTATION_BOUND,
        "disclosure_policy_bound",
    }, "both binding types the server writes today must be represented"

    for event in events:
        recomputed = base64.urlsafe_b64encode(
            binding_event_hash(
                event["event_type"], event["ref_id"], event["prev_hash"], event["rebuilt_payload"]
            )
        ).decode().rstrip("=")
        assert recomputed == event["event_hash"], (
            f"{event['event_type']}: the bytes Python canonicalises are not the bytes the Rust "
            "writer hashed. That is a cross-verifier divergence, not a test failure — see "
            "evidence/canonical.rs and audit/binding.rs"
        )


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


def test_the_checkpoint_slot_is_reserved_and_the_gap_is_stated(tmp_path):
    """The terminal row of this bundle's segment is unprotected. Say so, exactly.

    Reported as INFO, not NOT RUN, on purpose: a check that no bundle in
    existence can satisfy would make every bundle INCOMPLETE forever, which
    would empty that word of meaning and bury the NOT RUNs that are genuinely
    about the pack in front of you.

    The wording carries a distinction that is easy to lose and expensive to
    lose: checkpoints EXIST now (`audit/checkpoint.rs`, and
    `GET /orgs/:id/audit-chain/checkpoint`), and this builder simply does not
    fetch one. "No deployment produces one" would have been a false statement
    about the product, made by the tool an examiner is most likely to believe.
    """
    bundle = make_bundle(tmp_path)
    absent = {item["path"]: item for item in json.loads((bundle / "MANIFEST.json").read_text())["absent"]}
    assert "audit_chain_checkpoint.json" in absent
    reason = absent["audit_chain_checkpoint.json"]["reason"]
    assert "followed" in reason.lower()
    assert "or covered by a signed checkpoint" in reason, (
        "the sentence describing what a chain protects must name both mechanisms"
    )
    assert "not about the deployment" in reason

    report = run(bundle)
    step_7c = next(f for f in report.findings if f["step"] == "7c")
    assert step_7c["status"] == verifier.INFO
    assert step_7c["bears_on_integrity"] is False
    detail = "\n".join(step_7c["detail"])
    assert "WHAT IS THEREFORE UNPROTECTED HERE" in detail
    assert "WHAT A CHECKPOINT ADDS" in detail
    assert "never written" in detail, "the checkpoint's own limit must be stated too"
    assert "necessarily made AFTER the events it pins" in detail, (
        "and so must the residual window: a checkpoint cannot cover a row that did not exist "
        "when it was signed, so the newest rows are always briefly covered by neither mechanism"
    )

    step_7 = "\n".join(next(f for f in report.findings if f["step"] == "7")["detail"])
    assert "FOLLOWED by another record, OR covered by a signed checkpoint" in step_7


def test_a_checkpoint_file_is_not_credited_by_a_verifier_that_cannot_check_it(tmp_path):
    """Presence is not verification. An old verifier must not pass a new file."""
    bundle = make_bundle(tmp_path)
    checkpoint = bundle / "audit_chain_checkpoint.json"
    checkpoint.write_text(json.dumps({"seq": 4131, "signature": "not checked by this version"}))

    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"].append(
        {
            "path": "audit_chain_checkpoint.json",
            "sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
            "bytes": checkpoint.stat().st_size,
            "what": "a checkpoint from a future build",
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    report = run(bundle)
    step_7c = next(f for f in report.findings if f["step"] == "7c")
    assert step_7c["status"] == verifier.NOT_RUN
    assert "does not yet know how to check it" in "\n".join(step_7c["detail"])
    assert report.integrity_verdict == verifier.INTEGRITY_INCOMPLETE


def test_provenance_is_carried_and_printed_before_any_pass(tmp_path):
    """No check in the procedure can tell demo data from a live assessment."""
    note = "DEMONSTRATION DATA: constructed offline, not a real client."
    bundle = make_bundle(tmp_path, provenance=note)
    assert json.loads((bundle / "MANIFEST.json").read_text())["provenance"] == note

    report = run(bundle)
    rendered = "\n".join(verifier.render_report(report, bundle))
    assert note in rendered
    assert rendered.index(note) < rendered.index("[   PASS]"), "provenance must precede the findings"

    # And a builder that says nothing gets a default that tells the reader to ask.
    silent = json.loads((make_bundle(tmp_path, name="silent") / "MANIFEST.json").read_text())
    assert "Not stated by the builder" in silent["provenance"]


def test_the_persisted_example_bundle_verifies_with_the_real_toolchain():
    """The bundle checked into scripts/bundle/example/, verified as shipped.

    Skips rather than fails without `bb`, matching the rest of this suite: a
    missing local toolchain must never look like a broken bundle. When bb IS
    present this is the only test in the repository that runs a real
    Barretenberg verification end to end through the auditor's own procedure.
    """
    example = REPO_ROOT / "scripts" / "bundle" / "example"
    if not example.is_dir():
        pytest.skip("no example bundle checked in")

    report = verifier.verify_bundle(example, bb_bin="bb")
    assert failures(report) == []
    assert report.outcome_verdict == "NOT SUITABLE"

    step_5 = next(f for f in report.findings if f["step"] == "5")
    if shutil.which("bb") is None:
        assert step_5["status"] == verifier.NOT_RUN
        assert report.integrity_verdict == verifier.INTEGRITY_INCOMPLETE
        pytest.skip("bb is not on PATH, so step 5 could not be exercised")

    assert step_5["status"] == verifier.PASS
    assert "Proof verified successfully" in "\n".join(step_5["detail"])
    assert report.integrity_verdict == verifier.INTEGRITY_VALID


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
