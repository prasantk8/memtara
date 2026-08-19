#!/usr/bin/env python3
"""Run the whole offline verification procedure and report TWO verdicts.

    python3 tools/verify_bundle.py .          # from inside a bundle
    python3 scripts/bundle/verify_bundle.py <bundle-dir>

This program opens no sockets. It does not merely avoid them: `--allow-network`
is off by default and, while it is off, `socket.connect` raises. If some future
edit adds a fetch, the test suite fails rather than an auditor silently
verifying a pack against whatever the network said that morning.

THE TWO VERDICTS ARE NEVER COMBINED
-----------------------------------
    EVIDENCE INTEGRITY   VALID / INVALID / INCOMPLETE
    DECISION OUTCOME     SUITABLE / NOT SUITABLE / NOT ASSESSED / UNREADABLE

They answer different questions. Integrity asks whether this pack is the bytes
that were sealed. Outcome asks what the circuit answered, and it is read from
public input 11 — never from an exit code. A valid proof of NOT SUITABLE has
perfect integrity and is a correctly formed rejection; a tool that printed one
"PASS" for both would report that decline as an approval.

Exit status encodes the integrity verdict only, because that is the one a
script can act on:

    0   integrity VALID       every applicable check ran and passed
    1   integrity INVALID     at least one check failed
    2   integrity INCOMPLETE  nothing failed, but some check could not be run

An INCOMPLETE bundle is not a passing bundle. It is a bundle that did not
carry enough to be checked, and the reasons are printed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

# Works both from inside a bundle (tools/ has the modules as flat siblings)
# and from a checkout (scripts/bundle/ is a package). The bundle copy is the
# one that matters; the checkout copy is what gets tested.
try:  # pragma: no cover - exercised by whichever layout is in use
    from scripts.bundle.evidence_ops import (
        BB_VERIFIER_TARGET,
        OUTCOME_INDEX,
        PUBLIC_INPUT_NAMES,
        canonical_bytes,
        outcome_from_public_inputs,
        pack_public_inputs,
        select_subject_proof,
        sha256_hex,
        verdict_words,
    )
    from scripts.bundle.jwks import verify_jwt_against_snapshot
    from scripts.bundle.structure import unsupported_keywords, validate
except ImportError:  # pragma: no cover - the in-bundle layout
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from evidence_ops import (  # type: ignore[no-redef]
        BB_VERIFIER_TARGET,
        OUTCOME_INDEX,
        PUBLIC_INPUT_NAMES,
        canonical_bytes,
        outcome_from_public_inputs,
        pack_public_inputs,
        select_subject_proof,
        sha256_hex,
        verdict_words,
    )
    from jwks import verify_jwt_against_snapshot  # type: ignore[no-redef]
    from structure import unsupported_keywords, validate  # type: ignore[no-redef]

PASS, FAIL, NOT_RUN, INFO = "PASS", "FAIL", "NOT RUN", "INFO"

INTEGRITY_VALID = "VALID"
INTEGRITY_INVALID = "INVALID"
INTEGRITY_INCOMPLETE = "INCOMPLETE"

MANIFEST_FILENAME = "MANIFEST.json"
MANIFEST_SIGNATURE_FILENAME = "MANIFEST.json.sig"

# Files that cannot appear in the manifest's own file list: the manifest
# cannot hash itself, and a signature over the manifest is written after it.
SELF_REFERENTIAL = {MANIFEST_FILENAME, MANIFEST_SIGNATURE_FILENAME}


class NetworkAttempted(RuntimeError):
    """A verification step tried to open a socket. That is a defect, not a warning."""


def install_network_guard() -> None:
    """Make an outbound connection impossible for the rest of this process.

    Enforced rather than promised. A verifier that only *intends* to be
    offline is one refactor away from fetching a key set, and the failure mode
    is silent: everything passes, on a machine that had network, for a pack
    that would have failed on the machine that mattered.
    """

    def refuse(*_args: Any, **_kwargs: Any):
        raise NetworkAttempted(
            "verify_bundle.py attempted a network connection. Offline verification must read "
            "the pinned files in the bundle and nothing else."
        )

    socket.socket.connect = refuse  # type: ignore[method-assign]
    socket.socket.connect_ex = refuse  # type: ignore[method-assign]
    socket.create_connection = refuse  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Report:
    """Every check, its status, and which verdict it bears on."""

    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.decision_outcome: bool | None = None
        self.outcome_readable = False

    def add(self, step: str, title: str, status: str, detail: list[str], *, integrity: bool = True) -> None:
        self.findings.append(
            {
                "step": step,
                "title": title,
                "status": status,
                "detail": detail,
                "bears_on_integrity": integrity and status in (PASS, FAIL, NOT_RUN),
            }
        )

    @property
    def integrity_verdict(self) -> str:
        relevant = [f for f in self.findings if f["bears_on_integrity"]]
        if any(f["status"] == FAIL for f in relevant):
            return INTEGRITY_INVALID
        if any(f["status"] == NOT_RUN for f in relevant):
            return INTEGRITY_INCOMPLETE
        return INTEGRITY_VALID

    @property
    def outcome_verdict(self) -> str:
        return verdict_words(self.decision_outcome) if self.outcome_readable else "UNREADABLE"


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def step_1_manifest(bundle: Path, report: Report) -> dict | None:
    title = "Every file is the file the manifest names"
    manifest_path = bundle / MANIFEST_FILENAME
    if not manifest_path.exists():
        report.add("1", title, FAIL, [f"no {MANIFEST_FILENAME} in {bundle}"])
        return None
    try:
        manifest = _load_json(manifest_path)
    except ValueError as exc:
        report.add("1", title, FAIL, [f"{MANIFEST_FILENAME} is not valid JSON: {exc}"])
        return None

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        report.add("1", title, FAIL, [f"{MANIFEST_FILENAME} lists no files"])
        return manifest

    detail: list[str] = []
    mismatched, missing = [], []
    for entry in entries:
        relative = entry.get("path")
        target = bundle / relative
        if not target.exists():
            missing.append(relative)
            continue
        actual = sha256_hex(target.read_bytes())
        if actual != entry.get("sha256"):
            mismatched.append(relative)
            detail.append(f"  {relative}")
            detail.append(f"    manifest {entry.get('sha256')}")
            detail.append(f"    on disk  {actual}")

    listed = {entry.get("path") for entry in entries}
    unlisted = sorted(
        str(p.relative_to(bundle))
        for p in bundle.rglob("*")
        if p.is_file() and str(p.relative_to(bundle)) not in listed
        and str(p.relative_to(bundle)) not in SELF_REFERENTIAL
        and "__pycache__" not in p.parts
    )

    if missing:
        detail.insert(0, f"{len(missing)} file(s) named by the manifest are not in the bundle:")
        detail[1:1] = [f"  {name}" for name in missing]
    if unlisted:
        detail.append(f"{len(unlisted)} file(s) present but not named by the manifest:")
        detail.extend(f"  {name}" for name in unlisted)

    if mismatched or missing or unlisted:
        detail.append(
            "A manifest mismatch is not a formatting problem. It means the bytes an auditor "
            "is reading are not the bytes that were sealed, and no later step's PASS can "
            "restore that."
        )
        report.add("1", title, FAIL, detail)
    else:
        report.add(
            "1",
            title,
            PASS,
            [f"{len(entries)} files, every SHA-256 as recorded, nothing unlisted"],
        )
    return manifest


def step_2_evidence_matches_the_seal(bundle: Path, manifest: dict | None, report: Report) -> dict | None:
    title = "The evidence record is the one the seal covers"
    evidence_path = bundle / "decision_evidence.json"
    seal_path = bundle / "case_file.pdf.seal.json"
    if not evidence_path.exists():
        report.add("2", title, FAIL, ["decision_evidence.json is missing"])
        return None

    raw = evidence_path.read_bytes()
    digest = sha256_hex(raw)
    detail = [f"sha256(decision_evidence.json)  {digest}"]

    try:
        pack = json.loads(raw)
    except ValueError as exc:
        report.add("2", title, FAIL, detail + [f"it is not valid JSON: {exc}"])
        return None

    # The file must already BE the canonical serialisation, not merely contain
    # the same data. If it were re-indented, `shasum` would not reproduce the
    # sealed digest and the first line of the procedure would not work.
    if canonical_bytes(pack) != raw:
        report.add(
            "2",
            title,
            FAIL,
            detail
            + [
                "the file is not in canonical form (sorted keys, no insignificant whitespace), "
                "so its digest cannot be compared with the seal's without re-serialising it"
            ],
        )
        return pack

    ok = True
    if seal_path.exists():
        try:
            seal = _load_json(seal_path)
        except ValueError as exc:
            detail.append(f"the seal is not valid JSON: {exc}")
            ok = False
            seal = {}
        sealed = seal.get("canonical_evidence_sha256")
        detail.append(f"seal.canonical_evidence_sha256  {sealed}")
        if sealed != digest:
            ok = False
            detail.append("the record and the seal are from different exports")
    else:
        ok = False
        detail.append("case_file.pdf.seal.json is missing, so there is nothing to compare against")

    if isinstance(manifest, dict) and manifest.get("canonical_evidence_sha256") not in (None, digest):
        ok = False
        detail.append(
            f"the manifest claims canonical_evidence_sha256 {manifest['canonical_evidence_sha256']}"
        )

    report.add("2", title, PASS if ok else FAIL, detail)
    return pack


def step_3_structure(bundle: Path, pack: dict | None, report: Report) -> None:
    title = "The record is structurally what it claims to be"
    schema_path = bundle / "evidence_schema" / "case_file_pack.v1.schema.json"
    if pack is None:
        report.add("3", title, NOT_RUN, ["there is no readable record to check"])
        return
    if not schema_path.exists():
        report.add("3", title, NOT_RUN, [f"no schema at {schema_path.relative_to(bundle)}"])
        return
    try:
        schema = _load_json(schema_path)
    except ValueError as exc:
        report.add("3", title, FAIL, [f"the schema is not valid JSON: {exc}"])
        return

    unsupported = unsupported_keywords(schema)
    errors = validate(pack, schema)
    detail = [
        f"schema {schema.get('x_schema_version', '(unversioned)')}, "
        f"{len(schema.get('required', []))} required top-level properties"
    ]
    if unsupported:
        # Said out loud. A validator that ignores a keyword it does not
        # implement will pass a document the schema rejects, and "schema: PASS"
        # gives the reader no way to know which keywords were consulted.
        detail.append(
            "keywords this validator does not enforce, so they were NOT checked: "
            + ", ".join(sorted(unsupported))
        )
    if errors:
        detail.extend(f"  {error}" for error in errors[:20])
        if len(errors) > 20:
            detail.append(f"  ... and {len(errors) - 20} more")
        report.add("3", title, FAIL, detail)
    else:
        report.add("3", title, PASS, detail)


def step_4_verification_key(bundle: Path, pack: dict | None, report: Report) -> None:
    title = "The verification key is the one the issuer published"
    vk_path = bundle / "vkey" / "wealth_suitability.vk"
    if not vk_path.exists():
        report.add("4", title, FAIL, ["vkey/wealth_suitability.vk is missing"])
        return

    actual = sha256_hex(vk_path.read_bytes())
    detail = [f"sha256(vkey/wealth_suitability.vk)  {actual}"]
    recorded = (pack or {}).get("verification_key", {}).get("sha256")
    detail.append(f"digest recorded in the evidence     {recorded}")

    vk_hash_path = bundle / "vkey" / "vk_hash"
    if vk_hash_path.exists():
        detail.append(
            "vkey/vk_hash is Barretenberg's own 32-byte commitment to the key "
            f"({vk_hash_path.read_bytes().hex()}). It is NOT a SHA-256 of the file and "
            "`sha256sum` will not reproduce it; only `bb write_vk` can."
        )

    if recorded and recorded != actual:
        detail.append(
            "the key in this bundle is not the key this assessment was checked against"
        )
        report.add("4", title, FAIL, detail)
    elif not recorded:
        report.add("4", title, NOT_RUN, detail + ["the record names no key digest to compare with"])
    else:
        report.add("4", title, PASS, detail)


def step_5_bb_verify(bundle: Path, pack: dict | None, report: Report, *, bb_bin: str = "bb") -> None:
    title = "The proof verifies against that key"
    proof_path = bundle / "proof" / "wealth_suitability.proof"
    inputs_path = bundle / "proof" / "public_inputs"
    vk_path = bundle / "vkey" / "wealth_suitability.vk"

    command = (
        f"{bb_bin} verify -i proof/public_inputs -p proof/wealth_suitability.proof "
        f"-k vkey/wealth_suitability.vk -t {BB_VERIFIER_TARGET}"
    )

    missing = [str(p.relative_to(bundle)) for p in (proof_path, inputs_path, vk_path) if not p.exists()]
    if missing:
        report.add(
            "5",
            title,
            NOT_RUN,
            [
                f"$ {command}",
                "not run: the bundle does not carry " + ", ".join(missing),
                "See `absent` in MANIFEST.json for why. This step being NOT RUN is not a "
                "failure of the proof; it means nobody has checked it here.",
            ],
        )
        return
    if shutil.which(bb_bin) is None:
        report.add(
            "5",
            title,
            NOT_RUN,
            [
                f"$ {command}",
                f"not run: `{bb_bin}` is not on PATH. Install the pinned version named in "
                "MANIFEST.json (pinned_dependencies.bb.install) and re-run.",
            ],
        )
        return

    proc = subprocess.run(
        [bb_bin, "verify", "-i", str(inputs_path), "-p", str(proof_path), "-k", str(vk_path),
         "-t", BB_VERIFIER_TARGET],
        cwd=str(bundle),
        capture_output=True,
        text=True,
        timeout=600,
    )
    detail = [f"$ {command}", f"exit code: {proc.returncode}"]
    for stream, text in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        if text.strip():
            detail.append(f"--- {stream} ---")
            detail.extend(f"  {line}" for line in text.strip().splitlines())
    detail.append(
        "Exit 0 means the proof was correctly constructed against this key. It does NOT mean "
        f"the client passed: the answer is public input {OUTCOME_INDEX}, reported separately "
        "in step 6."
    )
    report.add("5", title, PASS if proc.returncode == 0 else FAIL, detail)


def step_6_read_the_decision(bundle: Path, pack: dict | None, report: Report) -> None:
    """The outcome. Deliberately bears on no integrity verdict at all."""
    title = f"The decision, read from public input {OUTCOME_INDEX}"
    inputs_path = bundle / "proof" / "public_inputs"

    proof = select_subject_proof(pack or {})
    if proof is None:
        # NOT ASSESSED, not UNREADABLE. "No proof exists" is a determinate fact
        # about the firm's conduct and the bundle can state it confidently;
        # UNREADABLE is reserved for a proof whose verdict position cannot be
        # parsed, which is a defect rather than a finding.
        report.decision_outcome = None
        report.outcome_readable = True
        report.add(
            "6",
            title,
            INFO,
            [
                "No proof was submitted against this assessment, so there is no verdict to "
                "read. That is a different fact from a decline and must not be read as one: "
                "nobody said no, nobody said anything. Any recommendation made on this "
                "instrument to this client was made outside the assessed channel."
            ],
            integrity=False,
        )
        return

    values = list(proof.get("public_inputs") or [])
    detail = []
    for index, value in enumerate(values):
        name = PUBLIC_INPUT_NAMES[index] if index < len(PUBLIC_INPUT_NAMES) else "UNNAMED — layout drifted"
        marker = "  <-- the answer" if index == OUTCOME_INDEX else ""
        detail.append(f"  {index:>2}  {name:<26}  {value}{marker}")

    outcome = outcome_from_public_inputs(values)
    report.decision_outcome = outcome
    report.outcome_readable = len(values) > OUTCOME_INDEX and outcome is not None

    claimed = (pack or {}).get("outcome", {}).get("suitable")
    read_from = (pack or {}).get("outcome", {}).get("read_from")
    detail.append(f"read from the proof's public inputs   {verdict_words(outcome)}")
    detail.append(f"stated by the evidence record         {verdict_words(claimed)}")
    if read_from:
        detail.append(f"the record says it was read from      {read_from}")
        if f"input {OUTCOME_INDEX}" not in str(read_from):
            detail.append(
                f"WARNING: this verifier reads index {OUTCOME_INDEX} and the record names a "
                "different position. The circuit layout has changed; treat the names above as "
                "unverified."
            )
    report.add("6", title, INFO, detail, integrity=False)

    # The cross-check IS an integrity matter: the rendered record and the
    # cryptographic material must agree about what was decided.
    if claimed != outcome:
        report.add(
            "6b",
            "The record and the proof agree about what was decided",
            FAIL,
            [
                f"the record says {verdict_words(claimed)}; public input {OUTCOME_INDEX} says "
                f"{verdict_words(outcome)}"
            ],
        )
    else:
        report.add(
            "6b",
            "The record and the proof agree about what was decided",
            PASS,
            [f"both say {verdict_words(outcome)}"],
        )

    # And the packed file must be the one the record implies, or an auditor
    # running step 5 by hand would be verifying inputs nobody can trace.
    if inputs_path.exists():
        try:
            expected = pack_public_inputs(values)
        except ValueError as exc:
            report.add("6c", "proof/public_inputs was rebuilt from the record", FAIL, [str(exc)])
            return
        actual = inputs_path.read_bytes()
        if actual == expected:
            report.add(
                "6c",
                "proof/public_inputs was rebuilt from the record",
                PASS,
                [
                    f"{len(actual)} bytes = {len(values)} field elements x 32, big-endian, "
                    "identical to the values in decision_evidence.json"
                ],
            )
        else:
            report.add(
                "6c",
                "proof/public_inputs was rebuilt from the record",
                FAIL,
                [
                    f"the packed file is {len(actual)} bytes and the record implies "
                    f"{len(expected)}; they are not the same inputs"
                ],
            )


def step_7_audit_chains(bundle: Path, pack: dict | None, report: Report) -> None:
    title = "The audit chain segment"
    segment_path = bundle / "audit_chain_segment.jsonl"
    detail: list[str] = []
    status = PASS

    if not segment_path.exists():
        report.add("7", title, NOT_RUN, ["audit_chain_segment.jsonl is missing"])
    else:
        events = []
        for number, line in enumerate(segment_path.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                status = FAIL
                detail.append(f"line {number} is not valid JSON")
        detail.insert(0, f"{len(events)} event(s) from Memtara's global hash chain")

        # The excerpt must match the record it was extracted from. That is the
        # only thing about it this bundle can prove on its own, and saying so
        # plainly is more use to an auditor than a check that looks stronger.
        if isinstance(pack, dict) and pack.get("audit_chain_excerpt") is not None:
            if events != pack["audit_chain_excerpt"]:
                status = FAIL
                detail.append(
                    "the segment does not match audit_chain_excerpt in decision_evidence.json"
                )
            else:
                detail.append("identical to audit_chain_excerpt in decision_evidence.json")

        adjacent = 0
        for previous, current in zip(events, events[1:]):
            if isinstance(previous.get("seq"), int) and current.get("seq") == previous["seq"] + 1:
                adjacent += 1
                if current.get("prev_hash") != previous.get("event_hash"):
                    status = FAIL
                    detail.append(
                        f"seq {current.get('seq')} follows seq {previous.get('seq')} but its "
                        "prev_hash does not match that event's hash — the chain is broken here"
                    )
        detail.append(
            f"{adjacent} of {max(len(events) - 1, 0)} adjacent pair(s) had consecutive seq and "
            "could be linked here"
        )
        detail.append(
            "WHAT THIS CANNOT SHOW: Memtara's chain is global across tenants, so this "
            "assessment's events are normally NOT adjacent — their prev_hash values point at "
            "rows belonging to other firms, which are not in this bundle and must not be. And "
            "`audit_log` stores no payload column: event_hash commits to a payload the row "
            "does not contain, so no recomputation from this file is possible at all. This "
            "segment's integrity rests on step 1 and step 2, not on itself."
        )
        report.add("7", title, status, detail)

    step_7b_aihoots(bundle, report)


def step_7b_aihoots(bundle: Path, report: Report) -> None:
    title = "The relying party's AIHOOTS chain, checked by AIHOOTS's own verifier"
    chain_path = bundle / "aihoots_audit_chain.jsonl"
    vendored = bundle / "tools" / "aihoots_reference"
    cli = vendored / "src" / "verifier" / "cli.py"

    if not chain_path.exists():
        report.add("7b", title, NOT_RUN, ["no aihoots_audit_chain.jsonl in this bundle"])
        return
    if not cli.exists():
        report.add(
            "7b",
            title,
            NOT_RUN,
            [
                f"the vendored verifier is not at {cli.relative_to(bundle)}. This bundle does "
                "not reimplement it: a second hash-chain walker that agreed would prove "
                "nothing, and one that disagreed would be indistinguishable from a bug."
            ],
        )
        return

    proc = subprocess.run(
        [sys.executable, "-m", "src.verifier.cli", str(chain_path.resolve())],
        cwd=str(vendored),
        capture_output=True,
        text=True,
        timeout=300,
    )
    detail = [f"$ python3 -m src.verifier.cli {chain_path.name}", f"exit code: {proc.returncode}"]
    for stream, text in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        if text.strip():
            detail.append(f"--- {stream} ---")
            detail.extend(f"  {line}" for line in text.strip().splitlines())
    detail.append(
        "Exit 0 means every record's stored hash matches its recomputed contents and every "
        "prev_hash matches its predecessor. It means the log is internally consistent; it does "
        "not mean the log is complete. A hash chain proves nothing was altered, not that "
        "nothing was deleted from the end or never written."
    )
    report.add("7b", title, PASS if proc.returncode == 0 else FAIL, detail)


def step_8_token(bundle: Path, pack: dict | None, report: Report) -> None:
    title = "The issuance token, against the pinned key set"
    snapshot_path = bundle / "jwks_snapshot.json"
    token_record = (pack or {}).get("proof_token") or {}

    if not token_record.get("supplied"):
        report.add(
            "8",
            title,
            NOT_RUN,
            [
                "the record carries no proof token. The server does not retain it — it is a "
                "bearer credential and the audit chain is a commitment, not a secret store — "
                "so it can only be in this bundle if the firm kept it and supplied it at "
                "export time. Without it, the strongest independently checkable artefact here "
                "is the proof itself (steps 4 and 5)."
            ],
        )
        return
    if not snapshot_path.exists():
        report.add(
            "8",
            title,
            NOT_RUN,
            [
                "there is a token but no jwks_snapshot.json to check it against. This bundle "
                "was built without capturing the issuer's key set; see `absent` in "
                "MANIFEST.json. Fetching one now would evidence today's DNS, not the issuance."
            ],
        )
        return

    try:
        snapshot = _load_json(snapshot_path)
    except ValueError as exc:
        report.add("8", title, FAIL, [f"jwks_snapshot.json is not valid JSON: {exc}"])
        return

    finding = verify_jwt_against_snapshot(token_record.get("token", ""), snapshot)
    detail = [
        f"key set captured  {snapshot.get('fetched_at')} from {snapshot.get('source_url')}",
        "  (that URL is provenance. This program did not open it, and cannot: see the "
        "network guard at the top of this file.)",
        f"token kid         {finding['kid']}",
        f"pinned thumbprint {finding['thumbprint_rfc7638']}",
    ]
    if finding.get("thumbprint_matches_kid") is False:
        detail.append("the pinned key's RFC 7638 thumbprint does not equal its kid")
    if finding.get("expires_at"):
        detail.append(
            f"token expired at  {finding['expires_at']}"
            + ("  (expected: these live minutes, not years)" if finding.get("expired") else "")
        )

    if finding["signature_valid"] is True:
        detail.append(
            "The EdDSA signature verifies. WHAT THIS DOES NOT PROVE: that this key set was the "
            "issuer's. The firm captured it. It proves the token and the pinned key agree, "
            "which becomes an origin check once the thumbprint above is compared with one "
            "obtained independently of this bundle."
        )
        report.add("8", title, PASS, detail)
    elif finding["signature_valid"] is False:
        report.add("8", title, FAIL, detail + [str(finding.get("reason"))])
    else:
        report.add("8", title, NOT_RUN, detail + [str(finding.get("reason"))])


def step_9_origin(bundle: Path, report: Report, *, expected_public_key: str | None = None) -> None:
    title = "Who produced this bundle"
    seal_path = bundle / "case_file.pdf.seal.json"
    pdf_path = bundle / "case_file.pdf"
    signature_path = bundle / MANIFEST_SIGNATURE_FILENAME
    detail: list[str] = []
    status = PASS

    # The PDF's own digest first: the seal covers the paper, and the paper is
    # what gets printed and passed around.
    if seal_path.exists() and pdf_path.exists():
        try:
            seal = _load_json(seal_path)
        except ValueError as exc:
            status = FAIL
            seal = {}
            detail.append(f"the seal is not valid JSON: {exc}")
        recorded = (seal.get("pdf") or {}).get("sha256")
        actual = sha256_hex(pdf_path.read_bytes())
        detail.append(f"sha256(case_file.pdf)  {actual}")
        if recorded != actual:
            status = FAIL
            detail.append(f"the seal records {recorded}: this is not the sealed document")

        if seal.get("signature") is None:
            detail.append(
                "THE SEAL IS NOT A SIGNATURE. It is a hash commitment: it detects any change "
                "to these bytes and establishes nothing about who made them. `signature` is "
                "null because no signing key was supplied, and the exporter refuses to "
                "generate one — a signature verifying against a key nobody holds looks like a "
                "signature that means something. Origin evidence in this pack comes from step "
                "8's token, if there is one, and otherwise from nowhere."
            )
        else:
            ok, lines = _check_detached_signature(
                seal["signature"], pdf_path.read_bytes(), expected_public_key
            )
            status = status if ok else FAIL
            detail.extend(lines)
    else:
        status = FAIL
        detail.append("the PDF or its seal is missing")

    if signature_path.exists():
        try:
            manifest_signature = _load_json(signature_path)
        except ValueError as exc:
            status = FAIL
            detail.append(f"{MANIFEST_SIGNATURE_FILENAME} is not valid JSON: {exc}")
        else:
            ok, lines = _check_detached_signature(
                manifest_signature,
                (bundle / MANIFEST_FILENAME).read_bytes(),
                expected_public_key,
                what=MANIFEST_FILENAME,
            )
            status = status if ok else FAIL
            detail.extend(lines)
    else:
        detail.append(
            f"{MANIFEST_SIGNATURE_FILENAME} is absent, so MANIFEST.json is unauthenticated. "
            "Every hash in it is only as trustworthy as the copy of the manifest you are "
            "holding: anyone who can rewrite the bundle can rewrite the manifest to match."
        )
        if expected_public_key:
            status = FAIL
            detail.append("a public key was expected but this bundle carries no manifest signature")

    report.add("9", title, status, detail)


def _check_detached_signature(
    signature: Any, payload: bytes, expected_public_key: str | None, what: str = "case_file.pdf"
) -> tuple[bool, list[str]]:
    lines: list[str] = []
    if not isinstance(signature, dict):
        return False, [f"the signature over {what} is not an object"]
    if signature.get("algorithm") != "Ed25519":
        return False, [f"unsupported signature algorithm {signature.get('algorithm')!r} over {what}"]
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover
        return False, ["the `cryptography` package is not installed, so signatures cannot be checked"]
    try:
        public_bytes = bytes.fromhex(signature.get("public_key_hex", ""))
        signature_bytes = bytes.fromhex(signature.get("signature_hex", ""))
    except ValueError:
        return False, [f"the signature over {what} is not valid hex"]

    if expected_public_key and public_bytes.hex() != expected_public_key.strip().lower():
        return False, [
            f"{what} was signed by a different key than the one expected",
            f"  expected {expected_public_key.strip().lower()}",
            f"  signed   {public_bytes.hex()}",
        ]
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, payload)
    except (InvalidSignature, ValueError) as exc:
        return False, [f"the Ed25519 signature over {what} does not verify ({exc})"]

    lines.append(f"Ed25519 signature over {what} verifies, key {public_bytes.hex()}")
    if expected_public_key:
        lines.append("and that key is the one that was expected, supplied from outside this bundle")
    else:
        lines.append(
            "verified against the key inside the bundle itself: this shows the two files agree, "
            "not who made them. Pass --expected-public-key to check authorship."
        )
    return True, lines


# ---------------------------------------------------------------------------
# Orchestration and output
# ---------------------------------------------------------------------------


def verify_bundle(
    bundle: Path, *, expected_public_key: str | None = None, bb_bin: str = "bb"
) -> Report:
    bundle = Path(bundle)
    report = Report()
    manifest = step_1_manifest(bundle, report)
    pack = step_2_evidence_matches_the_seal(bundle, manifest, report)
    step_3_structure(bundle, pack, report)
    step_4_verification_key(bundle, pack, report)
    step_5_bb_verify(bundle, pack, report, bb_bin=bb_bin)
    step_6_read_the_decision(bundle, pack, report)
    step_7_audit_chains(bundle, pack, report)
    step_8_token(bundle, pack, report)
    step_9_origin(bundle, report, expected_public_key=expected_public_key)
    return report


def render_report(report: Report, bundle: Path) -> list[str]:
    lines = [
        "=" * 78,
        f"OFFLINE VERIFICATION — {bundle}",
        "=" * 78,
        "",
    ]
    for finding in report.findings:
        lines.append(f"[{finding['status']:>7}]  step {finding['step']}. {finding['title']}")
        lines.extend(f"           {line}" for line in finding["detail"])
        lines.append("")

    integrity = report.integrity_verdict
    lines.extend(
        [
            "=" * 78,
            "TWO VERDICTS. They answer different questions and are never combined.",
            "=" * 78,
            "",
            f"  EVIDENCE INTEGRITY   {integrity}",
            "      Is this pack the bytes that were sealed?",
            "",
            f"  DECISION OUTCOME     {report.outcome_verdict}",
            f"      What did the circuit answer? Read from public input {OUTCOME_INDEX}.",
            "",
        ]
    )
    if integrity == INTEGRITY_INCOMPLETE:
        lines.append(
            "  INCOMPLETE is not a pass. Nothing failed, but the checks marked NOT RUN above"
        )
        lines.append("  were not performed, and nobody should record them as though they were.")
        lines.append("")
    if report.outcome_verdict == "NOT SUITABLE":
        # Worded against the integrity verdict actually reached. Telling a
        # reader a decline is "correctly evidenced" under an INCOMPLETE or
        # INVALID integrity finding would be the same overclaim this whole
        # program exists to avoid, one line further down the page.
        if integrity == INTEGRITY_VALID:
            lines.append(
                "  NOT SUITABLE with VALID integrity is a correctly evidenced decline. It is not"
            )
            lines.append("  a failure of this pack, and it is not an approval.")
        else:
            lines.append(
                f"  The decision was a decline. Integrity is {integrity}, so how much weight that"
            )
            lines.append(
                "  decline can carry depends on the findings above — but it is still not an"
            )
            lines.append("  approval, whatever the integrity verdict turns out to be.")
        lines.append("")
    lines.append(
        "  Integrity says nothing about whether the decision was right, and the outcome says"
    )
    lines.append("  nothing about whether these files are authentic. Record both.")
    return lines


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_bundle.py",
        description="Verify a Memtara evidence bundle offline. Prints two verdicts, separately.",
    )
    default = Path(__file__).resolve().parent.parent if Path(__file__).resolve().parent.name == "tools" else Path(".")
    parser.add_argument("bundle", nargs="?", type=Path, default=default, help="the bundle directory")
    parser.add_argument(
        "--expected-public-key",
        help="Ed25519 public key hex obtained from OUTSIDE this bundle. Supply it and the "
        "signature checks become checks of authorship rather than of internal consistency.",
    )
    parser.add_argument("--bb", default="bb", help="path to the bb binary (default: bb on PATH)")
    parser.add_argument("--json", action="store_true", help="machine-readable findings")
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="disable the socket guard. No verification step needs this; it exists so that "
        "turning it on has to be a deliberate act that appears in a shell history.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.allow_network:
        install_network_guard()

    bundle = Path(args.bundle)
    if not bundle.is_dir():
        print(f"verify_bundle: {bundle} is not a directory", file=sys.stderr)
        return 1

    report = verify_bundle(bundle, expected_public_key=args.expected_public_key, bb_bin=args.bb)

    if args.json:
        print(
            json.dumps(
                {
                    "bundle": str(bundle),
                    "evidence_integrity": report.integrity_verdict,
                    "decision_outcome": report.outcome_verdict,
                    "findings": report.findings,
                },
                indent=2,
            )
        )
    else:
        for line in render_report(report, bundle):
            print(line)

    return {INTEGRITY_VALID: 0, INTEGRITY_INVALID: 1, INTEGRITY_INCOMPLETE: 2}[report.integrity_verdict]


if __name__ == "__main__":
    raise SystemExit(main())
