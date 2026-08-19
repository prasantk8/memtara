#!/usr/bin/env python3
"""Assemble the offline verification bundle for one decision.

Run this where the evidence lives. It may call the Memtara API, read the
firm's exported database rows and fetch the issuer's JWKS over the network —
producing new evidence legitimately requires the system that produced the
decision to still exist. What comes out the other end must not need any of
that ever again.

    scripts/bundle/build_bundle.py \\
        --request-id <uuid> --org-api-key <key> --output ./bundle-<uuid>

    scripts/bundle/build_bundle.py \\
        --evidence-json ./evidence.json --jwks-file ./jwks.json \\
        --proof-file ./wealth_suitability.proof --output ./bundle

The second form exists because the first one cannot be regression-tested and
cannot be re-run in five years. Everything after the network call takes plain
files.

WHAT THIS TOOL WILL NOT DO
--------------------------
It will not write a file it could not verify. The proof bytes are checked
against the `proof_sha256` the server recorded before they are copied in; a
mismatch stops the build rather than producing a bundle whose own manifest
disagrees with its own evidence.

It will not invent a JWKS. Without `--base-url` or `--jwks-file` the bundle
is built with `jwks_snapshot.json` absent and the manifest says so in
`absent`, so a reader learns the token cannot be checked here rather than
finding a key set that came from nowhere.

It will not generate a signing key. `--signing-key` signs MANIFEST.json with
a key the firm controls; without one the bundle is tamper-evident and
unauthenticated, and `VERIFY.md` step 7 says exactly that. An ephemeral
signature verifies against a key nobody holds and looks like one that means
something — the same reasoning `export_audit_evidence.py` applies to its own
seal.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.bundle import BUNDLE_FORMAT_VERSION, MANIFEST_FILENAME, MANIFEST_SIGNATURE_FILENAME
from scripts.bundle.evidence_ops import (
    BB_VERIFIER_TARGET,
    OUTCOME_INDEX,
    canonical_bytes,
    outcome_from_public_inputs,
    pack_public_inputs,
    select_subject_proof,
    sha256_hex,
    verdict_words,
)
from scripts.bundle.jwks import fetch_jwks, jwks_url, snapshot_from_jwks
from scripts.export_audit_evidence import (
    ExportError,
    build_pack,
    collect_aihoots,
    decode_proof_token,
    load_signing_key,
    pack_proof_hashes,
    read_proof_token_argument,
    render_and_seal,
)

BUILDER_NAME = "scripts/bundle/build_bundle.py"

DEFAULT_VKEY_DIR = REPO_ROOT / "circuits" / "wealth_suitability" / "vkey"
SCHEMA_SOURCE = Path(__file__).resolve().parent / "schema" / "case_file_pack.v1.schema.json"
VERIFY_DOC_SOURCE = REPO_ROOT / "docs" / "VERIFY.md"
AIHOOTS_SOURCE = REPO_ROOT / "tests" / "aihoots_reference"

# The AIHOOTS files `audit-verify` actually needs. Its CLI imports exactly one
# module (`src.gateway.audit.chain`), and that module imports only the standard
# library — so the vendored copy is four small files and no dependency tree,
# rather than a 192 KB checkout of a gateway the auditor will never run.
AIHOOTS_VENDORED_FILES = [
    "src/__init__.py",
    "src/verifier/__init__.py",
    "src/verifier/cli.py",
    "src/gateway/__init__.py",
    "src/gateway/audit/__init__.py",
    "src/gateway/audit/chain.py",
]

# Copied into every bundle so the procedure can be run with nothing but the
# bundle and a Python interpreter.
TOOL_MODULES = ["verify_bundle.py", "jwks.py", "structure.py", "evidence_ops.py"]

# Pinned from .github/workflows/ci.yml, which is the version the committed
# vkey was regenerated and diffed against. A bundle that named a bb version
# other than the one CI checks the key with would be pinning the wrong thing.
DEFAULT_BB_VERSION = "5.1.0"
BB_INSTALL = (
    "curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/"
    "barretenberg/bbup/install | bash && ~/.bb/bbup -v {version}"
)


class BuildError(Exception):
    """Anything that should stop the build rather than produce a partial bundle."""


# ---------------------------------------------------------------------------
# Pinned dependency identifiers
# ---------------------------------------------------------------------------


def resolve_aihoots_commit(root: Path = AIHOOTS_SOURCE) -> str | None:
    """The exact commit of the reference verifier, from git, or None.

    Recorded rather than assumed. `.gitmodules` names a URL; only the checked
    out commit says which code produced the verdict quoted in the case file.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = proc.stdout.strip()
    return commit if proc.returncode == 0 and len(commit) == 40 else None


def detect_bb_version(bb_bin: str = "bb") -> str | None:
    """`bb --version`, or None if it is not installed here.

    None is a fact worth recording: it means the bundle was assembled on a
    machine that could not itself have run step 4, so nobody should read the
    bundle's existence as evidence that step 4 passed.
    """
    if shutil.which(bb_bin) is None:
        return None
    try:
        proc = subprocess.run([bb_bin, "--version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() or proc.stderr.strip() or None


def pinned_dependencies(*, bb_version_pin: str, bb_observed: str | None, aihoots_commit: str | None,
                        aihoots_vendored: bool) -> dict:
    return {
        "bb": {
            "name": "Barretenberg (bb)",
            "pinned_version": bb_version_pin,
            "observed_on_the_build_machine": bb_observed,
            "vendored": False,
            "why_not_vendored": (
                "bb is a platform-specific binary from a public, open-source project that is "
                "not Memtara's. Shipping one architecture's build would make the bundle "
                "unusable on every other, and shipping a binary an auditor cannot rebuild "
                "would replace trust in Memtara with trust in whatever this tool copied."
            ),
            "install": BB_INSTALL.format(version=bb_version_pin),
            "verifier_target": BB_VERIFIER_TARGET,
            "why_the_target_matters": (
                "-t noir-recursive selects the poseidon2 transcript and the ZK-preserving "
                "proving target. A key written with a different target verifies nothing this "
                "system produces."
            ),
        },
        "aihoots_reference_verifier": {
            "name": "AIHOOTS audit-verify",
            "source": "https://github.com/prasantk8/aihoots-e1-audit-gateway.git",
            "pinned_commit": aihoots_commit,
            "vendored": aihoots_vendored,
            "vendored_path": "tools/aihoots_reference" if aihoots_vendored else None,
            "entrypoint": "python3 -m src.verifier.cli <audit_chain.jsonl>",
            "note": (
                "Vendored so the chain cross-check needs no git, no network and no submodule "
                "checkout. It is AIHOOTS's own code at the commit named above, not a "
                "reimplementation: a second hash-chain walker that agreed with the first "
                "would prove nothing, and one that disagreed would be indistinguishable from "
                "a bug."
            ),
        },
        "python": {
            "minimum": "3.9",
            "third_party_packages_required_by_the_verifier": ["cryptography (step 5 only)"],
            "note": (
                "Steps 1-4 and 6 run on a bare interpreter. Only the EdDSA check in step 5 "
                "needs `cryptography`; without it that step reports NOT RUN rather than PASS."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _jsonl(records: list[dict]) -> bytes:
    """One canonical JSON object per line. Sorted keys, so a diff is a real diff."""
    return b"".join(canonical_bytes(record) + b"\n" for record in records)


def build_bundle(
    pack: dict,
    output_dir: Path,
    *,
    pdf_path: Path,
    seal_path: Path,
    jwks_snapshot: dict | None = None,
    vkey_dir: Path = DEFAULT_VKEY_DIR,
    proof_path: Path | None = None,
    aihoots_audit_path: Path | None = None,
    vendor_aihoots: bool = True,
    bb_version_pin: str = DEFAULT_BB_VERSION,
    signing_key: Any = None,
    created_at: datetime | None = None,
) -> dict:
    """Write the bundle and return a summary. Raises BuildError on anything unverifiable."""
    moment = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files: list[dict] = []
    absent: list[dict] = []

    def record(relative: str, data: bytes, what: str) -> None:
        _write(output_dir / relative, data)
        files.append(
            {"path": relative, "sha256": sha256_hex(data), "bytes": len(data), "what": what}
        )

    # --- the evidence itself -------------------------------------------------
    # Written as the canonical bytes, not as pretty-printed JSON. `shasum -a 256
    # decision_evidence.json` must reproduce the seal's canonical_evidence_sha256
    # directly; a re-indented copy would force the auditor to re-canonicalise by
    # hand before the first step of the procedure could be run.
    evidence_bytes = canonical_bytes(pack)
    canonical_sha256 = sha256_hex(evidence_bytes)
    record(
        "decision_evidence.json",
        evidence_bytes,
        "The decision record, canonical form. Its SHA-256 is the seal's canonical_evidence_sha256.",
    )

    if not SCHEMA_SOURCE.exists():  # pragma: no cover - shipped with this file
        raise BuildError(f"the pack schema is missing at {SCHEMA_SOURCE}")
    record(
        "evidence_schema/case_file_pack.v1.schema.json",
        SCHEMA_SOURCE.read_bytes(),
        "The structure decision_evidence.json is asserted to have.",
    )

    # --- proof and public inputs --------------------------------------------
    subject_proof = select_subject_proof(pack)
    if subject_proof is None:
        absent.append(
            {
                "path": "proof/",
                "reason": (
                    "No proof was ever submitted against this assessment. The request was "
                    "opened and the terms registered, but no proof exists to ship. This is a "
                    "materially different fact from a decline and the bundle does not present "
                    "it as one."
                ),
            }
        )
        public_inputs: list[str] = []
    else:
        public_inputs = list(subject_proof.get("public_inputs") or [])
        try:
            packed = pack_public_inputs(public_inputs)
        except ValueError as exc:
            raise BuildError(f"cannot rebuild the public-inputs file: {exc}") from exc
        record(
            "proof/public_inputs",
            packed,
            (
                f"{len(public_inputs)} field elements, 32 bytes each, big-endian, in circuit "
                "order. Rebuilt from decision_evidence.json, so it is checkable rather than "
                "merely supplied."
            ),
        )

        if proof_path is not None:
            proof_bytes = Path(proof_path).read_bytes()
            expected = subject_proof.get("proof_sha256")
            actual = sha256_hex(proof_bytes)
            if expected and expected != actual:
                raise BuildError(
                    f"--proof-file {proof_path} hashes to {actual}, but the evidence record "
                    f"says this assessment's proof is {expected}. Refusing to build a bundle "
                    "whose manifest would disagree with its own evidence."
                )
            record(
                "proof/wealth_suitability.proof",
                proof_bytes,
                "The proof bytes, SHA-256-matched against proof_sha256 in the evidence record.",
            )
        else:
            absent.append(
                {
                    "path": "proof/wealth_suitability.proof",
                    "reason": (
                        "Not supplied to the builder. The evidence endpoint returns the proof's "
                        "LENGTH and its SHA-256, not the proof bytes (wealth/evidence.rs records "
                        "`proof_bytes: p.proof_bytes.len()`), so the bytes can only come from "
                        "the firm's own records. Without them step 4 cannot be run and the "
                        "verifier reports it NOT RUN rather than PASS."
                    ),
                    "expected_sha256": subject_proof.get("proof_sha256"),
                }
            )

    # --- verification key ----------------------------------------------------
    vkey_dir = Path(vkey_dir)
    vk_file = vkey_dir / "vk"
    vk_hash_file = vkey_dir / "vk_hash"
    if not vk_file.exists():
        raise BuildError(
            f"no verification key at {vk_file}. This is the one key in the repository that is "
            "committed rather than generated at boot, precisely so it can be shipped here."
        )
    vk_bytes = vk_file.read_bytes()
    record(
        "vkey/wealth_suitability.vk",
        vk_bytes,
        "The committed, CI-pinned verification key for wealth_suitability.",
    )
    if vk_hash_file.exists():
        record(
            "vkey/vk_hash",
            vk_hash_file.read_bytes(),
            (
                "Barretenberg's own 32-byte commitment to the key, as `bb write_vk` emitted it. "
                "This is NOT the SHA-256 of the vk file and `sha256sum` will not reproduce it."
            ),
        )

    # --- the exported database rows -----------------------------------------
    # Written out as static files so verification never needs the API to be up.
    # What they can and cannot prove is stated in VERIFY.md step 6, not here.
    record(
        "audit_chain_segment.jsonl",
        _jsonl(pack.get("audit_chain_excerpt") or []),
        (
            "This assessment's events from Memtara's global hash chain, exported. `seq` values "
            "are not consecutive by design: the chain interleaves every tenant."
        ),
    )
    record(
        "institution_and_thresholds.json",
        canonical_bytes(
            {
                "organisation": pack.get("organisation"),
                "product": pack.get("product"),
                "terms_assessed_against": pack.get("terms_assessed_against"),
                "window": pack.get("window"),
                "nonce": pack.get("nonce"),
                "note": (
                    "Extracted verbatim from decision_evidence.json so these rows can be read "
                    "without parsing the whole record. They are a copy, not a second source: "
                    "the verifier checks them against decision_evidence.json and a divergence "
                    "is a finding."
                ),
            }
        ),
        "The institution metadata and the thresholds this assessment was measured against.",
    )

    if aihoots_audit_path is not None:
        aihoots_path = Path(aihoots_audit_path)
        if not aihoots_path.exists():
            raise BuildError(f"--aihoots-audit: no such file: {aihoots_path}")
        record(
            "aihoots_audit_chain.jsonl",
            aihoots_path.read_bytes(),
            (
                "The relying party's own AIHOOTS chain. Unlike the Memtara segment this one is "
                "fully recomputable offline, which is why the vendored audit-verify can give a "
                "verdict on it."
            ),
        )
    else:
        absent.append(
            {
                "path": "aihoots_audit_chain.jsonl",
                "reason": (
                    "No relying-party audit log was supplied. Nothing about the proof, the "
                    "verdict or the seal depends on it; the independent second record of what "
                    "the firm's model was told does."
                ),
            }
        )

    # --- the pinned key set --------------------------------------------------
    if jwks_snapshot is not None:
        record(
            "jwks_snapshot.json",
            canonical_bytes(jwks_snapshot),
            (
                "The issuer's key set as captured at export time, pinned by kid and RFC 7638 "
                "thumbprint. The verifier reads this file and never the network."
            ),
        )
    else:
        absent.append(
            {
                "path": "jwks_snapshot.json",
                "reason": (
                    "No key set was captured: the builder was given neither --base-url nor "
                    "--jwks-file. Step 5 cannot be run, and a bundle with no snapshot is "
                    "honest about that rather than pointing the reader at a live URL that may "
                    "not answer when it matters."
                ),
            }
        )

    # --- the human-readable rendering and its seal ---------------------------
    pdf_path, seal_path = Path(pdf_path), Path(seal_path)
    if not pdf_path.exists():
        raise BuildError(f"no case file PDF at {pdf_path}")
    if not seal_path.exists():
        raise BuildError(f"no seal at {seal_path}")
    record("case_file.pdf", pdf_path.read_bytes(), "The human-readable rendering of this record.")
    seal_bytes = seal_path.read_bytes()
    record("case_file.pdf.seal.json", seal_bytes, "The digest seal over the PDF and the evidence.")

    try:
        seal = json.loads(seal_bytes)
    except ValueError as exc:
        raise BuildError(f"{seal_path} is not valid JSON: {exc}") from exc
    if seal.get("canonical_evidence_sha256") != canonical_sha256:
        raise BuildError(
            "the seal's canonical_evidence_sha256 does not match the evidence being bundled "
            f"({seal.get('canonical_evidence_sha256')} vs {canonical_sha256}). The PDF and the "
            "record are from different exports."
        )

    # --- the procedure and the tools to run it -------------------------------
    if not VERIFY_DOC_SOURCE.exists():  # pragma: no cover - shipped with this repo
        raise BuildError(f"docs/VERIFY.md is missing at {VERIFY_DOC_SOURCE}")
    record("VERIFY.md", VERIFY_DOC_SOURCE.read_bytes(), "The procedure. Read this first.")

    package_dir = Path(__file__).resolve().parent
    for module in TOOL_MODULES:
        record(
            f"tools/{module}",
            (package_dir / module).read_bytes(),
            "The offline verifier, shipped so the bundle can be checked without this repository.",
        )

    aihoots_commit = resolve_aihoots_commit()
    vendored = False
    if vendor_aihoots:
        missing = [name for name in AIHOOTS_VENDORED_FILES if not (AIHOOTS_SOURCE / name).exists()]
        if missing:
            absent.append(
                {
                    "path": "tools/aihoots_reference/",
                    "reason": (
                        "The reference verifier could not be vendored: the submodule is not "
                        f"checked out (missing {', '.join(missing)}). Run "
                        "`git submodule update --init` and rebuild. Until then the chain "
                        "cross-check is unavailable inside this bundle."
                    ),
                }
            )
        else:
            for name in AIHOOTS_VENDORED_FILES:
                record(
                    f"tools/aihoots_reference/{name}",
                    (AIHOOTS_SOURCE / name).read_bytes(),
                    f"AIHOOTS's own audit-verify at commit {aihoots_commit or '(unknown)'}.",
                )
            vendored = True

    # --- the manifest --------------------------------------------------------
    claimed_outcome = pack.get("outcome", {}).get("suitable")
    read_outcome = outcome_from_public_inputs(public_inputs)

    manifest = {
        "manifest_version": "1.0.0",
        "bundle_format_version": BUNDLE_FORMAT_VERSION,
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "produced_by": BUILDER_NAME,
        "request_id": pack.get("request_id"),
        "circuit": pack.get("circuit"),
        "canonical_evidence_sha256": canonical_sha256,
        "files": sorted(files, key=lambda entry: entry["path"]),
        "absent": absent,
        "pinned_dependencies": pinned_dependencies(
            bb_version_pin=bb_version_pin,
            bb_observed=detect_bb_version(),
            aihoots_commit=aihoots_commit,
            aihoots_vendored=vendored,
        ),
        "two_verdicts": {
            "note": (
                "These are two findings, not one. Evidence integrity asks whether this pack is "
                "the bytes that were sealed. Decision outcome asks what the circuit answered. A "
                "valid proof of NOT SUITABLE is a correctly formed rejection with perfect "
                "integrity; anything that reported it as a single PASS would be reporting a "
                "decline as an approval."
            ),
            "decision_outcome_claimed_by_the_record": verdict_words(claimed_outcome),
            "decision_outcome_read_from_public_input_%d" % OUTCOME_INDEX: verdict_words(read_outcome),
            "the_two_agree": claimed_outcome == read_outcome,
        },
        "independence_scope": (
            "The cryptographic independence this bundle offers covers the `wealth_suitability` "
            "circuit and no other. That circuit's verification key is committed to the "
            "repository and CI fails if it drifts from a fresh build, so an examiner can check "
            "the proof without trusting Memtara's build pipeline. The other four circuits' "
            "verification keys are gitignored build artefacts regenerated at boot, and no "
            "equivalent guarantee exists for them. This is a property of one circuit, not of "
            "the system."
        ),
        "manifest_integrity": (
            "This file lists every other file's SHA-256 and therefore cannot list its own. "
            "Its own integrity rests on MANIFEST.json.sig if one is present, and on nothing "
            "otherwise."
        ),
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _write(output_dir / MANIFEST_FILENAME, manifest_bytes)

    signed = False
    if signing_key is not None:
        signature = {
            "algorithm": "Ed25519",
            "encoding": "raw, detached, hex",
            "signed_over": f"the bytes of {MANIFEST_FILENAME}, exactly as written",
            "public_key_hex": signing_key.public_key().public_bytes_raw().hex(),
            "signature_hex": signing_key.sign(manifest_bytes).hex(),
            "caveat": (
                "The public key is carried here for identification. Verifying against it proves "
                "only that this signature and that manifest agree; authenticity requires the "
                "verifier to already hold the expected key from elsewhere "
                "(verify_bundle.py --expected-public-key)."
            ),
        }
        _write(
            output_dir / MANIFEST_SIGNATURE_FILENAME,
            json.dumps(signature, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )
        signed = True

    return {
        "output_dir": output_dir,
        "manifest": manifest,
        "canonical_evidence_sha256": canonical_sha256,
        "decision_outcome": verdict_words(read_outcome),
        "files": len(files),
        "absent": len(absent),
        "signed": signed,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_bundle.py",
        description="Assemble a self-contained, offline-verifiable evidence bundle.",
    )
    parser.add_argument("--output", required=True, type=Path, help="directory to write")

    source = parser.add_argument_group("where the evidence comes from (pick one)")
    source.add_argument("--request-id", help="fetch this assessment from the API")
    source.add_argument(
        "--evidence-json",
        type=Path,
        help="a saved wealth-assessment evidence response, instead of a live fetch",
    )
    source.add_argument("--base-url", default=os.environ.get("MEMTARA_BASE_URL", "http://localhost:8080"))
    source.add_argument("--org-api-key", default=os.environ.get("MEMTARA_ORG_API_KEY", ""))

    extra = parser.add_argument_group("artefacts the API does not return")
    extra.add_argument(
        "--proof-file",
        type=Path,
        help="the raw bb proof bytes from the firm's records. Checked against proof_sha256.",
    )
    extra.add_argument("--proof-token", help="the JWT Memtara issued, or @path")
    extra.add_argument("--aihoots-audit", type=Path, help="the relying party's audit.jsonl")
    extra.add_argument(
        "--jwks-file",
        type=Path,
        help="a key set already captured, instead of fetching one",
    )
    extra.add_argument(
        "--no-jwks-fetch",
        action="store_true",
        help="do not fetch the key set; build without one and record it as absent",
    )
    extra.add_argument("--vkey-dir", type=Path, default=DEFAULT_VKEY_DIR)
    extra.add_argument("--bb-version", default=DEFAULT_BB_VERSION)
    extra.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 key (PEM or 32-byte seed) to sign MANIFEST.json with. Never generated.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        signing_key = load_signing_key(args.signing_key) if args.signing_key else None

        if args.evidence_json:
            evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8"))
        elif args.request_id:
            from scripts.export_audit_evidence import fetch_evidence

            if not args.org_api_key:
                raise BuildError(
                    "no organisation API key: pass --org-api-key or set MEMTARA_ORG_API_KEY. "
                    "Producing a bundle needs it; verifying one never does."
                )
            evidence = fetch_evidence(args.base_url, args.request_id, args.org_api_key)
        else:
            raise BuildError("give either --request-id (live fetch) or --evidence-json (a file)")

        token = decode_proof_token(read_proof_token_argument(args.proof_token)) if args.proof_token else None
        pack = build_pack(evidence, token=token)
        if args.aihoots_audit:
            pack["aihoots"] = collect_aihoots(args.aihoots_audit, pack_proof_hashes(pack))

        snapshot = None
        if args.jwks_file:
            raw = json.loads(Path(args.jwks_file).read_text(encoding="utf-8"))
            # Accept either a bare JWK Set or a snapshot this tool wrote earlier,
            # so re-bundling an archived pack does not silently double-wrap it.
            if isinstance(raw, dict) and "jwks" in raw and "pinned_keys" in raw:
                snapshot = raw
            else:
                snapshot = snapshot_from_jwks(raw, source_url=f"file://{Path(args.jwks_file).resolve()}")
        elif not args.no_jwks_fetch:
            snapshot = snapshot_from_jwks(
                fetch_jwks(args.base_url), source_url=jwks_url(args.base_url)
            )

        staging = Path(args.output) / "_render"
        pdf_path = staging / "case_file.pdf"
        rendered = render_and_seal(pack, pdf_path)

        result = build_bundle(
            pack,
            Path(args.output),
            pdf_path=rendered["pdf"],
            seal_path=rendered["seal"],
            jwks_snapshot=snapshot,
            vkey_dir=args.vkey_dir,
            proof_path=args.proof_file,
            aihoots_audit_path=args.aihoots_audit,
            bb_version_pin=args.bb_version,
            signing_key=signing_key,
        )
        shutil.rmtree(staging, ignore_errors=True)
    except (BuildError, ExportError, OSError, ValueError) as exc:
        print(f"build_bundle: {exc}", file=sys.stderr)
        return 1

    print(f"files              {result['files']}", file=sys.stderr)
    print(f"absent             {result['absent']}", file=sys.stderr)
    print(f"evidence sha256    {result['canonical_evidence_sha256']}", file=sys.stderr)
    print(f"decision outcome   {result['decision_outcome']}", file=sys.stderr)
    if not result["signed"]:
        print(
            "note               MANIFEST.json is unsigned: tamper-evident, but nothing "
            "establishes who produced it (--signing-key)",
            file=sys.stderr,
        )
    print(result["output_dir"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
