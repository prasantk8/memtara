#!/usr/bin/env python3
"""memtara-export — the Canonical Case File exporter.

A bank's Chief Risk Officer runs this and hands the output to a DFSA or CBUAE
examiner. It produces one PDF per suitability assessment plus a `.seal.json`
sidecar, from exactly one server call (`GET /api/v1/wealth-assessments/{id}`)
and, optionally, the relying party's own AIHOOTS audit log.

    scripts/memtara-export --request-id <uuid> --output ./case.pdf
    scripts/memtara-export verify ./case.pdf

What this tool is careful about, because getting any of it wrong turns an
evidence pack into a liability:

  * **It never invents.** Everything printed comes from the API response, the
    supplied AIHOOTS log, or the supplied token. Where a value is absent the
    document says so; it does not fall back to a plausible default. An
    examiner reading "(not recorded)" learns something true. An examiner
    reading a default learns something false.

  * **It renders a projection, not the response.** `build_pack()` copies a
    fixed set of fields out of the API response and `build_document()` can
    only see what `build_pack()` copied. That is a whitelist, and it is the
    reason a client's income cannot reach the paper even if some future
    endpoint, proxy or test fixture starts putting one in the JSON. A
    renderer that walked the response dict would have no such property, and
    the failure would be silent and permanent — the pack is already in a
    regulator's hands by the time anyone notices.

  * **It does not re-implement anyone else's verifier.** `audit-verify` is
    AIHOOTS's own CLI, run as a subprocess from the pinned submodule, and its
    verdict is reproduced verbatim including the exit code. A second
    implementation of a hash chain walker that agreed with the first would
    prove nothing; one that disagreed would be indistinguishable from a bug
    in this file.

  * **It does not overstate its own seal.** The sidecar signature is a raw
    Ed25519 detached signature over the PDF bytes. It is *not* PAdES, not
    AdES, not embedded, and no PDF viewer will show a green tick for it. The
    strongest authenticity claim in the pack is the Memtara-issued JWT, which
    an examiner verifies against the issuer's published JWKS without needing
    the bank, this tool, or Memtara to still exist. Section 5 of the document
    says all of that in the document itself, not just here.

  * **It will not fabricate a signer.** With no `--signing-key` the pack is
    tamper-evident (digests) and unauthenticated, and says so. Generating an
    ephemeral key and signing with it would produce a document that looks
    signed, verifies against a key nobody holds, and means nothing.

Output convention: informational lines go to stderr and the path of the
written PDF is the only thing on stdout, so `pack=$(memtara-export ...)` is
usable in a script. Exit status is 0 only on success.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.pdf import Document  # noqa: E402  (needs REPO_ROOT on the path first)

TOOL_NAME = "scripts/export_audit_evidence.py"

# Bumped by hand when the *shape* of the pack changes — a new section, a
# field added to the canonical evidence, a change to what the seal covers.
# It is recorded in the sidecar so that a pack produced two years from now
# can be compared against one produced today without guessing which of them
# omitted something.
TOOL_VERSION = "1.0.0"

SEAL_VERSION = 1

AIHOOTS_ROOT = REPO_ROOT / "tests" / "aihoots_reference"

DEFAULT_BASE_URL = "http://localhost:8080"

MISSING = "(not recorded)"


# ---------------------------------------------------------------------------
# The 12 public inputs of `wealth_suitability`, in circuit order.
#
# Duplicated from `backend/api/src/wealth/mod.rs::public_input_template` for
# the same reason `generate_regulatory_demo.py` duplicates the predicate
# registry: this tool must run against a deployment whose source nobody has
# checked out, and a Rust file is not importable from Python. The Rust side
# guards its own ordering with
# `public_input_template_names_every_position_in_circuit_order`, and the
# evidence response independently carries `outcome.read_from` ("public input
# 11 of 12") — so if this list ever drifts, `OUTCOME_INDEX` below stops
# agreeing with the server and the document says so on the page rather than
# printing a confident wrong label.
#
# `who_fixes` matters as much as the name. The whole security argument for
# the verdict is that the four thresholds are the firm's and were registered
# before the client was asked; a reader who cannot tell which positions the
# client controls cannot evaluate that argument.
# ---------------------------------------------------------------------------

PUBLIC_INPUTS = [
    ("current_time", "client, pinned by the server into the assessment window"),
    ("expiry_time", "server"),
    ("vault_root", "client, pinned by the server to the root this user synced"),
    ("product_ref", "server (digest of the ISIN)"),
    ("min_income", "server, from the product registry"),
    ("min_liquidity", "server, from the product registry"),
    ("max_concentration_percent", "server, from the product registry"),
    ("product_risk_level", "server, from the product registry"),
    ("user_public_key_x", "client (Baby Jubjub)"),
    ("user_public_key_y", "client (Baby Jubjub)"),
    ("nonce", "server, single use"),
    ("suitable", "THE CIRCUIT - this is the answer, not an input"),
]

OUTCOME_INDEX = 11

# The DFSA citation, both halves. See docs/REGULATORY_MATRIX.md, appendix.
DFSA_EMITTED_CLAIM = "COB 3.1"
DFSA_CORRECT_RULE = "COB 3.4"

# Short obligation text for the CBUAE clauses the assessment maps to. Taken
# from docs/REGULATORY_MATRIX.md, which was written against the vendored
# Guidance Note (`tests/aihoots_reference/CBUAE_EN_6958_VER1.pdf`). Anything
# not in this table is printed with its identifier and no gloss rather than
# with an invented one.
CBUAE_CLAUSES = {
    "3(a)": (
        "No discriminatory or manipulative outcomes.",
        "Narrows the feature surface: the firm receives one bit, not the figures behind "
        "it. Does not measure disparate impact - see the matrix, this is a named gap.",
    ),
    "4(a)": (
        "Be transparent about AI use and high-impact decisions, and be able to disclose "
        "how they were made.",
        "This pack is that disclosure: the terms, the inputs, the verdict and the "
        "position it was read from.",
    ),
    "5(a)": (
        "Clear provenance and audit trails for data used in AI/ML.",
        "The proof digest ties the verdict to specific proof bytes; the chain excerpt in "
        "section 3 ties those to a position in an append-only log.",
    ),
    "5(c)": (
        "Personal data used only for legitimate and proportionate purposes; in-country "
        "retention.",
        "Proportionality is enforced by the circuit rather than by policy. The firm "
        "received one boolean; storage and residency duties do not attach to figures it "
        "never held.",
    ),
    "5(d)": (
        "Privacy-by-design and security-by-design built into AI systems.",
        "The plaintext is not in the system to protect. Single-use nonce, in-circuit time "
        "bound, and a vault root the server pins rather than accepts.",
    ),
    "5(e)": (
        "Use AI to identify financial-crime issues, subject to reporting duties.",
        "Not exercised by this assessment.",
    ),
    "7(a)": (
        "Meaningful human oversight for consumer-significant decisions.",
        "No proof exists unless the client performed an explicit device-local action; the "
        "gate is held by the person whose interests are at stake.",
    ),
    "7(b)": (
        "Human involvement commensurate with the risk to the consumer.",
        "The assessment window is bounded server-side and the grant is single-use.",
    ),
}


class ExportError(Exception):
    """Anything that should end the run with a message and a non-zero exit."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    """The exact serialisation the canonical evidence digest is taken over.

    `sort_keys` plus the tight separators is the same convention AIHOOTS's
    audit chain uses for its record hashes (`chain.py::_canonical_payload`).
    Matching it is deliberate: two systems in the same pack that canonicalise
    differently give a reviewer two rules to learn and one more thing to get
    wrong when they recompute a digest by hand.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _s(value: Any) -> str:
    """Render a JSON scalar for the page. `None` becomes a visible absence."""
    if value is None:
        return MISSING
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        # `proofs.public_inputs` is a jsonb column; a deployment that stored it
        # as a JSON *string* rather than an array would otherwise be rendered
        # one character per row.
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]


def _get(mapping: Any, *path: str, default: Any = None) -> Any:
    cursor = mapping
    for key in path:
        if not isinstance(cursor, dict):
            return default
        cursor = cursor.get(key)
    return default if cursor is None else cursor


def _chunk(text: str, width: int) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)] or [""]


# ---------------------------------------------------------------------------
# Data source 1 — the evidence endpoint
# ---------------------------------------------------------------------------


def normalise_request_id(raw: str) -> str:
    """Accept both `req_<uuid>` and a bare UUID.

    The CLI this was specified against writes `--request-id req_xxx`, while
    the route is `/api/v1/wealth-assessments/:request_id` typed as a `Uuid`.
    Rather than pick a side, strip the prefix if it is there and let the
    server reject anything that is still not a UUID — its error message is
    better than any guess made here.
    """
    value = raw.strip()
    for prefix in ("req_", "request_"):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def fetch_evidence(base_url: str, request_id: str, api_key: str, timeout: float = 30.0) -> dict:
    url = f"{base_url.rstrip('/')}/api/v1/wealth-assessments/{normalise_request_id(request_id)}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": f"memtara-export/{TOOL_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace").strip()
        if exc.code == 401:
            raise ExportError(
                "the server rejected the organisation API key (401). The key is the one "
                "shown once by POST /orgs; pass it with --org-api-key or set "
                "MEMTARA_ORG_API_KEY."
            ) from exc
        if exc.code == 404:
            raise ExportError(
                f"no assessment {request_id} for this organisation (404). The endpoint "
                "deliberately does not distinguish 'does not exist' from 'belongs to "
                "another tenant' — see the WHERE clause in wealth/evidence.rs — so check "
                "the request id and the key together."
            ) from exc
        raise ExportError(f"GET {url} failed: HTTP {exc.code} {exc.reason}\n{detail}") from exc
    except urllib.error.URLError as exc:
        raise ExportError(f"cannot reach {url}: {exc.reason}") from exc

    try:
        evidence = json.loads(body)
    except ValueError as exc:
        raise ExportError(f"{url} did not return JSON: {body[:200]!r}") from exc
    if not isinstance(evidence, dict):
        raise ExportError(f"{url} returned {type(evidence).__name__}, expected an object")
    return evidence


# ---------------------------------------------------------------------------
# Data source 1b — the binding check, and the model block it is about
#
# WHY THIS IS A SECOND CALL, AND WHY IT IS TO THE decision-evidence ROUTE
# ---------------------------------------------------------------------------
# `fetch_evidence` above reads `/api/v1/wealth-assessments/:id`, the
# operational view a bank's own tooling already consumes. It does not carry a
# model block and it does not carry a binding verdict. Both live on the sealed
# route, `/api/v1/wealth-assessments/:id/decision-evidence`, which returns the
# `DecisionEvidence` record plus a `binding_integrity` envelope BESIDE it —
# beside rather than inside, because the record is canonicalised and sealed and
# a value that depends on when you ask cannot live in bytes that must be
# identical every time (`respond` in backend/api/src/wealth/evidence.rs).
#
# WHAT THIS EXPORT TAKES FROM THAT RESPONSE, AND WHAT IT LEAVES
# ---------------------------------------------------------------------------
# Two things and no more: the binding events for this decision, and the record's
# `model` block. `build_pack` is this tool's redaction boundary and widening it
# is the one change here that could put a client figure on the paper, so the
# widening is as narrow as it can be — the model block is the firm's own
# declaration about its own software and contains nothing about the subject.
#
# What is deliberately NOT taken is the server's `verdict`, each event's
# `result` and its `recomputed_event_hash`. Those are Memtara's claims about
# Memtara's own evidence. Carrying them into a pack Memtara assembled and
# printing them would add nothing an examiner could act on; carrying the hash
# INPUTS instead lets them compute the verdict themselves, which is the whole
# difference between a verifier and a press release. `scripts/bundle/
# evidence_ops.py::recompute_binding_event` is where that recomputation lives.
# ---------------------------------------------------------------------------


class BindingUnavailable(Exception):
    """The binding report could not be obtained. Recorded, never worked around."""


def fetch_decision_evidence(base_url: str, request_id: str, api_key: str, timeout: float = 30.0) -> dict:
    """`GET /api/v1/wealth-assessments/:id/decision-evidence`, whole envelope."""
    url = (
        f"{base_url.rstrip('/')}/api/v1/wealth-assessments/"
        f"{normalise_request_id(request_id)}/decision-evidence"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": f"memtara-export/{TOOL_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace").strip()
        raise BindingUnavailable(f"GET {url} answered HTTP {exc.code} {exc.reason}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise BindingUnavailable(f"cannot reach {url}: {exc.reason}") from exc
    try:
        envelope = json.loads(body)
    except ValueError as exc:
        raise BindingUnavailable(f"{url} did not return JSON: {body[:200]!r}") from exc
    if not isinstance(envelope, dict):
        raise BindingUnavailable(f"{url} returned {type(envelope).__name__}, expected an object")
    return envelope


#: The static prose that travels inside the sealed pack beside the events.
#:
#: Static on purpose. The export timestamp and the tool version are already
#: kept out of the pack so that two exports of the same assessment share a
#: digest (see `build_pack`), and the same rule bars the replay report's
#: `checked_at`, its org-wide counts and its verdict: every one of them moves
#: without the evidence moving. The events themselves do not — if they change,
#: the digest changing is the finding, not a nuisance.
BINDING_REPLAY_NOTE = (
    "The audit_log rows that commit to this decision's model attestation and to the policy it "
    "was measured against, with the payload each one hashed rebuilt from the rows as they stand. "
    "Memtara's own verdict on them is NOT carried here: recompute it. "
    "event_hash = SHA256(framed(event_type) || framed(ref_id) || framed(prev_hash) || "
    "framed(payload)), where framed(x) is an 8-byte big-endian length followed by x, ref_id is "
    "the UUID's 16 raw bytes, prev_hash is the raw digest bytes, and payload is the canonical "
    "JSON of rebuilt_payload. See docs/VERIFY.md step 7d."
)

MODEL_ATTESTATION_NOTE = (
    "The model identity the sealed DecisionEvidence record serves, carried so it can be compared "
    "with the identity the hash chain committed to. `supplied: false` means the exporter could "
    "not obtain it and is NOT the assertion that no AI participated; that assertion is "
    "`supplied: true` with `model: null`."
)


def _binding_events_for(envelope: dict, request_id: str) -> tuple[list[dict], int]:
    """This decision's binding events, in chain order, hash inputs only.

    Filtered to `ref_id == request_id` even though the `binding_integrity`
    envelope is already scoped to this decision, because the org-wide replay
    endpoint has the same shape and a caller who reaches for it instead must
    not leak another decision's identifiers into this pack.

    The count of what was dropped is returned and carried, rather than the
    filter being silent. Two binding event types exist today and both name the
    decision; a third is being built for model corrections and might not. If it
    does not, this count goes non-zero and someone notices, which is the whole
    difference between a filter and a hole. `event_type` is never used to
    decide what to keep — the verifier iterates whatever types are here.
    """
    report = envelope.get("binding_integrity")
    if not isinstance(report, dict):
        raise BindingUnavailable(
            "the decision-evidence response carried no `binding_integrity` envelope. A record "
            "served with no integrity statement at all is the silence that field exists to end, "
            "so this is recorded as unavailable rather than treated as a clean result"
        )
    wanted = normalise_request_id(request_id)
    events, dropped = [], 0
    for event in _as_list(report.get("events")):
        if not isinstance(event, dict):
            continue
        if _s(event.get("ref_id")) != wanted:
            dropped += 1
            continue
        events.append(
            {
                "seq": event.get("seq"),
                "event_type": _s(event.get("event_type")),
                "ref_id": _s(event.get("ref_id")),
                "created_at": _s(event.get("created_at")),
                # Named `event_hash`/`prev_hash` to match `audit_chain_excerpt`
                # in the same pack. One vocabulary for one concept.
                "event_hash": _s(event.get("recorded_event_hash")),
                "prev_hash": _s(event.get("prev_hash")),
                # Kept as-is, nulls included: this is the material the digest
                # is recomputed over and any coercion would change the bytes.
                "rebuilt_payload": event.get("rebuilt_payload"),
            }
        )
    events.sort(key=lambda e: (e["seq"] is None, e["seq"]))
    return events, dropped


def collect_binding(envelope: dict | None, request_id: str, *, reason: str = "") -> tuple[dict, dict]:
    """`(binding_replay, model_attestation)` for the pack, in both directions."""
    if envelope is None:
        unavailable = reason or "the exporter did not fetch the decision-evidence endpoint"
        return (
            {"supplied": False, "events": [], "events_naming_another_decision": 0,
             "note": BINDING_REPLAY_NOTE, "unavailable_reason": unavailable},
            {"supplied": False, "model": None, "model_provenance": None,
             "note": MODEL_ATTESTATION_NOTE, "unavailable_reason": unavailable},
        )
    events, dropped = _binding_events_for(envelope, request_id)
    record = envelope.get("decision_evidence")
    has_model = isinstance(record, dict) and "model" in record
    return (
        {"supplied": True, "events": events, "events_naming_another_decision": dropped,
         "note": BINDING_REPLAY_NOTE, "unavailable_reason": None},
        {
            "supplied": bool(has_model),
            # `model` is `null` for the no-AI assertion, which is why the
            # `supplied` flag exists: without it, "no AI participated" and
            # "no block was obtained" would be the same two bytes.
            "model": record["model"] if has_model else None,
            # Carried beside it because `model` alone stopped being the right
            # comparand at schema 1.2.0: it serves the organisation's CURRENT
            # statement, and a filed correction changes it legitimately. The
            # binding event commits to the row as declared at open, which is
            # what `model_provenance.as_declared_at_open` preserves verbatim.
            # Comparing against that is what keeps the offline check from
            # reporting a corrected decision as a tampered one.
            "model_provenance": (record or {}).get("model_provenance")
            if isinstance(record, dict)
            else None,
            "note": MODEL_ATTESTATION_NOTE,
            "unavailable_reason": None if has_model else
            "the decision-evidence response carried no `model` key",
        },
    )


# ---------------------------------------------------------------------------
# Data source 2 — the AIHOOTS audit chain
# ---------------------------------------------------------------------------


def _record_proof_hashes(record: dict) -> set[str]:
    """Every proof digest a single AIHOOTS record claims to be about.

    Two key names, on purpose. `integrations/aihoots/memtara_claims.py`
    writes `detail.proof_hash`; the working spec for this exporter called it
    `memtara_proof_hash`, which is the naming the *other* Memtara fields in
    that same dict use (`memtara_user_id`, `memtara_circuit`, ...). Accepting
    both costs one line and means a relying party that followed either
    convention still gets a linked section instead of an empty one.
    """
    detail = record.get("detail")
    if not isinstance(detail, dict):
        return set()
    return {
        detail[key]
        for key in ("proof_hash", "memtara_proof_hash")
        if isinstance(detail.get(key), str)
    }


def run_audit_verify(audit_path: Path, aihoots_root: Path = AIHOOTS_ROOT) -> dict:
    """Run AIHOOTS's own `audit-verify` and record what it said, verbatim.

    Not reimplemented, and not summarised into a boolean either: the exit code
    and both streams go into the pack as printed. A verifier's own words are
    evidence; this tool's paraphrase of them would be hearsay.
    """
    module_path = aihoots_root / "src" / "verifier" / "cli.py"
    command = f"{Path(sys.executable).name} -m src.verifier.cli {audit_path}"
    if not module_path.exists():
        return {
            "available": False,
            "command": command,
            "reason": (
                f"AIHOOTS's verifier is not present at {module_path} — the submodule is "
                "empty. Run `git submodule update --init` and re-export."
            ),
        }
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "src.verifier.cli", str(audit_path.resolve())],
            cwd=str(aihoots_root),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "command": command, "reason": f"could not run it: {exc}"}
    return {
        "available": True,
        "command": command,
        "exit_code": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "intact": proc.returncode == 0,
    }


def collect_aihoots(audit_path: Path, proof_hashes: set[str], aihoots_root: Path = AIHOOTS_ROOT) -> dict:
    if not audit_path.exists():
        raise ExportError(f"--aihoots-audit: no such file: {audit_path}")

    records: list[dict] = []
    malformed = 0
    for number, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            # Counted and reported rather than raised. A chain with a corrupt
            # line is exactly the situation the section exists to surface, and
            # `audit-verify` will have its own, more authoritative, opinion
            # about it a few lines below.
            malformed += 1
            continue
        if isinstance(record, dict):
            records.append(record)

    matched = []
    for record in records:
        hits = _record_proof_hashes(record) & proof_hashes
        if not hits:
            continue
        matched.append(
            {
                "seq": record.get("seq"),
                "event_type": _s(record.get("event_type")),
                "decision": _s(record.get("decision")),
                "caller": _s(record.get("caller")),
                "timestamp": record.get("timestamp"),
                "prev_hash": _s(record.get("prev_hash")),
                "record_hash": _s(record.get("record_hash")),
                "proof_hash": sorted(hits)[0],
                "regulatory_audit_id": _s(_get(record, "detail", "regulatory_audit_id")),
            }
        )

    linked = {entry["proof_hash"] for entry in matched}
    return {
        "supplied": True,
        "path": str(audit_path),
        "records_total": len(records),
        "records_malformed": malformed,
        "matched": matched,
        "proof_hashes_with_no_entry": sorted(proof_hashes - linked),
        "audit_verify": run_audit_verify(audit_path, aihoots_root),
    }


# ---------------------------------------------------------------------------
# Data source 3 — the proof token the caller kept
# ---------------------------------------------------------------------------


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_proof_token(token: str) -> dict:
    """Split and decode a JWT **without verifying it**.

    Verification is deliberately not attempted here. Doing it would need the
    issuer's JWKS, which means a network call at export time, which means a
    pack that cannot be produced offline and a "verified" stamp whose meaning
    depends on what DNS said that morning. The examiner re-verifies against
    the published JWKS themselves; section 2e of the document tells them how
    and states plainly that this tool did not.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ExportError(
            f"--proof-token does not look like a JWT ({len(parts)} dot-separated parts, "
            "expected 3)"
        )
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature_bytes = len(_b64url_decode(parts[2]))
    except (ValueError, binascii.Error) as exc:
        raise ExportError(f"--proof-token could not be decoded: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ExportError("--proof-token: header and payload must both be JSON objects")

    return {
        "supplied": True,
        "token": token,
        "header": header,
        "claims": claims,
        "signature_bytes": signature_bytes,
        "verified_by_this_exporter": False,
    }


def read_proof_token_argument(value: str) -> str:
    """`--proof-token @path` reads the token from a file.

    Tokens are ~600 characters. Pasting one onto a command line puts a bearer
    credential into the shell history of the machine that produced the
    regulator's copy, which is a bad habit to design into a compliance tool
    even for a credential that expired 300 seconds after it was minted.
    """
    if value.startswith("@"):
        path = Path(value[1:]).expanduser()
        if not path.exists():
            raise ExportError(f"--proof-token @{path}: no such file")
        return path.read_text(encoding="utf-8").strip()
    return value


# ---------------------------------------------------------------------------
# The pack — the projection everything downstream is allowed to see
# ---------------------------------------------------------------------------


def build_pack(
    evidence: dict,
    *,
    aihoots: dict | None = None,
    token: dict | None = None,
    binding: tuple[dict, dict] | None = None,
) -> dict:
    """Copy the fields the case file asserts out of the API response.

    This is the redaction boundary. `build_document` takes the result of this
    function and never sees `evidence`, so a field that is not named here
    cannot reach the paper — which is what makes "no client figure appears in
    the rendered bytes" a property of the code rather than a property of
    today's server response.

    `public_inputs` are the one place values pass through verbatim, because an
    examiner must be able to retype them into `bb verify` and get the same
    answer. They are safe to pass through for a structural reason, not a
    hopeful one: they are the circuit's *public* inputs, and the four figures
    the client owns are private witnesses that never appear among them. Any
    day that stops being true, the circuit has been changed and this document
    is the smallest of the resulting problems.

    Note what is absent: the export timestamp and the tool version. The digest
    over this structure identifies the *evidence*, not the run that printed
    it, so two exports of the same assessment share a digest and a change in
    the digest means the underlying record moved. Those two fields live in the
    sidecar instead.
    """
    proofs = []
    for proof in _as_list(evidence.get("proofs")):
        if not isinstance(proof, dict):
            continue
        proofs.append(
            {
                "proof_id": _s(proof.get("proof_id")),
                "accepted_by_bb_verify": bool(proof.get("accepted_by_bb_verify")),
                "verified_at": _s(proof.get("verified_at")),
                "proof_bytes": proof.get("proof_bytes"),
                "proof_sha256": _s(proof.get("proof_sha256")),
                "public_inputs": [_s(value) for value in _as_list(proof.get("public_inputs"))],
            }
        )

    # Always present, both keys, whether or not a report was obtained — the
    # rule the pack schema states as `x_every_key_is_required`. A key that
    # vanished when the binding check could not be run would change the
    # canonical byte layout for a reason that is about the exporter's
    # circumstances rather than about the decision, and would let "not
    # obtained" read as "nothing to report".
    binding_replay, model_attestation = binding or collect_binding(
        None,
        _s(evidence.get("request_id")),
        reason="this pack was built without a decision-evidence fetch",
    )

    chain = []
    for event in _as_list(evidence.get("audit_chain_excerpt")):
        if not isinstance(event, dict):
            continue
        chain.append(
            {
                "seq": event.get("seq"),
                "event_type": _s(event.get("event_type")),
                "event_hash": _s(event.get("event_hash")),
                "prev_hash": _s(event.get("prev_hash")),
                "created_at": _s(event.get("created_at")),
            }
        )

    return {
        "request_id": _s(evidence.get("request_id")),
        "circuit": _s(evidence.get("circuit")),
        "status": _s(evidence.get("status")),
        "opened_at": _s(evidence.get("opened_at")),
        "organisation": {
            "id": _s(_get(evidence, "organisation", "id")),
            "name": _s(_get(evidence, "organisation", "name")),
            "type": _s(_get(evidence, "organisation", "type")),
        },
        "subject": {
            "user_id": _s(_get(evidence, "subject", "user_id")),
            "disclosed_attributes": [
                _s(item) for item in _as_list(_get(evidence, "subject", "disclosed_attributes"))
            ],
            "note": _s(_get(evidence, "subject", "note")),
        },
        "product": {
            "id": _s(_get(evidence, "product", "id")),
            "isin": _s(_get(evidence, "product", "isin")),
            "name": _s(_get(evidence, "product", "name")),
            "product_ref": _s(_get(evidence, "product", "product_ref")),
        },
        "terms_assessed_against": {
            "min_income": _get(evidence, "terms_assessed_against", "min_income"),
            "min_liquidity": _get(evidence, "terms_assessed_against", "min_liquidity"),
            "max_concentration_percent": _get(
                evidence, "terms_assessed_against", "max_concentration_percent"
            ),
            "product_risk_level": _get(evidence, "terms_assessed_against", "product_risk_level"),
            "source": _s(_get(evidence, "terms_assessed_against", "source")),
        },
        "window": {
            "start": _s(_get(evidence, "window", "start")),
            "end": _s(_get(evidence, "window", "end")),
            "expires_at": _s(_get(evidence, "window", "expires_at")),
        },
        "outcome": {
            "assessed": bool(_get(evidence, "outcome", "assessed", default=False)),
            # Tri-state on purpose: True, False and "never assessed" are three
            # different facts about a firm's conduct and collapsing the last
            # two into `false` would let an assessment that never happened
            # read as a decline.
            "suitable": _get(evidence, "outcome", "suitable"),
            "assessed_at": _s(_get(evidence, "outcome", "assessed_at")),
            "read_from": _s(_get(evidence, "outcome", "read_from")),
            "note": _s(_get(evidence, "outcome", "note")),
        },
        "nonce": _s(evidence.get("nonce")),
        "verification_key": {
            "sha256": _s(_get(evidence, "verification_key", "sha256")),
            "bytes": _get(evidence, "verification_key", "bytes"),
            "verifier_target": _s(_get(evidence, "verification_key", "verifier_target")),
            "published_at": _s(_get(evidence, "verification_key", "published_at")),
            "note": _s(_get(evidence, "verification_key", "note")),
        },
        "proofs": proofs,
        "audit_chain_excerpt": chain,
        # The chain proves rows were not removed or reordered. These two prove
        # something the chain never claimed: that the mutable rows this
        # decision is judged on STILL SAY what was hashed. Separate keys for
        # separate claims — see docs/VERIFY.md steps 7 and 7d.
        "binding_replay": binding_replay,
        "model_attestation": model_attestation,
        "regulatory_mapping": {
            "dfsa_claim_values": [_s(v) for v in _as_list(_get(evidence, "regulatory_mapping", "dfsa"))],
            "dfsa_correct_citation": DFSA_CORRECT_RULE,
            "cbuae": [_s(v) for v in _as_list(_get(evidence, "regulatory_mapping", "cbuae"))],
        },
        "aihoots": aihoots or {"supplied": False},
        "proof_token": token or {"supplied": False},
    }


def pack_proof_hashes(pack: dict) -> set[str]:
    return {p["proof_sha256"] for p in pack["proofs"] if p["proof_sha256"] not in ("", MISSING)}


def _accepted_proof(pack: dict) -> dict | None:
    for proof in pack["proofs"]:
        if proof["accepted_by_bb_verify"]:
            return proof
    return None


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


def _verdict_words(pack: dict) -> str:
    suitable = pack["outcome"]["suitable"]
    if suitable is True:
        return "SUITABLE"
    if suitable is False:
        return "NOT SUITABLE"
    return "NOT ASSESSED"


def build_document(
    pack: dict,
    *,
    canonical_sha256: str,
    created_at: datetime | None = None,
    source_url: str = "",
    seal_filename: str = "",
    signing_public_key_hex: str | None = None,
) -> Document:
    """Lay out the five sections. Takes a pack, never a raw API response."""
    request_id = pack["request_id"]
    org_name = pack["organisation"]["name"]
    verdict = _verdict_words(pack)

    doc = Document(
        title="Canonical Case File - structured-product suitability",
        subtitle=(
            f"Assessment {request_id} - {org_name} - "
            f"instrument {pack['product']['isin']} - verdict {verdict}"
        ),
        created_at=created_at,
        # Kept under 100 characters on purpose: `pdf.py` truncates the running
        # header to the page width, and a header cut off mid-word in the
        # middle of a regulator's copy reads as carelessness about the rest.
        running_header=f"Memtara canonical case file - {request_id} - not an AdES signature",
    )

    _section_0_preamble(doc, pack, source_url=source_url, verdict=verdict)
    _section_1_metadata(doc, pack)
    _section_2_receipt(doc, pack, verdict=verdict)
    _section_3_chains(doc, pack)
    _section_4_regulatory(doc, pack)
    _section_5_seal(
        doc,
        pack,
        canonical_sha256=canonical_sha256,
        seal_filename=seal_filename,
        signing_public_key_hex=signing_public_key_hex,
    )
    return doc


def _section_0_preamble(doc: Document, pack: dict, *, source_url: str, verdict: str) -> None:
    doc.paragraph(
        "This is the complete record of one structured-product suitability assessment: "
        "who was assessed, against whose terms, what the zero-knowledge circuit answered, "
        "where that answer is recorded in two independent audit chains, and which "
        "regulatory obligations it bears on. It is assembled from a single call to the "
        "issuing server's evidence endpoint and, where supplied, the relying party's own "
        "audit log."
    )
    doc.preformatted(
        [
            f"  Assessment      {pack['request_id']}",
            f"  Firm            {pack['organisation']['name']}",
            f"  Instrument      {pack['product']['isin']}  {pack['product']['name']}",
            f"  VERDICT         {verdict}",
        ]
    )
    doc.paragraph(
        "Read section 2 before acting on the verdict. The single most consequential "
        "misreading available to a relying party is described there, and it is a "
        "misreading that leaves the reader holding cryptographic evidence which appears "
        "to support the wrong conclusion."
    )
    doc.bullet(
        "Section 1, client and product metadata - including a plain statement of what the "
        "issuer does not hold."
    )
    doc.bullet(
        "Section 2, zero-knowledge proof verification receipt - the key, the inputs, the "
        "verdict."
    )
    doc.bullet(
        "Section 3, audit chains - Memtara's own log and the relying party's AIHOOTS chain."
    )
    doc.bullet("Section 4, regulatory mapping - DFSA Conduct of Business, and CBUAE.")
    doc.bullet("Section 5, cryptographic seal - what it is, and what it deliberately is not.")
    if source_url:
        doc.paragraph(f"Source: {source_url}")
    doc.rule()


def _section_1_metadata(doc: Document, pack: dict) -> None:
    doc.heading("1. Client and product metadata", level=1)

    doc.heading("1a. The subject", level=2)
    doc.key_values(
        [
            ("Client reference", pack["subject"]["user_id"]),
            ("Assessment", pack["request_id"]),
            ("Circuit", pack["circuit"]),
            ("Request status", pack["status"]),
            ("Opened at", pack["opened_at"]),
            ("Firm", f"{pack['organisation']['name']} ({pack['organisation']['type']})"),
            ("Firm id", pack["organisation"]["id"]),
        ]
    )
    doc.paragraph(
        "The subject is identified by the UUID above and by nothing else. Memtara holds no "
        "name for this person, so none appears here; the firm resolves the UUID against its "
        "own client records."
    )

    doc.heading("1b. What the issuer does not hold", level=2)
    doc.paragraph(
        "Stated explicitly, because a reader of an evidence pack will look for the client's "
        "finances and should know why they will not find them rather than be left to wonder "
        "whether their absence is an oversight."
    )
    doc.paragraph(
        "Memtara holds no annual income figure, no liquid-assets figure, no risk-tolerance "
        "score and no existing-holdings value for this subject. It never did. The four limbs "
        "of the assessment were evaluated inside a zero-knowledge circuit on the holder's own "
        "device; the figures were private witnesses to that computation and were not "
        "transmitted. What crossed the wire was a proof and twelve public inputs, of which the "
        "last is the one-bit verdict."
    )
    doc.paragraph(
        "This is the product, not a limitation of it. A firm that cannot produce the figures "
        "cannot leak, mis-share or be compelled to hand over figures it does not have, and the "
        "obligations that attach to holding them do not attach here. The consequence a reader "
        "should also register: nobody - not the firm, not Memtara, not this document - can "
        "reconstruct the client's finances from this pack, so a challenge to the verdict must "
        "be resolved by re-running the assessment, not by re-reading the file."
    )
    disclosed = pack["subject"]["disclosed_attributes"]
    doc.key_values(
        [
            (
                "Attributes disclosed",
                ", ".join(disclosed) if disclosed else "none (the verdict is not an attribute)",
            ),
            ("Issuer's own note", pack["subject"]["note"]),
        ]
    )

    doc.heading("1c. The instrument", level=2)
    doc.key_values(
        [
            ("ISIN", pack["product"]["isin"]),
            ("Name", pack["product"]["name"]),
            ("Registry id", pack["product"]["id"]),
        ]
    )
    doc.paragraph(
        "product_ref is the digest of the ISIN that the circuit actually consumed as public "
        "input 3. It is what binds this proof to this instrument; an ISIN printed on a report "
        "binds nothing."
    )
    doc.preformatted([f"  product_ref  {pack['product']['product_ref']}"])

    doc.heading("1d. The terms assessed against", level=2)
    terms = pack["terms_assessed_against"]
    doc.table(
        ["Term", "Value", "Public input"],
        [
            ["Minimum annual income", _s(terms["min_income"]), "4  min_income"],
            ["Minimum liquid assets", _s(terms["min_liquidity"]), "5  min_liquidity"],
            [
                "Maximum post-trade concentration",
                f"{_s(terms['max_concentration_percent'])}%",
                "6  max_concentration_percent",
            ],
            ["Product risk level", _s(terms["product_risk_level"]), "7  product_risk_level"],
        ],
    )
    doc.key_values([("Provenance", terms["source"])])
    doc.paragraph(
        "The provenance line is the load-bearing part of this subsection. These four numbers "
        "are the firm's, they come from the product registry, and they were snapshotted into "
        "the assessment when it was opened - before the client was asked anything. The "
        "snapshot matters: amending the product tomorrow does not change what this proof was "
        "measured against."
    )
    doc.paragraph(
        "Every value of these thresholds yields a valid proof. A client who could choose its "
        "own minimum income could prove itself suitable for anything, with cryptography that "
        "checks out perfectly. What makes the verdict mean what the firm thinks it means is "
        "the server's comparison of each submitted public input against the terms above, not "
        "the proof."
    )

    doc.heading("1e. The assessment window", level=2)
    doc.key_values(
        [
            ("Window opens", pack["window"]["start"]),
            ("Window closes", pack["window"]["end"]),
            ("Grant expires", pack["window"]["expires_at"]),
        ]
    )
    doc.paragraph(
        "The window is enforced inside the circuit, not only by the server: public input 0 "
        "must fall within it. The nonce below is single-use and was issued when the "
        "assessment was opened, which is what prevents a verdict being back-dated onto a "
        "recommendation that had already been made."
    )
    doc.preformatted([f"  nonce  {pack['nonce']}"])
    doc.page_break()


def _section_2_receipt(doc: Document, pack: dict, *, verdict: str) -> None:
    doc.heading("2. Zero-knowledge proof verification receipt", level=1)

    doc.heading("2a. The verification key", level=2)
    vkey = pack["verification_key"]
    doc.paragraph(
        "An examiner re-verifying the proof needs the digest of the key it was checked "
        "against. Without it, 'the proof verifies' is a claim about a key nobody identified."
    )
    doc.preformatted(
        [
            f"  vkey SHA-256      {vkey['sha256']}",
            f"  vkey size         {_s(vkey['bytes'])} bytes",
            f"  verifier target   {vkey['verifier_target']}",
            f"  published at      {vkey['published_at']}",
        ]
    )
    if vkey["note"] != MISSING:
        doc.key_values([("Issuer's note", vkey["note"])])

    doc.heading("2b. Proof attempts", level=2)
    proofs = pack["proofs"]
    if not proofs:
        doc.paragraph(
            "No proof was ever submitted against this assessment. The request was opened and "
            "the terms were registered, but the client never produced a proof - so there is no "
            "verdict, and any recommendation made on this instrument to this client was made "
            "outside the assessed channel."
        )
    else:
        rejected = [p for p in proofs if not p["accepted_by_bb_verify"]]
        doc.table(
            ["#", "Verified at", "bb verify", "Proof bytes", "Proof id"],
            [
                [
                    str(index),
                    proof["verified_at"],
                    "accepted" if proof["accepted_by_bb_verify"] else "REJECTED",
                    _s(proof["proof_bytes"]),
                    proof["proof_id"],
                ]
                for index, proof in enumerate(proofs, start=1)
            ],
        )
        doc.paragraph(
            "Every attempt is listed, accepted and rejected alike. A pack that showed only the "
            "accepted proof would hide the pattern a reviewer is looking for."
        )
        doc.preformatted(
            [
                line
                for index, proof in enumerate(proofs, start=1)
                for line in (
                    f"  attempt {index}  {'accepted' if proof['accepted_by_bb_verify'] else 'REJECTED'}",
                    f"    proof SHA-256  {proof['proof_sha256']}",
                )
            ]
        )
        if rejected:
            doc.paragraph(
                f"{len(rejected)} of {len(proofs)} submitted proofs were rejected by bb verify. "
                "A rejection consumes nothing - not the nonce, not the grant - so a rejected "
                "attempt is not evidence of a failed client, and a run of them is worth asking "
                "the firm about."
            )
        else:
            doc.paragraph("No submitted proof was rejected by bb verify.")

    doc.heading("2c. The public inputs, in circuit order", level=2)
    subject_proof = _accepted_proof(pack) or (proofs[0] if proofs else None)
    if subject_proof is None:
        doc.paragraph("No proof was submitted, so there are no public inputs to record.")
    else:
        values = subject_proof["public_inputs"]
        doc.paragraph(
            "From the "
            + ("accepted" if subject_proof["accepted_by_bb_verify"] else "most recent (rejected)")
            + " proof. Order is a protocol detail no client can guess and getting it wrong "
            "produces a proof that fails verification with no clue why - so the position of "
            "each value is itself part of the evidence."
        )
        lines = []
        for index, value in enumerate(values):
            if index < len(PUBLIC_INPUTS):
                name = PUBLIC_INPUTS[index][0]
            else:
                name = "UNNAMED - circuit layout has drifted"
            lines.append(f"{index:>2}  {name:<26}  {value}")
        if len(values) < len(PUBLIC_INPUTS):
            for index in range(len(values), len(PUBLIC_INPUTS)):
                lines.append(f"{index:>2}  {PUBLIC_INPUTS[index][0]:<26}  {MISSING}")
        doc.preformatted(lines)
        doc.table(
            ["#", "Public input", "Who fixes it"],
            [[str(i), name, owner] for i, (name, owner) in enumerate(PUBLIC_INPUTS)],
        )

    doc.heading("2d. What bb verify does and does not mean", level=2)
    doc.paragraph(
        "bb verify answers one question: was this proof correctly constructed against this "
        "verification key. It does not answer whether the client passed."
    )
    doc.paragraph(
        "A proof that the client FAILED the assessment verifies exactly as cleanly as one that "
        "they passed - same key, same exit code, same success message. A relying party that "
        "reads the exit code and stops there approves everyone who was assessed, including "
        "everyone who failed, while holding cryptographic evidence that appears to support it. "
        "This is demonstrated with a real Barretenberg proof in "
        "tests/test_wealth_suitability_e2e.py, not merely asserted."
    )
    doc.paragraph(
        "The verdict is not the exit code. It is a public output of the circuit, read "
        "explicitly from its position in the public input vector:"
    )
    outcome = pack["outcome"]
    doc.preformatted(
        [
            f"  VERDICT       {verdict}",
            f"  read from     {outcome['read_from']}",
            f"  assessed at   {outcome['assessed_at']}",
            f"  assessed      {_s(outcome['assessed'])}",
        ]
    )
    if outcome["read_from"] != MISSING and f"input {OUTCOME_INDEX}" not in outcome["read_from"]:
        doc.paragraph(
            f"NOTE: this exporter expects the verdict at public input {OUTCOME_INDEX} and the "
            f"server reported '{outcome['read_from']}'. The two disagree, which means the "
            "circuit layout has changed since this tool was written. Treat the input names in "
            "2c as unverified until that is reconciled."
        )
    if outcome["suitable"] is None:
        doc.paragraph(
            "There is no verdict because no accepted proof exists for this assessment. That is "
            "a materially different fact from a decline, and this pack does not present it as "
            "one."
        )
    doc.key_values([("Issuer's own note", outcome["note"])])

    doc.heading("2e. The attestation token", level=2)
    token = pack["proof_token"]
    if not token.get("supplied"):
        doc.paragraph(
            "No proof token was supplied to this export, so none is reproduced here. The "
            "server does not retain it and could not have supplied it: the token is a bearer "
            "credential and the audit chain is a commitment, not a secret store (see the "
            "comment in backend/api/src/issuance/mod.rs). The chain records the token's jti and "
            "proof_hash, which is enough to prove after the fact which token an event refers "
            "to, without the log becoming a place to steal one."
        )
        doc.paragraph(
            "The consequence for this pack, stated plainly: without the token, the strongest "
            "independently checkable artefact here is the proof itself against the published "
            "verification key. Re-run the export with --proof-token if the firm kept it."
        )
    else:
        doc.paragraph(
            "Supplied by the caller. Anyone can re-verify this token against the issuer's "
            "published JWKS - GET <issuer>/.well-known/jwks.json, then one EdDSA check in any "
            "JOSE library - with no call to Memtara, no cooperation from the firm, and no "
            "reliance on this document. That makes it the strongest authenticity claim in the "
            "pack, stronger than the seal in section 5."
        )
        doc.paragraph(
            "This exporter decoded the token but did NOT verify its signature. Verification "
            "needs the issuer's key set, and a pack whose 'verified' stamp depended on what "
            "DNS answered at export time would be asserting something it cannot evidence. The "
            "check above is the reader's to run."
        )
        doc.key_values(
            [
                ("Algorithm", _s(token["header"].get("alg"))),
                ("Key id (kid)", _s(token["header"].get("kid"))),
                ("Signature", f"{token['signature_bytes']} bytes"),
            ]
        )
        doc.paragraph("Decoded claims:")
        doc.preformatted(json.dumps(token["claims"], indent=2, sort_keys=True).splitlines())
        doc.paragraph(
            "Two claims are easy to conflate and must not be. 'verified' is about the proof - "
            "it is always true on an issued token, because a failed verification produces an "
            "error rather than a token. 'suitable' is the answer that proof carried, and it is "
            "legitimately false sometimes. A relying party that gates on 'verified' has gated "
            "on nothing."
        )
        doc.paragraph("The token as issued:")
        doc.preformatted([f"  {chunk}" for chunk in _chunk(token["token"], 90)])
        doc.paragraph(
            "The token had a lifetime of a few minutes and expired long before this pack was "
            "printed, so reproducing it here discloses no usable credential. It is reproduced "
            "because it is the artefact an examiner re-checks."
        )
    doc.page_break()


def _section_3b_binding(doc: Document, pack: dict) -> None:
    """The binding events, printed as inputs to a calculation the reader makes.

    Section 3a prints the chain, and a reader who stops there will conclude
    that an intact chain means an intact record. It does not, and that
    conclusion is exactly the one that produced finding 4 in
    docs/BREAK_IT_FINDINGS.md. So this section states the three claims apart
    from each other, and then hands over the material for the third rather than
    Memtara's verdict on it.
    """
    doc.heading("3b. Binding: do the rows still say what was hashed?", level=2)
    doc.paragraph(
        "Section 3a shows LINKAGE - that no row was removed or reordered. That is one of three "
        "separable claims about this log, and the most consequential misreading of this document "
        "after the one in section 2 is to take the first as evidence of the third."
    )
    doc.bullet(
        "LINKAGE - each row's prev_hash is its predecessor's event_hash. Section 3a, and the "
        "chain walk in the offline bundle. It says nothing about what any row's payload said."
    )
    doc.bullet(
        "HEAD - the newest row is followed by nothing, so nothing in the chain commits to it. "
        "That row is covered only by a signed checkpoint published outside the database "
        "(GET /orgs/:id/audit-chain/checkpoint). Between the head moving and the next "
        "checkpoint being signed, the newest rows are covered by neither."
    )
    doc.bullet(
        "BINDING - the mutable rows this decision is judged on STILL SAY what was hashed. This "
        "section, and nothing else. A database UPDATE that rewrites the declared model identity "
        "leaves linkage byte-identical and fails only this."
    )

    binding = pack["binding_replay"]
    if not binding.get("supplied"):
        doc.paragraph(
            "No binding report was obtained for this assessment, so this claim is UNCHECKED in "
            "this pack. It is printed as unchecked rather than omitted: a section that is not "
            "there reads as a system with nothing to report, and an unchecked claim is not a "
            "satisfied one."
        )
        doc.preformatted([f"  {binding.get('unavailable_reason') or MISSING}"])
        return
    if not binding["events"]:
        doc.paragraph(
            "The binding report was obtained and contains no binding events for this assessment. "
            "That is itself a finding rather than a clean result: every assessment opened since "
            "backend/api/src/audit/binding.rs landed writes two of them in the same transaction "
            "as the request row, so an assessment with none either predates that change or had "
            "its events removed - and a removal breaks linkage, which section 3a is where to "
            "look for."
        )
        return

    doc.paragraph(
        "Each event below commits to the contents of a row this decision is judged on. The "
        "payload is not stored in audit_log - there is no column for it - so it was REBUILT from "
        "the rows as they stand at export time and is printed here in full. That is what makes "
        "this checkable rather than asserted: recompute the digest yourself and compare."
    )
    doc.preformatted(
        [
            "  event_hash = SHA256( framed(event_type) || framed(ref_id)",
            "                    || framed(prev_hash)  || framed(payload) )",
            "",
            "  framed(x)   an 8-byte big-endian length, then x",
            "  ref_id      the UUID's 16 raw bytes (empty when there is none)",
            "  prev_hash   the raw digest bytes (empty for the first event in the chain)",
            "  payload     canonical JSON of the payload below: sorted keys, no insignificant",
            "              whitespace, non-ASCII escaped - the same rule as section 5's digest",
        ]
    )
    doc.table(
        ["seq", "Event", "Binds", "event_hash"],
        [
            [
                _s(event["seq"]),
                event["event_type"],
                {
                    "decision_model_attestation_bound": "decision_model_attestations",
                    "disclosure_policy_bound": "disclosure_requests.policy",
                }.get(event["event_type"], "(see the payload)"),
                event["event_hash"][:16],
            ]
            for event in binding["events"]
        ],
    )
    for event in binding["events"]:
        doc.preformatted(
            [
                f"  seq {_s(event['seq'])}  {event['event_type']}",
                f"    ref_id      {event['ref_id']}",
                f"    prev_hash   {event['prev_hash']}",
                f"    event_hash  {event['event_hash']}",
                "    payload:",
            ]
            + (
                [
                    "      (none - the rows this event commits to no longer exist. The event "
                    "survives as a",
                    "       commitment that they did and to what they said; there is nothing "
                    "left to compare)",
                ]
                if event["rebuilt_payload"] is None
                else [
                    f"      {line}"
                    for line in json.dumps(
                        event["rebuilt_payload"], indent=2, sort_keys=True
                    ).splitlines()
                ]
            )
        )

    doc.paragraph(
        "What a match shows: the row still contains what it contained when the event was "
        "written. What it does not show: that the row was TRUE when it was written. The model "
        "attestation is a forward declaration made when the assessment was opened, before the "
        "proof existed and before any human reviewed it, and no digest can reach back and check "
        "it - see migrations/0009_model_attestation_corrections.sql for the route a firm has to "
        "contradict its own earlier declaration."
    )

    model = pack["model_attestation"]
    if not model.get("supplied"):
        doc.paragraph(
            "The sealed record's own model block was not obtained by this export, so the "
            "identity above could not be compared against the identity the record serves. "
            f"Reason: {model.get('unavailable_reason') or MISSING}"
        )
        return
    provenance = model.get("model_provenance") or {}
    declared = provenance.get("as_declared_at_open")
    if isinstance(declared, dict):
        doc.paragraph(
            "The record's own copy of what was declared when this assessment was opened - the "
            "exact row the binding event above commits to, preserved verbatim in the sealed "
            "bytes. Compare it with the payload above leaf for leaf: they must agree, nulls "
            "included."
        )
        doc.preformatted(
            [f"  {line}" for line in json.dumps(declared, indent=2, sort_keys=True).splitlines()]
        )
    if provenance.get("corrected"):
        doc.paragraph(
            f"This decision carries {_s(provenance.get('correction_count'))} filed correction(s), "
            "so the model block the record SERVES is the organisation's current statement and is "
            "expected to differ from the payload bound above. That difference is not tampering "
            "and must not be read as it - see section 3b's declaration copy for what was "
            "originally said, and migrations/0009_model_attestation_corrections.sql for why a "
            "correction is an append rather than an edit."
        )

    if model["model"] is None:
        doc.paragraph(
            "The sealed record serves model: null - a signed statement that no AI system "
            "participated in this decision. That is an answer, not a blank, and it is the "
            "strongest claim the schema can carry. It agrees with the binding payload above only "
            "if that payload's declaration reads no_ai_participated; if it reads anything else, "
            "the record and the chain contradict each other and neither should be relied on "
            "until that is explained."
        )
        return
    doc.paragraph(
        "The model block the record serves today, for comparison with the payload above. The "
        "offline bundle performs that comparison mechanically (docs/VERIFY.md step 7e); it is "
        "printed here so a reader of the paper can perform it by eye."
    )
    doc.preformatted(
        [f"  {line}" for line in json.dumps(model["model"], indent=2, sort_keys=True).splitlines()]
    )


def _section_3_chains(doc: Document, pack: dict) -> None:
    doc.heading("3. Audit chains", level=1)
    doc.paragraph(
        "Two independent, append-only hash chains cover this assessment: Memtara's own "
        "audit_log, and the relying party's AIHOOTS audit.jsonl. The systems never call each "
        "other. They are correlated by the proof digest and the regulatory_audit_id carried in "
        "the token, which is what lets an auditor holding both logs show they describe the same "
        "event - and what stops either operator fabricating a match without breaking a chain."
    )

    doc.heading("3a. Memtara audit_log excerpt", level=2)
    chain = pack["audit_chain_excerpt"]
    if not chain:
        doc.paragraph(
            "The evidence endpoint returned no audit events for this assessment. That should "
            "not happen for an assessment that was opened through the API - the request row and "
            "its audit entry are written in the same transaction - so treat an empty excerpt as "
            "a finding rather than as a formality."
        )
    else:
        doc.table(
            ["seq", "Event", "Created at", "prev_hash", "event_hash"],
            [
                [
                    _s(event["seq"]),
                    event["event_type"],
                    event["created_at"],
                    event["prev_hash"][:16],
                    event["event_hash"][:16],
                ]
                for event in chain
            ],
        )
        doc.paragraph(
            "Hashes are shown truncated to 16 characters for the table; the full values follow. "
            "seq is the position in the firm's global chain, so consecutive entries for this "
            "assessment are not expected to be adjacent - other assessments were interleaved."
        )
        doc.preformatted(
            [
                line
                for event in chain
                for line in (
                    f"  seq {_s(event['seq'])}  {event['event_type']}",
                    f"    event_hash  {event['event_hash']}",
                    f"    prev_hash   {event['prev_hash']}",
                )
            ]
        )

    _section_3b_binding(doc, pack)

    doc.heading("3c. AIHOOTS SHA-256 audit chain", level=2)
    aihoots = pack["aihoots"]
    if not aihoots.get("supplied"):
        doc.paragraph(
            "No AIHOOTS audit log was supplied to this export, so this section is empty. The "
            "section is printed anyway: an omitted section is worse than one that states its "
            "own absence, because a reader cannot tell an omission from a system that has no "
            "such record."
        )
        doc.paragraph(
            "What is missing as a result: the relying party's independent record of what its "
            "model was told about this assessment, and the verdict of AIHOOTS's own "
            "audit-verify over that record. Re-run the export with --aihoots-audit "
            "<path/to/audit.jsonl> to include it. Nothing about the proof, the verdict or "
            "sections 1, 2, 4 and 5 depends on it."
        )
        return

    doc.key_values(
        [
            ("Log", aihoots["path"]),
            ("Records read", _s(aihoots["records_total"])),
            ("Entries matching this assessment", _s(len(aihoots["matched"]))),
        ]
    )
    if aihoots.get("records_malformed"):
        doc.paragraph(
            f"{aihoots['records_malformed']} line(s) in the log were not valid JSON and were "
            "skipped by this exporter. audit-verify's own verdict below is the authoritative "
            "reading of that file."
        )

    if not aihoots["matched"]:
        doc.paragraph(
            "No entry in the supplied log carries a proof digest from this assessment. Either "
            "this is the wrong log, or the relying party never processed this assessment "
            "through its gateway. The linkage is by proof_hash: the digests in section 2b are "
            "what an entry must carry to appear here."
        )
    else:
        doc.paragraph(
            "Linked by proof digest: each entry below carries, in its own detail payload, one "
            "of the proof digests printed in section 2b. That digest is computed over the same "
            "proof bytes the server verified, so the linkage is cryptographic rather than "
            "clerical."
        )
        doc.table(
            ["seq", "Event", "Decision", "Caller", "record_hash"],
            [
                [
                    _s(entry["seq"]),
                    entry["event_type"],
                    entry["decision"],
                    entry["caller"],
                    entry["record_hash"][:16],
                ]
                for entry in aihoots["matched"]
            ],
        )
        doc.preformatted(
            [
                line
                for entry in aihoots["matched"]
                for line in (
                    f"  seq {_s(entry['seq'])}  {entry['event_type']}",
                    f"    proof_hash   {entry['proof_hash']}",
                    f"    record_hash  {entry['record_hash']}",
                    f"    prev_hash    {entry['prev_hash']}",
                )
            ]
        )
    if aihoots["proof_hashes_with_no_entry"]:
        doc.paragraph(
            "Proof digests from section 2b with no matching entry in this log (expected for "
            "rejected attempts, which never reach a relying party):"
        )
        doc.preformatted([f"  {digest}" for digest in aihoots["proof_hashes_with_no_entry"]])

    doc.heading("3d. audit-verify verdict", level=3)
    verify = aihoots["audit_verify"]
    if not verify.get("available"):
        doc.paragraph(
            "AIHOOTS's verifier could not be run, so this pack carries no verdict on the "
            "integrity of that chain. It deliberately does not substitute one of its own: a "
            "second implementation of the same walk would prove nothing if it agreed and would "
            "be indistinguishable from a bug in this tool if it did not."
        )
        doc.preformatted([f"  {verify.get('reason', MISSING)}"])
        return
    doc.paragraph(
        "Run as a subprocess against AIHOOTS's own pinned code, reproduced verbatim - exit "
        "code and both streams. Nothing here is this tool's paraphrase. A line wider than the "
        "page is clipped rather than re-flowed, with a '>' marking the cut; the untruncated "
        "text is part of the canonical evidence hashed in section 5."
    )
    lines = [f"  $ {verify['command']}", f"  exit code: {verify['exit_code']}"]
    for stream in ("stdout", "stderr"):
        text = verify.get(stream) or ""
        if text:
            lines.append(f"  --- {stream} ---")
            lines.extend(f"  {line}" for line in text.splitlines())
    doc.preformatted(lines)
    doc.paragraph(
        "Exit code 0 means every record's stored hash matches its recomputed contents and "
        "every prev_hash matches its predecessor. It means the log is internally consistent; "
        "it does not mean the log is complete. A hash chain proves nothing was altered, not "
        "that nothing was deleted from the end or never written - retention and off-box "
        "replication remain the firm's obligation."
    )
    doc.page_break()


def _section_4_regulatory(doc: Document, pack: dict) -> None:
    doc.heading("4. Regulatory mapping", level=1)
    doc.paragraph(
        "Neither Memtara nor the gateway is a Licensed Financial Institution or an Authorised "
        "Firm. Every obligation below binds the firm. What these systems supply is evidence - "
        "the artefact the firm hands its Audit and Risk Committee, or a regulator, to show a "
        "control was operating rather than asserted. This section maps what this pack "
        "evidences and is explicit about what it does not."
    )

    doc.heading("4a. DFSA Conduct of Business - the citation, both halves", level=2)
    mapping = pack["regulatory_mapping"]
    # Columns aligned by ljust rather than by counted spaces: a table drawn
    # with literal space runs is one edit away from being visibly crooked, and
    # crookedness in a regulator's copy reads as carelessness about the rest.
    def row(label: str, value: str) -> str:
        return "  " + label.ljust(40) + value

    doc.preformatted(
        [
            row("Claim value emitted in Memtara tokens", ", ".join(mapping["dfsa_claim_values"])),
            row(
                "Correct citation for a DFSA filing",
                f"{DFSA_CORRECT_RULE}  (Suitability; the assessment at COB 3.4.2)",
            ),
            row(f"What {DFSA_EMITTED_CLAIM} actually is", "Application"),
        ]
    )
    doc.paragraph(
        f"The discrepancy, in one sentence: Memtara's tokens and audit records emit the string "
        f"{DFSA_EMITTED_CLAIM} because that is the identifier the relying parties integrating "
        f"against this system were told to match, while the rule this assessment actually "
        f"discharges is {DFSA_CORRECT_RULE} (Suitability) - {DFSA_EMITTED_CLAIM} is titled "
        "Application - so a deployment filing evidence with the DFSA should cite "
        f"{DFSA_CORRECT_RULE} and treat the claim value as an integration contract rather than "
        "as a citation."
    )
    doc.paragraph(
        "Changing the emitted string unilaterally would break every relying party matching on "
        "it, which is why it has not been changed silently. It is a free-text list and one "
        "line changes it; the decision belongs to the firm, not to the vendor. This is "
        "recorded the same way in docs/REGULATORY_MATRIX.md."
    )
    doc.paragraph(
        "A caveat that applies to this section and not to the CBUAE one below: the DFSA "
        "Rulebook is NOT vendored in this repository, and its current rule text was not "
        "retrievable in a form that could be quoted. The section titles are confirmed; the "
        "substance is taken from an archived version (COB/VER7/08-06, S.6.2.1) whose wording "
        "may since have changed. Read the mapping as being against the substance of a "
        "suitability obligation and verify the current text before relying on it."
    )
    doc.table(
        ["Obligation", "What this pack shows", "Remains the firm's"],
        [
            [
                "A recommendation must be suitable, having regard to objectives and risk "
                "tolerance.",
                "risk_tolerance >= product_risk_level is one of the four limbs, evaluated "
                "in-circuit against the registered risk level.",
                "Investment objectives are not modelled by the circuit, and any relevant fact "
                "outside the four limbs still has to be acted on.",
            ],
            [
                "The assessment must precede the recommendation.",
                "The terms were registered and the nonce issued before the client was asked; "
                "the token is minted only after a proof against those terms verifies.",
                "Not making recommendations outside the gated channel.",
            ],
            [
                "The firm must be able to demonstrate it assessed.",
                "This document, re-verifiable years later against the published verification "
                "key and JWKS without Memtara or the firm.",
                "Retaining both logs for the applicable period.",
            ],
            [
                "A decline must be evidenced as much as an approval.",
                "suitable is a public output, not an assertion, so a proof of NOT SUITABLE "
                "exists and is attested identically.",
                "Acting on the decline.",
            ],
            [
                "The criteria must be the firm's, not the client's.",
                "Section 1d: terms from the product registry, snapshotted at open, compared "
                "against every submitted public input.",
                "Maintaining the product master.",
            ],
            [
                "Records must be retained (six years in the archived version).",
                "Not covered. A hash chain proves internal consistency, not availability - an "
                "operator can still delete a whole log.",
                "Retention, off-box replication, append-only storage.",
            ],
        ],
    )
    doc.paragraph(
        "One limit worth naming while a reader is looking at the four limbs: the rule "
        "enumerates objectives and risk tolerance. It does not mandate an income floor, a "
        "liquidity floor or a concentration cap - those are the firm's own suitability policy, "
        "which is the correct shape for a rule that delegates the criteria to the firm. The "
        "circuit implements a policy, and this pack evidences that the policy was applied "
        "before the recommendation and can be shown."
    )

    doc.heading("4b. CBUAE Guidance Note", level=2)
    doc.paragraph(
        "Guidance Note on Consumer Protection and the Responsible Adoption and Use of "
        "Artificial Intelligence and Machine Learning by Licensed Financial Institutions in "
        "the U.A.E. (CBUAE_EN_6958_VER1). Unlike the DFSA rulebook, this document is vendored "
        "in the repository and every clause below was read from it. Clause identifiers follow "
        "the document's own scheme - numbered sections, lettered sub-clauses; there is no "
        "section 4.3 or 5.2 despite what some briefs assume."
    )
    clauses = mapping["cbuae"]
    if not clauses:
        doc.paragraph("The evidence response carried no CBUAE clause mapping for this assessment.")
    else:
        doc.table(
            ["Clause", "What it requires", "What this pack shows"],
            [
                [
                    f"S.{clause}",
                    CBUAE_CLAUSES.get(clause, ("see docs/REGULATORY_MATRIX.md", ""))[0],
                    CBUAE_CLAUSES.get(clause, ("", "not glossed by this tool"))[1],
                ]
                for clause in clauses
            ],
        )
    doc.paragraph(
        "The gaps a reader should carry away, unchanged from the matrix: bias measurement "
        "(S.3(a)) and training-data representativeness (S.3(b)) are not covered by either "
        "system; bilingual disclosure (S.4(b)) is specified but not built; the complaints and "
        "redress half of S.7(c) does not exist in either system; and the proof token is not "
        "revocable inside its short lifetime, which is a deliberate trade for offline "
        "validation rather than an oversight. Nothing in this section is a legal opinion or a "
        "substitute for the firm's own compliance assessment."
    )
    doc.page_break()


def _section_5_seal(
    doc: Document,
    pack: dict,
    *,
    canonical_sha256: str,
    seal_filename: str,
    signing_public_key_hex: str | None,
) -> None:
    doc.heading("5. Cryptographic seal", level=1)

    doc.heading("5a. Digest of the evidence", level=2)
    doc.paragraph(
        "Everything this pack asserts is also serialised as canonical JSON - sorted keys, no "
        "insignificant whitespace, the same convention the AIHOOTS chain uses for its record "
        "hashes - and hashed. Recomputing this digest from a fresh export of the same "
        "assessment reproduces it exactly; a different value means the underlying record moved."
    )
    doc.preformatted([f"  canonical evidence SHA-256  {canonical_sha256}"])
    doc.paragraph(
        "The digest deliberately excludes the export timestamp and the tool version, so it "
        "identifies the evidence rather than the run that printed it. Those two live in the "
        "sidecar."
    )

    doc.heading("5b. Digest of this document", level=2)
    doc.paragraph(
        "The SHA-256 of the finished PDF bytes cannot appear inside those same bytes - a "
        "document cannot contain its own digest. It is written to the sidecar file alongside "
        "this one:"
    )
    doc.preformatted([f"  {seal_filename or '<output>.seal.json'}"])
    doc.paragraph(
        "To check this copy is the one that was sealed: "
        "shasum -a 256 <this file>, and compare with pdf.sha256 in the sidecar. The exporter's "
        "own verify subcommand does the same thing and also re-checks the signature."
    )

    doc.heading("5c. What the seal is not", level=2)
    doc.paragraph(
        "This is NOT a PAdES or AdES signature. It is not embedded in the PDF, it is not a "
        "qualified or advanced electronic signature under any framework, and no PDF viewer "
        "will show a green tick or a signature panel for it. Any reader who opens this file "
        "expecting the viewer to vouch for it will be told nothing, and that is the expected "
        "behaviour rather than a fault in the file."
    )
    doc.paragraph(
        "Nor is the strongest claim in this pack the exporter's own. That is the Memtara-issued "
        "JWT of section 2e, verifiable against the issuer's published JWKS by anyone, with no "
        "call to Memtara and no cooperation from the firm - and behind it the proof itself, "
        "re-verifiable against the published verification key. The seal below covers the paper. "
        "Those cover the facts."
    )

    doc.heading("5d. Authentication status of this pack", level=2)
    if signing_public_key_hex:
        doc.paragraph(
            "This pack was signed. The sidecar carries a raw Ed25519 detached signature over "
            "the exact PDF bytes, made with the key supplied to the exporter by the person who "
            "produced this pack."
        )
        doc.preformatted(
            [
                "  algorithm       Ed25519 (RFC 8032), detached, raw",
                "  signed over     the finished PDF bytes",
                f"  public key      {signing_public_key_hex}",
            ]
        )
        doc.paragraph(
            "One honest limitation. The sidecar also carries this public key, so verifying the "
            "signature against the key in the sidecar proves only that the two files agree - "
            "anyone who can replace both can produce a consistent pair. It becomes an "
            "authenticity check only when the verifier already holds the expected public key "
            "from somewhere other than the sidecar: the firm's key register, a published "
            "fingerprint, an email from a named signer. The verify subcommand accepts an "
            "expected key for exactly that reason."
        )
    else:
        doc.paragraph(
            "This pack is UNSIGNED. No signing key was supplied to the exporter, so the pack is "
            "tamper-evident - the digests above will not match an altered copy - but "
            "unauthenticated: nothing here establishes who produced it."
        )
        doc.paragraph(
            "The exporter deliberately did not generate a key of its own to sign with. An "
            "ephemeral signature verifies against a key nobody holds and means nothing, while "
            "looking exactly like a signature that means something. Re-run with --signing-key "
            "to sign with a key the firm actually controls."
        )

    doc.heading("5e. How to re-verify all of this without the firm", level=2)
    doc.bullet(
        "Step 1. Check the token in section 2e against the issuer's published JWKS with any "
        "JOSE library. Prefer the pinned snapshot in an offline verification bundle "
        "(jwks_snapshot.json, see docs/VERIFY.md step 8) over a live fetch: a key set "
        "retrieved today evidences today's DNS, not this issuance, and a live fetch stops "
        "working the day the issuer or that key goes away."
    )
    doc.bullet(
        "Step 2. Take the proof bytes and the public inputs from the firm's records and run bb "
        "verify against the verification key whose digest is in section 2a, target "
        + pack["verification_key"]["verifier_target"]
        + "."
    )
    doc.bullet(
        f"Step 3. Read public input {OUTCOME_INDEX}. It is the verdict in section 2d. Do not "
        "read the exit code as the verdict."
    )
    doc.bullet(
        "Step 4. Re-run AIHOOTS's audit-verify over the relying party's log to confirm nothing "
        "moved, and match the entries by the proof digest in section 3c."
    )
    doc.bullet(
        "Step 5. Compare the SHA-256 of this PDF with the sidecar, and the signature if there "
        "is one."
    )
    doc.paragraph(
        "Step 2 is what distinguishes this from a signed PDF of a spreadsheet. The firm cannot "
        "produce a proof that verifies against that key unless the assessment really was "
        "carried out over a vault committed to the root recorded at the time - and neither can "
        "Memtara."
    )


# ---------------------------------------------------------------------------
# The seal
# ---------------------------------------------------------------------------


def load_signing_key(path: Path):
    """Load an Ed25519 private key from PEM, or from a raw 32-byte seed.

    PEM first because that is what `openssl genpkey -algorithm ed25519`
    produces and what a bank's key management is likely to hand over. The raw
    seed forms are accepted because this repository already uses them
    (`MEMTARA_PRIVATE_KEY` is base64 of 32 bytes) and a tool that refused the
    format its own deployment uses would push people towards converting keys
    by hand.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    data = path.read_bytes()

    try:
        mode = path.stat().st_mode
    except OSError:  # pragma: no cover - stat on an unreadable path already raised
        mode = 0
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(
            f"warning: {path} is readable by group or other; a signing key that other local "
            "accounts can read cannot evidence who signed",
            file=sys.stderr,
        )

    if data.lstrip().startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise ExportError(
                f"--signing-key {path}: PEM could not be loaded (encrypted keys are not "
                f"supported; decrypt it first): {exc}"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ExportError(
                f"--signing-key {path}: this is a {type(key).__name__}, and the seal format is "
                "Ed25519 only. A seal that silently accepted another algorithm would produce "
                "sidecars no verifier could read."
            )
        return key

    text = data.strip().decode("utf-8", "replace")
    for decode in (
        lambda s: bytes.fromhex(s),
        lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=True),
        lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
    ):
        try:
            seed = decode(text)
        except (ValueError, binascii.Error):
            continue
        if len(seed) == 32:
            return Ed25519PrivateKey.from_private_bytes(seed)
    if len(data) == 32:
        return Ed25519PrivateKey.from_private_bytes(data)

    raise ExportError(
        f"--signing-key {path}: not a PEM Ed25519 private key and not a 32-byte seed in hex, "
        "base64 or raw bytes"
    )


def build_seal(
    *,
    pdf_bytes: bytes,
    pdf_path: Path,
    canonical_sha256: str,
    request_id: str,
    created_at: datetime,
    signing_key=None,
) -> dict:
    seal = {
        "seal_version": SEAL_VERSION,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "request_id": request_id,
        "pdf": {
            "filename": pdf_path.name,
            "bytes": len(pdf_bytes),
            "sha256": sha256_hex(pdf_bytes),
        },
        "canonical_evidence_sha256": canonical_sha256,
        "signature": None,
        "what_this_is_not": (
            "Not a PAdES/AdES signature and not embedded in the PDF; no viewer will show a "
            "signature panel for it. The strongest authenticity claim in the pack is the "
            "Memtara-issued JWT verifiable against the issuer's published JWKS, not this seal."
        ),
    }
    if signing_key is None:
        seal["authentication"] = (
            "UNSIGNED. Tamper-evident by digest, unauthenticated as to origin. No ephemeral "
            "key was generated: a signature verifying against a key nobody holds is worse "
            "than none, because it looks like one that means something."
        )
        return seal

    public_key = signing_key.public_key().public_bytes_raw()
    seal["signature"] = {
        "algorithm": "Ed25519",
        "encoding": "raw, detached, hex",
        "signed_over": "the PDF bytes named above, exactly as written",
        "public_key_hex": public_key.hex(),
        "signature_hex": signing_key.sign(pdf_bytes).hex(),
        "caveat": (
            "The public key is carried here for identification. Verifying against it proves "
            "only that this sidecar and that PDF agree; authenticity requires the verifier to "
            "already hold the expected key from elsewhere (memtara-export verify --public-key)."
        ),
    }
    return seal


def verify_seal(pdf_path: Path, seal_path: Path, expected_public_key_hex: str | None = None) -> tuple[bool, list[str]]:
    """Re-check a pack. Returns (ok, lines to print)."""
    lines: list[str] = []
    ok = True

    if not pdf_path.exists():
        return False, [f"FAIL  no such PDF: {pdf_path}"]
    if not seal_path.exists():
        return False, [f"FAIL  no such seal: {seal_path}"]

    pdf_bytes = pdf_path.read_bytes()
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return False, [f"FAIL  {seal_path} is not valid JSON: {exc}"]
    if not isinstance(seal, dict):
        return False, [f"FAIL  {seal_path} does not contain a JSON object"]

    lines.append(f"pdf   {pdf_path}")
    lines.append(f"seal  {seal_path}")
    lines.append(f"      produced {seal.get('created_at', MISSING)} by {seal.get('tool', MISSING)} {seal.get('tool_version', '')}".rstrip())

    recorded = _get(seal, "pdf", "sha256")
    actual = sha256_hex(pdf_bytes)
    if recorded == actual:
        lines.append(f"PASS  pdf sha256 matches      {actual}")
    else:
        ok = False
        lines.append("FAIL  pdf sha256 does NOT match the seal")
        lines.append(f"      sealed    {_s(recorded)}")
        lines.append(f"      this file {actual}")

    recorded_bytes = _get(seal, "pdf", "bytes")
    if isinstance(recorded_bytes, int) and recorded_bytes != len(pdf_bytes):
        ok = False
        lines.append(f"FAIL  pdf is {len(pdf_bytes)} bytes, the seal records {recorded_bytes}")

    # Cross-check that the sidecar describes *this* document rather than
    # another one with the same name. The canonical digest is printed in the
    # PDF and pdf.py writes uncompressed content streams on purpose, so the
    # string is findable in the bytes. If someone turns on /FlateDecode this
    # check breaks loudly, which is the correct failure for a check whose
    # premise stopped holding.
    canonical = seal.get("canonical_evidence_sha256")
    if isinstance(canonical, str) and canonical:
        if canonical.encode("ascii") in pdf_bytes:
            lines.append("PASS  evidence digest is stated in the pdf")
        else:
            ok = False
            lines.append(
                "FAIL  the canonical evidence digest in the seal does not appear in the pdf; "
                "these two files are not a pair"
            )
    else:
        ok = False
        lines.append("FAIL  the seal carries no canonical_evidence_sha256")

    signature = seal.get("signature")
    if signature is None:
        lines.append(
            "NOTE  this pack is UNSIGNED: digests check out, origin is not established"
        )
        if expected_public_key_hex:
            ok = False
            lines.append("FAIL  a public key was expected but the pack carries no signature")
    else:
        ok = _verify_signature(signature, pdf_bytes, expected_public_key_hex, lines) and ok

    lines.append("OK    pack verifies" if ok else "BAD   pack does not verify")
    return ok, lines


def _verify_signature(signature: Any, pdf_bytes: bytes, expected_public_key_hex: str | None, lines: list[str]) -> bool:
    if not isinstance(signature, dict):
        lines.append("FAIL  the seal's signature field is not an object")
        return False
    if signature.get("algorithm") != "Ed25519":
        lines.append(f"FAIL  unsupported signature algorithm {signature.get('algorithm')!r}")
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover - cryptography is a declared dependency
        lines.append("FAIL  cryptography is not installed, so the signature cannot be checked")
        return False

    try:
        public_bytes = bytes.fromhex(signature.get("public_key_hex", ""))
        signature_bytes = bytes.fromhex(signature.get("signature_hex", ""))
    except ValueError:
        lines.append("FAIL  the signature or public key in the seal is not valid hex")
        return False

    if expected_public_key_hex:
        expected = expected_public_key_hex.strip().lower()
        if public_bytes.hex() != expected:
            lines.append("FAIL  the seal was signed by a different key than the one expected")
            lines.append(f"      expected {expected}")
            lines.append(f"      sealed   {public_bytes.hex()}")
            return False
        lines.append("PASS  signing key matches the expected key")

    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, pdf_bytes)
    except (InvalidSignature, ValueError) as exc:
        lines.append(f"FAIL  Ed25519 signature does not verify over the pdf bytes ({exc})")
        return False

    lines.append(f"PASS  Ed25519 signature verifies  key {public_bytes.hex()}")
    if not expected_public_key_hex:
        lines.append(
            "NOTE  verified against the key inside the seal itself: this shows the two files "
            "agree, not who made them. Pass --public-key to check authorship."
        )
    return True


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def render_and_seal(
    pack: dict,
    output: Path,
    *,
    created_at: datetime | None = None,
    signing_key=None,
    source_url: str = "",
) -> dict:
    """Render a pack to `output` and write `<output>.seal.json` beside it.

    Split out of `export()` so that everything after the network call is
    reachable without a server: the document, the digests and the seal are the
    parts with properties worth testing, and a test that had to reimplement
    this sequence would be testing its own copy of it.
    """
    moment = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    canonical_sha256 = sha256_hex(canonical_bytes(pack))
    seal_path = Path(str(output) + ".seal.json")

    document = build_document(
        pack,
        canonical_sha256=canonical_sha256,
        created_at=moment,
        source_url=source_url,
        seal_filename=seal_path.name,
        signing_public_key_hex=(
            signing_key.public_key().public_bytes_raw().hex() if signing_key else None
        ),
    )
    pdf_bytes = document.render()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(pdf_bytes)

    seal = build_seal(
        pdf_bytes=pdf_bytes,
        pdf_path=output,
        canonical_sha256=canonical_sha256,
        request_id=pack["request_id"],
        created_at=moment,
        signing_key=signing_key,
    )
    seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "pdf": output,
        "seal": seal_path,
        "pdf_bytes": pdf_bytes,
        "pdf_sha256": seal["pdf"]["sha256"],
        "canonical_sha256": canonical_sha256,
        "verdict": _verdict_words(pack),
        "signed": signing_key is not None,
        "pack": pack,
    }


def export(
    *,
    request_id: str,
    output: Path,
    base_url: str,
    api_key: str,
    aihoots_audit: Path | None = None,
    proof_token: str | None = None,
    signing_key_path: Path | None = None,
    created_at: datetime | None = None,
) -> dict:
    """Fetch, build, render, seal. Returns a summary for the caller to print."""
    if not api_key:
        raise ExportError(
            "no organisation API key: pass --org-api-key or set MEMTARA_ORG_API_KEY. The key "
            "is what scopes the evidence endpoint to this firm's own assessments."
        )

    # Loaded before anything is fetched or rendered. A bad key path should
    # fail in the first second, not after a render that then cannot be sealed.
    signing_key = load_signing_key(signing_key_path) if signing_key_path else None

    evidence = fetch_evidence(base_url, request_id, api_key)
    token = decode_proof_token(proof_token) if proof_token else None

    # A failure here does not stop the export. The binding check is one claim
    # among several and the rest of the pack — the proof, the verdict, the
    # chain excerpt — is unaffected by not having it; refusing to write a case
    # file because a second endpoint was unreachable would trade a partial
    # record for none. What must not happen is the failure going unrecorded,
    # so the reason travels inside the sealed bytes and section 3c prints it.
    try:
        binding = collect_binding(
            fetch_decision_evidence(base_url, request_id, api_key), request_id
        )
    except BindingUnavailable as exc:
        binding = collect_binding(None, request_id, reason=str(exc))

    pack = build_pack(evidence, token=token, binding=binding)
    if aihoots_audit is not None:
        # Attached after the fact because the linkage runs the other way: the
        # AIHOOTS entries are selected by the proof digests the pack already
        # carries, so the pack has to exist before the log can be searched.
        pack["aihoots"] = collect_aihoots(aihoots_audit, pack_proof_hashes(pack))

    return render_and_seal(
        pack,
        output,
        created_at=created_at,
        signing_key=signing_key,
        source_url=f"{base_url.rstrip('/')}/api/v1/wealth-assessments/{normalise_request_id(request_id)}",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _export_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memtara-export",
        description="Export the Canonical Case File for one suitability assessment.",
        epilog="memtara-export verify <pdf> [seal]  re-checks a pack that was already written.",
    )
    parser.add_argument("--request-id", required=True, help="assessment id (uuid, or req_<uuid>)")
    parser.add_argument("--output", required=True, type=Path, help="path of the PDF to write")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("MEMTARA_BASE_URL", DEFAULT_BASE_URL),
        help=f"issuing server (default {DEFAULT_BASE_URL}, or MEMTARA_BASE_URL)",
    )
    parser.add_argument(
        "--org-api-key",
        default=os.environ.get("MEMTARA_ORG_API_KEY", ""),
        help="organisation API key; defaults to MEMTARA_ORG_API_KEY",
    )
    parser.add_argument(
        "--aihoots-audit",
        type=Path,
        help="path to the relying party's AIHOOTS audit.jsonl",
    )
    parser.add_argument(
        "--proof-token",
        help="the JWT Memtara issued, or @path to read it from a file. The server does not "
        "retain it, so it can only appear in the pack if you supply it.",
    )
    parser.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 private key (PEM, or a 32-byte seed) to sign the finished PDF with. "
        "Without it the pack is tamper-evident but unauthenticated, and says so.",
    )
    return parser


def _verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memtara-export verify",
        description="Re-check a case file against its .seal.json.",
    )
    parser.add_argument("pdf", type=Path)
    parser.add_argument(
        "seal",
        type=Path,
        nargs="?",
        help="defaults to <pdf>.seal.json",
    )
    parser.add_argument(
        "--public-key",
        help="expected Ed25519 public key, hex. Supply it and the check becomes one of "
        "authorship rather than of internal consistency.",
    )
    return parser


def _verify_command(argv: list[str]) -> int:
    args = _verify_parser().parse_args(argv)
    seal_path = args.seal or Path(str(args.pdf) + ".seal.json")
    ok, lines = verify_seal(args.pdf, seal_path, args.public_key)
    for line in lines:
        print(line, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def _export_command(argv: list[str]) -> int:
    args = _export_parser().parse_args(argv)
    result = export(
        request_id=args.request_id,
        output=args.output,
        base_url=args.base_url,
        api_key=args.org_api_key,
        aihoots_audit=args.aihoots_audit,
        proof_token=read_proof_token_argument(args.proof_token) if args.proof_token else None,
        signing_key_path=args.signing_key,
    )
    print(f"verdict            {result['verdict']}", file=sys.stderr)
    print(f"evidence sha256    {result['canonical_sha256']}", file=sys.stderr)
    print(f"pdf sha256         {result['pdf_sha256']}", file=sys.stderr)
    print(f"seal               {result['seal']}", file=sys.stderr)
    if not result["signed"]:
        print(
            "note               unsigned: tamper-evident, but nothing establishes who "
            "produced it (--signing-key)",
            file=sys.stderr,
        )
    print(result["pdf"])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] == "verify":
            return _verify_command(args[1:])
        if args and args[0] == "export":
            args = args[1:]
        return _export_command(args)
    except ExportError as exc:
        print(f"memtara-export: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
