"""Operations on the evidence record that both halves of the bundle need.

This module is duplicated into every bundle that gets built, because the
verifier has to run on a machine that has this repository nowhere on it. That
duplication is the reason the functions here are small, stdlib-only and
deliberately boring: anything with a dependency could not travel.

Two constants are re-stated here rather than imported from the backend, and
the reason is the same one `export_audit_evidence.py` gives for duplicating
its own public-input table: a Rust file is not importable from Python, and a
verifier must run against a deployment whose source nobody has checked out.
Both are guarded — `verify/mod.rs::public_input_template_names_every_position_in_circuit_order`
on the Rust side, and the evidence record's own `outcome.read_from` string on
this side, which the verifier compares against `OUTCOME_INDEX` and reports on
rather than assuming.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

# 12 field elements, 32 bytes each, big-endian, in `main`'s declaration order
# with the public return value last. See circuits/wealth_suitability/vkey/README.md.
PUBLIC_INPUT_NAMES = [
    "current_time",
    "expiry_time",
    "vault_root",
    "product_ref",
    "min_income",
    "min_liquidity",
    "max_concentration_percent",
    "product_risk_level",
    "user_public_key_x",
    "user_public_key_y",
    "nonce",
    "suitable",
]

FIELD_BYTES = 32
OUTCOME_INDEX = 11
BB_VERIFIER_TARGET = "noir-recursive"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    """Byte-for-byte the serialisation `export_audit_evidence.canonical_bytes` produces.

    Restated rather than imported so a bundle can be verified without this
    repository. `tests/test_bundle.py` asserts the two agree on a real pack;
    if they ever diverge, every seal digest in the field stops reproducing and
    that test is where it gets caught.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def select_subject_proof(pack: dict) -> dict | None:
    """The proof the bundle is about.

    Identical selection to `export_audit_evidence._section_2_receipt`: the
    accepted proof if there is one, otherwise the first attempt. The bundle
    and the PDF must be about the same proof or an examiner comparing the two
    is comparing different assessments.
    """
    proofs = pack.get("proofs") or []
    for proof in proofs:
        if proof.get("accepted_by_bb_verify"):
            return proof
    return proofs[0] if proofs else None


def field_hex_to_bytes(index: int, value: str) -> bytes:
    """One 0x-hex field element to its 32-byte big-endian encoding.

    Mirrors `backend/api/src/verify/mod.rs::parse_field_hex`, which is the
    function whose output the server actually handed to `bb`. Reproducing the
    packing exactly is what lets an auditor rebuild `proof/public_inputs`
    from the JSON record and get the same bytes rather than having to trust
    the file shipped beside it.
    """
    if not isinstance(value, str):
        raise ValueError(f"public_inputs[{index}] is {type(value).__name__}, expected a string")
    stripped = value[2:] if value[:2].lower() == "0x" else None
    if stripped is None:
        raise ValueError(f"public_inputs[{index}]: expected a 0x-prefixed hex string, got {value!r}")
    if not stripped or len(stripped) > 64 or not all(c in "0123456789abcdefABCDEF" for c in stripped):
        raise ValueError(
            f"public_inputs[{index}]: not a valid field element (up to 64 hex digits after 0x)"
        )
    return bytes.fromhex(stripped.rjust(64, "0"))


def pack_public_inputs(values: list[str]) -> bytes:
    """The `public_inputs` file bb reads: the field elements concatenated, in order."""
    return b"".join(field_hex_to_bytes(index, value) for index, value in enumerate(values))


def outcome_from_public_inputs(values: list[str]) -> bool | None:
    """Read the verdict out of index 11, or None if it is not there to read.

    This is the decision. It is not the exit code of `bb verify`, and nothing
    in this module ever derives one from the other.
    """
    if len(values) <= OUTCOME_INDEX:
        return None
    try:
        raw = field_hex_to_bytes(OUTCOME_INDEX, values[OUTCOME_INDEX])
    except ValueError:
        return None
    as_int = int.from_bytes(raw, "big")
    if as_int == 1:
        return True
    if as_int == 0:
        return False
    # A field element that is neither 0 nor 1 in the return position is not a
    # verdict at all. Reported as unreadable rather than coerced to a boolean.
    return None


def verdict_words(suitable: bool | None) -> str:
    if suitable is True:
        return "SUITABLE"
    if suitable is False:
        return "NOT SUITABLE"
    return "NOT ASSESSED"


# ---------------------------------------------------------------------------
# Binding events
#
# WHY THIS CODE EXISTS AT ALL, GIVEN THE SERVER ALREADY REPORTS A VERDICT
# ---------------------------------------------------------------------------
# `GET /orgs/:id/audit-log/replay` and the `binding_integrity` envelope on
# `GET /api/v1/wealth-assessments/:id/decision-evidence` both return a
# `verdict`. Carrying that verdict into a bundle and printing it would add
# nothing an examiner could act on: Memtara built the bundle, so Memtara's own
# statement about the bundle is not evidence about it. The bundle therefore
# carries the INPUTS to the hash — event_type, ref_id, prev_hash, the recorded
# digest and the rebuilt payload — and this module recomputes the digest in
# Python, on the examiner's machine, from those inputs alone. What is
# deliberately NOT carried is the server's `result`, `recomputed_event_hash`
# and `verdict` fields; see `build_bundle.py`'s description of the file.
#
# THE CONSTRUCTION, AND WHERE IT COMES FROM
# ---------------------------------------------------------------------------
# `backend/api/src/audit/mod.rs::compute_event_hash`, reproduced exactly:
#
#     event_hash = SHA256( framed(event_type)
#                       || framed(ref_id)
#                       || framed(prev_hash)
#                       || framed(payload) )
#
# where `write_framed` in that file prepends an 8-byte big-endian length to
# each component before hashing. The framing is not decoration: without it,
# event_type="ab" + payload="cd" and event_type="a" + payload="bcd" hash the
# same, and the split between two adjacent fields becomes forgeable.
#
#   * `ref_id` is the UUID's 16 RAW bytes — `id.as_bytes()` on the Rust side,
#     not its 36-character text form — and the empty string when there is none.
#   * `prev_hash` is the predecessor's raw 32-byte digest, and the empty string
#     for the first event in the chain. The bundle carries it base64url
#     (unpadded), the encoding `audit/mod.rs::encode_b64` uses.
#   * `payload` is the payload's canonical JSON bytes. Rust hashes
#     `serde_json::to_vec(payload)`, and `canonical_bytes` above is Python's
#     rule; the two agree over the value domain `evidence/canonical.rs`
#     permits, and `audit/binding.rs::guard_cross_verifier_reproducible`
#     refuses at WRITE time to record any binding payload where they do not.
#     That guard is what makes the equality below safe to rely on rather than
#     hope for — and `tests/test_bundle.py` checks it against a bundle built
#     from a live server rather than taking the guard's word for it.
#
# The payload the bundle carries is the payload as it stands NOW, disagreement
# included. If it disagrees with the recorded digest, that disagreement IS the
# finding, and hiding it would defeat the point of shipping it.
# ---------------------------------------------------------------------------

BINDING_EVENTS_FILENAME = "audit_binding_events.jsonl"

#: The keys of a `decision_model_attestation_binding/v1` payload that name the
#: model, mapped to the leaf of `DecisionEvidence.model` each one must agree
#: with. Kept as data rather than as a chain of `if`s so that a leaf added on
#: one side and not the other is visible as a missing entry.
BOUND_MODEL_LEAVES = {
    "model_provider": "provider",
    "model_name": "model_name",
    "model_version": "model_version",
    "prompt_version": "prompt_version",
    "model_environment": "environment",
    "model_config_fingerprint": "config_fingerprint",
    "model_system_prompt_or_policy_id": "system_prompt_or_policy_id",
    "model_timestamp": "timestamp",
}

#: `decision_model_attestations.declaration` — the closed set migrations/0006's
#: CHECK constraint permits. `no_ai_participated` is the one that matters here:
#: it is a SIGNED ASSERTION that no AI took part, and the record expresses it as
#: `model: null`. It is structurally different from `participated_but_unidentified`,
#: which is an AI nobody can name, and a check that treated the two alike would
#: have broken the product's central claim.
DECLARATION_NO_AI = "no_ai_participated"
DECLARATION_IDENTIFIED = "model_identified"
DECLARATION_UNIDENTIFIED = "participated_but_unidentified"

MODEL_ATTESTATION_BOUND = "decision_model_attestation_bound"


class BindingError(ValueError):
    """A carried binding event could not be recomputed. Never a verdict about the data."""


def b64url_decode(value: str) -> bytes:
    """The inverse of `audit/mod.rs::encode_b64` (URL-safe, no padding)."""
    if not isinstance(value, str):
        raise BindingError(f"expected a base64url string, got {type(value).__name__}")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise BindingError(f"not valid base64url: {value!r} ({exc})") from exc


def framed(data: bytes) -> bytes:
    """One component, length-prefixed exactly as `audit/mod.rs::write_framed` does."""
    return len(data).to_bytes(8, "big") + data


def uuid_bytes(value: Any) -> bytes:
    """A UUID's 16 raw bytes, or b"" when there is none.

    Parsed by hand rather than with `uuid.UUID` so this module stays importable
    on an interpreter with nothing but the standard library present — which it
    already is, but more importantly so the rejection is specific: a `ref_id`
    that is not a UUID means the bundle carries an event this construction
    cannot reproduce, and that must not degrade into hashing its text form.
    """
    if value is None:
        return b""
    text = str(value).strip().replace("urn:uuid:", "")
    hex_only = text.replace("-", "")
    if len(hex_only) != 32 or any(c not in "0123456789abcdefABCDEF" for c in hex_only):
        raise BindingError(
            f"ref_id {value!r} is not a UUID. audit/mod.rs hashes the UUID's 16 raw bytes, so "
            "there is no defensible way to fold this value into the digest"
        )
    return bytes.fromhex(hex_only)


def binding_event_hash(event_type: str, ref_id: Any, prev_hash_b64: Any, payload: Any) -> bytes:
    """Recompute one event's `event_hash` from the material the bundle carries."""
    if not isinstance(event_type, str) or not event_type:
        raise BindingError("event_type is missing, so the first framed component is unknown")
    digest = hashlib.sha256()
    digest.update(framed(event_type.encode("utf-8")))
    digest.update(framed(uuid_bytes(ref_id)))
    digest.update(framed(b"" if prev_hash_b64 in (None, "") else b64url_decode(prev_hash_b64)))
    digest.update(framed(canonical_bytes(payload)))
    return digest.digest()


def recompute_binding_event(event: dict) -> dict:
    """Recompute one carried event and say what came out.

    Four outcomes, matching `audit/replay.rs::ReplayResult` in meaning but
    reached independently — nothing here reads the server's own `result`, and
    the bundle does not carry it. "intact" and "altered" are the obvious pair;
    the other two exist because collapsing them into "altered" would tell an
    examiner the wrong thing to do. A binding whose source row is gone and one
    whose source row was edited are different incidents, and an event this
    verifier cannot reproduce at all is a defect in the verifier until it is
    explained, not an accusation about the data.
    """
    recorded = event.get("event_hash")
    out = {
        "seq": event.get("seq"),
        "event_type": event.get("event_type"),
        "ref_id": event.get("ref_id"),
        "recorded_event_hash": recorded,
        "recomputed_event_hash": None,
        "result": None,
        "detail": "",
    }
    if "rebuilt_payload" not in event:
        out["result"] = "unverifiable"
        out["detail"] = (
            "the carried event has no `rebuilt_payload` key at all, so there is nothing to hash. "
            "A bundle built by scripts/bundle/build_bundle.py always writes the key, null "
            "included, so this file was written by something else"
        )
        return out
    if event["rebuilt_payload"] is None:
        out["result"] = "source_row_missing"
        out["detail"] = (
            "the rows this event commits to no longer existed when the bundle was built, so no "
            "payload could be rebuilt from them. The event survives as a commitment that they "
            "did exist and to what they said; there is nothing left here to compare it against"
        )
        return out
    try:
        computed = binding_event_hash(
            event.get("event_type"),
            event.get("ref_id"),
            event.get("prev_hash"),
            event["rebuilt_payload"],
        )
        recorded_raw = b64url_decode(recorded)
    except BindingError as exc:
        out["result"] = "unverifiable"
        out["detail"] = (
            f"{exc}. Reported rather than counted as a pass or a failure: until it is explained "
            "it is a defect in this verifier, not evidence about the data"
        )
        return out

    out["recomputed_event_hash"] = base64.urlsafe_b64encode(computed).decode("ascii").rstrip("=")
    if computed == recorded_raw:
        out["result"] = "intact"
        out["detail"] = "the carried payload hashes to the digest recorded in the chain"
    else:
        out["result"] = "altered"
        out["detail"] = (
            "the carried payload does NOT hash to the digest recorded in the chain. Either the "
            "rows changed after the event was written, or this file was edited after the bundle "
            "was built. The chain's own linkage is unaffected either way, which is the point: "
            "this is the edit linkage cannot see"
        )
    return out


def read_model_leaf(model: Any, key: str) -> tuple[str, Any]:
    """One leaf of the record's `model` block, and how it was expressed.

    Returns `(state, value)` where state is `recorded`, `absent` (the leaf
    carries no value — either unpopulated with a stated reason, or not there at
    all) or `unreadable`. `evidence/provenance.rs` wraps every leaf in a
    `{state, value, unpopulated_reason}` envelope; the auditor console's
    fixtures and older exports carry bare values. Both are read, because a
    verifier that only understood one of them would report a shape difference
    as a tamper.
    """
    if not isinstance(model, dict):
        return "unreadable", None
    if key not in model:
        return "absent", None
    leaf = model[key]
    if isinstance(leaf, dict) and "state" in leaf and "value" in leaf:
        if leaf["state"] == "recorded":
            return "recorded", leaf["value"]
        return "absent", None
    if leaf is None or leaf == "":
        return "absent", None
    return "recorded", leaf


def locate_model_block(record: Any) -> tuple[str, Any]:
    """Find the record's model attestation, whichever record shape this is.

    Two shapes carry one, and the difference is a naming collision this repo
    already has rather than one introduced here:

      * `DecisionEvidence` (schema/decision_evidence/v1.3.0.json, and the
        auditor console's fixtures) carries `model` at the top level, where
        `null` is the signed assertion that no AI participated.
      * The case-file pack in an offline bundle
        (scripts/bundle/schema/case_file_pack.v1.schema.json) is a different
        projection with a different schema, and both files are called
        `decision_evidence.json` in their respective worlds. It carries
        `model_attestation`, a two-key envelope, precisely because a bare
        `model: null` there could not distinguish "no AI participated" from
        "the exporter could not obtain the block" — and conflating those two
        is the single error this whole field exists to prevent.

    Returns `(state, model)` with state in `present` | `not_supplied` |
    `absent_key`. `present` with `model is None` is the no-AI assertion.
    """
    if not isinstance(record, dict):
        return "absent_key", None
    if "model" in record:
        return "present", record["model"]
    envelope = record.get("model_attestation")
    if isinstance(envelope, dict):
        if envelope.get("supplied") is True and "model" in envelope:
            return "present", envelope["model"]
        return "not_supplied", None
    return "absent_key", None




def locate_declared_at_open(record: Any) -> tuple[str, Any]:
    """The model declaration exactly as it was made when the assessment opened.

    This is what a `decision_model_attestation_bound` event actually commits
    to: the row in `decision_model_attestations`, which is written by
    `POST /api/v1/issue-wealth-request` in the same transaction as the
    assessment and is never altered afterwards. Schema 1.2.0 carries it
    verbatim as `model_provenance.as_declared_at_open`, in exactly the shape
    the binding payload has — a declaration string, the two branch-specific
    statements, and eight bare model leaves.

    Comparing against THIS rather than against `model` is what keeps the check
    correct once corrections exist. Since 1.2.0 `model` serves the
    organisation's current best statement of which model ran, so a decision
    with a filed correction has a `model` block that legitimately differs from
    what the chain bound. A verifier that reported that as tampering would be
    crying wolf on the one path the correction mechanism was built to make
    possible (migrations/0009_model_attestation_corrections.sql), and an
    operator who learns to dismiss this alarm has lost the control.

    Returns `(state, declared)` with state in `present` | `absent`.
    """
    for holder in (record, (record or {}).get("model_attestation")):
        if not isinstance(holder, dict):
            continue
        provenance = holder.get("model_provenance")
        if isinstance(provenance, dict) and isinstance(
            provenance.get("as_declared_at_open"), dict
        ):
            return "present", provenance["as_declared_at_open"]
    return "absent", None


def locate_corrections(record: Any) -> tuple[Any, Any]:
    """`(corrected, correction_count)` from `model_provenance`, or `(None, None)`."""
    for holder in (record, (record or {}).get("model_attestation")):
        if not isinstance(holder, dict):
            continue
        provenance = holder.get("model_provenance")
        if isinstance(provenance, dict):
            return provenance.get("corrected"), provenance.get("correction_count")
    return None, None


def _compare_declared_at_open(payload: dict, declared: dict) -> list[str]:
    """Leaf-for-leaf, null-for-null. Returns the disagreements, or []."""
    problems: list[str] = []
    identity = declared.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    for bound_key, value in [
        ("declaration", declared.get("declaration")),
        ("no_ai_attestation", declared.get("no_ai_attestation")),
        ("unidentified_reason", declared.get("unidentified_reason")),
    ]:
        if payload.get(bound_key) != value:
            problems.append(
                f"  {bound_key}\n"
                f"    chain-bound  {payload.get(bound_key)!r}\n"
                f"    record says  {value!r}"
            )
    for bound_key, leaf_key in sorted(BOUND_MODEL_LEAVES.items()):
        # `!=` on the raw values, not a stringified compare: the record and the
        # binding payload are both serialised from the same columns by the same
        # process, so a difference in type is a difference, not a formatting
        # accident this verifier should smooth over.
        if payload.get(bound_key) != identity.get(leaf_key):
            problems.append(
                f"  identity.{leaf_key}\n"
                f"    chain-bound  {payload.get(bound_key)!r}\n"
                f"    record says  {identity.get(leaf_key)!r}"
            )
    return problems


def compare_model_identity(payload: dict, record: Any) -> dict:
    """Does the record's model identity agree with the one the chain bound?

    THIS is the check that makes a tampered bundle detectable with no database
    access and no network. `recompute_binding_event` proves the carried payload
    hashes to the carried digest; it says nothing about whether the record
    beside it tells the same story. An attacker holding only the bundle edits
    the record's model block and leaves the binding file untouched: every hash
    still checks out, and only this comparison catches it.

    Two comparisons, in order, because the record makes two different
    statements about the model and only one of them is what the chain bound:

      1. `model_provenance.as_declared_at_open` — the declaration as made when
         the assessment opened. This is the row the binding event commits to,
         and a disagreement here is unambiguous: one of the two was altered.
      2. `model` — the identity the record serves TODAY. Under schema 1.2.0 a
         filed correction changes this legitimately, so it is compared only
         when nothing has been corrected, and the corrections are reported
         rather than flagged when they have.

    `model: null` is its own case throughout and never blurs into "no model
    named". It is a signed assertion that no AI system participated
    (`ModelAttestation` in backend/api/src/evidence/mod.rs), structurally
    distinct from an AI that could not be identified. A record serving it for a
    decision whose chain-bound attestation names a model is the escalation of
    finding 4 — `tests/break_it/test_attack_04_model_identity_change.py`
    reaches it with one UPDATE — and it is reported as a contradiction, never
    as agreement.

    Returns `{"state": ..., "lines": [...]}` with state in
    `agree` | `contradict` | `not_checkable`.
    """
    declaration = payload.get("declaration")
    lines: list[str] = [f"chain-bound declaration   {declaration!r}"]
    contradictions: list[str] = []
    checked_something = False

    # --- 1. against the declaration as made at open -------------------------
    declared_state, declared = locate_declared_at_open(record)
    if declared_state == "present":
        checked_something = True
        problems = _compare_declared_at_open(payload, declared)
        if problems:
            contradictions.append(
                "CONTRADICTION against model_provenance.as_declared_at_open — the record's own "
                "copy of what was declared when this assessment was opened, which is the exact "
                "row this binding event commits to:"
            )
            contradictions.extend(problems)
        else:
            lines.append(
                "as_declared_at_open       matches the bound payload leaf for leaf, nulls "
                "included"
            )

    # --- 2. against the identity the record serves today --------------------
    corrected, correction_count = locate_corrections(record)
    located, model = locate_model_block(record)

    if corrected:
        lines.append(
            f"model block               superseded by {correction_count} filed correction(s), so "
            "it is EXPECTED to differ from the bound payload and is not compared here. The "
            "corrections are themselves append-only rows; whether they still say what was "
            "hashed is a separate binding event's business, not this one's."
        )
    elif located == "not_supplied":
        lines.append(
            "model block               not obtained by the exporter "
            "(`model_attestation.supplied` is false), so the served identity could not be "
            "compared. Note what this is NOT: an absent block is not the `model: null` "
            "assertion. Absence says nothing; null says, inside the sealed bytes, that no AI "
            "took part."
        )
    elif located == "absent_key":
        lines.append(
            "model block               the record carries neither a `model` key nor a "
            "`model_attestation` envelope, so the served identity could not be compared. An "
            "absent key is not the `model: null` assertion."
        )
    else:
        checked_something = True
        asserts_no_ai = model is None
        lines.append(
            "model block               "
            + (
                "null — a signed assertion that no AI participated"
                if asserts_no_ai
                else f"an object with {len(model)} leaf/leaves"
                if isinstance(model, dict)
                else f"{type(model).__name__}, which is neither null nor an object"
            )
        )
        if declaration == DECLARATION_NO_AI and not asserts_no_ai:
            contradictions.append(
                "CONTRADICTION. The chain committed to a declaration that no AI participated, "
                "and the record serves a model block anyway. One of the two was changed after "
                "the binding event was written."
            )
        elif declaration in (DECLARATION_IDENTIFIED, DECLARATION_UNIDENTIFIED) and asserts_no_ai:
            contradictions.append(
                "CONTRADICTION, and it is the worst shape this failure takes. The record serves "
                "`model: null` — the strongest claim in the schema, a signed assertion that no "
                "AI system took part — for a decision the chain committed to as "
                f"{declaration!r}. This is the escalation described in "
                "tests/break_it/test_attack_04_model_identity_change.py and in "
                "backend/api/src/audit/binding.rs. Do not rely on the no-AI assertion in this "
                "record."
            )
        elif asserts_no_ai:
            lines.append(
                "attestation given         " + repr(payload.get("no_ai_attestation"))
            )
        elif not isinstance(model, dict):
            contradictions.append(
                "the record's model block is neither null nor an object, so it cannot express "
                "the identity the chain bound"
            )
        else:
            disagreements, compared, unreadable = [], 0, []
            for bound_key, leaf_key in sorted(BOUND_MODEL_LEAVES.items()):
                bound_value = payload.get(bound_key)
                state, record_value = read_model_leaf(model, leaf_key)
                if state == "unreadable":
                    unreadable.append(leaf_key)
                    continue
                bound_absent, record_absent = bound_value is None, state == "absent"
                if bound_absent and record_absent:
                    continue
                compared += 1
                if bound_absent != record_absent or str(bound_value) != str(record_value):
                    disagreements.append(
                        f"  {leaf_key}\n"
                        f"    chain-bound  {bound_value!r}\n"
                        f"    record says  {record_value!r}"
                        + ("  (the record does not carry this leaf)" if record_absent else "")
                    )
            if unreadable:
                lines.append(
                    "leaves this verifier could not read out of the record: "
                    + ", ".join(unreadable)
                )
            if disagreements:
                contradictions.append(
                    f"{len(disagreements)} of {compared} compared model leaf/leaves disagree "
                    "with the chain-bound payload:"
                )
                contradictions.extend(disagreements)
            else:
                lines.append(
                    f"model leaves compared     {compared}, all in agreement with the bound payload"
                )

    if contradictions:
        return {
            "state": "contradict",
            "lines": lines
            + contradictions
            + [
                "The record and the chain do not tell the same story about which model produced "
                "this decision. A bundle where they disagree is the finding: whichever side was "
                "edited, the identity in the record is not the identity that was committed to. "
                "Do not report either until it is explained."
            ],
        }
    if not checked_something:
        return {
            "state": "not_checkable",
            "lines": lines
            + [
                "Nothing in this bundle's record could be compared against the chain-bound "
                "identity. Obtain the record from "
                "GET /api/v1/wealth-assessments/:id/decision-evidence and rebuild.",
            ],
        }
    return {
        "state": "agree",
        "lines": lines
        + [
            "What this shows: the model identity in this record is the identity the hash chain "
            "committed to when the decision was opened, so neither the record nor the binding "
            "file was edited to disagree with the other.",
            "What it does not show: that the identity was CORRECT. It is a forward declaration "
            "the calling system made about itself, before the proof existed and before anyone "
            "reviewed the decision, and nothing in this bundle can check it against the model "
            "that actually ran. Compare model_provenance.declared_at with "
            "decision.timestamps.assessed_at and draw your own conclusion.",
        ],
    }
