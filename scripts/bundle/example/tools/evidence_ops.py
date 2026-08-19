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
