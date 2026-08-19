"""audit-verify: independently walk an audit log and prove chain integrity.

Exit code 0 = intact, 1 = tampering detected. Designed to be run on a schedule
(ADR-001 guideline 4) and to be the on-camera demo: mutate one byte of a
historical record, run this, watch it name the exact broken record.
"""
from __future__ import annotations

import argparse
import json
import sys

# Import works whether run as a module or a script.
try:
    from src.gateway.audit.chain import AuditEvent, GENESIS_PREV_HASH
except ImportError:  # pragma: no cover - path shim for direct execution
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    from src.gateway.audit.chain import AuditEvent, GENESIS_PREV_HASH


class VerificationError:
    def __init__(self, seq: int, reason: str) -> None:
        self.seq = seq
        self.reason = reason

    def __str__(self) -> str:
        return f"record seq={self.seq}: {self.reason}"


def verify(path: str) -> list[VerificationError]:
    """Return a list of errors; empty list means the chain is intact."""
    errors: list[VerificationError] = []
    expected_prev = GENESIS_PREV_HASH
    expected_seq = 0

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            data = json.loads(raw)

            if data["seq"] != expected_seq:
                errors.append(VerificationError(data["seq"], f"sequence gap (expected {expected_seq})"))

            if data["prev_hash"] != expected_prev:
                errors.append(VerificationError(data["seq"], "prev_hash does not match previous record's hash (chain broken)"))

            # Recompute this record's hash from its own contents.
            stored_hash = data["record_hash"]
            event = AuditEvent(**{k: v for k, v in data.items()})
            recomputed = event.compute_hash()
            if recomputed != stored_hash:
                errors.append(VerificationError(data["seq"], "record_hash does not match contents (record was altered)"))

            expected_prev = stored_hash
            expected_seq = data["seq"] + 1

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an AIHOOTS audit chain.")
    parser.add_argument("path", help="Path to the JSONL audit log")
    args = parser.parse_args(argv)

    errors = verify(args.path)
    if not errors:
        print(f"OK: audit chain intact ({args.path})")
        return 0

    print(f"TAMPERING DETECTED in {args.path}:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
