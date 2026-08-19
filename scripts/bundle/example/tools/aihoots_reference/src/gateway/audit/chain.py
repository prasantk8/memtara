"""Tamper-evident, append-only audit log built on a SHA-256 hash chain.

Each record embeds the hash of the previous record. Altering any historical
record changes its hash, which breaks every subsequent link — detectable by
the verifier. See docs/ADR-001.

Design notes:
- Records are newline-delimited JSON (JSONL): append-only, human-inspectable,
  trivially reproducible. No database required for E1 (ADR-001).
- The chain stores digests of prompt/response, not full payloads, to keep the
  audit record small and reduce sensitive-data sprawl (ADR-001 guideline 3).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

GENESIS_PREV_HASH = "0" * 64


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def digest(text: str) -> str:
    """Public helper: stable digest of a payload for storage in the chain."""
    return _sha256(text)


@dataclass
class AuditEvent:
    """A single audited interaction or decision.

    `record_hash` and `prev_hash` are populated by the writer; callers only
    supply the semantic fields.
    """
    request_id: str
    timestamp: float
    caller: str
    model: str
    event_type: str            # "request" | "response" | "decision"
    decision: str              # "allow" | "redact" | "block" | "n/a"
    prompt_digest: str = ""
    response_digest: str = ""
    prompt_len: int = 0
    response_len: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)
    seq: int = 0
    prev_hash: str = ""
    record_hash: str = ""

    def _canonical_payload(self) -> str:
        """Deterministic serialization of everything EXCEPT record_hash.

        record_hash is derived from this string, so it must be excluded and the
        key order must be stable across machines (sort_keys=True).
        """
        body = {k: v for k, v in asdict(self).items() if k != "record_hash"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        return _sha256(self._canonical_payload())


class AuditChain:
    """Append-only writer over a JSONL file, thread-safe for a single process."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Resume the chain from an existing file, or start a fresh genesis."""
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return 0, GENESIS_PREV_HASH
        last_line = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for last_line in fh:
                pass
        if not last_line:
            return 0, GENESIS_PREV_HASH
        last = json.loads(last_line)
        return last["seq"] + 1, last["record_hash"]

    def append(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            event.seq = self._seq
            event.prev_hash = self._last_hash
            event.record_hash = event.compute_hash()
            line = json.dumps(asdict(event), sort_keys=True, separators=(",", ":"))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq += 1
            self._last_hash = event.record_hash
            return event


def new_event(request_id: str, caller: str, model: str, event_type: str,
              decision: str = "n/a", **kwargs: Any) -> AuditEvent:
    """Convenience factory that stamps the current time."""
    return AuditEvent(
        request_id=request_id,
        timestamp=time.time(),
        caller=caller,
        model=model,
        event_type=event_type,
        decision=decision,
        **kwargs,
    )
