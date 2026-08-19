"""Attack #11 — swap the model mid-flight, without recording it.

    ATTACK: the AI model actually used to produce a recommendation is
    swapped for a different one (different provider, different version,
    even a different config/prompt) partway through, and the evidence for
    the decision never reflects it.

    STATUS: BLOCKED — same root cause as attack #4, verified the same way,
    not a duplicate test of it. #4 asks "can a recorded model identity be
    CHANGED and have the system notice"; this one asks "can a model be
    swapped WITHOUT ANYTHING EVER RECORDING an identity to compare against
    in the first place." Both are unanswerable today for the identical
    reason: `decision_evidence_spec.md` §1.2 confirms zero `model.*` concept
    exists anywhere in `backend/api/src/`. There is nothing to swap FROM in
    the system's own records, so "swap without recording it" isn't a
    bypass of a control — it's the system's only mode.

    This is deliberately its own test file, not folded into #4, because the
    break-it table needs both attacks reported honestly on their own line —
    collapsing them would understate how much of Task 1's MODEL gap the
    board's eleven attacks actually depend on (two of eleven, independently).

    WHAT A LOUD SKIP MEANS HERE, CONCRETELY: re-verified live via grep at
    run time; if the capability lands, this test FAILS instead of skipping,
    naming the exact match, so a stale green skip can't survive the gap
    closing.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 11
BREAK_IT_ATTACK_TITLE = "Swap the model without recording it"
BREAK_IT_KIND = "blocked"
BREAK_IT_NOTE = "same root cause as #4: no model.* concept anywhere to swap-and-fail-to-update — decision_evidence_spec.md Task 1 MODEL block"

import pytest

from conftest import blocked_pending_capture

MODEL_IDENTITY_PATTERNS = [
    r"model_provider",
    r"model_name",
    r"model_version",
    r"model_config_fingerprint",
    r"ModelIdentity",
    r"struct\s+Model\b",
]

MODEL_CAPTURE_PATTERNS = [
    r"(create|alter)\s+table[^;]*model",
    r"model_(provider|name|version)\s+(text|varchar|jsonb)",
    r"\.route\(\s*\"[^\"]*model",
]


def test_swapping_the_model_undetected_is_blocked_pending_task1_model_block():
    blocked_pending_capture(
        type_patterns=MODEL_IDENTITY_PATTERNS,
        capture_patterns=MODEL_CAPTURE_PATTERNS,
        capability="model identity",
        unblocked_by=(
            "the same capture path attack #4 waits on — a migration plus the intake "
            "route (decision_evidence_spec.md Task 1 §1.2)"
        ),
        real_attack=(
            "swap the model identity between two steps of a decision without updating "
            "any recorded field, and confirm the evidence either refuses to finalise or "
            "visibly flags the inconsistency rather than silently carrying whichever "
            "identity was asserted last. This is a distinct finding from #4: #4 attacks "
            "a value that is recorded, this attacks the absence of a rebind."
        ),
    )
