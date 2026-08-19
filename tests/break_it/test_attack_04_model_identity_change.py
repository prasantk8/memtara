"""Attack #4 — change the model identity (provider/name/version) an
assessment was recorded against.

    ATTACK: an AI-mediated recommendation is made by model A. Before or
    during evidence generation, the recorded model identity is changed to
    model B (or never pinned in the first place) — the evidence should not
    silently accept whichever identity is asserted at read time.

    STATUS: BLOCKED. This capability does not exist in the backend at all
    today — not "exists but unguarded" (that would be a NOT STOPPED finding,
    like attack #3), not "exists but untested" (like attack #9) — there is
    no `model.*` concept anywhere to attack. `decision_evidence_spec.md`
    §1.2 confirms this by direct grep: "No LLM/model-provider concept
    exists... one comment marking an LLM front door explicitly *out of
    scope*." Needed: the MODEL evidence block from Task 1
    (`model.provider`, `model.name`, `model.version`, `model.environment`,
    `model.config_fingerprint`, `model.system_prompt_or_policy_id`,
    `model.timestamp` — all seven marked MISSING in that spec's table).

    This is the SAME missing capability as attack #11 ("swap the model
    without recording it") — that attack is untestable for the identical
    reason, not a coincidence. See that module for the companion note.

    WHAT A LOUD SKIP MEANS HERE, CONCRETELY: this test re-verifies the
    capability is still absent by grepping the live source tree at run
    time (not from memory of when this file was written). If that grep
    ever finds a hit, the test FAILS — loudly, not skips — because at that
    point skipping would be a lie: the capability would exist and this test
    would owe a real implementation instead of a permanent green skip.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 4
BREAK_IT_ATTACK_TITLE = "Change the model identity"
BREAK_IT_KIND = "blocked"
BREAK_IT_NOTE = "no model.* concept exists anywhere in backend/api/src — decision_evidence_spec.md Task 1 MODEL block"

import pytest

from conftest import blocked_pending_capture

# The typed record. Present since DecisionEvidence v1 landed on 19 Aug 2026 —
# as explicitly-unpopulated placeholders, which is not the same as a
# capability.
MODEL_IDENTITY_PATTERNS = [
    r"model_provider",
    r"model_name",
    r"model_version",
    r"model_config_fingerprint",
    r"ModelIdentity",
    r"struct\s+Model\b",
]

# Somewhere for a model identity to be stored, or a route through which one
# can be supplied. Until one of these matches, an attacker has nothing to
# reach: you cannot swap a value the API will not accept.
MODEL_CAPTURE_PATTERNS = [
    r"(create|alter)\s+table[^;]*model",
    r"model_(provider|name|version)\s+(text|varchar|jsonb)",
    r"\.route\(\s*\"[^\"]*model",
]


def test_model_identity_change_is_blocked_pending_task1_model_block():
    blocked_pending_capture(
        type_patterns=MODEL_IDENTITY_PATTERNS,
        capture_patterns=MODEL_CAPTURE_PATTERNS,
        capability="model identity",
        unblocked_by=(
            "a migration giving model identity somewhere to live, plus the intake "
            "route on the single gateway path the pilot exercises "
            "(decision_evidence_spec.md Task 1 §1.2, the seven `model.*` leaves)"
        ),
        real_attack=(
            "change a recorded model provider/name/version mid-flight, or between "
            "assessment and export, and confirm the system refuses the change or "
            "surfaces the mismatch rather than silently serving whichever identity "
            "was asserted last. Companion attack: #11, same root cause."
        ),
    )
