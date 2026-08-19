"""Attack #8 — revoke consent.

    ATTACK: a customer revokes consent for their data to be used after a
    session/proof was already authorized under it. Anything relying on that
    consent afterward should be refused.

    STATUS: BLOCKED, and more fundamentally than attacks #4/#10/#11. Those
    three are missing a RECORD (model identity, a per-decision human
    review). This one is missing the CONCEPT: there is no representation of
    consent anywhere in the backend to revoke. `decision_evidence_spec.md`
    §1.2 confirms by direct grep: "Zero matches for 'consent' anywhere in
    `backend/api/src/`." The nearest relative,
    `vault::session::SessionPolicy.purpose_hash`, is a fixed hash of a
    hardcoded purpose string (e.g. `memtara:purpose:ai_session`) bound at
    session-creation time — a purpose BINDING, not a consent RECORD with an
    id, a version, a grant timestamp, or (the part this attack needs) any
    way to revoke it.

    This test verifies both halves live, rather than trusting the prior
    written analysis to still be true:

      1. No `consent`-named concept exists in `backend/api/src/` (grep).
      2. `purpose_hash` DOES exist (confirming the nearest-but-insufficient
         proxy is real, not imagined) and there is no revocation route for
         it — `disclosure-requests/:id/revoke` exists, but revokes a
         REQUEST (a specific pending ask), not a standing grant of consent;
         the two are not the same thing, and conflating them would be the
         wrong finding to report.

    WHAT A LOUD SKIP MEANS HERE, CONCRETELY: if a future change introduces
    a `consent`-shaped concept, this test FAILS instead of continuing to
    skip, naming exactly what it found, so nobody mistakes a stale green
    skip for "consent revocation was verified."
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 8
BREAK_IT_ATTACK_TITLE = "Revoke consent"
BREAK_IT_KIND = "blocked"
BREAK_IT_NOTE = "no consent concept exists at all (not even an unguarded one) — decision_evidence_spec.md Task 1, consent.id/version/scope"

import pytest

from conftest import blocked_pending_capture, grep_backend

CONSENT_CAPTURE_PATTERNS = [
    r"(create|alter)\s+table[^;]*consent",
    r"\.route\(\s*\"[^\"]*consent",
]

CONSENT_PATTERNS = [
    r"consent_id",
    r"consent_version",
    r"revoke_consent",
    r"ConsentRecord",
    r"struct\s+Consent\b",
    r"\bconsents\b",
]

PURPOSE_HASH_PATTERN = r"purpose_hash"


def test_consent_revocation_is_blocked_pending_a_consent_concept():
    # Confirm the documented "nearest proxy" claim is itself real, not
    # assumed — purpose_hash should exist even though full consent does not.
    purpose_hits = grep_backend([PURPOSE_HASH_PATTERN])
    assert purpose_hits, (
        "expected to find `purpose_hash` (vault/src/session.rs) as the nearest existing proxy "
        "for consent — if this no longer matches, the whole framing of this skip needs revisiting"
    )

    blocked_pending_capture(
        type_patterns=CONSENT_PATTERNS,
        capture_patterns=CONSENT_CAPTURE_PATTERNS,
        capability="consent",
        unblocked_by=(
            "a real consent object — a table with id, version, scope and granted_at, "
            "plus a revocation endpoint or state transition "
            "(decision_evidence_spec.md Task 1 §1.2, sized L)"
        ),
        real_attack=(
            "authorise something under a consent record, revoke it, and confirm anything "
            "relying on it afterwards is refused rather than served from stale "
            "authorisation. Note this is the one attack whose blocker is a missing "
            "*concept*, not a missing field: SessionPolicy.purpose_hash is a fixed, "
            "non-revocable purpose binding, so there is nothing to revoke."
        ),
    )
