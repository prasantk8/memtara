"""Attack #10 — bypass human review.

    ATTACK: a decision that is supposed to require a human reviewer's
    sign-off (approve/reject/modify) is finalized without one — or the
    review step is skipped, forged, or overridden silently.

    STATUS: BLOCKED. There is no per-decision human review gate in the
    backend to bypass. `decision_evidence_spec.md` §1.2: "Zero matches for
    'reviewer' in `backend/api/src/`." The one governance-shaped field that
    DOES exist, `products.approved_by_risk_committee`
    (`backend/api/src/products/mod.rs`), gates a PRODUCT — a catalogue
    entry, checked once at `issue_wealth_request` time
    (`backend/api/src/wealth/mod.rs`, "if !product.approved_by_risk_committee")
    — not a per-DECISION review of this specific client's assessment. An
    attack that bypasses the product gate is a different (and already
    covered) test: `tests/test_wealth_suitability_e2e.py::
    test_an_unapproved_product_cannot_be_assessed`. This attack needs a
    review action tied to `decision_id`, and none exists.

    This test verifies both halves live:

      1. No per-decision review concept (`reviewer_id`, `decision_reviews`,
         a review `action` enum) exists in `backend/api/src/`.
      2. `approved_by_risk_committee` DOES exist, and its only two call
         sites are confirmed to be product-registry code
         (`products/mod.rs`) and the product-level gate check in
         `wealth/mod.rs` — never anything keyed on an individual decision.

    WHAT A LOUD SKIP MEANS HERE, CONCRETELY: if a `decision_reviews`-shaped
    table or a `reviewer_id`/`human_review` field lands, this test FAILS
    with the exact match, rather than continuing to report green.
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 10
BREAK_IT_ATTACK_TITLE = "Bypass human review"
BREAK_IT_KIND = "blocked"
BREAK_IT_NOTE = "no per-decision review concept exists; approved_by_risk_committee gates a product, not a decision — decision_evidence_spec.md Task 1 human_review block"

import pytest

from conftest import blocked_pending_capture, grep_backend

HUMAN_REVIEW_CAPTURE_PATTERNS = [
    r"(create|alter)\s+table[^;]*(decision_review|human_review|reviewer)",
    r"\.route\(\s*\"[^\"]*review",
]

HUMAN_REVIEW_PATTERNS = [
    r"reviewer_id",
    r"decision_reviews",
    r"human_review",
    r"HumanReview",
    r"reviewer_role",
]


def test_bypassing_human_review_is_blocked_pending_a_per_decision_review_concept():
    approved_by_committee_hits = grep_backend([r"approved_by_risk_committee"])
    assert approved_by_committee_hits, "expected to find the product-level governance flag"
    # Only real code counts. A `///` or `//` line that merely *names* the flag —
    # evidence/mod.rs carries one explaining why a product-level flag is not a
    # per-decision review — does not move the flag's reach, and failing on it
    # would make this tripwire fire on documentation.
    sites = [
        line
        for line in approved_by_committee_hits[r"approved_by_risk_committee"]
        if not line.split(":", 2)[-1].lstrip().startswith("//")
    ]
    assert sites, "expected at least one real call site, not only comments"
    assert all(("products/mod.rs" in line or "wealth/mod.rs" in line) for line in sites), (
        "expected approved_by_risk_committee to live only in the product registry and the "
        f"product-level gate check — if it now appears elsewhere, re-examine this skip:\n{sites}"
    )

    blocked_pending_capture(
        type_patterns=HUMAN_REVIEW_PATTERNS,
        capture_patterns=HUMAN_REVIEW_CAPTURE_PATTERNS,
        capability="per-decision human review",
        unblocked_by=(
            "a `decision_reviews` table plus the endpoint that writes it "
            "(decision_evidence_spec.md Task 1 §1.2 — reviewer_id, reviewer_role, "
            "action, override/reason, reviewed_at)"
        ),
        real_attack=(
            "reach a final decision state without a recorded review action, or with a "
            "forged or unexplained override, and confirm the system refuses. The only "
            "governance-shaped field today, products.approved_by_risk_committee, gates a "
            "catalogue entry rather than an individual decision — verified above that its "
            "only call sites are the product registry and the product-level check — so "
            "there is currently no review action to bypass."
        ),
    )
