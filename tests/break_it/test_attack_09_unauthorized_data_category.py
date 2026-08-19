"""Attack #9 — attempt an unauthorized data category.

    ATTACK: an AI-connector session is scoped to specific vault record
    categories the customer allowed to be shared. A caller (device, or an
    attacker with the customer's key material but not their genuine
    consent) tries to disclose a record whose category is outside that
    scope.

    WHERE THE ENFORCEMENT ACTUALLY LIVES — checked, not assumed:
    `backend/api/src/verify/mod.rs` has ZERO references to "categories" or
    "allowed_categories" (grepped as part of writing this test). Unlike
    `wealth_suitability`'s `product_ref`/terms/`vault_root`, which
    `submit_wealth_proof` cross-checks against a server-side snapshot before
    ever calling `bb verify`, the four session circuits — including
    `ai_session` — get NO application-level cross-check of their structural
    public inputs at all. `allowed_categories_root` is enforced ENTIRELY
    inside `circuits/ai_session/src/main.nr`: the circuit constrains every
    disclosed record's category hash to a real Merkle-inclusion proof
    against `allowed_categories_root`
    (`verify_merkle_inclusion(allowed_categories_root, category_hashes[i], ...)`).
    A client that does not hold an authentic inclusion path for an
    out-of-scope category cannot construct a satisfying witness — there is
    no proof to submit to the server at all, which is a STRONGER stop than
    an application-level rejection (nothing ever reaches the network).

    WHAT THIS TEST PROVES: this test runs the circuit's OWN existing test,
    `tests::test_rejects_category_not_allowed`
    (`circuits/ai_session/src/main.nr`), for real, via `nargo test` — the
    actual Noir constraint solver, actually executing the ACIR the compiled
    circuit ships, not a description of what the constraint is supposed to
    do. That test constructs a scenario with a genuine, correctly-built
    Merkle proof against the RIGHT `allowed_categories_root`, then swaps in
    a wrong root and confirms the circuit is UNSATISFIABLE
    (`#[test(should_fail)]` — `nargo test` must observe an actual failure,
    not merely "no assertion ran"). This test also guards against the
    silent-false-green failure mode of filtered `nargo test` runs (a typo'd
    filter matching zero tests still exits 0 "N tests passed" for N=0) by
    asserting the exact test actually ran.

    WHAT THIS TEST DOES NOT PROVE: it reuses the circuit's existing test
    rather than constructing a fresh witness from Python, deliberately — a
    hand-rolled Merkle/witness builder for `ai_session` risks a subtle
    construction bug that would make this test lie about what it's
    checking, and no such client exists in this repo today to build on
    (unlike `wealth_suitability`, which has `clients/wealth_client.py`).
    This test also does not exercise the full HTTP path (open an AI session
    disclosure request, submit a category-violating proof, observe the
    server reject it) — per the enforcement analysis above, that is not
    where the defence lives, so a passing HTTP-level test here would prove
    less than this one does, not more. Whether an END-TO-END adversarial
    test against the live server exists was flagged "untested/unconfirmed"
    in decision_evidence_spec.md Task 4 item 9; this test resolves that to
    "the underlying constraint is real and enforced," while leaving "is
    there also app-level defence in depth for the four session circuits"
    open as the same gap already named there (compare `wealth_suitability`,
    which does have it).
"""

from __future__ import annotations

BREAK_IT_ATTACK_NUMBER = 9
BREAK_IT_ATTACK_TITLE = "Attempt an unauthorized data category"
BREAK_IT_STATUS_ON_PASS = "STOPPED"
BREAK_IT_NOTE = "circuit-level: an unauthorized category makes the circuit unsatisfiable (nargo test, real constraint solver); no app-level cross-check exists for the 4 session circuits (see docstring)"

import subprocess

from conftest import CIRCUITS_DIR

AI_SESSION_DIR = CIRCUITS_DIR / "ai_session"
TEST_NAME = "test_rejects_category_not_allowed"


def test_the_circuit_refuses_to_prove_disclosure_of_an_unauthorized_category():
    result = subprocess.run(
        ["nargo", "test", TEST_NAME],
        cwd=AI_SESSION_DIR,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr

    assert "Running 1 test function" in output, (
        f"expected exactly the one named test to be selected (guards against a filter typo "
        f"silently matching zero tests and reporting a false pass); got:\n{output}"
    )
    assert f"tests::{TEST_NAME}" in output, output
    assert result.returncode == 0, (
        f"nargo test must exit 0: the test itself asserts the circuit is UNSATISFIABLE for a "
        f"wrong allowed_categories_root (#[test(should_fail)]), so a 0 exit here means that "
        f"unsatisfiability was genuinely observed, not skipped:\n{output}"
    )
    assert "1 test passed" in output, output
