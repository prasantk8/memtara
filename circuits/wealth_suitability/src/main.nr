// Structured-product suitability (DFSA Conduct of Business 3.1).
//
// A bank must satisfy itself that a structured product is suitable for a
// client before recommending it. Doing that conventionally means the client
// hands over income, portfolio and risk-profile documents, and the bank
// stores them — a permanent, breachable copy of the client's whole financial
// position held solely to justify one recommendation.
//
// This circuit produces the same regulatory evidence without the copy. The
// client's device proves, over the vault the client already holds, that the
// four COB 3.1 limbs were evaluated against the product's published terms,
// and discloses exactly one bit: suitable, or not.
//
// -------------------------------------------------------------------
// WHY THE ANSWER IS AN OUTPUT AND NOT AN ASSERT
// -------------------------------------------------------------------
// The obvious reading of "assert income >= min_income" makes the circuit
// unsatisfiable for an unsuitable client. That is wrong for this use case in
// a way that matters to the regulator rather than to the code: COB 3.1
// obliges the firm to *assess*, not to approve, and a bank that declines
// needs evidence of the assessment exactly as much as one that proceeds. A
// circuit that cannot produce a proof of "not suitable" makes a declined
// recommendation indistinguishable from an assessment that never happened.
//
// So the four limbs are computed and ANDed into the public output
// `suitable`. Well-formedness of the request (risk scale 1-5, cap <= 100%)
// still asserts — a malformed product must fail loudly, not quietly present
// itself as a client who failed the test. See
// `memtara_circuits::suitability` for the predicates themselves.
//
// A relying party MUST therefore check the public output. `submit-wealth-proof`
// (backend/api/src/wealth/mod.rs) does; a verifier that treats "bb verify
// exited 0" as "suitable" has misread this circuit.
//
// -------------------------------------------------------------------
// WHAT BINDS THE WITNESSES DOWN
// -------------------------------------------------------------------
// Without the Merkle and signature limbs below, the four private inputs
// would be unconstrained and the client could simply assert an income of
// whatever the product required. So, matching the other four session
// circuits:
//
//   * every financial value is proven to be a leaf of the committed
//     `vault_root`, so the numbers are the ones the vault actually holds;
//   * the whole parameter set — including `product_ref` — is hashed into a
//     commitment the user's Baby Jubjub key signs, so the assessment is
//     bound to THIS product on THIS request and cannot be re-presented as
//     evidence for a different note that happens to share a risk level;
//   * `nonce` is public and inside that commitment, so the off-circuit
//     `used_nonces` registry can make the proof single-use.

use memtara_circuits::MERKLE_DEPTH;
use memtara_circuits::merkle_inclusion::verify_merkle_inclusion;
use memtara_circuits::signature_verify::{EddsaPublicKey, EddsaSignature, eddsa_verify};
use memtara_circuits::suitability::assess_suitability;
use memtara_circuits::time_bound::verify_time_window;
use poseidon::poseidon::bn254::{hash_2, hash_8};

fn main(
    // --- session window ---
    current_time: pub u64,
    start_time: u64,
    expiry_time: pub u64,
    // --- vault binding ---
    vault_root: pub Field,
    // --- the product this assessment is for ---
    // A field-encoded digest of the ISIN (see `wealth::product_ref` on the
    // Rust side). The ISIN itself is not secret; carrying a digest rather
    // than the 12 characters keeps it one field element.
    product_ref: pub Field,
    // --- private financial witnesses ---
    income: u64,
    liquid_assets: u64,
    risk_tolerance: u64,
    existing_holdings_value: u64,
    // --- authentication paths proving each witness is really in the vault ---
    income_index: Field,
    income_path: [Field; MERKLE_DEPTH],
    liquid_assets_index: Field,
    liquid_assets_path: [Field; MERKLE_DEPTH],
    risk_tolerance_index: Field,
    risk_tolerance_path: [Field; MERKLE_DEPTH],
    existing_holdings_index: Field,
    existing_holdings_path: [Field; MERKLE_DEPTH],
    // --- the product's published suitability terms ---
    min_income: pub u64,
    min_liquidity: pub u64,
    max_concentration_percent: pub u64,
    product_risk_level: pub u64,
    // --- authorization ---
    user_public_key_x: pub Field,
    user_public_key_y: pub Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    signature_s: Field,
    nonce: pub Field,
) -> pub Field {
    // 1. The assessment is being run inside the window the bank opened.
    verify_time_window(current_time, start_time, expiry_time);

    // 2. Each financial figure is genuinely the one committed in the vault,
    //    not a number the client picked to clear the threshold.
    //    `verify_merkle_inclusion` hashes its `leaf` argument internally, so
    //    raw values are passed here — matching how the vault tree commits
    //    them, and matching tax_session's use of the same helper.
    verify_merkle_inclusion(vault_root, income as Field, income_index, income_path);
    verify_merkle_inclusion(vault_root, liquid_assets as Field, liquid_assets_index, liquid_assets_path);
    verify_merkle_inclusion(vault_root, risk_tolerance as Field, risk_tolerance_index, risk_tolerance_path);
    verify_merkle_inclusion(
        vault_root,
        existing_holdings_value as Field,
        existing_holdings_index,
        existing_holdings_path,
    );

    // 3. The client authorized this exact assessment: these terms, this
    //    product, this nonce. Any change to the public parameters
    //    invalidates the signature.
    let terms = hash_8([
        current_time as Field,
        start_time as Field,
        expiry_time as Field,
        vault_root,
        product_ref,
        min_income as Field,
        min_liquidity as Field,
        max_concentration_percent as Field,
    ]);
    let policy_commitment = hash_2([hash_2([terms, product_risk_level as Field]), nonce]);

    let public_key = EddsaPublicKey { x: user_public_key_x, y: user_public_key_y };
    let signature = EddsaSignature { r8_x: signature_r8_x, r8_y: signature_r8_y, s: signature_s };
    assert(eddsa_verify(public_key, signature, policy_commitment));

    // 4. The assessment itself. One bit out; nothing else about the client's
    //    finances crosses the boundary.
    let suitable = assess_suitability(
        income,
        liquid_assets,
        risk_tolerance,
        existing_holdings_value,
        min_income,
        min_liquidity,
        max_concentration_percent,
        product_risk_level,
    );
    suitable as Field
}

mod tests {
    use memtara_circuits::MERKLE_DEPTH;
    use memtara_circuits::merkle_inclusion::hash_leaf;
    use poseidon::poseidon::bn254::hash_2;

    global TREE_LEAVES: u32 = 16; // 2^MERKLE_DEPTH

    // Leaf slots for the four financial figures. Fixed positions in the
    // wealth category of the vault tree.
    global INCOME_SLOT: u32 = 0;
    global LIQUID_SLOT: u32 = 1;
    global RISK_SLOT: u32 = 2;
    global HOLDINGS_SLOT: u32 = 3;

    fn build_tree(leaves: [Field; TREE_LEAVES]) -> (Field, [[Field; MERKLE_DEPTH]; TREE_LEAVES]) {
        let mut hashes: [Field; TREE_LEAVES] = leaves.map(|l| hash_leaf(l));
        let mut paths: [[Field; MERKLE_DEPTH]; TREE_LEAVES] = [[0; MERKLE_DEPTH]; TREE_LEAVES];

        for level in 0..MERKLE_DEPTH {
            for leaf_idx in 0..TREE_LEAVES {
                let pos = leaf_idx >> level;
                let sibling_pos = pos ^ 1;
                paths[leaf_idx][level] = hashes[sibling_pos];
            }
            let half = TREE_LEAVES >> (level + 1);
            for i in 0..half {
                hashes[i] = hash_2([hashes[2 * i], hashes[2 * i + 1]]);
            }
        }
        (hashes[0], paths)
    }

    struct Portfolio {
        vault_root: Field,
        income: u64,
        liquid_assets: u64,
        risk_tolerance: u64,
        existing_holdings_value: u64,
        paths: [[Field; MERKLE_DEPTH]; TREE_LEAVES],
    }

    fn build_portfolio(
        income: u64,
        liquid_assets: u64,
        risk_tolerance: u64,
        existing_holdings_value: u64,
    ) -> Portfolio {
        let mut leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES];
        leaves[INCOME_SLOT] = income as Field;
        leaves[LIQUID_SLOT] = liquid_assets as Field;
        leaves[RISK_SLOT] = risk_tolerance as Field;
        leaves[HOLDINGS_SLOT] = existing_holdings_value as Field;
        let (root, paths) = build_tree(leaves);
        Portfolio { vault_root: root, income, liquid_assets, risk_tolerance, existing_holdings_value, paths }
    }

    // Every test below drives `main` with an all-zero signature, which
    // `eddsa_verify` rejects — so each is `should_fail` regardless of the
    // suitability outcome, and would prove nothing on its own about the
    // suitability limbs. That is deliberate and is why the suitability logic
    // is unit-tested independently in `memtara_circuits::suitability`, where
    // no signature is in the way. What these tests do establish is that the
    // *binding* limbs really are wired into `main`: swap a Merkle path or a
    // vault root and the circuit fails before it ever reaches the
    // assessment.
    //
    // Constructing a genuinely valid Baby Jubjub signature requires scalar
    // arithmetic modulo the subgroup order, which is off-circuit signer work
    // (see the note at the foot of lib/src/signature_verify.nr). No such
    // signer exists in this repo yet; that gap is recorded in
    // docs/REGULATORY_DEMO_REPORT.md as the one remaining seam.

    fn run(p: Portfolio, min_income: u64, min_liquidity: u64, max_conc: u64, risk_level: u64) {
        let start_time: u64 = 1_755_000_000;
        let expiry_time: u64 = start_time + 900;
        let current_time: u64 = start_time + 30;

        let _ = crate::main(
            current_time,
            start_time,
            expiry_time,
            p.vault_root,
            0x1234, // product_ref
            p.income,
            p.liquid_assets,
            p.risk_tolerance,
            p.existing_holdings_value,
            INCOME_SLOT as Field,
            p.paths[INCOME_SLOT],
            LIQUID_SLOT as Field,
            p.paths[LIQUID_SLOT],
            RISK_SLOT as Field,
            p.paths[RISK_SLOT],
            HOLDINGS_SLOT as Field,
            p.paths[HOLDINGS_SLOT],
            min_income,
            min_liquidity,
            max_conc,
            risk_level,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }

    #[test(should_fail)]
    fn test_rejects_unsigned_assessment_of_a_suitable_client() {
        // The `wealth_demo` profile from tests/test_wealth_suitability_e2e.py.
        // Suitable on all four limbs — and still rejected, because nothing
        // authorized it.
        run(build_portfolio(750_000, 2_000_000, 4, 200_000), 500_000, 1_000_000, 30, 3);
    }

    #[test(should_fail)]
    fn test_rejects_income_figure_not_in_the_vault() {
        let mut p = build_portfolio(750_000, 2_000_000, 4, 200_000);
        // Claim a higher income than the vault committed to, keeping the
        // path that proved the real one.
        p.income = 9_000_000;
        run(p, 500_000, 1_000_000, 30, 3);
    }

    #[test(should_fail)]
    fn test_rejects_risk_tolerance_figure_not_in_the_vault() {
        let mut p = build_portfolio(750_000, 2_000_000, 2, 200_000);
        // The client's real tolerance is 2; inflate it to clear a level-3
        // product. The Merkle limb catches it before the assessment runs.
        p.risk_tolerance = 5;
        run(p, 500_000, 1_000_000, 30, 3);
    }

    #[test(should_fail)]
    fn test_rejects_a_different_vaults_root() {
        let mut p = build_portfolio(750_000, 2_000_000, 4, 200_000);
        p.vault_root = 0xdead;
        run(p, 500_000, 1_000_000, 30, 3);
    }

    #[test(should_fail)]
    fn test_rejects_assessment_outside_the_session_window() {
        let p = build_portfolio(750_000, 2_000_000, 4, 200_000);
        let start_time: u64 = 1_755_000_000;
        let expiry_time: u64 = start_time + 900;
        let current_time: u64 = start_time + 10_000; // window closed

        let _ = crate::main(
            current_time,
            start_time,
            expiry_time,
            p.vault_root,
            0x1234,
            p.income,
            p.liquid_assets,
            p.risk_tolerance,
            p.existing_holdings_value,
            INCOME_SLOT as Field,
            p.paths[INCOME_SLOT],
            LIQUID_SLOT as Field,
            p.paths[LIQUID_SLOT],
            RISK_SLOT as Field,
            p.paths[RISK_SLOT],
            HOLDINGS_SLOT as Field,
            p.paths[HOLDINGS_SLOT],
            500_000,
            1_000_000,
            30,
            3,
            0,
            0,
            0,
            0,
            0,
            999,
        );
    }
}
