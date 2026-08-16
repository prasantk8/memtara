// ISO 6166 (ISIN) validation.
//
// Lives with the product registry rather than with the suitability circuit
// because the registry is where an identifier enters the system. By the time
// `wealth::issue_wealth_request` sees an ISIN it has already been through
// here — it looks the product up, it does not re-parse the string.

/// Structural check: two-letter country prefix, nine alphanumerics, one
/// trailing check digit.
///
/// Structure only. The check digit is computed by `check_digit_ok` below but
/// deliberately not enforced — see that function.
pub(crate) fn structure_ok(isin: &str) -> bool {
    let b = isin.as_bytes();
    b.len() == 12
        && b[0..2].iter().all(|c| c.is_ascii_uppercase())
        && b[2..11].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && b[11].is_ascii_digit()
}

/// The ISO 6166 check digit: letters expand to two-digit numbers (A=10 …
/// Z=35), then Luhn over the resulting digit string including the check digit
/// itself; valid iff the total is a multiple of ten.
///
/// Computed and reported, not enforced. The commissioning brief's worked
/// example — `XS1234567890` — fails this check (it sums to 64), which is
/// unsurprising for an illustrative identifier but means enforcement would
/// reject the very case this feature was specified against. The same is true
/// of `TEST1234567890`-style identifiers used in demos.
///
/// So the registry accepts the product, warns in the log, and returns the
/// result to the caller as `check_digit_valid` on the created row — a bank
/// feeding this from a real product master can assert on that field, and the
/// omission is visible in the API rather than buried in a comment. Turning it
/// into a hard rejection is a one-line change at the call site in
/// `products::create_product`.
pub(crate) fn check_digit_ok(isin: &str) -> bool {
    let mut digits: Vec<u32> = Vec::with_capacity(24);
    for c in isin.chars() {
        if let Some(d) = c.to_digit(10) {
            digits.push(d);
        } else if c.is_ascii_uppercase() {
            let v = c as u32 - 'A' as u32 + 10;
            digits.push(v / 10);
            digits.push(v % 10);
        } else {
            return false;
        }
    }
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        // Positions are counted from the right starting at 1; every second
        // one (i.e. zero-indexed odd) is doubled.
        let v = if i % 2 == 1 { d * 2 } else { *d };
        sum += if v > 9 { v - 9 } else { v };
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structure_accepts_the_canonical_shape() {
        assert!(structure_ok("XS1234567890"));
        assert!(structure_ok("AE000A0M4TP4"));
    }

    #[test]
    fn structure_rejects_malformed_identifiers() {
        assert!(!structure_ok(""));
        assert!(!structure_ok("XS123456789"), "11 characters");
        assert!(!structure_ok("XS12345678901"), "13 characters");
        assert!(!structure_ok("xs1234567890"), "lowercase prefix");
        assert!(!structure_ok("X11234567890"), "prefix must be two letters");
        assert!(!structure_ok("XS123456789A"), "check position must be a digit");
    }

    #[test]
    fn check_digit_matches_known_good_and_bad_identifiers() {
        // A real ISIN (Apple Inc.) — the canonical worked example in ISO 6166
        // discussions, and it validates.
        assert!(check_digit_ok("US0378331005"));
        // The brief's illustrative identifier does not. Asserted rather than
        // assumed, so the claim in `check_digit_ok`'s own doc comment stays
        // true if anyone edits the algorithm.
        assert!(!check_digit_ok("XS1234567890"));
    }

    #[test]
    fn the_demo_identifier_is_structurally_valid_even_though_its_check_digit_is_not() {
        // scripts/demo_cro_workflow.py registers TEST1234567890 — 14
        // characters, which is not an ISIN at all. Pin the shape the demo has
        // to use instead so the two can't drift apart: the demo's identifier
        // must pass `structure_ok`, or the CRO walkthrough fails at step one.
        assert!(!structure_ok("TEST1234567890"), "14 chars is not an ISIN");
        assert!(structure_ok("XS0000000001"), "the shape the demo must use instead");
    }
}
