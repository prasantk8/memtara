// The exact bytes a DecisionEvidence digest is taken over.
//
// -------------------------------------------------------------------
// THE CONSTRAINT
// -------------------------------------------------------------------
// `scripts/export_audit_evidence.py:200` already defines this project's
// canonical form:
//
//     json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
//
// and its docstring is explicit that matching AIHOOTS's `chain.py`
// convention was deliberate, because "two systems in the same pack that
// canonicalise differently give a reviewer two rules to learn and one more
// thing to get wrong when they recompute a digest by hand". A third rule
// would be worse still. So this module reproduces Python's output byte for
// byte, rather than calling `serde_json::to_vec`, which does not.
//
// -------------------------------------------------------------------
// WHERE serde_json ALONE DIVERGES FROM PYTHON, AND WHAT WE DO
// -------------------------------------------------------------------
// 1. NON-ASCII. `json.dumps` defaults to `ensure_ascii=True`: the character
//    U+00E9 is written as the six ASCII bytes \u00e9. `serde_json` emits
//    the two raw UTF-8 bytes instead. Any Arabic clause text, any accented
//    org or reviewer name, silently breaks digest agreement between the Rust
//    writer and the Python verifier. FIXED HERE: `write_json_string` escapes
//    every codepoint outside 0x20..=0x7E, using UTF-16 surrogate pairs above
//    the BMP, exactly as CPython's `c_encode_basestring_ascii` does.
//
// 2. DEL (0x7F). CPython's `S_CHAR` macro is `c >= ' ' && c <= '~'`, so 0x7F
//    is escaped to \u007f. `serde_json` passes it through raw.
//    FIXED HERE: the same 0x20..=0x7E printable window.
//
// 3. KEY ORDER. Python's `sort_keys` sorts by codepoint; `serde_json::Map`
//    is a `BTreeMap<String, _>`, i.e. UTF-8 byte order. Those two orders
//    coincide, because UTF-8 preserves codepoint order — so no fix is
//    needed. We nonetheless re-sort into an explicit `BTreeMap` below rather
//    than trusting `Map`'s iteration order, because that order is one Cargo
//    feature away from being insertion order (`serde_json/preserve_order`),
//    and a silently changed digest is precisely the failure this module
//    exists to prevent.
//
// 4. FLOATS. Python renders 1e300 as `1e+300`; Rust's ryu renders it as
//    `1e300`. Python emits bare `NaN`/`Infinity`, which are not JSON at all
//    and which `serde_json` refuses to produce. Matching Python across the
//    whole float domain would mean reimplementing CPython's `repr(float)`.
//    NOT FIXED — REFUSED INSTEAD: `canonical_bytes` returns
//    `CanonicalError::FloatNotPermitted` for any non-integer number. Within
//    the permitted domain (null, bool, string, integer, array, object) the
//    output is byte-identical to Python's, and that domain covers all of
//    DecisionEvidence: no field of it is float-typed. The only route a float
//    could take in is a caller-supplied `policy.thresholds.values`, whose
//    real members are the i64/i16 columns of `products`
//    (migrations/0004_products.sql). A money amount arriving as a float is a
//    bug worth failing on, not rounding.
//
// 5. INTEGER RANGE. Python's ints are arbitrary precision; serde_json's are
//    i64/u64. A wider value cannot be constructed on this side at all, so it
//    cannot diverge here — it fails earlier, at the type.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("value is not serialisable to JSON: {0}")]
    Serde(#[from] serde_json::Error),
    /// See note 4 in the module header.
    #[error(
        "the canonical form permits integers only; found the floating-point value {0}. \
         Python's json.dumps and Rust's ryu disagree on exponent formatting, so a float \
         here would produce a digest that only one of the two verifiers of a sealed pack \
         could reproduce. Encode fixed-point amounts as integers in minor units."
    )]
    FloatNotPermitted(f64),
}

/// The canonical serialisation. Byte-identical to
/// `scripts/export_audit_evidence.py::canonical_bytes` for every value this
/// function accepts.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let json = serde_json::to_value(value)?;
    let mut out = String::new();
    write_value(&json, &mut out)?;
    Ok(out.into_bytes())
}

/// SHA-256 over `canonical_bytes`, lower-case hex — the same shape as the
/// seal's `canonical_evidence_sha256` field and as
/// `crypto::signer::proof_digest_hex`.
pub fn canonical_sha256_hex<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if n.is_f64() {
                // `is_f64` is true only for numbers that did not land in
                // i64/u64, i.e. genuine floats. Integers keep integer
                // rendering, which Python matches exactly.
                return Err(CanonicalError::FloatNotPermitted(
                    n.as_f64().unwrap_or(f64::NAN),
                ));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sorted explicitly, not by trusting `Map`'s own iteration
            // order — see note 3 in the module header.
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push('{');
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// CPython's `c_encode_basestring_ascii`, transliterated. Its printable
/// window is `S_CHAR(c) = c >= ' ' && c <= '~' && c != backslash && c != quote`;
/// everything outside it is escaped — short form where one exists, otherwise
/// lower-case-hex \uXXXX.
///
/// Matched on codepoints rather than `char` literals so that every escape
/// sequence in this function appears exactly once, in the table below, and
/// cannot be mistyped in a pattern.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        let cp = ch as u32;
        match cp {
            0x22 => out.push_str(r#"\""#),
            0x5c => out.push_str(r"\\"),
            0x08 => out.push_str(r"\b"),
            0x0c => out.push_str(r"\f"),
            0x0a => out.push_str(r"\n"),
            0x0d => out.push_str(r"\r"),
            0x09 => out.push_str(r"\t"),
            0x20..=0x7e => out.push(ch),
            _ if cp <= 0xFFFF => {
                out.push_str(r"\u");
                out.push_str(&format!("{cp:04x}"));
            }
            _ => {
                // UTF-16 surrogate pair, as Python emits for astral planes.
                let v = cp - 0x1_0000;
                let high = 0xD800 + (v >> 10);
                let low = 0xDC00 + (v & 0x3FF);
                out.push_str(r"\u");
                out.push_str(&format!("{high:04x}"));
                out.push_str(r"\u");
                out.push_str(&format!("{low:04x}"));
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Every expected string below was produced by running this project's own
    // canonicaliser over the same input:
    //
    //   json.dumps(OBJ, sort_keys=True, separators=(",", ":"))
    //
    // If one of these fails, either this file drifted or
    // `export_audit_evidence.py:200` did — and the two independent verifiers
    // of a sealed pack no longer agree on what its digest covers.

    fn canon(v: Value) -> String {
        String::from_utf8(canonical_bytes(&v).unwrap()).unwrap()
    }

    #[test]
    fn keys_are_sorted_and_separators_are_tight() {
        assert_eq!(
            canon(json!({"b": 1, "a": {"d": [1, 2], "c": null}})),
            r#"{"a":{"c":null,"d":[1,2]},"b":1}"#
        );
    }

    #[test]
    fn non_ascii_is_escaped_the_way_python_escapes_it() {
        // The divergence that would otherwise have broken every Arabic
        // clause string and every accented reviewer surname:
        // `serde_json::to_string` emits these as raw UTF-8.
        assert_eq!(
            canon(json!({"name": "Société"})),
            r#"{"name":"Soci\u00e9t\u00e9"}"#
        );
        assert_eq!(
            canon(json!({"clause": "البند"})),
            r#"{"clause":"\u0627\u0644\u0628\u0646\u062f"}"#
        );
    }

    #[test]
    fn astral_codepoints_become_utf16_surrogate_pairs() {
        assert_eq!(canon(json!("\u{1F512}")), r#""\ud83d\udd12""#);
    }

    #[test]
    fn control_characters_and_del_match_cpython() {
        // DEL is the subtle one: CPython escapes it, serde_json does not.
        assert_eq!(canon(json!("a\u{7f}b")), r#""a\u007fb""#);
        assert_eq!(
            canon(json!("\t\n\r\u{08}\u{0c}\u{01}")),
            r#""\t\n\r\b\f\u0001""#
        );
        assert_eq!(
            canon(json!("quote\"back\\slash")),
            r#""quote\"back\\slash""#
        );
        // Python does not escape the forward slash. Neither do we.
        assert_eq!(canon(json!("a/b")), r#""a/b""#);
    }

    #[test]
    fn floats_are_refused_rather_than_silently_diverging() {
        let err = canonical_bytes(&json!({"x": 1.5})).unwrap_err();
        assert!(matches!(err, CanonicalError::FloatNotPermitted(_)));
        // Integers at the edges of the range are fine.
        assert_eq!(
            canon(json!({"x": i64::MIN, "y": u64::MAX})),
            r#"{"x":-9223372036854775808,"y":18446744073709551615}"#
        );
    }

    #[test]
    fn digest_is_sha256_of_exactly_those_bytes() {
        let value = json!({"a": 1});
        assert_eq!(canonical_bytes(&value).unwrap(), br#"{"a":1}"#.to_vec());
        // python3: hashlib.sha256(canonical_bytes({"a": 1})).hexdigest()
        assert_eq!(
            canonical_sha256_hex(&value).unwrap(),
            "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
        );
    }
}
