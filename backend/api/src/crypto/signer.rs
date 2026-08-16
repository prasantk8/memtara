// Ed25519 proof-token issuance and the JWK Set that lets anyone verify the
// result offline.
//
// Why hand-rolled JWS rather than a JWT crate: the signed input is exactly
// `ASCII(base64url(header) || "." || base64url(payload))` and the signature
// is a raw 64-byte Ed25519 signature, base64url'd (RFC 7515 §3.3 +
// RFC 8037 §3.1). That is short enough to write once and read forever, and
// a compliance reviewer can check the bytes we sign against the RFC without
// tracing through a library's option surface. It also means there is no
// `alg` negotiation: this issuer signs EdDSA and nothing else, so the
// `alg: "none"` and algorithm-confusion families of JWT bugs have no code
// path to live in.

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Env var holding the base64-encoded Ed25519 private key.
pub const PRIVATE_KEY_ENV: &str = "MEMTARA_PRIVATE_KEY";

/// The only `alg` this issuer will ever emit. See module comment.
const ALG: &str = "EdDSA";

/// Claims carried by a proof token.
///
/// The four the integration contract requires are `user_id`, `predicate`,
/// `verified` and `exp`. The rest exist because an attestation that can't be
/// tied back to a specific verification event isn't audit evidence:
/// `proof_hash` binds the token to the exact proof bytes that were verified,
/// and `regulatory_audit_id` is the join key between this token, Memtara's
/// own `audit_log` chain, and AIHOOTS's `audit.jsonl` chain — the single
/// identifier that makes the two independent hash chains correlatable
/// without either system calling the other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofTokenClaims {
    /// Issuer — this deployment's public base URL.
    pub iss: String,
    /// Subject: same value as `user_id`, present so generic JOSE tooling
    /// (which looks for `sub`) works without knowing our claim names.
    pub sub: String,
    pub user_id: String,
    /// The predicate that was proven, e.g. `income_gte_threshold`.
    pub predicate: String,
    /// Always `true` on an issued token: a failed verification does not
    /// produce a token at all, it produces an error. The field is explicit
    /// rather than implied so a relying party can assert on it and fail
    /// closed if a future version ever issues negative attestations.
    pub verified: bool,
    /// Which of the four Noir circuits produced the verdict.
    pub circuit: String,
    /// SHA-256 of the verified proof bytes, hex. Binds this attestation to
    /// one specific proof.
    pub proof_hash: String,
    /// Correlation id written into Memtara's audit chain alongside this
    /// issuance, and echoed into AIHOOTS's chain by the relying party.
    pub regulatory_audit_id: String,
    /// CBUAE Guidance Note clauses this disclosure is evidence for, e.g.
    /// `["5(c)", "5(d)"]`. See docs/REGULATORY_MATRIX.md.
    pub cbuae_clauses: Vec<String>,
    /// Suitability attestations only: the ISO 6166 identifier of the
    /// structured product the assessment was performed for.
    ///
    /// Present because a suitability verdict is meaningless detached from
    /// the instrument it was reached about — the same client is suitable for
    /// one note and not another. A relying party that acts on `suitable`
    /// without checking this claim against the product it is actually about
    /// to recommend has an audit trail that proves the wrong thing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_isin: Option<String>,
    /// Suitability attestations only: the circuit's own public output.
    ///
    /// This is NOT `verified` under another name. `verified` says a proof
    /// was cryptographically checked; `suitable` is the answer that proof
    /// carried, and it is legitimately `false` sometimes — a documented
    /// decline is evidence of an assessment under DFSA COB 3.1, and
    /// suppressing it would leave a declined recommendation looking
    /// identical to one that was never assessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suitable: Option<bool>,
    /// DFSA Conduct of Business rules this attestation is evidence for, e.g.
    /// `["COB 3.1"]`.
    ///
    /// A separate claim from `cbuae_clauses` rather than a merged
    /// `regulatory_refs` list, because the two are different regulators with
    /// different citation schemes and a relying party filing evidence with
    /// one of them needs to know which citations are addressed to it. An
    /// empty list is omitted from the token entirely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dfsa_rules: Vec<String>,
    /// Issued-at / expiry, seconds since the Unix epoch.
    pub iat: i64,
    pub exp: i64,
    /// Unique token id — lets a relying party reject a replayed token
    /// within the validity window if it chooses to keep a seen-set.
    pub jti: String,
}

#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// This deployment's issuer identity: one Ed25519 key plus its derived
/// public material. Cheap to clone is not needed — it lives behind an `Arc`
/// in `AppState`.
pub struct IssuerKey {
    signing: SigningKey,
    /// base64url-no-pad of the 32-byte public key — the JWK `x` parameter
    /// (RFC 8037 §2).
    public_x: String,
    /// RFC 7638 JWK thumbprint, base64url-no-pad. Stable for a given key,
    /// so a relying party that caches the JWKS can tell whether the key it
    /// has is still the one being used.
    kid: String,
    /// Issuer URL stamped into every token's `iss`.
    issuer: String,
}

impl IssuerKey {
    /// Load the issuer key from `MEMTARA_PRIVATE_KEY`, or generate an
    /// ephemeral one if unset.
    ///
    /// Accepted encodings for the env var (both standard and URL-safe
    /// base64, with or without padding):
    ///   * 32 bytes — an Ed25519 seed (the usual form)
    ///   * 64 bytes — a seed||public concatenation as emitted by some
    ///     tooling; the trailing public half is recomputed from the seed
    ///     and the supplied copy is ignored rather than trusted.
    ///
    /// The ephemeral fallback is deliberate and loud. A hardcoded default
    /// private key would be a real vulnerability the moment someone shipped
    /// it; refusing to boot would make `cargo test` and local development
    /// require key management for no security benefit. An ephemeral key
    /// gives a working local system whose tokens simply stop verifying
    /// across a restart — an obvious symptom, not a silent one.
    pub fn from_env(issuer: &str) -> anyhow::Result<Self> {
        match std::env::var(PRIVATE_KEY_ENV) {
            Ok(encoded) if !encoded.trim().is_empty() => {
                let seed = decode_private_key(encoded.trim())?;
                Ok(Self::from_seed(seed, issuer))
            }
            _ => {
                tracing::warn!(
                    "{PRIVATE_KEY_ENV} is not set — generating an EPHEMERAL Ed25519 issuer key. \
                     Proof tokens will stop verifying when this process restarts. Set \
                     {PRIVATE_KEY_ENV} (see .env.example) for any deployment that matters."
                );
                let mut seed = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut seed);
                Ok(Self::from_seed(seed, issuer))
            }
        }
    }

    pub fn from_seed(seed: [u8; 32], issuer: &str) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public_x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let kid = jwk_thumbprint(&public_x);
        Self { signing, public_x, kid, issuer: issuer.to_string() }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The public key as an RFC 8037 OKP JWK, wrapped in a JWK Set.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": self.public_x,
                "use": "sig",
                "alg": ALG,
                "kid": self.kid,
            }]
        })
    }

    /// Sign `claims` into a compact-serialization JWS (a JWT).
    pub fn issue(&self, claims: &ProofTokenClaims) -> anyhow::Result<String> {
        let header = JwsHeader { alg: ALG, typ: "JWT", kid: &self.kid };
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?),
        );
        let signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
    }
}

/// SHA-256 of the proof bytes, lowercase hex — the `proof_hash` claim.
///
/// Hex rather than base64 because this value is meant to be pasted into an
/// audit report and eyeball-compared against AIHOOTS's chain, which is hex
/// throughout (`src/gateway/audit/chain.py` uses `hexdigest()`).
pub fn proof_digest_hex(proof_bytes: &[u8]) -> String {
    let digest = Sha256::digest(proof_bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 7638 thumbprint for an OKP key: SHA-256 over the JSON object of the
/// required members only (`crv`, `kty`, `x`), lexicographically ordered, no
/// whitespace. Built by hand rather than via `serde_json::to_string` on a
/// map, because RFC 7638 requires exact member ordering and no insignificant
/// whitespace — properties of a specific byte string, not of "some JSON that
/// happens to have these fields".
fn jwk_thumbprint(public_x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{public_x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn decode_private_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    // Try both alphabets; operators paste whichever their key-generation
    // tool emitted, and failing on the wrong one would be a needlessly
    // confusing startup error.
    let bytes = B64_STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')))
        .map_err(|_| anyhow::anyhow!("{PRIVATE_KEY_ENV} is not valid base64"))?;

    match bytes.len() {
        32 => Ok(bytes.try_into().expect("length checked immediately above")),
        // seed||public: keep the seed, recompute the public half rather
        // than trusting the supplied copy (a mismatched pair would
        // otherwise produce tokens that fail against our own JWKS).
        64 => Ok(bytes[..32].try_into().expect("length checked immediately above")),
        n => anyhow::bail!(
            "{PRIVATE_KEY_ENV} decoded to {n} bytes; expected 32 (Ed25519 seed) or 64 (seed||public)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn test_signer() -> IssuerKey {
        IssuerKey::from_seed([7u8; 32], "https://api.memtara.test")
    }

    /// Rebuild the verifying key from what `/.well-known/jwks.json` would
    /// actually serve. Every test below verifies against THIS, never
    /// against private material — which is the property that matters: a
    /// relying party only ever has the published bytes.
    fn published_key(signer: &IssuerKey) -> VerifyingKey {
        let x = signer.jwks()["keys"][0]["x"].as_str().expect("x is a string").to_string();
        let bytes: [u8; 32] =
            URL_SAFE_NO_PAD.decode(&x).expect("x is base64url").try_into().expect("32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("valid Ed25519 point")
    }

    fn sample_claims() -> ProofTokenClaims {
        ProofTokenClaims {
            iss: "https://api.memtara.test".into(),
            sub: "11111111-1111-1111-1111-111111111111".into(),
            user_id: "11111111-1111-1111-1111-111111111111".into(),
            predicate: "income_gte_threshold".into(),
            verified: true,
            circuit: "tax_session".into(),
            proof_hash: proof_digest_hex(b"proof bytes"),
            regulatory_audit_id: "22222222-2222-2222-2222-222222222222".into(),
            cbuae_clauses: vec!["5(c)".into(), "5(d)".into()],
            product_isin: None,
            suitable: None,
            dfsa_rules: vec![],
            iat: 1_760_000_000,
            exp: 1_760_000_300,
            jti: "33333333-3333-3333-3333-333333333333".into(),
        }
    }

    #[test]
    fn same_seed_yields_same_public_key_and_kid() {
        let a = test_signer();
        let b = test_signer();
        assert_eq!(a.public_x, b.public_x);
        assert_eq!(a.kid(), b.kid());
    }

    #[test]
    fn different_seeds_yield_different_kids() {
        let a = IssuerKey::from_seed([7u8; 32], "https://api.memtara.test");
        let b = IssuerKey::from_seed([8u8; 32], "https://api.memtara.test");
        assert_ne!(a.kid(), b.kid());
    }

    #[test]
    fn jwks_is_a_wellformed_rfc8037_okp_key_set() {
        let signer = test_signer();
        let jwks = signer.jwks();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], signer.kid());

        // `x` must be exactly the 32-byte public key, base64url-no-pad.
        let x = key["x"].as_str().expect("x is a string");
        let decoded = URL_SAFE_NO_PAD.decode(x).expect("x is base64url");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn issued_token_verifies_against_the_published_public_key() {
        let signer = test_signer();
        let token = signer.issue(&sample_claims()).expect("issue");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has exactly three parts");

        // Reconstruct the signing input exactly as RFC 7515 §5.2 specifies
        // and check it against the key a relying party would fetch from
        // /.well-known/jwks.json — not against anything held privately.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature is base64url");
        let sig = Signature::from_slice(&sig_bytes).expect("64-byte signature");

        published_key(&signer).verify(signing_input.as_bytes(), &sig).expect("token verifies");
    }

    #[test]
    fn non_suitability_tokens_carry_no_suitability_claims_at_all() {
        // `skip_serializing_if` means these are absent, not null. A relying
        // party reading `suitable` on a token that never made a suitability
        // assessment must get "no such claim" rather than a JSON null it
        // might coerce to false — the two are different facts.
        let token = test_signer().issue(&sample_claims()).expect("issue");
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
        let obj = payload.as_object().unwrap();
        assert!(!obj.contains_key("suitable"));
        assert!(!obj.contains_key("product_isin"));
        assert!(!obj.contains_key("dfsa_rules"));
    }

    #[test]
    fn a_negative_suitability_verdict_survives_the_round_trip() {
        // The failure this guards against is a `skip_serializing_if` that
        // treats `Some(false)` as "nothing to say" — which would turn every
        // declined recommendation into a token that looks like it was never
        // assessed, exactly inverting the evidence DFSA COB 3.1 wants.
        let mut claims = sample_claims();
        claims.predicate = "structured_product_suitable".into();
        claims.circuit = "wealth_suitability".into();
        claims.product_isin = Some("XS1234567890".into());
        claims.suitable = Some(false);
        claims.dfsa_rules = vec!["COB 3.1".into()];

        let token = test_signer().issue(&claims).expect("issue");
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();

        assert_eq!(payload["suitable"], serde_json::Value::Bool(false));
        assert_eq!(payload["product_isin"], "XS1234567890");
        assert_eq!(payload["dfsa_rules"][0], "COB 3.1");
        // `verified` is about the proof, not the verdict, and stays true.
        assert_eq!(payload["verified"], serde_json::Value::Bool(true));

        let decoded: ProofTokenClaims = serde_json::from_value(payload).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn tampering_with_the_payload_breaks_verification() {
        let signer = test_signer();
        let token = signer.issue(&sample_claims()).expect("issue");
        let parts: Vec<&str> = token.split('.').collect();

        // Flip `verified` to false — the exact forgery a relying party
        // must not accept, and the reason `verified` is a signed claim
        // rather than an assumption.
        let mut claims = sample_claims();
        claims.verified = false;
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

        let signing_input = format!("{}.{}", parts[0], forged_payload);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();

        assert!(published_key(&signer).verify(signing_input.as_bytes(), &sig).is_err());
    }

    #[test]
    fn header_declares_eddsa_and_the_matching_kid() {
        let signer = test_signer();
        let token = signer.issue(&sample_claims()).expect("issue");
        let header_json = URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], signer.kid());
    }

    #[test]
    fn claims_round_trip_through_the_payload_segment() {
        let signer = test_signer();
        let claims = sample_claims();
        let token = signer.issue(&claims).expect("issue");
        let payload_json = URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap();
        let decoded: ProofTokenClaims = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn env_key_accepts_a_32_byte_seed_and_a_64_byte_pair() {
        let seed = [9u8; 32];
        let expected = IssuerKey::from_seed(seed, "https://x").public_x;

        let from_seed = decode_private_key(&B64_STANDARD.encode(seed)).unwrap();
        assert_eq!(IssuerKey::from_seed(from_seed, "https://x").public_x, expected);

        // seed || public — the trailing half is recomputed, not trusted, so
        // even a garbage public half yields the correct key.
        let mut pair = seed.to_vec();
        pair.extend_from_slice(&[0u8; 32]);
        let from_pair = decode_private_key(&B64_STANDARD.encode(&pair)).unwrap();
        assert_eq!(IssuerKey::from_seed(from_pair, "https://x").public_x, expected);
    }

    #[test]
    fn env_key_rejects_wrong_length_and_non_base64() {
        assert!(decode_private_key(&B64_STANDARD.encode([1u8; 16])).is_err());
        assert!(decode_private_key("not base64 at all !!!").is_err());
    }

    #[test]
    fn thumbprint_matches_rfc7638_canonical_form() {
        // Recompute the thumbprint independently from the RFC's rule
        // (required members, lexicographic order, no whitespace) rather
        // than calling the function under test with different inputs.
        let signer = test_signer();
        let x = &signer.public_x;
        let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        assert_eq!(signer.kid(), expected);
    }

    #[test]
    fn proof_digest_is_stable_lowercase_hex() {
        let d = proof_digest_hex(b"abc");
        // Known SHA-256("abc") — a fixed vector, not a self-comparison.
        assert_eq!(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(d.len(), 64);
    }
}
