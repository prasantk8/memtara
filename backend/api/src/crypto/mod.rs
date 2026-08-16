// Cryptographic identity for the *issuer* side of Memtara: the Ed25519 key
// this deployment signs proof tokens with, and the JWKS endpoint that lets a
// relying party (AIHOOTS, a bank's own gateway) verify those tokens without
// ever calling back here.
//
// This is a THIRD, deliberately separate key domain. The codebase now has:
//   1. WebAuthn passkeys        — authenticate a human to this backend
//   2. Baby Jubjub / EdDSA      — sign vault records, verified INSIDE the
//                                 Noir circuits (circuits/lib/src/signature_verify.nr)
//   3. Ed25519 (this module)    — sign the issuer's attestation ABOUT a
//                                 verified proof, for consumption outside
//                                 the ZK system entirely
//
// Keeping (3) uncoupled from (2) is not incidental. Baby Jubjub is chosen
// for cheap in-circuit verification over BN254; Ed25519 is chosen because
// every JOSE library on earth can verify it (RFC 8037). Forcing one key to
// do both jobs would mean either an expensive circuit or a signature no
// standard verifier accepts.

pub mod signer;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/jwks.json", get(jwks))
}

/// `GET /.well-known/jwks.json` — the public half of this deployment's
/// signing key, in the standard JWK Set format a relying party's JOSE
/// library consumes directly.
///
/// Unauthenticated by design: a public key is public, and requiring a
/// credential to fetch it would defeat the point of offline validation.
async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(state.signer.jwks())
}
