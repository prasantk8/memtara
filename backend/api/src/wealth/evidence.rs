// `GET /api/v1/wealth-assessments/:request_id` — everything needed to
// reconstruct one suitability assessment, in one call.
//
// -------------------------------------------------------------------
// WHY THIS IS AN API AND NOT A REPORT GENERATOR
// -------------------------------------------------------------------
// The obvious way to build a compliance evidence pack is a script that
// queries Postgres directly. It is also the wrong way, for a reason that
// only shows up later: a bank's compliance function will eventually want the
// pack in their own template, in Arabic, joined to their own CRM. If the
// only way to get the evidence is a script we wrote against our schema, they
// are blocked on us for every one of those.
//
// So the schema stays private and the evidence is a documented, org-scoped
// response. `scripts/export_audit_evidence.py` is then just one consumer of
// it — the one that happens to render a PDF — and a bank can write another.
//
// What is deliberately NOT in here: the client's income, liquid assets, risk
// tolerance or holdings. The server never had them. That absence is the
// product, so the response says so explicitly rather than leaving a reader to
// notice the gap and wonder whether it is an oversight.

use axum::extract::{Path, State};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use crate::crypto::signer::proof_digest_hex;
use crate::domain::CircuitType;
use crate::error::{ApiError, ApiResult};
use crate::orgs::OrgAuth;
use crate::state::AppState;
use crate::verify::public_input_layout;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) async fn get_wealth_assessment(
    OrgAuth(org_id): OrgAuth,
    Path(request_id): Path<Uuid>,
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    // Scoped by `org_id` in the WHERE clause, not fetched-then-checked. A
    // request belonging to another tenant is indistinguishable from one that
    // does not exist, which is the only answer that doesn't confirm the
    // existence of a competitor's assessment.
    let req = sqlx::query!(
        r#"
        select w.product_isin, w.product_name, w.product_id, w.product_ref,
               w.min_income, w.min_liquidity, w.max_concentration_percent, w.product_risk_level,
               w.window_start, w.window_end, w.suitable, w.assessed_at, w.created_at,
               d.user_id, d.org_id, d.status, d.nonce, d.expires_at,
               o.name as org_name, o.org_type
        from wealth_requests w
        join disclosure_requests d on d.id = w.request_id
        join organizations o on o.id = d.org_id
        where w.request_id = $1 and d.org_id = $2
        "#,
        request_id,
        org_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    // Every attempt, accepted and rejected. A pack that showed only the
    // accepted proof would hide the fact that four earlier submissions
    // failed, which is exactly the pattern a reviewer is looking for.
    let proofs = sqlx::query!(
        r#"
        select id, valid, verified_at, public_inputs, proof_bytes
        from proofs
        where request_id = $1
        order by verified_at asc
        "#,
        request_id,
    )
    .fetch_all(&state.db)
    .await?;

    let proof_json: Vec<serde_json::Value> = proofs
        .iter()
        .map(|p| {
            json!({
                "proof_id": p.id,
                "accepted_by_bb_verify": p.valid,
                "verified_at": p.verified_at,
                "proof_bytes": p.proof_bytes.len(),
                // The same digest that appears in the token's `proof_hash`
                // claim and in AIHOOTS's audit chain. Three independent
                // records of one artefact; if they agree, the chain is
                // genuinely tied to this proof.
                "proof_sha256": proof_digest_hex(&p.proof_bytes),
                "public_inputs": p.public_inputs,
            })
        })
        .collect();

    // The audit excerpt: this request's own events, in chain order, with the
    // linkage a verifier needs. `seq` is the position in the global chain —
    // see audit/mod.rs on why consecutive entries here are not adjacent.
    let events = sqlx::query!(
        r#"
        select seq as "seq!", event_type, event_hash, prev_hash, created_at
        from audit_log
        where ref_id = $1 and (org_id = $2 or org_id is null)
        order by seq asc
        "#,
        request_id,
        org_id,
    )
    .fetch_all(&state.db)
    .await?;

    let event_json: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            json!({
                "seq": e.seq,
                "event_type": e.event_type,
                "event_hash": hex(&e.event_hash),
                "prev_hash": e.prev_hash.as_ref().map(|h| hex(h)),
                "created_at": e.created_at,
            })
        })
        .collect();

    // The verification key this assessment was checked against. An examiner
    // re-verifying the proof needs its digest to know they are holding the
    // same key; without it, "the proof verifies" is a claim about a key
    // nobody identified.
    let vkey_path =
        std::path::Path::new(&state.config.vkeys_dir).join(CircuitType::WealthSuitability.as_str()).join("vk");
    let vkey = match tokio::fs::read(&vkey_path).await {
        Ok(bytes) => json!({
            "sha256": hex(&<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&bytes))),
            "bytes": bytes.len(),
            "verifier_target": "noir-recursive",
            "published_at": "circuits/wealth_suitability/vkey/vk",
        }),
        Err(_) => json!({ "sha256": null, "note": "verification key not readable on this instance" }),
    };

    let layout = public_input_layout(CircuitType::WealthSuitability);

    Ok(Json(json!({
        "request_id": request_id,
        "circuit": CircuitType::WealthSuitability.as_str(),
        "status": req.status,
        "organisation": { "id": req.org_id, "name": req.org_name, "type": req.org_type },
        "subject": {
            "user_id": req.user_id,
            // Named rather than left implicit. A reader of an evidence pack
            // will look for the client's finances; this tells them why they
            // will not find them.
            "disclosed_attributes": [],
            "note": "Memtara holds no income, liquidity, risk-tolerance or holdings figure for \
                     this subject. The assessment was computed on the holder's device and only \
                     its one-bit result was disclosed.",
        },
        "product": {
            "id": req.product_id,
            "isin": req.product_isin,
            "name": req.product_name,
            "product_ref": format!("0x{}", hex(&req.product_ref)),
        },
        "terms_assessed_against": {
            "min_income": req.min_income,
            "min_liquidity": req.min_liquidity,
            "max_concentration_percent": req.max_concentration_percent,
            "product_risk_level": req.product_risk_level,
            "source": "product registry, snapshotted when the assessment was opened",
        },
        "window": {
            "start": req.window_start,
            "end": req.window_end,
            "expires_at": req.expires_at,
        },
        "outcome": {
            "assessed": req.suitable.is_some(),
            "suitable": req.suitable,
            "assessed_at": req.assessed_at,
            "read_from": format!("public input {} of {}", layout.outcome_index.unwrap_or(0), layout.count),
            "note": "`bb verify` succeeding means the proof is well formed, not that the client \
                     passed. The verdict is the circuit's public output and is read explicitly.",
        },
        "nonce": format!("0x{}", hex(&req.nonce)),
        "verification_key": vkey,
        "proofs": proof_json,
        "audit_chain_excerpt": event_json,
        "regulatory_mapping": {
            "dfsa": ["COB 3.1"],
            "cbuae": ["5(c)", "5(d)", "4(a)"],
        },
        "opened_at": req.created_at,
    })))
}
