// The intake contract for MODEL identity.
//
// -------------------------------------------------------------------
// WHY THIS IS A CONTRACT AND NOT A FEATURE
// -------------------------------------------------------------------
// Nothing in this repository can source a model identity. There is no LLM
// gateway here and the founder's scope decision is explicit that there will
// not be one this quarter: capture model identity on the single path the
// pilot actually exercises, nothing more. So the entire engineering problem
// is the shape of the question we ask the calling AI system, and what we do
// with silence.
//
// -------------------------------------------------------------------
// THE ONE THING THIS FILE EXISTS TO PREVENT
// -------------------------------------------------------------------
// `model: null` in a sealed record is a signed assertion that no AI system
// participated in this decision. It is not "we did not capture that". A firm
// that runs no models can prove it rather than leave a blank, which is the
// commercial point of the field — and it is exactly why the assertion must
// never be reachable by accident.
//
// The failure mode is specific and it is the default one. An integration
// forgets a field; the server has nothing to record; the naive handler
// writes the empty case; the record now says, inside bytes the firm signed,
// that no AI was involved in a decision an AI made. Nobody lied. The API
// shape did it.
//
// So the mapping here is deliberately asymmetric:
//
//   caller says nothing            -> participated_but_unidentified
//   caller sends an empty object   -> 400
//   caller sends a blank statement -> 400
//   caller explicitly declares it  -> no_ai_participated
//
// Silence costs the caller an honest admission of ignorance. The flattering
// answer costs them a sentence they had to type. That asymmetry is the whole
// design, and it is the reverse of what happens by default.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::evidence::{ModelAttestation, ModelIdentity, Provenanced};

/// The shortest free-text justification accepted for either of the two
/// declarations that carry one. Same floor, and same reasoning, as
/// `evidence::MIN_OVERRIDE_REASON_CHARS` and the CHECK constraints in
/// migrations/0006: it does not measure quality, it stops `"x"`, `"n/a"` and
/// `"-"`, which is what a required free-text field collects when nobody
/// means to fill it in.
const MIN_STATEMENT_CHARS: usize = 10;

/// What the caller declares about AI participation in this decision.
///
/// An externally tagged enum on `declaration`, so the three cases are
/// mutually exclusive at the parser and a caller cannot half-fill one. There
/// is no `#[serde(other)]` and no default variant: an unrecognised
/// declaration is a 400, because the set of honest answers is closed and
/// growing it silently is how a fourth meaning gets invented in the field.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "declaration", rename_all = "snake_case", deny_unknown_fields)]
pub enum AiParticipation {
    /// The strong assertion. Reachable only from here — never from omission,
    /// never from an empty object, never from a null.
    NoAiParticipated {
        /// What decided instead, in the firm's own words. Required, because
        /// an assertion this strong with nothing behind it is a checkbox,
        /// and a checkbox is what this record exists to replace.
        attestation: String,
    },
    /// An AI participated and here is which one.
    ModelIdentified {
        provider: String,
        model_name: String,
        // The remaining six are individually optional. A caller that knows
        // its provider and model but not its config fingerprint should
        // record the two it has and carry the third as an explicit gap —
        // refusing the whole submission would trade a partial truth for no
        // truth, and inventing a default would trade it for a false one.
        #[serde(default)]
        model_version: Option<String>,
        #[serde(default)]
        prompt_version: Option<String>,
        #[serde(default)]
        environment: Option<String>,
        #[serde(default)]
        config_fingerprint: Option<String>,
        #[serde(default)]
        system_prompt_or_policy_id: Option<String>,
        #[serde(default)]
        timestamp: Option<DateTime<Utc>>,
    },
    /// An AI participated and the caller cannot say which. The honest middle
    /// state, and the one silence maps to.
    ParticipatedButUnidentified { reason: String },
}

/// What the caller was told we recorded, echoed on the response.
///
/// An integrator who meant to declare a model and mistyped the tag would
/// otherwise learn about it from an evidence export months later. This is
/// the cheapest possible way to make the difference visible at integration
/// time, when it is still free to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedDeclaration {
    NoAiParticipated,
    ModelIdentified,
    ParticipatedButUnidentified,
}

/// The reason recorded when a caller supplies no `ai_participation` block at
/// all.
///
/// Written into `decision_model_attestations.unidentified_reason` and read
/// back into every leaf of the model block, so an examiner sees the gap and
/// what would have closed it without reading our source — and so that the
/// silence is legible as silence rather than as an answer.
pub const SILENCE_REASON: &str =
    "the calling system supplied no ai_participation block on \
     POST /api/v1/issue-wealth-request, so whether an AI participated in this decision is \
     unknown to Memtara. This is NOT an assertion that no AI was involved: that assertion \
     requires an explicit declaration of no_ai_participated with a statement of what decided \
     instead, and is never inferred from omission";

/// One row of `decision_model_attestations`, validated and ready to write.
///
/// Deliberately flat and deliberately not `AiParticipation`: the enum is the
/// wire shape and the row is the storage shape, and keeping them separate is
/// what lets the CHECK constraints in migrations/0006 be a genuine second
/// opinion rather than a restatement of the parser.
#[derive(Debug, Clone)]
pub struct AttestationRow {
    pub declaration: &'static str,
    pub no_ai_attestation: Option<String>,
    pub unidentified_reason: Option<String>,
    pub provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub prompt_version: Option<String>,
    pub environment: Option<String>,
    pub config_fingerprint: Option<String>,
    pub system_prompt_or_policy_id: Option<String>,
    pub model_timestamp: Option<DateTime<Utc>>,
}

impl AttestationRow {
    pub fn recorded_declaration(&self) -> RecordedDeclaration {
        match self.declaration {
            "no_ai_participated" => RecordedDeclaration::NoAiParticipated,
            "model_identified" => RecordedDeclaration::ModelIdentified,
            _ => RecordedDeclaration::ParticipatedButUnidentified,
        }
    }
}

fn non_blank(field: &str, value: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "ai_participation.{field} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn statement(field: &str, value: &str, why: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.chars().count() < MIN_STATEMENT_CHARS {
        return Err(ApiError::BadRequest(format!(
            "ai_participation.{field} must be at least {MIN_STATEMENT_CHARS} characters. {why}"
        )));
    }
    Ok(trimmed.to_string())
}

/// A lower-case hex SHA-256, or a 400.
///
/// Rejected rather than stored loosely because these two fields are digests
/// or they are nothing: a value that is not a digest sitting under a key
/// named `..._fingerprint` reads to an examiner as a commitment that can be
/// recomputed, and it cannot be. Same lower-case hex convention as
/// `crypto::signer::proof_digest_hex` and `circuits/.../vk_hash`, so an
/// examiner has one rule to learn.
pub fn parse_digest(field: &str, value: &str) -> ApiResult<String> {
    let v = value.trim().to_ascii_lowercase();
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be a SHA-256 as 64 lower-case hex characters (got {} characters). \
             It is a digest an examiner recomputes or it is nothing, so a value that is not one \
             is refused rather than stored under a name that promises it is",
            v.len()
        )));
    }
    Ok(v)
}

/// Parse and resolve the raw `ai_participation` value from the request body.
///
/// -------------------------------------------------------------------
/// WHY THIS TAKES A `Value` AND NOT AN `Option<AiParticipation>`
/// -------------------------------------------------------------------
/// Typing the field as the enum directly makes axum's `Json` extractor
/// reject a malformed declaration before the handler runs, and its rejection
/// is a bare 422 reading "Failed to deserialize the JSON body". Safe — the
/// refusal still happens, and silence still cannot reach the no-AI assertion
/// — but useless: the integrator most likely to send a malformed block is
/// the one trying to declare something for the first time, and telling them
/// only that the body was wrong is how a field gets abandoned.
///
/// So the field arrives untyped and is parsed here, where the error can name
/// the three declarations and what each requires.
pub fn resolve_value(raw: Option<serde_json::Value>) -> ApiResult<AttestationRow> {
    // A JSON `null` is silence, not a malformed declaration.
    let raw = match raw {
        None | Some(serde_json::Value::Null) => return resolve(None),
        Some(v) => v,
    };
    let declared: AiParticipation = serde_json::from_value(raw).map_err(|e| {
        ApiError::BadRequest(format!(
            "ai_participation is not a recognised declaration ({e}). It must be exactly one of: \
             {{\"declaration\":\"no_ai_participated\",\"attestation\":\"<what decided instead>\"}} \
             — a signed assertion that no AI took part, which is why it costs a sentence; \
             {{\"declaration\":\"model_identified\",\"provider\":\"...\",\"model_name\":\"...\"}} \
             plus any of model_version, prompt_version, environment, config_fingerprint, \
             system_prompt_or_policy_id, timestamp; or \
             {{\"declaration\":\"participated_but_unidentified\",\"reason\":\"<why not>\"}}. \
             Omitting the field entirely is also accepted and records the third case — it never \
             records the first"
        ))
    })?;
    resolve(Some(declared))
}

/// Turn what the caller said — including having said nothing — into the row
/// that will be written.
///
/// `None` is a first-class input here, not an error and not the empty case.
/// It is the whole reason this function takes an `Option` rather than being
/// called only when a block is present.
pub fn resolve(declared: Option<AiParticipation>) -> ApiResult<AttestationRow> {
    let blank = AttestationRow {
        declaration: "participated_but_unidentified",
        no_ai_attestation: None,
        unidentified_reason: None,
        provider: None,
        model_name: None,
        model_version: None,
        prompt_version: None,
        environment: None,
        config_fingerprint: None,
        system_prompt_or_policy_id: None,
        model_timestamp: None,
    };

    let Some(declared) = declared else {
        // Silence. The honest answer, never the flattering one.
        return Ok(AttestationRow {
            unidentified_reason: Some(SILENCE_REASON.to_string()),
            ..blank
        });
    };

    match declared {
        AiParticipation::NoAiParticipated { attestation } => Ok(AttestationRow {
            declaration: "no_ai_participated",
            no_ai_attestation: Some(statement(
                "attestation",
                &attestation,
                "Declaring that no AI participated is a signed assertion inside the sealed \
                 record, not a blank. Name what decided instead — the rules engine, the \
                 desk, the committee — so that a reader in three years can check the claim \
                 against something",
            )?),
            ..blank
        }),

        AiParticipation::ParticipatedButUnidentified { reason } => Ok(AttestationRow {
            unidentified_reason: Some(statement(
                "reason",
                &reason,
                "Say why the model cannot be named — an upstream vendor that does not expose \
                 it, a legacy path with no instrumentation. A gap that does not name what \
                 would fill it is indistinguishable from a bug",
            )?),
            ..blank
        }),

        AiParticipation::ModelIdentified {
            provider,
            model_name,
            model_version,
            prompt_version,
            environment,
            config_fingerprint,
            system_prompt_or_policy_id,
            timestamp,
        } => {
            let optional = |field: &str, v: Option<String>| -> ApiResult<Option<String>> {
                match v {
                    None => Ok(None),
                    Some(s) => non_blank(field, &s).map(Some),
                }
            };
            let config_fingerprint = match config_fingerprint {
                None => None,
                Some(s) => Some(parse_digest("ai_participation.config_fingerprint", &s)?),
            };
            Ok(AttestationRow {
                declaration: "model_identified",
                provider: Some(non_blank("provider", &provider)?),
                model_name: Some(non_blank("model_name", &model_name)?),
                model_version: optional("model_version", model_version)?,
                prompt_version: optional("prompt_version", prompt_version)?,
                environment: optional("environment", environment)?,
                config_fingerprint,
                system_prompt_or_policy_id: optional(
                    "system_prompt_or_policy_id",
                    system_prompt_or_policy_id,
                )?,
                model_timestamp: timestamp,
                ..blank
            })
        }
    }
}

/// The reason a single leaf carries when the caller identified a model but
/// left that leaf out. Names the exact request field that would fill it.
fn leaf_gap(field: &str) -> String {
    format!(
        "the calling system identified a model but did not supply \
         ai_participation.{field} on POST /api/v1/issue-wealth-request"
    )
}

fn leaf(field: &str, value: Option<String>) -> Provenanced<String> {
    match value {
        Some(v) => Provenanced::recorded(v),
        None => Provenanced::unpopulated(leaf_gap(field)),
    }
}

/// Read a stored row back into the evidence record's `model` block.
///
/// The three declarations map to three visibly different serialisations and
/// there is no fourth:
///
///   no_ai_participated             -> `"model": null`
///   model_identified               -> an object with recorded leaves
///   participated_but_unidentified  -> an object with unpopulated leaves
///
/// The second and third are both objects, and that is the point: an AI whose
/// identity is unknown must not collapse into the same bytes as no AI at
/// all, or a firm that lost its model metadata would be signing a claim it
/// runs no models.
pub fn to_attestation(row: &AttestationRow) -> ModelAttestation {
    match row.declaration {
        "no_ai_participated" => ModelAttestation::no_ai_participated(),
        "model_identified" => ModelAttestation::recorded(ModelIdentity {
            provider: leaf("provider", row.provider.clone()),
            model_name: leaf("model_name", row.model_name.clone()),
            model_version: leaf("model_version", row.model_version.clone()),
            prompt_version: leaf("prompt_version", row.prompt_version.clone()),
            environment: leaf("environment", row.environment.clone()),
            config_fingerprint: leaf("config_fingerprint", row.config_fingerprint.clone()),
            system_prompt_or_policy_id: leaf(
                "system_prompt_or_policy_id",
                row.system_prompt_or_policy_id.clone(),
            ),
            timestamp: match row.model_timestamp {
                Some(t) => Provenanced::recorded(t),
                None => Provenanced::unpopulated(leaf_gap("timestamp")),
            },
        }),
        _ => ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(
            row.unidentified_reason.as_deref().unwrap_or(SILENCE_REASON),
        )),
    }
}

/// The attestation for a decision opened before this capture path existed —
/// or for one whose row is somehow absent.
///
/// Not `no_ai_participated`, for the same reason silence is not: an
/// assessment opened in July 2026 was opened by a system that was never
/// asked the question, and a record claiming it involved no AI would be
/// asserting something nobody ever established.
pub fn absent_attestation() -> ModelAttestation {
    ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(
        "this assessment was opened before model identity capture existed \
         (migrations/0006_decision_capture.sql), so no declaration was ever requested from the \
         calling system. Absence of a declaration is not a declaration of absence",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: serde_json::Value) -> Result<AttestationRow, ApiError> {
        resolve_value(Some(v))
    }

    /// The invariant the whole module exists for.
    ///
    /// Every route to `model: null` that does not involve a caller typing
    /// the declaration and a sentence must fail to produce it. If any of
    /// these ever yields `no_ai_participated`, a firm can sign a claim it
    /// uses no AI by forgetting a field.
    #[test]
    fn no_route_from_silence_or_error_reaches_the_no_ai_assertion() {
        // (a) Field entirely absent.
        let silent = resolve(None).unwrap();
        assert_eq!(silent.declaration, "participated_but_unidentified");
        assert!(to_attestation(&silent).identity().is_some());
        assert!(!to_attestation(&silent).asserts_no_ai());
        assert!(silent.unidentified_reason.unwrap().contains("NOT an assertion"));

        // (b) Explicit JSON null for the block.
        let nulled = parse(json!(null)).unwrap();
        assert_eq!(nulled.declaration, "participated_but_unidentified");

        // (c) An empty object, a wrong tag, a misspelled tag: all refused
        //     outright. None of them may degrade to the strong assertion.
        for bad in [
            json!({}),
            json!({ "declaration": "none" }),
            json!({ "declaration": "no_ai" }),
            json!({ "declaration": "NoAiParticipated" }),
            json!({ "declaration": "no_ai_participated" }),
            json!({ "declaration": "model_identified" }),
        ] {
            let err = parse(bad.clone()).unwrap_err();
            assert!(
                matches!(err, ApiError::BadRequest(_)),
                "{bad} must be refused, not interpreted"
            );
        }

        // (d) A declaration with a blank or token attestation is refused —
        //     the assertion costs a sentence, and that is deliberate.
        for weak in ["", "   ", "n/a", "none", "no ai"] {
            let err = parse(json!({
                "declaration": "no_ai_participated",
                "attestation": weak,
            }))
            .unwrap_err();
            assert!(matches!(err, ApiError::BadRequest(_)), "{weak:?}");
        }

        // (e) And the one route that does reach it, works.
        let asserted = parse(json!({
            "declaration": "no_ai_participated",
            "attestation": "suitability produced by the deterministic rules engine in Avaloq; \
                            no model in the recommendation path",
        }))
        .unwrap();
        assert_eq!(asserted.declaration, "no_ai_participated");
        assert!(to_attestation(&asserted).asserts_no_ai());
        assert_eq!(
            serde_json::to_value(to_attestation(&asserted)).unwrap(),
            serde_json::Value::Null
        );
    }

    /// An unidentified model and no model are different bytes.
    ///
    /// This is the type-level invariant from `evidence/mod.rs` re-asserted
    /// at the intake boundary, because the intake is where the two could be
    /// confused: both cases arrive with no provider and no model name.
    #[test]
    fn an_unnamed_model_is_not_the_same_record_as_no_model() {
        let unnamed = parse(json!({
            "declaration": "participated_but_unidentified",
            "reason": "the recommendation arrives from the group model gateway, which does not \
                       yet return which deployment served it",
        }))
        .unwrap();
        let none = parse(json!({
            "declaration": "no_ai_participated",
            "attestation": "deterministic rules engine only, no model in the path",
        }))
        .unwrap();

        let a = serde_json::to_value(to_attestation(&unnamed)).unwrap();
        let b = serde_json::to_value(to_attestation(&none)).unwrap();
        assert!(a.is_object(), "an unnamed model must serialise as an object");
        assert!(b.is_null(), "no model must serialise as null");
        assert_ne!(a, b);
        assert_eq!(
            a.pointer("/provider/state").and_then(|v| v.as_str()),
            Some("unpopulated")
        );
        // The reason travels into every leaf, so a reader who lands on any
        // one field learns why it is empty.
        assert!(a
            .pointer("/model_name/unpopulated_reason")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("group model gateway"));
    }

    /// A partly-known model records what is known and marks the rest,
    /// rather than refusing the submission or defaulting the gaps.
    #[test]
    fn a_partly_identified_model_records_the_parts_it_has() {
        let row = parse(json!({
            "declaration": "model_identified",
            "provider": "anthropic",
            "model_name": "claude-opus-4",
            "environment": "production",
        }))
        .unwrap();
        let v = serde_json::to_value(to_attestation(&row)).unwrap();

        assert_eq!(v.pointer("/provider/value").and_then(|x| x.as_str()), Some("anthropic"));
        assert_eq!(
            v.pointer("/environment/value").and_then(|x| x.as_str()),
            Some("production")
        );
        for missing in ["model_version", "prompt_version", "config_fingerprint", "timestamp"] {
            assert_eq!(
                v.pointer(&format!("/{missing}/state")).and_then(|x| x.as_str()),
                Some("unpopulated"),
                "{missing}"
            );
            assert!(v
                .pointer(&format!("/{missing}/unpopulated_reason"))
                .and_then(|x| x.as_str())
                .unwrap()
                .contains(missing));
        }

        // An identification that names neither provider nor model is not an
        // identification, and is refused rather than stored as one.
        for bad in [
            json!({ "declaration": "model_identified", "provider": "", "model_name": "x" }),
            json!({ "declaration": "model_identified", "provider": "x", "model_name": "  " }),
        ] {
            assert!(matches!(parse(bad).unwrap_err(), ApiError::BadRequest(_)));
        }
    }

    /// Fingerprints are digests or they are refused.
    #[test]
    fn a_fingerprint_that_is_not_a_digest_is_refused() {
        assert!(parse(json!({
            "declaration": "model_identified",
            "provider": "anthropic",
            "model_name": "claude-opus-4",
            "config_fingerprint": "temperature=0",
        }))
        .is_err());

        let good = "ab".repeat(32);
        let row = parse(json!({
            "declaration": "model_identified",
            "provider": "anthropic",
            "model_name": "claude-opus-4",
            "config_fingerprint": good.to_uppercase(),
        }))
        .unwrap();
        // Normalised to lower case, so two callers who disagree about case
        // do not produce two different-looking commitments to one config.
        assert_eq!(row.config_fingerprint.as_deref(), Some(good.as_str()));

        assert!(parse_digest("x", &"a".repeat(63)).is_err());
        assert!(parse_digest("x", &"g".repeat(64)).is_err());
    }

    /// A decision from before the capture path is unidentified, never
    /// no-AI. Catches a future "backfill the old rows" instinct.
    #[test]
    fn a_pre_capture_decision_is_unidentified_not_ai_free() {
        let a = absent_attestation();
        assert!(!a.asserts_no_ai());
        let v = serde_json::to_value(&a).unwrap();
        assert!(v.is_object());
        assert!(v
            .pointer("/provider/unpopulated_reason")
            .and_then(|x| x.as_str())
            .unwrap()
            .contains("Absence of a declaration is not a declaration of absence"));
    }
}
