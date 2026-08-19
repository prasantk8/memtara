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

use chrono::{DateTime, Duration, Utc};
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

// ---------------------------------------------------------------------
// THE WINDOW A DECLARED MODEL CALL MAY SIT IN
//
// `model.timestamp` is the one leaf capable of dating a model call against
// the decision it claims to describe, and until this pass it was stored
// verbatim with nothing looking at it: attack 11 declares a call timestamped
// January 2023 for an assessment opened in 2026, and the server accepts it,
// stores it, and serves it as `state: "recorded"`. A leaf that would expose a
// stale attestation is worth nothing if it is never read.
//
// Both bounds are measured against the ASSESSMENT'S OWN OPEN TIME — the
// server's clock at the moment `POST /api/v1/issue-wealth-request` was
// received, and the same instant that becomes `window_start` — rather than
// against `now()` at some later point, because the question is not "is this
// timestamp plausible today" but "could this model call have produced the
// recommendation THIS assessment is about".
// ---------------------------------------------------------------------

/// How far AHEAD of the assessment's open time a declared model call may sit.
///
/// Some tolerance is mandatory and not merely kind. The timestamp is produced
/// by the calling AI system's clock, the open time by ours, and two hosts in
/// the same rack routinely disagree by seconds — the break-it suite documents
/// this deployment's own Postgres container running tens of milliseconds ahead
/// of the server process, and a bank desktop is far worse than a container.
/// Refusing on a few seconds of skew would fail honest requests, and an
/// endpoint that 400s an honest integration is one a bank routes around, which
/// would cost the record the whole field.
///
/// Beyond the tolerance it is not skew, it is nonsense: a model call in next
/// quarter cannot have produced a recommendation being assessed now. Five
/// minutes, the same number and the same reasoning as
/// `review::MAX_CLOCK_SKEW_SECONDS`, so a caller integrating both endpoints
/// has one allowance to learn rather than two.
const MAX_MODEL_CALL_SKEW_SECONDS: i64 = 300;

/// How far BEHIND the assessment's open time a declared model call may sit.
///
/// A model call legitimately precedes the assessment: the recommendation is
/// produced first and the assessment is opened to evidence it. Overnight batch
/// scoring, a desk that picks the run up the next morning, a long weekend —
/// all normal, all hours or days rather than seconds, which is why this bound
/// is nothing like the one above.
///
/// Thirty days is deliberately loose, and the looseness is the point. This
/// check exists to refuse a timestamp that is IMPOSSIBLE for this assessment,
/// not to enforce a model-freshness policy that no firm here has stated and
/// that Memtara has no standing to invent. A tight bound would reject
/// legitimate submissions, and the pressure it created would land on making
/// the field *pass* rather than making it *true* — integrators would send
/// `now()` and the leaf would go back to being worth nothing, which is exactly
/// the state this pass is closing. Thirty days is longer than any advisory
/// episode this product has seen and three orders of magnitude shorter than
/// the three-year gap attack 11 walks through.
const MAX_MODEL_CALL_BACKDATE_DAYS: i64 = 30;

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

/// A declared model-call timestamp that could belong to this assessment, or a
/// 400 that says why it could not.
///
/// Refused rather than stored, and refused rather than downgraded to an
/// `unpopulated` leaf with a note. Both softer options were considered:
///
///   * Storing it and flagging it in the record moves the judgement to
///     whoever reads the export, months later, when the integration that
///     produced it has shipped a thousand more. The caller is the only party
///     who can still find out what happened, and they are on the phone right
///     now.
///   * Dropping the value and recording "the caller supplied an implausible
///     timestamp" would put a fact about our validator inside the model
///     block, where every other leaf is a fact about the model. It would also
///     silently discard the single most interesting field in a swapped
///     attestation.
///
/// So it is a 400, and the body says which bound was crossed and by how much,
/// because "invalid timestamp" is a message an integrator cannot act on.
fn check_model_timestamp(
    timestamp: DateTime<Utc>,
    assessment_opened_at: DateTime<Utc>,
) -> ApiResult<DateTime<Utc>> {
    let latest = assessment_opened_at + Duration::seconds(MAX_MODEL_CALL_SKEW_SECONDS);
    if timestamp > latest {
        let ahead = (timestamp - assessment_opened_at).num_seconds();
        return Err(ApiError::BadRequest(format!(
            "ai_participation.timestamp ({timestamp}) is {ahead} seconds after this assessment \
             was opened ({assessment_opened_at}), which is more than the \
             {MAX_MODEL_CALL_SKEW_SECONDS} seconds of clock skew this endpoint tolerates. The \
             field records when the MODEL was called, and a model call cannot have produced the \
             recommendation an assessment opened before it is about. Some tolerance is allowed \
             because your clock and ours are different clocks; this is past that. If the intent \
             was to record when the assessment was opened, that is decision.timestamps.opened_at \
             and this server sets it"
        )));
    }

    let earliest = assessment_opened_at - Duration::days(MAX_MODEL_CALL_BACKDATE_DAYS);
    if timestamp < earliest {
        let behind = (assessment_opened_at - timestamp).num_days();
        return Err(ApiError::BadRequest(format!(
            "ai_participation.timestamp ({timestamp}) is {behind} days before this assessment was \
             opened ({assessment_opened_at}), and this endpoint accepts at most \
             {MAX_MODEL_CALL_BACKDATE_DAYS}. A model call legitimately precedes the assessment it \
             is evidenced by — overnight scoring picked up the next morning is ordinary — so the \
             bound is deliberately generous rather than tight. It is not a freshness policy and \
             is not trying to be one. What it refuses is a timestamp that cannot belong to this \
             decision at all, which is the shape a stale or copied attestation takes: the model \
             identity is asserted by the calling system and this leaf is the only one that can \
             be checked against anything, so it is checked"
        )));
    }

    Ok(timestamp)
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
///
/// `assessment_opened_at` is the server's clock at the moment the assessment
/// this declaration belongs to was opened. It is a parameter rather than a
/// `Utc::now()` inside this function because the correction endpoint resolves
/// a declaration weeks after the fact and must measure its timestamp against
/// the same instant the original was measured against — otherwise a
/// correction could carry a model call the original declaration would have
/// been refused for.
pub fn resolve_value(
    raw: Option<serde_json::Value>,
    assessment_opened_at: DateTime<Utc>,
) -> ApiResult<AttestationRow> {
    // A JSON `null` is silence, not a malformed declaration.
    let raw = match raw {
        None | Some(serde_json::Value::Null) => return resolve(None, assessment_opened_at),
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
    resolve(Some(declared), assessment_opened_at)
}

/// Turn what the caller said — including having said nothing — into the row
/// that will be written.
///
/// `None` is a first-class input here, not an error and not the empty case.
/// It is the whole reason this function takes an `Option` rather than being
/// called only when a block is present.
pub fn resolve(
    declared: Option<AiParticipation>,
    assessment_opened_at: DateTime<Utc>,
) -> ApiResult<AttestationRow> {
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
                // Checked, not merely stored — see `check_model_timestamp`.
                // `None` stays `None`: a caller that supplied no timestamp
                // has an honest gap, and refusing it would trade a partial
                // truth for no truth, which is the rule the other six
                // optional leaves already follow.
                model_timestamp: timestamp
                    .map(|t| check_model_timestamp(t, assessment_opened_at))
                    .transpose()?,
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

/// Read a CORRECTION back into the evidence record's `model` block.
///
/// Separate from `to_attestation` and deliberately not a parameter on it. The
/// two produce the same shape from the same `AttestationRow`, and every
/// sentence they put in the record differs: a leaf the calling system left out
/// at open time is filled by a field on `issue-wealth-request`, and a leaf a
/// correction left out is filled by a field on the corrections endpoint. A
/// shared function with a flag would have produced one of those two sentences
/// for both cases, and the wrong one is worse than none — it tells a reader to
/// go and look at a request that has already happened.
///
/// The reason text names the correction by number and by author, so a reader
/// who lands on a single leaf learns that the value they are looking at is not
/// the one this decision was opened with, without having to know that
/// `model_provenance` exists.
///
/// `no_ai_participated` cannot arrive here: migrations/0009 forbids it as a
/// corrected declaration and `model_correction.rs` refuses it with a 400. The
/// arm is handled rather than unwrapped for the reason `wealth/evidence.rs`
/// gives about impossible database rows — a row read out of a database is
/// input, and the honest failure for one is a record that says what it found,
/// not a panic.
pub fn correction_to_attestation(
    correction_no: i32,
    asserted_by: &str,
    asserted_at: DateTime<Utc>,
    row: &AttestationRow,
) -> ModelAttestation {
    let provenance = format!(
        "correction {correction_no}, asserted by {asserted_by} on {asserted_at}, supersedes the \
         model identity this assessment was opened with. The original declaration is preserved \
         unaltered at model_provenance.as_declared_at_open"
    );

    let gap = |field: &str| {
        format!(
            "{provenance}. That correction did not supply {field}; it would be supplied as \
             corrected_model.{field} on \
             POST /api/v1/wealth-assessments/{{request_id}}/model-corrections"
        )
    };
    let leaf = |field: &str, value: Option<String>| match value {
        Some(v) => Provenanced::recorded(v),
        None => Provenanced::unpopulated(gap(field)),
    };

    match row.declaration {
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
                None => Provenanced::unpopulated(gap("timestamp")),
            },
        }),
        // Both remaining cases produce an object with unpopulated leaves and
        // never `model: null`. An AI whose identity is unknown must not
        // collapse into the bytes that assert no AI took part — and a
        // correction is precisely where that collapse would be most damaging,
        // because it would let a decision opened naming a model end up
        // asserting none was involved.
        _ => ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(&format!(
            "{provenance}. It states that an AI participated in this decision and that the \
             organisation cannot identify which: {}",
            row.unidentified_reason
                .as_deref()
                .unwrap_or("no reason was recorded, which the CHECK constraint \
                            decision_model_corrections_unidentified_names_why forbids — this row \
                            was written around the schema"),
        ))),
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

    /// A fixed open time, so that every timestamp assertion below is about
    /// the bounds and not about how long the test took to run.
    fn opened_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-18T17:59:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn parse(v: serde_json::Value) -> Result<AttestationRow, ApiError> {
        resolve_value(Some(v), opened_at())
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
        let silent = resolve(None, opened_at()).unwrap();
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

    /// The one leaf that can date a model call against its decision is
    /// checked against that decision, and the check is neither a wall nor a
    /// decoration.
    ///
    /// The load-bearing case is the first one: attack 11 declares a model
    /// call in January 2023 for an assessment opened in 2026 and the server
    /// used to store it verbatim and serve it as `state: "recorded"`. The
    /// rest of the table exists so that closing that hole cannot be mistaken
    /// for closing the field: an honest overnight batch, a caller whose clock
    /// is a minute fast, and a caller with no timestamp at all must all still
    /// get through.
    #[test]
    fn a_model_call_that_cannot_belong_to_this_assessment_is_refused() {
        let identified = |ts: &str| {
            json!({
                "declaration": "model_identified",
                "provider": "anthropic",
                "model_name": "claude-opus-4",
                "timestamp": ts,
            })
        };
        let stored = |ts: &str| parse(identified(ts)).map(|r| r.model_timestamp);

        // (a) THE FINDING. Three years before the assessment was opened.
        let err = stored("2023-01-05T04:00:00Z").unwrap_err();
        match &err {
            ApiError::BadRequest(m) => {
                assert!(m.contains("days before this assessment was opened"), "{m}");
                // The body names the bound rather than only announcing a
                // refusal, because an integrator cannot act on "invalid".
                assert!(m.contains(&MAX_MODEL_CALL_BACKDATE_DAYS.to_string()), "{m}");
            }
            other => panic!("expected a 400 naming the backdate bound, got {other:?}"),
        }

        // (b) A model call in next quarter is nonsense in the other
        //     direction, and is refused for a visibly different reason.
        let err = stored("2026-11-01T00:00:00Z").unwrap_err();
        match &err {
            ApiError::BadRequest(m) => {
                assert!(m.contains("after this assessment was opened"), "{m}")
            }
            other => panic!("expected a 400 naming the skew bound, got {other:?}"),
        }

        // (c) Legitimate submissions, all of which a tighter rule would have
        //     broken. A call a few seconds after our clock (skew), one a
        //     minute before (the ordinary case), an overnight batch picked up
        //     the next morning, and a fortnight-old run.
        for ok in [
            "2026-08-18T18:01:00Z",
            "2026-08-18T17:58:00Z",
            "2026-08-18T02:14:33Z",
            "2026-08-04T09:00:00Z",
        ] {
            assert!(stored(ok).is_ok(), "{ok} must not be refused");
        }

        // (d) Exactly on each bound is accepted; one second past each is
        //     not. Pins the comparison as inclusive rather than leaving it to
        //     whichever way a future `>` gets typed.
        let open = opened_at();
        let at = |t: DateTime<Utc>| stored(&t.to_rfc3339());
        assert!(at(open + Duration::seconds(MAX_MODEL_CALL_SKEW_SECONDS)).is_ok());
        assert!(at(open + Duration::seconds(MAX_MODEL_CALL_SKEW_SECONDS + 1)).is_err());
        assert!(at(open - Duration::days(MAX_MODEL_CALL_BACKDATE_DAYS)).is_ok());
        assert!(at(open - Duration::days(MAX_MODEL_CALL_BACKDATE_DAYS) - Duration::seconds(1)).is_err());

        // (e) No timestamp at all is still an honest gap and not an error.
        //     Refusing it would trade a partial truth for no truth, which is
        //     the rule the other six optional leaves follow.
        let none = parse(json!({
            "declaration": "model_identified",
            "provider": "anthropic",
            "model_name": "claude-opus-4",
        }))
        .unwrap();
        assert!(none.model_timestamp.is_none());
        let v = serde_json::to_value(to_attestation(&none)).unwrap();
        assert_eq!(
            v.pointer("/timestamp/state").and_then(|x| x.as_str()),
            Some("unpopulated")
        );

        // (f) A refused timestamp refuses the whole declaration. It must not
        //     be possible to get a row written with the offending value
        //     quietly dropped — that would turn a caller's error into a
        //     silent gap in the record, and the gap would name our validator
        //     rather than the model.
        assert!(parse(json!({
            "declaration": "model_identified",
            "provider": "anthropic",
            "model_name": "claude-opus-4",
            "timestamp": "2023-01-05T04:00:00Z",
        }))
        .is_err());
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
