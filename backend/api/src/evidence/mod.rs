// DecisionEvidence — the record a regulator reads when nobody from Memtara
// is in the room.
//
// INTEGRATED as of schema 1.1.0, at 1.3.0 as of this build.
// `wealth/evidence.rs::build_decision_evidence` is the single construction
// site; `GET /api/v1/wealth-assessments/:id/decision-evidence` serves it and
// `POST .../review` returns it. The note that used to stand here — "nothing in
// this module is wired into a route yet" — is no longer true, and the model
// and human_review blocks now carry captured values rather than placeholders.
//
// 1.2.0 added `model_provenance`, which is where the model block stopped
// being a single un-rechecked forward declaration. Read that type's header
// before changing anything about `model`.
//
// 1.3.0 gave `data.consent` a real source (`consents::` /
// migrations/0011_consent_grants.sql) and renamed `DecisionBasis::
// ProofAndHumanApproved` to `ProofAndHumanConcurred` — see the constant's
// header below for both.
//
// -------------------------------------------------------------------
// WHY THE ALLOW IS STILL HERE, HONESTLY
// -------------------------------------------------------------------
// The previous note said both allows should come off in the integration
// task. They cannot come off cleanly yet, and pretending otherwise by
// deleting the line would trade one inaccurate comment for six new warnings.
// Removing it today reports: `canonical_bytes`/`canonical_sha256_hex` and
// `FieldState` as unused re-exports (callers reach them through the
// inherent methods and through `Provenanced`), `ModelAttestation::
// asserts_no_ai`/`identity`, `DecisionEvidence::canonical_bytes`, and
// `Provenanced::is_coherent`/`is_recorded` as never used — every one of them
// exercised only by this module's own tests.
//
// Those are real observations about a binary crate, not noise to suppress
// permanently. What removes the allow for good is a caller outside the
// tests reaching them: the offline verification bundle needs
// `canonical_bytes` and `is_coherent` (a record whose leaves contradict
// their own state should fail bundle validation, not travel), and the
// exporter needs `asserts_no_ai` to render "no AI participated" as a
// sentence rather than as an absent section. Both are named work, neither is
// this task, and the allow should be reviewed again when the first of them
// lands rather than left to become permanent furniture.
#![allow(dead_code, unused_imports)]

pub mod canonical;
pub mod provenance;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use canonical::{canonical_bytes, canonical_sha256_hex, CanonicalError};
pub use provenance::{FieldState, Provenanced};

/// The version of *this* schema. It is written into every record, inside the
/// signed payload (see `DecisionEvidence::evidence_schema_version`), and it
/// is the key an examiner uses to find `schema/decision_evidence/v1.3.0.json`
/// in the repo at the matching tag.
///
/// Bumping this is not a code change on its own. A new value requires a new
/// pinned `schema/decision_evidence/vX.Y.Z.json`; the existing file is
/// immutable once any record has been sealed against it, for the same reason
/// `circuits/wealth_suitability/vkey/vk_hash` is committed and CI-pinned — a
/// digest an examiner cannot re-derive two years later is not evidence.
///
/// -------------------------------------------------------------------
/// 1.0.0 -> 1.1.0: WHY
/// -------------------------------------------------------------------
/// `human_review` gained two keys — `review_duration_ms` and
/// `review_duration_source`. `schema/decision_evidence/v1.0.0.json` sets
/// `additionalProperties: false` on every block, so a 1.1.0 record is not a
/// valid 1.0.0 record and must not claim to be one. v1.0.0.json is left
/// byte-for-byte alone and `v1.1.0.json` was added beside it.
///
/// The addition is the Cigna field. In that litigation the finding that
/// ended the argument was a duration — roughly 1.2 seconds per claim, in
/// batches, without the file being opened. Every one of those denials had a
/// named reviewer, a timestamp and an action; a record carrying only the
/// v1.0.0 fields would have described them as fully reviewed. A firm's own
/// compliance function must be able to see that pattern in its own data, and
/// it cannot see it in fields that do not exist.
///
/// The bump is a minor version because the change is purely additive: every
/// v1.0.0 key survives with its meaning intact, so a reader written for
/// 1.0.0 that ignores unknown keys still reads a 1.1.0 record correctly.
/// Nothing was removed, renamed, or re-constrained.
///
/// -------------------------------------------------------------------
/// 1.1.0 -> 1.2.0: WHY
/// -------------------------------------------------------------------
/// The record gained one top-level key, `model_provenance`, and `model`
/// gained a second possible source.
///
/// The defect. `decision_model_attestations` is written in the same
/// transaction as the assessment, by `POST /api/v1/issue-wealth-request` —
/// before the client's device has proved anything, before a verdict exists
/// and before any human has reviewed it. Under 1.1.0 the record served that
/// forward declaration with every leaf `state: "recorded"`, which is the same
/// provenance a fact observed at decision time carries, and carried nothing
/// saying when the declaration was made or whether anything had since
/// contradicted it. `tests/break_it/test_attack_11_swap_model_undetected.py`
/// demonstrates the consequence against a running server: the model that
/// actually served the recommendation changes, no recorded field changes with
/// it, and the record reads as internally consistent and wrong.
///
/// `model_provenance` carries `declared_at` — so an examiner can compare it
/// against `decision.timestamps.assessed_at` and see for themselves that the
/// attestation predates the decision — the declaration as made at open,
/// verbatim and never altered, and the append-only corrections filed against
/// it through `POST /api/v1/wealth-assessments/{id}/model-corrections`.
///
/// WHY `model` NOW SERVES THE CORRECTED IDENTITY, AND WHY THAT IS STILL
/// ADDITIVE. The alternative was to leave `model` pinned to the original and
/// put the correction only in the new block. That was rejected: a reader who
/// looks at `model.provider` — which is every reader, and every tool written
/// against 1.1.0 — would get an identity the organisation has since said was
/// wrong, and would get it labelled `recorded`. The record would still lie,
/// with a footnote. So `model` means what it always meant, "which AI system
/// participated in this decision, as this organisation states it", and a
/// correction changes the answer rather than annotating it.
///
/// That is not a semantic break, and the reason is arithmetic: no record
/// written under 1.1.0 can have a correction, because the table did not
/// exist. For every 1.1.0-era record the original and the effective identity
/// are the same value, so nothing already sealed changes meaning or bytes. A
/// 1.1.0 reader pointed at a 1.2.0 record gets the organisation's current
/// best statement of which model ran, which is more correct than the original,
/// not less.
///
/// WHAT DID NOT CHANGE. `model: null` is still a signed assertion that no AI
/// participated, and it is now a slightly stronger one: a correction can never
/// assert `no_ai_participated` (migrations/0009 forbids it and
/// `model_correction.rs` refuses it with a 400), so `model: null` means the
/// declaration made at open said no AI took part AND nothing has since said
/// otherwise. An AI whose identity is unknown is still an object with
/// `unpopulated` leaves and still hashes differently.
///
/// Minor rather than major because every 1.1.0 key survives with its meaning
/// intact and nothing was removed, renamed or re-constrained. It is a new
/// file rather than an edit for the same reason 1.1.0 was: v1.1.0.json sets
/// `additionalProperties: false` at the top level, so a 1.2.0 record is not a
/// valid 1.1.0 record and must not claim to be one.
///
/// -------------------------------------------------------------------
/// 1.2.0 -> 1.3.0: WHY
/// -------------------------------------------------------------------
/// Two changes, bumped together because the first is what forced the bump
/// and the second was queued waiting for one: populating `data.consent`
/// with real provenance, and renaming `DecisionBasis::ProofAndHumanApproved`
/// to `ProofAndHumanConcurred`.
///
/// THE CONSENT LEAVES. `Consent`'s five fields — `consent_id`,
/// `consent_version`, `scope`, `granted_at`, `purpose_hash` — have carried
/// the same doc comment since schema 1.0.0: every one of them
/// `Provenanced::unpopulated`, because nothing in this repository could
/// source them. `migrations/0011_consent_grants.sql` and `consents::` are
/// that source. Populating a field the pinned shape has always had is not,
/// on its own, a reason to bump — the JSON Schema at every prior version
/// already allowed `state: "recorded"` here, so a 1.2.0 reader that ignores
/// `$comment`s reads a genuinely-populated 1.3.0 consent block exactly as
/// it would read the unpopulated one, key for key. The bump is forced by
/// the second change below, which touches the wire values of an existing
/// field and could not ship as a patch.
///
/// THE RENAME. `ProofAndHumanApproved` never described what this system
/// checks: `derive_decision_basis` reaches that variant whenever a human
/// reviewed a decision without overriding it, which includes a reviewer who
/// rubber-stamped without reading a word — `human_review.review_duration_ms`
/// is the field that can tell the difference, not this one. "Approved"
/// borrows the weight of a judgement the basis alone does not evidence.
/// "Concurred" says only what is true unconditionally: a human looked at the
/// same verdict the proof produced and did not go against it. The serialised
/// value moves with it, `proof_and_human_approved` -> `proof_and_human_
/// concurred`, which is exactly the kind of change `additionalProperties:
/// false` + a `const` on `evidence_schema_version` exists to make a breaking
/// one rather than a silent one: a 1.2.0-era reader matching on the old
/// string would now find nothing to match, which is the correct failure —
/// loud — rather than a reader quietly treating every future record as
/// unapproved.
///
/// Minor, not major, for the same test 1.1.0 and 1.2.0 both passed: no
/// record sealed under 1.2.0 or earlier can be re-interpreted as 1.3.0 —
/// each version file is immutable and a reader must already select the file
/// named by `evidence_schema_version` — so nothing already sealed changes
/// meaning or bytes. What changes is only what a NEW record may say.
pub const EVIDENCE_SCHEMA_VERSION: &str = "1.3.0";

// =====================================================================
// The record
// =====================================================================

/// One decision, in the shape an offline auditor validates against
/// `schema/decision_evidence/v{EVIDENCE_SCHEMA_VERSION}.json` — v1.2.0 as of
/// this build, with every superseded file still on disk beside it because a
/// record sealed under one of them validates against it and against nothing
/// else.
///
/// -------------------------------------------------------------------
/// FOUR INVARIANTS THIS TYPE ENFORCES STRUCTURALLY
/// -------------------------------------------------------------------
/// 1. REJECTION SYMMETRY. No field anywhere below is `Option<T>` because
///    the decision went against the client. `human_review.action` and
///    `decision.status` are required `DecisionAction` enums; `outcome` is a
///    required `DecisionOutcome`. Nothing in this module carries
///    `#[serde(skip_serializing_if)]`, so no key can vanish for any reason.
///    An approval and a rejection built from the same inputs serialise with
///    an identical key set at every level — asserted by
///    `rejection_and_approval_have_identical_key_sets`. This matters because
///    the seal is a digest over `canonical_bytes`: a key that disappears on
///    rejection changes the bytes, changes the digest, and makes "the record
///    was tampered with" and "the client was declined" look alike.
///
/// 2. THE SCHEMA VERSION IS INSIDE THE SIGNED PAYLOAD.
///    `evidence_schema_version` is a field of this struct, not sidecar
///    metadata beside it, so it is covered by the digest and travels with
///    the record. `export_audit_evidence.py:80-84` has the right instinct
///    one layer too high (it versions the *pack format*); this is the same
///    idea pushed down to the object that actually gets signed.
///
/// 3. `model: null` IS AN ASSERTION, NOT A GAP. See `ModelAttestation`.
///
/// 4. WHAT `model` SAYS TODAY AND WHAT WAS DECLARED AT OPEN ARE BOTH IN THE
///    RECORD, AND NEITHER CAN BE ABSENT. `model_provenance` is a required
///    field, so "nobody has contradicted this attestation" is a claim the
///    record makes explicitly rather than one a reader infers from a missing
///    block — and the declaration made when the assessment was opened is
///    preserved verbatim under it, so a correction adds a statement and never
///    erases one. New in 1.2.0; see `ModelProvenance` for why it exists and
///    `tests/break_it/test_attack_11_swap_model_undetected.py` for what it
///    costs not to have it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvidence {
    /// Semver of the schema this record was written under. Inside the
    /// payload deliberately — invariant 2.
    pub evidence_schema_version: String,
    pub decision: DecisionBlock,
    pub policy: PolicyBlock,
    pub data: DataBlock,
    /// Which AI system participated, as this organisation states it TODAY.
    ///
    /// `null` here is a signed assertion that no AI system participated. It
    /// is never "we did not record it". See `ModelAttestation`.
    ///
    /// Since 1.2.0 this is the declaration made at open time only until a
    /// correction contradicts it; `model_provenance` beside it says which,
    /// and preserves what was declared at open unaltered.
    pub model: ModelAttestation,
    /// How the block above came to say what it says: when the declaration was
    /// made, what it said at the time, and every correction filed against it.
    pub model_provenance: ModelProvenance,
    pub human_review: HumanReviewBlock,
    pub evidence: EvidenceBlock,
}

// ---------------------------------------------------------------------
// decision
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBlock {
    /// Today's `disclosure_requests.id`, which `wealth/evidence.rs:41`
    /// already threads through as `request_id`. Renamed here because the
    /// record is about a decision, not about the HTTP request that carried
    /// it; the natural key already exists.
    pub decision_id: Uuid,
    pub institution: Institution,
    /// e.g. "wealth.suitability_recommendation". No process identifier
    /// exists in the backend today — `circuit: "wealth_suitability"`
    /// (`wealth/evidence.rs:149`) names a proof type, not a business
    /// process, and conflating them would put a cryptographic artefact where
    /// a regulator expects a bank's own process taxonomy.
    pub business_process: Provenanced<String>,
    /// The decision's own disposition. NOT `disclosure_requests.status`,
    /// which is pipeline state (pending/fulfilled/expired). Required enum:
    /// this is the field §1.3 of the spec calls the crux.
    pub status: DecisionAction,
    pub final_decision: FinalDecision,
    /// Digest over the inputs the deciding system saw. Sibling of `model`
    /// rather than a child of it, deliberately: when `model` is null the
    /// decision still had inputs, and a fingerprint that disappears along
    /// with the AI would leave a non-AI decision with nothing committing to
    /// what it was decided on.
    pub input_context_fingerprint: Provenanced<String>,
    /// Digest over the decision's structured output, hashed the way
    /// `crypto::signer::proof_digest_hex` hashes proof bytes.
    pub output_fingerprint: Provenanced<String>,
    pub timestamps: Timestamps,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Institution {
    pub org_id: Uuid,
    pub org_name: String,
    /// `organizations.org_type` — bank / ai_platform / hospital /
    /// government. A string rather than `domain::OrgType` so that a record
    /// written by an older build still parses when a variant is added; an
    /// evidence reader must never fail closed on an org type it has not
    /// heard of.
    pub org_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalDecision {
    pub outcome: DecisionOutcome,
    pub decided_at: DateTime<Utc>,
    pub decision_basis: Provenanced<DecisionBasis>,
}

/// Approved / Rejected / Modified. Required everywhere it appears.
///
/// Three variants and no fourth: there is no `Pending`, because an evidence
/// record is written about a decision that was reached. A decision still in
/// flight has no evidence record, which is a different and honest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Approved,
    Rejected,
    Modified,
}

/// What the control actually returned.
///
/// This is `wealth/evidence.rs:180-187` promoted into the type system. That
/// code is the one place in the codebase that already distinguishes "no
/// proof exists" from "a proof exists and it says no" (see the exporter's
/// own note at `evidence.rs:971-976`). Collapsing `NoVerdict` into `Negative`
/// would let an outage read as a decline, which is the single most damaging
/// confusion available in this domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// A verdict was produced and it was affirmative (e.g. circuit public
    /// input 11, `suitable`, read as true).
    Affirmative,
    /// A verdict was produced and it was negative. NOT an absence.
    Negative,
    /// No verdict was produced — the control could not run. Pairs with
    /// `timestamps.assessed_at == null`.
    NoVerdict,
}

/// Why the decision came out the way it did — proof alone, proof plus a
/// human, or a human against the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionBasis {
    /// The cryptographic verdict, with no human in the loop.
    ProofOnly,
    /// A proof was verified and a human separately concurred with it.
    ProofAndHumanConcurred,
    /// A human overrode the cryptographic verdict. The most important
    /// variant in the set and the one a supervisor will grep for.
    ProofAndHumanOverride,
    /// The proof service was unavailable and a human decided anyway —
    /// Mode C in the spec's continuity section. Cannot be produced today
    /// and is here so that, when it can be, it has a name rather than
    /// being backfilled into `ProofOnly`.
    HumanOnlyProofUnavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamps {
    /// `wealth_requests.created_at`.
    pub opened_at: DateTime<Utc>,
    /// `wealth_requests.assessed_at`. Nullable because a decision can be
    /// opened and never assessed — NOT because it was rejected. A rejection
    /// has an `assessed_at` exactly as an approval does. The key is always
    /// present either way.
    pub assessed_at: Option<DateTime<Utc>>,
    /// When this record was exported. Today this exists only inside the
    /// PDF filename (`export_audit_evidence.py:495`), i.e. outside the
    /// hashed bytes, which means it is not evidence of anything.
    pub exported_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBlock {
    /// `disclosure_requests.policy` is snapshotted at open time
    /// (`wealth/mod.rs:294-322`) but carries no identifier and no version,
    /// and no `policies` table exists in migrations 0001-0005.
    pub policy_id: Provenanced<String>,
    pub policy_version: Provenanced<String>,
    /// Where the policy text came from. Populated today: the snapshot-on-
    /// write behaviour is real even though the versioning is not.
    pub source: String,
    /// Which revision of the rules turned inputs into a verdict — the
    /// circuit build plus the server-side checks. Distinct from
    /// `policy_version`: the policy can be unchanged while the logic that
    /// enforces it is rebuilt.
    pub decision_logic_version: Provenanced<String>,
    pub thresholds: Thresholds,
    pub regulatory_control_mapping: Vec<RegulatoryControl>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub threshold_set_id: Provenanced<String>,
    /// `products` is audited on every amendment with a before/after diff
    /// (`products/mod.rs:350-413`) but carries only `updated_at` — "which
    /// version applied" has to be reconstructed by replaying the audit
    /// chain. A monotonic `terms_version` column would populate this.
    pub threshold_version: Provenanced<String>,
    /// The threshold values themselves, snapshotted at open time. A sorted
    /// map so the canonical bytes do not depend on insertion order. Values
    /// must be integers or strings — see `canonical::CanonicalError`.
    pub values: BTreeMap<String, Value>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatoryControl {
    /// e.g. "DFSA", "CBUAE".
    pub framework: String,
    /// e.g. "COB 3.1", "5(c)".
    pub clause: String,
}

// ---------------------------------------------------------------------
// data
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataBlock {
    pub customer: Customer,
    pub consent: Consent,
    /// The version of the vault/record schema the subject's data was held
    /// under. Not threaded through the backend today.
    pub data_schema_version: Provenanced<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Customer {
    /// `disclosure_requests.user_id`. A pseudonymous identifier — the
    /// record deliberately carries no attribute values.
    pub subject_id: String,
    pub data_provenance: DataProvenance,
    pub data_provenance_version: Provenanced<String>,
}

/// Where the decision's inputs came from.
///
/// `wealth/evidence.rs:158-160` already says, in prose, that Memtara holds
/// none of the client's financial data. Prose is the right instinct and the
/// wrong container: a reader cannot diff it, and a translator can weaken it.
/// This is the same statement as structure — an explicitly empty
/// `disclosed_attributes` array, plus the cryptographic anchor that the
/// absence is defensible against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataProvenance {
    /// Attributes actually disclosed to the server. Empty for the wealth
    /// flow, and empty by design rather than by omission.
    pub disclosed_attributes: Vec<String>,
    /// The vault commitment the assessment was computed against — circuit
    /// public input `vault_root` (`verify/mod.rs:266-272`). The nearest
    /// thing to a provenance proof that exists today.
    pub vault_root: Provenanced<String>,
    /// Human-readable restatement, for the examiner who reads the PDF and
    /// not the JSON.
    pub statement: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub consent_id: Provenanced<String>,
    /// The consent *policy* version this grant was made under — the field
    /// the brief calls "consent policy version". Named `consent_version` to
    /// match the spec's §1.1 field list.
    pub consent_version: Provenanced<String>,
    pub scope: Provenanced<Vec<String>>,
    pub granted_at: Provenanced<DateTime<Utc>>,
    /// `SessionPolicy.purpose_hash` (`vault/src/session.rs:53,102`) — the
    /// only consent-adjacent value that exists today. It is a purpose
    /// *binding*, not a consent record: it has no grant time, no subject
    /// acknowledgement and no revocation path. Carried as its own field so
    /// that populating it can never be mistaken for having consent.
    pub purpose_hash: Provenanced<String>,
}

// ---------------------------------------------------------------------
// model
// ---------------------------------------------------------------------

/// Whether an AI system participated, and if so which one.
///
/// -------------------------------------------------------------------
/// WHY THIS IS A NAMED TYPE AND NOT A BARE `Option<ModelIdentity>`
/// -------------------------------------------------------------------
/// `model: null` is a *claim*, and a strong one: it says, inside the signed
/// bytes, that no AI system took part in this decision. It must never be
/// reachable by accident from "we did not capture that". A bare
/// `Option<ModelIdentity>` invites exactly that: someone with nothing to put
/// in it writes `None` and has silently signed an assertion they did not
/// mean to make.
///
/// So there are two constructors and no `Default`. If an AI did participate
/// but cannot yet be identified, the honest record is
/// `recorded(ModelIdentity::participated_but_unidentified(..))` — an object
/// whose every leaf is `Unpopulated`. That is visibly different from `null`
/// to any reader, and it is the only shape available for that case.
///
/// Commercially this is the point of the whole field: a firm with no AI in
/// production today produces a record of exactly the same shape as one that
/// runs a model, and can say so provably rather than by leaving a blank.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelAttestation(Option<ModelIdentity>);

impl ModelAttestation {
    /// A signed assertion that no AI system participated in this decision.
    /// Serialises as an explicit `null` under the key `model`; the key is
    /// never absent.
    pub fn no_ai_participated() -> Self {
        Self(None)
    }

    /// An AI system participated and here is what is known about it.
    pub fn recorded(identity: ModelIdentity) -> Self {
        Self(Some(identity))
    }

    /// True when this record asserts no AI took part. Distinct from
    /// "the model block is present but empty".
    pub fn asserts_no_ai(&self) -> bool {
        self.0.is_none()
    }

    pub fn identity(&self) -> Option<&ModelIdentity> {
        self.0.as_ref()
    }
}

/// Identity of the AI system that participated.
///
/// Every leaf is `Provenanced` because none of them has a source in this
/// repository: `grep -rn "model|llm|inference|prompt"` over
/// `backend/api/src/` matches only incidental English and one comment
/// marking an LLM front door explicitly out of scope
/// (`issuance/mod.rs:5`). These must be supplied by the calling AI system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    pub provider: Provenanced<String>,
    pub model_name: Provenanced<String>,
    pub model_version: Provenanced<String>,
    /// Version of the prompt/instruction set in force for this call.
    /// Separate from `system_prompt_or_policy_id`: the identifier says which
    /// prompt, the version says which revision of it.
    pub prompt_version: Provenanced<String>,
    /// e.g. "production", "staging". Nothing tags decisions with a
    /// deployment environment today, which means a record produced in a test
    /// harness is currently indistinguishable from a live one.
    pub environment: Provenanced<String>,
    /// SHA-256 over the caller's serialised model configuration, following
    /// the vkey digest pattern at `wealth/evidence.rs:137`.
    pub config_fingerprint: Provenanced<String>,
    pub system_prompt_or_policy_id: Provenanced<String>,
    /// When the model was called. Distinct from
    /// `decision.timestamps.assessed_at`, which times the proof workflow.
    pub timestamp: Provenanced<DateTime<Utc>>,
}

impl ModelIdentity {
    /// An AI system took part but nothing about it can be named yet. The
    /// honest middle state between a populated identity and the assertion
    /// that no AI was involved.
    pub fn participated_but_unidentified(reason: &str) -> Self {
        let r = || Provenanced::unpopulated(reason);
        Self {
            provider: r(),
            model_name: r(),
            model_version: r(),
            prompt_version: r(),
            environment: r(),
            config_fingerprint: r(),
            system_prompt_or_policy_id: r(),
            timestamp: Provenanced::unpopulated(reason),
        }
    }
}

// ---------------------------------------------------------------------
// model_provenance
// ---------------------------------------------------------------------

/// Where the `model` block's contents came from, and what they replaced.
///
/// -------------------------------------------------------------------
/// WHY THIS BLOCK EXISTS
/// -------------------------------------------------------------------
/// The model attestation is written when the assessment is OPENED, in the
/// same transaction — before the client's device has proved anything, before
/// a verdict exists, before any human review. Up to schema 1.1.0 the record
/// served that forward declaration with every leaf `state: "recorded"`, which
/// is the provenance a fact observed at decision time carries, and said
/// nothing at all about when the declaration was made or whether anything had
/// since contradicted it. `tests/break_it/test_attack_11_swap_model_undetected.py`
/// demonstrates what that costs: the model that served the recommendation
/// changes, no recorded field changes with it, and the record reads as
/// internally consistent and wrong.
///
/// Every field here answers one of the two questions that record could not:
/// *when was this said*, and *has anyone said otherwise since*.
///
/// -------------------------------------------------------------------
/// WHY THE ORIGINAL IS CARRIED HERE RATHER THAN LEFT IN `model`
/// -------------------------------------------------------------------
/// A correction changes what `model` says, because a reader who looks only at
/// `model.provider` — which is every reader — must not be handed an identity
/// the organisation has retracted. But the declaration made at open is still
/// evidence, and it is evidence of a different thing: not which model ran,
/// but what this organisation asserted before it knew how the decision would
/// turn out. That is a fact about the organisation, it is often the more
/// interesting of the two, and it is exactly what a firm would want to lose.
/// So it is preserved verbatim, in the signed bytes, beside the correction
/// that supersedes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProvenance {
    /// When the declaration was recorded, on the server's clock —
    /// `decision_model_attestations.created_at`.
    ///
    /// The single most useful field in this block, because it is the one an
    /// examiner compares against `decision.timestamps.assessed_at` without
    /// being told to. Deliberately NOT accompanied by a derived
    /// `declared_before_the_decision` boolean: both timestamps are in this
    /// record, the comparison is the reader's to make, and a derived flag is
    /// one more thing that can disagree with its own inputs.
    ///
    /// `Provenanced` rather than a bare timestamp because a decision opened
    /// before migrations/0006 has no attestation row and therefore no
    /// declaration time, and writing one would invent a fact.
    pub declared_at: Provenanced<DateTime<Utc>>,
    /// The declaration exactly as it was made when the assessment was opened.
    /// Never altered by anything, including this system.
    pub as_declared_at_open: DeclaredAttestation,
    /// Whether anything in `corrections` contradicts it. Derived from the
    /// vector by `ModelProvenance::new`, so it cannot disagree with it.
    pub corrected: bool,
    /// How many corrections this decision carries.
    ///
    /// Redundant with `corrections.len()` on purpose, and the redundancy is
    /// the point: `correction_no` is dense from 1, so a reader comparing this
    /// count against the highest `correction_no` present sees a removed row
    /// as a mismatch. Two corrections numbered 1 and 3 is a deletion; two
    /// numbered 1 and 2 is not.
    pub correction_count: i64,
    /// Every correction, oldest first. Append-only: a later correction never
    /// edits or removes an earlier one, because an organisation that has
    /// corrected twice has said two things and an examiner is entitled to
    /// both.
    pub corrections: Vec<ModelCorrection>,
    /// Human-readable restatement, for the examiner who reads the PDF and not
    /// the JSON — the same reason `data_provenance.statement` exists.
    pub statement: String,
}

/// The declaration as made at open, or one correction's replacement for it.
///
/// Plain `Option`s rather than `Provenanced` leaves, and the difference from
/// `ModelIdentity` is deliberate. `ModelIdentity` describes what the record
/// currently asserts, where a missing leaf is a gap that needs a stated
/// reason. This describes a statement that was made: a leaf the declaring
/// system did not supply is simply not part of the statement, and wrapping it
/// in "unpopulated, and here is what would fill it" would attach a
/// forward-looking remedy to a historical document. The same reasoning that
/// makes `EvidenceArtifact` and `CryptographicProof` plain structs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredAttestation {
    /// `no_ai_participated` | `model_identified` |
    /// `participated_but_unidentified`. A string rather than an enum for the
    /// same reason `Institution::org_type` is one: an evidence reader must
    /// not fail closed on a declaration added after this schema was pinned.
    pub declaration: String,
    /// Only ever set under `no_ai_participated`: what the organisation
    /// asserted decided instead. Null, never absent.
    pub no_ai_attestation: Option<String>,
    /// Only ever set under `participated_but_unidentified`: why the model
    /// could not be named.
    pub unidentified_reason: Option<String>,
    /// Always present as an object, whatever the declaration, with null
    /// leaves where the declaration carries none.
    ///
    /// An object with eight nulls rather than `identity: null`, because
    /// `null` under a model-shaped key already means something specific in
    /// this record — a signed assertion that no AI participated — and a second
    /// null meaning "this branch has no identity" one level down is exactly
    /// the ambiguity `ModelAttestation` exists to prevent.
    pub identity: DeclaredIdentity,
}

/// The eight model leaves as stated, with nothing inferred.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredIdentity {
    pub provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub prompt_version: Option<String>,
    pub environment: Option<String>,
    pub config_fingerprint: Option<String>,
    pub system_prompt_or_policy_id: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

impl DeclaredIdentity {
    /// No leaves stated. Used for the two declarations that carry none — and
    /// a constructor rather than `Default` so that "the caller named nothing"
    /// is always a decision somebody made in code, never a struct literal
    /// somebody forgot to fill in.
    pub fn none_stated() -> Self {
        Self {
            provider: None,
            model_name: None,
            model_version: None,
            prompt_version: None,
            environment: None,
            config_fingerprint: None,
            system_prompt_or_policy_id: None,
            timestamp: None,
        }
    }
}

/// One correction to the declaration, as filed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCorrection {
    /// The row's own id, and the `audit_log.ref_id` the chain committed to
    /// this correction under (`audit/binding.rs`). Carried in the record so
    /// the join runs in both directions: a reader holding this record can
    /// find the binding event for a specific correction in a replay report,
    /// and a reader holding the report can find the decision from the
    /// payload's `request_id`. Without it the cross-check only works one way.
    pub correction_id: Uuid,
    /// Dense from 1 per decision. A gap means a correction was removed from
    /// the database after it was filed — which the chain also catches, as a
    /// `source_row_missing` result on
    /// `GET /orgs/:id/audit-log/replay`.
    pub correction_no: i32,
    /// The organisation's own identifier for whoever asserted it, and the
    /// authority they asserted it under. Text, quoted rather than resolved:
    /// Memtara has no directory of a bank's staff.
    pub asserted_by: String,
    pub asserted_by_role: String,
    /// Why. Substantive by constraint — at least
    /// `model_correction::MIN_CORRECTION_REASON_CHARS` characters, enforced in
    /// the handler and again by `decision_model_corrections_reason_is_substantive`
    /// in migrations/0009.
    pub correction_reason: String,
    /// When the organisation says it determined the correction.
    pub asserted_at: DateTime<Utc>,
    /// When this server observed it. Beside the claim rather than instead of
    /// it: the gap between the two is the only unforgeable thing about the
    /// first, and a batch of corrections all claiming to be weeks apart while
    /// arriving in one second is visible from these two fields alone.
    pub recorded_at: DateTime<Utc>,
    /// `model_identified` | `participated_but_unidentified`. Never
    /// `no_ai_participated`: a correction may weaken or re-point an
    /// organisation's AI claim and may never strengthen it into the strongest
    /// assertion the system can make. migrations/0009 carries the argument.
    pub declaration: String,
    pub unidentified_reason: Option<String>,
    pub identity: DeclaredIdentity,
}

/// The prose an examiner reads instead of this module.
const MODEL_PROVENANCE_STATEMENT: &str =
    "The model block in this record is what this organisation asserts about the AI system that \
     participated in this decision. The declaration it made when the assessment was opened is \
     preserved here under as_declared_at_open and is never altered by anything, including a \
     correction. Note when that declaration is made: at open, in the same transaction as the \
     assessment, before the subject's device has produced a proof, before a verdict exists and \
     before any human review — so it is a statement about a decision that has not happened yet. \
     Compare declared_at with decision.timestamps.assessed_at. Corrections are append-only and \
     numbered from 1; a gap in correction_no means a correction was removed from the database \
     after it was filed, and each one is separately committed to the audit chain.";

impl ModelProvenance {
    /// The one constructor. `corrected` and `correction_count` are derived
    /// from `corrections` here rather than passed in, so no call site can
    /// produce a record that says it was never corrected while carrying a
    /// correction.
    pub fn new(
        declared_at: Provenanced<DateTime<Utc>>,
        as_declared_at_open: DeclaredAttestation,
        corrections: Vec<ModelCorrection>,
    ) -> Self {
        Self {
            declared_at,
            as_declared_at_open,
            corrected: !corrections.is_empty(),
            correction_count: corrections.len() as i64,
            corrections,
            statement: MODEL_PROVENANCE_STATEMENT.to_string(),
        }
    }

    /// The provenance of a decision that has no attestation row at all.
    ///
    /// Not `no_ai_participated`, for the same reason
    /// `model_intake::absent_attestation` is not: an assessment opened before
    /// the capture path existed was opened by a system that was never asked
    /// the question, and a record claiming it involved no AI would assert
    /// something nobody established. There is nothing to correct either, which
    /// is why `model_correction.rs` answers 409 rather than creating a
    /// declaration on the organisation's behalf.
    pub fn never_declared(reason: &str) -> Self {
        Self::new(
            Provenanced::unpopulated(reason),
            DeclaredAttestation {
                declaration: "participated_but_unidentified".to_string(),
                no_ai_attestation: None,
                unidentified_reason: Some(reason.to_string()),
                identity: DeclaredIdentity::none_stated(),
            },
            vec![],
        )
    }
}

// ---------------------------------------------------------------------
// human_review
// ---------------------------------------------------------------------

/// What a human did about this decision.
///
/// `performed` is an addition to the spec's §1.1 field list, and it is here
/// for the same reason `model` is nullable: "no human reviewed this" is a
/// claim worth signing, and it is not the same claim as "a human reviewed it
/// and we lost the reviewer's name". Without it, a decision with no review
/// step would have to carry an `action` that reads as a human verdict —
/// which would be a false statement in the signed bytes, and a far worse
/// defect than an extra boolean.
///
/// `action` stays a required, non-optional `DecisionAction` regardless. When
/// `performed` is false it records the disposition the automated path
/// reached, and `performed` is what tells the reader nobody stood behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanReviewBlock {
    /// Whether a human review step occurred at all.
    pub performed: bool,
    /// No `reviewer` concept exists in `backend/api/src/`. The only
    /// governance flag in the codebase, `products.approved_by_risk_committee`
    /// (`products/mod.rs:73`), approves a catalogue entry, not this
    /// decision — mapping it here would be the "bypass human review" defect
    /// dressed as a feature.
    pub reviewer_id: Provenanced<String>,
    pub reviewer_role: Provenanced<String>,
    /// Required. Never `Option`, never absent, identical key on a rejection
    /// and on an approval.
    pub action: DecisionAction,
    #[serde(rename = "override")]
    pub overridden: bool,
    /// Genuinely nullable by meaning: there is no reason when there was no
    /// override. Null, never missing — the key is present in both cases.
    ///
    /// The pairing `overridden == true && override_reason == None` is
    /// forbidden in three independent places, because it is the one field
    /// combination in this record that can turn a control failure into a
    /// clean-looking row: the JSON schema forbids it for a record, the
    /// `ReviewOverride` input type makes it unconstructable through the
    /// builder, and `decision_reviews_override_requires_reason`
    /// (migrations/0006) forbids it for a row — the only one of the three
    /// that survives someone writing to Postgres by hand.
    /// `validate_override_pairing` below is the check for a record that
    /// arrived by deserialisation, where no constructor ran at all.
    pub override_reason: Option<String>,
    pub reviewed_at: Provenanced<DateTime<Utc>>,
    /// Which revision of the firm's review procedure the reviewer worked
    /// under. Nothing in the codebase records a review procedure at all.
    pub human_review_protocol_version: Provenanced<String>,
    /// How long the reviewer spent on this decision, in milliseconds.
    ///
    /// -------------------------------------------------------------------
    /// WHY A DURATION IS A FIRST-CLASS FIELD AND NOT AN ANALYTICS CONCERN
    /// -------------------------------------------------------------------
    /// This is the field the Cigna case turned on. Medical directors were
    /// found to have cleared claims at about 1.2 seconds each, in batches,
    /// without opening the file. Every one of those reviews had a named
    /// reviewer, a timestamp and an action — the whole of v1.0.0's
    /// `human_review` block — and by that record they were reviews. The
    /// duration is what made them not reviews.
    ///
    /// A firm that captures this from month one can run the query against
    /// itself before anyone else runs it against them, which is the entire
    /// commercial proposition of this record. A firm that does not cannot
    /// reconstruct it later: the clock is only observable while the review
    /// is happening.
    pub review_duration_ms: Provenanced<i64>,
    /// How `review_duration_ms` was arrived at.
    ///
    /// Separate from the number, and more important than it. A duration a
    /// reviewer's own client asserts is exactly the number a firm gaming
    /// this metric would inflate, so an examiner must be able to tell an
    /// asserted duration from a measured one without asking us — and a
    /// duration whose provenance is unstated is admissible as neither.
    /// Values match `decision_reviews.review_duration_source`
    /// (migrations/0006): `reviewer_client_asserted`, or
    /// `server_computed_from_declared_start`.
    pub review_duration_source: Provenanced<String>,
}

/// Whether this review went against the control, and if so why.
///
/// -------------------------------------------------------------------
/// WHY THIS IS AN ENUM AND NOT A `bool` PLUS AN `Option<String>`
/// -------------------------------------------------------------------
/// `override: true` with no reason is not a weaker record — it is the shape
/// a bypassed control takes when nobody wants to write down that they
/// bypassed it. Left as two independent fields, that pairing is one forgotten
/// `if` away at every call site, forever. As a sum type it does not exist:
/// there is no way to name the overridden case without carrying a reason,
/// and `overridden()` refuses a blank or a token one.
///
/// The serialised record still has the two flat keys the pinned schema
/// defines — this type governs construction, not the wire form. That
/// asymmetry is deliberate: the wire form is fixed by v1.0.0 and cannot
/// change, and the invariant belongs to whoever is building a record, not to
/// whoever is reading one back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewOverride {
    /// The reviewer's action agreed with the control's verdict.
    NotOverridden,
    /// The reviewer went against the control, for this stated reason.
    Overridden { reason: String },
}

/// The shortest override reason this will accept. Ten characters is not a
/// quality bar and does not pretend to be one — it is the floor that stops
/// `"x"`, `"n/a"` and `"-"`, which are the three things a required free-text
/// field actually collects when nobody means to fill it in. The same floor is
/// a CHECK constraint in migrations/0006 so the two cannot drift.
const MIN_OVERRIDE_REASON_CHARS: usize = 10;

/// The refusal returned when an override is offered without a usable reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "an override must state why. A recorded override with no reason is the shape a bypassed \
     control takes when nobody wants to write down that they bypassed it, so it is refused \
     here rather than stored and explained later; give at least {MIN_OVERRIDE_REASON_CHARS} \
     characters naming what the reviewer knew that the control did not"
)]
pub struct OverrideReasonMissing;

impl ReviewOverride {
    /// The overriding case. Fallible on purpose: this is the only route to
    /// `overridden = true` through the builder, so the reason cannot be
    /// omitted, blanked, or filled with a placeholder.
    pub fn overridden(reason: impl Into<String>) -> Result<Self, OverrideReasonMissing> {
        let reason = reason.into();
        if reason.trim().chars().count() < MIN_OVERRIDE_REASON_CHARS {
            return Err(OverrideReasonMissing);
        }
        Ok(Self::Overridden { reason })
    }

    fn flag(&self) -> bool {
        matches!(self, Self::Overridden { .. })
    }

    fn reason(&self) -> Option<String> {
        match self {
            Self::NotOverridden => None,
            Self::Overridden { reason } => Some(reason.clone()),
        }
    }
}

// ---------------------------------------------------------------------
// evidence
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBlock {
    /// Proof bytes, audit excerpt and vkey digest exist today but are
    /// scattered across four top-level keys of the wealth response
    /// (`wealth/evidence.rs:82-98,116-127,133-143`). One array, one shape.
    pub evidence_artifacts: Vec<EvidenceArtifact>,
    pub cryptographic_proofs: Vec<CryptographicProof>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    #[serde(rename = "type")]
    pub artifact_type: String,
    /// Relative to the verification bundle root, e.g.
    /// "proof/wealth_suitability.proof". Not an http URL: a bundle that
    /// resolves its own contents over the network is not offline-verifiable.
    pub uri: String,
    /// Lower-case hex SHA-256.
    pub digest: String,
}

/// One proof attempt. Every attempt, accepted and rejected — the array shape
/// `wealth/evidence.rs:67-69` already uses, for the reason stated there: a
/// pack showing only the accepted proof hides the four that failed first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptographicProof {
    pub circuit: String,
    /// `crypto::signer::proof_digest_hex` over the proof bytes.
    pub proof_digest: String,
    /// Field elements as submitted, hex, in circuit order.
    pub public_inputs: Vec<String>,
    /// SHA-256 of the verification key, matching
    /// `circuits/wealth_suitability/vkey/vk_hash`.
    pub verification_key_digest: String,
    /// Whether `bb verify` exited 0. NOT the decision: a valid proof of
    /// unsuitability verifies successfully. The verdict is
    /// `decision.final_decision.outcome`, read from the circuit's public
    /// output — see `wealth/evidence.rs:185-187`.
    pub accepted_by_bb_verify: bool,
}

// =====================================================================
// Construction
// =====================================================================

/// Everything a caller must decide in order to produce a record.
///
/// This exists so that there is exactly one construction site for a
/// `DecisionEvidence`, which is the same discipline `product_response!`
/// enforces for `ProductResponse` (`products/mod.rs:82-103`): "the one place
/// a `products` row becomes a response... so `check_digit_valid` cannot be
/// present on one endpoint and quietly missing from another".
///
/// A function rather than a macro, deliberately. The macro form buys
/// field-name terseness over a `sqlx` row; here the inputs come from several
/// sources and the compiler checking a struct literal is worth more than the
/// brevity. The invariant the macro protects — one code path, no per-branch
/// shape — is preserved, and it is what §1.3 of the spec is asking for: an
/// approval and a rejection differ only in the *values* of `status`,
/// `outcome` and `action`, never in which fields exist.
pub struct DecisionInputs {
    pub decision_id: Uuid,
    pub institution: Institution,
    pub status: DecisionAction,
    pub outcome: DecisionOutcome,
    pub decided_at: DateTime<Utc>,
    pub opened_at: DateTime<Utc>,
    pub assessed_at: Option<DateTime<Utc>>,
    pub exported_at: DateTime<Utc>,
    pub subject_id: String,
    pub disclosed_attributes: Vec<String>,
    pub provenance_statement: String,
    pub policy_source: String,
    pub threshold_source: String,
    pub threshold_values: BTreeMap<String, Value>,
    pub regulatory_control_mapping: Vec<RegulatoryControl>,
    pub model: ModelAttestation,
    /// How `model` came to say what it says. Required rather than defaulted:
    /// a caller that has not thought about whether this decision's
    /// attestation was ever corrected must not be able to produce a record
    /// that silently asserts it was not.
    pub model_provenance: ModelProvenance,
    pub human_review: HumanReviewInputs,
    pub evidence_artifacts: Vec<EvidenceArtifact>,
    pub cryptographic_proofs: Vec<CryptographicProof>,
    /// The grant this decision was authorised under — real provenance since
    /// schema 1.3.0 (`consents::`, migrations/0011), where every earlier
    /// version could only ever build this as `unpopulated`. Required, like
    /// `model_provenance`: a caller that has not thought about which grant
    /// covered this decision must not be able to produce a record that
    /// silently claims there was none to think about.
    pub consent: Consent,

    // -----------------------------------------------------------------
    // Fields that were hardcoded to `unpopulated` in the v1.0.0 builder
    // because nothing could source them, and that now have a source. They
    // are `Provenanced` rather than plain values because "this deployment
    // can source it" and "this particular decision has it" are different
    // questions: an assessment opened before migrations/0007 genuinely has
    // no `threshold_version`, and the honest record of that is an
    // `unpopulated` with a reason, not a fabricated `1`.
    // -----------------------------------------------------------------
    /// The firm's own process taxonomy entry, e.g.
    /// "wealth.suitability_recommendation". Still not a database lookup —
    /// the module that implements a process is the one that can name it.
    pub business_process: Provenanced<String>,
    /// Derivable once human review exists: proof alone, proof plus a
    /// concurring human, or a human against the proof.
    pub decision_basis: Provenanced<DecisionBasis>,
    /// Caller-supplied SHA-256 over the context the deciding system saw.
    pub input_context_fingerprint: Provenanced<String>,
    /// Caller-supplied SHA-256 over the decision's structured output.
    pub output_fingerprint: Provenanced<String>,
    /// Circuit public input 2, as submitted and as checked against the
    /// holder's registered root.
    pub vault_root: Provenanced<String>,
    /// Which registry row supplied the thresholds — `products.id`.
    pub threshold_set_id: Provenanced<String>,
    /// `products.terms_version` as snapshotted at open time.
    pub threshold_version: Provenanced<String>,
}

/// The human-review half of `DecisionInputs`, separated because it is the
/// only part of a record with a genuine two-state shape — a human reviewed
/// this, or nobody did — and because that distinction has to be made once,
/// at a constructor, rather than by six fields agreeing with each other at
/// every call site.
pub struct HumanReviewInputs {
    performed: bool,
    reviewer_id: Provenanced<String>,
    reviewer_role: Provenanced<String>,
    action: DecisionAction,
    overridden: bool,
    override_reason: Option<String>,
    reviewed_at: Provenanced<DateTime<Utc>>,
    protocol_version: Provenanced<String>,
    review_duration_ms: Provenanced<i64>,
    review_duration_source: Provenanced<String>,
}

/// What a completed human review supplies. Every field is required except
/// the duration pair, which is `None` when the reviewing client did not
/// report one.
pub struct CompletedReview {
    pub reviewer_id: String,
    pub reviewer_role: String,
    pub action: DecisionAction,
    pub over_ride: ReviewOverride,
    pub reviewed_at: DateTime<Utc>,
    pub protocol_version: String,
    /// `(milliseconds, source)`. Both or neither — a duration with no
    /// provenance is not admissible, so the pair is one `Option`, not two.
    pub duration: Option<(i64, String)>,
}

impl HumanReviewInputs {
    /// A human reviewed this decision.
    pub fn completed(review: CompletedReview) -> Self {
        let (duration_ms, duration_source) = match review.duration {
            Some((ms, source)) => (
                Provenanced::recorded(ms),
                Provenanced::recorded(source),
            ),
            None => (
                Provenanced::unpopulated(NO_DURATION),
                Provenanced::unpopulated(NO_DURATION),
            ),
        };
        Self {
            performed: true,
            reviewer_id: Provenanced::recorded(review.reviewer_id),
            reviewer_role: Provenanced::recorded(review.reviewer_role),
            action: review.action,
            overridden: review.over_ride.flag(),
            override_reason: review.over_ride.reason(),
            reviewed_at: Provenanced::recorded(review.reviewed_at),
            protocol_version: Provenanced::recorded(review.protocol_version),
            review_duration_ms: duration_ms,
            review_duration_source: duration_source,
        }
    }

    /// Nobody reviewed this decision.
    ///
    /// `action` is still required and still records the disposition the
    /// automated path reached — the type has no fourth variant and should
    /// not grow one, because "a decision was reached" is what makes a record
    /// exist at all. What stops that reading as a human's judgement is that
    /// `performed` is false and every reviewer-identity field is
    /// `NotApplicable`: a signed assertion that there was no review step,
    /// not an admission that we lost the reviewer's name. Those are
    /// different claims and an examiner must be able to tell them apart —
    /// `Unpopulated` here would say "a human may well have reviewed this and
    /// we failed to record who", which is a confession this deployment has
    /// no reason to make.
    pub fn not_performed(automated_action: DecisionAction) -> Self {
        let absent = || Provenanced::not_applicable(NO_REVIEW);
        Self {
            performed: false,
            reviewer_id: absent(),
            reviewer_role: absent(),
            action: automated_action,
            overridden: false,
            override_reason: None,
            reviewed_at: Provenanced::not_applicable(NO_REVIEW),
            protocol_version: absent(),
            review_duration_ms: Provenanced::not_applicable(NO_REVIEW),
            review_duration_source: Provenanced::not_applicable(NO_REVIEW),
        }
    }
}

const NO_REVIEW: &str = "no human review step was performed on this decision; \
                         human_review.performed is false, and this field is not \
                         applicable rather than missing";

const NO_DURATION: &str = "the reviewing client did not report how long the review took; \
                           supply review_duration_ms or review_started_at on \
                           POST /api/v1/wealth-assessments/{id}/review to populate it";

/// The reason string every field that this codebase cannot yet source
/// carries. Kept as one constant so a reader grepping a sealed record finds
/// every gap at once, and so no caller can invent a softer phrasing.
const NO_SOURCE: &str =
    "no source exists in memtara-api as of evidence schema 1.3.0; see \
     schema/decision_evidence/v1.3.0.json for what would populate it";

impl DecisionEvidence {
    /// Build a record, filling every field the codebase cannot yet source
    /// with an explicit `Unpopulated` placeholder rather than a default.
    ///
    /// One code path. `status`, `outcome` and `action` are inputs, not
    /// branches: there is no `if rejected` anywhere below, and therefore no
    /// way for a rejection to acquire a different shape.
    pub fn from_inputs(input: DecisionInputs) -> Self {
        Self {
            evidence_schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            decision: DecisionBlock {
                decision_id: input.decision_id,
                institution: input.institution,
                business_process: input.business_process,
                status: input.status,
                final_decision: FinalDecision {
                    outcome: input.outcome,
                    decided_at: input.decided_at,
                    decision_basis: input.decision_basis,
                },
                input_context_fingerprint: input.input_context_fingerprint,
                output_fingerprint: input.output_fingerprint,
                timestamps: Timestamps {
                    opened_at: input.opened_at,
                    assessed_at: input.assessed_at,
                    exported_at: input.exported_at,
                },
            },
            policy: PolicyBlock {
                policy_id: Provenanced::unpopulated(NO_SOURCE),
                policy_version: Provenanced::unpopulated(NO_SOURCE),
                source: input.policy_source,
                decision_logic_version: Provenanced::unpopulated(NO_SOURCE),
                thresholds: Thresholds {
                    threshold_set_id: input.threshold_set_id,
                    threshold_version: input.threshold_version,
                    values: input.threshold_values,
                    source: input.threshold_source,
                },
                regulatory_control_mapping: input.regulatory_control_mapping,
            },
            data: DataBlock {
                customer: Customer {
                    subject_id: input.subject_id,
                    data_provenance: DataProvenance {
                        disclosed_attributes: input.disclosed_attributes,
                        vault_root: input.vault_root,
                        statement: input.provenance_statement,
                    },
                    data_provenance_version: Provenanced::unpopulated(NO_SOURCE),
                },
                consent: input.consent,
                data_schema_version: Provenanced::unpopulated(NO_SOURCE),
            },
            model: input.model,
            model_provenance: input.model_provenance,
            human_review: HumanReviewBlock {
                performed: input.human_review.performed,
                reviewer_id: input.human_review.reviewer_id,
                reviewer_role: input.human_review.reviewer_role,
                action: input.human_review.action,
                overridden: input.human_review.overridden,
                override_reason: input.human_review.override_reason,
                reviewed_at: input.human_review.reviewed_at,
                human_review_protocol_version: input.human_review.protocol_version,
                review_duration_ms: input.human_review.review_duration_ms,
                review_duration_source: input.human_review.review_duration_source,
            },
            evidence: EvidenceBlock {
                evidence_artifacts: input.evidence_artifacts,
                cryptographic_proofs: input.cryptographic_proofs,
            },
        }
    }

    /// The bytes the seal digests. See `canonical`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical::canonical_bytes(self)
    }

    /// The value that goes in the seal's `canonical_evidence_sha256`.
    pub fn canonical_sha256_hex(&self) -> Result<String, CanonicalError> {
        canonical::canonical_sha256_hex(self)
    }

    /// The override pairing, checked on a record that did not come through
    /// `from_inputs`.
    ///
    /// `ReviewOverride` makes the bad pairing unconstructable through the
    /// builder and migrations/0006 makes it unstorable, but neither runs
    /// when a record arrives as bytes: `serde` will happily deserialise
    /// `{"override": true, "override_reason": null}` because the pinned
    /// wire shape is two independent keys and always will be. So a reader
    /// gets an explicit check rather than an assumption. This is the same
    /// reasoning as `Provenanced::is_coherent`, which exists for exactly the
    /// case of a hand-edited record claiming a state its value contradicts.
    pub fn validate_override_pairing(&self) -> Result<(), OverrideReasonMissing> {
        let stated = self
            .human_review
            .override_reason
            .as_deref()
            .map(|r| r.trim().chars().count())
            .unwrap_or(0);
        if self.human_review.overridden && stated < MIN_OVERRIDE_REASON_CHARS {
            return Err(OverrideReasonMissing);
        }
        Ok(())
    }
}

/// Why the decision came out the way it did, derived from whether a human
/// stood behind it and whether they agreed with the control.
///
/// A function rather than three assignments at the call site, because
/// `ProofAndHumanOverride` is the variant a supervisor greps for and it must
/// not be possible for one code path to reach an override without setting
/// it. `HumanOnlyProofUnavailable` is deliberately not reachable here: it
/// belongs to the continuity mode where the proof service is down and a
/// human decides anyway, which this system cannot do today, and inferring it
/// from `NoVerdict` would let an outage plus a review manufacture a basis
/// nobody implemented.
pub fn derive_decision_basis(review: &HumanReviewInputs) -> DecisionBasis {
    match (review.performed, review.overridden) {
        (false, _) => DecisionBasis::ProofOnly,
        (true, false) => DecisionBasis::ProofAndHumanConcurred,
        (true, true) => DecisionBasis::ProofAndHumanOverride,
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).unwrap()
    }

    /// The one fixture the whole module is tested against. `status`,
    /// `outcome` and `action` are parameters so that an approval and a
    /// rejection are provably the *same* inputs.
    fn fixture(
        status: DecisionAction,
        outcome: DecisionOutcome,
        action: DecisionAction,
        model: ModelAttestation,
    ) -> DecisionEvidence {
        fixture_with_review(status, outcome, model, HumanReviewInputs::not_performed(action))
    }

    /// The same fixture with the human-review block supplied directly, so
    /// the reviewed and unreviewed paths can be compared as records rather
    /// than described in prose.
    fn fixture_with_review(
        status: DecisionAction,
        outcome: DecisionOutcome,
        model: ModelAttestation,
        review: HumanReviewInputs,
    ) -> DecisionEvidence {
        fixture_with_provenance(status, outcome, model, review, uncorrected())
    }

    /// The declaration the fixture's `model` block corresponds to: the same
    /// signed assertion that no AI participated, in the shape
    /// `model_provenance` records it. Kept in step with `approval()` on
    /// purpose — a fixture whose `model` and `as_declared_at_open` disagreed
    /// would be testing a record no builder can produce.
    fn declared_no_ai() -> DeclaredAttestation {
        DeclaredAttestation {
            declaration: "no_ai_participated".to_string(),
            no_ai_attestation: Some(
                "suitability produced by the deterministic rules engine; no model in the \
                 recommendation path"
                    .to_string(),
            ),
            unidentified_reason: None,
            identity: DeclaredIdentity::none_stated(),
        }
    }

    fn uncorrected() -> ModelProvenance {
        ModelProvenance::new(
            Provenanced::recorded(ts("2026-08-18T17:59:00Z")),
            declared_no_ai(),
            vec![],
        )
    }

    /// The same decision after the organisation named a model it had
    /// declared no AI for. One correction, fully populated, so the corrected
    /// branch of every shape assertion is exercised against real values
    /// rather than against nulls.
    fn corrected() -> ModelProvenance {
        ModelProvenance::new(
            Provenanced::recorded(ts("2026-08-18T17:59:00Z")),
            declared_no_ai(),
            vec![ModelCorrection {
                correction_id: uuid("6f0f2b8c-3f4a-4d2b-8a1e-5c9d7e3b1a02"),
                correction_no: 1,
                asserted_by: "mrm-desk-11".to_string(),
                asserted_by_role: "model_risk_officer".to_string(),
                correction_reason: "an inference-log reconciliation shows a model was in the \
                                    recommendation path for this desk in the period covering \
                                    this decision"
                    .to_string(),
                asserted_at: ts("2026-09-02T09:15:00Z"),
                recorded_at: ts("2026-09-02T09:15:04Z"),
                declaration: "model_identified".to_string(),
                unidentified_reason: None,
                identity: DeclaredIdentity {
                    provider: Some("anthropic".to_string()),
                    model_name: Some("claude-opus-4".to_string()),
                    model_version: Some("20260514".to_string()),
                    prompt_version: Some("suitability-v7".to_string()),
                    environment: Some("production".to_string()),
                    config_fingerprint: Some("ab".repeat(32)),
                    system_prompt_or_policy_id: Some("policy/suitability/7".to_string()),
                    timestamp: Some(ts("2026-08-18T17:58:41Z")),
                },
            }],
        )
    }

    fn fixture_with_provenance(
        status: DecisionAction,
        outcome: DecisionOutcome,
        model: ModelAttestation,
        review: HumanReviewInputs,
        model_provenance: ModelProvenance,
    ) -> DecisionEvidence {
        let mut values = BTreeMap::new();
        values.insert("min_income".to_string(), Value::from(500_000i64));
        values.insert("min_liquidity".to_string(), Value::from(250_000i64));
        values.insert("max_concentration_percent".to_string(), Value::from(20i64));
        values.insert("product_risk_level".to_string(), Value::from(3i64));

        DecisionEvidence::from_inputs(DecisionInputs {
            decision_id: uuid("71386234-daae-4896-91fe-4c469cf59af2"),
            institution: Institution {
                org_id: uuid("2f1c8d4e-0a1b-4c3d-9e8f-7a6b5c4d3e2f"),
                org_name: "Example Bank PJSC".to_string(),
                org_type: "bank".to_string(),
            },
            status,
            outcome,
            decided_at: ts("2026-08-18T18:03:52Z"),
            opened_at: ts("2026-08-18T17:59:00Z"),
            assessed_at: Some(ts("2026-08-18T18:03:52Z")),
            exported_at: ts("2026-08-18T18:04:00Z"),
            subject_id: "user_9f2a".to_string(),
            disclosed_attributes: vec![],
            provenance_statement: "Memtara holds no income, liquidity, risk-tolerance or \
                                   holdings figure for this subject."
                .to_string(),
            policy_source: "disclosure_requests.policy, snapshotted at open".to_string(),
            threshold_source: "product registry, snapshotted when the assessment was opened"
                .to_string(),
            threshold_values: values,
            regulatory_control_mapping: vec![
                RegulatoryControl {
                    framework: "DFSA".to_string(),
                    clause: "COB 3.1".to_string(),
                },
                RegulatoryControl {
                    framework: "CBUAE".to_string(),
                    clause: "5(c)".to_string(),
                },
            ],
            model,
            model_provenance,
            human_review: review,
            consent: Consent {
                consent_id: Provenanced::unpopulated(NO_SOURCE),
                consent_version: Provenanced::unpopulated(NO_SOURCE),
                scope: Provenanced::unpopulated(NO_SOURCE),
                granted_at: Provenanced::unpopulated(NO_SOURCE),
                purpose_hash: Provenanced::unpopulated(NO_SOURCE),
            },
            business_process: Provenanced::unpopulated(NO_SOURCE),
            decision_basis: Provenanced::unpopulated(NO_SOURCE),
            input_context_fingerprint: Provenanced::unpopulated(NO_SOURCE),
            output_fingerprint: Provenanced::unpopulated(NO_SOURCE),
            vault_root: Provenanced::unpopulated(NO_SOURCE),
            threshold_set_id: Provenanced::unpopulated(NO_SOURCE),
            threshold_version: Provenanced::unpopulated(NO_SOURCE),
            evidence_artifacts: vec![EvidenceArtifact {
                artifact_type: "zk_proof".to_string(),
                uri: "proof/wealth_suitability.proof".to_string(),
                digest: "aa".repeat(32),
            }],
            cryptographic_proofs: vec![CryptographicProof {
                circuit: "wealth_suitability".to_string(),
                proof_digest: "bb".repeat(32),
                public_inputs: vec!["0x01".to_string(), "0x02".to_string()],
                verification_key_digest: "cc".repeat(32),
                accepted_by_bb_verify: true,
            }],
        })
    }

    fn approval() -> DecisionEvidence {
        fixture(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            DecisionAction::Approved,
            ModelAttestation::no_ai_participated(),
        )
    }

    fn rejection() -> DecisionEvidence {
        fixture(
            DecisionAction::Rejected,
            DecisionOutcome::Negative,
            DecisionAction::Rejected,
            ModelAttestation::no_ai_participated(),
        )
    }

    /// The same decision with a human behind it, timed.
    fn reviewed_approval() -> DecisionEvidence {
        fixture_with_review(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            ModelAttestation::no_ai_participated(),
            HumanReviewInputs::completed(CompletedReview {
                reviewer_id: "emp-4417".to_string(),
                reviewer_role: "senior_suitability_officer".to_string(),
                action: DecisionAction::Approved,
                over_ride: ReviewOverride::NotOverridden,
                reviewed_at: ts("2026-08-18T18:31:00Z"),
                protocol_version: "cob-review-2026.2".to_string(),
                duration: Some((214_000, "reviewer_client_asserted".to_string())),
            }),
        )
    }

    /// Every key path in a value, arrays flattened to `[]` so that two
    /// records with different array lengths still compare structurally.
    fn key_paths(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    let path = format!("{prefix}.{k}");
                    out.insert(path.clone());
                    key_paths(v, &path, out);
                }
            }
            Value::Array(items) => {
                let path = format!("{prefix}[]");
                for v in items {
                    key_paths(v, &path, out);
                }
            }
            _ => {}
        }
    }

    fn paths_of(evidence: &DecisionEvidence) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        key_paths(&serde_json::to_value(evidence).unwrap(), "", &mut out);
        out
    }

    // -----------------------------------------------------------------
    // INVARIANT 1 — rejection symmetry
    // -----------------------------------------------------------------

    /// Fails the moment any field becomes optional-because-declined.
    ///
    /// Concretely, this catches: a `#[serde(skip_serializing_if)]` added to
    /// any field; an `Option<T>` that is `None` on the rejection path and
    /// `Some` on the approval path; a nested block replaced by `null` when
    /// the decision goes against the client. Any of those changes the
    /// canonical bytes, and therefore the seal digest, for a reason that has
    /// nothing to do with tampering — which is the defect that makes a
    /// declined client's record look altered.
    #[test]
    fn rejection_and_approval_have_identical_key_sets() {
        let approved = paths_of(&approval());
        let rejected = paths_of(&rejection());

        let only_in_approval: Vec<_> = approved.difference(&rejected).collect();
        let only_in_rejection: Vec<_> = rejected.difference(&approved).collect();
        assert!(
            only_in_approval.is_empty() && only_in_rejection.is_empty(),
            "key sets diverge. only in approval: {only_in_approval:?}; \
             only in rejection: {only_in_rejection:?}"
        );

        // And the difference is real: the two records are not accidentally
        // identical, they differ only in values. Without this the test would
        // pass just as happily against two copies of the same record.
        assert_ne!(approval(), rejection());
        assert_ne!(
            approval().canonical_sha256_hex().unwrap(),
            rejection().canonical_sha256_hex().unwrap()
        );
    }

    /// The stronger form of the same invariant: it must hold for every
    /// combination of the three enums, not just the two the fixture uses.
    #[test]
    fn key_set_is_invariant_across_every_action_outcome_combination() {
        let actions = [
            DecisionAction::Approved,
            DecisionAction::Rejected,
            DecisionAction::Modified,
        ];
        let outcomes = [
            DecisionOutcome::Affirmative,
            DecisionOutcome::Negative,
            DecisionOutcome::NoVerdict,
        ];
        let baseline = paths_of(&approval());
        for status in actions {
            for outcome in outcomes {
                for action in actions {
                    let paths = paths_of(&fixture(
                        status,
                        outcome,
                        action,
                        ModelAttestation::no_ai_participated(),
                    ));
                    assert_eq!(paths, baseline, "{status:?}/{outcome:?}/{action:?}");
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // INVARIANT 2 — the schema version is inside the signed payload
    // -----------------------------------------------------------------

    /// Fails if `evidence_schema_version` is ever moved out of the record
    /// into a sidecar, renamed, or left off the canonical bytes.
    ///
    /// What it catches: the failure mode where a 2028 examiner holds a
    /// sealed record and cannot tell which schema it was written under
    /// without asking a live registry that may no longer exist — and where,
    /// worse, the version could be edited without breaking the seal because
    /// it was never inside the digested bytes.
    #[test]
    fn evidence_schema_version_is_inside_the_signed_payload() {
        let record = approval();
        let bytes = record.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();

        // Present in the record, at the top level, under this exact name.
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value.get("evidence_schema_version").and_then(Value::as_str),
            Some(EVIDENCE_SCHEMA_VERSION)
        );

        // Present in the bytes the digest is taken over.
        assert!(text.contains(r#""evidence_schema_version":"1.3.0""#));

        // The pinned file for this version exists. A record naming a schema
        // nobody can open is a record an examiner cannot check, and the
        // failure mode is silent: the string looks like an answer.
        let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema/decision_evidence")
            .join(format!("v{EVIDENCE_SCHEMA_VERSION}.json"));
        assert!(
            pinned.exists(),
            "every record names a schema version; the file for {EVIDENCE_SCHEMA_VERSION} must be \
             committed at {}",
            pinned.display()
        );

        // Every superseded version is immutable and stays on disk beside it.
        // Records sealed under one of them are still readable, which is the
        // whole reason a bump is a new file rather than an edit — and the
        // reason this loop grows with each bump rather than tracking only the
        // previous one. A record sealed under 1.0.0 is not less of a record
        // because two versions have happened since.
        for superseded in ["v1.0.0.json", "v1.1.0.json"] {
            assert!(
                pinned.parent().unwrap().join(superseded).exists(),
                "{superseded} must stay on disk: records sealed under it validate against it and \
                 against nothing else"
            );
        }

        // And covered by the digest: change it, and the digest changes.
        let before = record.canonical_sha256_hex().unwrap();
        let mut tampered = record.clone();
        tampered.evidence_schema_version = "1.0.0".to_string();
        assert_ne!(before, tampered.canonical_sha256_hex().unwrap());
    }

    // -----------------------------------------------------------------
    // INVARIANT 3 — model: null is an assertion
    // -----------------------------------------------------------------

    /// Fails if `model` can ever be an absent key, or if the "no AI took
    /// part" assertion becomes indistinguishable from "we did not record a
    /// model".
    ///
    /// What it catches: adding `skip_serializing_if = "Option::is_none"` to
    /// `model` (which would make a no-AI firm's record structurally
    /// different from an AI firm's, and would silently drop the assertion);
    /// and any change that lets an unidentified-but-present model serialise
    /// as `null`, which would convert an admission of ignorance into a
    /// signed claim that no AI was involved.
    #[test]
    fn model_null_is_a_signed_assertion_not_an_absent_key() {
        // (a) The no-AI assertion is an explicit null under a present key.
        let no_ai = approval();
        let value = serde_json::to_value(&no_ai).unwrap();
        assert!(
            value.as_object().unwrap().contains_key("model"),
            "the `model` key must exist even when no AI participated"
        );
        assert_eq!(value.get("model"), Some(&Value::Null));
        assert!(String::from_utf8(no_ai.canonical_bytes().unwrap())
            .unwrap()
            .contains(r#""model":null"#));
        assert!(no_ai.model.asserts_no_ai());

        // (b) "An AI took part but we cannot name it" is a different shape
        //     and a different digest. If these two ever collapsed into the
        //     same bytes, a firm that lost its model metadata would be
        //     signing a false claim that it uses no AI.
        let unidentified = fixture(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            DecisionAction::Approved,
            ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(
                "caller did not supply model identity",
            )),
        );
        assert!(!unidentified.model.asserts_no_ai());
        assert_ne!(
            no_ai.canonical_sha256_hex().unwrap(),
            unidentified.canonical_sha256_hex().unwrap()
        );
        let uv = serde_json::to_value(&unidentified).unwrap();
        assert!(uv.get("model").unwrap().is_object());
        assert_eq!(
            uv.pointer("/model/provider/state").and_then(Value::as_str),
            Some("unpopulated")
        );
        assert_eq!(uv.pointer("/model/provider/value"), Some(&Value::Null));

        // (c) There is no third serialisation. A populated model is an
        //     object whose leaves are `recorded`.
        let mut identity = ModelIdentity::participated_but_unidentified("x");
        identity.provider = Provenanced::recorded("anthropic".to_string());
        let populated = fixture(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            DecisionAction::Approved,
            ModelAttestation::recorded(identity),
        );
        let pv = serde_json::to_value(&populated).unwrap();
        assert_eq!(
            pv.pointer("/model/provider/state").and_then(Value::as_str),
            Some("recorded")
        );
        assert_eq!(
            pv.pointer("/model/provider/value").and_then(Value::as_str),
            Some("anthropic")
        );
    }

    // -----------------------------------------------------------------
    // Round trip and canonicalisation
    // -----------------------------------------------------------------

    /// serialise -> parse -> re-serialise, bytes identical, for all three
    /// model shapes. Catches any asymmetry between `Serialize` and
    /// `Deserialize` (a rename applied to one direction only, a field with a
    /// serde default that swallows a null, an enum whose wire form does not
    /// parse back).
    #[test]
    fn canonical_bytes_round_trip_is_byte_identical() {
        let cases = vec![
            approval(),
            rejection(),
            fixture(
                DecisionAction::Modified,
                DecisionOutcome::NoVerdict,
                DecisionAction::Modified,
                ModelAttestation::recorded(ModelIdentity::participated_but_unidentified("none")),
            ),
        ];
        for original in cases {
            let first = original.canonical_bytes().unwrap();
            let parsed: DecisionEvidence = serde_json::from_slice(&first).unwrap();
            let second = parsed.canonical_bytes().unwrap();
            assert_eq!(
                String::from_utf8(first).unwrap(),
                String::from_utf8(second).unwrap()
            );
            assert_eq!(original, parsed);
        }
    }

    /// A fixed fixture whose canonical bytes are written out literally, so
    /// that any change to a field name, a field order (there is none — keys
    /// are sorted), an enum's wire form, or the escaping rules shows up as a
    /// failing test rather than as a pack that a Python verifier silently
    /// disagrees with.
    ///
    /// The expected string below is exactly what
    /// `json.dumps(obj, sort_keys=True, separators=(",", ":"))` produces for
    /// the same logical object. That was not asserted by eye: it was checked
    /// by loading `scripts/export_audit_evidence.py`, parsing this literal
    /// and feeding it back through the exporter's own `canonical_bytes`, and
    /// comparing byte for byte. Re-run that check whenever this literal
    /// changes — a fixture that only Rust agrees with proves nothing about
    /// what an offline verifier will compute.
    ///
    /// Re-run for the 1.2.0 -> 1.3.0 rewrite of this literal, which gave
    /// `data.consent` a real source in `wealth/evidence.rs` (this fixture is
    /// built directly, not through that path, so it still shows the
    /// unpopulated shape a pre-migrations/0011 decision continues to serve)
    /// and moved every `NO_SOURCE` string to name the new version. Two
    /// checks, both against these exact bytes: the exporter's own
    /// `canonical_bytes` reproduces them, and `jsonschema` validates the
    /// parsed object against the pinned `schema/decision_evidence/v1.3.0.json`
    /// with zero errors — and against `v1.2.0.json` with errors, which is the
    /// expected result and the reason the bump is a new file rather than an
    /// edit.
    #[test]
    fn canonical_bytes_of_the_fixed_fixture_do_not_drift() {
        const EXPECTED: &str = concat!(
            r#"{"data":{"consent":{"consent_id":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""consent_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""granted_at":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""purpose_hash":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""scope":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null}},"#,
            r#""customer":{"data_provenance":{"disclosed_attributes":[],"statement":"Memtara holds no income, liquidity, risk-tolerance or holdings figure for this subject.","vault_root":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null}},"#,
            r#""data_provenance_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""subject_id":"user_9f2a"},"data_schema_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null}},"#,
            r#""decision":{"business_process":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""decision_id":"71386234-daae-4896-91fe-4c469cf59af2","final_decision":{"decided_at":"2026-08-18T18:03:52Z","decision_basis":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""outcome":"affirmative"},"input_context_fingerprint":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""institution":{"org_id":"2f1c8d4e-0a1b-4c3d-9e8f-7a6b5c4d3e2f","org_name":"Example Bank PJSC","org_type":"bank"},"output_fingerprint":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""status":"approved","timestamps":{"assessed_at":"2026-08-18T18:03:52Z","exported_at":"2026-08-18T18:04:00Z","opened_at":"2026-08-18T17:59:00Z"}},"evidence":{"cryptographic_proofs":[{"accepted_by_bb_verify":true,"circuit":"wealth_suitability","proof_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","public_inputs":["0x01","0x02"],"verification_key_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"evidence_artifacts":[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"zk_proof","uri":"proof/wealth_suitability.proof"}]},"#,
            r#""evidence_schema_version":"1.3.0","human_review":{"action":"approved","human_review_protocol_version":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null},"#,
            r#""override":false,"override_reason":null,"performed":false,"review_duration_ms":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null},"#,
            r#""review_duration_source":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null},"#,
            r#""reviewed_at":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null},"#,
            r#""reviewer_id":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null},"#,
            r#""reviewer_role":{"state":"not_applicable","unpopulated_reason":"no human review step was performed on this decision; human_review.performed is false, and this field is not applicable rather than missing","value":null}},"#,
            r#""model":null,"model_provenance":{"as_declared_at_open":{"declaration":"no_ai_participated","identity":{"config_fingerprint":null,"environment":null,"model_name":null,"model_version":null,"prompt_version":null,"provider":null,"system_prompt_or_policy_id":null,"timestamp":null},"#,
            r#""no_ai_attestation":"suitability produced by the deterministic rules engine; no model in the recommendation path","unidentified_reason":null},"corrected":false,"correction_count":0,"corrections":[],"declared_at":{"state":"recorded","unpopulated_reason":null,"value":"2026-08-18T17:59:00Z"},"#,
            r#""statement":"The model block in this record is what this organisation asserts about the AI system that participated in this decision. The declaration it made when the assessment was opened is preserved here under as_declared_at_open and is never altered by anything, including a correction. Note when that declaration is made: at open, in the same transaction as the assessment, before the subject's device has produced a proof, before a verdict exists and before any human review \u2014 so it is a statement about a decision that has not happened yet. Compare declared_at with decision.timestamps.assessed_at. Corrections are append-only and numbered from 1; a gap in correction_no means a correction was removed from the database after it was filed, and each one is separately committed to the audit chain."},"#,
            r#""policy":{"decision_logic_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""policy_id":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""policy_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""regulatory_control_mapping":[{"clause":"COB 3.1","framework":"DFSA"},{"clause":"5(c)","framework":"CBUAE"}],"source":"disclosure_requests.policy, snapshotted at open","thresholds":{"source":"product registry, snapshotted when the assessment was opened","threshold_set_id":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""threshold_version":{"state":"unpopulated","unpopulated_reason":"no source exists in memtara-api as of evidence schema 1.3.0; see schema/decision_evidence/v1.3.0.json for what would populate it","value":null},"#,
            r#""values":{"max_concentration_percent":20,"min_income":500000,"min_liquidity":250000,"product_risk_level":3}}}}"#,
        );

        let actual = String::from_utf8(approval().canonical_bytes().unwrap()).unwrap();
        assert_eq!(actual, EXPECTED);
    }

    // -----------------------------------------------------------------
    // Supporting invariants
    // -----------------------------------------------------------------

    /// Every placeholder in a freshly built record says why it is empty.
    /// Catches a future `Provenanced::unpopulated("")` or a silent default.
    #[test]
    fn every_unpopulated_field_names_what_would_fill_it() {
        let value = serde_json::to_value(approval()).unwrap();
        let mut checked = 0usize;
        fn walk(v: &Value, checked: &mut usize) {
            if let Value::Object(map) = v {
                if let Some(Value::String(state)) = map.get("state") {
                    if map.contains_key("value") && map.contains_key("unpopulated_reason") {
                        *checked += 1;
                        match state.as_str() {
                            "recorded" => {
                                assert!(!map["value"].is_null());
                                assert!(map["unpopulated_reason"].is_null());
                            }
                            "unpopulated" | "not_applicable" => {
                                assert!(map["value"].is_null());
                                let reason = map["unpopulated_reason"].as_str().unwrap();
                                assert!(
                                    reason.len() > 20,
                                    "placeholder reason is not informative: {reason:?}"
                                );
                            }
                            other => panic!("unknown field state {other:?}"),
                        }
                    }
                }
                for child in map.values() {
                    walk(child, checked);
                }
            }
            if let Value::Array(items) = v {
                for child in items {
                    walk(child, checked);
                }
            }
        }
        walk(&value, &mut checked);
        assert!(checked >= 16, "expected many placeholders, found {checked}");
    }

    /// `Provenanced` cannot claim a state its value contradicts.
    #[test]
    fn provenanced_states_and_values_agree() {
        assert!(Provenanced::recorded("x".to_string()).is_coherent());
        assert!(Provenanced::<String>::unpopulated("reason").is_coherent());
        assert!(Provenanced::<String>::not_applicable("reason").is_coherent());

        let incoherent = Provenanced::<String> {
            state: FieldState::Recorded,
            value: None,
            unpopulated_reason: None,
        };
        assert!(!incoherent.is_coherent());
    }

    /// The three version fields that live outside `model` are all present
    /// and all named, plus the five inside it. Catches a rename or a
    /// deletion during a refactor.
    #[test]
    fn every_version_field_the_spec_requires_is_present() {
        let with_model = fixture(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            DecisionAction::Approved,
            ModelAttestation::recorded(ModelIdentity::participated_but_unidentified("n/a")),
        );
        let v = serde_json::to_value(&with_model).unwrap();
        for pointer in [
            "/evidence_schema_version",
            "/model/model_version",
            "/model/prompt_version",
            "/policy/thresholds/threshold_version",
            "/policy/policy_version",
            "/policy/decision_logic_version",
            "/data/data_schema_version",
            "/data/consent/consent_version",
            "/human_review/human_review_protocol_version",
        ] {
            assert!(
                v.pointer(pointer).is_some(),
                "missing required version field {pointer}"
            );
        }
    }

    // -----------------------------------------------------------------
    // INVARIANT 4 — an override always states why
    // -----------------------------------------------------------------

    /// The negative control for the one field pairing that can turn a
    /// bypassed control into a clean-looking row.
    ///
    /// What it catches: a future `ReviewOverride::Overridden` constructed
    /// directly rather than through `overridden()`; a relaxation of the
    /// minimum length that lets `"n/a"` through; and — via
    /// `validate_override_pairing` — a record that arrived as bytes with
    /// `override: true` and a null reason, which `serde` will always accept
    /// because the pinned wire shape is two independent keys.
    ///
    /// The pairing is forbidden in three places and this test walks all
    /// three, because two of them are unreachable from the third: the DB
    /// constraint does not run in a unit test and the constructor does not
    /// run on a deserialised record.
    #[test]
    fn an_override_without_a_reason_cannot_be_built_or_read_back_as_valid() {
        // (a) The constructor refuses every shape of "no reason".
        for empty in ["", "   ", "n/a", "-", "\t\n", "why"] {
            assert_eq!(
                ReviewOverride::overridden(empty),
                Err(OverrideReasonMissing),
                "an override reason of {empty:?} must be refused"
            );
        }
        let good = ReviewOverride::overridden(
            "client's documented liquidity event post-dates the vault snapshot",
        )
        .expect("a real reason is accepted");

        // (b) A record built through the builder carries both halves or
        //     neither. There is no route to `override: true` with a null
        //     reason, because the only constructor for the overridden case
        //     consumes a reason.
        let overridden = fixture_with_review(
            DecisionAction::Approved,
            DecisionOutcome::Negative,
            ModelAttestation::no_ai_participated(),
            HumanReviewInputs::completed(CompletedReview {
                reviewer_id: "emp-4417".to_string(),
                reviewer_role: "senior_suitability_officer".to_string(),
                action: DecisionAction::Approved,
                over_ride: good,
                reviewed_at: ts("2026-08-18T18:31:00Z"),
                protocol_version: "cob-review-2026.2".to_string(),
                duration: Some((214_000, "reviewer_client_asserted".to_string())),
            }),
        );
        let v = serde_json::to_value(&overridden).unwrap();
        assert_eq!(v.pointer("/human_review/override"), Some(&Value::Bool(true)));
        assert!(v
            .pointer("/human_review/override_reason")
            .and_then(Value::as_str)
            .is_some_and(|r| r.contains("liquidity event")));
        assert!(overridden.validate_override_pairing().is_ok());

        // (c) The same record hand-edited the way an insider would edit it —
        //     keep the flag, drop the justification — is refused on read.
        let mut tampered = overridden.clone();
        tampered.human_review.override_reason = None;
        assert_eq!(
            tampered.validate_override_pairing(),
            Err(OverrideReasonMissing)
        );
        tampered.human_review.override_reason = Some("   ".to_string());
        assert_eq!(
            tampered.validate_override_pairing(),
            Err(OverrideReasonMissing)
        );

        // And the check is not vacuous: a non-override with no reason is
        // fine, which is the whole point of the field being nullable.
        assert!(approval().validate_override_pairing().is_ok());
    }

    /// A decision nobody reviewed must not carry a reviewer's judgement.
    ///
    /// `action` stays required — the type has three variants and no
    /// `Pending`, because a record exists only once a decision was reached —
    /// so the load-bearing part is everything around it: `performed: false`
    /// and every reviewer-identity field asserting non-applicability rather
    /// than admitting ignorance. Those are different claims. `Unpopulated`
    /// would say "a human may have reviewed this and we lost the name",
    /// which is a confession this deployment has no reason to make.
    #[test]
    fn an_unreviewed_decision_asserts_that_no_human_stood_behind_it() {
        let v = serde_json::to_value(approval()).unwrap();
        assert_eq!(v.pointer("/human_review/performed"), Some(&Value::Bool(false)));
        for field in [
            "reviewer_id",
            "reviewer_role",
            "reviewed_at",
            "human_review_protocol_version",
            "review_duration_ms",
            "review_duration_source",
        ] {
            assert_eq!(
                v.pointer(&format!("/human_review/{field}/state"))
                    .and_then(Value::as_str),
                Some("not_applicable"),
                "{field} must assert absence, not admit ignorance, when nobody reviewed"
            );
        }
        assert_eq!(v.pointer("/human_review/override"), Some(&Value::Bool(false)));
        assert_eq!(v.pointer("/human_review/override_reason"), Some(&Value::Null));

        // A reviewed record is visibly different at every one of those keys.
        let reviewed = reviewed_approval();
        let rv = serde_json::to_value(&reviewed).unwrap();
        assert_eq!(rv.pointer("/human_review/performed"), Some(&Value::Bool(true)));
        assert_eq!(
            rv.pointer("/human_review/reviewer_id/state")
                .and_then(Value::as_str),
            Some("recorded")
        );
        assert_ne!(
            approval().canonical_sha256_hex().unwrap(),
            reviewed.canonical_sha256_hex().unwrap()
        );
    }

    /// The Cigna field, and the reason it is two fields.
    ///
    /// A duration with no stated provenance is admissible as neither an
    /// asserted number nor a measured one, so the two travel together or not
    /// at all. Catches a future change that records the milliseconds and
    /// drops the source — which is the shape that would let a client-timed
    /// 1.2 seconds be read as a server measurement.
    #[test]
    fn review_duration_and_its_provenance_are_recorded_together() {
        let timed = reviewed_approval();
        let v = serde_json::to_value(&timed).unwrap();
        assert_eq!(
            v.pointer("/human_review/review_duration_ms/value")
                .and_then(Value::as_i64),
            Some(214_000)
        );
        assert_eq!(
            v.pointer("/human_review/review_duration_source/value")
                .and_then(Value::as_str),
            Some("reviewer_client_asserted")
        );

        // An untimed review: both unpopulated, both naming the input that
        // would fill them. Never one recorded and one blank.
        let untimed = fixture_with_review(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            ModelAttestation::no_ai_participated(),
            HumanReviewInputs::completed(CompletedReview {
                reviewer_id: "emp-4417".to_string(),
                reviewer_role: "senior_suitability_officer".to_string(),
                action: DecisionAction::Approved,
                over_ride: ReviewOverride::NotOverridden,
                reviewed_at: ts("2026-08-18T18:31:00Z"),
                protocol_version: "cob-review-2026.2".to_string(),
                duration: None,
            }),
        );
        let uv = serde_json::to_value(&untimed).unwrap();
        for field in ["review_duration_ms", "review_duration_source"] {
            assert_eq!(
                uv.pointer(&format!("/human_review/{field}/state"))
                    .and_then(Value::as_str),
                Some("unpopulated"),
                "{field}"
            );
            assert!(uv
                .pointer(&format!("/human_review/{field}/unpopulated_reason"))
                .and_then(Value::as_str)
                .is_some_and(|r| r.contains("review_duration_ms")));
        }

        // The duration is inside the digested bytes. A number a firm can
        // edit after the fact is not a finding, it is a spreadsheet.
        let mut faster = timed.clone();
        faster.human_review.review_duration_ms = Provenanced::recorded(1_200);
        assert_ne!(
            timed.canonical_sha256_hex().unwrap(),
            faster.canonical_sha256_hex().unwrap()
        );
    }

    /// `decision_basis` is derived, never assigned, so no code path can
    /// reach an override without the basis that names it — the variant a
    /// supervisor greps for.
    #[test]
    fn decision_basis_names_the_override_it_came_from() {
        let none = HumanReviewInputs::not_performed(DecisionAction::Approved);
        assert_eq!(derive_decision_basis(&none), DecisionBasis::ProofOnly);

        let concurring = HumanReviewInputs::completed(CompletedReview {
            reviewer_id: "e1".to_string(),
            reviewer_role: "r".to_string(),
            action: DecisionAction::Rejected,
            over_ride: ReviewOverride::NotOverridden,
            reviewed_at: ts("2026-08-18T18:31:00Z"),
            protocol_version: "p".to_string(),
            duration: None,
        });
        assert_eq!(
            derive_decision_basis(&concurring),
            DecisionBasis::ProofAndHumanConcurred
        );

        let against = HumanReviewInputs::completed(CompletedReview {
            reviewer_id: "e1".to_string(),
            reviewer_role: "r".to_string(),
            action: DecisionAction::Approved,
            over_ride: ReviewOverride::overridden("documented liquidity event post-dates the vault")
                .unwrap(),
            reviewed_at: ts("2026-08-18T18:31:00Z"),
            protocol_version: "p".to_string(),
            duration: None,
        });
        assert_eq!(
            derive_decision_basis(&against),
            DecisionBasis::ProofAndHumanOverride
        );
    }

    /// Rejection symmetry, held across the review dimension as well as the
    /// three enums. A reviewed approval and a reviewed decline differ only
    /// in values.
    #[test]
    fn key_set_is_invariant_across_reviewed_and_unreviewed_records() {
        let baseline = paths_of(&approval());
        let reviewed_declined = fixture_with_review(
            DecisionAction::Rejected,
            DecisionOutcome::Negative,
            ModelAttestation::no_ai_participated(),
            HumanReviewInputs::completed(CompletedReview {
                reviewer_id: "emp-4417".to_string(),
                reviewer_role: "senior_suitability_officer".to_string(),
                action: DecisionAction::Rejected,
                over_ride: ReviewOverride::NotOverridden,
                reviewed_at: ts("2026-08-18T18:31:00Z"),
                protocol_version: "cob-review-2026.2".to_string(),
                duration: Some((214_000, "reviewer_client_asserted".to_string())),
            }),
        );
        assert_eq!(paths_of(&reviewed_approval()), baseline);
        assert_eq!(paths_of(&reviewed_declined), baseline);
        assert_ne!(
            reviewed_approval().canonical_sha256_hex().unwrap(),
            reviewed_declined.canonical_sha256_hex().unwrap()
        );
    }

    // -----------------------------------------------------------------
    // INVARIANT 5 — a corrected attestation is visible, and the original
    //               survives it
    // -----------------------------------------------------------------

    /// The record of a corrected decision must not be readable as the record
    /// of an uncorrected one.
    ///
    /// This is the half of attack 11 that the correction path alone does not
    /// close. A route that files corrections nobody reading the record can
    /// see would have corrected nothing: the record would go on serving the
    /// pre-decision declaration with `state: "recorded"`, internally
    /// consistent and wrong, which is exactly the finding.
    ///
    /// What this catches: `model` left pinned to the original when a
    /// correction exists; `model_provenance` dropped from the record or made
    /// optional; `corrected` assigned rather than derived; and the original
    /// declaration being overwritten by the correction instead of preserved
    /// beside it.
    #[test]
    fn a_correction_changes_what_the_record_says_and_keeps_what_it_said() {
        let before = approval();
        let after = fixture_with_provenance(
            DecisionAction::Approved,
            DecisionOutcome::Affirmative,
            // The `model` block a builder produces once a correction exists:
            // the corrected identity, not the declaration it supersedes.
            ModelAttestation::recorded(ModelIdentity {
                provider: Provenanced::recorded("anthropic".to_string()),
                model_name: Provenanced::recorded("claude-opus-4".to_string()),
                model_version: Provenanced::recorded("20260514".to_string()),
                prompt_version: Provenanced::recorded("suitability-v7".to_string()),
                environment: Provenanced::recorded("production".to_string()),
                config_fingerprint: Provenanced::recorded("ab".repeat(32)),
                system_prompt_or_policy_id: Provenanced::recorded(
                    "policy/suitability/7".to_string(),
                ),
                timestamp: Provenanced::recorded(ts("2026-08-18T17:58:41Z")),
            }),
            HumanReviewInputs::not_performed(DecisionAction::Approved),
            corrected(),
        );

        let b = serde_json::to_value(&before).unwrap();
        let a = serde_json::to_value(&after).unwrap();

        // 1. Uncorrected says so explicitly rather than by an absent key. A
        //    reader must not have to infer "nobody corrected this" from a
        //    missing block, because a missing block and a dropped feature
        //    look identical.
        assert_eq!(b.pointer("/model_provenance/corrected"), Some(&Value::Bool(false)));
        assert_eq!(
            b.pointer("/model_provenance/correction_count").and_then(Value::as_i64),
            Some(0)
        );

        // 2. Corrected serves the corrected identity, and the superseded one
        //    is nowhere in `model`.
        assert_eq!(a.pointer("/model_provenance/corrected"), Some(&Value::Bool(true)));
        assert_eq!(
            a.pointer("/model/provider/value").and_then(Value::as_str),
            Some("anthropic")
        );

        // 3. And the declaration made at open survives, verbatim, including
        //    the fact that it was the strong no-AI assertion — which is the
        //    single most interesting thing about this particular correction
        //    and the thing a firm would most want to lose.
        assert_eq!(
            a.pointer("/model_provenance/as_declared_at_open/declaration")
                .and_then(Value::as_str),
            Some("no_ai_participated")
        );
        assert!(a
            .pointer("/model_provenance/as_declared_at_open/no_ai_attestation")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("rules engine")));
        assert_eq!(
            a.pointer("/model_provenance/as_declared_at_open/identity/provider"),
            Some(&Value::Null)
        );

        // 4. Who, why and when — all three, or the correction is an
        //    unattributed edit wearing an audit trail.
        for pointer in [
            "/model_provenance/corrections/0/asserted_by",
            "/model_provenance/corrections/0/asserted_by_role",
            "/model_provenance/corrections/0/correction_reason",
            "/model_provenance/corrections/0/asserted_at",
            "/model_provenance/corrections/0/recorded_at",
            "/model_provenance/corrections/0/correction_id",
        ] {
            assert!(a.pointer(pointer).is_some_and(|v| !v.is_null()), "{pointer}");
        }

        // 5. The seal moves. A correction the digested bytes do not carry is
        //    a correction anyone can drop.
        assert_ne!(
            before.canonical_sha256_hex().unwrap(),
            after.canonical_sha256_hex().unwrap()
        );

        // 6. `declared_at` is in the record, which is what lets an examiner
        //    establish the finding's core fact — that the attestation
        //    predates the decision — without our source. Both operands are
        //    here; the comparison is deliberately theirs to make.
        let declared_at = b
            .pointer("/model_provenance/declared_at/value")
            .and_then(Value::as_str)
            .expect("declared_at must be recorded when an attestation exists");
        let assessed_at = b
            .pointer("/decision/timestamps/assessed_at")
            .and_then(Value::as_str)
            .unwrap();
        assert!(declared_at < assessed_at);
    }

    /// Rejection symmetry survives the correction dimension.
    ///
    /// The invariant is that an approval and a decline built from the same
    /// inputs serialise with an identical key set, so that a digest
    /// difference can only ever mean tampering and never "this client was
    /// declined". `model_provenance` is a new top-level block containing a
    /// variable-length array, which is exactly the shape that breaks it if
    /// anything in there ever varies by outcome. Nothing does, and this is
    /// what will fail if something starts to.
    ///
    /// Compared against a corrected baseline rather than `approval()`: a
    /// corrected record legitimately carries more paths than an uncorrected
    /// one, because the corrections array has entries. That difference is a
    /// function of what happened to the decision, not of how it came out.
    #[test]
    fn a_corrected_approval_and_a_corrected_decline_have_identical_key_sets() {
        let of = |status, outcome| {
            paths_of(&fixture_with_provenance(
                status,
                outcome,
                ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(
                    "correction 1 states an AI participated and cannot be identified",
                )),
                HumanReviewInputs::completed(CompletedReview {
                    reviewer_id: "emp-4417".to_string(),
                    reviewer_role: "senior_suitability_officer".to_string(),
                    action: status,
                    over_ride: ReviewOverride::NotOverridden,
                    reviewed_at: ts("2026-08-18T18:31:00Z"),
                    protocol_version: "cob-review-2026.2".to_string(),
                    duration: Some((214_000, "reviewer_client_asserted".to_string())),
                }),
                corrected(),
            ))
        };
        let approved = of(DecisionAction::Approved, DecisionOutcome::Affirmative);
        let declined = of(DecisionAction::Rejected, DecisionOutcome::Negative);
        let only_approved: Vec<_> = approved.difference(&declined).collect();
        let only_declined: Vec<_> = declined.difference(&approved).collect();
        assert!(
            only_approved.is_empty() && only_declined.is_empty(),
            "only in approval: {only_approved:?}; only in decline: {only_declined:?}"
        );

        // And the correction block is genuinely in the compared set, so this
        // is not passing because both records happen to lack it.
        assert!(approved.contains(".model_provenance.corrections[].correction_reason"));
    }

    /// `model: null` is still the signed no-AI assertion, and a correction
    /// can never produce it.
    ///
    /// The rule migrations/0009 enforces at the row level and
    /// `model_correction.rs` enforces at the boundary, asserted here at the
    /// level of the serialised record: because a correction's declaration can
    /// only be `model_identified` or `participated_but_unidentified`, and
    /// both of those serialise as a present object, `model: null` in a record
    /// with `corrected: true` is unreachable. So the assertion is now
    /// slightly stronger than it was under 1.1.0: null means the declaration
    /// made at open said no AI took part AND nothing has since said
    /// otherwise.
    #[test]
    fn a_correction_can_never_produce_the_no_ai_assertion() {
        for declaration in ["model_identified", "participated_but_unidentified"] {
            let mut provenance = corrected();
            provenance.corrections[0].declaration = declaration.to_string();
            // Whatever the corrected declaration is, the model block a
            // builder produces from it is an object. There is no third
            // rendering, and `null` is not among the two.
            let record = fixture_with_provenance(
                DecisionAction::Approved,
                DecisionOutcome::Affirmative,
                ModelAttestation::recorded(ModelIdentity::participated_but_unidentified(
                    "the correction could not name the deployment",
                )),
                HumanReviewInputs::not_performed(DecisionAction::Approved),
                provenance,
            );
            let v = serde_json::to_value(&record).unwrap();
            assert!(v.get("model").unwrap().is_object(), "{declaration}");
            assert!(!record.model.asserts_no_ai(), "{declaration}");
            // And it is still not the same bytes as the assertion, which is
            // the property that stops a firm that lost its model metadata
            // from signing a claim that it runs no models.
            assert_ne!(
                record.canonical_sha256_hex().unwrap(),
                approval().canonical_sha256_hex().unwrap()
            );
        }

        // The assertion itself is unchanged: an uncorrected record whose
        // declaration was no-AI still serialises `model` as an explicit null
        // under a present key.
        let v = serde_json::to_value(approval()).unwrap();
        assert_eq!(v.get("model"), Some(&Value::Null));
        assert_eq!(v.pointer("/model_provenance/corrected"), Some(&Value::Bool(false)));
    }

    /// `corrected` and `correction_count` cannot contradict the corrections
    /// they describe, because no call site sets them.
    ///
    /// A boolean that a caller assigns is a boolean that will eventually
    /// disagree with its own data — and this one disagreeing in the
    /// convenient direction reads as "this decision was never corrected",
    /// which is the exact claim the correction path exists to make
    /// impossible.
    #[test]
    fn corrected_and_correction_count_are_derived_and_not_assignable() {
        let none = ModelProvenance::new(
            Provenanced::unpopulated("no attestation row"),
            declared_no_ai(),
            vec![],
        );
        assert!(!none.corrected);
        assert_eq!(none.correction_count, 0);

        let one = corrected();
        assert!(one.corrected);
        assert_eq!(one.correction_count, 1);
        assert_eq!(one.correction_count as usize, one.corrections.len());

        // The pre-capture case: never declared, therefore never corrected,
        // and the reason travels into both the timestamp and the declaration
        // rather than leaving either blank.
        let never = ModelProvenance::never_declared(
            "this assessment was opened before model identity capture existed",
        );
        assert!(!never.corrected);
        assert_eq!(never.as_declared_at_open.declaration, "participated_but_unidentified");
        assert!(never.as_declared_at_open.unidentified_reason.is_some());
        assert!(!never.declared_at.is_recorded());
    }

    /// The struct and the pinned schema cannot drift apart at the top level.
    ///
    /// Cheap, and it catches the specific mistake this change was one step
    /// away from making: adding a key to `DecisionEvidence` and shipping it
    /// against a schema that forbids unknown properties, so that every record
    /// the server produces fails validation in an examiner's own tooling
    /// while passing every test here.
    ///
    /// Only the top level, deliberately. A full JSON Schema validation would
    /// need a validator dependency this crate does not have and does not need
    /// — the offline bundle carries one, and `scripts/bundle` runs it. This
    /// is the tripwire, not the check.
    #[test]
    fn the_pinned_schema_names_exactly_the_top_level_keys_this_record_serves() {
        let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema/decision_evidence")
            .join(format!("v{EVIDENCE_SCHEMA_VERSION}.json"));
        let schema: Value =
            serde_json::from_slice(&std::fs::read(&pinned).expect("pinned schema is readable"))
                .expect("pinned schema is JSON");

        let record = serde_json::to_value(approval()).unwrap();
        let served: BTreeSet<String> =
            record.as_object().unwrap().keys().cloned().collect();

        let declared: BTreeSet<String> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            served, declared,
            "the record's top-level keys and the pinned schema's properties must match exactly; \
             the schema sets additionalProperties: false, so a key on one side only makes every \
             record this server produces invalid in an examiner's tooling"
        );

        // And every one of them is required, not merely permitted. A key that
        // may be absent is a key whose absence carries no meaning, which is
        // the opposite of what this record is for.
        let required: BTreeSet<String> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(served, required);
        assert_eq!(schema["properties"]["evidence_schema_version"]["const"], EVIDENCE_SCHEMA_VERSION);
    }

    /// `NoVerdict` is not a synonym for a decline. The distinction
    /// `wealth/evidence.rs:180-187` already draws, held at the type level.
    #[test]
    fn no_verdict_is_distinct_from_a_negative_verdict() {
        let declined = rejection();
        let outage = fixture(
            DecisionAction::Rejected,
            DecisionOutcome::NoVerdict,
            DecisionAction::Rejected,
            ModelAttestation::no_ai_participated(),
        );
        assert_ne!(
            declined.canonical_sha256_hex().unwrap(),
            outage.canonical_sha256_hex().unwrap()
        );
        assert_eq!(
            serde_json::to_value(&outage)
                .unwrap()
                .pointer("/decision/final_decision/outcome")
                .and_then(Value::as_str),
            Some("no_verdict")
        );
    }
}
