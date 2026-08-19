// A field that knows whether it was populated, and why not if it wasn't.
//
// -------------------------------------------------------------------
// WHY THIS TYPE EXISTS
// -------------------------------------------------------------------
// About half of DecisionEvidence v1's leaf fields have no source in this
// codebase yet (see the spec's §1.2 table: all of `model.*`, all of
// `consent.*`, all of `human_review.*` identity, `policy_version`,
// `threshold_version`, `data_schema_version`). There are three ways to ship
// that and two of them are lies:
//
//   1. Omit the key            — the record's key set now depends on how much
//                                the deployment happened to know, so two
//                                records of the same decision canonicalise to
//                                different bytes. This is the exact defect
//                                the rejection-symmetry invariant forbids.
//   2. Emit `""` or `"1.0.0"`  — an examiner in 2028 cannot tell a real
//                                version from a default nobody set. Worse
//                                than omission, because it looks answered.
//   3. Emit a three-key object that says, in the signed bytes, "this is not
//      populated and here is why" — which is what this is.
//
// `state` is not derivable from `value`: `Unpopulated` and `NotApplicable`
// both carry `value: null`, and the difference between them is the whole
// point. `NotApplicable` is a *signed assertion of absence* — the field-level
// analogue of `model: null`. `Unpopulated` is an admission of ignorance.
// Collapsing them would let "we never built consent capture" read as "no
// consent was required here".

use serde::{Deserialize, Serialize};

/// Whether a `Provenanced` field carries a value, and if not, which kind of
/// absence it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    /// A real value was captured from a real source.
    Recorded,
    /// A signed assertion that this field does not apply to this decision —
    /// e.g. `consent.granted_at` on a process with no consent gate. An
    /// examiner may treat this as answered.
    NotApplicable,
    /// No source exists for this field in the system that produced the
    /// record. An examiner must treat this as a gap, not as a negative
    /// answer. `unpopulated_reason` names what would fill it.
    Unpopulated,
}

/// A leaf value plus the provenance of its presence or absence.
///
/// The serialised shape is always exactly three keys — `state`, `value`,
/// `unpopulated_reason` — in every state. Nothing here is ever
/// `skip_serializing_if`: a key that disappears changes the canonical bytes
/// and therefore the digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenanced<T> {
    pub state: FieldState,
    /// `Some` if and only if `state == Recorded`. Enforced by the
    /// constructors and asserted by `is_coherent`.
    pub value: Option<T>,
    /// Free text naming what would populate this field, or why it does not
    /// apply. `None` only when `state == Recorded`.
    pub unpopulated_reason: Option<String>,
}

impl<T> Provenanced<T> {
    /// A value that was actually captured.
    pub fn recorded(value: T) -> Self {
        Self {
            state: FieldState::Recorded,
            value: Some(value),
            unpopulated_reason: None,
        }
    }

    /// No source exists yet. `reason` must name what would populate it —
    /// a table, an endpoint, a caller-supplied argument. "unknown" is not a
    /// reason; the point of this variant is that the gap is legible without
    /// reading our source.
    pub fn unpopulated(reason: impl Into<String>) -> Self {
        Self {
            state: FieldState::Unpopulated,
            value: None,
            unpopulated_reason: Some(reason.into()),
        }
    }

    /// A signed assertion that the field does not apply to this decision.
    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Self {
            state: FieldState::NotApplicable,
            value: None,
            unpopulated_reason: Some(reason.into()),
        }
    }

    /// `state` and `value` agree. Deserialisation cannot enforce this (a
    /// hand-edited record could claim `Recorded` with a null value), so the
    /// check is available to callers and is asserted in the tests.
    pub fn is_coherent(&self) -> bool {
        match self.state {
            FieldState::Recorded => self.value.is_some() && self.unpopulated_reason.is_none(),
            FieldState::NotApplicable | FieldState::Unpopulated => {
                self.value.is_none() && self.unpopulated_reason.is_some()
            }
        }
    }

    pub fn is_recorded(&self) -> bool {
        matches!(self.state, FieldState::Recorded)
    }
}
