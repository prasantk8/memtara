// Shared domain types. Every role builds against these rather than
// redefining them per-module — this is the contract.
//
// Postgres enums are modeled as plain TEXT columns (see migrations/0001_init.sql
// CHECK constraints) with manual to/from-str mapping here, rather than sqlx's
// `Type` derive — one less macro-version assumption to get wrong on the first
// try. Keep `as_str()` and `parse()` in lockstep with the CHECK constraints.

use serde::{Deserialize, Serialize};

// Re-export the vault's own policy types so the wire format the backend
// accepts is exactly what circuits/vault already agree on — no parallel
// definition to drift out of sync.
pub use memtara_vault::session::{Operator, PredicateConstraint, SessionPolicy, SessionType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgType {
    Bank,
    AiPlatform,
    Hospital,
    Government,
}

impl OrgType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgType::Bank => "bank",
            OrgType::AiPlatform => "ai_platform",
            OrgType::Hospital => "hospital",
            OrgType::Government => "government",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bank" => Some(OrgType::Bank),
            "ai_platform" => Some(OrgType::AiPlatform),
            "hospital" => Some(OrgType::Hospital),
            "government" => Some(OrgType::Government),
            _ => None,
        }
    }
}

/// Matches the 4 real circuits under `circuits/` — every disclosure request
/// names exactly one of these; there is no "generic" circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitType {
    EmergencySession,
    AiSession,
    TaxSession,
    IdentitySession,
}

impl CircuitType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitType::EmergencySession => "emergency_session",
            CircuitType::AiSession => "ai_session",
            CircuitType::TaxSession => "tax_session",
            CircuitType::IdentitySession => "identity_session",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "emergency_session" => Some(CircuitType::EmergencySession),
            "ai_session" => Some(CircuitType::AiSession),
            "tax_session" => Some(CircuitType::TaxSession),
            "identity_session" => Some(CircuitType::IdentitySession),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Pending,
    Fulfilled,
    Expired,
    Revoked,
}

impl DisclosureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureStatus::Pending => "pending",
            DisclosureStatus::Fulfilled => "fulfilled",
            DisclosureStatus::Expired => "expired",
            DisclosureStatus::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(DisclosureStatus::Pending),
            "fulfilled" => Some(DisclosureStatus::Fulfilled),
            "expired" => Some(DisclosureStatus::Expired),
            "revoked" => Some(DisclosureStatus::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtpChannel {
    Sms,
    Whatsapp,
}

impl OtpChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpChannel::Sms => "sms",
            OtpChannel::Whatsapp => "whatsapp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sms" => Some(OtpChannel::Sms),
            "whatsapp" => Some(OtpChannel::Whatsapp),
            _ => None,
        }
    }
}
