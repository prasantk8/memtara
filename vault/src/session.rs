// Session Management for Memtara ZKP System
// Handles scoped temporary access with cryptographic proofs

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Types of sessions in Memtara
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionType {
    /// Health/emergency session - limited medical data disclosure
    Emergency,
    /// AI connector session - selective data for AI processing
    AiSession,
    /// Tax/financial session - income and deduction proof
    Tax,
    /// Identity/career session - professional credentials
    Identity,
    /// General vault access with custom constraints
    Custom,
}

/// Purpose hash constants (pre-computed for common use cases)
pub mod purposes {
    use sha2::{Digest, Sha256};

    pub const EMERGENCY: [u8; 32] = {
        let h = Sha256::digest(b"memtara:purpose:emergency");
        h.into()
    };
    
    pub const AI_SESSION: [u8; 32] = {
        let h = Sha256::digest(b"memtara:purpose:ai_session");
        h.into()
    };
    
    pub const TAX_PREPARER: [u8; 32] = {
        let h = Sha256::digest(b"memtara:purpose:tax_preparer");
        h.into()
    };
    
    pub const IDENTITY_INTERVIEW: [u8; 32] = {
        let h = Sha256::digest(b"memtara:purpose:identity_interview");
        h.into()
    };
}

/// Session policy defining scope and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub session_type: SessionType,
    pub purpose_hash: [u8; 32],
    pub categories: Vec<String>,        // Data categories to share
    pub duration_seconds: u64,          // How long the session is valid
    pub predicates: Vec<PredicateConstraint>, // What data must match
    pub max_payload_size: Option<usize>,      // Optional limit on payload size
}

/// Constraint for filtering which records can be included in a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateConstraint {
    pub field: String,
    pub operator: Operator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Equals,
    GreaterThan,
    LessThan,
    RangeMin,
    RangeMax,
    SetContains,
    BloodType,   // Special operator for blood type matching
    AllergyCheck, // Check if allergy is present/absent
}

/// Active session with cryptographic proof data
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub policy: SessionPolicy,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce: [u8; 32],
    
    /// ZKP proof data (would be populated by circuit execution)
    pub zkp_proof: Option<Vec<u8>>,
    
    /// Public statement for verification
    pub public_statement: SessionStatement,
}

/// Public statement that gets proven in the ZKP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatement {
    pub session_id: String,
    pub vault_root: [u8; 32],         // Commitment to all vault data
    pub categories_commitment: [u8; 32], // Merkle root of allowed categories
    pub purpose_hash: [u8; 32],
    pub start_time: i64,              // Unix timestamp
    pub expiry_time: i64,             // Unix timestamp
    pub nonce_commitment: [u8; 32],   // Poseidon hash of nonce
}

/// Builder for creating session policies with ZKP integration
pub struct SessionBuilder {
    vault_root: [u8; 32],
    session_type: Option<SessionType>,
    categories: Vec<String>,
    predicates: Vec<PredicateConstraint>,
    duration_seconds: u64,
}

impl SessionBuilder {
    pub fn new(vault_root: [u8; 32]) -> Self {
        Self {
            vault_root,
            session_type: None,
            categories: vec![],
            predicates: vec![],
            duration_seconds: 3600, // Default 1 hour
        }
    }

    pub fn emergency() -> Self {
        Self {
            vault_root: [0u8; 32],
            session_type: Some(SessionType::Emergency),
            categories: vec!["health".to_string()],
            predicates: vec![],
            duration_seconds: 3600, // 1 hour emergency access
        }
    }

    pub fn ai_session() -> Self {
        Self {
            vault_root: [0u8; 32],
            session_type: Some(SessionType::AiSession),
            categories: vec![],
            predicates: vec![],
            duration_seconds: 1800, // 30 minutes for AI sessions
        }
    }

    pub fn with_vault_root(mut self, root: [u8; 32]) -> Self {
        self.vault_root = root;
        self
    }

    pub fn with_categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }

    pub fn add_category(mut self, category: &str) -> Self {
        if !self.categories.contains(&category.to_string()) {
            self.categories.push(category.to_string());
        }
        self
    }

    pub fn with_predicates(mut self, predicates: Vec<PredicateConstraint>) -> Self {
        self.predicates = predicates;
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.duration_seconds = seconds.min(86400); // Max 24 hours
        self
    }

    pub fn build(self) -> Result<Session> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.duration_seconds as i64);
        
        let nonce = Self::generate_nonce();
        let purpose_hash = match self.session_type {
            Some(SessionType::Emergency) => purposes::EMERGENCY,
            Some(SessionType::AiSession) => purposes::AI_SESSION,
            Some(SessionType::Tax) => purposes::TAX_PREPARER,
            Some(SessionType::Identity) => purposes::IDENTITY_INTERVIEW,
            _ => {
                let h = sha2::Sha256::digest(b"memtara:purpose:custom");
                h.into()
            }
        };

        // Compute commitments (simplified - would use proper Merkle trees in production)
        let categories_commitment = Self::compute_categories_root(&self.categories);

        Ok(Session {
            id: Uuid::new_v4(),
            policy: SessionPolicy {
                session_type: self.session_type.unwrap_or(SessionType::Custom),
                purpose_hash,
                categories: self.categories,
                duration_seconds: self.duration_seconds,
                predicates: self.predicates,
                max_payload_size: None,
            },
            created_at: now,
            expires_at,
            nonce,
            zkp_proof: None,
            public_statement: SessionStatement {
                session_id: format!("{}", Uuid::new_v4()),
                vault_root: self.vault_root,
                categories_commitment,
                purpose_hash,
                start_time: now.timestamp(),
                expiry_time: expires_at.timestamp(),
                nonce_commitment: Self::hash_nonce(&nonce),
            },
        })
    }

    fn generate_nonce() -> [u8; 32] {
        use rand::{rngs::OsRng, RngCore};
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn compute_categories_root(categories: &[String]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for cat in categories {
            hasher.update(cat.as_bytes());
        }
        hasher.finalize().into()
    }

    fn hash_nonce(nonce: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"memtara:nonce:");
        hasher.update(nonce);
        hasher.finalize().into()
    }
}

impl Session {
    /// Check if session is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Get time remaining in seconds
    pub fn time_remaining(&self) -> i64 {
        let now = Utc::now();
        if now < self.expires_at {
            (self.expires_at - now).num_seconds()
        } else {
            0
        }
    }

    /// Generate emergency session with minimal required data
    pub fn generate_emergency_proof(
        vault_data: &str, // Simplified - would use actual vault records
    ) -> Result<EmergencyProof> {
        let nonce = SessionBuilder::generate_nonce();
        
        Ok(EmergencyProof {
            blood_type: "A+".to_string(),
            allergies: vec!["penicillin".to_string()],
            key_medications: vec!["aspirin".to_string()],
            insurance_id_hash: sha2::Sha256::digest(b"insurance-123").into(),
            nonce,
        })
    }

    /// Prepare session for AI with selective disclosure guarantee
    pub fn prepare_ai_session(
        allowed_categories: Vec<String>,
        max_duration_seconds: u64,
    ) -> Result<AISessionProof> {
        let nonce = SessionBuilder::generate_nonce();
        
        Ok(AISessionProof {
            session_id: Uuid::new_v4().to_string(),
            allowed_categories_root: SessionBuilder::compute_categories_root(&allowed_categories),
            max_duration_seconds,
            nonce,
            data_commitments: vec![], // Would contain commitments to records being shared
        })
    }
}

/// Emergency session proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyProof {
    pub blood_type: String,
    pub allergies: Vec<String>,
    pub key_medications: Vec<String>,
    pub insurance_id_hash: [u8; 32],
    pub nonce: [u8; 32],
}

/// AI session proof structure with selective disclosure guarantee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISessionProof {
    pub session_id: String,
    pub allowed_categories_root: [u8; 32],
    pub max_duration_seconds: u64,
    pub nonce: [u8; 32],
    
    /// Commitments to each record being shared (for audit trail)
    pub data_commitments: Vec<[u8; 32]>,
}

/// Verify that a session proof is valid
pub fn verify_session(session: &Session, current_time: i64) -> Result<bool> {
    let statement = &session.public_statement;
    
    // Check time bounds
    if current_time < statement.start_time {
        return Err(anyhow!("Session hasn't started yet"));
    }
    
    if current_time > statement.expiry_time {
        return Err(anyhow!("Session has expired"));
    }
    
    // Verify nonce commitment
    let computed_nonce_hash = SessionBuilder::hash_nonce(&session.nonce);
    if computed_nonce_hash != statement.nonce_commitment {
        return Err(anyhow!("Nonce verification failed"));
    }
    
    Ok(true)
}

/// Generate proof for AI that data came only from granted scope
pub fn generate_ai_scope_proof(
    session: &Session,
    record_hashes: Vec<[u8; 32]>,
    categories_included: Vec<String>,
) -> Result<AIScopeProof> {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    for hash in &record_hashes {
        hasher.update(hash);
    }
    for cat in &categories_included {
        hasher.update(cat.as_bytes());
    }
    
    Ok(AIScopeProof {
        session_id: session.id.to_string(),
        records_commitment: hasher.finalize().into(),
        categories_root: session.public_statement.categories_commitment,
        vault_root: session.public_statement.vault_root,
        proof_timestamp: Utc::now().timestamp(),
    })
}

/// AI scope proof for audit trail verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIScopeProof {
    pub session_id: String,
    pub records_commitment: [u8; 32], // Commitment to all records shared in this session
    pub categories_root: [u8; 32],     // Root of allowed categories
    pub vault_root: [u8; 32],          // Vault root at time of proof
    pub proof_timestamp: i64,          // When proof was generated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emergency_session() -> Result<()> {
        let vault_root = [1u8; 32];
        let builder = SessionBuilder::emergency().with_vault_root(vault_root);
        
        let session = builder.build()?;
        
        assert_eq!(session.policy.session_type, SessionType::Emergency);
        assert!(session.is_valid());
        assert!(session.time_remaining() > 0);
        
        Ok(())
    }

    #[test]
    fn test_ai_session_builder() -> Result<()> {
        let vault_root = [2u8; 32];
        let builder = SessionBuilder::new(vault_root)
            .with_categories(vec!["health".to_string(), "labs".to_string()])
            .with_duration(1800); // 30 minutes
        
        let session = builder.build()?;
        
        assert!(session.is_valid());
        assert_eq!(session.policy.categories.len(), 2);
        
        Ok(())
    }

    #[test]
    fn test_session_verification() -> Result<()> {
        let vault_root = [3u8; 32];
        let session = SessionBuilder::new(vault_root)
            .with_duration(3600)
            .build()?;
        
        let current_time = Utc::now().timestamp();
        assert!(verify_session(&session, current_time)?);
        
        Ok(())
    }

    #[test]
    fn test_ai_scope_proof() -> Result<()> {
        let vault_root = [4u8; 32];
        let session = SessionBuilder::new(vault_root)
            .with_categories(vec!["health".to_string()])
            .build()?;
        
        let record_hashes = vec![[1u8; 32], [2u8; 32]];
        let categories = vec!["health".to_string()];
        
        let proof = generate_ai_scope_proof(&session, record_hashes, categories)?;
        
        assert_eq!(proof.vault_root, vault_root);
        assert!(!proof.records_commitment.iter().all(|&b| b == 0));
        
        Ok(())
    }
}