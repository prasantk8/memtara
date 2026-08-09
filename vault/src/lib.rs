// Memtara Vault - Local-First Encrypted Data Store
// Implements zero-knowledge proof infrastructure for selective disclosure

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

pub mod encryption;
pub mod merkle;
pub mod session;

#[derive(Debug, Clone)]
pub struct Vault {
    pub encrypted_store: Arc<RwLock<EncryptedStore>>,
    pub commitments: Arc<RwLock<commitment::CommitmentManager>>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            encrypted_store: Arc::new(RwLock::new(EncryptedStore::new())),
            commitments: Arc::new(RwLock::new(commitment::CommitmentManager::new())),
        }
    }

    /// Store an encrypted record with metadata under the given encryption key.
    pub async fn store_record(&self, item: VaultItem, encryption_key: &[u8; 32]) -> Result<()> {
        let mut store = self.encrypted_store.write().await;
        let id = item.id.clone();

        let data = item
            .data
            .as_deref()
            .ok_or_else(|| anyhow!("VaultItem '{}' has no data to store", id))?;

        // Encrypt the data before storing
        let encrypted_data = encryption::encrypt(data, encryption_key)?;

        // Create commitment to the record hash
        let record_hash = commitment::poseidon_commit(&[encrypted_data.hash()]);
        self.commitments.write().await.add_record_commitment(&id, &record_hash);

        store.items.insert(id, VaultItemEntry {
            encrypted_data,
            category: item.category.clone(),
            created_at: chrono::Utc::now().timestamp(),
            metadata: item.metadata,
            commitment: record_hash,
        });

        Ok(())
    }

    /// Retrieve an encrypted record by ID (requires the decryption key it was stored with)
    pub async fn get_record(&self, id: &str, decryption_key: &[u8; 32]) -> Result<VaultItem> {
        let store = self.encrypted_store.read().await;

        if let Some(entry) = store.items.get(id) {
            let decrypted_data = encryption::decrypt(&entry.encrypted_data, decryption_key)?;
            Ok(VaultItem {
                id: id.to_string(),
                data: Some(decrypted_data),
                category: entry.category.clone(),
                metadata: entry.metadata.clone(),
            })
        } else {
            Err(anyhow!("Record not found"))
        }
    }

    /// List records in a specific category (metadata only)
    pub async fn list_records(&self, category_filter: Option<&str>) -> Result<Vec<RecordMetadata>> {
        let store = self.encrypted_store.read().await;
        
        Ok(store.items
            .iter()
            .filter_map(|(id, entry)| {
                if category_filter.map_or(true, |cat| entry.category == cat) {
                    Some(RecordMetadata {
                        id: id.clone(),
                        category: entry.category.clone(),
                        created_at: entry.created_at,
                        commitment: entry.commitment,
                    })
                } else {
                    None
                }
            })
            .collect())
    }

    /// Build a Merkle tree of all records in a category for ZKP proofs.
    ///
    /// TODO(Phase 3): switch to Poseidon-BN254 (see vault/src/merkle.rs) so
    /// this root matches what circuits/lib/src/merkle_inclusion.nr verifies.
    pub async fn build_category_tree(&self, category: &str) -> Result<merkle::MerkleTree> {
        let store = self.encrypted_store.read().await;

        let leaves: Vec<[u8; 32]> = store
            .items
            .values()
            .filter(|entry| entry.category == category)
            .map(|entry| entry.commitment)
            .collect();

        Ok(merkle::MerkleTree::new(leaves))
    }

    /// Generate ZKP for proving possession of records matching criteria
    pub async fn generate_session_proof(&self, request: SessionRequest) -> Result<SessionProof> {
        // This would integrate with the Noir circuits via FFI or HTTP API
        // For now, return a placeholder structure
        
        let store = self.encrypted_store.read().await;
        
        // Collect matching records
        let mut matching_records: Vec<RecordMetadata> = vec![];
        for (id, entry) in store.items.iter() {
            if request.categories.contains(&entry.category) {
                // Check predicates (simplified - would use attribute_predicates.nr)
                if self.matches_predicate(entry, &request.predicates)? {
                    matching_records.push(RecordMetadata {
                        id: id.clone(),
                        category: entry.category.clone(),
                        created_at: entry.created_at,
                        commitment: entry.commitment,
                    });
                }
            }
        }

        Ok(SessionProof {
            session_id: uuid::Uuid::new_v4().to_string(),
            vault_root: self.commitments.read().await.get_root(),
            records_included: matching_records,
            policy_signature: request.policy_signature,
            nonce: request.nonce,
            expiry_time: request.expiry_time,
            purpose_hash: request.purpose_hash,
        })
    }

    fn matches_predicate(&self, entry: &VaultItemEntry, predicates: &[Predicate]) -> Result<bool> {
        // Simplified predicate matching - would integrate with ZK circuits
        for pred in predicates {
            match pred.field.as_str() {
                "age" => {
                    if let Some(age) = entry.metadata.get("age").and_then(|v| v.as_u64()).map(|n| n as u32) {
                        if !(pred.min_value.map_or(true, |min| age >= min)) 
                            || !(pred.max_value.map_or(true, |max| age <= max)) {
                            return Ok(false);
                        }
                    }
                }
                "blood_type" => {
                    // Would verify blood type matches required value
                }
                _ => continue,
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>, // Actual encrypted bytes (optional for metadata ops)
    pub category: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemEntry {
    encrypted_data: encryption::EncryptedData,
    pub category: String,
    pub created_at: i64,
    pub metadata: HashMap<String, serde_json::Value>,
    pub commitment: [u8; 32], // Poseidon commitment hash
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedStore {
    pub items: HashMap<String, VaultItemEntry>,
}

impl EncryptedStore {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub id: String,
    pub category: String,
    pub created_at: i64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub categories: Vec<String>,
    pub predicates: Vec<Predicate>,
    pub policy_signature: Signature,
    pub nonce: [u8; 32],
    pub expiry_time: u64,
    pub purpose_hash: Field, // From the ZKP field type
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    pub field: String,
    pub min_value: Option<u32>,
    pub max_value: Option<u32>,
    pub values: Vec<String>, // For set membership
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: [Field; 2],
    pub s: Field,
}

pub type Field = [u8; 32]; // Placeholder for ZKP field element

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProof {
    pub session_id: String,
    pub vault_root: [u8; 32],
    pub records_included: Vec<RecordMetadata>,
    pub policy_signature: Signature,
    pub nonce: [u8; 32],
    pub expiry_time: u64,
    pub purpose_hash: Field,
}

pub mod commitment {
    use super::Field;
    use sha2::Digest;
    use std::collections::HashMap;

    /// Poseidon hash commitment (simplified - would integrate with actual ZKP lib)
    pub fn poseidon_commit(inputs: &[Field]) -> [u8; 32] {
        // Placeholder - in production this would call the Noir/NoirJS Poseidon implementation
        let mut hasher = sha2::Sha256::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }

    #[derive(Debug)]
    pub struct CommitmentManager {
        records: HashMap<String, [u8; 32]>,
        categories: HashMap<String, Vec<[u8; 32]>>,
    }

    impl CommitmentManager {
        pub fn new() -> Self {
            Self {
                records: HashMap::new(),
                categories: HashMap::new(),
            }
        }

        pub fn add_record_commitment(&mut self, record_id: &str, commitment: &[u8; 32]) {
            self.records.insert(record_id.to_string(), *commitment);
            
            // Update category commitments (simplified)
            if let Some(cat_root) = self.categories.get_mut("default") {
                cat_root.push(*commitment);
            } else {
                self.categories.insert("default".to_string(), vec![*commitment]);
            }
        }

        pub fn get_root(&self) -> [u8; 32] {
            // Return Merkle root of all commitments
            if let Some(leaves) = self.categories.get("default") {
                let mut hasher = sha2::Sha256::new();
                for leaf in leaves {
                    hasher.update(leaf);
                }
                hasher.finalize().into()
            } else {
                [0u8; 32]
            }
        }

        pub fn get_record_commitment(&self, record_id: &str) -> Option<[u8; 32]> {
            self.records.get(record_id).copied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[tokio::test]
    async fn test_vault_store_and_retrieve() -> Result<()> {
        let vault = Vault::new();
        let key = encryption::generate_key();

        let item = VaultItem {
            id: "test-record-1".to_string(),
            data: Some(b"sensitive health data".to_vec()),
            category: "health".to_string(),
            metadata: HashMap::from([
                ("type".to_string(), serde_json::json!("lab_result")),
                ("created_at".to_string(), serde_json::json!(chrono::Utc::now().timestamp())),
            ]),
        };

        vault.store_record(item.clone(), &key).await?;

        let retrieved = vault.get_record("test-record-1", &key).await?;
        assert_eq!(retrieved.id, "test-record-1");
        assert_eq!(retrieved.data, item.data);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_record_fails_with_wrong_key() -> Result<()> {
        let vault = Vault::new();
        let key = encryption::generate_key();
        let wrong_key = encryption::generate_key();

        let item = VaultItem {
            id: "test-record-2".to_string(),
            data: Some(b"sensitive health data".to_vec()),
            category: "health".to_string(),
            metadata: HashMap::new(),
        };

        vault.store_record(item, &key).await?;
        assert!(vault.get_record("test-record-2", &wrong_key).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_commitment_manager() -> Result<()> {
        let mut cm = commitment::CommitmentManager::new();
        
        let commitment: [u8; 32] = sha2::Sha256::digest(b"test").into();
        cm.add_record_commitment("record-1", &commitment);
        
        assert!(cm.get_root().iter().any(|&b| b != 0));
        
        Ok(())
    }
}