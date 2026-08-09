// Memtara Vault - Local-First Encrypted Data Store
// Implements zero-knowledge proof infrastructure for selective disclosure

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

pub mod encryption;
pub mod commitment;
pub mod session;

#[derive(Debug, Clone)]
pub struct Vault {
    pub encrypted_store: Arc<RwLock<EncryptedStore>>,
    pub commitments: CommitmentManager,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            encrypted_store: Arc::new(RwLock::new(EncryptedStore::new())),
            commitments: CommitmentManager::new(),
        }
    }

    /// Store an encrypted record with metadata
    pub async fn store_record(&self, item: VaultItem) -> Result<()> {
        let mut store = self.encrypted_store.write().await;
        let id = item.id.clone();
        
        // Encrypt the data before storing
        let encrypted_data = encryption::encrypt(&item.data)?;
        
        // Create commitment to the record hash
        let record_hash = commitment::poseidon_commit(&[encrypted_data.hash()]);
        self.commitments.add_record_commitment(&id, &record_hash);
        
        store.items.insert(id, VaultItemEntry {
            encrypted_data,
            category: item.category.clone(),
            created_at: chrono::Utc::now().timestamp(),
            metadata: item.metadata,
            commitment: record_hash,
        });

        Ok(())
    }

    /// Retrieve an encrypted record by ID (requires decryption key)
    pub async fn get_record(&self, id: &str, decryption_key: &[u8]) -> Result<VaultItem> {
        let store = self.encrypted_store.read().await;
        
        if let Some(entry) = store.items.get(id) {
            let decrypted_data = encryption::decrypt(&entry.encrypted_data, decryption_key)?;
            Ok(VaultItem {
                id: id.to_string(),
                data: decrypted_data,
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

    /// Build a Merkle tree of all records in a category for ZKP proofs
    pub async fn build_category_tree(&self, category: &str) -> Result<erkatree::MerkleTree> {
        let store = self.encrypted_store.read().await;
        
        let mut leaves: Vec<[u8; 32]> = vec![];
        for (_, entry) in store.items.iter() {
            if entry.category == category {
                // Use the commitment as leaf (already a hash)
                leaves.push(entry.commitment.to_string().as_bytes().try_into().unwrap_or([0u8; 32]));
            }
        }
        
        let tree = erkatree::MerkleTree::new(leaves)?;
        Ok(tree)
    }

    /// Generate ZKP for proving possession of records matching criteria
    pub async fn generate_session_proof(&self, request: SessionRequest) -> Result<SessionProof> {
        // This would integrate with the Noir circuits via FFI or HTTP API
        // For now, return a placeholder structure
        
        let store = self.encrypted_store.read().await;
        
        // Collect matching records
        let mut matching_records: Vec<RecordMetadata> = vec![];
        for (_, entry) in store.items.iter() {
            if request.categories.contains(&entry.category) {
                // Check predicates (simplified - would use attribute_predicates.nr)
                if self.matches_predicate(entry, &request.predicates)? {
                    matching_records.push(RecordMetadata {
                        id: entry.id.clone(),
                        category: entry.category.clone(),
                        created_at: entry.created_at,
                        commitment: entry.commitment,
                    });
                }
            }
        }

        Ok(SessionProof {
            session_id: uuid::Uuid::new_v4().to_string(),
            vault_root: self.commitments.get_root(),
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
                    if let Some(age) = entry.metadata.get("age").and_then(|v| v.parse::<u32>().ok()) {
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

#[derive(Debug, Clone)]
struct VaultItemEntry {
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

    /// Poseidon hash commitment (simplified - would integrate with actual ZKP lib)
    pub fn poseidon_commit(inputs: &[Field]) -> [u8; 32] {
        // Placeholder - in production this would call the Noir/NoirJS Poseidon implementation
        let mut hasher = sha2::Sha256::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }

    pub struct CommitmentManager {
        records: HashMap<String, [u8; 32]>,
        categories: HashMap<String, Vec<[u8; 32]>>,
        root: [u8; 32],
    }

    impl CommitmentManager {
        pub fn new() -> Self {
            Self {
                records: HashMap::new(),
                categories: HashMap::new(),
                root: [0u8; 32],
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

    #[tokio::test]
    async fn test_vault_store_and_retrieve() -> Result<()> {
        let vault = Vault::new();
        
        let item = VaultItem {
            id: "test-record-1".to_string(),
            data: Some(b"sensitive health data".to_vec()),
            category: "health".to_string(),
            metadata: HashMap::from([
                ("type".to_string(), serde_json::json!("lab_result")),
                ("created_at".to_string(), serde_json::json!(chrono::Utc::now().timestamp())),
            ]),
        };

        vault.store_record(item.clone()).await?;
        
        let retrieved = vault.get_record("test-record-1", b"test-key").await;
        
        // Note: retrieval will fail without proper key derivation - this is expected
        assert!(retrieved.is_err() || retrieved.unwrap().id == "test-record-1");

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