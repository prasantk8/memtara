// Encryption module for Memtara Vault
// Implements authenticated encryption with key derivation

use anyhow::{anyhow, Result};
use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Encrypted data container
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12], // GCM nonce size
}

impl EncryptedData {
    /// Compute a hash of the encrypted data for commitments
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.ciphertext);
        hasher.update(&self.nonce);
        hasher.finalize().into()
    }
}

/// Derive encryption key from master key and context
pub fn derive_key(master_key: &[u8], context: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(master_key);
    hasher.update(context.as_bytes());
    
    Ok(hasher.finalize().into())
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(plaintext: &[u8]) -> Result<EncryptedData> {
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Use a placeholder key derivation (in production, use proper key management)
    let key_bytes = derive_key(b"memtara-vault-default-key", "encryption")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Clone plaintext for in-place encryption (GCM requires this)
    let mut buffer = plaintext.to_vec();
    
    cipher.encrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    Ok(EncryptedData {
        ciphertext: buffer,
        nonce: nonce_bytes,
    })
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(encrypted: &EncryptedData, _decryption_key: &[u8]) -> Result<Vec<u8>> {
    // In production, derive key from user's master key and context
    let key_bytes = derive_key(b"memtara-vault-default-key", "encryption")?;
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;
    
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    // Clone ciphertext for in-place decryption
    let mut buffer = encrypted.ciphertext.clone();
    
    cipher.decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;
    
    Ok(buffer)
}

/// Generate a new random key for the vault
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let plaintext = b"Sensitive health record data";
        
        let encrypted = encrypt(plaintext)?;
        assert_ne!(encrypted.ciphertext, plaintext);
        assert_eq!(encrypted.nonce.len(), 12);
        
        let decrypted = decrypt(&encrypted, &[])?;
        assert_eq!(decrypted, plaintext.as_slice());
        
        Ok(())
    }

    #[test]
    fn test_key_derivation() -> Result<()> {
        let key1 = derive_key(b"master-key", "context-1")?;
        let key2 = derive_key(b"master-key", "context-2")?;
        
        assert_ne!(key1, key2);
        
        Ok(())
    }

    #[test]
    fn test_hash() -> Result<()> {
        let data = EncryptedData {
            ciphertext: b"test".to_vec(),
            nonce: [0u8; 12],
        };
        
        let hash = data.hash();
        assert_eq!(hash.len(), 32);
        
        Ok(())
    }
}