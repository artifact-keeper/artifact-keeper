//! Encryption utilities for storing sensitive credentials.
//!
//! Provides AES-256-GCM authenticated encryption for storing Artifactory
//! credentials and other sensitive migration data.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during encryption operations
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid ciphertext: too short")]
    CiphertextTooShort,

    #[error("Decryption failed: invalid padding or corrupted data")]
    DecryptionFailed,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}

/// AES-256-GCM authenticated encryption for credentials.
///
/// Ciphertext format: nonce (12 bytes) || AES-GCM ciphertext+tag
pub struct CredentialEncryption {
    key: [u8; 32],
}

impl CredentialEncryption {
    /// Create a new encryption instance with the given key.
    /// Key must be exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength(key.len()));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Ok(Self { key: key_array })
    }

    /// Create from a passphrase by hashing it to derive a key.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();
        Self { key }
    }

    /// Encrypt plaintext data using AES-256-GCM.
    /// Returns: nonce (12 bytes) || ciphertext+tag
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .expect("AES-256-GCM key length is always 32 bytes");

        // Generate random 96-bit nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-256-GCM encryption should not fail with valid key and nonce");

        // Combine: nonce || ciphertext+tag
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt ciphertext data using AES-256-GCM.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Minimum size: nonce (12) + tag (16) = 28 bytes
        if data.len() < 28 {
            return Err(EncryptionError::CiphertextTooShort);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }
}

/// Encrypt credentials JSON for storage.
pub fn encrypt_credentials(credentials_json: &str, encryption_key: &str) -> Vec<u8> {
    let encryptor = CredentialEncryption::from_passphrase(encryption_key);
    encryptor.encrypt(credentials_json.as_bytes())
}

/// Decrypt credentials from storage.
pub fn decrypt_credentials(
    encrypted: &[u8],
    encryption_key: &str,
) -> Result<String, EncryptionError> {
    let encryptor = CredentialEncryption::from_passphrase(encryption_key);
    let plaintext = encryptor.decrypt(encrypted)?;
    String::from_utf8(plaintext).map_err(|_| EncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = CredentialEncryption::from_passphrase("test-passphrase");
        let plaintext = b"secret credentials here";

        let encrypted = encryptor.encrypt(plaintext);
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        let credentials = r#"{"token": "abc123", "username": "admin"}"#;
        let key = "my-secret-key";

        let encrypted = encrypt_credentials(credentials, key);
        let decrypted = decrypt_credentials(&encrypted, key).unwrap();

        assert_eq!(credentials, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let encryptor1 = CredentialEncryption::from_passphrase("key1");
        let encryptor2 = CredentialEncryption::from_passphrase("key2");

        let encrypted = encryptor1.encrypt(b"secret");
        let result = encryptor2.decrypt(&encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let encryptor = CredentialEncryption::from_passphrase("key");
        let mut encrypted = encryptor.encrypt(b"secret");

        // Tamper with the ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0xFF;
        }

        let result = encryptor.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short_data_fails() {
        let encryptor = CredentialEncryption::from_passphrase("key");
        let result = encryptor.decrypt(&[0u8; 10]);
        assert!(matches!(result, Err(EncryptionError::CiphertextTooShort)));
    }

    #[test]
    fn test_different_encryptions_differ() {
        let encryptor = CredentialEncryption::from_passphrase("key");
        let plaintext = b"same data";

        let enc1 = encryptor.encrypt(plaintext);
        let enc2 = encryptor.encrypt(plaintext);

        // Due to random nonce, encryptions should differ
        assert_ne!(enc1, enc2);

        // But both should decrypt to the same value
        assert_eq!(
            encryptor.decrypt(&enc1).unwrap(),
            encryptor.decrypt(&enc2).unwrap()
        );
    }

    #[test]
    fn test_empty_plaintext() {
        let encryptor = CredentialEncryption::from_passphrase("key");
        let encrypted = encryptor.encrypt(b"");
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let encryptor = CredentialEncryption::from_passphrase("key");
        let plaintext = vec![0xAB_u8; 1_000_000];
        let encrypted = encryptor.encrypt(&plaintext);
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = CredentialEncryption::new(&[0u8; 16]);
        assert!(matches!(result, Err(EncryptionError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_valid_key_length() {
        let result = CredentialEncryption::new(&[0u8; 32]);
        assert!(result.is_ok());
    }
}
