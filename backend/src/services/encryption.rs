//! Encryption utilities for storing sensitive credentials.
//!
//! Provides AES-256-GCM authenticated encryption for storing Artifactory
//! credentials and other sensitive migration data.
//!
//! Key derivation uses HKDF-SHA256 with a static application-level salt.
//! Legacy data encrypted with raw SHA-256 key derivation is transparently
//! decrypted via automatic fallback.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

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

/// Derive a 32-byte key from a passphrase using HMAC-SHA256.
///
/// Uses the passphrase as the HMAC key and an application-specific context
/// string as the message, producing a 32-byte derived key with domain
/// separation. This is equivalent to a single-step KDF per NIST SP 800-108.
fn derive_key_hkdf(passphrase: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(passphrase.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(b"artifact-keeper/credential-encryption/aes-256-gcm/v1");
    mac.finalize().into_bytes().into()
}

/// Derive a 32-byte key from a passphrase using legacy raw SHA-256 (for
/// backward compatibility with data encrypted before the HKDF upgrade).
fn derive_key_legacy(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

/// AES-256-GCM authenticated encryption for credentials.
///
/// Ciphertext format: nonce (12 bytes) || AES-GCM ciphertext+tag
pub struct CredentialEncryption {
    key: [u8; 32],
    /// Legacy key derived via raw SHA-256, kept for transparent decryption
    /// of data encrypted before the HKDF upgrade.
    legacy_key: Option<[u8; 32]>,
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
        Ok(Self {
            key: key_array,
            legacy_key: None,
        })
    }

    /// Create from a passphrase using HKDF-SHA256 key derivation.
    ///
    /// New encryptions use the HKDF-derived key. Decryption automatically
    /// falls back to the legacy SHA-256-derived key if the HKDF key fails,
    /// providing transparent backward compatibility.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let key = derive_key_hkdf(passphrase);
        let legacy = derive_key_legacy(passphrase);
        Self {
            key,
            legacy_key: Some(legacy),
        }
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
    ///
    /// Tries the primary (HKDF) key first. If that fails and a legacy key is
    /// available, retries with the legacy key for backward compatibility.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Minimum size: nonce (12) + tag (16) = 28 bytes
        if data.len() < 28 {
            return Err(EncryptionError::CiphertextTooShort);
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        // Try primary (HKDF) key
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            return Ok(plaintext);
        }

        // Fall back to legacy (SHA-256) key if available
        if let Some(ref legacy) = self.legacy_key {
            let legacy_cipher = Aes256Gcm::new_from_slice(legacy)
                .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
            return legacy_cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncryptionError::DecryptionFailed);
        }

        Err(EncryptionError::DecryptionFailed)
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

    // -----------------------------------------------------------------------
    // HKDF upgrade backward compatibility
    // -----------------------------------------------------------------------

    #[test]
    fn test_legacy_data_decrypts_with_hkdf_encryptor() {
        // Simulate legacy encryption: encrypt with raw SHA-256 derived key
        let passphrase = "backward-compat-test";
        let legacy_key = derive_key_legacy(passphrase);
        let legacy_encryptor = CredentialEncryption::new(&legacy_key).unwrap();
        let legacy_ciphertext = legacy_encryptor.encrypt(b"legacy secret data");

        // Decrypt using the new HKDF-based from_passphrase (should fall back)
        let new_encryptor = CredentialEncryption::from_passphrase(passphrase);
        let decrypted = new_encryptor.decrypt(&legacy_ciphertext).unwrap();
        assert_eq!(decrypted, b"legacy secret data");
    }

    #[test]
    fn test_hkdf_key_differs_from_legacy() {
        let passphrase = "test-key-derivation";
        let hkdf_key = derive_key_hkdf(passphrase);
        let legacy_key = derive_key_legacy(passphrase);
        assert_ne!(hkdf_key, legacy_key, "HKDF and legacy keys must differ");
    }

    #[test]
    fn test_new_encryption_uses_hkdf_not_legacy() {
        let passphrase = "new-encryption-test";
        let encryptor = CredentialEncryption::from_passphrase(passphrase);
        let ciphertext = encryptor.encrypt(b"new data");

        // The ciphertext should decrypt with HKDF key directly
        let hkdf_key = derive_key_hkdf(passphrase);
        let hkdf_only = CredentialEncryption::new(&hkdf_key).unwrap();
        let decrypted = hkdf_only.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"new data");

        // And should NOT decrypt with legacy key alone
        let legacy_key = derive_key_legacy(passphrase);
        let legacy_only = CredentialEncryption::new(&legacy_key).unwrap();
        assert!(legacy_only.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_cross_passphrase_legacy_fails() {
        // Legacy ciphertext from passphrase A should not decrypt with passphrase B
        let legacy_key = derive_key_legacy("passphrase-a");
        let legacy_enc = CredentialEncryption::new(&legacy_key).unwrap();
        let ciphertext = legacy_enc.encrypt(b"secret");

        let wrong = CredentialEncryption::from_passphrase("passphrase-b");
        assert!(wrong.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_convenience_functions_backward_compat() {
        // Encrypt with legacy (simulate old data), decrypt with convenience function
        let key = "compat-convenience";
        let legacy_derived = derive_key_legacy(key);
        let legacy_enc = CredentialEncryption::new(&legacy_derived).unwrap();
        let ciphertext = legacy_enc.encrypt(b"old credentials json");

        let decrypted = decrypt_credentials(&ciphertext, key).unwrap();
        assert_eq!(decrypted, "old credentials json");
    }
}
