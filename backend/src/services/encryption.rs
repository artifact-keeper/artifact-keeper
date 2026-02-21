//! Encryption utilities for storing sensitive credentials.
//!
//! Provides symmetric encryption for storing Artifactory credentials
//! and other sensitive migration data.

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

/// Simple XOR-based encryption with HMAC for integrity.
///
/// Note: For production use, consider using a proper encryption library
/// like `aes-gcm` or `chacha20poly1305`. This implementation is a
/// placeholder that provides basic protection.
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
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    /// Encrypt plaintext data.
    /// Returns: IV (16 bytes) || ciphertext || HMAC (32 bytes)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate random IV
        let iv: [u8; 16] = rand::random();

        // Derive encryption key from main key + IV
        let enc_key = self.derive_enc_key(&iv);

        // XOR encryption (simple stream cipher)
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, byte) in plaintext.iter().enumerate() {
            let key_byte = enc_key[i % enc_key.len()];
            ciphertext.push(byte ^ key_byte);
        }

        // Compute HMAC for integrity
        let hmac = self.compute_hmac(&iv, &ciphertext);

        // Combine: IV || ciphertext || HMAC
        let mut result = Vec::with_capacity(16 + ciphertext.len() + 32);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&hmac);

        result
    }

    /// Decrypt ciphertext data.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Minimum size: IV (16) + HMAC (32) = 48 bytes
        if data.len() < 48 {
            return Err(EncryptionError::CiphertextTooShort);
        }

        // Extract components
        let iv = &data[0..16];
        let ciphertext = &data[16..data.len() - 32];
        let stored_hmac = &data[data.len() - 32..];

        // Verify HMAC
        let computed_hmac = self.compute_hmac(iv, ciphertext);
        if !constant_time_compare(stored_hmac, &computed_hmac) {
            return Err(EncryptionError::DecryptionFailed);
        }

        // Derive decryption key
        let enc_key = self.derive_enc_key(iv);

        // XOR decryption
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (i, byte) in ciphertext.iter().enumerate() {
            let key_byte = enc_key[i % enc_key.len()];
            plaintext.push(byte ^ key_byte);
        }

        Ok(plaintext)
    }

    /// Derive encryption key from main key and IV using SHA-256.
    fn derive_enc_key(&self, iv: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        hasher.update(iv);
        hasher.update(b"encryption");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Compute HMAC over IV and ciphertext.
    fn compute_hmac(&self, iv: &[u8], ciphertext: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        hasher.update(iv);
        hasher.update(ciphertext);
        hasher.update(b"hmac");
        let result = hasher.finalize();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&result);
        hmac
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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

        // Due to random IV, encryptions should differ
        assert_ne!(enc1, enc2);

        // But both should decrypt to the same value
        assert_eq!(
            encryptor.decrypt(&enc1).unwrap(),
            encryptor.decrypt(&enc2).unwrap()
        );
    }
}
