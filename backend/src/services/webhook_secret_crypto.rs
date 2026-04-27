//! Webhook secret encryption helpers.
//!
//! Stores webhook signing secrets at rest using AES-256-GCM. The raw secret
//! is shown to the operator exactly once at creation or rotation time;
//! afterwards only the ciphertext (and a short non-reversible digest, used
//! for UI identification) is persisted.
//!
//! The 32-byte symmetric key is sourced from the `AK_WEBHOOK_SECRET_KEY`
//! environment variable, base64 encoded. The encryption format is
//! nonce-prefixed AES-256-GCM, identical to the layout used by
//! [`crate::services::encryption::CredentialEncryption`]. Existing secrets
//! that pre-date this module are stored as bcrypt hashes; those are
//! unrecoverable and must be rotated by the operator before the backend
//! can sign deliveries against them.
//!
//! This module is deliberately scoped to webhook secrets so that the key
//! can be rotated independently from the SSO credential key.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use thiserror::Error;

use crate::services::encryption::{CredentialEncryption, EncryptionError};

/// Environment variable that holds the base64-encoded 32-byte AES key.
pub const ENV_KEY: &str = "AK_WEBHOOK_SECRET_KEY";

/// Length, in bytes, of a freshly generated webhook secret (before the
/// `whsec_` prefix is added). Chosen to give 192 bits of entropy after
/// URL-safe base64 encoding without padding.
const RAW_SECRET_BYTES: usize = 24;

/// Prefix advertised to operators so that webhook secrets are visually
/// distinct from API tokens and other credentials.
pub const SECRET_PREFIX: &str = "whsec_";

/// Errors raised by the webhook secret crypto helpers.
#[derive(Debug, Error)]
pub enum WebhookSecretError {
    #[error("AK_WEBHOOK_SECRET_KEY is not configured")]
    KeyMissing,

    #[error("AK_WEBHOOK_SECRET_KEY is not valid base64: {0}")]
    KeyNotBase64(String),

    #[error("AK_WEBHOOK_SECRET_KEY must decode to exactly 32 bytes, got {0}")]
    KeyWrongLength(usize),

    #[error("webhook secret encryption failed: {0}")]
    Crypto(#[from] EncryptionError),

    #[error("decrypted webhook secret is not valid UTF-8")]
    NotUtf8,
}

/// Result type for webhook crypto operations.
pub type Result<T> = std::result::Result<T, WebhookSecretError>;

/// Load the 32-byte key from the environment, decoding base64.
fn load_key() -> Result<[u8; 32]> {
    let raw = std::env::var(ENV_KEY).map_err(|_| WebhookSecretError::KeyMissing)?;
    let trimmed = raw.trim();
    let bytes = B64
        .decode(trimmed)
        .map_err(|e| WebhookSecretError::KeyNotBase64(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(WebhookSecretError::KeyWrongLength(bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encryptor() -> Result<CredentialEncryption> {
    let key = load_key()?;
    Ok(CredentialEncryption::new(&key)?)
}

/// Generate a fresh webhook secret string of the form `whsec_<base64url>`.
///
/// Uses the OS CSPRNG. The unprefixed body has at least 192 bits of entropy.
pub fn generate_secret() -> String {
    let mut buf = [0u8; RAW_SECRET_BYTES];
    rand::rng().fill_bytes(&mut buf);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    format!("{}{}", SECRET_PREFIX, body)
}

/// Encrypt a secret for at-rest storage.
///
/// Returns nonce-prefixed AES-256-GCM ciphertext. Callers should persist
/// this directly into the `secret_encrypted` `bytea` column.
pub fn encrypt_secret(plaintext: &str) -> Result<Vec<u8>> {
    let enc = encryptor()?;
    Ok(enc.encrypt(plaintext.as_bytes()))
}

/// Decrypt a previously stored webhook secret.
pub fn decrypt_secret(ciphertext: &[u8]) -> Result<String> {
    let enc = encryptor()?;
    let plaintext = enc.decrypt(ciphertext)?;
    String::from_utf8(plaintext).map_err(|_| WebhookSecretError::NotUtf8)
}

/// Compute a stable, non-reversible identifier suitable for surfacing in
/// list/get responses so operators can distinguish secrets without exposing
/// them. Format: `<prefix>...<last4>` where the prefix is the literal
/// `whsec_` (or whatever prefix the secret already carries) and the last
/// four characters of the secret body are the only material revealed.
///
/// For secrets shorter than 8 characters the digest is the full secret;
/// such inputs only occur in tests.
pub fn digest_for_display(secret: &str) -> String {
    if secret.len() < 8 {
        return secret.to_string();
    }
    let last4 = &secret[secret.len() - 4..];
    if let Some(rest) = secret.strip_prefix(SECRET_PREFIX) {
        if rest.len() <= 4 {
            return secret.to_string();
        }
        return format!("{}...{}", SECRET_PREFIX, last4);
    }
    let head: String = secret.chars().take(4).collect();
    format!("{}...{}", head, last4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes env mutation across the tests in this module so that
    /// they do not race each other (Rust runs unit tests on a thread pool
    /// by default and `std::env::set_var` is process-global).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_test_key() {
        // 32 bytes of zeros, base64-encoded.
        let key = B64.encode([0u8; 32]);
        // SAFETY: ENV_LOCK serializes env access for tests in this module.
        unsafe {
            std::env::set_var(ENV_KEY, key);
        }
    }

    fn set_alt_key() {
        let mut k = [0u8; 32];
        k[0] = 1;
        let encoded = B64.encode(k);
        unsafe {
            std::env::set_var(ENV_KEY, encoded);
        }
    }

    #[test]
    fn test_generate_secret_has_prefix_and_entropy() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert!(s1.starts_with(SECRET_PREFIX));
        assert!(s2.starts_with(SECRET_PREFIX));
        assert_ne!(s1, s2);
        // base64url of 24 bytes (no padding) is 32 chars.
        assert_eq!(s1.len(), SECRET_PREFIX.len() + 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap();
        set_test_key();
        let plaintext = "whsec_super_secret_value";
        let ct = encrypt_secret(plaintext).expect("encrypt");
        let pt = decrypt_secret(&ct).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let _g = ENV_LOCK.lock().unwrap();
        set_test_key();
        let plaintext = "same plaintext";
        let a = encrypt_secret(plaintext).expect("encrypt a");
        let b = encrypt_secret(plaintext).expect("encrypt b");
        assert_ne!(a, b, "ciphertexts must differ due to random nonce");
        // First 12 bytes are the nonce; they should differ.
        assert_ne!(&a[..12], &b[..12]);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        // Encrypt with key A.
        set_test_key();
        let ct = encrypt_secret("whsec_value").expect("encrypt");
        // Switch to key B and try to decrypt.
        set_alt_key();
        let res = decrypt_secret(&ct);
        assert!(matches!(res, Err(WebhookSecretError::Crypto(_))));
    }

    #[test]
    fn test_bad_ciphertext_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        set_test_key();
        let mut ct = encrypt_secret("whsec_value").expect("encrypt");
        // Flip a byte in the AEAD tag region.
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let res = decrypt_secret(&ct);
        assert!(matches!(res, Err(WebhookSecretError::Crypto(_))));
    }

    #[test]
    fn test_truncated_ciphertext_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        set_test_key();
        let res = decrypt_secret(&[0u8; 8]);
        assert!(matches!(res, Err(WebhookSecretError::Crypto(_))));
    }

    #[test]
    fn test_missing_key_yields_key_missing() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var(ENV_KEY);
        }
        let res = encrypt_secret("x");
        assert!(matches!(res, Err(WebhookSecretError::KeyMissing)));
    }

    #[test]
    fn test_invalid_base64_key() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_KEY, "@@@not-base64@@@");
        }
        let res = encrypt_secret("x");
        assert!(matches!(res, Err(WebhookSecretError::KeyNotBase64(_))));
    }

    #[test]
    fn test_wrong_length_key() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_KEY, B64.encode([0u8; 16]));
        }
        let res = encrypt_secret("x");
        assert!(matches!(res, Err(WebhookSecretError::KeyWrongLength(16))));
    }

    #[test]
    fn test_digest_format() {
        let secret = "whsec_abcdef0123456789";
        let digest = digest_for_display(secret);
        assert_eq!(digest, "whsec_...6789");
    }

    #[test]
    fn test_digest_short_secret_returns_self() {
        assert_eq!(digest_for_display("abc"), "abc");
    }

    #[test]
    fn test_digest_non_prefixed_secret() {
        let digest = digest_for_display("hello-world-1234");
        assert_eq!(digest, "hell...1234");
    }
}
