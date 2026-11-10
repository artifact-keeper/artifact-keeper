//! At-rest encryption for stored secrets (SSO client secrets, LDAP bind
//! passwords, upstream and migration credentials, signing private keys,
//! TOTP seeds), on the validated module through `crate::crypto` (#5583).
//!
//! Two key sources, two ciphertext formats, every build reads both:
//!
//! * **Legacy / default.** The key is derived from a passphrase (the
//!   deployment's `JWT_SECRET`) with HMAC-SHA256 over a fixed context, with a
//!   raw-SHA-256 fallback for rows written before that. Ciphertext is
//!   `nonce (12) || AES-256-GCM ciphertext+tag`. This is what every mode but
//!   `strict` keeps writing, so an upgrade followed by a downgrade never
//!   produces a row the older binary cannot read.
//! * **Dedicated data key (v2).** When `DATA_ENCRYPTION_KEY` is configured
//!   and `FIPS_MODE=strict`, new rows are written as
//!   `0x02 || nonce (12) || ciphertext+tag` under a per-purpose subkey
//!   derived from the data key with SP 800-108 KBKDF, so the token-signing
//!   secret and the at-rest key are no longer the same material.
//!
//! Decryption tries v2 first when the first byte says so (a legacy nonce
//! starting with `0x02` simply fails the tag check and falls through), then
//! the passphrase key, then the raw-SHA-256 key. The `reencrypt-secrets`
//! command rewrites legacy rows as v2 once an operator opts in; it is never
//! automatic.

use std::sync::OnceLock;

use thiserror::Error;

use crate::crypto::{aead, digest, hmac, kdf};

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

/// Version byte that opens a ciphertext written under the dedicated data key.
pub const DATA_KEY_CIPHERTEXT_VERSION: u8 = 0x02;

/// KBKDF label of the subkey used for credential ciphertexts.
pub const PURPOSE_CREDENTIALS: &[u8] = b"credential-aead";
/// KBKDF label of the subkey used for TOTP seeds.
pub const PURPOSE_TOTP_SEED: &[u8] = b"totp-seed";

/// Derive a 32-byte key from a passphrase using HMAC-SHA256.
///
/// Uses the passphrase as the HMAC key and an application-specific context
/// string as the message, producing a 32-byte derived key with domain
/// separation. This is equivalent to a single-step KDF per NIST SP 800-108.
fn derive_key_hkdf(passphrase: &str) -> [u8; 32] {
    hmac::sha256(
        passphrase.as_bytes(),
        b"artifact-keeper/credential-encryption/aes-256-gcm/v1",
    )
}

/// Derive a 32-byte key from a passphrase using legacy raw SHA-256 (for
/// backward compatibility with data encrypted before the HKDF upgrade).
fn derive_key_legacy(passphrase: &str) -> [u8; 32] {
    digest::sha256(passphrase.as_bytes())
}

static DATA_KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Decode `DATA_ENCRYPTION_KEY` material: 32 raw bytes as base64 (standard
/// or URL-safe, padding optional) or 64 hex characters.
pub fn parse_data_key(raw: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let trimmed = raw.trim();
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed).map_err(|e| e.to_string())?
    } else {
        let unpadded = trimmed.trim_end_matches('=');
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(unpadded)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(unpadded))
            .map_err(|_| {
                "DATA_ENCRYPTION_KEY is neither base64 nor 64 hex characters".to_string()
            })?
    };
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "DATA_ENCRYPTION_KEY must decode to 32 bytes, got {}",
            bytes.len()
        )
    })
}

/// Publish the dedicated data key for this process (`None` when the operator
/// has not configured one). Called once at startup; later calls are ignored.
pub fn install_data_key(key: Option<[u8; 32]>) {
    let _ = DATA_KEY.set(key);
}

/// Whether a dedicated data key is configured.
pub fn data_key_configured() -> bool {
    DATA_KEY.get().is_some_and(|k| k.is_some())
}

/// The per-purpose 32-byte subkey under the data key, if one is configured.
pub fn data_subkey_raw(purpose: &[u8]) -> Option<Vec<u8>> {
    let dk = (*DATA_KEY.get()?)?;
    Some(kdf::kbkdf_sha256(&dk, purpose, b"", aead::KEY_LEN))
}

/// The per-purpose AEAD subkey under the data key, if one is configured.
pub fn data_subkey(purpose: &[u8]) -> Option<aead::Key> {
    let sub = data_subkey_raw(purpose)?;
    Some(aead::Key::new(&sub).expect("KBKDF output is 32 bytes"))
}

/// KBKDF label of the API-token HMAC subkey.
pub const PURPOSE_TOKEN_HMAC: &[u8] = b"token-hmac";

/// The key API tokens are stored under in strict mode (#5582): the
/// `token-hmac` subkey of the data key when one is configured, otherwise
/// derived from `jwt_secret`. Rotating the source secret invalidates every
/// keyed token row (docs/fips.md, "Key hierarchy").
pub fn token_key_for(jwt_secret: &str) -> crate::crypto::token::TokenKey {
    match data_subkey_raw(PURPOSE_TOKEN_HMAC) {
        Some(sub) => crate::crypto::token::TokenKey::from_subkey(&sub),
        None => crate::crypto::token::TokenKey::derive(jwt_secret.as_bytes()),
    }
}

/// Whether any row that needs the data key exists while no data key is
/// configured: TOTP seeds written as `enc:` under strict mode. Logged at
/// startup in every mode so a downgrade that dropped `DATA_ENCRYPTION_KEY`
/// is visible before the first 2FA login fails.
pub async fn warn_if_data_key_rows_unreadable(db: &sqlx::PgPool) {
    if data_key_configured() {
        return;
    }
    match sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE totp_secret LIKE 'enc:%'")
        .fetch_one(db)
        .await
    {
        Ok(n) if n > 0 => tracing::warn!(
            users = n,
            "{n} user(s) have TOTP seeds encrypted under DATA_ENCRYPTION_KEY but no key is \
             configured; their TOTP logins will fail until the key is restored"
        ),
        Ok(_) => {}
        Err(e) => tracing::debug!(error = %e, "could not check for data-key-dependent rows"),
    }
}

/// Whether v2 rows should be written: data key present and strict mode.
fn write_v2() -> bool {
    crate::fips::strict() && data_key_configured()
}

/// Whether `data` is a legacy (passphrase-keyed) ciphertext that
/// `reencrypt-secrets` should rewrite. A v2 ciphertext is recognised by its
/// version byte *and* by opening under the data key, so a legacy row whose
/// random nonce happens to start with `0x02` is still reported as legacy.
pub fn is_legacy_ciphertext(data: &[u8]) -> bool {
    if data.first() != Some(&DATA_KEY_CIPHERTEXT_VERSION) {
        return true;
    }
    match data_subkey(PURPOSE_CREDENTIALS) {
        Some(k) => k.open(&data[1..], b"").is_err(),
        None => true,
    }
}

/// AES-256-GCM authenticated encryption for credentials.
///
/// Ciphertext format: nonce (12 bytes) || AES-GCM ciphertext+tag, or the v2
/// form described in the module docs when a dedicated data key is in use.
pub struct CredentialEncryption {
    key: aead::Key,
    /// Legacy key derived via raw SHA-256, kept for transparent decryption
    /// of data encrypted before the HKDF upgrade.
    legacy_key: Option<aead::Key>,
    /// Whether this instance takes part in the data-key hierarchy (only
    /// passphrase-derived instances do; `new(key)` callers bring their own
    /// dedicated key already).
    data_key_eligible: bool,
}

impl CredentialEncryption {
    /// Create a new encryption instance with the given key.
    /// Key must be exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        let key = aead::Key::new(key).map_err(|e| match e {
            aead::Error::KeyLength(n) => EncryptionError::InvalidKeyLength(n),
            other => EncryptionError::EncryptionFailed(other.to_string()),
        })?;
        Ok(Self {
            key,
            legacy_key: None,
            data_key_eligible: false,
        })
    }

    /// Create from a passphrase using HKDF-SHA256 key derivation.
    ///
    /// New encryptions use the HKDF-derived key (or the dedicated data key
    /// in strict mode). Decryption automatically falls back to the legacy
    /// SHA-256-derived key if the HKDF key fails, providing transparent
    /// backward compatibility.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let key = aead::Key::new(&derive_key_hkdf(passphrase)).expect("32-byte derived key");
        let legacy = aead::Key::new(&derive_key_legacy(passphrase)).expect("32-byte derived key");
        Self {
            key,
            legacy_key: Some(legacy),
            data_key_eligible: true,
        }
    }

    /// Encrypt plaintext data using AES-256-GCM.
    /// Returns: nonce (12 bytes) || ciphertext+tag, or the v2 form.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        if self.data_key_eligible && write_v2() {
            if let Some(k) = data_subkey(PURPOSE_CREDENTIALS) {
                let mut out =
                    Vec::with_capacity(1 + aead::NONCE_LEN + plaintext.len() + aead::TAG_LEN);
                out.push(DATA_KEY_CIPHERTEXT_VERSION);
                out.extend_from_slice(&k.seal(plaintext, b""));
                return out;
            }
        }
        self.key.seal(plaintext, b"")
    }

    /// Decrypt ciphertext data using AES-256-GCM.
    ///
    /// Tries the data key (v2) when the version byte matches, then the
    /// primary (HKDF) key, then the legacy key for backward compatibility.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < aead::NONCE_LEN + aead::TAG_LEN {
            return Err(EncryptionError::CiphertextTooShort);
        }
        if self.data_key_eligible && data[0] == DATA_KEY_CIPHERTEXT_VERSION {
            if let Some(k) = data_subkey(PURPOSE_CREDENTIALS) {
                if let Ok(plain) = k.open(&data[1..], b"") {
                    return Ok(plain);
                }
            }
        }
        if let Ok(plaintext) = self.key.open(data, b"") {
            return Ok(plaintext);
        }
        if let Some(legacy) = &self.legacy_key {
            return legacy
                .open(data, b"")
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

/// Outcome of [`reencrypt_legacy_rows`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReencryptReport {
    /// Rows rewritten under the data key.
    pub rewritten: usize,
    /// Rows already in v2 form (idempotent re-runs).
    pub already_current: usize,
    /// Rows that could not be decrypted with the passphrase key (left as is).
    pub failed: usize,
}

impl std::fmt::Display for ReencryptReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "reencrypt-secrets: {} rewritten, {} already current, {} failed",
            self.rewritten, self.already_current, self.failed
        )
    }
}

/// How a column stores its ciphertext.
#[derive(Clone, Copy)]
enum ColumnEncoding {
    Bytea,
    HexText,
}

/// Which passphrase a column's legacy ciphertext was written under.
#[derive(Clone, Copy)]
enum LegacyKey {
    /// `SSO_ENCRYPTION_KEY`, falling back to `JWT_SECRET`
    /// (`auth_config_service::encryption_key`).
    Sso,
    /// `JWT_SECRET` directly (`SigningService::new`).
    Jwt,
    /// `MIGRATION_ENCRYPTION_KEY`, falling back to the built-in dev key
    /// (`handlers::migration::migration_encryption_key`).
    Migration,
}

/// The passphrases the legacy columns were written under, resolved by the
/// caller from the same sources the writers use.
pub struct ReencryptKeys {
    pub sso: String,
    pub jwt: String,
    pub migration: String,
}

/// Every passphrase-encrypted column in the schema. Webhook secrets are not
/// here: they have their own dedicated key (`WEBHOOK_SECRET_KEY`).
const ENCRYPTED_COLUMNS: &[(&str, &str, &str, ColumnEncoding, LegacyKey)] = &[
    (
        "oidc_configs",
        "id",
        "client_secret_encrypted",
        ColumnEncoding::HexText,
        LegacyKey::Sso,
    ),
    (
        "ldap_configs",
        "id",
        "bind_password_encrypted",
        ColumnEncoding::HexText,
        LegacyKey::Sso,
    ),
    (
        "remote_instances",
        "id",
        "api_key_encrypted",
        ColumnEncoding::HexText,
        LegacyKey::Sso,
    ),
    (
        "signing_keys",
        "id",
        "private_key_enc",
        ColumnEncoding::Bytea,
        LegacyKey::Jwt,
    ),
    (
        "source_connections",
        "id",
        "credentials_enc",
        ColumnEncoding::Bytea,
        LegacyKey::Migration,
    ),
];

/// Rewrite every legacy ciphertext under the dedicated data key (#5583).
///
/// Idempotent and resumable: rows already in v2 form are counted and left
/// alone, each row is its own statement, and a row that fails to decrypt is
/// logged (table, id, never contents) and skipped so one bad row cannot
/// stop the rest. Requires [`install_data_key`] to have run with a key and
/// is only meaningful when strict mode is going to be enabled; it does not
/// consult `FIPS_MODE` itself so an operator can prepare in advance.
pub async fn reencrypt_legacy_rows(
    db: &sqlx::PgPool,
    keys: &ReencryptKeys,
) -> crate::error::Result<ReencryptReport> {
    use crate::error::AppError;

    let Some(k) = data_subkey(PURPOSE_CREDENTIALS) else {
        return Err(AppError::Config(
            "reencrypt-secrets: no DATA_ENCRYPTION_KEY installed".into(),
        ));
    };
    let sso = CredentialEncryption::from_passphrase(&keys.sso);
    let jwt = CredentialEncryption::from_passphrase(&keys.jwt);
    let migration = CredentialEncryption::from_passphrase(&keys.migration);
    let mut report = ReencryptReport::default();

    for (table, id_col, col, enc, key) in ENCRYPTED_COLUMNS {
        let legacy = match key {
            LegacyKey::Sso => &sso,
            LegacyKey::Jwt => &jwt,
            LegacyKey::Migration => &migration,
        };
        // Table and column names come from the constant list above, never
        // from input, hence the explicit opt-in.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {id_col}::text AS id, {col} AS value FROM {table} WHERE {col} IS NOT NULL"
        )))
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(format!("{table}.{col}: {e}")))?;

        for row in rows {
            use sqlx::Row;
            let id: String = row.get("id");
            let bytes: Vec<u8> = match enc {
                ColumnEncoding::Bytea => row.get("value"),
                ColumnEncoding::HexText => {
                    let hex_text: String = row.get("value");
                    match hex::decode(hex_text.trim()) {
                        Ok(b) => b,
                        Err(_) => {
                            tracing::warn!(table, id, "ciphertext column is not hex; skipped");
                            report.failed += 1;
                            continue;
                        }
                    }
                }
            };
            if !is_legacy_ciphertext(&bytes) {
                report.already_current += 1;
                continue;
            }
            let plain = match legacy.decrypt(&bytes) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        table,
                        id,
                        "could not decrypt with the passphrase key; skipped"
                    );
                    report.failed += 1;
                    continue;
                }
            };
            let mut v2 = Vec::with_capacity(1 + aead::NONCE_LEN + plain.len() + aead::TAG_LEN);
            v2.push(DATA_KEY_CIPHERTEXT_VERSION);
            v2.extend_from_slice(&k.seal(&plain, b""));

            let sql = || {
                sqlx::AssertSqlSafe(format!(
                    "UPDATE {table} SET {col} = $2 WHERE {id_col}::text = $1"
                ))
            };
            let result = match enc {
                ColumnEncoding::Bytea => sqlx::query(sql()).bind(&id).bind(v2).execute(db).await,
                ColumnEncoding::HexText => {
                    sqlx::query(sql())
                        .bind(&id)
                        .bind(hex::encode(v2))
                        .execute(db)
                        .await
                }
            };
            match result {
                Ok(_) => report.rewritten += 1,
                Err(e) => {
                    tracing::warn!(table, id, error = %e, "update failed; skipped");
                    report.failed += 1;
                }
            }
        }
    }

    // `upstream_auth_credentials` lives in a key/value table, under the SSO key.
    let legacy = &sso;
    let rows = sqlx::query(
        "SELECT repository_id::text AS id, value FROM repository_config \
         WHERE key = 'upstream_auth_credentials' AND value IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(format!("repository_config: {e}")))?;
    for row in rows {
        use sqlx::Row;
        let id: String = row.get("id");
        let hex_text: String = row.get("value");
        let Ok(bytes) = hex::decode(hex_text.trim()) else {
            tracing::warn!(table = "repository_config", id, "value is not hex; skipped");
            report.failed += 1;
            continue;
        };
        if !is_legacy_ciphertext(&bytes) {
            report.already_current += 1;
            continue;
        }
        let Ok(plain) = legacy.decrypt(&bytes) else {
            tracing::warn!(
                table = "repository_config",
                id,
                "could not decrypt; skipped"
            );
            report.failed += 1;
            continue;
        };
        let mut v2 = vec![DATA_KEY_CIPHERTEXT_VERSION];
        v2.extend_from_slice(&k.seal(&plain, b""));
        match sqlx::query(
            "UPDATE repository_config SET value = $2 \
             WHERE repository_id::text = $1 AND key = 'upstream_auth_credentials'",
        )
        .bind(&id)
        .bind(hex::encode(v2))
        .execute(db)
        .await
        {
            Ok(_) => report.rewritten += 1,
            Err(e) => {
                tracing::warn!(table = "repository_config", id, error = %e, "update failed; skipped");
                report.failed += 1;
            }
        }
    }

    tracing::info!(
        rewritten = report.rewritten,
        already_current = report.already_current,
        failed = report.failed,
        "reencrypt-secrets finished"
    );
    Ok(report)
}

#[cfg(ak_test_shard = "services-1")]
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
