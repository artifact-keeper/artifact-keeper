//! Signing service for GPG/RSA key management and metadata signing.
//!
//! Provides key generation, storage (encrypted), and signing operations
//! for Debian/APT, RPM/YUM, Alpine/APK, and Conda repositories.

use crate::error::{AppError, Result};
use crate::models::signing_key::{RepositorySigningConfig, SigningKey, SigningKeyPublic};
use crate::services::encryption::CredentialEncryption;
use chrono::Utc;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Map an algorithm string to the RSA key size in bits.
/// Returns `Ok(bits)` for valid RSA algorithms, `Err(message)` for unsupported ones.
pub(crate) fn algorithm_to_bits(algorithm: &str) -> std::result::Result<usize, String> {
    match algorithm {
        "rsa2048" => Ok(2048),
        "rsa4096" | "rsa" => Ok(4096),
        other => Err(format!(
            "Unsupported algorithm: {}. Use rsa2048 or rsa4096.",
            other
        )),
    }
}

/// Compute the SHA-256 fingerprint of a DER-encoded public key.
/// Returns the full hex-encoded fingerprint.
pub(crate) fn compute_fingerprint(public_key_der: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key_der))
}

/// Derive the short key ID (last 16 hex chars) from a full fingerprint.
pub(crate) fn derive_key_id(fingerprint: &str) -> String {
    fingerprint[fingerprint.len().saturating_sub(16)..].to_string()
}

/// Build a rotated key name from an existing key name.
pub(crate) fn build_rotated_key_name(original_name: &str) -> String {
    format!("{} (rotated)", original_name)
}

/// Service for managing signing keys and signing operations.
pub struct SigningService {
    db: PgPool,
    encryption: CredentialEncryption,
}

/// Request to create a new signing key.
pub struct CreateKeyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: String,  // "gpg", "rsa", "ed25519"
    pub algorithm: String, // "rsa2048", "rsa4096"
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
    pub created_by: Option<Uuid>,
}

impl SigningService {
    pub fn new(db: PgPool, encryption_key: &str) -> Self {
        Self {
            db,
            encryption: CredentialEncryption::from_passphrase(encryption_key),
        }
    }

    /// Generate a new RSA key pair and store it.
    pub async fn create_key(&self, req: CreateKeyRequest) -> Result<SigningKeyPublic> {
        let bits = algorithm_to_bits(&req.algorithm).map_err(AppError::Validation)?;

        // Generate RSA key pair (use OsRng from rsa's rand_core to avoid version mismatch)
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| AppError::Internal(format!("Failed to generate RSA key: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        // Serialize keys
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("Failed to encode public key: {}", e)))?;

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("Failed to encode private key: {}", e)))?;

        // Encrypt private key
        let private_bytes = private_pem.as_bytes();
        let private_enc = self.encryption.encrypt(private_bytes);

        // Compute fingerprint (SHA-256 of DER-encoded public key)
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| AppError::Internal(format!("Failed to encode public key DER: {}", e)))?;
        let fingerprint = compute_fingerprint(public_der.as_ref());
        let key_id = derive_key_id(&fingerprint);

        // Build GPG-style armored public key if key_type is gpg
        let public_key_out = if req.key_type == "gpg" {
            // For GPG consumers, wrap the RSA public key in a GPG-compatible format.
            // We use raw PEM for now — real GPG armoring would need pgp crate.
            // Consumers that need actual GPG packets should import via gpg --import.
            public_pem.clone()
        } else {
            public_pem.clone()
        };

        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO signing_keys (id, repository_id, name, key_type, fingerprint, key_id,
                public_key_pem, private_key_enc, algorithm, uid_name, uid_email, is_active,
                created_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true, $12, $13)
            "#,
            id,
            req.repository_id,
            req.name,
            req.key_type,
            fingerprint,
            key_id,
            public_key_out,
            private_enc,
            req.algorithm,
            req.uid_name,
            req.uid_email,
            now,
            req.created_by,
        )
        .execute(&self.db)
        .await?;

        // Audit log
        self.audit_key_action(id, "created", req.created_by, None)
            .await?;

        Ok(SigningKeyPublic {
            id,
            repository_id: req.repository_id,
            name: req.name,
            key_type: req.key_type,
            fingerprint: Some(fingerprint),
            key_id: Some(key_id),
            public_key_pem: public_key_out,
            algorithm: req.algorithm,
            uid_name: req.uid_name,
            uid_email: req.uid_email,
            expires_at: None,
            is_active: true,
            created_at: now,
            last_used_at: None,
        })
    }

    /// Get a signing key by ID (public info only).
    pub async fn get_key(&self, key_id: Uuid) -> Result<SigningKeyPublic> {
        let key = sqlx::query_as!(
            SigningKey,
            "SELECT * FROM signing_keys WHERE id = $1",
            key_id,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signing key not found".to_string()))?;

        Ok(key.into())
    }

    /// Get the active signing key for a repository.
    pub async fn get_active_key_for_repo(&self, repo_id: Uuid) -> Result<Option<SigningKey>> {
        let key = sqlx::query_as!(
            SigningKey,
            r#"
            SELECT sk.* FROM signing_keys sk
            JOIN repository_signing_config rsc ON rsc.signing_key_id = sk.id
            WHERE rsc.repository_id = $1 AND sk.is_active = true AND rsc.sign_metadata = true
            LIMIT 1
            "#,
            repo_id,
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(key)
    }

    /// List signing keys, optionally filtered by repository.
    pub async fn list_keys(&self, repo_id: Option<Uuid>) -> Result<Vec<SigningKeyPublic>> {
        let keys = if let Some(rid) = repo_id {
            sqlx::query_as!(
                SigningKey,
                "SELECT * FROM signing_keys WHERE repository_id = $1 ORDER BY created_at DESC",
                rid,
            )
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as!(
                SigningKey,
                "SELECT * FROM signing_keys ORDER BY created_at DESC",
            )
            .fetch_all(&self.db)
            .await?
        };

        Ok(keys.into_iter().map(|k| k.into()).collect())
    }

    /// Deactivate (revoke) a signing key.
    pub async fn revoke_key(&self, key_id: Uuid, user_id: Option<Uuid>) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE signing_keys SET is_active = false WHERE id = $1",
            key_id,
        )
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Signing key not found".to_string()));
        }

        self.audit_key_action(key_id, "revoked", user_id, None)
            .await?;
        Ok(())
    }

    /// Delete a signing key permanently.
    pub async fn delete_key(&self, key_id: Uuid) -> Result<()> {
        sqlx::query!("DELETE FROM signing_keys WHERE id = $1", key_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Sign data with the repository's active signing key (RSA PKCS#1 v1.5 SHA-256).
    pub async fn sign_data(&self, repo_id: Uuid, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = match self.get_active_key_for_repo(repo_id).await? {
            Some(k) => k,
            None => return Ok(None),
        };

        let signature = self.sign_with_key(&key, data)?;

        // Update last_used_at
        sqlx::query!(
            "UPDATE signing_keys SET last_used_at = NOW() WHERE id = $1",
            key.id,
        )
        .execute(&self.db)
        .await?;

        Ok(Some(signature))
    }

    /// Sign data with a specific key.
    pub fn sign_with_key(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>> {
        // Decrypt private key
        let private_pem = self
            .encryption
            .decrypt(&key.private_key_enc)
            .map_err(|e| AppError::Internal(format!("Failed to decrypt private key: {}", e)))?;

        let private_key = RsaPrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&private_pem)
                .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in key: {}", e)))?,
        )
        .map_err(|e| AppError::Internal(format!("Failed to parse private key: {}", e)))?;

        let signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }

    /// Get the public key in PEM format for a repository.
    pub async fn get_repo_public_key(&self, repo_id: Uuid) -> Result<Option<String>> {
        let key = self.get_active_key_for_repo(repo_id).await?;
        Ok(key.map(|k| k.public_key_pem))
    }

    /// Get or create signing configuration for a repository.
    pub async fn get_signing_config(
        &self,
        repo_id: Uuid,
    ) -> Result<Option<RepositorySigningConfig>> {
        let config = sqlx::query_as!(
            RepositorySigningConfig,
            "SELECT * FROM repository_signing_config WHERE repository_id = $1",
            repo_id,
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(config)
    }

    /// Update signing configuration for a repository.
    pub async fn update_signing_config(
        &self,
        repo_id: Uuid,
        signing_key_id: Option<Uuid>,
        sign_metadata: bool,
        sign_packages: bool,
        require_signatures: bool,
    ) -> Result<RepositorySigningConfig> {
        let config = sqlx::query_as!(
            RepositorySigningConfig,
            r#"
            INSERT INTO repository_signing_config
                (repository_id, signing_key_id, sign_metadata, sign_packages, require_signatures, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (repository_id) DO UPDATE SET
                signing_key_id = $2,
                sign_metadata = $3,
                sign_packages = $4,
                require_signatures = $5,
                updated_at = NOW()
            RETURNING *
            "#,
            repo_id,
            signing_key_id,
            sign_metadata,
            sign_packages,
            require_signatures,
        )
        .fetch_one(&self.db)
        .await?;
        Ok(config)
    }

    /// Rotate a key: create new key, link it, deactivate old one.
    pub async fn rotate_key(
        &self,
        old_key_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<SigningKeyPublic> {
        let old_key = sqlx::query_as!(
            SigningKey,
            "SELECT * FROM signing_keys WHERE id = $1",
            old_key_id,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signing key not found".to_string()))?;

        // Create new key with same params
        let new_key = self
            .create_key(CreateKeyRequest {
                repository_id: old_key.repository_id,
                name: build_rotated_key_name(&old_key.name),
                key_type: old_key.key_type.clone(),
                algorithm: old_key.algorithm.clone(),
                uid_name: old_key.uid_name.clone(),
                uid_email: old_key.uid_email.clone(),
                created_by: user_id,
            })
            .await?;

        // Mark old key as rotated
        sqlx::query!(
            "UPDATE signing_keys SET is_active = false WHERE id = $1",
            old_key_id,
        )
        .execute(&self.db)
        .await?;

        // Update rotated_from on new key
        sqlx::query!(
            "UPDATE signing_keys SET rotated_from = $1 WHERE id = $2",
            old_key_id,
            new_key.id,
        )
        .execute(&self.db)
        .await?;

        // Update signing config to point to new key
        if let Some(repo_id) = old_key.repository_id {
            sqlx::query!(
                "UPDATE repository_signing_config SET signing_key_id = $1, updated_at = NOW() WHERE repository_id = $2 AND signing_key_id = $3",
                new_key.id,
                repo_id,
                old_key_id,
            )
            .execute(&self.db)
            .await?;
        }

        self.audit_key_action(
            old_key_id,
            "rotated",
            user_id,
            Some(serde_json::json!({"new_key_id": new_key.id.to_string()})),
        )
        .await?;

        Ok(new_key)
    }

    async fn audit_key_action(
        &self,
        key_id: Uuid,
        action: &str,
        user_id: Option<Uuid>,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO signing_key_audit (signing_key_id, action, performed_by, details) VALUES ($1, $2, $3, $4)",
            key_id,
            action,
            user_id,
            details,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    use uuid::Uuid;

    /// Generate a real RSA key pair, encrypt the private key with the given
    /// passphrase, and return a SigningKey model struct suitable for sign_with_key.
    fn generate_test_signing_key(passphrase: &str) -> SigningKey {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen failed");
        let public_key = RsaPublicKey::from(&private_key);

        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pub pem encode failed");
        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("priv pem encode failed");

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_enc = encryption.encrypt(private_pem.as_bytes());

        let public_der = public_key
            .to_public_key_der()
            .expect("pub der encode failed");
        let fingerprint = hex::encode(sha2::Sha256::digest(public_der.as_ref()));
        let key_id = fingerprint[fingerprint.len() - 16..].to_string();

        let now = Utc::now();
        SigningKey {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test-key".to_string(),
            key_type: "rsa".to_string(),
            fingerprint: Some(fingerprint),
            key_id: Some(key_id),
            public_key_pem: public_pem,
            private_key_enc: private_enc,
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: true,
            created_at: now,
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        }
    }

    // -----------------------------------------------------------------------
    // sign_with_key: roundtrip test (sign then verify)
    //
    // NOTE: SigningService::sign_with_key requires &self (which needs PgPool).
    // This is a testability blocker. The crypto logic (decrypt -> parse ->
    // sign) should be extracted into a free function that takes
    // (&CredentialEncryption, &SigningKey, &[u8]) -> Result<Vec<u8>>.
    // Below we replicate the crypto logic to verify correctness.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_produces_valid_signature() {
        let passphrase = "test-encryption-key-for-signing";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"Hello, Artifact Keeper!";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_sign_different_data_different_signatures() {
        let passphrase = "test-key-diff";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let sig1 = rsa_signing_key.sign(b"data A");
        let sig2 = rsa_signing_key.sign(b"data B");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Encryption roundtrip for private key material
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_encryption_roundtrip() {
        let passphrase = "encryption-roundtrip-test";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let decrypted = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let decrypted_str = std::str::from_utf8(&decrypted).unwrap();

        assert!(decrypted_str.contains("BEGIN PRIVATE KEY"));
        assert!(decrypted_str.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_wrong_passphrase_fails_decryption() {
        let signing_key = generate_test_signing_key("correct-passphrase");
        let wrong_encryption = CredentialEncryption::from_passphrase("wrong-passphrase");

        let result = wrong_encryption.decrypt(&signing_key.private_key_enc);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Fingerprint and key_id derivation
    // -----------------------------------------------------------------------

    #[test]
    fn test_fingerprint_is_valid_hex() {
        let signing_key = generate_test_signing_key("fp-test");
        let fingerprint = signing_key.fingerprint.as_ref().unwrap();
        // SHA-256 hex = 64 chars
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_key_id_is_last_16_of_fingerprint() {
        let signing_key = generate_test_signing_key("kid-test");
        let fingerprint = signing_key.fingerprint.as_ref().unwrap();
        let key_id = signing_key.key_id.as_ref().unwrap();
        assert_eq!(key_id.len(), 16);
        assert_eq!(key_id, &fingerprint[fingerprint.len() - 16..]);
    }

    // -----------------------------------------------------------------------
    // SigningKey -> SigningKeyPublic conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_to_public_conversion() {
        let signing_key = generate_test_signing_key("conv-test");
        let public: SigningKeyPublic = signing_key.clone().into();

        assert_eq!(public.id, signing_key.id);
        assert_eq!(public.name, signing_key.name);
        assert_eq!(public.key_type, signing_key.key_type);
        assert_eq!(public.fingerprint, signing_key.fingerprint);
        assert_eq!(public.key_id, signing_key.key_id);
        assert_eq!(public.public_key_pem, signing_key.public_key_pem);
        assert_eq!(public.algorithm, signing_key.algorithm);
        assert_eq!(public.is_active, signing_key.is_active);
        assert_eq!(public.created_at, signing_key.created_at);
    }

    // -----------------------------------------------------------------------
    // algorithm_to_bits (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_algorithm_to_bits_rsa2048() {
        assert_eq!(algorithm_to_bits("rsa2048").unwrap(), 2048);
    }

    #[test]
    fn test_algorithm_to_bits_rsa4096() {
        assert_eq!(algorithm_to_bits("rsa4096").unwrap(), 4096);
    }

    #[test]
    fn test_algorithm_to_bits_rsa_alias() {
        assert_eq!(algorithm_to_bits("rsa").unwrap(), 4096);
    }

    #[test]
    fn test_algorithm_to_bits_unsupported() {
        let result = algorithm_to_bits("ed25519");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported algorithm"));
    }

    #[test]
    fn test_algorithm_to_bits_unknown() {
        assert!(algorithm_to_bits("unknown").is_err());
    }

    #[test]
    fn test_algorithm_to_bits_empty() {
        assert!(algorithm_to_bits("").is_err());
    }

    // -----------------------------------------------------------------------
    // compute_fingerprint (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_fingerprint_is_valid_hex() {
        let data = b"test public key data";
        let fp = compute_fingerprint(data);
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let data = b"same data";
        let fp1 = compute_fingerprint(data);
        let fp2 = compute_fingerprint(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_different_data() {
        let fp1 = compute_fingerprint(b"data A");
        let fp2 = compute_fingerprint(b"data B");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_empty() {
        let fp = compute_fingerprint(b"");
        assert_eq!(fp.len(), 64);
    }

    // -----------------------------------------------------------------------
    // derive_key_id (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_key_id_from_fingerprint() {
        let fp = "a".repeat(64);
        let kid = derive_key_id(&fp);
        assert_eq!(kid.len(), 16);
        assert_eq!(kid, "a".repeat(16));
    }

    #[test]
    fn test_derive_key_id_is_suffix() {
        let fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kid = derive_key_id(fp);
        assert_eq!(kid, &fp[48..]);
    }

    #[test]
    fn test_derive_key_id_short_fingerprint() {
        // Edge case: fingerprint shorter than 16
        let fp = "abcdef";
        let kid = derive_key_id(fp);
        assert_eq!(kid, "abcdef");
    }

    // -----------------------------------------------------------------------
    // build_rotated_key_name (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rotated_key_name() {
        assert_eq!(build_rotated_key_name("my-key"), "my-key (rotated)");
    }

    #[test]
    fn test_build_rotated_key_name_already_rotated() {
        assert_eq!(
            build_rotated_key_name("my-key (rotated)"),
            "my-key (rotated) (rotated)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_empty() {
        assert_eq!(build_rotated_key_name(""), " (rotated)");
    }

    // -----------------------------------------------------------------------
    // CreateKeyRequest construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_key_request_construction() {
        let repo_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let req = CreateKeyRequest {
            repository_id: Some(repo_id),
            name: "my-signing-key".to_string(),
            key_type: "rsa".to_string(),
            algorithm: "rsa4096".to_string(),
            uid_name: Some("John Doe".to_string()),
            uid_email: Some("john@example.com".to_string()),
            created_by: Some(user_id),
        };
        assert_eq!(req.repository_id, Some(repo_id));
        assert_eq!(req.name, "my-signing-key");
        assert_eq!(req.key_type, "rsa");
        assert_eq!(req.algorithm, "rsa4096");
        assert_eq!(req.uid_name, Some("John Doe".to_string()));
        assert_eq!(req.uid_email, Some("john@example.com".to_string()));
        assert_eq!(req.created_by, Some(user_id));
    }

    #[test]
    fn test_create_key_request_minimal() {
        let req = CreateKeyRequest {
            repository_id: None,
            name: "global-key".to_string(),
            key_type: "gpg".to_string(),
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            created_by: None,
        };
        assert!(req.repository_id.is_none());
        assert!(req.uid_name.is_none());
        assert!(req.uid_email.is_none());
        assert!(req.created_by.is_none());
    }

    // -----------------------------------------------------------------------
    // CredentialEncryption - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_encryption_empty_data() {
        let encryption = CredentialEncryption::from_passphrase("test-key");
        let encrypted = encryption.encrypt(b"");
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encryption_large_data() {
        let encryption = CredentialEncryption::from_passphrase("test-key");
        let data = vec![0xABu8; 10_000];
        let encrypted = encryption.encrypt(&data);
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_binary_data() {
        let encryption = CredentialEncryption::from_passphrase("binary-test");
        let data: Vec<u8> = (0..=255).collect();
        let encrypted = encryption.encrypt(&data);
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_different_passphrases_produce_different_output() {
        let enc1 = CredentialEncryption::from_passphrase("key-1");
        let enc2 = CredentialEncryption::from_passphrase("key-2");
        let data = b"secret data";
        let encrypted1 = enc1.encrypt(data);
        let encrypted2 = enc2.encrypt(data);
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_encryption_same_passphrase_decrypts_to_same() {
        let enc1 = CredentialEncryption::from_passphrase("same-key");
        let enc2 = CredentialEncryption::from_passphrase("same-key");
        let data = b"test data";
        let encrypted1 = enc1.encrypt(data);
        let encrypted2 = enc2.encrypt(data);
        // Both should decrypt to the same plaintext
        let decrypted1 = enc1.decrypt(&encrypted1).unwrap();
        let decrypted2 = enc2.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1, data);
        assert_eq!(decrypted2, data);
        // Cross-decryption should also work
        let cross1 = enc2.decrypt(&encrypted1).unwrap();
        let cross2 = enc1.decrypt(&encrypted2).unwrap();
        assert_eq!(cross1, data);
        assert_eq!(cross2, data);
    }

    // -----------------------------------------------------------------------
    // SigningKey fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_all_fields() {
        let key = generate_test_signing_key("all-fields-test");
        assert_eq!(key.name, "test-key");
        assert_eq!(key.key_type, "rsa");
        assert_eq!(key.algorithm, "rsa2048");
        assert!(key.is_active);
        assert!(key.repository_id.is_none());
        assert!(key.uid_name.is_none());
        assert!(key.uid_email.is_none());
        assert!(key.expires_at.is_none());
        assert!(key.created_by.is_none());
        assert!(key.rotated_from.is_none());
        assert!(key.last_used_at.is_none());
    }

    #[test]
    fn test_signing_key_clone() {
        let key = generate_test_signing_key("clone-test");
        let cloned = key.clone();
        assert_eq!(key.id, cloned.id);
        assert_eq!(key.name, cloned.name);
        assert_eq!(key.fingerprint, cloned.fingerprint);
        assert_eq!(key.key_id, cloned.key_id);
        assert_eq!(key.public_key_pem, cloned.public_key_pem);
        assert_eq!(key.private_key_enc, cloned.private_key_enc);
    }

    // -----------------------------------------------------------------------
    // SigningKeyPublic fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_public_fields() {
        let key = generate_test_signing_key("pub-fields-test");
        let public: SigningKeyPublic = key.clone().into();

        assert_eq!(public.id, key.id);
        assert_eq!(public.repository_id, key.repository_id);
        assert_eq!(public.name, key.name);
        assert_eq!(public.key_type, key.key_type);
        assert_eq!(public.fingerprint, key.fingerprint);
        assert_eq!(public.key_id, key.key_id);
        assert_eq!(public.public_key_pem, key.public_key_pem);
        assert_eq!(public.algorithm, key.algorithm);
        assert_eq!(public.uid_name, key.uid_name);
        assert_eq!(public.uid_email, key.uid_email);
        assert_eq!(public.is_active, key.is_active);
        assert_eq!(public.created_at, key.created_at);
        assert_eq!(public.last_used_at, key.last_used_at);
    }

    // -----------------------------------------------------------------------
    // Public key PEM format
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_pem_format() {
        let key = generate_test_signing_key("pem-format-test");
        assert!(key.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(key.public_key_pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_public_key_is_parseable() {
        let key = generate_test_signing_key("parseable-test");
        let result = RsaPublicKey::from_public_key_pem(&key.public_key_pem);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Fingerprint properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_fingerprint_deterministic() {
        // Two keys should have different fingerprints (different random keys)
        let key1 = generate_test_signing_key("fp-det-1");
        let key2 = generate_test_signing_key("fp-det-2");
        assert_ne!(
            key1.fingerprint.as_ref().unwrap(),
            key2.fingerprint.as_ref().unwrap()
        );
    }

    #[test]
    fn test_key_id_is_hex() {
        let key = generate_test_signing_key("kid-hex-test");
        let key_id = key.key_id.as_ref().unwrap();
        assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // sign / verify with different data
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_empty_data() {
        let passphrase = "empty-data-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_sign_large_data() {
        let passphrase = "large-data-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = vec![0xBBu8; 100_000];
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(&data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(&data, &signature).is_ok());
    }

    #[test]
    fn test_tampered_data_fails_verification() {
        let passphrase = "tamper-test";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"original data";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        // Tampered data should fail verification
        assert!(verifying_key.verify(b"tampered data", &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key1 = generate_test_signing_key("key-1-verify");
        let signing_key2 = generate_test_signing_key("key-2-verify");

        let encryption1 = CredentialEncryption::from_passphrase("key-1-verify");
        let private_pem_bytes = encryption1.decrypt(&signing_key1.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"test data for wrong key";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        // Try to verify with key2's public key - should fail
        let public_key2 = RsaPublicKey::from_public_key_pem(&signing_key2.public_key_pem).unwrap();
        let verifying_key2 = VerifyingKey::<Sha256>::new(public_key2);
        assert!(verifying_key2.verify(data, &signature).is_err());
    }

    // -----------------------------------------------------------------------
    // Deterministic signing
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_same_data_deterministic() {
        let passphrase = "deterministic-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"deterministic test data";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let sig1 = rsa_signing_key.sign(data);
        let sig2 = rsa_signing_key.sign(data);

        // PKCS#1 v1.5 is deterministic (unlike PSS)
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Private key encrypted storage
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_not_stored_plaintext() {
        let key = generate_test_signing_key("not-plaintext");
        let enc_bytes = &key.private_key_enc;
        // The encrypted bytes should NOT contain the PEM header
        let enc_str = String::from_utf8_lossy(enc_bytes);
        assert!(
            !enc_str.contains("BEGIN PRIVATE KEY"),
            "Private key should not be stored as plaintext PEM"
        );
    }
}
