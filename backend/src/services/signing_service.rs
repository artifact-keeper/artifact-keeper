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

/// Service for managing signing keys and signing operations.
pub struct SigningService {
    db: PgPool,
    encryption: CredentialEncryption,
}

/// Request to create a new signing key.
pub struct CreateKeyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: String,        // "gpg", "rsa", "ed25519"
    pub algorithm: String,       // "rsa2048", "rsa4096"
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
        let bits = match req.algorithm.as_str() {
            "rsa2048" => 2048,
            "rsa4096" | "rsa" => 4096,
            other => {
                return Err(AppError::Validation(format!(
                    "Unsupported algorithm: {}. Use rsa2048 or rsa4096.",
                    other
                )))
            }
        };

        // Generate RSA key pair (use OsRng from rsa's rand_core to avoid version mismatch)
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|e| {
            AppError::Internal(format!("Failed to generate RSA key: {}", e))
        })?;
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
        let fingerprint = hex::encode(Sha256::digest(public_der.as_ref()));
        let key_id = fingerprint[fingerprint.len() - 16..].to_string();

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
                name: format!("{} (rotated)", old_key.name),
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
