//! Signing key models for repository metadata signing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// A signing key used for repository metadata (GPG/RSA/Ed25519).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SigningKey {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: String,
    pub fingerprint: Option<String>,
    pub key_id: Option<String>,
    pub public_key_pem: String,
    /// Encrypted private key material. `None` for public-only trust anchors
    /// used only for upstream verification.
    #[serde(skip_serializing)]
    pub private_key_enc: Option<Vec<u8>>,
    pub algorithm: String,
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub rotated_from: Option<Uuid>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Public view of a signing key (no private material).
#[derive(Debug, Serialize, ToSchema)]
pub struct SigningKeyPublic {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: String,
    pub fingerprint: Option<String>,
    pub key_id: Option<String>,
    pub public_key_pem: String,
    /// True when this key can sign (has local private material). False for
    /// public-only trust anchors used only for upstream verification.
    pub can_sign: bool,
    pub algorithm: String,
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<SigningKey> for SigningKeyPublic {
    fn from(k: SigningKey) -> Self {
        Self {
            id: k.id,
            repository_id: k.repository_id,
            name: k.name,
            key_type: k.key_type,
            fingerprint: k.fingerprint,
            key_id: k.key_id,
            public_key_pem: k.public_key_pem,
            can_sign: k.private_key_enc.is_some(),
            algorithm: k.algorithm,
            uid_name: k.uid_name,
            uid_email: k.uid_email,
            expires_at: k.expires_at,
            is_active: k.is_active,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
        }
    }
}

/// Repository signing configuration.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct RepositorySigningConfig {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub signing_key_id: Option<Uuid>,
    pub sign_metadata: bool,
    pub sign_packages: bool,
    pub require_signatures: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_key(private_key_enc: Option<Vec<u8>>) -> SigningKey {
        let now = chrono::Utc::now();
        SigningKey {
            id: Uuid::new_v4(),
            repository_id: Some(Uuid::new_v4()),
            name: "my-gpg-key".to_string(),
            key_type: "gpg".to_string(),
            fingerprint: Some("ABCDEF1234567890".to_string()),
            key_id: Some("12345678".to_string()),
            public_key_pem: "-----BEGIN PGP PUBLIC KEY BLOCK-----...".to_string(),
            private_key_enc,
            algorithm: "RSA".to_string(),
            uid_name: Some("Test User".to_string()),
            uid_email: Some("test@example.com".to_string()),
            expires_at: None,
            is_active: true,
            created_at: now,
            created_by: None,
            rotated_from: None,
            last_used_at: Some(now),
        }
    }

    #[test]
    fn test_signing_key_public_from_signing_key() {
        let key = base_key(Some(vec![1, 2, 3, 4, 5]));
        let key_id = key.id;
        let repo_id = key.repository_id;

        let public: SigningKeyPublic = key.into();

        assert_eq!(public.id, key_id);
        assert_eq!(public.repository_id, repo_id);
        assert_eq!(public.name, "my-gpg-key");
        assert_eq!(public.key_type, "gpg");
        assert_eq!(public.fingerprint.as_deref(), Some("ABCDEF1234567890"));
        assert_eq!(public.key_id.as_deref(), Some("12345678"));
        assert!(public.public_key_pem.contains("BEGIN PGP"));
        assert!(public.can_sign);
        assert_eq!(public.algorithm, "RSA");
        assert_eq!(public.uid_name.as_deref(), Some("Test User"));
        assert_eq!(public.uid_email.as_deref(), Some("test@example.com"));
        assert!(public.is_active);
        assert!(public.last_used_at.is_some());
    }

    #[test]
    fn test_signing_key_public_from_key_with_none_fields() {
        let now = chrono::Utc::now();
        let key = SigningKey {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "global-key".to_string(),
            key_type: "ed25519".to_string(),
            fingerprint: None,
            key_id: None,
            public_key_pem: "PEM".to_string(),
            private_key_enc: None,
            algorithm: "Ed25519".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: false,
            created_at: now,
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        };

        let public: SigningKeyPublic = key.into();
        assert!(public.repository_id.is_none());
        assert!(public.fingerprint.is_none());
        assert!(public.key_id.is_none());
        assert!(!public.can_sign);
        assert!(public.uid_name.is_none());
        assert!(public.uid_email.is_none());
        assert!(!public.is_active);
        assert!(public.last_used_at.is_none());
    }

    #[test]
    fn test_public_only_trust_anchor_cannot_sign() {
        let key = base_key(None);
        let public: SigningKeyPublic = key.into();
        assert!(!public.can_sign);
    }
}
