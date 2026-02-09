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
    #[serde(skip_serializing)]
    pub private_key_enc: Vec<u8>,
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
