//! API token model.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// API token entity for programmatic access.
///
/// Tokens are stored as hashes with only a prefix stored in plaintext
/// for identification purposes. The full token is only returned once
/// during creation and cannot be retrieved later.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Response type for API token creation (includes the actual token only once).
#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenCreated {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
