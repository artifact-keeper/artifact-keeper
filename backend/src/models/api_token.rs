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
#[derive(Clone, FromRow, Serialize)]
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
    pub created_by_user_id: Option<Uuid>,
    pub description: Option<String>,
    pub repo_selector: Option<serde_json::Value>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
}

redacted_debug!(ApiToken {
    show id,
    show user_id,
    show name,
    redact token_hash,
    show token_prefix,
    show scopes,
    show expires_at,
});

/// Response type for API token creation (includes the actual token only once).
#[derive(Clone, Serialize)]
pub struct ApiTokenCreated {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub repository_ids: Vec<Uuid>,
}

redacted_debug!(ApiTokenCreated {
    show id,
    show name,
    redact token,
    show token_prefix,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_token_debug_redacts_hash() {
        let token = ApiToken {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "my-token".to_string(),
            token_hash: "argon2id$secret_hash_value".to_string(),
            token_prefix: "ak_abcd".to_string(),
            scopes: vec!["read".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
        };
        let debug = format!("{:?}", token);
        assert!(debug.contains("my-token"));
        assert!(debug.contains("ak_abcd"));
        assert!(!debug.contains("secret_hash_value"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_api_token_created_debug_redacts_token() {
        let created = ApiTokenCreated {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "new-token".to_string(),
            token: "ak_abcd1234_full_secret_token_value".to_string(),
            token_prefix: "ak_abcd".to_string(),
            scopes: vec![],
            expires_at: None,
            created_at: Utc::now(),
            description: None,
            repository_ids: vec![],
        };
        let debug = format!("{:?}", created);
        assert!(debug.contains("new-token"));
        assert!(!debug.contains("full_secret_token_value"));
        assert!(debug.contains("[REDACTED]"));
    }
}
