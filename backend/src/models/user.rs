//! User model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Auth provider enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "lowercase")]
pub enum AuthProvider {
    Local,
    Ldap,
    Saml,
    Oidc,
}

/// User entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub auth_provider: AuthProvider,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub is_service_account: bool,
    pub must_change_password: bool,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub totp_backup_codes: Option<String>,
    pub totp_verified_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API token entity
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_token_debug_redacts_token_hash() {
        let token = ApiToken {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "ci-token".to_string(),
            token_hash: "$argon2id$v=19$secret_hash".to_string(),
            token_prefix: "ak_1234".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            created_by_user_id: None,
            description: Some("CI pipeline token".to_string()),
        };
        let debug = format!("{:?}", token);
        assert!(debug.contains("ci-token"));
        assert!(debug.contains("ak_1234"));
        assert!(!debug.contains("secret_hash"));
        assert!(debug.contains("[REDACTED]"));
    }
}
