//! User model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Auth provider enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
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
    pub must_change_password: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API token entity
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
