//! Role and permission models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Permission type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_type", rename_all = "lowercase")]
pub enum PermissionType {
    Read,
    Write,
    Delete,
    Admin,
}

/// Role entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Permission grant entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PermissionGrant {
    pub id: Uuid,
    pub role_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub permission: PermissionType,
    pub created_at: DateTime<Utc>,
}

/// Role assignment entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
