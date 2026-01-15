//! Repository model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Repository format enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_format", rename_all = "lowercase")]
pub enum RepositoryFormat {
    Maven,
    Gradle,
    Npm,
    Pypi,
    Nuget,
    Go,
    Rubygems,
    Docker,
    Helm,
    Rpm,
    Debian,
    Conan,
    Cargo,
    Generic,
}

/// Repository type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_type", rename_all = "lowercase")]
pub enum RepositoryType {
    Local,
    Remote,
    Virtual,
}

/// Repository entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Virtual repository member entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct VirtualRepoMember {
    pub id: Uuid,
    pub virtual_repo_id: Uuid,
    pub member_repo_id: Uuid,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}
