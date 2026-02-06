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
    // OCI-based aliases
    Podman,
    Buildx,
    Oras,
    #[sqlx(rename = "wasm_oci")]
    WasmOci,
    #[sqlx(rename = "helm_oci")]
    HelmOci,
    // PyPI-based aliases
    Poetry,
    Conda,
    // npm-based aliases
    Yarn,
    Bower,
    Pnpm,
    // NuGet-based aliases
    Chocolatey,
    Powershell,
    // Native format handlers
    Terraform,
    Opentofu,
    Alpine,
    #[sqlx(rename = "conda_native")]
    CondaNative,
    Composer,
    // Language-specific
    Hex,
    Cocoapods,
    Swift,
    Pub,
    Sbt,
    // Config management
    Chef,
    Puppet,
    Ansible,
    // Git LFS
    Gitlfs,
    // Editor extensions
    Vscode,
    Jetbrains,
    // ML/AI
    Huggingface,
    Mlmodel,
    // Miscellaneous
    Cran,
    Vagrant,
    Opkg,
    P2,
    Bazel,
}

/// Repository type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_type", rename_all = "lowercase")]
pub enum RepositoryType {
    Local,
    Remote,
    Virtual,
    Staging,
}

impl RepositoryType {
    /// Check if this is a staging repository (requires promotion to release)
    pub fn is_staging(&self) -> bool {
        matches!(self, RepositoryType::Staging)
    }

    /// Check if this is a hosted repository (Local or Staging)
    pub fn is_hosted(&self) -> bool {
        matches!(self, RepositoryType::Local | RepositoryType::Staging)
    }
}

/// Replication priority for Borg replication policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "replication_priority", rename_all = "snake_case")]
pub enum ReplicationPriority {
    Immediate,
    Scheduled,
    OnDemand,
    LocalOnly,
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
    pub replication_priority: ReplicationPriority,
    /// For staging repos: default release repo to promote artifacts to
    pub promotion_target_id: Option<Uuid>,
    /// For staging repos: security policy to evaluate before promotion
    pub promotion_policy_id: Option<Uuid>,
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

/// Promotion history entry tracking artifact promotions from staging to release
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PromotionHistory {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub source_repo_id: Uuid,
    pub target_repo_id: Uuid,
    pub promoted_by: Option<Uuid>,
    pub policy_result: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to promote an artifact from staging to release
#[derive(Debug, Clone, Deserialize)]
pub struct PromoteArtifactRequest {
    pub target_repository: String,
    #[serde(default)]
    pub skip_policy_check: bool,
    pub notes: Option<String>,
}

/// Response from artifact promotion
#[derive(Debug, Clone, Serialize)]
pub struct PromotionResult {
    pub promoted: bool,
    pub source: String,
    pub target: String,
    pub policy_violations: Vec<PolicyViolation>,
    pub promotion_id: Option<Uuid>,
}

/// Policy violation detail
#[derive(Debug, Clone, Serialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
}
