//! Migration models for Artifactory to Artifact Keeper migration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// Source connection authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    ApiToken,
    BasicAuth,
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::ApiToken => write!(f, "api_token"),
            AuthType::BasicAuth => write!(f, "basic_auth"),
        }
    }
}

/// Source connection for an Artifactory instance
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SourceConnection {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    #[serde(skip_serializing)]
    pub credentials_enc: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub verified_at: Option<DateTime<Utc>>,
}

/// Migration job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationJobStatus {
    Pending,
    Assessing,
    Ready,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for MigrationJobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationJobStatus::Pending => write!(f, "pending"),
            MigrationJobStatus::Assessing => write!(f, "assessing"),
            MigrationJobStatus::Ready => write!(f, "ready"),
            MigrationJobStatus::Running => write!(f, "running"),
            MigrationJobStatus::Paused => write!(f, "paused"),
            MigrationJobStatus::Completed => write!(f, "completed"),
            MigrationJobStatus::Failed => write!(f, "failed"),
            MigrationJobStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for MigrationJobStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(MigrationJobStatus::Pending),
            "assessing" => Ok(MigrationJobStatus::Assessing),
            "ready" => Ok(MigrationJobStatus::Ready),
            "running" => Ok(MigrationJobStatus::Running),
            "paused" => Ok(MigrationJobStatus::Paused),
            "completed" => Ok(MigrationJobStatus::Completed),
            "failed" => Ok(MigrationJobStatus::Failed),
            "cancelled" => Ok(MigrationJobStatus::Cancelled),
            _ => Err(format!("Unknown migration job status: {}", s)),
        }
    }
}

/// Migration job type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationJobType {
    Full,
    Incremental,
    Assessment,
}

impl std::fmt::Display for MigrationJobType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationJobType::Full => write!(f, "full"),
            MigrationJobType::Incremental => write!(f, "incremental"),
            MigrationJobType::Assessment => write!(f, "assessment"),
        }
    }
}

/// Migration job configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct MigrationConfig {
    #[serde(default)]
    pub include_repos: Vec<String>,
    #[serde(default)]
    pub exclude_repos: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub include_users: bool,
    #[serde(default = "default_true")]
    pub include_groups: bool,
    #[serde(default = "default_true")]
    pub include_permissions: bool,
    #[serde(default)]
    pub include_cached_remote: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_conflict_resolution")]
    pub conflict_resolution: String,
    #[serde(default = "default_concurrent_transfers")]
    pub concurrent_transfers: i32,
    #[serde(default = "default_throttle_delay")]
    pub throttle_delay_ms: i32,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
}

fn default_true() -> bool {
    true
}

fn default_conflict_resolution() -> String {
    "skip".to_string()
}

fn default_concurrent_transfers() -> i32 {
    4
}

fn default_throttle_delay() -> i32 {
    100
}

/// Migration job entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MigrationJob {
    pub id: Uuid,
    pub source_connection_id: Uuid,
    pub status: String,
    pub job_type: String,
    pub config: serde_json::Value,
    pub total_items: i32,
    pub completed_items: i32,
    pub failed_items: i32,
    pub skipped_items: i32,
    pub total_bytes: i64,
    pub transferred_bytes: i64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub error_summary: Option<String>,
}

impl MigrationJob {
    /// Calculate progress percentage
    pub fn progress_percent(&self) -> f64 {
        if self.total_items == 0 {
            0.0
        } else {
            (self.completed_items + self.failed_items + self.skipped_items) as f64
                / self.total_items as f64
                * 100.0
        }
    }

    /// Estimate remaining time in seconds
    pub fn estimated_time_remaining(&self) -> Option<i64> {
        if let Some(started_at) = self.started_at {
            let elapsed = Utc::now().signed_duration_since(started_at);
            let processed = self.completed_items + self.failed_items + self.skipped_items;
            if processed > 0 {
                let remaining = self.total_items - processed;
                let rate = processed as f64 / elapsed.num_seconds() as f64;
                if rate > 0.0 {
                    return Some((remaining as f64 / rate) as i64);
                }
            }
        }
        None
    }
}

/// Migration item type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationItemType {
    Repository,
    Artifact,
    User,
    Group,
    Permission,
    Property,
}

impl std::fmt::Display for MigrationItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationItemType::Repository => write!(f, "repository"),
            MigrationItemType::Artifact => write!(f, "artifact"),
            MigrationItemType::User => write!(f, "user"),
            MigrationItemType::Group => write!(f, "group"),
            MigrationItemType::Permission => write!(f, "permission"),
            MigrationItemType::Property => write!(f, "property"),
        }
    }
}

/// Migration item status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationItemStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
}

impl std::fmt::Display for MigrationItemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationItemStatus::Pending => write!(f, "pending"),
            MigrationItemStatus::InProgress => write!(f, "in_progress"),
            MigrationItemStatus::Completed => write!(f, "completed"),
            MigrationItemStatus::Failed => write!(f, "failed"),
            MigrationItemStatus::Skipped => write!(f, "skipped"),
        }
    }
}

/// Migration item entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MigrationItem {
    pub id: Uuid,
    pub job_id: Uuid,
    pub item_type: String,
    pub source_path: String,
    pub target_path: Option<String>,
    pub status: String,
    pub size_bytes: i64,
    pub checksum_source: Option<String>,
    pub checksum_target: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Migration report entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MigrationReport {
    pub id: Uuid,
    pub job_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub summary: serde_json::Value,
    pub warnings: serde_json::Value,
    pub errors: serde_json::Value,
    pub recommendations: serde_json::Value,
}

/// Report summary structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub duration_seconds: i64,
    pub repositories: ItemSummary,
    pub artifacts: ItemSummary,
    pub users: ItemSummary,
    pub groups: ItemSummary,
    pub permissions: ItemSummary,
    pub total_bytes_transferred: i64,
}

/// Item summary for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSummary {
    pub total: i64,
    pub migrated: i64,
    pub failed: i64,
    pub skipped: i64,
}

/// Warning entry in report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportWarning {
    pub code: String,
    pub message: String,
    pub item_path: Option<String>,
}

/// Error entry in report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportError {
    pub code: String,
    pub message: String,
    pub item_path: Option<String>,
    pub stack_trace: Option<String>,
}
