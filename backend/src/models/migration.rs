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
    /// Whether to verify that locally computed checksums match the digests
    /// advertised by the source registry. Defaults to `true`. Set to
    /// `false` to disable verification when the source registry is known
    /// to return inaccurate digests (issue #856).
    #[serde(default = "default_true")]
    pub verify_checksums: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // AuthType Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_type_display() {
        assert_eq!(AuthType::ApiToken.to_string(), "api_token");
        assert_eq!(AuthType::BasicAuth.to_string(), "basic_auth");
    }

    // -----------------------------------------------------------------------
    // MigrationJobStatus Display + FromStr
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_job_status_display() {
        assert_eq!(MigrationJobStatus::Pending.to_string(), "pending");
        assert_eq!(MigrationJobStatus::Assessing.to_string(), "assessing");
        assert_eq!(MigrationJobStatus::Ready.to_string(), "ready");
        assert_eq!(MigrationJobStatus::Running.to_string(), "running");
        assert_eq!(MigrationJobStatus::Paused.to_string(), "paused");
        assert_eq!(MigrationJobStatus::Completed.to_string(), "completed");
        assert_eq!(MigrationJobStatus::Failed.to_string(), "failed");
        assert_eq!(MigrationJobStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_migration_job_status_from_str_valid() {
        assert_eq!(
            "pending".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Pending
        );
        assert_eq!(
            "running".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Running
        );
        assert_eq!(
            "completed".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Completed
        );
        assert_eq!(
            "failed".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Failed
        );
        assert_eq!(
            "cancelled".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Cancelled
        );
        assert_eq!(
            "assessing".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Assessing
        );
        assert_eq!(
            "ready".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Ready
        );
        assert_eq!(
            "paused".parse::<MigrationJobStatus>().unwrap(),
            MigrationJobStatus::Paused
        );
    }

    #[test]
    fn test_migration_job_status_from_str_invalid() {
        let result = "invalid".parse::<MigrationJobStatus>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown migration job status"));
    }

    #[test]
    fn test_migration_job_status_roundtrip() {
        let statuses = vec![
            MigrationJobStatus::Pending,
            MigrationJobStatus::Assessing,
            MigrationJobStatus::Ready,
            MigrationJobStatus::Running,
            MigrationJobStatus::Paused,
            MigrationJobStatus::Completed,
            MigrationJobStatus::Failed,
            MigrationJobStatus::Cancelled,
        ];
        for status in statuses {
            let s = status.to_string();
            let parsed: MigrationJobStatus = s.parse().unwrap();
            assert_eq!(parsed, status);
        }
    }

    // -----------------------------------------------------------------------
    // MigrationJobType Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_job_type_display() {
        assert_eq!(MigrationJobType::Full.to_string(), "full");
        assert_eq!(MigrationJobType::Incremental.to_string(), "incremental");
        assert_eq!(MigrationJobType::Assessment.to_string(), "assessment");
    }

    // -----------------------------------------------------------------------
    // MigrationItemType Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_item_type_display() {
        assert_eq!(MigrationItemType::Repository.to_string(), "repository");
        assert_eq!(MigrationItemType::Artifact.to_string(), "artifact");
        assert_eq!(MigrationItemType::User.to_string(), "user");
        assert_eq!(MigrationItemType::Group.to_string(), "group");
        assert_eq!(MigrationItemType::Permission.to_string(), "permission");
        assert_eq!(MigrationItemType::Property.to_string(), "property");
    }

    // -----------------------------------------------------------------------
    // MigrationItemStatus Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_item_status_display() {
        assert_eq!(MigrationItemStatus::Pending.to_string(), "pending");
        assert_eq!(MigrationItemStatus::InProgress.to_string(), "in_progress");
        assert_eq!(MigrationItemStatus::Completed.to_string(), "completed");
        assert_eq!(MigrationItemStatus::Failed.to_string(), "failed");
        assert_eq!(MigrationItemStatus::Skipped.to_string(), "skipped");
    }

    // -----------------------------------------------------------------------
    // MigrationJob::progress_percent
    // -----------------------------------------------------------------------

    fn make_test_job(total: i32, completed: i32, failed: i32, skipped: i32) -> MigrationJob {
        MigrationJob {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "running".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({}),
            total_items: total,
            completed_items: completed,
            failed_items: failed,
            skipped_items: skipped,
            total_bytes: 0,
            transferred_bytes: 0,
            started_at: Some(Utc::now()),
            finished_at: None,
            created_at: Utc::now(),
            created_by: None,
            error_summary: None,
        }
    }

    #[test]
    fn test_progress_percent_zero_total() {
        let job = make_test_job(0, 0, 0, 0);
        assert_eq!(job.progress_percent(), 0.0);
    }

    #[test]
    fn test_progress_percent_all_completed() {
        let job = make_test_job(100, 100, 0, 0);
        assert!((job.progress_percent() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_percent_partial() {
        let job = make_test_job(200, 50, 10, 20);
        // (50 + 10 + 20) / 200 * 100 = 40.0
        assert!((job.progress_percent() - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_percent_mixed_outcomes() {
        let job = make_test_job(10, 5, 3, 2);
        // (5 + 3 + 2) / 10 * 100 = 100.0
        assert!((job.progress_percent() - 100.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // MigrationJob::estimated_time_remaining
    // -----------------------------------------------------------------------

    #[test]
    fn test_estimated_time_remaining_no_start() {
        let mut job = make_test_job(100, 50, 0, 0);
        job.started_at = None;
        assert!(job.estimated_time_remaining().is_none());
    }

    #[test]
    fn test_estimated_time_remaining_zero_processed() {
        let job = make_test_job(100, 0, 0, 0);
        assert!(job.estimated_time_remaining().is_none());
    }

    // -----------------------------------------------------------------------
    // MigrationConfig defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_config_default() {
        let config = MigrationConfig::default();
        assert!(config.include_repos.is_empty());
        assert!(config.exclude_repos.is_empty());
        assert!(config.exclude_paths.is_empty());
        assert!(!config.include_users); // Default trait default is false
        assert!(!config.include_groups);
        assert!(!config.include_permissions);
        assert!(!config.include_cached_remote);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_migration_config_deserialize_with_defaults() {
        let json = r#"{"conflict_resolution": "overwrite"}"#;
        let config: MigrationConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.conflict_resolution, "overwrite");
        assert!(!config.dry_run);
    }

    #[test]
    fn test_migration_config_verify_checksums_serde_default_true() {
        // Issue #856: when `verify_checksums` is absent from the API
        // payload, the serde default must be `true` so existing migrations
        // continue to validate digests after upgrade. (Note: Rust's
        // `Default::default()` for this struct returns the all-zero value
        // because it is derived, not the serde default. API ingress always
        // goes through deserialization, so the serde default is what
        // matters on the wire.)
        let json = r#"{}"#;
        let config: MigrationConfig = serde_json::from_str(json).unwrap();
        assert!(config.verify_checksums);
    }

    #[test]
    fn test_migration_config_verify_checksums_can_be_disabled() {
        // Issue #856: setting the field to false through the API must
        // actually disable verification end to end. This test guards the
        // deserialization half of that contract; the worker half is
        // covered by test_worker_config_verify_checksums_can_be_disabled.
        let json = r#"{"verify_checksums": false}"#;
        let config: MigrationConfig = serde_json::from_str(json).unwrap();
        assert!(!config.verify_checksums);
    }
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
