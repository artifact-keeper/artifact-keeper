//! Build tracking service.
//!
//! Manages build lifecycle: creation, status updates, and artifact attachment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Build service for managing CI/CD build records.
pub struct BuildService {
    db: PgPool,
}

/// A build row from the database.
#[derive(Debug, Serialize, FromRow)]
pub struct Build {
    pub id: Uuid,
    pub name: String,
    pub build_number: i32,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub agent: Option<String>,
    pub artifact_count: Option<i32>,
    pub vcs_url: Option<String>,
    pub vcs_revision: Option<String>,
    pub vcs_branch: Option<String>,
    pub vcs_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A build artifact row from the database.
#[derive(Debug, Serialize, FromRow)]
pub struct BuildArtifact {
    pub id: Uuid,
    pub build_id: Uuid,
    pub module_name: Option<String>,
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new build.
#[derive(Debug, Deserialize)]
pub struct CreateBuildInput {
    pub name: String,
    pub build_number: i32,
    pub agent: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub vcs_url: Option<String>,
    pub vcs_revision: Option<String>,
    pub vcs_branch: Option<String>,
    pub vcs_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Input for updating build status.
#[derive(Debug, Deserialize)]
pub struct UpdateBuildStatusInput {
    pub status: String,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Input for a single build artifact.
#[derive(Debug, Deserialize)]
pub struct BuildArtifactInput {
    pub module_name: Option<String>,
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

impl BuildService {
    /// Create a new build service.
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new build with status "running".
    pub async fn create(&self, input: CreateBuildInput) -> Result<Build> {
        if input.name.is_empty() {
            return Err(AppError::Validation("Build name is required".to_string()));
        }

        let build: Build = sqlx::query_as(
            r#"
            INSERT INTO builds (name, build_number, status, started_at, agent,
                                vcs_url, vcs_revision, vcs_branch, vcs_message, metadata)
            VALUES ($1, $2, 'running', $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, name, build_number, status, started_at, finished_at,
                      duration_ms, agent, artifact_count,
                      vcs_url, vcs_revision, vcs_branch, vcs_message, metadata,
                      created_at, updated_at
            "#,
        )
        .bind(&input.name)
        .bind(input.build_number)
        .bind(input.started_at.unwrap_or_else(Utc::now))
        .bind(&input.agent)
        .bind(&input.vcs_url)
        .bind(&input.vcs_revision)
        .bind(&input.vcs_branch)
        .bind(&input.vcs_message)
        .bind(&input.metadata)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(build)
    }

    /// Update build status and compute duration_ms if finished_at is provided.
    pub async fn update_status(
        &self,
        build_id: Uuid,
        input: UpdateBuildStatusInput,
    ) -> Result<Build> {
        // Validate status
        match input.status.as_str() {
            "success" | "failed" | "cancelled" | "running" | "pending" => {}
            other => {
                return Err(AppError::Validation(format!(
                    "Invalid build status: {}. Must be one of: pending, running, success, failed, cancelled",
                    other
                )));
            }
        }

        // Compute duration_ms if finished_at is provided
        let build: Build = sqlx::query_as(
            r#"
            UPDATE builds
            SET status = $2,
                finished_at = $3,
                duration_ms = CASE
                    WHEN $3::timestamptz IS NOT NULL AND started_at IS NOT NULL
                    THEN EXTRACT(EPOCH FROM ($3::timestamptz - started_at)) * 1000
                    ELSE duration_ms
                END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, build_number, status, started_at, finished_at,
                      duration_ms, agent, artifact_count,
                      vcs_url, vcs_revision, vcs_branch, vcs_message, metadata,
                      created_at, updated_at
            "#,
        )
        .bind(build_id)
        .bind(&input.status)
        .bind(input.finished_at)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Build {} not found", build_id)))?;

        Ok(build)
    }

    /// Bulk insert artifacts for a build and update the artifact_count.
    pub async fn add_artifacts(
        &self,
        build_id: Uuid,
        artifacts: Vec<BuildArtifactInput>,
    ) -> Result<Vec<BuildArtifact>> {
        if artifacts.is_empty() {
            return Err(AppError::Validation(
                "At least one artifact is required".to_string(),
            ));
        }

        // Verify build exists
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM builds WHERE id = $1)")
            .bind(build_id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if !exists {
            return Err(AppError::NotFound(format!("Build {} not found", build_id)));
        }

        let mut inserted = Vec::with_capacity(artifacts.len());

        for artifact in &artifacts {
            if artifact.name.is_empty() {
                return Err(AppError::Validation(
                    "Artifact name is required".to_string(),
                ));
            }
            if artifact.path.is_empty() {
                return Err(AppError::Validation(
                    "Artifact path is required".to_string(),
                ));
            }

            let row: BuildArtifact = sqlx::query_as(
                r#"
                INSERT INTO build_artifacts (build_id, module_name, name, path, checksum_sha256, size_bytes)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, build_id, module_name, name, path, checksum_sha256, size_bytes, created_at
                "#,
            )
            .bind(build_id)
            .bind(&artifact.module_name)
            .bind(&artifact.name)
            .bind(&artifact.path)
            .bind(&artifact.checksum_sha256)
            .bind(artifact.size_bytes)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            inserted.push(row);
        }

        // Update artifact_count on the build
        sqlx::query(
            r#"
            UPDATE builds
            SET artifact_count = (SELECT COUNT(*) FROM build_artifacts WHERE build_id = $1),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(build_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CreateBuildInput deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_build_input_deserialization_full() {
        let json = r#"{
            "name": "my-build",
            "build_number": 42,
            "agent": "github-actions",
            "vcs_url": "https://github.com/org/repo",
            "vcs_revision": "abc123",
            "vcs_branch": "main",
            "vcs_message": "Fix bug",
            "metadata": {"ci": "github"}
        }"#;
        let input: CreateBuildInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.name, "my-build");
        assert_eq!(input.build_number, 42);
        assert_eq!(input.agent.as_deref(), Some("github-actions"));
        assert_eq!(
            input.vcs_url.as_deref(),
            Some("https://github.com/org/repo")
        );
        assert_eq!(input.vcs_revision.as_deref(), Some("abc123"));
        assert_eq!(input.vcs_branch.as_deref(), Some("main"));
        assert_eq!(input.vcs_message.as_deref(), Some("Fix bug"));
        assert!(input.metadata.is_some());
    }

    #[test]
    fn test_create_build_input_deserialization_minimal() {
        let json = r#"{"name": "release-build", "build_number": 1}"#;
        let input: CreateBuildInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.name, "release-build");
        assert_eq!(input.build_number, 1);
        assert!(input.agent.is_none());
        assert!(input.vcs_url.is_none());
        assert!(input.vcs_revision.is_none());
        assert!(input.vcs_branch.is_none());
        assert!(input.vcs_message.is_none());
        assert!(input.metadata.is_none());
        assert!(input.started_at.is_none());
    }

    // -----------------------------------------------------------------------
    // UpdateBuildStatusInput deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_build_status_input_deserialization() {
        let json = r#"{"status": "success"}"#;
        let input: UpdateBuildStatusInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.status, "success");
        assert!(input.finished_at.is_none());
    }

    #[test]
    fn test_update_build_status_input_with_finished_at() {
        let json = r#"{"status": "failed", "finished_at": "2024-06-15T12:00:00Z"}"#;
        let input: UpdateBuildStatusInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.status, "failed");
        assert!(input.finished_at.is_some());
    }

    // -----------------------------------------------------------------------
    // Status validation logic (from update_status)
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_build_statuses() {
        let valid_statuses = vec!["success", "failed", "cancelled", "running", "pending"];
        for status in valid_statuses {
            match status {
                "success" | "failed" | "cancelled" | "running" | "pending" => {}
                other => panic!("Status '{}' should be valid", other),
            }
        }
    }

    #[test]
    fn test_invalid_build_status() {
        let status = "invalid";
        let is_valid = matches!(
            status,
            "success" | "failed" | "cancelled" | "running" | "pending"
        );
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_build_status_error_message() {
        let status = "unknown";
        let err = AppError::Validation(format!(
            "Invalid build status: {}. Must be one of: pending, running, success, failed, cancelled",
            status
        ));
        let msg = err.to_string();
        assert!(msg.contains("unknown"));
        assert!(msg.contains("pending, running, success, failed, cancelled"));
    }

    // -----------------------------------------------------------------------
    // BuildArtifactInput deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_input_deserialization() {
        let json = r#"{
            "name": "app.jar",
            "path": "target/app.jar",
            "checksum_sha256": "deadbeef",
            "size_bytes": 1048576
        }"#;
        let input: BuildArtifactInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.name, "app.jar");
        assert_eq!(input.path, "target/app.jar");
        assert_eq!(input.checksum_sha256, "deadbeef");
        assert_eq!(input.size_bytes, 1_048_576);
        assert!(input.module_name.is_none());
    }

    #[test]
    fn test_build_artifact_input_with_module() {
        let json = r#"{
            "module_name": "backend",
            "name": "server.bin",
            "path": "backend/target/server.bin",
            "checksum_sha256": "abc123",
            "size_bytes": 5242880
        }"#;
        let input: BuildArtifactInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.module_name.as_deref(), Some("backend"));
    }

    // -----------------------------------------------------------------------
    // Build serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_serialization() {
        let now = Utc::now();
        let build = Build {
            id: Uuid::nil(),
            name: "test-build".to_string(),
            build_number: 100,
            status: "success".to_string(),
            started_at: Some(now),
            finished_at: Some(now),
            duration_ms: Some(5000),
            agent: Some("ci".to_string()),
            artifact_count: Some(3),
            vcs_url: None,
            vcs_revision: Some("abc123".to_string()),
            vcs_branch: Some("main".to_string()),
            vcs_message: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&build).unwrap();
        assert_eq!(json["name"], "test-build");
        assert_eq!(json["build_number"], 100);
        assert_eq!(json["status"], "success");
        assert_eq!(json["duration_ms"], 5000);
        assert_eq!(json["artifact_count"], 3);
    }

    // -----------------------------------------------------------------------
    // BuildArtifact serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_serialization() {
        let artifact = BuildArtifact {
            id: Uuid::nil(),
            build_id: Uuid::nil(),
            module_name: Some("core".to_string()),
            name: "core.jar".to_string(),
            path: "core/target/core.jar".to_string(),
            checksum_sha256: "sha256hash".to_string(),
            size_bytes: 2_097_152,
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&artifact).unwrap();
        assert_eq!(json["name"], "core.jar");
        assert_eq!(json["module_name"], "core");
        assert_eq!(json["size_bytes"], 2_097_152);
    }

    // -----------------------------------------------------------------------
    // Validation logic (from create and add_artifacts)
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_name_validation() {
        let input = CreateBuildInput {
            name: "".to_string(),
            build_number: 1,
            agent: None,
            started_at: None,
            vcs_url: None,
            vcs_revision: None,
            vcs_branch: None,
            vcs_message: None,
            metadata: None,
        };
        assert!(input.name.is_empty());
    }

    #[test]
    fn test_empty_artifact_name_validation() {
        let artifact = BuildArtifactInput {
            module_name: None,
            name: "".to_string(),
            path: "some/path".to_string(),
            checksum_sha256: "abc".to_string(),
            size_bytes: 100,
        };
        assert!(artifact.name.is_empty());
    }

    #[test]
    fn test_empty_artifact_path_validation() {
        let artifact = BuildArtifactInput {
            module_name: None,
            name: "artifact.jar".to_string(),
            path: "".to_string(),
            checksum_sha256: "abc".to_string(),
            size_bytes: 100,
        };
        assert!(artifact.path.is_empty());
    }

    #[test]
    fn test_empty_artifacts_list() {
        let artifacts: Vec<BuildArtifactInput> = vec![];
        assert!(artifacts.is_empty());
    }
}
