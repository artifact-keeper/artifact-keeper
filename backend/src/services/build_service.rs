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
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM builds WHERE id = $1)",
        )
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
