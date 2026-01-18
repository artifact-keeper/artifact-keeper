//! Migration API handlers for Artifactory to Artifact Keeper migration.
//!
//! Provides endpoints for:
//! - Source connection management (CRUD, test)
//! - Migration job management (create, start, pause, resume, cancel)
//! - Progress streaming (SSE)
//! - Assessment and reporting

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{sse::Event, IntoResponse, Sse},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::convert::Infallible;
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::migration::MigrationConfig;
use crate::services::artifactory_client::{ArtifactoryAuth, ArtifactoryClient, ArtifactoryClientConfig};
use crate::services::encryption::{encrypt_credentials, decrypt_credentials};

/// Create the migration router
pub fn router() -> Router<SharedState> {
    Router::new()
        // Source connections
        .route("/connections", get(list_connections).post(create_connection))
        .route(
            "/connections/:id",
            get(get_connection).delete(delete_connection),
        )
        .route("/connections/:id/test", post(test_connection))
        .route("/connections/:id/repositories", get(list_source_repositories))
        // Migration jobs
        .route("/", get(list_migrations).post(create_migration))
        .route("/:id", get(get_migration).delete(delete_migration))
        .route("/:id/start", post(start_migration))
        .route("/:id/pause", post(pause_migration))
        .route("/:id/resume", post(resume_migration))
        .route("/:id/cancel", post(cancel_migration))
        .route("/:id/stream", get(stream_migration_progress))
        .route("/:id/items", get(list_migration_items))
        .route("/:id/report", get(get_migration_report))
        // Assessment
        .route("/:id/assess", post(run_assessment))
        .route("/:id/assessment", get(get_assessment))
}

// ============ Database Row Types ============

#[derive(Debug, FromRow)]
pub struct SourceConnectionRow {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub credentials_enc: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, FromRow)]
pub struct MigrationJobRow {
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
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    pub error_summary: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct MigrationItemRow {
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
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, FromRow)]
pub struct MigrationReportRow {
    pub id: Uuid,
    pub job_id: Uuid,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub summary: serde_json::Value,
    pub warnings: serde_json::Value,
    pub errors: serde_json::Value,
    pub recommendations: serde_json::Value,
}

// ============ Request/Response DTOs ============

#[derive(Debug, Deserialize)]
pub struct CreateConnectionRequest {
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub credentials: ConnectionCredentials,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConnectionCredentials {
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SourceConnectionRow> for ConnectionResponse {
    fn from(row: SourceConnectionRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            url: row.url,
            auth_type: row.auth_type,
            created_at: row.created_at,
            verified_at: row.verified_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub message: String,
    pub artifactory_version: Option<String>,
    pub license_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SourceRepository {
    pub key: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    pub package_type: String,
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMigrationRequest {
    pub source_connection_id: Uuid,
    pub job_type: Option<String>,
    pub config: MigrationConfig,
}

#[derive(Debug, Deserialize)]
pub struct ListMigrationsQuery {
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ListItemsQuery {
    pub status: Option<String>,
    pub item_type: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub pagination: Option<PaginationInfo>,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
}

#[derive(Debug, Serialize)]
pub struct MigrationJobResponse {
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
    pub progress_percent: f64,
    pub estimated_time_remaining: Option<i64>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub error_summary: Option<String>,
}

impl From<MigrationJobRow> for MigrationJobResponse {
    fn from(row: MigrationJobRow) -> Self {
        let total = row.total_items;
        let done = row.completed_items + row.failed_items + row.skipped_items;
        let progress = if total > 0 {
            done as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        Self {
            id: row.id,
            source_connection_id: row.source_connection_id,
            status: row.status,
            job_type: row.job_type,
            config: row.config,
            total_items: row.total_items,
            completed_items: row.completed_items,
            failed_items: row.failed_items,
            skipped_items: row.skipped_items,
            total_bytes: row.total_bytes,
            transferred_bytes: row.transferred_bytes,
            progress_percent: progress,
            estimated_time_remaining: None, // TODO: Calculate
            started_at: row.started_at,
            finished_at: row.finished_at,
            created_at: row.created_at,
            error_summary: row.error_summary,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationItemResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub item_type: String,
    pub source_path: String,
    pub target_path: Option<String>,
    pub status: String,
    pub size_bytes: i64,
    pub checksum_source: Option<String>,
    pub checksum_target: Option<String>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<MigrationItemRow> for MigrationItemResponse {
    fn from(row: MigrationItemRow) -> Self {
        Self {
            id: row.id,
            job_id: row.job_id,
            item_type: row.item_type,
            source_path: row.source_path,
            target_path: row.target_path,
            status: row.status,
            size_bytes: row.size_bytes,
            checksum_source: row.checksum_source,
            checksum_target: row.checksum_target,
            error_message: row.error_message,
            retry_count: row.retry_count,
            started_at: row.started_at,
            completed_at: row.completed_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationReportResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub summary: serde_json::Value,
    pub warnings: serde_json::Value,
    pub errors: serde_json::Value,
    pub recommendations: serde_json::Value,
}

impl From<MigrationReportRow> for MigrationReportResponse {
    fn from(row: MigrationReportRow) -> Self {
        Self {
            id: row.id,
            job_id: row.job_id,
            generated_at: row.generated_at,
            summary: row.summary,
            warnings: row.warnings,
            errors: row.errors,
            recommendations: row.recommendations,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AssessmentResult {
    pub job_id: Uuid,
    pub status: String,
    pub repositories: Vec<RepositoryAssessment>,
    pub users_count: i64,
    pub groups_count: i64,
    pub permissions_count: i64,
    pub total_artifacts: i64,
    pub total_size_bytes: i64,
    pub estimated_duration_seconds: i64,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RepositoryAssessment {
    pub key: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    pub package_type: String,
    pub artifact_count: i64,
    pub total_size_bytes: i64,
    pub compatibility: String,
    pub warnings: Vec<String>,
}

// ============ Handler Implementations ============

/// List all source connections for the current user
async fn list_connections(
    State(state): State<SharedState>,
) -> Result<Json<ListResponse<ConnectionResponse>>> {
    // Check if table exists
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'source_connections')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(ListResponse {
            items: vec![],
            pagination: None,
        }));
    }

    let connections: Vec<SourceConnectionRow> = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, created_at, created_by, verified_at
        FROM source_connections
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let items: Vec<ConnectionResponse> = connections.into_iter().map(Into::into).collect();

    Ok(Json(ListResponse {
        items,
        pagination: None,
    }))
}

/// Create a new source connection
async fn create_connection(
    State(state): State<SharedState>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<(StatusCode, Json<ConnectionResponse>)> {
    // Encrypt credentials before storing
    let credentials_json = serde_json::to_string(&req.credentials)?;
    let encryption_key = std::env::var("MIGRATION_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "default-migration-key-change-in-prod".to_string());
    let credentials_enc = encrypt_credentials(&credentials_json, &encryption_key);

    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        INSERT INTO source_connections (name, url, auth_type, credentials_enc)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, url, auth_type, credentials_enc, created_at, created_by, verified_at
        "#,
    )
    .bind(&req.name)
    .bind(&req.url)
    .bind(&req.auth_type)
    .bind(&credentials_enc)
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(connection.into())))
}

/// Get a specific source connection
async fn get_connection(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionResponse>> {
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, created_at, created_by, verified_at
        FROM source_connections
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    Ok(Json(connection.into()))
}

/// Delete a source connection
async fn delete_connection(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let result = sqlx::query("DELETE FROM source_connections WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Source connection not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Test connection to Artifactory
async fn test_connection(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionTestResult>> {
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, created_at, created_by, verified_at
        FROM source_connections
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    // Create Artifactory client
    let client = match create_artifactory_client(&connection) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Json(ConnectionTestResult {
                success: false,
                message: format!("Failed to create client: {}", e),
                artifactory_version: None,
                license_type: None,
            }));
        }
    };

    // Test the connection by pinging and getting version
    let ping_result = client.ping().await;

    let result = match ping_result {
        Ok(true) => {
            // Try to get version info
            match client.get_version().await {
                Ok(version_info) => ConnectionTestResult {
                    success: true,
                    message: "Connection successful".into(),
                    artifactory_version: Some(version_info.version),
                    license_type: version_info.license,
                },
                Err(_) => ConnectionTestResult {
                    success: true,
                    message: "Connection successful (version info unavailable)".into(),
                    artifactory_version: None,
                    license_type: None,
                },
            }
        }
        Ok(false) => ConnectionTestResult {
            success: false,
            message: "Artifactory ping returned unsuccessful response".into(),
            artifactory_version: None,
            license_type: None,
        },
        Err(e) => ConnectionTestResult {
            success: false,
            message: format!("Connection failed: {}", e),
            artifactory_version: None,
            license_type: None,
        },
    };

    // Update verified_at if successful
    if result.success {
        let _ = sqlx::query("UPDATE source_connections SET verified_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await;
    }

    Ok(Json(result))
}

/// Helper to create an Artifactory client from a connection row
fn create_artifactory_client(connection: &SourceConnectionRow) -> std::result::Result<ArtifactoryClient, String> {
    // Decrypt credentials
    let encryption_key = std::env::var("MIGRATION_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "default-migration-key-change-in-prod".to_string());

    let credentials_json = decrypt_credentials(&connection.credentials_enc, &encryption_key)
        .map_err(|e| format!("Failed to decrypt credentials: {}", e))?;

    let creds: ConnectionCredentials = serde_json::from_str(&credentials_json)
        .map_err(|e| format!("Failed to parse credentials: {}", e))?;

    let auth = match connection.auth_type.as_str() {
        "api_token" => {
            let token = creds.token
                .ok_or_else(|| "API token missing from credentials".to_string())?;
            ArtifactoryAuth::ApiToken(token)
        }
        "basic_auth" => {
            let username = creds.username
                .ok_or_else(|| "Username missing from credentials".to_string())?;
            let password = creds.password
                .ok_or_else(|| "Password missing from credentials".to_string())?;
            ArtifactoryAuth::BasicAuth { username, password }
        }
        other => return Err(format!("Unknown auth type: {}", other)),
    };

    let config = ArtifactoryClientConfig {
        base_url: connection.url.clone(),
        auth,
        ..Default::default()
    };

    ArtifactoryClient::new(config)
        .map_err(|e| format!("Failed to create client: {}", e))
}

/// List repositories from Artifactory source
async fn list_source_repositories(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ListResponse<SourceRepository>>> {
    // Fetch connection
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, created_at, created_by, verified_at
        FROM source_connections
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    // Create Artifactory client
    let client = create_artifactory_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))?;

    // List repositories from Artifactory
    let repos = client.list_repositories().await
        .map_err(|e| AppError::Internal(format!("Failed to list repositories: {}", e)))?;

    let items: Vec<SourceRepository> = repos
        .into_iter()
        .map(|r| SourceRepository {
            key: r.key,
            repo_type: r.repo_type,
            package_type: r.package_type,
            url: r.url.unwrap_or_default(),
            description: r.description,
        })
        .collect();

    Ok(Json(ListResponse {
        items,
        pagination: None,
    }))
}

/// List migration jobs
async fn list_migrations(
    State(state): State<SharedState>,
    Query(query): Query<ListMigrationsQuery>,
) -> Result<Json<ListResponse<MigrationJobResponse>>> {
    // Check if table exists
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'migration_jobs')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(ListResponse {
            items: vec![],
            pagination: Some(PaginationInfo {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            }),
        }));
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let offset = (page - 1) * per_page;

    let jobs: Vec<MigrationJobRow> = if let Some(status) = &query.status {
        sqlx::query_as(
            r#"
            SELECT id, source_connection_id, status, job_type, config, total_items, completed_items,
                   failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                   finished_at, created_at, created_by, error_summary
            FROM migration_jobs
            WHERE status = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(status)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, source_connection_id, status, job_type, config, total_items, completed_items,
                   failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                   finished_at, created_at, created_by, error_summary
            FROM migration_jobs
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    // Get total count
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM migration_jobs")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListResponse {
        items: jobs.into_iter().map(Into::into).collect(),
        pagination: Some(PaginationInfo {
            page,
            per_page,
            total: total.0,
            total_pages: (total.0 + per_page - 1) / per_page,
        }),
    }))
}

/// Create a new migration job
async fn create_migration(
    State(state): State<SharedState>,
    Json(req): Json<CreateMigrationRequest>,
) -> Result<(StatusCode, Json<MigrationJobResponse>)> {
    let job_type = req.job_type.unwrap_or_else(|| "full".to_string());
    let config_json = serde_json::to_value(&req.config)?;

    let job: MigrationJobRow = sqlx::query_as(
        r#"
        INSERT INTO migration_jobs (source_connection_id, job_type, config)
        VALUES ($1, $2, $3)
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(req.source_connection_id)
    .bind(&job_type)
    .bind(&config_json)
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(job.into())))
}

/// Get a specific migration job
async fn get_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        SELECT id, source_connection_id, status, job_type, config, total_items, completed_items,
               failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
               finished_at, created_at, created_by, error_summary
        FROM migration_jobs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Migration job not found".into()))?;

    Ok(Json(job.into()))
}

/// Delete a migration job
async fn delete_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let result = sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Migration job not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Start a migration job
async fn start_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        UPDATE migration_jobs
        SET status = 'running', started_at = NOW()
        WHERE id = $1 AND status IN ('pending', 'ready')
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be started (wrong state or not found)".into())
    })?;

    // TODO: Spawn background worker to process migration

    Ok(Json(job.into()))
}

/// Pause a migration job
async fn pause_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        UPDATE migration_jobs
        SET status = 'paused'
        WHERE id = $1 AND status = 'running'
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be paused (wrong state or not found)".into())
    })?;

    Ok(Json(job.into()))
}

/// Resume a paused migration job
async fn resume_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        UPDATE migration_jobs
        SET status = 'running'
        WHERE id = $1 AND status = 'paused'
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be resumed (wrong state or not found)".into())
    })?;

    // TODO: Resume background worker

    Ok(Json(job.into()))
}

/// Cancel a migration job
async fn cancel_migration(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        UPDATE migration_jobs
        SET status = 'cancelled', finished_at = NOW()
        WHERE id = $1 AND status IN ('pending', 'ready', 'running', 'paused', 'assessing')
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be cancelled (wrong state or not found)".into())
    })?;

    Ok(Json(job.into()))
}

/// Stream migration progress via Server-Sent Events
async fn stream_migration_progress(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    // Verify job exists
    let _job: MigrationJobRow = sqlx::query_as(
        r#"
        SELECT id, source_connection_id, status, job_type, config, total_items, completed_items,
               failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
               finished_at, created_at, created_by, error_summary
        FROM migration_jobs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Migration job not found".into()))?;

    let db = state.db.clone();

    // Create SSE stream that polls for progress
    let stream = async_stream::stream! {
        // Send initial connection event
        yield Ok(Event::default().event("connected").data(format!(r#"{{"job_id":"{}"}}"#, id)));

        let mut last_completed = 0i32;
        let terminal_statuses = ["completed", "failed", "cancelled"];

        loop {
            // Fetch current progress
            let result: Option<(String, i32, i32, i32, i32, i64, i64)> = sqlx::query_as(
                r#"
                SELECT status, total_items, completed_items, failed_items, skipped_items,
                       total_bytes, transferred_bytes
                FROM migration_jobs
                WHERE id = $1
                "#,
            )
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();

            match result {
                Some((status, total, completed, failed, skipped, total_bytes, transferred)) => {
                    // Calculate progress
                    let done = completed + failed + skipped;
                    let progress = if total > 0 {
                        done as f64 / total as f64 * 100.0
                    } else {
                        0.0
                    };

                    // Create progress event
                    let event_data = serde_json::json!({
                        "job_id": id.to_string(),
                        "status": status,
                        "total_items": total,
                        "completed_items": completed,
                        "failed_items": failed,
                        "skipped_items": skipped,
                        "total_bytes": total_bytes,
                        "transferred_bytes": transferred,
                        "progress_percent": progress,
                    });

                    yield Ok(Event::default().event("progress").data(event_data.to_string()));

                    // Check if job is finished
                    if terminal_statuses.contains(&status.as_str()) {
                        yield Ok(Event::default().event("complete").data(event_data.to_string()));
                        break;
                    }

                    last_completed = completed;
                }
                None => {
                    // Job was deleted
                    yield Ok(Event::default().event("error").data(r#"{"message":"Job not found"}"#));
                    break;
                }
            }

            // Poll interval
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    };

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    ))
}

/// List migration items for a job
async fn list_migration_items(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListItemsQuery>,
) -> Result<Json<ListResponse<MigrationItemResponse>>> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50);
    let offset = (page - 1) * per_page;

    // Build query based on filters
    let items: Vec<MigrationItemRow> = sqlx::query_as(
        r#"
        SELECT id, job_id, item_type, source_path, target_path, status, size_bytes,
               checksum_source, checksum_target, metadata, error_message, retry_count,
               started_at, completed_at
        FROM migration_items
        WHERE job_id = $1
        ORDER BY started_at DESC NULLS LAST
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM migration_items WHERE job_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(ListResponse {
        items: items.into_iter().map(Into::into).collect(),
        pagination: Some(PaginationInfo {
            page,
            per_page,
            total: total.0,
            total_pages: (total.0 + per_page - 1) / per_page,
        }),
    }))
}

/// Get migration report
async fn get_migration_report(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<impl IntoResponse> {
    let report: MigrationReportRow = sqlx::query_as(
        r#"
        SELECT id, job_id, generated_at, summary, warnings, errors, recommendations
        FROM migration_reports
        WHERE job_id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Migration report not found".into()))?;

    match query.format.as_deref() {
        Some("html") => {
            // TODO: Render HTML report
            Ok((
                StatusCode::OK,
                [("content-type", "text/html")],
                "<html><body>Report not yet implemented</body></html>".to_string(),
            )
                .into_response())
        }
        _ => {
            let response: MigrationReportResponse = report.into();
            Ok(Json(response).into_response())
        }
    }
}

/// Run pre-migration assessment
async fn run_assessment(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<MigrationJobResponse>)> {
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        UPDATE migration_jobs
        SET status = 'assessing', job_type = 'assessment'
        WHERE id = $1 AND status = 'pending'
        RETURNING id, source_connection_id, status, job_type, config, total_items, completed_items,
                  failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
                  finished_at, created_at, created_by, error_summary
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Cannot start assessment (wrong state or not found)".into())
    })?;

    // TODO: Spawn assessment worker

    Ok((StatusCode::ACCEPTED, Json(job.into())))
}

/// Get assessment results
async fn get_assessment(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssessmentResult>> {
    // Verify job exists and is an assessment
    let job: MigrationJobRow = sqlx::query_as(
        r#"
        SELECT id, source_connection_id, status, job_type, config, total_items, completed_items,
               failed_items, skipped_items, total_bytes, transferred_bytes, started_at,
               finished_at, created_at, created_by, error_summary
        FROM migration_jobs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Migration job not found".into()))?;

    // TODO: Return actual assessment results from database/cache
    Ok(Json(AssessmentResult {
        job_id: job.id,
        status: job.status,
        repositories: vec![],
        users_count: 0,
        groups_count: 0,
        permissions_count: 0,
        total_artifacts: 0,
        total_size_bytes: 0,
        estimated_duration_seconds: 0,
        warnings: vec![],
        blockers: vec![],
    }))
}
