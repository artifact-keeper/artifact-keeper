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
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::migration::MigrationConfig;
use crate::services::artifactory_client::{
    ArtifactoryAuth, ArtifactoryClient, ArtifactoryClientConfig,
};
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

/// Return the migration encryption key from the environment, or error if unset.
fn migration_encryption_key() -> Result<String> {
    std::env::var("MIGRATION_ENCRYPTION_KEY").map_err(|_| {
        AppError::Internal(
            "MIGRATION_ENCRYPTION_KEY is not set. \
             Configure this environment variable before using migration features."
                .to_string(),
        )
    })
}
use crate::services::migration_service::MigrationService;
use crate::services::migration_worker::{ConflictResolution, MigrationWorker, WorkerConfig};
use crate::services::nexus_client::{NexusAuth, NexusClient, NexusClientConfig};
use crate::services::source_registry::SourceRegistry;

use crate::api::validation::validate_outbound_url;

/// Create the migration router
pub fn router() -> Router<SharedState> {
    Router::new()
        // Source connections
        .route(
            "/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/connections/:id",
            get(get_connection).delete(delete_connection),
        )
        .route("/connections/:id/test", post(test_connection))
        .route(
            "/connections/:id/repositories",
            get(list_source_repositories),
        )
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

#[derive(Debug, FromRow, ToSchema)]
pub struct SourceConnectionRow {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub credentials_enc: Vec<u8>,
    pub source_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, FromRow, ToSchema)]
pub struct MigrationJobRow {
    pub id: Uuid,
    pub source_connection_id: Uuid,
    pub status: String,
    pub job_type: String,
    #[schema(value_type = Object)]
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

#[derive(Debug, FromRow, ToSchema)]
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
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, FromRow, ToSchema)]
pub struct MigrationReportRow {
    pub id: Uuid,
    pub job_id: Uuid,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub summary: serde_json::Value,
    #[schema(value_type = Object)]
    pub warnings: serde_json::Value,
    #[schema(value_type = Object)]
    pub errors: serde_json::Value,
    #[schema(value_type = Object)]
    pub recommendations: serde_json::Value,
}

// ============ Request/Response DTOs ============

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConnectionRequest {
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub credentials: ConnectionCredentials,
    /// Source registry type: "artifactory" (default) or "nexus"
    pub source_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ConnectionCredentials {
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub auth_type: String,
    pub source_type: String,
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
            source_type: row.source_type,
            created_at: row.created_at,
            verified_at: row.verified_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub message: String,
    pub artifactory_version: Option<String>,
    pub license_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SourceRepository {
    pub key: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    pub package_type: String,
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMigrationRequest {
    pub source_connection_id: Uuid,
    pub job_type: Option<String>,
    #[schema(value_type = Object)]
    pub config: MigrationConfig,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListMigrationsQuery {
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListItemsQuery {
    pub status: Option<String>,
    pub item_type: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ReportQuery {
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub pagination: Option<PaginationInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaginationInfo {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MigrationJobResponse {
    pub id: Uuid,
    pub source_connection_id: Uuid,
    pub status: String,
    pub job_type: String,
    #[schema(value_type = Object)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct MigrationReportResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub summary: serde_json::Value,
    #[schema(value_type = Object)]
    pub warnings: serde_json::Value,
    #[schema(value_type = Object)]
    pub errors: serde_json::Value,
    #[schema(value_type = Object)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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
#[utoipa::path(
    get,
    path = "/connections",
    context_path = "/api/v1/migrations",
    tag = "migration",
    responses(
        (status = 200, description = "List of source connections", body = Vec<ConnectionResponse>),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
        SELECT id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at
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
#[utoipa::path(
    post,
    path = "/connections",
    context_path = "/api/v1/migrations",
    tag = "migration",
    request_body = CreateConnectionRequest,
    responses(
        (status = 201, description = "Connection created successfully", body = ConnectionResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn create_connection(
    State(state): State<SharedState>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<(StatusCode, Json<ConnectionResponse>)> {
    // Validate URL to prevent SSRF when migration fetches from this source
    validate_outbound_url(&req.url, "Migration source URL")?;

    // Encrypt credentials before storing
    let credentials_json = serde_json::to_string(&req.credentials)?;
    let encryption_key = migration_encryption_key()?;
    let credentials_enc = encrypt_credentials(&credentials_json, &encryption_key);

    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at
        "#,
    )
    .bind(&req.name)
    .bind(&req.url)
    .bind(&req.auth_type)
    .bind(&credentials_enc)
    .bind(req.source_type.as_deref().unwrap_or("artifactory"))
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(connection.into())))
}

/// Get a specific source connection
#[utoipa::path(
    get,
    path = "/connections/{id}",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Connection ID")
    ),
    responses(
        (status = 200, description = "Connection details", body = ConnectionResponse),
        (status = 404, description = "Connection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn get_connection(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionResponse>> {
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at
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
#[utoipa::path(
    delete,
    path = "/connections/{id}",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Connection ID")
    ),
    responses(
        (status = 204, description = "Connection deleted successfully"),
        (status = 404, description = "Connection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/connections/{id}/test",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Connection ID")
    ),
    responses(
        (status = 200, description = "Connection test result", body = ConnectionTestResult),
        (status = 404, description = "Connection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn test_connection(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionTestResult>> {
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at
        FROM source_connections
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    // Create source registry client
    let client = match create_source_client(&connection) {
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

/// Build a `WorkerConfig` from a `MigrationConfig`, clamping values to sane minimums.
fn build_worker_config(config: &MigrationConfig) -> WorkerConfig {
    WorkerConfig {
        concurrency: config.concurrent_transfers.max(1) as usize,
        throttle_delay_ms: config.throttle_delay_ms.max(0) as u64,
        dry_run: config.dry_run,
        ..Default::default()
    }
}

/// Parse a `MigrationConfig` from the JSON value stored on a job row, falling
/// back to defaults when the value cannot be deserialized.
fn parse_migration_config(config_json: &serde_json::Value) -> MigrationConfig {
    serde_json::from_value(config_json.clone()).unwrap_or_default()
}

/// Extract the `ConflictResolution` strategy from a `MigrationConfig`.
fn resolve_conflict_strategy(config: &MigrationConfig) -> ConflictResolution {
    ConflictResolution::from_str(&config.conflict_resolution)
}

/// Mark a migration job as failed in the database. Best-effort: errors are
/// logged but not propagated because this is typically called from a spawned
/// task that has no caller to return an error to.
async fn mark_job_failed(db: &sqlx::PgPool, job_id: Uuid, error_msg: &str) {
    let _ = sqlx::query(
        "UPDATE migration_jobs SET status = 'failed', finished_at = NOW(), error_summary = $2 WHERE id = $1",
    )
    .bind(job_id)
    .bind(error_msg)
    .execute(db)
    .await;
}

/// Fetch a source connection by ID and construct the appropriate registry
/// client (Artifactory or Nexus). Returns the client wrapped in an `Arc`.
async fn fetch_connection_and_client(
    db: &sqlx::PgPool,
    connection_id: Uuid,
) -> Result<Arc<dyn SourceRegistry>> {
    let connection: SourceConnectionRow = sqlx::query_as(
        "SELECT id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at FROM source_connections WHERE id = $1",
    )
    .bind(connection_id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    create_source_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))
}

/// Which migration worker method to invoke inside the spawned task.
enum MigrationAction {
    Start,
    Resume,
}

/// Spawn a migration worker on a background task. This is the single place
/// that creates a `MigrationWorker`, runs either `process_job` or
/// `resume_job`, and marks the job as failed when an error occurs. Callers
/// only need to specify the action (start vs. resume).
fn spawn_migration_worker(
    db: sqlx::PgPool,
    job_id: Uuid,
    client: Arc<dyn SourceRegistry>,
    storage: Arc<dyn crate::storage::StorageBackend>,
    worker_config: WorkerConfig,
    conflict_resolution: ConflictResolution,
    action: MigrationAction,
) {
    tokio::spawn(async move {
        let cancel_token = CancellationToken::new();
        let worker = MigrationWorker::new(db.clone(), storage, worker_config, cancel_token);
        let result = match action {
            MigrationAction::Start => {
                worker
                    .process_job(job_id, client, conflict_resolution, None)
                    .await
            }
            MigrationAction::Resume => {
                worker
                    .resume_job(job_id, client, conflict_resolution, None)
                    .await
            }
        };
        if let Err(e) = result {
            tracing::error!(job_id = %job_id, error = %e, "Migration worker failed");
            mark_job_failed(&db, job_id, &e.to_string()).await;
        }
    });
}

/// Execute a pre-migration assessment. This is the core logic that runs inside
/// the spawned task; extracting it into its own function makes the assessment
/// pipeline unit-testable without requiring a real database or tokio::spawn.
async fn execute_assessment(
    db: sqlx::PgPool,
    job_id: Uuid,
    connection_id: Uuid,
    client: Arc<dyn SourceRegistry>,
) {
    let service = MigrationService::new(db.clone());
    match service.run_assessment(connection_id, client.as_ref()).await {
        Ok(result) => {
            if let Err(e) = service.save_assessment(job_id, &result).await {
                tracing::error!(job_id = %job_id, error = %e, "Failed to save assessment results");
                mark_job_failed(&db, job_id, &format!("Failed to save assessment: {}", e)).await;
            }
        }
        Err(e) => {
            tracing::error!(job_id = %job_id, error = %e, "Assessment worker failed");
            mark_job_failed(&db, job_id, &e.to_string()).await;
        }
    }
}

/// Create the appropriate source registry client based on connection type
fn create_source_client(
    connection: &SourceConnectionRow,
) -> std::result::Result<Arc<dyn SourceRegistry>, String> {
    match connection.source_type.as_str() {
        "nexus" => {
            let encryption_key = std::env::var("MIGRATION_ENCRYPTION_KEY")
                .map_err(|_| "MIGRATION_ENCRYPTION_KEY is not set".to_string())?;
            let credentials_json =
                decrypt_credentials(&connection.credentials_enc, &encryption_key)
                    .map_err(|e| format!("Failed to decrypt credentials: {}", e))?;
            let creds: ConnectionCredentials = serde_json::from_str(&credentials_json)
                .map_err(|e| format!("Failed to parse credentials: {}", e))?;

            let config = NexusClientConfig {
                base_url: connection.url.clone(),
                auth: NexusAuth {
                    username: creds.username.unwrap_or_default(),
                    password: creds.password.unwrap_or_default(),
                },
                ..Default::default()
            };
            let client = NexusClient::new(config)
                .map_err(|e| format!("Failed to create Nexus client: {}", e))?;
            Ok(Arc::new(client))
        }
        _ => {
            // Default: Artifactory
            let client = create_artifactory_client(connection)?;
            Ok(Arc::new(client))
        }
    }
}

/// Helper to create an Artifactory client from a connection row
fn create_artifactory_client(
    connection: &SourceConnectionRow,
) -> std::result::Result<ArtifactoryClient, String> {
    // Decrypt credentials
    let encryption_key = std::env::var("MIGRATION_ENCRYPTION_KEY")
        .map_err(|_| "MIGRATION_ENCRYPTION_KEY is not set".to_string())?;

    let credentials_json = decrypt_credentials(&connection.credentials_enc, &encryption_key)
        .map_err(|e| format!("Failed to decrypt credentials: {}", e))?;

    let creds: ConnectionCredentials = serde_json::from_str(&credentials_json)
        .map_err(|e| format!("Failed to parse credentials: {}", e))?;

    let auth = match connection.auth_type.as_str() {
        "api_token" => {
            let token = creds
                .token
                .ok_or_else(|| "API token missing from credentials".to_string())?;
            ArtifactoryAuth::ApiToken(token)
        }
        "basic_auth" => {
            let username = creds
                .username
                .ok_or_else(|| "Username missing from credentials".to_string())?;
            let password = creds
                .password
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

    ArtifactoryClient::new(config).map_err(|e| format!("Failed to create client: {}", e))
}

/// List repositories from Artifactory source
#[utoipa::path(
    get,
    path = "/connections/{id}/repositories",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Connection ID")
    ),
    responses(
        (status = 200, description = "List of source repositories", body = Vec<SourceRepository>),
        (status = 404, description = "Connection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn list_source_repositories(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ListResponse<SourceRepository>>> {
    // Fetch connection
    let connection: SourceConnectionRow = sqlx::query_as(
        r#"
        SELECT id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at
        FROM source_connections
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    // Create source registry client
    let client = create_source_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))?;

    // List repositories from source
    let repos = client
        .list_repositories()
        .await
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
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(ListMigrationsQuery),
    responses(
        (status = 200, description = "List of migration jobs", body = Vec<MigrationJobResponse>),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/migrations",
    tag = "migration",
    request_body = CreateMigrationRequest,
    responses(
        (status = 201, description = "Migration job created successfully", body = MigrationJobResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Migration job details", body = MigrationJobResponse),
        (status = 404, description = "Migration job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 204, description = "Migration job deleted successfully"),
        (status = 404, description = "Migration job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/{id}/start",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Migration job started", body = MigrationJobResponse),
        (status = 404, description = "Migration job not found"),
        (status = 409, description = "Migration cannot be started (wrong state)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

    let client = fetch_connection_and_client(&state.db, job.source_connection_id).await?;

    let config = parse_migration_config(&job.config);
    let conflict_resolution = resolve_conflict_strategy(&config);
    let storage = state.storage_for_repo(&crate::storage::StorageLocation {
        backend: state.config.storage_backend.clone(),
        path: state.config.storage_path.clone(),
    })?;
    let worker_config = build_worker_config(&config);

    spawn_migration_worker(
        state.db.clone(),
        job.id,
        client,
        storage,
        worker_config,
        conflict_resolution,
        MigrationAction::Start,
    );

    Ok(Json(job.into()))
}

/// Pause a migration job
#[utoipa::path(
    post,
    path = "/{id}/pause",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Migration job paused", body = MigrationJobResponse),
        (status = 409, description = "Migration cannot be paused (wrong state)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/{id}/resume",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Migration job resumed", body = MigrationJobResponse),
        (status = 409, description = "Migration cannot be resumed (wrong state)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

    let client = fetch_connection_and_client(&state.db, job.source_connection_id).await?;

    let config = parse_migration_config(&job.config);
    let conflict_resolution = resolve_conflict_strategy(&config);
    let storage = state.storage_for_repo(&crate::storage::StorageLocation {
        backend: state.config.storage_backend.clone(),
        path: state.config.storage_path.clone(),
    })?;
    let worker_config = build_worker_config(&config);

    spawn_migration_worker(
        state.db.clone(),
        job.id,
        client,
        storage,
        worker_config,
        conflict_resolution,
        MigrationAction::Resume,
    );

    Ok(Json(job.into()))
}

/// Cancel a migration job
#[utoipa::path(
    post,
    path = "/{id}/cancel",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Migration job cancelled", body = MigrationJobResponse),
        (status = 409, description = "Migration cannot be cancelled (wrong state)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}/stream",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "SSE stream of migration progress"),
        (status = 404, description = "Migration job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}/items",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID"),
        ListItemsQuery,
    ),
    responses(
        (status = 200, description = "List of migration items", body = Vec<MigrationItemResponse>),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}/report",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID"),
        ReportQuery,
    ),
    responses(
        (status = 200, description = "Migration report", body = MigrationReportResponse),
        (status = 404, description = "Migration report not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/{id}/assess",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 202, description = "Assessment started", body = MigrationJobResponse),
        (status = 409, description = "Cannot start assessment (wrong state)"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

    let client = fetch_connection_and_client(&state.db, job.source_connection_id).await?;

    // Spawn the assessment worker
    let db = state.db.clone();
    let job_id = job.id;
    let connection_id = job.source_connection_id;
    tokio::spawn(execute_assessment(db, job_id, connection_id, client));

    Ok((StatusCode::ACCEPTED, Json(job.into())))
}

/// Get assessment results
#[utoipa::path(
    get,
    path = "/{id}/assessment",
    context_path = "/api/v1/migrations",
    tag = "migration",
    params(
        ("id" = Uuid, Path, description = "Migration job ID")
    ),
    responses(
        (status = 200, description = "Assessment results", body = AssessmentResult),
        (status = 404, description = "Migration job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SourceConnectionRow -> ConnectionResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_response_from_row() {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = SourceConnectionRow {
            id,
            name: "My Artifactory".to_string(),
            url: "https://artifactory.example.com".to_string(),
            auth_type: "api_token".to_string(),
            credentials_enc: vec![1, 2, 3],
            source_type: "artifactory".to_string(),
            created_at: now,
            created_by: Some(Uuid::new_v4()),
            verified_at: Some(now),
        };
        let response: ConnectionResponse = row.into();
        assert_eq!(response.id, id);
        assert_eq!(response.name, "My Artifactory");
        assert_eq!(response.url, "https://artifactory.example.com");
        assert_eq!(response.auth_type, "api_token");
        assert_eq!(response.source_type, "artifactory");
        assert!(response.verified_at.is_some());
    }

    #[test]
    fn test_connection_response_no_verified_at() {
        let row = SourceConnectionRow {
            id: Uuid::new_v4(),
            name: "Nexus".to_string(),
            url: "https://nexus.local".to_string(),
            auth_type: "basic_auth".to_string(),
            credentials_enc: vec![],
            source_type: "nexus".to_string(),
            created_at: chrono::Utc::now(),
            created_by: None,
            verified_at: None,
        };
        let response: ConnectionResponse = row.into();
        assert!(response.verified_at.is_none());
        assert_eq!(response.source_type, "nexus");
    }

    // -----------------------------------------------------------------------
    // MigrationJobRow -> MigrationJobResponse conversion (progress calculation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_job_response_progress_zero_total() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "pending".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({}),
            total_items: 0,
            completed_items: 0,
            failed_items: 0,
            skipped_items: 0,
            total_bytes: 0,
            transferred_bytes: 0,
            started_at: None,
            finished_at: None,
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: None,
        };
        let response: MigrationJobResponse = row.into();
        assert_eq!(response.progress_percent, 0.0);
        assert_eq!(response.status, "pending");
    }

    #[test]
    fn test_migration_job_response_progress_half_done() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "running".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({}),
            total_items: 100,
            completed_items: 40,
            failed_items: 5,
            skipped_items: 5,
            total_bytes: 1000,
            transferred_bytes: 500,
            started_at: Some(chrono::Utc::now()),
            finished_at: None,
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: None,
        };
        let response: MigrationJobResponse = row.into();
        // done = 40 + 5 + 5 = 50, progress = 50/100 * 100 = 50.0
        assert!((response.progress_percent - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_migration_job_response_progress_complete() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "completed".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({}),
            total_items: 200,
            completed_items: 195,
            failed_items: 3,
            skipped_items: 2,
            total_bytes: 50000,
            transferred_bytes: 50000,
            started_at: Some(chrono::Utc::now()),
            finished_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: None,
        };
        let response: MigrationJobResponse = row.into();
        // done = 195 + 3 + 2 = 200, progress = 200/200 * 100 = 100.0
        assert!((response.progress_percent - 100.0).abs() < f64::EPSILON);
        assert!(response.finished_at.is_some());
    }

    #[test]
    fn test_migration_job_response_with_error() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "failed".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({"include_repos": ["docker-local"]}),
            total_items: 10,
            completed_items: 3,
            failed_items: 7,
            skipped_items: 0,
            total_bytes: 1024,
            transferred_bytes: 300,
            started_at: Some(chrono::Utc::now()),
            finished_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: Some("Connection timeout".to_string()),
        };
        let response: MigrationJobResponse = row.into();
        assert_eq!(response.status, "failed");
        assert_eq!(
            response.error_summary,
            Some("Connection timeout".to_string())
        );
        // done = 3 + 7 + 0 = 10, progress = 100%
        assert!((response.progress_percent - 100.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // MigrationItemRow -> MigrationItemResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_item_response_from_row() {
        let job_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let row = MigrationItemRow {
            id: item_id,
            job_id,
            item_type: "artifact".to_string(),
            source_path: "docker-local/image:latest".to_string(),
            target_path: Some("docker-hosted/image:latest".to_string()),
            status: "completed".to_string(),
            size_bytes: 5000,
            checksum_source: Some("sha256:abc".to_string()),
            checksum_target: Some("sha256:abc".to_string()),
            metadata: Some(serde_json::json!({"format": "docker"})),
            error_message: None,
            retry_count: 0,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
        };
        let response: MigrationItemResponse = row.into();
        assert_eq!(response.id, item_id);
        assert_eq!(response.job_id, job_id);
        assert_eq!(response.item_type, "artifact");
        assert_eq!(response.status, "completed");
        assert_eq!(response.size_bytes, 5000);
        assert!(response.error_message.is_none());
    }

    #[test]
    fn test_migration_item_response_failed() {
        let row = MigrationItemRow {
            id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            item_type: "artifact".to_string(),
            source_path: "npm-remote/express".to_string(),
            target_path: None,
            status: "failed".to_string(),
            size_bytes: 0,
            checksum_source: None,
            checksum_target: None,
            metadata: None,
            error_message: Some("Download failed: 404".to_string()),
            retry_count: 3,
            started_at: Some(chrono::Utc::now()),
            completed_at: None,
        };
        let response: MigrationItemResponse = row.into();
        assert_eq!(response.status, "failed");
        assert_eq!(
            response.error_message,
            Some("Download failed: 404".to_string())
        );
        assert_eq!(response.retry_count, 3);
        assert!(response.target_path.is_none());
    }

    // -----------------------------------------------------------------------
    // MigrationReportRow -> MigrationReportResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_report_response_from_row() {
        let job_id = Uuid::new_v4();
        let report_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = MigrationReportRow {
            id: report_id,
            job_id,
            generated_at: now,
            summary: serde_json::json!({"total": 100, "completed": 95}),
            warnings: serde_json::json!(["Low disk space"]),
            errors: serde_json::json!([]),
            recommendations: serde_json::json!(["Increase bandwidth"]),
        };
        let response: MigrationReportResponse = row.into();
        assert_eq!(response.id, report_id);
        assert_eq!(response.job_id, job_id);
        assert_eq!(response.summary["total"], 100);
        assert!(response.errors.as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // ConnectionCredentials serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_credentials_token() {
        let creds = ConnectionCredentials {
            token: Some("my-api-token".to_string()),
            username: None,
            password: None,
        };
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: ConnectionCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token, Some("my-api-token".to_string()));
        assert!(parsed.username.is_none());
    }

    #[test]
    fn test_connection_credentials_basic() {
        let creds = ConnectionCredentials {
            token: None,
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
        };
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: ConnectionCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.username, Some("admin".to_string()));
        assert_eq!(parsed.password, Some("secret".to_string()));
    }

    // -----------------------------------------------------------------------
    // PaginationInfo
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_info() {
        let page_info = PaginationInfo {
            page: 2,
            per_page: 20,
            total: 100,
            total_pages: 5,
        };
        let json = serde_json::to_value(&page_info).unwrap();
        assert_eq!(json["page"], 2);
        assert_eq!(json["per_page"], 20);
        assert_eq!(json["total"], 100);
        assert_eq!(json["total_pages"], 5);
    }

    #[test]
    fn test_pagination_calculation() {
        let total = 57i64;
        let per_page = 20i64;
        let total_pages = (total + per_page - 1) / per_page;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_pagination_calculation_exact() {
        let total = 40i64;
        let per_page = 20i64;
        let total_pages = (total + per_page - 1) / per_page;
        assert_eq!(total_pages, 2);
    }

    #[test]
    fn test_pagination_calculation_zero() {
        let total = 0i64;
        let per_page = 20i64;
        let total_pages = (total + per_page - 1) / per_page;
        assert_eq!(total_pages, 0);
    }

    // -----------------------------------------------------------------------
    // ListMigrationsQuery defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_migrations_query_defaults() {
        let q: ListMigrationsQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.status.is_none());
        assert!(q.page.is_none());
        assert!(q.per_page.is_none());
    }

    #[test]
    fn test_list_migrations_query_with_values() {
        let q: ListMigrationsQuery =
            serde_json::from_str(r#"{"status":"running","page":3,"per_page":10}"#).unwrap();
        assert_eq!(q.status, Some("running".to_string()));
        assert_eq!(q.page, Some(3));
        assert_eq!(q.per_page, Some(10));
    }

    // -----------------------------------------------------------------------
    // ListItemsQuery
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_items_query() {
        let q: ListItemsQuery =
            serde_json::from_str(r#"{"status":"failed","item_type":"artifact"}"#).unwrap();
        assert_eq!(q.status, Some("failed".to_string()));
        assert_eq!(q.item_type, Some("artifact".to_string()));
    }

    // -----------------------------------------------------------------------
    // ReportQuery
    // -----------------------------------------------------------------------

    #[test]
    fn test_report_query_json() {
        let q: ReportQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.format.is_none());
    }

    #[test]
    fn test_report_query_html() {
        let q: ReportQuery = serde_json::from_str(r#"{"format":"html"}"#).unwrap();
        assert_eq!(q.format, Some("html".to_string()));
    }

    // -----------------------------------------------------------------------
    // ConnectionTestResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_test_result_success() {
        let result = ConnectionTestResult {
            success: true,
            message: "Connection successful".to_string(),
            artifactory_version: Some("7.55.0".to_string()),
            license_type: Some("Enterprise".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["artifactory_version"], "7.55.0");
    }

    #[test]
    fn test_connection_test_result_failure() {
        let result = ConnectionTestResult {
            success: false,
            message: "Connection failed: timeout".to_string(),
            artifactory_version: None,
            license_type: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["artifactory_version"].is_null());
    }

    // -----------------------------------------------------------------------
    // SourceRepository serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_source_repository_serialization() {
        let repo = SourceRepository {
            key: "docker-local".to_string(),
            repo_type: "local".to_string(),
            package_type: "docker".to_string(),
            url: "https://art.example.com/docker-local".to_string(),
            description: Some("Docker images".to_string()),
        };
        let json = serde_json::to_value(&repo).unwrap();
        assert_eq!(json["key"], "docker-local");
        assert_eq!(json["type"], "local"); // serde rename
        assert_eq!(json["package_type"], "docker");
    }

    // -----------------------------------------------------------------------
    // AssessmentResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_assessment_result_empty() {
        let result = AssessmentResult {
            job_id: Uuid::new_v4(),
            status: "assessing".to_string(),
            repositories: vec![],
            users_count: 0,
            groups_count: 0,
            permissions_count: 0,
            total_artifacts: 0,
            total_size_bytes: 0,
            estimated_duration_seconds: 0,
            warnings: vec![],
            blockers: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["repositories"].as_array().unwrap().is_empty());
        assert!(json["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_repository_assessment() {
        let assessment = RepositoryAssessment {
            key: "npm-local".to_string(),
            repo_type: "local".to_string(),
            package_type: "npm".to_string(),
            artifact_count: 500,
            total_size_bytes: 1024 * 1024 * 100,
            compatibility: "full".to_string(),
            warnings: vec!["Large repository".to_string()],
        };
        let json = serde_json::to_value(&assessment).unwrap();
        assert_eq!(json["key"], "npm-local");
        assert_eq!(json["type"], "local");
        assert_eq!(json["artifact_count"], 500);
    }

    // -----------------------------------------------------------------------
    // Offset calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_offset_calculation() {
        let page = 3i64;
        let per_page = 20i64;
        let offset = (page - 1) * per_page;
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_offset_first_page() {
        let page = 1i64;
        let per_page = 50i64;
        let offset = (page - 1) * per_page;
        assert_eq!(offset, 0);
    }

    // -----------------------------------------------------------------------
    // migration_encryption_key tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_encryption_key_returns_env_value() {
        // If the env var happens to be set, it should return its value
        if let Ok(val) = std::env::var("MIGRATION_ENCRYPTION_KEY") {
            let result = migration_encryption_key();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), val);
        }
    }

    #[test]
    fn test_migration_encryption_key_errors_when_unset() {
        // Temporarily check if the env var is unset
        if std::env::var("MIGRATION_ENCRYPTION_KEY").is_err() {
            let result = migration_encryption_key();
            assert!(result.is_err());
            let err_msg = format!("{}", result.unwrap_err());
            assert!(err_msg.contains("MIGRATION_ENCRYPTION_KEY"));
        }
    }

    // -----------------------------------------------------------------------
    // build_worker_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_worker_config_defaults() {
        let config = MigrationConfig::default();
        let wc = build_worker_config(&config);
        // Default concurrent_transfers is 0 via Default, clamped to 1
        assert!(wc.concurrency >= 1);
        assert!(!wc.dry_run);
    }

    #[test]
    fn test_build_worker_config_custom_values() {
        let config = MigrationConfig {
            concurrent_transfers: 8,
            throttle_delay_ms: 250,
            dry_run: true,
            ..Default::default()
        };
        let wc = build_worker_config(&config);
        assert_eq!(wc.concurrency, 8);
        assert_eq!(wc.throttle_delay_ms, 250);
        assert!(wc.dry_run);
    }

    #[test]
    fn test_build_worker_config_clamps_negative_concurrency() {
        let config = MigrationConfig {
            concurrent_transfers: -5,
            throttle_delay_ms: -10,
            ..Default::default()
        };
        let wc = build_worker_config(&config);
        assert_eq!(wc.concurrency, 1);
        assert_eq!(wc.throttle_delay_ms, 0);
    }

    #[test]
    fn test_build_worker_config_zero_concurrency() {
        let config = MigrationConfig {
            concurrent_transfers: 0,
            ..Default::default()
        };
        let wc = build_worker_config(&config);
        assert_eq!(wc.concurrency, 1, "concurrency of 0 should be clamped to 1");
    }

    // -----------------------------------------------------------------------
    // parse_migration_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_migration_config_valid_json() {
        let json = serde_json::json!({
            "include_repos": ["docker-local", "npm-remote"],
            "dry_run": true,
            "concurrent_transfers": 16,
            "throttle_delay_ms": 100,
            "conflict_resolution": "overwrite"
        });
        let config = parse_migration_config(&json);
        assert_eq!(config.include_repos, vec!["docker-local", "npm-remote"]);
        assert!(config.dry_run);
        assert_eq!(config.concurrent_transfers, 16);
        assert_eq!(config.throttle_delay_ms, 100);
        assert_eq!(config.conflict_resolution, "overwrite");
    }

    #[test]
    fn test_parse_migration_config_empty_json() {
        let json = serde_json::json!({});
        let config = parse_migration_config(&json);
        // Should produce defaults
        assert!(config.include_repos.is_empty());
        assert!(!config.dry_run);
        assert!(config.include_users);
        assert!(config.include_groups);
        assert!(config.include_permissions);
    }

    #[test]
    fn test_parse_migration_config_invalid_json() {
        let json = serde_json::json!("not an object");
        let config = parse_migration_config(&json);
        // Falls back to Default
        assert!(!config.dry_run);
        assert!(config.include_repos.is_empty());
    }

    #[test]
    fn test_parse_migration_config_partial_fields() {
        let json = serde_json::json!({
            "dry_run": true
        });
        let config = parse_migration_config(&json);
        assert!(config.dry_run);
        // Other fields get defaults
        assert!(config.include_users);
        assert_eq!(config.conflict_resolution, "skip");
    }

    #[test]
    fn test_parse_migration_config_null_value() {
        let json = serde_json::Value::Null;
        let config = parse_migration_config(&json);
        // Null cannot be deserialized into MigrationConfig, falls back to default
        assert!(!config.dry_run);
    }

    #[test]
    fn test_parse_migration_config_with_dates() {
        let json = serde_json::json!({
            "date_from": "2025-01-01T00:00:00Z",
            "date_to": "2025-12-31T23:59:59Z",
            "exclude_repos": ["cache-repo"]
        });
        let config = parse_migration_config(&json);
        assert!(config.date_from.is_some());
        assert!(config.date_to.is_some());
        assert_eq!(config.exclude_repos, vec!["cache-repo"]);
    }

    #[test]
    fn test_parse_migration_config_exclude_paths() {
        let json = serde_json::json!({
            "exclude_paths": ["/tmp/**", "*.bak"],
            "include_cached_remote": true
        });
        let config = parse_migration_config(&json);
        assert_eq!(config.exclude_paths.len(), 2);
        assert!(config.include_cached_remote);
    }

    // -----------------------------------------------------------------------
    // resolve_conflict_strategy
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_conflict_strategy_skip() {
        let config = MigrationConfig {
            conflict_resolution: "skip".to_string(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Skip));
    }

    #[test]
    fn test_resolve_conflict_strategy_overwrite() {
        let config = MigrationConfig {
            conflict_resolution: "overwrite".to_string(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Overwrite));
    }

    #[test]
    fn test_resolve_conflict_strategy_rename() {
        let config = MigrationConfig {
            conflict_resolution: "rename".to_string(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Rename));
    }

    #[test]
    fn test_resolve_conflict_strategy_unknown_defaults_to_skip() {
        let config = MigrationConfig {
            conflict_resolution: "unknown_strategy".to_string(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Skip));
    }

    #[test]
    fn test_resolve_conflict_strategy_case_insensitive() {
        let config = MigrationConfig {
            conflict_resolution: "OVERWRITE".to_string(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Overwrite));
    }

    #[test]
    fn test_resolve_conflict_strategy_empty_string() {
        let config = MigrationConfig {
            conflict_resolution: String::new(),
            ..Default::default()
        };
        let strategy = resolve_conflict_strategy(&config);
        assert!(matches!(strategy, ConflictResolution::Skip));
    }

    // -----------------------------------------------------------------------
    // Combined parse + resolve (integration of the two helpers)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_and_resolve_roundtrip() {
        let json = serde_json::json!({
            "conflict_resolution": "rename",
            "concurrent_transfers": 4,
            "dry_run": false
        });
        let config = parse_migration_config(&json);
        let strategy = resolve_conflict_strategy(&config);
        let wc = build_worker_config(&config);

        assert!(matches!(strategy, ConflictResolution::Rename));
        assert_eq!(wc.concurrency, 4);
        assert!(!wc.dry_run);
    }

    #[test]
    fn test_parse_and_resolve_defaults_roundtrip() {
        let json = serde_json::json!({});
        let config = parse_migration_config(&json);
        let strategy = resolve_conflict_strategy(&config);
        let wc = build_worker_config(&config);

        // Default conflict resolution is "skip"
        assert!(matches!(strategy, ConflictResolution::Skip));
        assert!(wc.concurrency >= 1);
        assert!(!wc.dry_run);
    }

    // -----------------------------------------------------------------------
    // build_worker_config with parsed config (end-to-end from JSON)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_worker_config_from_parsed_json() {
        let json = serde_json::json!({
            "concurrent_transfers": 12,
            "throttle_delay_ms": 500,
            "dry_run": true
        });
        let config = parse_migration_config(&json);
        let wc = build_worker_config(&config);
        assert_eq!(wc.concurrency, 12);
        assert_eq!(wc.throttle_delay_ms, 500);
        assert!(wc.dry_run);
    }

    #[test]
    fn test_build_worker_config_from_empty_json() {
        let json = serde_json::json!({});
        let config = parse_migration_config(&json);
        let wc = build_worker_config(&config);
        // Default concurrent_transfers is 4 via default_concurrent_transfers()
        assert_eq!(wc.concurrency, 4);
        assert!(!wc.dry_run);
    }

    // -----------------------------------------------------------------------
    // MigrationJobResponse edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_job_response_assessment_status() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "assessing".to_string(),
            job_type: "assessment".to_string(),
            config: serde_json::json!({}),
            total_items: 0,
            completed_items: 0,
            failed_items: 0,
            skipped_items: 0,
            total_bytes: 0,
            transferred_bytes: 0,
            started_at: None,
            finished_at: None,
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: None,
        };
        let response: MigrationJobResponse = row.into();
        assert_eq!(response.status, "assessing");
        assert_eq!(response.job_type, "assessment");
        assert_eq!(response.progress_percent, 0.0);
    }

    #[test]
    fn test_migration_job_response_with_all_skipped() {
        let row = MigrationJobRow {
            id: Uuid::new_v4(),
            source_connection_id: Uuid::new_v4(),
            status: "completed".to_string(),
            job_type: "full".to_string(),
            config: serde_json::json!({}),
            total_items: 50,
            completed_items: 0,
            failed_items: 0,
            skipped_items: 50,
            total_bytes: 10000,
            transferred_bytes: 0,
            started_at: Some(chrono::Utc::now()),
            finished_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            created_by: None,
            error_summary: None,
        };
        let response: MigrationJobResponse = row.into();
        assert!((response.progress_percent - 100.0).abs() < f64::EPSILON);
        assert_eq!(response.transferred_bytes, 0);
    }

    // -----------------------------------------------------------------------
    // AssessmentResult with populated data
    // -----------------------------------------------------------------------

    #[test]
    fn test_assessment_result_with_repos_and_warnings() {
        let result = AssessmentResult {
            job_id: Uuid::new_v4(),
            status: "completed".to_string(),
            repositories: vec![
                RepositoryAssessment {
                    key: "docker-local".to_string(),
                    repo_type: "local".to_string(),
                    package_type: "docker".to_string(),
                    artifact_count: 200,
                    total_size_bytes: 1024 * 1024 * 500,
                    compatibility: "full".to_string(),
                    warnings: vec![],
                },
                RepositoryAssessment {
                    key: "pypi-remote".to_string(),
                    repo_type: "remote".to_string(),
                    package_type: "pypi".to_string(),
                    artifact_count: 50,
                    total_size_bytes: 1024 * 1024 * 10,
                    compatibility: "partial".to_string(),
                    warnings: vec!["Remote cache not included".to_string()],
                },
            ],
            users_count: 15,
            groups_count: 5,
            permissions_count: 30,
            total_artifacts: 250,
            total_size_bytes: 1024 * 1024 * 510,
            estimated_duration_seconds: 3600,
            warnings: vec!["Large migration".to_string()],
            blockers: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["repositories"].as_array().unwrap().len(), 2);
        assert_eq!(json["users_count"], 15);
        assert_eq!(json["total_artifacts"], 250);
        assert_eq!(json["estimated_duration_seconds"], 3600);
        assert!(json["blockers"].as_array().unwrap().is_empty());
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_assessment_result_with_blockers() {
        let result = AssessmentResult {
            job_id: Uuid::new_v4(),
            status: "failed".to_string(),
            repositories: vec![],
            users_count: 0,
            groups_count: 0,
            permissions_count: 0,
            total_artifacts: 0,
            total_size_bytes: 0,
            estimated_duration_seconds: 0,
            warnings: vec![],
            blockers: vec![
                "Unsupported package format: custom-format".to_string(),
                "Source version too old".to_string(),
            ],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["blockers"].as_array().unwrap().len(), 2);
        assert_eq!(json["status"], "failed");
    }

    // -----------------------------------------------------------------------
    // ListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_response_with_pagination() {
        let response = ListResponse {
            items: vec!["a".to_string(), "b".to_string()],
            pagination: Some(PaginationInfo {
                page: 1,
                per_page: 10,
                total: 2,
                total_pages: 1,
            }),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 2);
        assert_eq!(json["pagination"]["total"], 2);
    }

    #[test]
    fn test_list_response_without_pagination() {
        let response: ListResponse<String> = ListResponse {
            items: vec![],
            pagination: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert!(json["pagination"].is_null());
    }

    // -----------------------------------------------------------------------
    // CreateMigrationRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_migration_request_full() {
        let json = serde_json::json!({
            "source_connection_id": "550e8400-e29b-41d4-a716-446655440000",
            "job_type": "assessment",
            "config": {
                "include_repos": ["maven-local"],
                "dry_run": true
            }
        });
        let req: CreateMigrationRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.job_type, Some("assessment".to_string()));
        assert!(req.config.dry_run);
    }

    #[test]
    fn test_create_migration_request_minimal() {
        let json = serde_json::json!({
            "source_connection_id": "550e8400-e29b-41d4-a716-446655440000",
            "config": {}
        });
        let req: CreateMigrationRequest = serde_json::from_value(json).unwrap();
        assert!(req.job_type.is_none());
        assert!(!req.config.dry_run);
    }

    // -----------------------------------------------------------------------
    // CreateConnectionRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_connection_request_artifactory() {
        let json = serde_json::json!({
            "name": "Production Artifactory",
            "url": "https://artifactory.example.com",
            "auth_type": "api_token",
            "credentials": { "token": "my-token" }
        });
        let req: CreateConnectionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "Production Artifactory");
        assert!(req.source_type.is_none());
        assert_eq!(req.credentials.token, Some("my-token".to_string()));
    }

    #[test]
    fn test_create_connection_request_nexus() {
        let json = serde_json::json!({
            "name": "Nexus Server",
            "url": "https://nexus.example.com",
            "auth_type": "basic_auth",
            "credentials": { "username": "admin", "password": "secret" },
            "source_type": "nexus"
        });
        let req: CreateConnectionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.source_type, Some("nexus".to_string()));
        assert_eq!(req.credentials.username, Some("admin".to_string()));
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_connections,
        create_connection,
        get_connection,
        delete_connection,
        test_connection,
        list_source_repositories,
        list_migrations,
        create_migration,
        get_migration,
        delete_migration,
        start_migration,
        pause_migration,
        resume_migration,
        cancel_migration,
        stream_migration_progress,
        list_migration_items,
        get_migration_report,
        run_assessment,
        get_assessment,
    ),
    components(schemas(
        SourceConnectionRow,
        MigrationJobRow,
        MigrationItemRow,
        MigrationReportRow,
        CreateConnectionRequest,
        ConnectionCredentials,
        ConnectionResponse,
        ConnectionTestResult,
        SourceRepository,
        CreateMigrationRequest,
        PaginationInfo,
        MigrationJobResponse,
        MigrationItemResponse,
        MigrationReportResponse,
        AssessmentResult,
        RepositoryAssessment,
    ))
)]
pub struct MigrationApiDoc;
