//! Migration API handlers for Artifactory to Artifact Keeper migration.
//!
//! Provides endpoints for:
//! - Source connection management (CRUD, test)
//! - Migration job management (create, start, pause, resume, cancel)
//! - Progress streaming (SSE)
//! - Assessment and reporting

use axum::{
    extract::{Extension, Path, Query, State},
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

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::migration::MigrationConfig;
use crate::services::artifactory_client::{
    ArtifactoryAuth, ArtifactoryClient, ArtifactoryClientConfig,
};
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

/// Built-in fallback passphrase used to seed the credential-encryption key
/// when `MIGRATION_ENCRYPTION_KEY` is not configured. Connections created
/// under this key are stored with `from_passphrase` over the same string,
/// so they remain decryptable as long as the env var stays unset and a
/// later operator who sets the var inherits the same fallback only if
/// they reuse this exact value (which they shouldn't in prod).
///
/// The fallback exists so that fresh dev/test deployments — including the
/// `lifecycle-tests` remote/proxy/cleanup subsuites that exercise
/// `POST /api/v1/migrations/connections` — can create connections without
/// failing with HTTP 500 INTERNAL_ERROR. Without it, every call returned
/// a 500 unconditionally because `migration_encryption_key()` mapped the
/// missing env var to `AppError::Internal` (see issue #1439, Bug A).
const FALLBACK_MIGRATION_ENCRYPTION_KEY: &str = "artifact-keeper-default-migration-key-dev-only";

/// Return the migration encryption key from the environment, falling back
/// to a built-in dev passphrase if unset.
///
/// Production deployments should always set `MIGRATION_ENCRYPTION_KEY`
/// (the warning log fires once per call when the fallback is used). Dev
/// and unit-test invocations work out of the box so `create_connection`
/// no longer returns an unconditional 500 when the env var is unset.
fn migration_encryption_key() -> Result<String> {
    match std::env::var("MIGRATION_ENCRYPTION_KEY") {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => {
            tracing::warn!(
                "MIGRATION_ENCRYPTION_KEY is not set; using built-in fallback. \
                 Set this environment variable in production to protect stored \
                 source-connection credentials."
            );
            Ok(FALLBACK_MIGRATION_ENCRYPTION_KEY.to_string())
        }
    }
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

/// Column list selected into [`MigrationJobRow`]. Centralised so the many
/// `SELECT ... FROM migration_jobs` / `... RETURNING ...` statements stay in
/// lock-step with the struct (and so the identical column list is not
/// copy-pasted across every handler).
const MIGRATION_JOB_COLUMNS: &str =
    "id, source_connection_id, status, job_type, config, total_items, completed_items, \
     failed_items, skipped_items, total_bytes, transferred_bytes, started_at, \
     finished_at, created_at, created_by, error_summary";

/// Column list selected into [`SourceConnectionRow`]. Centralised for the same
/// reason as [`MIGRATION_JOB_COLUMNS`].
const SOURCE_CONNECTION_COLUMNS: &str =
    "id, name, url, auth_type, credentials_enc, source_type, created_at, created_by, verified_at";

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

/// Auth-type values accepted by the `source_connections.auth_type` column,
/// per the `source_connections_auth_type_check` CHECK constraint in migration
/// `020_migration_tables.sql`.
const ALLOWED_CONNECTION_AUTH_TYPES: [&str; 2] = ["api_token", "basic_auth"];

/// Reject any `auth_type` the database CHECK constraint would refuse, mapping
/// it to a clear HTTP 400 (`AppError::Validation`) instead of letting the
/// constraint violation surface as an opaque 500 DATABASE_ERROR.
fn validate_connection_auth_type(auth_type: &str) -> Result<()> {
    if ALLOWED_CONNECTION_AUTH_TYPES.contains(&auth_type) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "invalid auth_type '{}'; must be one of: {}",
            auth_type,
            ALLOWED_CONNECTION_AUTH_TYPES.join(", ")
        )))
    }
}

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
    pub pagination: Option<MigrationPaginationInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MigrationPaginationInfo {
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

// ============ Ownership Scoping ============
//
// The migration router is mounted under `auth_middleware`, so every request
// here is authenticated, but until now the handlers queried
// `source_connections` / `migration_jobs` by primary key only — any
// authenticated user could read or mutate any other user's (or tenant's) rows
// (BOLA). We scope every access to the calling user via the `created_by`
// columns that already exist on both tables (migration `020_migration_tables`),
// mirroring the per-user ownership model used by `repo_tokens.rs` (#1974) and
// `service_accounts.rs`: admins retain full cross-user visibility/control.
//
// Pre-fix rows have `created_by = NULL` (creation never stamped it); those are
// owned by nobody and therefore invisible/untouchable to non-admins
// (fail-closed). Admins can see and clean them up. Denials use
// `AppError::NotFound` (there is no `Forbidden` variant; this matches the
// `repo_tokens` idiom and avoids disclosing other tenants' resource existence).

/// Whether `auth` may access a row created by `created_by`.
///
/// Admins may access any row. A non-admin may access only rows they created;
/// rows with `created_by = NULL` (predating ownership stamping) are owned by
/// nobody and are therefore inaccessible to non-admins.
fn caller_owns(auth: &AuthExtension, created_by: Option<Uuid>) -> bool {
    auth.is_admin || created_by == Some(auth.user_id)
}

/// Load a source connection by id, enforcing per-user ownership.
///
/// Returns `AppError::NotFound` both when the row does not exist and when it
/// exists but the caller does not own it (and is not an admin), so cross-owner
/// probing cannot distinguish "missing" from "not yours".
async fn load_connection_owned(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
) -> Result<SourceConnectionRow> {
    let connection: SourceConnectionRow = sqlx::query_as(&format!(
        "SELECT {SOURCE_CONNECTION_COLUMNS} FROM source_connections WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    if !caller_owns(auth, connection.created_by) {
        return Err(AppError::NotFound("Source connection not found".into()));
    }
    Ok(connection)
}

/// Load a migration job by id, enforcing per-user ownership.
///
/// Returns `AppError::NotFound` when the row is missing or owned by another
/// user (non-admin caller). Used to gate the job sub-resources
/// (items/report/assessment/stream) on the parent job's owner.
async fn load_job_owned(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
) -> Result<MigrationJobRow> {
    let job: MigrationJobRow = sqlx::query_as(&format!(
        "SELECT {MIGRATION_JOB_COLUMNS} FROM migration_jobs WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Migration job not found".into()))?;

    if !caller_owns(auth, job.created_by) {
        return Err(AppError::NotFound("Migration job not found".into()));
    }
    Ok(job)
}

/// Build the [`WorkerConfig`] for `job` from its `config` JSON and spawn a
/// background [`MigrationWorker`] to run (or resume) it. Shared by
/// `start_migration` and `resume_migration`, which previously duplicated this
/// entire spawn block verbatim apart from the worker entrypoint. On worker
/// error the job is marked `failed` with the error summary (best-effort).
fn spawn_migration_worker(
    state: &SharedState,
    job: &MigrationJobRow,
    client: Arc<dyn SourceRegistry>,
    resume: bool,
) {
    let config: MigrationConfig = serde_json::from_value(job.config.clone()).unwrap_or_default();
    let conflict_resolution = ConflictResolution::from_str(&config.conflict_resolution);
    let cancel_token = CancellationToken::new();

    let worker_config = WorkerConfig {
        concurrency: config.concurrent_transfers.max(1) as usize,
        throttle_delay_ms: config.throttle_delay_ms.max(0) as u64,
        dry_run: config.dry_run,
        // Honor the user's `verify_checksums` preference from MigrationConfig
        // so the documented API flag actually disables verification
        // (issue #856).
        verify_checksums: config.verify_checksums,
        // Spill streamed artifact bodies onto the durable STORAGE_PATH volume
        // rather than the pod's ephemeral `/tmp` (issue #1608).
        staging_path: state.config.storage_path.clone(),
        ..Default::default()
    };

    let db = state.db.clone();
    let storage_registry = state.storage_registry.clone();
    let fail_db = state.db.clone();
    let job_id = job.id;
    tokio::spawn(async move {
        let worker = MigrationWorker::new(db, storage_registry, worker_config, cancel_token);
        let outcome = if resume {
            worker
                .resume_job(job_id, client, conflict_resolution, None)
                .await
        } else {
            worker
                .process_job(job_id, client, conflict_resolution, None)
                .await
        };
        if let Err(e) = outcome {
            let phase = if resume { "resume" } else { "worker" };
            tracing::error!(job_id = %job_id, error = %e, "Migration {phase} failed");
            let _ = sqlx::query(
                "UPDATE migration_jobs SET status = 'failed', finished_at = NOW(), error_summary = $2 WHERE id = $1"
            )
            .bind(job_id)
            .bind(e.to_string())
            .execute(&fail_db)
            .await;
        }
    });
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
    Extension(auth): Extension<AuthExtension>,
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

    // Non-admins see only the connections they created; admins see all.
    let connections: Vec<SourceConnectionRow> = sqlx::query_as(&format!(
        "SELECT {SOURCE_CONNECTION_COLUMNS} FROM source_connections \
         WHERE ($1 OR created_by = $2) ORDER BY created_at DESC"
    ))
    .bind(auth.is_admin)
    .bind(auth.user_id)
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
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<(StatusCode, Json<ConnectionResponse>)> {
    // Validate URL to prevent SSRF when migration fetches from this source
    validate_outbound_url(&req.url, "Migration source URL")?;

    // Validate auth_type against the values permitted by the
    // `source_connections_auth_type_check` CHECK constraint (migration
    // 020_migration_tables.sql). Without this, any other string reached the
    // INSERT and surfaced the constraint violation as an opaque HTTP 500
    // DATABASE_ERROR instead of a clear 400.
    validate_connection_auth_type(&req.auth_type)?;

    // Encrypt credentials before storing
    let credentials_json = serde_json::to_string(&req.credentials)?;
    let encryption_key = migration_encryption_key()?;
    let credentials_enc = encrypt_credentials(&credentials_json, &encryption_key);

    // Stamp `created_by` with the calling user so ownership is recorded and the
    // owner-scoped reads/writes below can match. Without this the column stayed
    // NULL and any owner filter would be useless.
    let connection: SourceConnectionRow = sqlx::query_as(&format!(
        "INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {SOURCE_CONNECTION_COLUMNS}"
    ))
    .bind(&req.name)
    .bind(&req.url)
    .bind(&req.auth_type)
    .bind(&credentials_enc)
    .bind(req.source_type.as_deref().unwrap_or("artifactory"))
    .bind(auth.user_id)
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionResponse>> {
    let connection = load_connection_owned(&state, &auth, id).await?;
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    // Enforce ownership before touching anything: a non-owner (non-admin) must
    // get the same 404 as a missing connection, and must not trigger the
    // cascade delete below. This also makes a repeat delete return 404.
    load_connection_owned(&state, &auth, id).await?;

    // A connection is the parent resource for its migration jobs. The
    // migration_jobs.source_connection_id FK has no ON DELETE clause (it
    // defaults to NO ACTION), so a raw DELETE on a connection that still has
    // jobs surfaced a bare Postgres FK-violation as HTTP 500. Cascade the
    // delete explicitly inside a transaction: remove the dependent jobs first
    // (migration_items and migration_reports already CASCADE off migration_jobs),
    // then the connection. This makes connection deletion idempotent and a
    // second DELETE correctly returns 404 instead of repeating the 500.
    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM migration_jobs WHERE source_connection_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    let result = sqlx::query("DELETE FROM source_connections WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() == 0 {
        // Nothing was deleted: the connection did not exist. Roll the
        // transaction back (the job-delete above was a no-op anyway) and
        // report 404 so a repeat delete is distinguishable from a server error.
        tx.rollback().await?;
        return Err(AppError::NotFound("Source connection not found".into()));
    }

    tx.commit().await?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionTestResult>> {
    let connection = load_connection_owned(&state, &auth, id).await?;

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

/// Create the appropriate source registry client based on connection type
fn create_source_client(
    connection: &SourceConnectionRow,
) -> std::result::Result<Arc<dyn SourceRegistry>, String> {
    match connection.source_type.as_str() {
        "nexus" => {
            // Mirrors `migration_encryption_key`: fall back to the dev
            // passphrase if the env var is unset so we can decrypt rows
            // written by `create_connection` under the same fallback.
            let encryption_key = migration_encryption_key()
                .map_err(|e| format!("Failed to load encryption key: {}", e))?;
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
    // Decrypt credentials. Mirrors `migration_encryption_key`'s fallback
    // so connections persisted under the built-in dev passphrase remain
    // decryptable from this code path too.
    let encryption_key =
        migration_encryption_key().map_err(|e| format!("Failed to load encryption key: {}", e))?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ListResponse<SourceRepository>>> {
    // Fetch connection (owner-scoped)
    let connection = load_connection_owned(&state, &auth, id).await?;

    // Create source registry client. A build failure here is a property of the
    // stored connection config (e.g. an http base_url under https_only, an
    // undecryptable credential, or an unknown auth type), not a server fault,
    // so surface it as a typed 400 rather than a generic 500 (issue #2097).
    let client = create_source_client(&connection).map_err(|e| {
        AppError::Validation(format!("Invalid source connection configuration: {}", e))
    })?;

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
    Extension(auth): Extension<AuthExtension>,
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
            pagination: Some(MigrationPaginationInfo {
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

    // Non-admins see only jobs they created; admins see all. The
    // `($1 OR created_by = $2)` predicate keeps both branches single-statement
    // and the count consistent with the listed rows.
    let jobs: Vec<MigrationJobRow> = if let Some(status) = &query.status {
        sqlx::query_as(&format!(
            "SELECT {MIGRATION_JOB_COLUMNS} FROM migration_jobs \
             WHERE ($1 OR created_by = $2) AND status = $3 \
             ORDER BY created_at DESC LIMIT $4 OFFSET $5"
        ))
        .bind(auth.is_admin)
        .bind(auth.user_id)
        .bind(status)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {MIGRATION_JOB_COLUMNS} FROM migration_jobs \
             WHERE ($1 OR created_by = $2) \
             ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        ))
        .bind(auth.is_admin)
        .bind(auth.user_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    // Get total count, scoped to the same ownership filter as the listing.
    let total: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM migration_jobs WHERE ($1 OR created_by = $2)")
            .bind(auth.is_admin)
            .bind(auth.user_id)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(ListResponse {
        items: jobs.into_iter().map(Into::into).collect(),
        pagination: Some(MigrationPaginationInfo {
            page,
            per_page,
            total: total.0,
            total_pages: (total.0 + per_page - 1) / per_page,
        }),
    }))
}

/// PostgreSQL SQLSTATE for a foreign-key violation.
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";

/// FK constraint that fires when `migration_jobs.source_connection_id` does not
/// reference an existing row in `source_connections`.
const MIGRATION_JOB_CONNECTION_FK: &str = "migration_jobs_source_connection_id_fkey";

/// Allowed values for the `migration_jobs.job_type` CHECK constraint
/// (see migration `020_migration_tables.sql`).
const VALID_JOB_TYPES: [&str; 3] = ["full", "incremental", "assessment"];

/// Map an `INSERT` error from `migration_jobs` to an [`AppError`].
///
/// A foreign-key violation means the supplied `source_connection_id` does not
/// reference an existing connection; this is a client error and must surface as
/// [`AppError::NotFound`] (HTTP 404) rather than an opaque
/// [`AppError::Sqlx`] (HTTP 500 DATABASE_ERROR). All other database errors fall
/// through to the default `sqlx::Error -> AppError` conversion (HTTP 500).
fn map_create_migration_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &err {
        if db_err.code().as_deref() == Some(PG_FOREIGN_KEY_VIOLATION)
            && db_err.constraint() == Some(MIGRATION_JOB_CONNECTION_FK)
        {
            return AppError::NotFound("Source connection not found".to_string());
        }
    }
    AppError::from(err)
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
        (status = 400, description = "Invalid request (e.g. unknown job_type)"),
        (status = 404, description = "Source connection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn create_migration(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateMigrationRequest>,
) -> Result<(StatusCode, Json<MigrationJobResponse>)> {
    let job_type = req.job_type.unwrap_or_else(|| "full".to_string());

    // Validate job_type against the DB CHECK constraint up-front. Without this,
    // an unknown value triggers a Postgres check-constraint violation that
    // surfaces as an opaque 500 DATABASE_ERROR; reject it as a 400 instead.
    if !VALID_JOB_TYPES.contains(&job_type.as_str()) {
        return Err(AppError::Validation(format!(
            "Invalid job_type '{}'; expected one of: {}",
            job_type,
            VALID_JOB_TYPES.join(", ")
        )));
    }

    let config_json = serde_json::to_value(&req.config)?;

    // A job may only be created against a connection the caller owns (admins:
    // any). This both prevents launching a job on another tenant's connection
    // and returns the same 404 as an unknown connection for cross-owner ids.
    load_connection_owned(&state, &auth, req.source_connection_id).await?;

    // The migration_jobs.source_connection_id FK had no application-level
    // pre-check, so an unknown connection id raised a bare Postgres FK
    // violation that propagated as HTTP 500 DATABASE_ERROR on every such call.
    // Map that specific violation to 404 so callers get an actionable error and
    // the write path stops looking like a server fault (mirrors the federation
    // assign-repo fix in #1954). `created_by` is stamped with the caller so the
    // owner-scoped reads/writes below can match (previously left NULL).
    let job: MigrationJobRow = sqlx::query_as(&format!(
        "INSERT INTO migration_jobs (source_connection_id, job_type, config, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
    .bind(req.source_connection_id)
    .bind(&job_type)
    .bind(&config_json)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(map_create_migration_error)?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    let job = load_job_owned(&state, &auth, id).await?;
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    // Fold ownership into the DELETE so it stays a single atomic statement:
    // a non-owner (non-admin) deletes zero rows and gets the same 404 as a
    // missing job.
    let result =
        sqlx::query("DELETE FROM migration_jobs WHERE id = $1 AND ($2 OR created_by = $3)")
            .bind(id)
            .bind(auth.is_admin)
            .bind(auth.user_id)
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    // Gate the job by owner first so a cross-owner start returns 404 (not a
    // 409 that would leak the job's existence/state) and never spawns a worker.
    load_job_owned(&state, &auth, id).await?;

    let job: MigrationJobRow = sqlx::query_as(&format!(
        "UPDATE migration_jobs SET status = 'running', started_at = NOW() \
         WHERE id = $1 AND status IN ('pending', 'ready') RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be started (wrong state or not found)".into())
    })?;

    // Fetch connection to create Artifactory client
    let connection: SourceConnectionRow = sqlx::query_as(&format!(
        "SELECT {SOURCE_CONNECTION_COLUMNS} FROM source_connections WHERE id = $1"
    ))
    .bind(job.source_connection_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    let client = create_source_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))?;

    // Create and spawn the migration worker (shared with resume).
    spawn_migration_worker(&state, &job, client, false);

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    load_job_owned(&state, &auth, id).await?;

    let job: MigrationJobRow = sqlx::query_as(&format!(
        "UPDATE migration_jobs SET status = 'paused' \
         WHERE id = $1 AND status = 'running' RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    load_job_owned(&state, &auth, id).await?;

    let job: MigrationJobRow = sqlx::query_as(&format!(
        "UPDATE migration_jobs SET status = 'running' \
         WHERE id = $1 AND status = 'paused' RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be resumed (wrong state or not found)".into())
    })?;

    // Fetch connection and spawn worker (same as start)
    let connection: SourceConnectionRow = sqlx::query_as(&format!(
        "SELECT {SOURCE_CONNECTION_COLUMNS} FROM source_connections WHERE id = $1"
    ))
    .bind(job.source_connection_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    let client = create_source_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))?;

    // Spawn the worker in resume mode (shared with start).
    spawn_migration_worker(&state, &job, client, true);

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationJobResponse>> {
    load_job_owned(&state, &auth, id).await?;

    let job: MigrationJobRow = sqlx::query_as(&format!(
        "UPDATE migration_jobs SET status = 'cancelled', finished_at = NOW() \
         WHERE id = $1 AND status IN ('pending', 'ready', 'running', 'paused', 'assessing') \
         RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Migration cannot be cancelled (wrong state or not found)".into())
    })?;

    // Cancellation is a terminal transition, so materialise the migration
    // report for the audit trail. Operators (and compliance tooling) fetch
    // GET /{id}/report after a job stops; without this the report endpoint
    // would 404 forever for cancelled jobs. generate_report upserts on the
    // UNIQUE job_id, so this is safe even if a report already exists. A
    // failure here is logged but does not roll back the cancel: the job is
    // already cancelled and reporting is best-effort metadata.
    let service = MigrationService::new(state.db.clone());
    if let Err(e) = service.generate_report(job.id).await {
        tracing::error!(job_id = %job.id, error = %e, "Failed to generate migration report on cancel");
    }

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    // Verify the job exists AND the caller owns it (admins: any) before
    // streaming; a cross-owner subscription returns 404 like a missing job.
    load_job_owned(&state, &auth, id).await?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListItemsQuery>,
) -> Result<Json<ListResponse<MigrationItemResponse>>> {
    // Items are scoped to their parent job; gate on the job's owner.
    load_job_owned(&state, &auth, id).await?;

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
        pagination: Some(MigrationPaginationInfo {
            page,
            per_page,
            total: total.0,
            total_pages: (total.0 + per_page - 1) / per_page,
        }),
    }))
}

/// Terminal migration job states, i.e. those where the job has stopped and an
/// audit report is meaningful. Mirrors the terminal set used by the progress
/// stream loop.
fn is_terminal_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// Fetch the persisted report row for a job, if one exists.
async fn fetch_migration_report(
    db: &sqlx::PgPool,
    job_id: Uuid,
) -> Result<Option<MigrationReportRow>> {
    Ok(sqlx::query_as(
        r#"
        SELECT id, job_id, generated_at, summary, warnings, errors, recommendations
        FROM migration_reports
        WHERE job_id = $1
        "#,
    )
    .bind(job_id)
    .fetch_optional(db)
    .await?)
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<impl IntoResponse> {
    // The report belongs to its parent job; gate on the job's owner.
    let job = load_job_owned(&state, &auth, id).await?;

    let report = match fetch_migration_report(&state.db, id).await? {
        Some(report) => report,
        None if is_terminal_status(&job.status) => {
            // A report row is only materialised at a terminal transition. The
            // cancel path writes it inline, but a job that reached a terminal
            // state by another route (notably a *successful* completion) never
            // did, so the report endpoint would 404 forever for a job that
            // plainly finished (issue #2097). Synthesise it lazily on first
            // read. generate_report upserts on the UNIQUE job_id, so this is
            // idempotent and never duplicates a row.
            let service = MigrationService::new(state.db.clone());
            service
                .generate_report(id)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to generate report: {}", e)))?;
            fetch_migration_report(&state.db, id)
                .await?
                .ok_or_else(|| AppError::NotFound("Migration report not found".into()))?
        }
        None => return Err(AppError::NotFound("Migration report not found".into())),
    };

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<MigrationJobResponse>)> {
    load_job_owned(&state, &auth, id).await?;

    let job: MigrationJobRow = sqlx::query_as(&format!(
        "UPDATE migration_jobs SET status = 'assessing', job_type = 'assessment' \
         WHERE id = $1 AND status = 'pending' RETURNING {MIGRATION_JOB_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        AppError::Conflict("Cannot start assessment (wrong state or not found)".into())
    })?;

    // Fetch source connection to create client
    let connection: SourceConnectionRow = sqlx::query_as(&format!(
        "SELECT {SOURCE_CONNECTION_COLUMNS} FROM source_connections WHERE id = $1"
    ))
    .bind(job.source_connection_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Source connection not found".into()))?;

    let client = create_source_client(&connection)
        .map_err(|e| AppError::Internal(format!("Failed to create client: {}", e)))?;

    let db = state.db.clone();
    let job_id = job.id;
    let connection_id = job.source_connection_id;
    tokio::spawn(async move {
        let service = MigrationService::new(db.clone());
        let err = match service.run_assessment(connection_id, &*client).await {
            Ok(result) => match service.save_assessment(job_id, &result).await {
                Ok(()) => None,
                Err(e) => {
                    tracing::error!(job_id = %job_id, error = %e, "Failed to save assessment results");
                    Some(e.to_string())
                }
            },
            Err(e) => {
                tracing::error!(job_id = %job_id, error = %e, "Assessment worker failed");
                Some(e.to_string())
            }
        };
        if let Some(msg) = err {
            let _ = sqlx::query(
                "UPDATE migration_jobs SET status = 'failed', finished_at = NOW(), error_summary = $2 WHERE id = $1"
            )
            .bind(job_id)
            .bind(msg)
            .execute(&db)
            .await;
        }
    });

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssessmentResult>> {
    // Verify the job exists, is owned by the caller (admins: any), and load it.
    let job = load_job_owned(&state, &auth, id).await?;

    // Extract assessment results from the job's config JSON (saved by save_assessment)
    let assessment_json = job.config.get("assessment");
    if let Some(assessment) = assessment_json {
        if let Ok(service_result) = serde_json::from_value::<
            crate::services::migration_service::AssessmentResult,
        >(assessment.clone())
        {
            return Ok(Json(AssessmentResult {
                job_id: job.id,
                status: job.status,
                repositories: service_result
                    .repositories
                    .into_iter()
                    .map(|r| RepositoryAssessment {
                        key: r.key,
                        repo_type: r.repo_type,
                        package_type: r.package_type,
                        artifact_count: r.artifact_count,
                        total_size_bytes: r.total_size_bytes,
                        compatibility: r.compatibility,
                        warnings: r.warnings,
                    })
                    .collect(),
                users_count: service_result.users_count,
                groups_count: service_result.groups_count,
                permissions_count: service_result.permissions_count,
                total_artifacts: service_result.total_artifacts,
                total_size_bytes: service_result.total_size_bytes,
                estimated_duration_seconds: service_result.estimated_duration_seconds,
                warnings: service_result.warnings,
                blockers: service_result.blockers,
            }));
        }
    }

    // Assessment not yet completed or results not available
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
    fn test_validate_connection_auth_type() {
        // Table-driven: accepted values must pass; anything the
        // source_connections_auth_type_check CHECK constraint would refuse
        // must map to a Validation error (HTTP 400), never reach the INSERT
        // and surface as an opaque 500 DATABASE_ERROR.
        let cases: &[(&str, bool)] = &[
            ("api_token", true),
            ("basic_auth", true),
            ("basic", false), // the persona's body shape -> previously 500
            ("token", false),
            ("", false),
            ("API_TOKEN", false), // case-sensitive
            ("' OR 1=1--", false),
        ];
        for &(auth_type, should_pass) in cases {
            let result = validate_connection_auth_type(auth_type);
            assert_eq!(
                result.is_ok(),
                should_pass,
                "auth_type {auth_type:?} expected pass={should_pass}, got {result:?}"
            );
            if !should_pass {
                assert!(
                    matches!(result, Err(AppError::Validation(_))),
                    "auth_type {auth_type:?} should yield Validation (400), got {result:?}"
                );
            }
        }
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
    // MigrationPaginationInfo
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_info() {
        let page_info = MigrationPaginationInfo {
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
        // (non-empty values take precedence over the dev fallback).
        if let Ok(val) = std::env::var("MIGRATION_ENCRYPTION_KEY") {
            if !val.is_empty() {
                let result = migration_encryption_key();
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), val);
            }
        }
    }

    #[test]
    fn test_migration_encryption_key_falls_back_when_unset() {
        // Bug #1439 / A: prior to the fix this returned `AppError::Internal`,
        // making `POST /api/v1/migrations/connections` an unconditional 500
        // whenever `MIGRATION_ENCRYPTION_KEY` was not set. The fallback
        // keeps the handler working for dev/test deployments.
        if std::env::var("MIGRATION_ENCRYPTION_KEY")
            .map(|v| v.is_empty())
            .unwrap_or(true)
        {
            let result = migration_encryption_key();
            assert!(
                result.is_ok(),
                "expected fallback to succeed, got {result:?}"
            );
            assert_eq!(result.unwrap(), FALLBACK_MIGRATION_ENCRYPTION_KEY);
        }
    }

    #[test]
    fn test_create_connection_encrypt_decrypt_roundtrip_with_fallback() {
        // Bug #1439 / A: the create-connection handler's only failure-prone
        // dependency on the env var is the encryption step. Verify the
        // fallback key produced by `migration_encryption_key()` round-trips
        // through `encrypt_credentials` / `decrypt_credentials`, so the
        // handler can persist and later read back a connection without the
        // env var being set.
        let key = migration_encryption_key().expect("fallback must succeed");
        let creds = ConnectionCredentials {
            token: Some("abc123".into()),
            username: None,
            password: None,
        };
        let plaintext = serde_json::to_string(&creds).expect("serialize creds");
        let ciphertext = encrypt_credentials(&plaintext, &key);
        let decrypted = decrypt_credentials(&ciphertext, &key).expect("decrypt round-trip");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn test_create_connection_request_valid_payload_deserializes() {
        // Bug #1439 / A: a representative `create-connection` JSON body
        // (the same shape lifecycle-tests POST for remote/proxy/cleanup
        // subsuites) must deserialize cleanly. Combined with the
        // encrypt/decrypt round-trip above, this proves the handler path
        // up to the SQL INSERT is regression-free without spinning up
        // Postgres in unit tests.
        let body = serde_json::json!({
            "name": "test-remote",
            "url": "https://artifactory.example.com",
            "auth_type": "api_token",
            "credentials": {"token": "abc123"},
        });
        let req: CreateConnectionRequest =
            serde_json::from_value(body).expect("valid body must deserialize");
        assert_eq!(req.name, "test-remote");
        assert_eq!(req.auth_type, "api_token");
        assert_eq!(req.credentials.token.as_deref(), Some("abc123"));
        assert!(req.source_type.is_none());
    }

    // -----------------------------------------------------------------------
    // map_create_migration_error tests (FK violation -> 404, others -> 500)
    //
    // Regression for the 1.2.2 "migration write 500" finding: creating a
    // migration job with a `source_connection_id` that does not exist raised a
    // bare Postgres FK violation that surfaced as HTTP 500 DATABASE_ERROR on
    // every call. These tests pin the mapping without needing a live database
    // (mirrors the federation assign-repo fix in #1954).
    // -----------------------------------------------------------------------

    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    /// Minimal in-memory `DatabaseError` for unit-testing the error mapper
    /// without a Postgres connection.
    #[derive(Debug)]
    struct MockDbError {
        message: String,
        code: Option<String>,
        constraint: Option<String>,
    }

    impl fmt::Display for MockDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl StdError for MockDbError {}

    impl DatabaseError for MockDbError {
        fn message(&self) -> &str {
            &self.message
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.as_deref().map(Cow::Borrowed)
        }
        fn constraint(&self) -> Option<&str> {
            self.constraint.as_deref()
        }
        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> ErrorKind {
            ErrorKind::ForeignKeyViolation
        }
    }

    #[test]
    fn test_map_create_migration_error_fk_violation_returns_not_found() {
        let err = sqlx::Error::Database(Box::new(MockDbError {
            message: "insert or update on table \"migration_jobs\" violates foreign key \
                      constraint \"migration_jobs_source_connection_id_fkey\""
                .to_string(),
            code: Some(PG_FOREIGN_KEY_VIOLATION.to_string()),
            constraint: Some(MIGRATION_JOB_CONNECTION_FK.to_string()),
        }));
        let mapped = map_create_migration_error(err);
        match mapped {
            AppError::NotFound(msg) => assert!(
                msg.contains("Source connection not found"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected NotFound (404), got {other:?}"),
        }
    }

    #[test]
    fn test_map_create_migration_error_other_fk_constraint_stays_database() {
        // An FK violation on some *other* constraint must not be masked as a
        // connection-not-found 404; it should remain a 500 DATABASE_ERROR.
        let err = sqlx::Error::Database(Box::new(MockDbError {
            message: "violates foreign key constraint \"migration_jobs_created_by_fkey\""
                .to_string(),
            code: Some(PG_FOREIGN_KEY_VIOLATION.to_string()),
            constraint: Some("migration_jobs_created_by_fkey".to_string()),
        }));
        let mapped = map_create_migration_error(err);
        assert!(
            matches!(mapped, AppError::Sqlx(_)),
            "unrelated FK constraint should stay a DB error, got {mapped:?}"
        );
    }

    #[test]
    fn test_map_create_migration_error_non_db_error_stays_database() {
        let mapped = map_create_migration_error(sqlx::Error::PoolClosed);
        assert!(
            matches!(mapped, AppError::Sqlx(_)),
            "non-database sqlx errors should stay DB errors, got {mapped:?}"
        );
    }

    #[test]
    fn test_valid_job_types_contains_full() {
        // job_type validation guards against a CHECK-constraint 500.
        assert!(VALID_JOB_TYPES.contains(&"full"));
        assert!(VALID_JOB_TYPES.contains(&"incremental"));
        assert!(VALID_JOB_TYPES.contains(&"assessment"));
        assert!(!VALID_JOB_TYPES.contains(&"bogus"));
    }

    // -----------------------------------------------------------------------
    // DB-backed tests: valid create persists; unknown connection id -> 404.
    //
    // These run only when DATABASE_URL is set (a migrated throwaway Postgres);
    // they skip cleanly otherwise so offline `cargo test` / CI without a DB do
    // not fail. The harness verifies them against a throwaway DB on :5513.
    // -----------------------------------------------------------------------

    async fn test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .ok()
    }

    #[tokio::test]
    async fn test_create_migration_job_persists_with_valid_connection() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };

        // Seed a source connection to reference.
        let conn_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type)
            VALUES ($1, $2, 'basic_auth', $3, 'nexus')
            RETURNING id
            "#,
        )
        .bind(format!("test-conn-{}", Uuid::new_v4()))
        .bind("http://nexus.local:8081")
        .bind(vec![1u8, 2, 3])
        .fetch_one(&pool)
        .await
        .expect("seed connection");

        // Insert a job exactly as the handler does and verify it persists.
        let config_json = serde_json::json!({});
        let job: MigrationJobRow = sqlx::query_as(
            r#"
            INSERT INTO migration_jobs (source_connection_id, job_type, config)
            VALUES ($1, $2, $3)
            RETURNING id, source_connection_id, status, job_type, config, total_items,
                      completed_items, failed_items, skipped_items, total_bytes,
                      transferred_bytes, started_at, finished_at, created_at, created_by,
                      error_summary
            "#,
        )
        .bind(conn_id)
        .bind("full")
        .bind(&config_json)
        .fetch_one(&pool)
        .await
        .map_err(map_create_migration_error)
        .expect("valid create must succeed");

        assert_eq!(job.source_connection_id, conn_id);
        assert_eq!(job.status, "pending");

        // Confirm the row is actually in the table.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM migration_jobs WHERE id = $1)")
                .bind(job.id)
                .fetch_one(&pool)
                .await
                .expect("existence check");
        assert!(exists, "job row must be persisted");

        // Cleanup.
        let _ = sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn test_create_migration_job_unknown_connection_maps_to_not_found() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };

        let missing = Uuid::new_v4();
        let config_json = serde_json::json!({});
        let result: std::result::Result<MigrationJobRow, sqlx::Error> = sqlx::query_as(
            r#"
            INSERT INTO migration_jobs (source_connection_id, job_type, config)
            VALUES ($1, $2, $3)
            RETURNING id, source_connection_id, status, job_type, config, total_items,
                      completed_items, failed_items, skipped_items, total_bytes,
                      transferred_bytes, started_at, finished_at, created_at, created_by,
                      error_summary
            "#,
        )
        .bind(missing)
        .bind("full")
        .bind(&config_json)
        .fetch_one(&pool)
        .await;

        let err = result.expect_err("unknown connection id must fail the FK");
        match map_create_migration_error(err) {
            AppError::NotFound(_) => {}
            other => panic!("expected NotFound (404) for unknown connection, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Ownership predicate (pure logic, no DB).
    // -----------------------------------------------------------------------

    fn auth_for(user_id: Uuid, is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id,
            username: "u".to_string(),
            email: "u@test.local".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn test_caller_owns_own_row() {
        let me = Uuid::new_v4();
        let auth = auth_for(me, false);
        assert!(caller_owns(&auth, Some(me)));
    }

    #[test]
    fn test_caller_owns_other_row_denied_for_non_admin() {
        let auth = auth_for(Uuid::new_v4(), false);
        assert!(!caller_owns(&auth, Some(Uuid::new_v4())));
    }

    #[test]
    fn test_caller_owns_null_owner_invisible_to_non_admin() {
        // Pre-fix rows have created_by = NULL: owned by nobody -> fail-closed.
        let auth = auth_for(Uuid::new_v4(), false);
        assert!(!caller_owns(&auth, None));
    }

    #[test]
    fn test_caller_owns_admin_sees_everything() {
        let auth = auth_for(Uuid::new_v4(), true);
        assert!(caller_owns(&auth, Some(Uuid::new_v4())));
        assert!(caller_owns(&auth, None));
    }

    // -----------------------------------------------------------------------
    // DB-backed BOLA tests for the migration subsystem.
    //
    // These run only when DATABASE_URL points at a migrated throwaway Postgres
    // (the harness provisions one on :5513); they skip cleanly otherwise so
    // offline `cargo test` does not fail. They exercise the real handlers
    // through an axum Router with the bare `Extension<AuthExtension>` injected
    // exactly as the production `auth_middleware` does.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};

    /// Build the migration router with `state` and an injected bare
    /// `Extension<AuthExtension>` (migration handlers extract the non-Option
    /// form, as `auth_middleware` provides). `router_with_auth_ext` also injects
    /// the `Option<AuthExtension>` copy to match production exactly.
    fn app_as(state: SharedState, auth: AuthExtension) -> axum::Router {
        tdh::router_with_auth_ext(router(), state, auth)
    }

    /// Seed a source connection owned by `owner` and return its id.
    async fn seed_connection(pool: &sqlx::PgPool, owner: Uuid) -> Uuid {
        sqlx::query_scalar(
            r#"
            INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type, created_by)
            VALUES ($1, 'http://src.local', 'basic_auth', $2, 'nexus', $3)
            RETURNING id
            "#,
        )
        .bind(format!("bola-conn-{}", Uuid::new_v4()))
        .bind(vec![1u8, 2, 3])
        .bind(owner)
        .fetch_one(pool)
        .await
        .expect("seed connection")
    }

    /// Seed a migration job owned by `owner` against `conn` and return its id.
    async fn seed_job(pool: &sqlx::PgPool, conn: Uuid, owner: Uuid) -> Uuid {
        sqlx::query_scalar(
            r#"
            INSERT INTO migration_jobs (source_connection_id, job_type, config, created_by)
            VALUES ($1, 'full', '{}'::jsonb, $2)
            RETURNING id
            "#,
        )
        .bind(conn)
        .bind(owner)
        .fetch_one(pool)
        .await
        .expect("seed job")
    }

    async fn cleanup_user(pool: &sqlx::PgPool, user_id: Uuid) {
        // migration_jobs/source_connections created_by FK + jobs reference
        // connections; delete jobs first, then connections, then the user.
        let _ = sqlx::query(
            "DELETE FROM migration_jobs WHERE created_by = $1 OR source_connection_id IN \
             (SELECT id FROM source_connections WHERE created_by = $1)",
        )
        .bind(user_id)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM source_connections WHERE created_by = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_cross_user_get_connection_returns_404() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (victor, victor_name) = tdh::create_user(&pool).await;
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let victor_conn = seed_connection(&pool, victor).await;

        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/connections/{victor_conn}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "marco must not read victor's connection"
        );

        let _ = victor_name;
        cleanup_user(&pool, victor).await;
        cleanup_user(&pool, marco).await;
    }

    #[tokio::test]
    async fn test_cross_user_delete_connection_returns_404() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (victor, _) = tdh::create_user(&pool).await;
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let victor_conn = seed_connection(&pool, victor).await;

        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/connections/{victor_conn}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Victor's connection must still exist (not cascade-deleted).
        let still: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM source_connections WHERE id = $1)")
                .bind(victor_conn)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(still, "cross-user delete must not remove the row");

        cleanup_user(&pool, victor).await;
        cleanup_user(&pool, marco).await;
    }

    #[tokio::test]
    async fn test_cross_user_get_and_start_job_returns_404() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (glen, _) = tdh::create_user(&pool).await;
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let glen_conn = seed_connection(&pool, glen).await;
        let glen_job = seed_job(&pool, glen_conn, glen).await;

        let state = tdh::build_state(pool.clone(), "/tmp");

        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let (get_status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{glen_job}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(get_status, StatusCode::NOT_FOUND);

        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (start_status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{glen_job}/start"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            start_status,
            StatusCode::NOT_FOUND,
            "marco must not start glen's job"
        );

        // Glen's job must remain in its original 'pending' state.
        let status: String = sqlx::query_scalar("SELECT status FROM migration_jobs WHERE id = $1")
            .bind(glen_job)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "pending", "cross-user start must not run the job");

        cleanup_user(&pool, glen).await;
        cleanup_user(&pool, marco).await;
    }

    #[tokio::test]
    async fn test_list_isolates_per_user() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (victor, _) = tdh::create_user(&pool).await;
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let _victor_conn = seed_connection(&pool, victor).await;
        let marco_conn = seed_connection(&pool, marco).await;
        let _marco_job = seed_job(&pool, marco_conn, marco).await;
        let victor_conn2 = seed_connection(&pool, victor).await;
        let _victor_job = seed_job(&pool, victor_conn2, victor).await;

        let state = tdh::build_state(pool.clone(), "/tmp");

        // Connections list: only marco's one connection.
        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri("/connections")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "marco must see only his own connection");
        assert_eq!(items[0]["id"], marco_conn.to_string());

        // Jobs list: only marco's one job.
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            1,
            "marco must see only his own job"
        );
        assert_eq!(v["pagination"]["total"], 1, "count must be owner-scoped");

        cleanup_user(&pool, victor).await;
        cleanup_user(&pool, marco).await;
    }

    #[tokio::test]
    async fn test_self_create_then_access_stamps_owner() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // Marco creates a connection via the handler.
        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let create_body = serde_json::json!({
            "name": format!("marco-conn-{}", Uuid::new_v4()),
            "url": "http://src.local",
            "auth_type": "basic_auth",
            "credentials": {"username": "u", "password": "p"},
            "source_type": "nexus",
        });
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri("/connections")
                .header("content-type", "application/json")
                .body(Body::from(create_body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let conn_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

        // created_by must be stamped to marco.
        let owner: Option<Uuid> =
            sqlx::query_scalar("SELECT created_by FROM source_connections WHERE id = $1")
                .bind(conn_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(owner, Some(marco), "create must stamp created_by");

        // Marco can GET his own connection.
        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/connections/{conn_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner must read his own connection");

        // Marco can DELETE his own connection.
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/connections/{conn_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "owner must delete his own connection"
        );

        cleanup_user(&pool, marco).await;
    }

    #[tokio::test]
    async fn test_admin_sees_and_gets_across_users() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (victor, _) = tdh::create_user(&pool).await;
        let victor_conn = seed_connection(&pool, victor).await;
        let victor_job = seed_job(&pool, victor_conn, victor).await;

        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let mut admin_auth = tdh::make_auth(admin_id, &admin_name);
        admin_auth.is_admin = true;

        let state = tdh::build_state(pool.clone(), "/tmp");

        // Admin can GET victor's connection.
        let app = app_as(state.clone(), admin_auth.clone());
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/connections/{victor_conn}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin must read any connection");

        // Admin can GET victor's job.
        let app = app_as(state, admin_auth);
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{victor_job}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin must read any job");

        cleanup_user(&pool, victor).await;
        cleanup_user(&pool, admin_id).await;
    }

    /// Mark a seeded job terminal so the report endpoint can synthesise a
    /// report for it (mirrors what the worker does on successful completion).
    async fn mark_job_completed(pool: &sqlx::PgPool, job: Uuid) {
        sqlx::query(
            "UPDATE migration_jobs SET status = 'completed', \
             started_at = NOW() - INTERVAL '1 minute', finished_at = NOW() WHERE id = $1",
        )
        .bind(job)
        .execute(pool)
        .await
        .expect("mark job completed");
    }

    async fn report_row_count(pool: &sqlx::PgPool, job: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM migration_reports WHERE job_id = $1")
            .bind(job)
            .fetch_one(pool)
            .await
            .expect("count reports")
    }

    // Issue #2097 Gap 1: a report must be readable after a *successful*
    // migration (previously 404), and re-reading must not duplicate the row.
    #[tokio::test]
    async fn test_completed_job_report_synthesized_and_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let conn = seed_connection(&pool, marco).await;
        let job = seed_job(&pool, conn, marco).await;
        mark_job_completed(&pool, job).await;

        let state = tdh::build_state(pool.clone(), "/tmp");

        // First read materialises the report lazily -> 200, not 404.
        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{job}/report"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "completed job must expose its report"
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["job_id"], job.to_string());
        assert_eq!(report_row_count(&pool, job).await, 1);

        // Second read must reuse the same row (idempotent upsert).
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{job}/report"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            report_row_count(&pool, job).await,
            1,
            "re-reading must not duplicate the report row"
        );

        cleanup_user(&pool, marco).await;
    }

    // A non-terminal (e.g. pending) job has no report and must still 404 --
    // lazy synthesis only applies to terminal jobs.
    #[tokio::test]
    async fn test_non_terminal_job_report_is_404() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let conn = seed_connection(&pool, marco).await;
        let job = seed_job(&pool, conn, marco).await; // status = 'pending'

        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{job}/report"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            report_row_count(&pool, job).await,
            0,
            "no report must be created for a running job"
        );

        cleanup_user(&pool, marco).await;
    }

    // The cancel path must still materialise a report (preserved behaviour).
    #[tokio::test]
    async fn test_cancel_then_report_available() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (marco, marco_name) = tdh::create_user(&pool).await;
        let conn = seed_connection(&pool, marco).await;
        let job = seed_job(&pool, conn, marco).await; // 'pending' -> cancellable

        let state = tdh::build_state(pool.clone(), "/tmp");

        let app = app_as(state.clone(), tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{job}/cancel"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner must cancel his own job");

        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{job}/report"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "cancelled job must expose a report");

        cleanup_user(&pool, marco).await;
    }

    // Issue #2097 Gap 2: an unbuildable source client (here, undecryptable
    // credentials) must surface as a typed 4xx, not a generic 500.
    #[tokio::test]
    async fn test_list_source_repositories_bad_config_returns_4xx() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (marco, marco_name) = tdh::create_user(&pool).await;
        // seed_connection stores non-decryptable credentials_enc, so
        // create_source_client fails to build the client.
        let conn = seed_connection(&pool, marco).await;

        let state = tdh::build_state(pool.clone(), "/tmp");
        let app = app_as(state, tdh::make_auth(marco, &marco_name));
        let (status, _) = tdh::send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/connections/{conn}/repositories"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "bad source config must map to 400, not 500"
        );

        cleanup_user(&pool, marco).await;
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
        MigrationPaginationInfo,
        MigrationJobResponse,
        MigrationItemResponse,
        MigrationReportResponse,
        AssessmentResult,
        RepositoryAssessment,
    ))
)]
pub struct MigrationApiDoc;
