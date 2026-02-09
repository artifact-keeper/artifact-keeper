//! Build management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::build_service::{
    BuildArtifactInput, BuildService, CreateBuildInput, UpdateBuildStatusInput,
};

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create build routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_builds).post(create_build))
        .route("/diff", get(get_build_diff))
        .route("/:id", get(get_build).put(update_build))
        .route("/:id/artifacts", post(add_build_artifacts))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListBuildsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifact {
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildModule {
    pub id: Uuid,
    pub name: String,
    pub artifacts: Vec<BuildArtifact>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct BuildRow {
    pub id: Uuid,
    pub name: String,
    pub build_number: i32,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
    pub agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub artifact_count: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildResponse {
    pub id: Uuid,
    pub name: String,
    pub number: i32,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
    pub agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub artifact_count: Option<i32>,
    pub modules: Option<Vec<BuildModule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

impl From<BuildRow> for BuildResponse {
    fn from(row: BuildRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            number: row.build_number,
            status: row.status,
            started_at: row.started_at,
            finished_at: row.finished_at,
            duration_ms: row.duration_ms,
            agent: row.agent,
            created_at: row.created_at,
            updated_at: row.updated_at,
            artifact_count: row.artifact_count,
            modules: None,
            vcs_url: None,
            vcs_revision: None,
            vcs_branch: None,
            vcs_message: None,
            metadata: None,
        }
    }
}

impl From<crate::services::build_service::Build> for BuildResponse {
    fn from(build: crate::services::build_service::Build) -> Self {
        Self {
            id: build.id,
            name: build.name,
            number: build.build_number,
            status: build.status,
            started_at: build.started_at,
            finished_at: build.finished_at,
            duration_ms: build.duration_ms,
            agent: build.agent,
            created_at: build.created_at,
            updated_at: build.updated_at,
            artifact_count: build.artifact_count,
            modules: None,
            vcs_url: build.vcs_url,
            vcs_revision: build.vcs_revision,
            vcs_branch: build.vcs_branch,
            vcs_message: build.vcs_message,
            metadata: build.metadata,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildListResponse {
    pub items: Vec<BuildResponse>,
    pub pagination: Pagination,
}

/// List builds
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(ListBuildsQuery),
    responses(
        (status = 200, description = "List of builds", body = BuildListResponse),
    )
)]
pub async fn list_builds(
    State(state): State<SharedState>,
    Query(query): Query<ListBuildsQuery>,
) -> Result<Json<BuildListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));
    let sort_desc = query.sort_order.as_deref() == Some("desc");

    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(BuildListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    // Build the query dynamically
    let order_clause = if sort_desc {
        "ORDER BY build_number DESC"
    } else {
        "ORDER BY build_number ASC"
    };

    let sql = format!(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, created_at, updated_at, artifact_count
        FROM builds
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR name ILIKE $2)
        {}
        OFFSET $3
        LIMIT $4
        "#,
        order_clause
    );

    let builds: Vec<BuildRow> = sqlx::query_as(&sql)
        .bind(&query.status)
        .bind(&search_pattern)
        .bind(offset)
        .bind(per_page as i64)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM builds
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR name ILIKE $2)
        "#,
    )
    .bind(&query.status)
    .bind(&search_pattern)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(BuildListResponse {
        items: builds.into_iter().map(BuildResponse::from).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a build by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    responses(
        (status = 200, description = "Build details", body = BuildResponse),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn get_build(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BuildResponse>> {
    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Build not found".to_string()));
    }

    let build: BuildRow = sqlx::query_as(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, created_at, updated_at, artifact_count
        FROM builds
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Build not found".to_string()))?;

    Ok(Json(BuildResponse::from(build)))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct BuildDiffQuery {
    pub build_a: Uuid,
    pub build_b: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifactDiff {
    pub name: String,
    pub path: String,
    pub old_checksum: String,
    pub new_checksum: String,
    pub old_size_bytes: i64,
    pub new_size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildDiffResponse {
    pub build_a: Uuid,
    pub build_b: Uuid,
    pub added: Vec<BuildArtifact>,
    pub removed: Vec<BuildArtifact>,
    pub modified: Vec<BuildArtifactDiff>,
}

/// Get diff between two builds
#[utoipa::path(
    get,
    path = "/diff",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(BuildDiffQuery),
    responses(
        (status = 200, description = "Diff between two builds", body = BuildDiffResponse),
    )
)]
pub async fn get_build_diff(
    State(_state): State<SharedState>,
    Query(query): Query<BuildDiffQuery>,
) -> Result<Json<BuildDiffResponse>> {
    // For now, return empty diff - this would require build_artifacts table
    Ok(Json(BuildDiffResponse {
        build_a: query.build_a,
        build_b: query.build_b,
        added: vec![],
        removed: vec![],
        modified: vec![],
    }))
}

// --- Write endpoints ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBuildRequest {
    pub name: String,
    pub build_number: i32,
    pub agent: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub vcs_url: Option<String>,
    pub vcs_revision: Option<String>,
    pub vcs_branch: Option<String>,
    pub vcs_message: Option<String>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

/// Create a new build (POST /api/v1/builds)
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/builds",
    tag = "builds",
    request_body = CreateBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Build created successfully", body = BuildResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn create_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateBuildRequest>,
) -> Result<Json<BuildResponse>> {
    let _auth = require_auth(auth)?;

    let service = BuildService::new(state.db.clone());
    let build = service
        .create(CreateBuildInput {
            name: payload.name,
            build_number: payload.build_number,
            agent: payload.agent,
            started_at: payload.started_at,
            vcs_url: payload.vcs_url,
            vcs_revision: payload.vcs_revision,
            vcs_branch: payload.vcs_branch,
            vcs_message: payload.vcs_message,
            metadata: payload.metadata,
        })
        .await?;

    Ok(Json(BuildResponse::from(build)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateBuildRequest {
    pub status: String,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Update build status (PUT /api/v1/builds/:id)
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    request_body = UpdateBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Build updated successfully", body = BuildResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn update_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBuildRequest>,
) -> Result<Json<BuildResponse>> {
    let _auth = require_auth(auth)?;

    let service = BuildService::new(state.db.clone());
    let build = service
        .update_status(
            id,
            UpdateBuildStatusInput {
                status: payload.status,
                finished_at: payload.finished_at,
            },
        )
        .await?;

    Ok(Json(BuildResponse::from(build)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddBuildArtifactsRequest {
    pub artifacts: Vec<BuildArtifactInputPayload>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BuildArtifactInputPayload {
    pub module_name: Option<String>,
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifactResponse {
    pub id: Uuid,
    pub build_id: Uuid,
    pub module_name: Option<String>,
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AddBuildArtifactsResponse {
    pub artifacts: Vec<BuildArtifactResponse>,
}

/// Attach artifacts to a build (POST /api/v1/builds/:id/artifacts)
#[utoipa::path(
    post,
    path = "/{id}/artifacts",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    request_body = AddBuildArtifactsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifacts added to build", body = AddBuildArtifactsResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn add_build_artifacts(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AddBuildArtifactsRequest>,
) -> Result<Json<AddBuildArtifactsResponse>> {
    let _auth = require_auth(auth)?;

    let service = BuildService::new(state.db.clone());
    let inputs: Vec<BuildArtifactInput> = payload
        .artifacts
        .into_iter()
        .map(|a| BuildArtifactInput {
            module_name: a.module_name,
            name: a.name,
            path: a.path,
            checksum_sha256: a.checksum_sha256,
            size_bytes: a.size_bytes,
        })
        .collect();

    let artifacts = service.add_artifacts(id, inputs).await?;

    let response_artifacts = artifacts
        .into_iter()
        .map(|a| BuildArtifactResponse {
            id: a.id,
            build_id: a.build_id,
            module_name: a.module_name,
            name: a.name,
            path: a.path,
            checksum_sha256: a.checksum_sha256,
            size_bytes: a.size_bytes,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(AddBuildArtifactsResponse {
        artifacts: response_artifacts,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_builds,
        get_build,
        get_build_diff,
        create_build,
        update_build,
        add_build_artifacts,
    ),
    components(schemas(
        ListBuildsQuery,
        BuildArtifact,
        BuildModule,
        BuildRow,
        BuildResponse,
        BuildListResponse,
        BuildDiffQuery,
        BuildArtifactDiff,
        BuildDiffResponse,
        CreateBuildRequest,
        UpdateBuildRequest,
        AddBuildArtifactsRequest,
        BuildArtifactInputPayload,
        BuildArtifactResponse,
        AddBuildArtifactsResponse,
    ))
)]
pub struct BuildsApiDoc;
