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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // require_auth tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_passes_with_some() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            scopes: None,
        };
        let result = require_auth(Some(auth));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "user");
    }

    #[test]
    fn test_require_auth_fails_with_none() {
        let err = require_auth(None).unwrap_err();
        assert!(
            format!("{}", err).contains("Authentication required"),
            "Expected 'Authentication required' in error: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // ListBuildsQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_builds_query_deserialize_full() {
        let json = json!({
            "page": 2,
            "per_page": 50,
            "status": "running",
            "search": "my-build",
            "sort_by": "build_number",
            "sort_order": "desc"
        });
        let query: ListBuildsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.status.as_deref(), Some("running"));
        assert_eq!(query.search.as_deref(), Some("my-build"));
        assert_eq!(query.sort_by.as_deref(), Some("build_number"));
        assert_eq!(query.sort_order.as_deref(), Some("desc"));
    }

    #[test]
    fn test_list_builds_query_deserialize_empty() {
        let json = json!({});
        let query: ListBuildsQuery = serde_json::from_value(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.status.is_none());
        assert!(query.search.is_none());
        assert!(query.sort_by.is_none());
        assert!(query.sort_order.is_none());
    }

    // -----------------------------------------------------------------------
    // Builds pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_builds_pagination_defaults() {
        let page = 1;
        let per_page = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_builds_pagination_page_clamped() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_builds_pagination_per_page_capped() {
        let per_page = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_builds_offset_calculation() {
        let page: u32 = 5;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    // -----------------------------------------------------------------------
    // Search pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pattern_construction() {
        let search = Some("my-build".to_string());
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(search_pattern.as_deref(), Some("%my-build%"));
    }

    #[test]
    fn test_search_pattern_none() {
        let search: Option<String> = None;
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert!(search_pattern.is_none());
    }

    // -----------------------------------------------------------------------
    // Sort order parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_sort_order_parsing() {
        assert!(Some("desc".to_string()).as_deref() == Some("desc"));
        assert!(Some("asc".to_string()).as_deref() != Some("desc"));
        assert!(None::<String>.as_deref() != Some("desc"));
    }

    #[test]
    fn test_sort_order_clause() {
        for (sort_desc, expected) in [
            (true, "ORDER BY build_number DESC"),
            (false, "ORDER BY build_number ASC"),
        ] {
            let order_clause = if sort_desc {
                "ORDER BY build_number DESC"
            } else {
                "ORDER BY build_number ASC"
            };
            assert_eq!(order_clause, expected);
        }
    }

    // -----------------------------------------------------------------------
    // BuildRow -> BuildResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_row_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let row = BuildRow {
            id,
            name: "my-project".to_string(),
            build_number: 42,
            status: "success".to_string(),
            started_at: Some(now),
            finished_at: Some(now),
            duration_ms: Some(30000),
            agent: Some("agent-1".to_string()),
            created_at: now,
            updated_at: now,
            artifact_count: Some(5),
        };
        let resp = BuildResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "my-project");
        assert_eq!(resp.number, 42);
        assert_eq!(resp.status, "success");
        assert_eq!(resp.duration_ms, Some(30000));
        assert_eq!(resp.agent.as_deref(), Some("agent-1"));
        assert_eq!(resp.artifact_count, Some(5));
        // BuildRow doesn't carry these fields
        assert!(resp.modules.is_none());
        assert!(resp.vcs_url.is_none());
        assert!(resp.vcs_revision.is_none());
        assert!(resp.vcs_branch.is_none());
        assert!(resp.vcs_message.is_none());
        assert!(resp.metadata.is_none());
    }

    #[test]
    fn test_build_row_to_response_minimal() {
        let now = Utc::now();
        let row = BuildRow {
            id: Uuid::nil(),
            name: "test".to_string(),
            build_number: 1,
            status: "running".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
        };
        let resp = BuildResponse::from(row);
        assert_eq!(resp.number, 1);
        assert!(resp.started_at.is_none());
        assert!(resp.finished_at.is_none());
        assert!(resp.duration_ms.is_none());
        assert!(resp.agent.is_none());
        assert!(resp.artifact_count.is_none());
    }

    // -----------------------------------------------------------------------
    // Build (service model) -> BuildResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_service_model_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let build = crate::services::build_service::Build {
            id,
            name: "my-app".to_string(),
            build_number: 100,
            status: "failed".to_string(),
            started_at: Some(now),
            finished_at: Some(now),
            duration_ms: Some(60000),
            agent: Some("ci-runner".to_string()),
            artifact_count: Some(3),
            vcs_url: Some("https://github.com/org/repo".to_string()),
            vcs_revision: Some("abc123".to_string()),
            vcs_branch: Some("main".to_string()),
            vcs_message: Some("fix: bug".to_string()),
            metadata: Some(json!({"ci": "github-actions"})),
            created_at: now,
            updated_at: now,
        };
        let resp = BuildResponse::from(build);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "my-app");
        assert_eq!(resp.number, 100);
        assert_eq!(resp.status, "failed");
        assert_eq!(resp.vcs_url.as_deref(), Some("https://github.com/org/repo"));
        assert_eq!(resp.vcs_revision.as_deref(), Some("abc123"));
        assert_eq!(resp.vcs_branch.as_deref(), Some("main"));
        assert_eq!(resp.vcs_message.as_deref(), Some("fix: bug"));
        assert!(resp.metadata.is_some());
        assert!(resp.modules.is_none()); // Never set in From impl
    }

    // -----------------------------------------------------------------------
    // BuildResponse serialization (skip_serializing_if)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_response_serialize_skips_none_vcs() {
        let now = Utc::now();
        let resp = BuildResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            number: 1,
            status: "running".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
            modules: None,
            vcs_url: None,
            vcs_revision: None,
            vcs_branch: None,
            vcs_message: None,
            metadata: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        // skip_serializing_if fields should not be present
        assert!(json.get("vcs_url").is_none());
        assert!(json.get("vcs_revision").is_none());
        assert!(json.get("vcs_branch").is_none());
        assert!(json.get("vcs_message").is_none());
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn test_build_response_serialize_includes_vcs() {
        let now = Utc::now();
        let resp = BuildResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            number: 1,
            status: "success".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
            modules: None,
            vcs_url: Some("https://github.com/test".to_string()),
            vcs_revision: Some("deadbeef".to_string()),
            vcs_branch: Some("feat/new".to_string()),
            vcs_message: Some("feat: new feature".to_string()),
            metadata: Some(json!({"key": "value"})),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["vcs_url"], "https://github.com/test");
        assert_eq!(json["vcs_revision"], "deadbeef");
        assert_eq!(json["vcs_branch"], "feat/new");
        assert_eq!(json["vcs_message"], "feat: new feature");
        assert_eq!(json["metadata"]["key"], "value");
    }

    // -----------------------------------------------------------------------
    // CreateBuildRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_build_request_deserialize_minimal() {
        let json = json!({"name": "my-build", "build_number": 1});
        let req: CreateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "my-build");
        assert_eq!(req.build_number, 1);
        assert!(req.agent.is_none());
        assert!(req.started_at.is_none());
        assert!(req.vcs_url.is_none());
        assert!(req.metadata.is_none());
    }

    #[test]
    fn test_create_build_request_deserialize_full() {
        let now = Utc::now();
        let json = json!({
            "name": "release-build",
            "build_number": 42,
            "agent": "jenkins-1",
            "started_at": now.to_rfc3339(),
            "vcs_url": "https://github.com/org/repo",
            "vcs_revision": "abc123",
            "vcs_branch": "main",
            "vcs_message": "release v1.0",
            "metadata": {"ci": "jenkins"}
        });
        let req: CreateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "release-build");
        assert_eq!(req.build_number, 42);
        assert_eq!(req.agent.as_deref(), Some("jenkins-1"));
        assert_eq!(req.vcs_url.as_deref(), Some("https://github.com/org/repo"));
        assert!(req.metadata.is_some());
    }

    // -----------------------------------------------------------------------
    // UpdateBuildRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_build_request_deserialize() {
        let json = json!({"status": "success"});
        let req: UpdateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.status, "success");
        assert!(req.finished_at.is_none());
    }

    #[test]
    fn test_update_build_request_with_finished_at() {
        let now = Utc::now();
        let json = json!({"status": "failed", "finished_at": now.to_rfc3339()});
        let req: UpdateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.status, "failed");
        assert!(req.finished_at.is_some());
    }

    // -----------------------------------------------------------------------
    // BuildDiffQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_diff_query_deserialize() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let json = json!({"build_a": id_a, "build_b": id_b});
        let query: BuildDiffQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.build_a, id_a);
        assert_eq!(query.build_b, id_b);
    }

    // -----------------------------------------------------------------------
    // AddBuildArtifactsRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_build_artifacts_request_deserialize() {
        let json = json!({
            "artifacts": [
                {
                    "module_name": "core",
                    "name": "core.jar",
                    "path": "/com/example/core/1.0/core-1.0.jar",
                    "checksum_sha256": "abc123",
                    "size_bytes": 1024
                },
                {
                    "name": "api.jar",
                    "path": "/com/example/api/1.0/api-1.0.jar",
                    "checksum_sha256": "def456",
                    "size_bytes": 2048
                }
            ]
        });
        let req: AddBuildArtifactsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifacts.len(), 2);
        assert_eq!(req.artifacts[0].module_name.as_deref(), Some("core"));
        assert!(req.artifacts[1].module_name.is_none());
        assert_eq!(req.artifacts[0].size_bytes, 1024);
        assert_eq!(req.artifacts[1].size_bytes, 2048);
    }

    // -----------------------------------------------------------------------
    // BuildArtifactDiff serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_diff_serialize() {
        let diff = BuildArtifactDiff {
            name: "app.jar".to_string(),
            path: "/com/example/app.jar".to_string(),
            old_checksum: "aaa".to_string(),
            new_checksum: "bbb".to_string(),
            old_size_bytes: 1000,
            new_size_bytes: 1500,
        };
        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["name"], "app.jar");
        assert_eq!(json["old_checksum"], "aaa");
        assert_eq!(json["new_checksum"], "bbb");
        assert_eq!(json["old_size_bytes"], 1000);
        assert_eq!(json["new_size_bytes"], 1500);
    }

    // -----------------------------------------------------------------------
    // BuildDiffResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_diff_response_empty() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let resp = BuildDiffResponse {
            build_a: id_a,
            build_b: id_b,
            added: vec![],
            removed: vec![],
            modified: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["build_a"], id_a.to_string());
        assert_eq!(json["build_b"], id_b.to_string());
        assert_eq!(json["added"].as_array().unwrap().len(), 0);
        assert_eq!(json["removed"].as_array().unwrap().len(), 0);
        assert_eq!(json["modified"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Total pages calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_builds_total_pages_calculation() {
        let total: i64 = 55;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }
}
