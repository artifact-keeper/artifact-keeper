//! Build management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create build routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_builds))
        .route("/diff", get(get_build_diff))
        .route("/:id", get(get_build))
}

#[derive(Debug, Deserialize)]
pub struct ListBuildsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildStatus {
    Pending,
    Running,
    Success,
    Failed,
    Cancelled,
}

#[derive(Debug, Serialize)]
pub struct BuildArtifact {
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct BuildModule {
    pub id: Uuid,
    pub name: String,
    pub artifacts: Vec<BuildArtifact>,
}

#[derive(Debug, Serialize)]
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
}

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct BuildListResponse {
    pub items: Vec<BuildResponse>,
    pub pagination: Pagination,
}

/// List builds
pub async fn list_builds(
    State(state): State<SharedState>,
    Query(query): Query<ListBuildsQuery>,
) -> Result<Json<BuildListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let status_filter = query.status.as_deref();
    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));
    let sort_by = query.sort_by.as_deref().unwrap_or("build_number");
    let sort_desc = query.sort_order.as_deref() == Some("desc");

    // Query builds table (assuming it exists, otherwise return empty)
    let builds_result = sqlx::query!(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, created_at, updated_at, artifact_count
        FROM builds
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR name ILIKE $2)
        ORDER BY
            CASE WHEN $3 = 'build_number' AND $4 = false THEN build_number END ASC,
            CASE WHEN $3 = 'build_number' AND $4 = true THEN build_number END DESC,
            CASE WHEN $3 = 'created_at' AND $4 = false THEN created_at END ASC,
            CASE WHEN $3 = 'created_at' AND $4 = true THEN created_at END DESC,
            CASE WHEN $3 = 'name' AND $4 = false THEN name END ASC,
            CASE WHEN $3 = 'name' AND $4 = true THEN name END DESC
        OFFSET $5
        LIMIT $6
        "#,
        status_filter,
        search_pattern,
        sort_by,
        sort_desc,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await;

    // If the builds table doesn't exist, return empty list
    let builds = match builds_result {
        Ok(rows) => rows,
        Err(e) => {
            // Check if it's a "table does not exist" error
            let err_str = e.to_string();
            if err_str.contains("does not exist") || err_str.contains("relation") {
                // Return empty list - table doesn't exist yet
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
            return Err(AppError::Database(err_str));
        }
    };

    let total_result = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM builds
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR name ILIKE $2)
        "#,
        status_filter,
        search_pattern
    )
    .fetch_one(&state.db)
    .await;

    let total = total_result.unwrap_or(0);
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(BuildListResponse {
        items: builds
            .into_iter()
            .map(|b| BuildResponse {
                id: b.id,
                name: b.name,
                number: b.build_number,
                status: b.status,
                started_at: b.started_at,
                finished_at: b.finished_at,
                duration_ms: b.duration_ms,
                agent: b.agent,
                created_at: b.created_at,
                updated_at: b.updated_at,
                artifact_count: b.artifact_count,
                modules: None,
            })
            .collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a build by ID
pub async fn get_build(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BuildResponse>> {
    let build_result = sqlx::query!(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, created_at, updated_at, artifact_count
        FROM builds
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await;

    let build = match build_result {
        Ok(Some(b)) => b,
        Ok(None) => return Err(AppError::NotFound("Build not found".to_string())),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("does not exist") || err_str.contains("relation") {
                return Err(AppError::NotFound("Build not found".to_string()));
            }
            return Err(AppError::Database(err_str));
        }
    };

    Ok(Json(BuildResponse {
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
    }))
}

#[derive(Debug, Deserialize)]
pub struct BuildDiffQuery {
    pub build_a: Uuid,
    pub build_b: Uuid,
}

#[derive(Debug, Serialize)]
pub struct BuildArtifactDiff {
    pub name: String,
    pub path: String,
    pub old_checksum: String,
    pub new_checksum: String,
    pub old_size_bytes: i64,
    pub new_size_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct BuildDiffResponse {
    pub build_a: Uuid,
    pub build_b: Uuid,
    pub added: Vec<BuildArtifact>,
    pub removed: Vec<BuildArtifact>,
    pub modified: Vec<BuildArtifactDiff>,
}

/// Get diff between two builds
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
