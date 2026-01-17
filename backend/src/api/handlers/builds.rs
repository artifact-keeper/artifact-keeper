//! Build management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
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

#[derive(Debug, Serialize, FromRow)]
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
        }
    }
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

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));
    let sort_desc = query.sort_order.as_deref() == Some("desc");

    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')"
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
        "#
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
pub async fn get_build(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BuildResponse>> {
    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')"
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
        "#
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Build not found".to_string()))?;

    Ok(Json(BuildResponse::from(build)))
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
