//! Helm Chart Repository API handlers.
//!
//! Implements the endpoints required for `helm repo add`, `helm install`,
//! and ChartMuseum-compatible upload/delete.
//!
//! Routes are mounted at `/helm/{repo_key}/...`:
//!   GET    /helm/{repo_key}/index.yaml                    - Repository index
//!   GET    /helm/{repo_key}/charts/{name}-{version}.tgz   - Download chart package
//!   POST   /helm/{repo_key}/api/charts                    - Upload chart (multipart)
//!   DELETE /helm/{repo_key}/api/charts/{name}/{version}    - Delete chart

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tracing::info;

use crate::api::SharedState;
use crate::formats::helm::{generate_index_yaml, ChartYaml, HelmHandler};
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Repository index
        .route("/:repo_key/index.yaml", get(index_yaml))
        // Download chart package
        .route("/:repo_key/charts/:filename", get(download_chart))
        // ChartMuseum-compatible upload
        .route("/:repo_key/api/charts", post(upload_chart))
        // ChartMuseum-compatible delete
        .route("/:repo_key/api/charts/:name/:version", delete(delete_chart))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

/// Authenticate via Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"helm\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"helm\"")
                .body(Body::from("Invalid credentials"))
                .unwrap()
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
}

async fn resolve_helm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\" FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt = repo.format.to_lowercase();
    if fmt != "helm" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Helm repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
    })
}

// ---------------------------------------------------------------------------
// GET /helm/{repo_key}/index.yaml -- Helm repository index
// ---------------------------------------------------------------------------

async fn index_yaml(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Query all non-deleted Helm artifacts with their metadata.
    // Using sqlx::query() (non-macro) since this is a new query not in the offline cache.
    let rows = sqlx::query(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.created_at,
               am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY a.name ASC, a.created_at DESC
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Build chart entries for index generation
    let mut charts: Vec<(ChartYaml, String, String, String)> = Vec::new();

    for row in &rows {
        let name: String = row.get("name");
        let version: Option<String> = row.get("version");
        let checksum_sha256: String = row.get("checksum_sha256");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let metadata: Option<serde_json::Value> = row.get("metadata");

        let version = match version {
            Some(v) => v,
            None => continue,
        };

        // Try to reconstruct ChartYaml from stored metadata
        let chart_yaml = metadata
            .as_ref()
            .and_then(|m| m.get("chart"))
            .and_then(|chart_value| serde_json::from_value::<ChartYaml>(chart_value.clone()).ok());

        // Fall back to a minimal ChartYaml if metadata is missing
        let chart_yaml = chart_yaml.unwrap_or_else(|| ChartYaml {
            api_version: "v2".to_string(),
            name: name.clone(),
            version: version.clone(),
            kube_version: None,
            description: metadata
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .map(String::from),
            chart_type: None,
            keywords: None,
            home: None,
            sources: None,
            dependencies: None,
            maintainers: None,
            icon: None,
            app_version: metadata
                .as_ref()
                .and_then(|m| m.get("appVersion"))
                .and_then(|v| v.as_str())
                .map(String::from),
            deprecated: None,
            annotations: None,
        });

        let filename = format!("{}-{}.tgz", name, version);
        let url = format!("/helm/{}/charts/{}", repo_key, filename);
        let created = created_at.to_rfc3339();
        let digest = checksum_sha256;

        charts.push((chart_yaml, url, created, digest));
    }

    let index_content = generate_index_yaml(charts).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate index.yaml: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-yaml; charset=utf-8")
        .body(Body::from(index_content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /helm/{repo_key}/charts/{filename} -- Download chart package
// ---------------------------------------------------------------------------

async fn download_chart(
    State(state): State<SharedState>,
    Path((repo_key, filename)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Find artifact by filename pattern
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE '%/' || $2
        LIMIT 1
        "#,
        repo.id,
        filename
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Chart not found").into_response())?;

    // Read from storage
    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /helm/{repo_key}/api/charts -- Upload chart (ChartMuseum-compatible)
// ---------------------------------------------------------------------------

async fn upload_chart(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Extract chart file from multipart form (field name: "chart")
    let mut chart_content: Option<Bytes> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "chart" {
            chart_content = Some(field.bytes().await.map_err(|e| {
                (StatusCode::BAD_REQUEST, format!("Invalid file: {}", e)).into_response()
            })?);
        }
    }

    let content = chart_content
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'chart' field").into_response())?;

    // Extract and validate Chart.yaml from the package
    let chart_yaml = HelmHandler::extract_chart_yaml(&content).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid chart package: {}", e),
        )
            .into_response()
    })?;

    let chart_name = &chart_yaml.name;
    let chart_version = &chart_yaml.version;
    let filename = format!("{}-{}.tgz", chart_name, chart_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Build artifact path
    let artifact_path = format!("{}/{}/{}", chart_name, chart_version, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Chart {} version {} already exists",
                chart_name, chart_version
            ),
        )
            .into_response());
    }

    // Store the chart package
    let storage_key = format!("helm/{}/{}/{}", chart_name, chart_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage
        .put(&storage_key, content.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let size_bytes = content.len() as i64;

    // Insert artifact record
    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        chart_name.clone(),
        chart_version.clone(),
        size_bytes,
        computed_sha256,
        "application/gzip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON including the full Chart.yaml data
    let helm_metadata = serde_json::json!({
        "name": chart_name,
        "version": chart_version,
        "chart": serde_json::to_value(&chart_yaml).unwrap_or_default(),
    });

    // Store metadata (using non-macro query since format='helm' is not in the offline cache)
    let _ = sqlx::query(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'helm', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
    )
    .bind(artifact_id)
    .bind(&helm_metadata)
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Helm upload: {} {} to repo {}",
        chart_name, chart_version, repo_key
    );

    // ChartMuseum-compatible response
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "saved": true
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// DELETE /helm/{repo_key}/api/charts/{name}/{version} -- Delete chart
// ---------------------------------------------------------------------------

async fn delete_chart(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // Authenticate
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_helm_repo(&state.db, &repo_key).await?;

    // Find the artifact (using non-macro query)
    let row = sqlx::query(
        r#"
        SELECT id, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
    )
    .bind(repo.id)
    .bind(&name)
    .bind(&version)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Chart {} version {} not found", name, version),
        )
            .into_response()
    })?;

    let artifact_id: uuid::Uuid = row.get("id");

    // Soft-delete the artifact
    sqlx::query("UPDATE artifacts SET is_deleted = true, updated_at = NOW() WHERE id = $1")
        .bind(artifact_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response()
        })?;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!("Helm delete: {} {} from repo {}", name, version, repo_key);

    // ChartMuseum-compatible response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "deleted": true
            }))
            .unwrap(),
        ))
        .unwrap())
}
