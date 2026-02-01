//! SBT/Ivy repository API handlers.
//!
//! Implements the endpoints required for SBT's Ivy-style artifact resolution.
//!
//! Routes are mounted at `/ivy/{repo_key}/...`:
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/ivys/ivy.xml               - Ivy descriptor
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/jars/{name}-{version}.jar  - Download JAR
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/srcs/{name}-{version}-sources.jar - Sources
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/docs/{name}-{version}-javadoc.jar - Javadoc
//!   PUT  /ivy/{repo_key}/*path                                             - Upload artifact
//!   HEAD /ivy/{repo_key}/*path                                             - Check existence

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::formats::sbt::SbtHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Single wildcard handles all Ivy layout paths:
        //   GET  — download artifact (ivy.xml, jars, srcs, docs, etc.)
        //   PUT  — upload artifact (auth required)
        //   HEAD — check artifact existence
        .route(
            "/:repo_key/*path",
            get(download_by_path)
                .put(upload_artifact)
                .head(check_exists),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"sbt\"")
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
                .header("WWW-Authenticate", "Basic realm=\"sbt\"")
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

async fn resolve_sbt_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "sbt" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an SBT/Ivy repository (format: {})",
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
// GET /ivy/{repo_key}/*path — Download artifact by path
// ---------------------------------------------------------------------------

async fn download_by_path(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, storage_key, size_bytes, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
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
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}\"",
                artifact_path.rsplit('/').next().unwrap_or(artifact_path)
            ),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /ivy/{repo_key}/*path — Upload artifact (auth required)
// ---------------------------------------------------------------------------

async fn upload_artifact(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/').to_string();

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty artifact file").into_response());
    }

    // Validate path via format handler
    let path_info = SbtHandler::parse_path(&artifact_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid SBT path: {}", e)).into_response()
    })?;

    let artifact_name = if path_info.is_ivy_descriptor {
        format!("{}/{}", path_info.org, path_info.module)
    } else {
        path_info
            .artifact
            .clone()
            .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
    };

    let artifact_version = path_info.revision.clone().unwrap_or_default();

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

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
        return Err((StatusCode::CONFLICT, "Artifact already exists at this path").into_response());
    }

    // Determine content type
    let content_type = if path_info.is_ivy_descriptor {
        "application/xml"
    } else {
        "application/java-archive"
    };

    // Store the file
    let storage_key = format!("sbt/{}", artifact_path);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let sbt_metadata = serde_json::json!({
        "org": path_info.org,
        "module": path_info.module,
        "revision": path_info.revision,
        "artifact": path_info.artifact,
        "ext": path_info.ext,
        "is_ivy_descriptor": path_info.is_ivy_descriptor,
    });

    let size_bytes = body.len() as i64;

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
        artifact_name,
        artifact_version,
        size_bytes,
        computed_sha256,
        content_type,
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

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'sbt', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        sbt_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "SBT upload: {} {} to repo {}",
        artifact_path, artifact_version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Successfully uploaded SBT artifact"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// HEAD /ivy/{repo_key}/*path — Check artifact existence
// ---------------------------------------------------------------------------

async fn check_exists(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT size_bytes, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
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
    })?
    .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::empty())
        .unwrap())
}
