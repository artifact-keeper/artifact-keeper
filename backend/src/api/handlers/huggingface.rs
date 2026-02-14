//! HuggingFace Hub API handlers.
//!
//! Implements endpoints for HuggingFace-style model hosting and retrieval.
//!
//! Routes are mounted at `/huggingface/{repo_key}/...`:
//!   GET  /huggingface/{repo_key}/api/models                                   - List models
//!   GET  /huggingface/{repo_key}/api/models/{model_id}                        - Model info
//!   GET  /huggingface/{repo_key}/{model_id}/resolve/{revision}/{filename}     - Download file
//!   POST /huggingface/{repo_key}/api/models/{model_id}/upload/{revision}      - Upload file
//!   GET  /huggingface/{repo_key}/api/models/{model_id}/tree/{revision}        - List files

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // List models
        .route("/:repo_key/api/models", get(list_models))
        // Model info
        .route("/:repo_key/api/models/:model_id", get(model_info))
        // Upload file to model
        .route(
            "/:repo_key/api/models/:model_id/upload/:revision",
            post(upload_file),
        )
        // List files in model (tree)
        .route(
            "/:repo_key/api/models/:model_id/tree/:revision",
            get(list_files),
        )
        // Download file from model
        .route(
            "/:repo_key/:model_id/resolve/:revision/*filename",
            get(download_file),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    // Try Basic auth
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

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"huggingface\"")
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
                .header("WWW-Authenticate", "Basic realm=\"huggingface\"")
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
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_huggingface_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        r#"SELECT id, storage_path, format::text as "format!", repo_type::text as "repo_type!", upstream_url
        FROM repositories WHERE key = $1"#,
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
    if fmt != "huggingface" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a HuggingFace repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models — List models
// ---------------------------------------------------------------------------

async fn list_models(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(name)) name, version,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY LOWER(name), a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let models: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let model_id = a.name.clone();
            let pipeline_tag = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("pipeline_tag"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            serde_json::json!({
                "modelId": model_id,
                "lastModified": a.version.clone().unwrap_or_default(),
                "pipeline_tag": pipeline_tag,
                "tags": [],
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&models).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models/{model_id} — Model info
// ---------------------------------------------------------------------------

async fn model_info(
    State(state): State<SharedState>,
    Path((repo_key, model_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        model_id
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Model not found").into_response())?;

    let siblings = sqlx::query!(
        r#"
        SELECT path, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
        ORDER BY path
        "#,
        repo.id,
        model_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let files: Vec<serde_json::Value> = siblings
        .iter()
        .map(|s| {
            serde_json::json!({
                "rfilename": s.path,
                "size": s.size_bytes,
            })
        })
        .collect();

    let pipeline_tag = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("pipeline_tag"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "modelId": model_id,
        "sha": artifact.checksum_sha256,
        "lastModified": artifact.version.clone().unwrap_or_default(),
        "pipeline_tag": pipeline_tag,
        "tags": [],
        "siblings": files,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/{model_id}/resolve/{revision}/{filename} — Download file
// ---------------------------------------------------------------------------

async fn download_file(
    State(state): State<SharedState>,
    Path((repo_key, model_id, revision, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;

    let filename = filename.trim_start_matches('/');
    let artifact_path = format!("{}/{}/{}", model_id, revision, filename);

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, storage_key, size_bytes
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("{}/resolve/{}/{}", model_id, revision, filename);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let upstream_path = format!("{}/resolve/{}/{}", model_id, revision, filename);
                let vpath = artifact_path.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let vpath = vpath.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db,
                                member_id,
                                &storage_path,
                                &vpath,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

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
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /huggingface/{repo_key}/api/models/{model_id}/upload/{revision} — Upload file
// ---------------------------------------------------------------------------

async fn upload_file(
    State(state): State<SharedState>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty file body").into_response());
    }

    // Extract filename from Content-Disposition header or default
    let filename = headers
        .get("x-filename")
        .or(headers.get("content-disposition"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // Try to extract filename from Content-Disposition
            if v.contains("filename=") {
                v.split("filename=")
                    .nth(1)
                    .map(|f| f.trim_matches('"').to_string())
            } else {
                Some(v.to_string())
            }
        })
        .unwrap_or_else(|| "uploaded_file".to_string());

    let artifact_path = format!("{}/{}/{}", model_id, revision, filename);

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
        return Err((StatusCode::CONFLICT, "File already exists at this path").into_response());
    }

    // Store the file
    let storage_key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let size_bytes = body.len() as i64;

    let metadata = serde_json::json!({
        "model_id": model_id,
        "revision": revision,
        "filename": filename,
    });

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
        model_id,
        revision,
        size_bytes,
        computed_sha256,
        "application/octet-stream",
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

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'huggingface', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
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
        "HuggingFace upload: {}/{}/{} to repo {}",
        model_id, revision, filename, repo_key
    );

    let response = serde_json::json!({
        "message": "File uploaded successfully",
        "path": artifact_path,
        "sha256": computed_sha256,
        "size": size_bytes,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /huggingface/{repo_key}/api/models/{model_id}/tree/{revision} — List files
// ---------------------------------------------------------------------------

async fn list_files(
    State(state): State<SharedState>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;

    let path_prefix = format!("{}/{}/", model_id, revision);

    let artifacts = sqlx::query!(
        r#"
        SELECT path, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 || '%'
        ORDER BY path
        "#,
        repo.id,
        path_prefix
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let files: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let relative_path = a
                .path
                .strip_prefix(&path_prefix)
                .unwrap_or(&a.path)
                .to_string();

            serde_json::json!({
                "type": "file",
                "path": relative_path,
                "size": a.size_bytes,
                "oid": a.checksum_sha256,
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&files).unwrap()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer hf_abc123"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("token".to_string(), "hf_abc123".to_string())));
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer hf_token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("token".to_string(), "hf_token".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:hf-pass");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "hf-pass".to_string())));
    }

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid"),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_basic_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    // -----------------------------------------------------------------------
    // Filename extraction from headers
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_from_x_filename_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-filename", HeaderValue::from_static("model.bin"));
        let filename = headers
            .get("x-filename")
            .or(headers.get("content-disposition"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                if v.contains("filename=") {
                    v.split("filename=")
                        .nth(1)
                        .map(|f| f.trim_matches('"').to_string())
                } else {
                    Some(v.to_string())
                }
            })
            .unwrap_or_else(|| "uploaded_file".to_string());
        assert_eq!(filename, "model.bin");
    }

    #[test]
    fn test_filename_from_content_disposition() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-disposition",
            HeaderValue::from_static("attachment; filename=\"weights.safetensors\""),
        );
        let filename = headers
            .get("x-filename")
            .or(headers.get("content-disposition"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                if v.contains("filename=") {
                    v.split("filename=")
                        .nth(1)
                        .map(|f| f.trim_matches('"').to_string())
                } else {
                    Some(v.to_string())
                }
            })
            .unwrap_or_else(|| "uploaded_file".to_string());
        assert_eq!(filename, "weights.safetensors");
    }

    #[test]
    fn test_filename_default() {
        let headers = HeaderMap::new();
        let filename = headers
            .get("x-filename")
            .or(headers.get("content-disposition"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                if v.contains("filename=") {
                    v.split("filename=")
                        .nth(1)
                        .map(|f| f.trim_matches('"').to_string())
                } else {
                    Some(v.to_string())
                }
            })
            .unwrap_or_else(|| "uploaded_file".to_string());
        assert_eq!(filename, "uploaded_file");
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_path_format() {
        let model_id = "bert-base-uncased";
        let revision = "main";
        let filename = "pytorch_model.bin";
        let path = format!("{}/{}/{}", model_id, revision, filename);
        assert_eq!(path, "bert-base-uncased/main/pytorch_model.bin");
    }

    #[test]
    fn test_storage_key_format() {
        let model_id = "gpt2";
        let revision = "v1.0";
        let filename = "config.json";
        let key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
        assert_eq!(key, "huggingface/gpt2/v1.0/config.json");
    }

    #[test]
    fn test_upstream_path_format() {
        let model_id = "bert-base-uncased";
        let revision = "main";
        let filename = "tokenizer.json";
        let path = format!("{}/resolve/{}/{}", model_id, revision, filename);
        assert_eq!(path, "bert-base-uncased/resolve/main/tokenizer.json");
    }

    #[test]
    fn test_path_prefix_for_file_listing() {
        let model_id = "llama-2-7b";
        let revision = "main";
        let prefix = format!("{}/{}/", model_id, revision);
        assert_eq!(prefix, "llama-2-7b/main/");
    }

    #[test]
    fn test_relative_path_stripping() {
        let path_prefix = "llama-2-7b/main/";
        let full_path = "llama-2-7b/main/model-00001.safetensors";
        let relative = full_path.strip_prefix(path_prefix).unwrap_or(full_path);
        assert_eq!(relative, "model-00001.safetensors");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"model weights");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_json() {
        let model_id = "gpt2";
        let revision = "main";
        let filename = "config.json";
        let meta = serde_json::json!({
            "model_id": model_id,
            "revision": revision,
            "filename": filename,
        });
        assert_eq!(meta["model_id"], "gpt2");
        assert_eq!(meta["revision"], "main");
        assert_eq!(meta["filename"], "config.json");
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            storage_path: "/data/huggingface".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/cache/hf".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://huggingface.co".to_string()),
        };
        assert_eq!(repo.upstream_url.as_deref(), Some("https://huggingface.co"));
    }
}
