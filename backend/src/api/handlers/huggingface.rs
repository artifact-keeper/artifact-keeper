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

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum model ID length. The `name` column in the artifacts table is
/// VARCHAR(512). HuggingFace model IDs follow the pattern `org/model-name`,
/// so 255 characters provides ample room while preventing DB constraint
/// violations with a clear error message.
const MAX_MODEL_ID_LEN: usize = 255;

/// Maximum revision length. The `version` column is VARCHAR(255).
const MAX_REVISION_LEN: usize = 255;

/// Maximum artifact path length. The `path` and `storage_key` columns are
/// VARCHAR(2048). The storage key adds a `huggingface/` prefix (12 chars),
/// so the artifact path must stay within 2036 to keep the storage key under
/// the column limit.
const MAX_PATH_LEN: usize = 2036;

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
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_huggingface_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["huggingface"], "a Hugging Face").await
}

/// Extract a filename from request headers.
///
/// Prefers the `X-Filename` header; falls back to `Content-Disposition`
/// (parsing the `filename=` parameter, stripping surrounding quotes); if
/// neither is present, returns `"uploaded_file"`.
fn filename_from_headers(headers: &axum::http::HeaderMap) -> String {
    headers
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
        .unwrap_or_else(|| "uploaded_file".to_string())
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
    .map_err(super::db_err)?;

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

    let artifact = proxy_helpers::find_artifact_by_name_lowercase(&state.db, repo.id, &model_id)
        .await?
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
    .map_err(super::db_err)?;

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

    Ok(super::json_response(&json))
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
    .map_err(super::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            let upstream_path = format!("{}/resolve/{}/{}", model_id, revision, filename);
            if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                &state,
                &repo,
                proxy_helpers::DownloadResponseOpts {
                    upstream_path: &upstream_path,
                    virtual_lookup: proxy_helpers::VirtualLookup::ExactPath(&artifact_path),
                    default_content_type: "application/octet-stream",
                    content_disposition_filename: None,
                },
            )
            .await?
            {
                return Ok(resp);
            }
            return Err(not_found);
        }
    };

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        "application/octet-stream",
        Some(filename),
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /huggingface/{repo_key}/api/models/{model_id}/upload/{revision} — Upload file
// ---------------------------------------------------------------------------

async fn upload_file(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, model_id, revision)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "huggingface")?.user_id;
    let repo = resolve_huggingface_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty file body").into_response());
    }

    // Validate model_id length: the `name` database column is VARCHAR(512)
    if model_id.len() > MAX_MODEL_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Model ID exceeds maximum length of {} characters (got {})",
                MAX_MODEL_ID_LEN,
                model_id.len()
            ),
        )
            .into_response());
    }

    // Validate revision length: the `version` database column is VARCHAR(255)
    if revision.len() > MAX_REVISION_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Revision exceeds maximum length of {} characters (got {})",
                MAX_REVISION_LEN,
                revision.len()
            ),
        )
            .into_response());
    }

    // Extract filename from X-Filename or Content-Disposition header.
    let filename = filename_from_headers(&headers);

    let artifact_path = format!("{}/{}/{}", model_id, revision, filename);

    // Validate total path length: the `path` database column is VARCHAR(2048)
    if artifact_path.len() > MAX_PATH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Artifact path exceeds maximum length of {} characters (got {}). \
                 Use a shorter model ID, revision, or filename.",
                MAX_PATH_LEN,
                artifact_path.len()
            ),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "File already exists at this path",
    )
    .await?;

    let storage_key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let size_bytes = body.len() as i64;

    let metadata = serde_json::json!({
        "model_id": model_id,
        "revision": revision,
        "filename": filename,
    });

    // Insert artifact record
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &model_id,
            version: &revision,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/octet-stream",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    // Store metadata
    proxy_helpers::record_artifact_metadata(
        &state.db,
        artifact_id,
        repo.id,
        "huggingface",
        &metadata,
    )
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

    let path_prefix = super::escape_path_prefix(&[&model_id, &revision]);

    let artifacts = sqlx::query!(
        r#"
        SELECT path, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 || '%' ESCAPE '\'
        ORDER BY path
        "#,
        repo.id,
        path_prefix
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

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
    // -----------------------------------------------------------------------
    // Filename extraction from headers
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_from_x_filename_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-filename", HeaderValue::from_static("model.bin"));
        assert_eq!(filename_from_headers(&headers), "model.bin");
    }

    #[test]
    fn test_filename_from_content_disposition() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-disposition",
            HeaderValue::from_static("attachment; filename=\"weights.safetensors\""),
        );
        assert_eq!(filename_from_headers(&headers), "weights.safetensors");
    }

    #[test]
    fn test_filename_default() {
        let headers = HeaderMap::new();
        assert_eq!(filename_from_headers(&headers), "uploaded_file");
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
            key: String::new(),
            storage_path: "/data/huggingface".to_string(),
            storage_backend: "filesystem".to_string(),
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
            key: String::new(),
            storage_path: "/cache/hf".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://huggingface.co".to_string()),
        };
        assert_eq!(repo.upstream_url.as_deref(), Some("https://huggingface.co"));
    }

    // -----------------------------------------------------------------------
    // Length validation constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_model_id_within_limit() {
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        assert!(model_id.len() <= MAX_MODEL_ID_LEN);
    }

    #[test]
    fn test_model_id_exceeds_limit() {
        let model_id = "a".repeat(MAX_MODEL_ID_LEN + 1);
        assert!(model_id.len() > MAX_MODEL_ID_LEN);
    }

    #[test]
    fn test_long_model_id_path_fits_in_db() {
        // A 255-char model_id with "main" revision and a typical filename
        // should produce a path under MAX_PATH_LEN.
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        let revision = "main";
        let filename = "model.safetensors";
        let path = format!("{}/{}/{}", model_id, revision, filename);
        assert!(
            path.len() <= MAX_PATH_LEN,
            "path length {} exceeds MAX_PATH_LEN {}",
            path.len(),
            MAX_PATH_LEN
        );
    }

    #[test]
    fn test_long_model_id_storage_key_fits_in_db() {
        // Storage key adds "huggingface/" prefix (12 chars).
        let model_id = "a".repeat(MAX_MODEL_ID_LEN);
        let revision = "main";
        let filename = "model.safetensors";
        let key = format!("huggingface/{}/{}/{}", model_id, revision, filename);
        assert!(
            key.len() <= 2048,
            "storage_key length {} exceeds VARCHAR(2048)",
            key.len()
        );
    }

    #[test]
    fn test_revision_within_limit() {
        let revision = "v".repeat(MAX_REVISION_LEN);
        assert!(revision.len() <= MAX_REVISION_LEN);
    }

    #[test]
    fn test_long_model_name_artifact_path() {
        // A model name over 100 characters should still produce valid paths.
        let model_id = "x".repeat(120);
        assert_eq!(model_id.len(), 120);
        let path = format!("{}/{}/{}", model_id, "main", "weights.safetensors");
        assert!(path.len() <= MAX_PATH_LEN);
        let key = format!(
            "huggingface/{}/{}/{}",
            model_id, "main", "weights.safetensors"
        );
        assert!(key.len() <= 2048);
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_huggingface_resolve_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/missing-model/resolve/main/missing.bin",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_resolve_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "huggingface/bert-base/main/config.json",
            "bert-base/main/config.json",
            "bert-base",
            "main",
            "application/json",
            bytes::Bytes::from_static(b"{\"x\":1}"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/bert-base/resolve/main/config.json",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"{\"x\":1}");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_model_info_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) =
            tdh::send(app, tdh::get(format!("/{}/api/models/missing", f.repo_key))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/models/m/upload/main", f.repo_key))
            .header("x-filename", "file.bin")
            .body(axum::body::Body::from("data"))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_huggingface_upload_succeeds_for_local() {
        let Some(f) = tdh::Fixture::setup("local", "huggingface").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/models/my-model/upload/main", f.repo_key))
            .header("x-filename", "weights.bin")
            .body(axum::body::Body::from(vec![0u8; 16]))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "got {}",
            status
        );
        f.teardown().await;
    }
}
