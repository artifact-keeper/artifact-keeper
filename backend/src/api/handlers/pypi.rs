//! PyPI Simple Repository API (PEP 503) handlers.
//!
//! Implements the endpoints required for `pip install` and `twine upload`
//! per PEP 503, PEP 658, and PEP 691.
//!
//! Routes are mounted at `/pypi/{repo_key}/...`:
//!   GET  /pypi/{repo_key}/simple/                     - Root index
//!   GET  /pypi/{repo_key}/simple/{project}/           - Package index
//!   GET  /pypi/{repo_key}/simple/{project}/{filename} - Download file
//!   GET  /pypi/{repo_key}/simple/{project}/{filename}.metadata - PEP 658 metadata
//!   POST /pypi/{repo_key}/                            - Twine upload

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use regex::Regex;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::formats::pypi::PypiHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Twine upload
        .route("/:repo_key/", post(upload))
        // Simple index root
        .route("/:repo_key/simple/", get(simple_root))
        .route("/:repo_key/simple", get(simple_root))
        // Package index
        .route("/:repo_key/simple/:project/", get(simple_project))
        .route("/:repo_key/simple/:project", get(simple_project))
        // Download & metadata
        .route(
            "/:repo_key/simple/:project/:filename",
            get(download_or_metadata),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_pypi_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["pypi", "poetry", "conda"], "a PyPI").await
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/ — PEP 503 root index
// ---------------------------------------------------------------------------

async fn simple_root(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // Get all distinct normalized package names in this repository
    let packages: Vec<String> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT
            LOWER(REPLACE(REPLACE(REPLACE(name, '_', '-'), '.', '-'), '--', '-'))
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false
        ORDER BY 1
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
    })?
    .into_iter()
    .flatten()
    .collect();

    // Check Accept header for PEP 691 JSON
    let accept = headers
        .get(CONTENT_TYPE.as_str())
        .or_else(|| headers.get("accept"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/vnd.pypi.simple.v1+json") {
        let json = serde_json::json!({
            "meta": { "api-version": "1.1" },
            "projects": packages.iter().map(|p| {
                serde_json::json!({ "name": p })
            }).collect::<Vec<_>>()
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap());
    }

    // HTML response (default)
    let mut html = String::from(
        "<!DOCTYPE html>\n<html>\n<head><meta name=\"pypi:repository-version\" content=\"1.0\"/>\
         <title>Simple Index</title></head>\n<body>\n<h1>Simple Index</h1>\n",
    );

    for package in &packages {
        let normalized = PypiHandler::normalize_name(package);
        html.push_str(&format!(
            "<a href=\"/pypi/{}/simple/{}/\">{}</a><br/>\n",
            repo_key, normalized, package
        ));
    }
    html.push_str("</body>\n</html>\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/{project}/ — PEP 503 package index
// ---------------------------------------------------------------------------

async fn simple_project(
    State(state): State<SharedState>,
    Path((repo_key, project)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;
    let normalized = PypiHandler::normalize_name(&project);

    // Find all artifacts that belong to this package.
    // We normalize the name for matching: replace [_.-]+ with - then lowercase.
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(REPLACE(REPLACE(REPLACE(a.name, '_', '-'), '.', '-'), '--', '-')) = $2
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        normalized
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

    if artifacts.is_empty() {
        // For remote repos, proxy the simple index from upstream
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = format!("simple/{}/", normalized);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;

                // Rewrite absolute download URLs to route through our proxy
                let ct = content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string());
                let body = if ct.contains("text/html") {
                    let html = String::from_utf8_lossy(&content);
                    let rewritten = rewrite_upstream_urls(&html, &repo_key, &project);
                    Body::from(rewritten)
                } else {
                    Body::from(content)
                };

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .body(body)
                    .unwrap());
            }
        }
        // For virtual repos, iterate through members and try proxy for remote members
        if repo.repo_type == RepositoryType::Virtual {
            let upstream_path = format!("simple/{}/", normalized);
            let rk = repo_key.clone();
            let proj = project.clone();
            return proxy_helpers::resolve_virtual_metadata(
                &state.db,
                state.proxy_service.as_deref(),
                repo.id,
                &upstream_path,
                |content, _member_key| {
                    let rk = rk.clone();
                    let proj = proj.clone();
                    async move {
                        let html = String::from_utf8_lossy(&content);
                        let rewritten = rewrite_upstream_urls(&html, &rk, &proj);
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "text/html; charset=utf-8")
                            .body(Body::from(rewritten))
                            .unwrap())
                    }
                },
            )
            .await;
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/vnd.pypi.simple.v1+json") {
        // PEP 691 JSON response
        let files: Vec<serde_json::Value> = artifacts
            .iter()
            .map(|a| {
                let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
                let requires_python = a
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("pkg_info"))
                    .and_then(|pi| pi.get("requires_python"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let mut file = serde_json::json!({
                    "filename": filename,
                    "url": format!("/pypi/{}/simple/{}/{}", repo_key, normalized, filename),
                    "hashes": { "sha256": &a.checksum_sha256 },
                    "size": a.size_bytes,
                });
                if let Some(rp) = requires_python {
                    file["requires-python"] = serde_json::Value::String(rp);
                }
                file
            })
            .collect();

        let versions: Vec<String> = artifacts
            .iter()
            .filter_map(|a| a.version.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let json = serde_json::json!({
            "meta": { "api-version": "1.1" },
            "name": normalized,
            "versions": versions,
            "files": files,
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap());
    }

    // HTML response
    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str("<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n");
    html.push_str(&format!("<title>Links for {}</title>\n", normalized));
    html.push_str("</head>\n<body>\n");
    html.push_str(&format!("<h1>Links for {}</h1>\n", normalized));

    for a in &artifacts {
        let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        let url = format!(
            "/pypi/{}/simple/{}/{}#sha256={}",
            repo_key, normalized, filename, a.checksum_sha256
        );

        let requires_python = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("pkg_info"))
            .and_then(|pi| pi.get("requires_python"))
            .and_then(|v| v.as_str());

        let rp_attr = requires_python
            .map(|rp| format!(" data-requires-python=\"{}\"", html_escape(rp)))
            .unwrap_or_default();

        html.push_str(&format!(
            "<a href=\"{}\"{}>{}</a><br/>\n",
            url, rp_attr, filename
        ));
    }

    html.push_str("</body>\n</html>\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/{project}/{filename} — Download or metadata
// ---------------------------------------------------------------------------

async fn download_or_metadata(
    State(state): State<SharedState>,
    Path((repo_key, project, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // PEP 658: if filename ends with .metadata, serve extracted METADATA
    if filename.ends_with(".metadata") {
        let real_filename = filename.trim_end_matches(".metadata");
        return serve_metadata(
            &state,
            &state.db,
            repo.id,
            &repo.storage_location(),
            real_filename,
        )
        .await;
    }

    // Regular file download
    serve_file(&state, &repo, &repo_key, &project, &filename).await
}

async fn serve_file(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    project: &str,
    filename: &str,
) -> Result<Response, Response> {
    // Find artifact by filename (last path segment matches)
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, content_type, storage_key
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
    })?;

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let normalized = PypiHandler::normalize_name(project);
                    let upstream_path = format!("simple/{}/{}", normalized, filename);
                    let (content, _content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;

                    let content_type = if filename.ends_with(".whl") {
                        "application/zip"
                    } else if filename.ends_with(".tar.gz") {
                        "application/gzip"
                    } else {
                        "application/octet-stream"
                    };

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, content_type)
                        .header(
                            "Content-Disposition",
                            format!("attachment; filename=\"{}\"", filename),
                        )
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let fname = filename.to_string();
                let normalized = PypiHandler::normalize_name(project);
                let upstream_path = format!("simple/{}/{}", normalized, filename);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let fname = fname.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db, &state, member_id, &location, &fname,
                            )
                            .await
                        }
                    },
                )
                .await?;

                let ct = content_type.unwrap_or_else(|| {
                    if fname.ends_with(".whl") {
                        "application/zip".to_string()
                    } else if fname.ends_with(".tar.gz") {
                        "application/gzip".to_string()
                    } else {
                        "application/octet-stream".to_string()
                    }
                });

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err((StatusCode::NOT_FOUND, "File not found").into_response());
        }
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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

    let content_type = if filename.ends_with(".whl") {
        "application/zip"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-PyPI-File-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

async fn serve_metadata(
    state: &SharedState,
    db: &PgPool,
    repo_id: uuid::Uuid,
    location: &crate::storage::StorageLocation,
    filename: &str,
) -> Result<Response, Response> {
    // Find the artifact
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.storage_key
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE '%/' || $2
        LIMIT 1
        "#,
        repo_id,
        filename
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response())?;

    // Try to extract METADATA from the package file
    let storage = state.storage_for_repo_or_500(location)?;
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let metadata_text = if filename.ends_with(".whl") {
        extract_metadata_from_wheel(&content)
    } else if filename.ends_with(".tar.gz") {
        extract_metadata_from_sdist(&content)
    } else {
        None
    };

    match metadata_text {
        Some(text) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(text))
            .unwrap()),
        None => Err((StatusCode::NOT_FOUND, "Metadata not available").into_response()),
    }
}

fn extract_metadata_from_wheel(content: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(content);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).ok()?;
        if file.name().contains(".dist-info/") && file.name().ends_with("METADATA") {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut file, &mut text).ok()?;
            return Some(text);
        }
    }
    None
}

fn extract_metadata_from_sdist(content: &[u8]) -> Option<String> {
    use flate2::read::GzDecoder;
    let gz = GzDecoder::new(content);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_path_buf();
        if path.ends_with("PKG-INFO") {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut entry, &mut text).ok()?;
            return Some(text);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// POST /pypi/{repo_key}/ — Twine upload
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = require_auth_basic(auth, "pypi")?.user_id;
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Parse multipart form data
    let mut action: Option<String> = None;
    let mut pkg_name: Option<String> = None;
    let mut pkg_version: Option<String> = None;
    let mut file_content: Option<Bytes> = None;
    let mut file_name: Option<String> = None;
    let mut sha256_digest: Option<String> = None;
    let mut _md5_digest: Option<String> = None;
    let mut requires_python: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut metadata_fields: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            ":action" => {
                action = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "name" => {
                pkg_name = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "version" => {
                pkg_version = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "sha256_digest" => {
                sha256_digest = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "md5_digest" => {
                _md5_digest = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "requires_python" => {
                requires_python = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "summary" => {
                summary = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "content" => {
                file_name = field.file_name().map(|s| s.to_string());
                file_content = Some(field.bytes().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Invalid file: {}", e)).into_response()
                })?);
            }
            // Capture other metadata fields
            _ => {
                if let Ok(text) = field.text().await {
                    // Handle repeated fields (classifiers, etc.)
                    if let Some(existing) = metadata_fields.get(&name) {
                        if let Some(arr) = existing.as_array() {
                            let mut arr = arr.clone();
                            arr.push(serde_json::Value::String(text));
                            metadata_fields.insert(name, serde_json::Value::Array(arr));
                        } else {
                            metadata_fields.insert(
                                name,
                                serde_json::Value::Array(vec![
                                    existing.clone(),
                                    serde_json::Value::String(text),
                                ]),
                            );
                        }
                    } else {
                        metadata_fields.insert(name, serde_json::Value::String(text));
                    }
                }
            }
        }
    }

    // Validate required fields
    let action = action.unwrap_or_default();
    if action != "file_upload" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Unsupported action: {}", action),
        )
            .into_response());
    }

    let pkg_name = pkg_name
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'name' field").into_response())?;
    let pkg_version = pkg_version
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'version' field").into_response())?;
    let content = file_content
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'content' field").into_response())?;
    let filename = file_name.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing filename in content field").into_response()
    })?;

    let normalized = PypiHandler::normalize_name(&pkg_name);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Verify digest if provided
    if let Some(ref expected) = sha256_digest {
        if !expected.is_empty() && expected != &computed_sha256 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "SHA256 mismatch: expected {} got {}",
                    expected, computed_sha256
                ),
            )
                .into_response());
        }
    }

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        format!("{}/{}/{}", normalized, pkg_version, filename)
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
        return Err((StatusCode::CONFLICT, "File already exists").into_response());
    }

    // Store the file
    let storage_key = format!("pypi/{}/{}/{}", normalized, pkg_version, filename);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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

    // Build metadata JSON
    let mut pkg_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "filename": filename,
    });
    if let Some(rp) = &requires_python {
        pkg_metadata["pkg_info"] = serde_json::json!({
            "requires_python": rp,
        });
    }
    if let Some(s) = &summary {
        pkg_metadata["pkg_info"]
            .as_object_mut()
            .get_or_insert(&mut serde_json::Map::new())
            .insert("summary".to_string(), serde_json::Value::String(s.clone()));
    }

    // Infer content type
    let content_type = if filename.ends_with(".whl") {
        "application/zip"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    };

    let artifact_path = format!("{}/{}/{}", normalized, pkg_version, filename);
    let size_bytes = content.len() as i64;

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

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
        normalized,
        pkg_version,
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

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'pypi', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pkg_metadata,
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

    // Populate packages / package_versions tables (best-effort)
    {
        let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
        pkg_svc
            .try_create_or_update_from_artifact(
                repo.id,
                &normalized,
                &pkg_version,
                size_bytes,
                &computed_sha256,
                summary.as_deref(),
                Some(serde_json::json!({ "format": "pypi" })),
            )
            .await;
    }

    info!(
        "PyPI upload: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("OK"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Rewrite absolute download URLs in upstream PyPI simple index HTML to route
/// through Artifact Keeper's proxy endpoint.
///
/// Upstream PyPI returns `<a href="https://files.pythonhosted.org/packages/...">`,
/// which causes pip to download directly from upstream, bypassing the cache.
/// This function rewrites those URLs to relative paths like
/// `/pypi/{repo_key}/simple/{project}/{filename}#sha256=...` so downloads
/// go through Artifact Keeper and get cached.
///
/// Only absolute URLs (starting with `http://` or `https://`) are rewritten.
/// Relative URLs and anchors are left unchanged.
fn rewrite_upstream_urls(html: &str, repo_key: &str, project: &str) -> String {
    // Match <a href="https://..."> or <a href="http://..."> patterns.
    // Captures the full URL (possibly with fragment) inside the href attribute.
    let re = Regex::new(r#"<a\s+([^>]*?)href="(https?://[^"]+)"([^>]*)>"#).unwrap();
    let normalized = PypiHandler::normalize_name(project);

    re.replace_all(html, |caps: &regex::Captures| {
        let before_href = &caps[1];
        let full_url = &caps[2];
        let after_href = &caps[3];

        // Split off the fragment (#sha256=...) if present
        let (url_path, fragment) = match full_url.find('#') {
            Some(pos) => (&full_url[..pos], &full_url[pos..]),
            None => (full_url, ""),
        };

        // Extract the filename from the URL path
        let filename = url_path.rsplit('/').next().unwrap_or(url_path);

        if filename.is_empty() {
            // Not a file URL, leave unchanged
            return caps[0].to_string();
        }

        let rewritten = format!(
            "/pypi/{}/simple/{}/{}{}",
            repo_key, normalized, filename, fragment
        );
        format!("<a {}href=\"{}\"{}>", before_href, rewritten, after_href)
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // html_escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_html_escape_no_special_chars() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn test_html_escape_ampersand() {
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn test_html_escape_less_than() {
        assert_eq!(html_escape("a < b"), "a &lt; b");
    }

    #[test]
    fn test_html_escape_greater_than() {
        assert_eq!(html_escape("a > b"), "a &gt; b");
    }

    #[test]
    fn test_html_escape_quotes() {
        assert_eq!(html_escape("a \"b\" c"), "a &quot;b&quot; c");
    }

    #[test]
    fn test_html_escape_all_special() {
        assert_eq!(
            html_escape("<script>alert(\"x&y\")</script>"),
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_html_escape_requires_python_version() {
        assert_eq!(html_escape(">=3.7"), "&gt;=3.7");
        assert_eq!(html_escape(">=3.7,<4.0"), "&gt;=3.7,&lt;4.0");
    }

    // -----------------------------------------------------------------------
    // rewrite_upstream_urls
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_absolute_url_with_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/ab/cd/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_absolute_url_without_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_preserves_relative_urls() {
        let html = r#"<a href="numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        // Relative URLs should be left unchanged
        assert_eq!(result, html);
    }

    #[test]
    fn test_rewrite_multiple_links() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=aaa">numpy-1.3.0.tar.gz</a><br/>"#,
            "\n",
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl#sha256=bbb">numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl</a><br/>"#,
        );
        let result = rewrite_upstream_urls(html, "my-pypi", "numpy");
        assert!(
            result.contains(r#"href="/pypi/my-pypi/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa""#)
        );
        assert!(result.contains(
            r#"href="/pypi/my-pypi/simple/numpy/numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl#sha256=bbb""#
        ));
    }

    #[test]
    fn test_rewrite_normalizes_project_name() {
        let html = r#"<a href="https://example.com/My_Package-1.0.tar.gz#sha256=abc">My_Package-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "My_Package");
        assert!(result.contains(
            r#"href="/pypi/pypi-remote/simple/my-package/My_Package-1.0.tar.gz#sha256=abc""#
        ));
    }

    #[test]
    fn test_rewrite_http_url() {
        let html = r#"<a href="http://example.com/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(
            result,
            r#"<a href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_preserves_data_attributes() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=abc" data-requires-python="&gt;=3.7">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert!(result
            .contains(r#"href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc""#));
        assert!(result.contains(r#"data-requires-python="&gt;=3.7""#));
    }

    #[test]
    fn test_rewrite_no_links() {
        let html = "<html><body><h1>No links here</h1></body></html>";
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(result, html);
    }

    #[test]
    fn test_rewrite_empty_string() {
        let result = rewrite_upstream_urls("", "repo", "pkg");
        assert_eq!(result, "");
    }

    #[test]
    fn test_rewrite_full_simple_index_page() {
        let html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.0"/><title>Links for numpy</title></head>
<body>
<h1>Links for numpy</h1>
<a href="https://files.pythonhosted.org/packages/3e/ee/numpy-1.3.0.tar.gz#sha256=aaa111" >numpy-1.3.0.tar.gz</a><br/>
<a href="https://files.pythonhosted.org/packages/c5/63/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=bbb222" data-requires-python="&gt;=3.9">numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl</a><br/>
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "pypi-public", "numpy");

        // Absolute URLs should be rewritten
        assert!(!result.contains("files.pythonhosted.org"));
        assert!(result
            .contains(r#"href="/pypi/pypi-public/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa111""#));
        assert!(result.contains(
            r#"href="/pypi/pypi-public/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=bbb222""#
        ));

        // data-requires-python should be preserved
        assert!(result.contains("data-requires-python"));

        // Non-link content should be preserved
        assert!(result.contains("<h1>Links for numpy</h1>"));
        assert!(result.contains("pypi:repository-version"));
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_relative() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/pkg-1.0.tar.gz#sha256=aaa">pkg-1.0.tar.gz</a>"#,
            "\n",
            r#"<a href="pkg-2.0.tar.gz#sha256=bbb">pkg-2.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        // Absolute URL is rewritten
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#sha256=aaa""#));
        // Relative URL is left unchanged
        assert!(result.contains(r#"href="pkg-2.0.tar.gz#sha256=bbb""#));
    }

    #[test]
    fn test_rewrite_url_with_deep_path() {
        // URLs from real PyPI have deep paths like /packages/3e/ee/ab/...
        let html = r#"<a href="https://files.pythonhosted.org/packages/3e/ee/ab/cd/ef/numpy-1.3.0.tar.gz#sha256=abc">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "numpy");
        assert!(result.contains(r#"href="/pypi/repo/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc""#));
    }

    #[test]
    fn test_rewrite_preserves_md5_fragment() {
        let html =
            r#"<a href="https://example.com/pkg-1.0.tar.gz#md5=deadbeef">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#md5=deadbeef""#));
    }

    // -----------------------------------------------------------------------
    // extract_metadata_from_wheel
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_metadata_from_wheel_with_valid_wheel() {
        // Create a minimal valid zip with a METADATA file inside .dist-info
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("mypackage-1.0.dist-info/METADATA", options)
            .unwrap();
        std::io::Write::write_all(
            &mut writer,
            b"Metadata-Version: 2.1\nName: mypackage\nVersion: 1.0\n",
        )
        .unwrap();
        let cursor = writer.finish().unwrap();
        let content = cursor.into_inner();

        let result = extract_metadata_from_wheel(&content);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Metadata-Version: 2.1"));
        assert!(text.contains("Name: mypackage"));
    }

    #[test]
    fn test_extract_metadata_from_wheel_no_metadata_file() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("some-other-file.txt", options).unwrap();
        std::io::Write::write_all(&mut writer, b"no metadata here").unwrap();
        let cursor = writer.finish().unwrap();
        let content = cursor.into_inner();

        let result = extract_metadata_from_wheel(&content);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_metadata_from_wheel_invalid_zip() {
        let content = b"not a zip file at all";
        let result = extract_metadata_from_wheel(content);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_metadata_from_sdist
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_metadata_from_sdist_with_pkg_info() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        // Build a tar.gz with a PKG-INFO file
        let mut tar_builder = tar::Builder::new(Vec::new());
        let pkg_info = b"Metadata-Version: 1.0\nName: mypackage\nVersion: 1.0\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("mypackage-1.0/PKG-INFO").unwrap();
        header.set_size(pkg_info.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &pkg_info[..]).unwrap();
        let tar_data = tar_builder.into_inner().unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let gz_data = gz.finish().unwrap();

        let result = extract_metadata_from_sdist(&gz_data);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Name: mypackage"));
    }

    #[test]
    fn test_extract_metadata_from_sdist_no_pkg_info() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut tar_builder = tar::Builder::new(Vec::new());
        let data = b"some other file content";
        let mut header = tar::Header::new_gnu();
        header.set_path("mypackage-1.0/setup.py").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &data[..]).unwrap();
        let tar_data = tar_builder.into_inner().unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let gz_data = gz.finish().unwrap();

        let result = extract_metadata_from_sdist(&gz_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_metadata_from_sdist_invalid_data() {
        let result = extract_metadata_from_sdist(b"not a tar.gz");
        assert!(result.is_none());
    }
}
