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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
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
use crate::formats::pypi::PypiHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

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
            .header("WWW-Authenticate", "Basic realm=\"pypi\"")
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
                .header("WWW-Authenticate", "Basic realm=\"pypi\"")
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

async fn resolve_pypi_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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

    // Verify it's a PyPI-format repository
    let fmt = repo.format.to_lowercase();
    if fmt != "pypi" && fmt != "poetry" && fmt != "conda" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a PyPI repository (format: {})",
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
        if repo.repo_type == "remote" {
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

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string()),
                    )
                    .body(Body::from(content))
                    .unwrap());
            }
        }
        // For virtual repos, iterate through members and try proxy for remote members
        if repo.repo_type == "virtual" {
            if let Some(ref proxy) = state.proxy_service {
                let members = sqlx::query!(
                    r#"SELECT r.id, r.key, r.repo_type::text as "repo_type!", r.upstream_url
                    FROM repositories r
                    INNER JOIN virtual_repo_members vrm ON r.id = vrm.member_repo_id
                    WHERE vrm.virtual_repo_id = $1
                    ORDER BY vrm.priority"#,
                    repo.id
                )
                .fetch_all(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to resolve virtual members: {}", e),
                    )
                        .into_response()
                })?;

                for member in &members {
                    // Try proxy for remote members
                    if member.repo_type == "remote" {
                        if let Some(ref upstream_url) = member.upstream_url {
                            let upstream_path = format!("simple/{}/", normalized);
                            if let Ok((content, content_type)) = proxy_helpers::proxy_fetch(
                                proxy,
                                member.id,
                                &member.key,
                                upstream_url,
                                &upstream_path,
                            )
                            .await
                            {
                                return Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .header(
                                        CONTENT_TYPE,
                                        content_type.unwrap_or_else(|| {
                                            "text/html; charset=utf-8".to_string()
                                        }),
                                    )
                                    .body(Body::from(content))
                                    .unwrap());
                            }
                        }
                    }
                }
            }
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
        return serve_metadata(&state.db, repo.id, &repo.storage_path, real_filename).await;
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
            if repo.repo_type == "remote" {
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
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let fname = filename.to_string();
                let normalized = PypiHandler::normalize_name(project);
                let upstream_path = format!("simple/{}/{}", normalized, filename);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let fname = fname.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db,
                                member_id,
                                &storage_path,
                                &fname,
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
    db: &PgPool,
    repo_id: uuid::Uuid,
    storage_path: &str,
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
    let storage = FilesystemStorage::new(storage_path);
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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        // "user:pass" in base64 = "dXNlcjpwYXNz"
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid!!!"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        // "useronly" base64 = "dXNlcm9ubHk="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcm9ubHk="),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        // "user:pa:ss" base64 = "dXNlcjpwYTpzcw=="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYTpzcw=="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pa:ss".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_empty_password() {
        let mut headers = HeaderMap::new();
        // "user:" base64 = "dXNlcjo="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjo="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
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
