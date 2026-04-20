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
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{debug, info};

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::error::AppError;
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
// PEP 503 name normalization
// ---------------------------------------------------------------------------

/// Normalize a package name per PEP 503: lowercase, and replace any run of
/// `[-_.]` characters with a single hyphen.
fn normalize_pep503(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut last_was_sep = true;

    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            result.push(c.to_ascii_lowercase());
            last_was_sep = false;
        } else if c == '-' || c == '_' || c == '.' {
            if !last_was_sep {
                result.push('-');
                last_was_sep = true;
            }
        } else {
            // Keep other characters as-is (digits, etc.)
            result.push(c);
            last_was_sep = false;
        }
    }

    if result.ends_with('-') {
        result.pop();
    }

    result
}

// ---------------------------------------------------------------------------
// Internal struct used to decouple DB query results from response rendering.
// ---------------------------------------------------------------------------

struct SimpleProjectArtifact {
    path: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
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

    // Get all distinct package names in this repository, then normalize
    // them in Rust per PEP 503 (the SQL REPLACE chain is only approximate).
    let raw_names: Vec<String> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

    let mut packages: Vec<String> = raw_names
        .iter()
        .map(|n| normalize_pep503(n))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    // Virtual repos have no artifacts of their own. Aggregate package names
    // from all member repos so that the root index lists every package
    // available through the virtual endpoint.
    if packages.is_empty() && repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut merged: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for member in &members {
            if member.repo_type == RepositoryType::Local
                || member.repo_type == RepositoryType::Staging
            {
                let member_raw: Vec<String> = sqlx::query_scalar!(
                    r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false
        "#,
                    member.id
                )
                .fetch_all(&state.db)
                .await
                .map_err(map_db_err)?;

                merged.extend(member_raw.iter().map(|n| normalize_pep503(n)));
            }
            // Remote member proxying for the root index is intentionally
            // skipped: the upstream /simple/ can be very large and slow.
            // Individual package lookups in simple_project() already proxy
            // remote members on demand.
        }

        packages = merged.into_iter().collect();
    }

    build_simple_root_response(&headers, &repo_key, &packages)
}

/// Render the simple root index (list of all packages) as either HTML (PEP 503)
/// or JSON (PEP 691) based on the Accept header.
#[allow(clippy::result_large_err)]
fn build_simple_root_response(
    headers: &HeaderMap,
    repo_key: &str,
    packages: &[String],
) -> Result<Response, Response> {
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

    for package in packages {
        html.push_str(&format!(
            "<a href=\"/pypi/{}/simple/{}/\">{}</a><br/>\n",
            repo_key, package, package
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
    let normalized = normalize_pep503(&project);

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
    .map_err(map_db_err)?;

    let simple_artifacts: Vec<SimpleProjectArtifact> = artifacts
        .into_iter()
        .map(|a| SimpleProjectArtifact {
            path: a.path,
            version: a.version,
            size_bytes: a.size_bytes,
            checksum_sha256: a.checksum_sha256,
            metadata: a.metadata,
        })
        .collect();

    if simple_artifacts.is_empty() {
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
        // For virtual repos, iterate through members in priority order.
        // Local/staging members are queried via DB; remote members use proxy.
        if repo.repo_type == RepositoryType::Virtual {
            let upstream_path = format!("simple/{}/", normalized);
            let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

            if members.is_empty() {
                return Err(
                    AppError::NotFound("Virtual repository has no members".to_string())
                        .into_response(),
                );
            }

            for member in &members {
                // For local and staging repos, query the DB for matching
                // artifacts, the same way we do for the top-level repo.
                if member.repo_type == RepositoryType::Local
                    || member.repo_type == RepositoryType::Staging
                {
                    let member_rows = sqlx::query!(
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
                        member.id,
                        normalized
                    )
                    .fetch_all(&state.db)
                    .await
                    .map_err(map_db_err)?;

                    if !member_rows.is_empty() {
                        let member_artifacts: Vec<SimpleProjectArtifact> = member_rows
                            .into_iter()
                            .map(|a| SimpleProjectArtifact {
                                path: a.path,
                                version: a.version,
                                size_bytes: a.size_bytes,
                                checksum_sha256: a.checksum_sha256,
                                metadata: a.metadata,
                            })
                            .collect();
                        return build_simple_project_response(
                            &headers,
                            &repo_key,
                            &normalized,
                            &member_artifacts,
                        );
                    }
                    continue;
                }

                // For remote repos, proxy the simple index from upstream.
                if member.repo_type != RepositoryType::Remote {
                    continue;
                }
                let Some(ref upstream_url) = member.upstream_url else {
                    continue;
                };
                let Some(ref proxy) = state.proxy_service else {
                    continue;
                };

                let result = proxy_helpers::proxy_fetch(
                    proxy,
                    member.id,
                    &member.key,
                    upstream_url,
                    &upstream_path,
                )
                .await;

                match result {
                    Ok((content, content_type)) => {
                        let ct =
                            content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string());
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
                    Err(_e) => {
                        debug!(
                            member_key = %member.key,
                            "simple index proxy fetch missed for virtual member"
                        );
                    }
                }
            }

            return Err(AppError::NotFound(
                "Package not found in any member repository".to_string(),
            )
            .into_response());
        }

        return Err(AppError::NotFound("Package not found".to_string()).into_response());
    }

    build_simple_project_response(&headers, &repo_key, &normalized, &simple_artifacts)
}

// ---------------------------------------------------------------------------
// Shared response builder for simple project listings (HTML + PEP 691 JSON)
// ---------------------------------------------------------------------------

/// Render the simple project index for a given set of artifacts, using either
/// HTML (PEP 503) or JSON (PEP 691) based on the Accept header.
/// URLs in the response always point through `repo_key` (the virtual or
/// direct repo the client originally requested).
#[allow(clippy::result_large_err)]
fn build_simple_project_response(
    headers: &HeaderMap,
    repo_key: &str,
    normalized: &str,
    artifacts: &[SimpleProjectArtifact],
) -> Result<Response, Response> {
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

    for a in artifacts {
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
    .map_err(map_db_err)?;

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Try the proxy cache first using a predictable local
                    // path. This avoids fetching the simple index from upstream
                    // just to rediscover the download URL when the file is
                    // already cached from a previous request.
                    let normalized = PypiHandler::normalize_name(project);
                    let local_cache_path = format!("simple/{}/{}", normalized, filename);

                    if let Some((content, _ct)) =
                        proxy_helpers::proxy_check_cache(proxy, repo_key, &local_cache_path).await
                    {
                        return Ok(build_file_response(filename, content));
                    }

                    // Cache miss: use PyPI-specific fetch logic.
                    let content = fetch_from_pypi_remote(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        project,
                        filename,
                    )
                    .await?;

                    return Ok(build_file_response(filename, content));
                }
            }
            // Virtual repo: try each member in priority order.
            // Unlike generic formats, PyPI requires format-specific fetch
            // logic for remote members because external registries (e.g.
            // pypi.org) host files on a different domain than the simple
            // index. We iterate members manually and delegate to
            // fetch_from_pypi_remote for each remote member.
            if repo.repo_type == RepositoryType::Virtual {
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

                if members.is_empty() {
                    return Err(AppError::NotFound(
                        "Virtual repository has no members".to_string(),
                    )
                    .into_response());
                }

                for member in &members {
                    // Try local storage first (works for hosted repos and
                    // cached remote artifacts)
                    match proxy_helpers::local_fetch_by_path_suffix(
                        &state.db,
                        state,
                        member.id,
                        &member.storage_location(),
                        filename,
                    )
                    .await
                    {
                        Ok((content, _ct)) => {
                            return Ok(build_file_response(filename, content));
                        }
                        Err(e) => {
                            debug!(
                                member_key = %member.key,
                                error = %e.status(),
                                "local fetch failed for virtual member"
                            );
                        }
                    }

                    // If member is a remote PyPI repo, use the same logic as
                    // the direct Remote path: check the proxy cache first using
                    // a stable key, then fall back to the format-specific fetch
                    // that resolves the real download URL via the simple index.
                    if member.repo_type == RepositoryType::Remote {
                        if let (Some(ref upstream_url), Some(ref proxy)) =
                            (&member.upstream_url, &state.proxy_service)
                        {
                            // Check proxy cache first (same optimization as the
                            // direct Remote path). This avoids re-fetching the
                            // simple index from upstream when the file is already
                            // cached from a previous request through this member.
                            let normalized = PypiHandler::normalize_name(project);
                            let local_cache_path = format!("simple/{}/{}", normalized, filename);

                            if let Some((content, _ct)) = proxy_helpers::proxy_check_cache(
                                proxy,
                                &member.key,
                                &local_cache_path,
                            )
                            .await
                            {
                                return Ok(build_file_response(filename, content));
                            }

                            match fetch_from_pypi_remote(
                                proxy,
                                member.id,
                                &member.key,
                                upstream_url,
                                project,
                                filename,
                            )
                            .await
                            {
                                Ok(content) => {
                                    return Ok(build_file_response(filename, content));
                                }
                                Err(e) => {
                                    debug!(
                                        member_key = %member.key,
                                        error = %e.status(),
                                        "remote PyPI fetch failed for virtual member"
                                    );
                                }
                            }
                        }
                    }
                }

                return Err(AppError::NotFound(
                    "Artifact not found in any member repository".to_string(),
                )
                .into_response());
            }
            return Err(AppError::NotFound("File not found".to_string()).into_response());
        }
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    // Record download statistics for locally-stored artifacts only.
    // Proxied and virtual-repo fetches go through build_file_response()
    // which intentionally skips stats since the artifact is not ours.
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, pypi_content_type(filename))
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-PyPI-File-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

/// Fetch a file from a remote PyPI upstream using the format-specific URL
/// resolution logic. External PyPI registries (e.g. pypi.org) host files on a
/// different domain (files.pythonhosted.org), so we cannot just append the
/// filename to the upstream URL. Instead, we fetch the simple index page,
/// parse it to discover the real download URL for the file, and then download
/// from that URL.
async fn fetch_from_pypi_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &str,
    filename: &str,
) -> Result<Bytes, Response> {
    let normalized = PypiHandler::normalize_name(project);

    let index_path = format!("simple/{}/", normalized);
    let (index_bytes, _ct, effective_url) =
        proxy_helpers::proxy_fetch_uncached(proxy, repo_id, repo_key, upstream_url, &index_path)
            .await?;

    let index_html = String::from_utf8_lossy(&index_bytes);

    // Use the effective URL (after redirects) as the base for resolving
    // relative hrefs. Some registries (Nexus, Artifactory) redirect the
    // index request, and the relative paths in the HTML are relative to
    // the final serving URL, not the originally requested URL.
    let full_index_url = effective_url;
    let file_url = find_upstream_url_for_file(&index_html, filename, Some(&full_index_url));

    let fallback = || {
        (
            upstream_url.to_string(),
            format!("simple/{}/{}", normalized, filename),
        )
    };

    // Validate resolved URL against SSRF before making the outbound request.
    // A malicious upstream index could contain hrefs pointing to internal
    // addresses (169.254.169.254, localhost, Docker service names, etc.).
    if let Some(ref url) = file_url {
        if let Err(e) = validate_outbound_url(url, "PyPI upstream file URL") {
            tracing::warn!(
                "SSRF check rejected resolved file URL '{}' from upstream index: {}",
                url,
                e
            );
            // Fall through to the fallback path instead of fetching the
            // potentially malicious URL.
            return Err(AppError::Validation(format!(
                "Upstream index contains a disallowed URL: {}",
                e
            ))
            .into_response());
        }
    }

    // Use a stable cache key (simple/{project}/{filename}) regardless of the
    // actual upstream URL. Nexus/devpi resolve to paths like
    // packages/requests/2.31.0/requests-2.31.0.tar.gz which differ from the
    // simple/ convention. A stable cache key ensures the cache-check
    // optimization in serve_file works for all upstream registry types.
    let local_cache_path = format!("simple/{}/{}", normalized, filename);

    let (fetch_base, fetch_path) = match file_url.as_deref().and_then(split_url_base_and_path) {
        Some(pair) => pair,
        None => fallback(),
    };

    let (content, _content_type) = proxy_helpers::proxy_fetch_with_cache_key(
        proxy,
        repo_id,
        repo_key,
        &fetch_base,
        &fetch_path,
        &local_cache_path,
    )
    .await?;

    Ok(content)
}

/// Build the HTTP response for serving a PyPI file download.
///
/// Used for proxied and virtual-repo fetches. Download statistics are not
/// recorded here because the artifact is not stored locally; stats are only
/// tracked for artifacts served from our own storage (see `serve_file`).
fn build_file_response(filename: &str, content: Bytes) -> Response {
    let content_type = pypi_content_type(filename);

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap()
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
    .map_err(map_db_err)?
    .ok_or_else(|| AppError::NotFound("File not found".to_string()).into_response())?;

    // Try to extract METADATA from the package file
    let storage = state.storage_for_repo_or_500(location)?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

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
        None => Err(AppError::NotFound("Metadata not available".to_string()).into_response()),
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

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Invalid multipart: {}", e)).into_response())?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            ":action" => {
                action = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "name" => {
                pkg_name = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "version" => {
                pkg_version = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "sha256_digest" => {
                sha256_digest = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "md5_digest" => {
                _md5_digest = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "requires_python" => {
                requires_python = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "summary" => {
                summary = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "content" => {
                file_name = field.file_name().map(|s| s.to_string());
                file_content = Some(field.bytes().await.map_err(|e| {
                    AppError::Validation(format!("Invalid file: {}", e)).into_response()
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
        return Err(
            AppError::Validation(format!("Unsupported action: {}", action)).into_response(),
        );
    }

    let pkg_name = pkg_name
        .ok_or_else(|| AppError::Validation("Missing 'name' field".to_string()).into_response())?;
    let pkg_version = pkg_version.ok_or_else(|| {
        AppError::Validation("Missing 'version' field".to_string()).into_response()
    })?;
    let content = file_content.ok_or_else(|| {
        AppError::Validation("Missing 'content' field".to_string()).into_response()
    })?;
    let filename = file_name.ok_or_else(|| {
        AppError::Validation("Missing filename in content field".to_string()).into_response()
    })?;

    let normalized = PypiHandler::normalize_name(&pkg_name);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Verify digest if provided
    if let Some(ref expected) = sha256_digest {
        if !expected.is_empty() && expected != &computed_sha256 {
            return Err(AppError::Validation(format!(
                "SHA256 mismatch: expected {} got {}",
                expected, computed_sha256
            ))
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
    .map_err(map_db_err)?;

    if existing.is_some() {
        return Err(AppError::Conflict("File already exists".to_string()).into_response());
    }

    // Store the file
    let storage_key = format!("pypi/{}/{}/{}", normalized, pkg_version, filename);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, content.clone())
        .await
        .map_err(map_storage_err)?;

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

    let content_type = pypi_content_type(&filename);

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
    .map_err(map_db_err)?;

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

/// Determine the Content-Type for a PyPI filename based on its extension.
fn pypi_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".whl") || filename.ends_with(".zip") {
        "application/zip"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else if filename.ends_with(".tar.bz2") {
        "application/x-bzip2"
    } else {
        "application/octet-stream"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Static regexes (compiled once, reused across requests)
// ---------------------------------------------------------------------------

static HREF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r##"<a\s+[^>]*?href="([^"#]+)"##).unwrap());

static REWRITE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<a\s+([^>]*?)href="([^"]+)"([^>]*)>"#).unwrap());

static METADATA_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\s*data-(?:dist-info-metadata|core-metadata)="[^"]*""#).unwrap());

/// Split a URL into its base (scheme + host) and path components.
///
/// For example, `https://files.pythonhosted.org/packages/ab/cd/file.whl` splits
/// into `("https://files.pythonhosted.org", "packages/ab/cd/file.whl")`.
/// Returns `None` if the URL has no `://` scheme separator or no path after the
/// host.
fn split_url_base_and_path(url_str: &str) -> Option<(String, String)> {
    let parsed = url::Url::parse(url_str).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let base = format!("{}://{}", parsed.scheme(), parsed.authority());
    let path = parsed.path().strip_prefix('/').unwrap_or(parsed.path());
    if path.is_empty() {
        return None;
    }
    Some((base, path.to_string()))
}

/// Look up the original download URL for a given filename in upstream simple
/// index HTML. Returns the full absolute URL (e.g.,
/// `https://files.pythonhosted.org/packages/.../six-1.16.0.whl`) or `None` if
/// no matching link is found. Hash fragments are stripped from the returned URL.
///
/// Supports both absolute URLs (`https://...`) and relative paths
/// (`../../packages/file.tar.gz` or `packages/file.tar.gz`). Relative paths
/// are resolved against `index_url`, which is the full URL of the simple index
/// page that was fetched (e.g.,
/// `https://nexus.example.com/repository/pypi/simple/requests/`).
///
/// Registries like Sonatype Nexus, Artifactory, and devpi commonly use relative
/// hrefs in their simple index HTML instead of absolute URLs.
fn find_upstream_url_for_file(
    index_html: &str,
    filename: &str,
    index_url: Option<&str>,
) -> Option<String> {
    for caps in HREF_RE.captures_iter(index_html) {
        let href = &caps[1];
        let href_filename = href.rsplit('/').next().unwrap_or("");
        if href_filename != filename {
            continue;
        }

        // Already an absolute URL, return as-is.
        if href.starts_with("http://") || href.starts_with("https://") {
            return Some(href.to_string());
        }

        // Relative or root-relative path: resolve against the index page URL.
        // Only return HTTP/HTTPS results to prevent javascript:, data:, file://
        // and other non-HTTP schemes from being promoted to fetch targets.
        if let Some(base) = index_url {
            if let Ok(base_url) = url::Url::parse(base) {
                if let Ok(resolved) = base_url.join(href) {
                    if resolved.scheme() == "http" || resolved.scheme() == "https" {
                        return Some(resolved.as_str().to_string());
                    }
                    continue;
                }
            }
        }
    }
    None
}

/// Rewrite download URLs in upstream PyPI simple index HTML to route through
/// Artifact Keeper's proxy endpoint.
///
/// Upstream sources return links that would bypass the cache:
///   - External PyPI: `<a href="https://files.pythonhosted.org/packages/...">`
///   - Local AK repos: `<a href="/pypi/upstream-key/simple/pkg/file#hash">`
///
/// This function rewrites both forms to paths under the current (remote) repo:
/// `/pypi/{repo_key}/simple/{project}/{filename}#sha256=...` so downloads go
/// through Artifact Keeper and get cached.
///
/// Absolute URLs (`http://`, `https://`) and root-relative paths starting with
/// `/pypi/` are rewritten. Plain relative URLs and anchors are left unchanged.
///
/// PEP 658 metadata attributes (`data-dist-info-metadata` and
/// `data-core-metadata`) are stripped from rewritten links because the proxy
/// cannot serve `.metadata` files for packages it has not stored locally.
/// Keeping these attributes would cause pip to request a `.metadata` URL that
/// returns 404, which pip treats as a hard error since the index promised the
/// metadata was available.
fn rewrite_upstream_urls(html: &str, repo_key: &str, project: &str) -> String {
    let normalized = PypiHandler::normalize_name(project);

    REWRITE_RE
        .replace_all(html, |caps: &regex::Captures| {
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

            // Strip PEP 658 metadata attributes. The proxy does not cache or
            // serve .metadata files, so advertising them causes pip to fail
            // with a 404 when it tries to fetch the promised metadata.
            let before_cleaned = METADATA_ATTR_RE.replace_all(before_href, "");
            let after_cleaned = METADATA_ATTR_RE.replace_all(after_href, "");

            format!(
                "<a {}href=\"{}\"{}>",
                before_cleaned, rewritten, after_cleaned
            )
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // normalize_pep503
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_pep503_lowercase() {
        assert_eq!(normalize_pep503("MyPackage"), "mypackage");
    }

    #[test]
    fn test_normalize_pep503_underscores_to_hyphen() {
        assert_eq!(normalize_pep503("my_package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_dots_to_hyphen() {
        assert_eq!(normalize_pep503("my.package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_mixed_separators() {
        assert_eq!(normalize_pep503("My_Package.Name"), "my-package-name");
    }

    #[test]
    fn test_normalize_pep503_consecutive_separators() {
        assert_eq!(normalize_pep503("my__package"), "my-package");
        assert_eq!(normalize_pep503("my_._package"), "my-package");
        assert_eq!(normalize_pep503("my--package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_already_normalized() {
        assert_eq!(normalize_pep503("my-package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_trailing_separator() {
        assert_eq!(normalize_pep503("my-package_"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_leading_separator() {
        // Leading separators are collapsed and skipped
        assert_eq!(normalize_pep503("_mypackage"), "mypackage");
    }

    #[test]
    fn test_normalize_pep503_real_world_names() {
        assert_eq!(normalize_pep503("Jinja2"), "jinja2");
        assert_eq!(normalize_pep503("zope.interface"), "zope-interface");
        assert_eq!(normalize_pep503("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(
            normalize_pep503("backports.ssl_match_hostname"),
            "backports-ssl-match-hostname"
        );
    }

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
    fn test_rewrite_rewrites_relative_urls() {
        // Relative URLs should now be rewritten to local proxy paths
        // (previously these were left unchanged, which broke Nexus/devpi remotes)
        let html = r#"<a href="numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert!(result
            .contains(r#"href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123""#));
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
        // Relative URL is now also rewritten (needed for Nexus/devpi remotes)
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-2.0.tar.gz#sha256=bbb""#));
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

    #[test]
    fn test_rewrite_local_upstream_root_relative_url() {
        // When a remote repo proxies a local AK repo, the simple index contains
        // root-relative paths like /pypi/upstream-key/simple/pkg/file#hash
        let html = r#"<a href="/pypi/upstream-local/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_local_upstream_without_hash() {
        let html = r#"<a href="/pypi/upstream-local/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "remote-repo", "pkg");
        assert_eq!(
            result,
            r#"<a href="/pypi/remote-repo/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a>"#
        );
    }

    #[test]
    fn test_rewrite_local_upstream_with_data_attr() {
        let html = r#"<a href="/pypi/upstream/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl#sha256=bbb" data-requires-python="&gt;=3.9">numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl</a>"#;
        let result = rewrite_upstream_urls(html, "my-remote", "numpy");
        assert!(result.contains(
            r#"href="/pypi/my-remote/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl#sha256=bbb""#
        ));
        assert!(result.contains(r#"data-requires-python="&gt;=3.9""#));
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_local_relative() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=aaa">numpy-1.3.0.tar.gz</a>"#,
            "\n",
            r#"<a href="/pypi/local-repo/simple/numpy/numpy-2.0.0.tar.gz#sha256=bbb">numpy-2.0.0.tar.gz</a>"#,
            "\n",
            r#"<a href="numpy-3.0.0.tar.gz#sha256=ccc">numpy-3.0.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "remote", "numpy");
        // Absolute URL is rewritten
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa""#)
        );
        // Root-relative /pypi/ URL is rewritten
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-2.0.0.tar.gz#sha256=bbb""#)
        );
        // Plain relative URL is now also rewritten (needed for Nexus/devpi)
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-3.0.0.tar.gz#sha256=ccc""#)
        );
    }

    #[test]
    fn test_rewrite_full_local_upstream_index() {
        // Simulates the full HTML generated by a local AK PyPI repo
        let html = r#"<!DOCTYPE html>
<html>
<head>
<meta name="pypi:repository-version" content="1.0"/>
<title>Links for mypackage</title>
</head>
<body>
<h1>Links for mypackage</h1>
<a href="/pypi/local-pypi/simple/mypackage/mypackage-1.0.0.tar.gz#sha256=aaa111">mypackage-1.0.0.tar.gz</a><br/>
<a href="/pypi/local-pypi/simple/mypackage/mypackage-1.0.0-py3-none-any.whl#sha256=bbb222" data-requires-python="&gt;=3.8">mypackage-1.0.0-py3-none-any.whl</a><br/>
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "remote-pypi", "mypackage");

        // Local upstream URLs should be rewritten to use the remote repo key
        assert!(!result.contains("local-pypi"));
        assert!(result.contains(
            r#"href="/pypi/remote-pypi/simple/mypackage/mypackage-1.0.0.tar.gz#sha256=aaa111""#
        ));
        assert!(result.contains(
            r#"href="/pypi/remote-pypi/simple/mypackage/mypackage-1.0.0-py3-none-any.whl#sha256=bbb222""#
        ));

        // data-requires-python and other structure should be preserved
        assert!(result.contains("data-requires-python"));
        assert!(result.contains("<h1>Links for mypackage</h1>"));
    }

    #[test]
    fn test_rewrite_strips_data_dist_info_metadata() {
        // Real PyPI HTML includes data-dist-info-metadata on .whl links.
        // The proxy cannot serve .metadata files, so these attributes must
        // be stripped to prevent pip from requesting them and getting 404.
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=8abb" data-requires-python="&gt;=2.7" data-dist-info-metadata="sha256=5507" data-core-metadata="sha256=5507">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-proxy", "six");
        assert!(result.contains(
            r#"href="/pypi/pypi-proxy/simple/six/six-1.16.0-py2.py3-none-any.whl#sha256=8abb""#
        ));
        // data-requires-python should be preserved
        assert!(result.contains(r#"data-requires-python="&gt;=2.7""#));
        // PEP 658 metadata attributes must be stripped
        assert!(!result.contains("data-dist-info-metadata"));
        assert!(!result.contains("data-core-metadata"));
    }

    #[test]
    fn test_rewrite_strips_metadata_attrs_from_real_pypi_html() {
        // Simulates the actual HTML returned by pypi.org for the `six` package
        let html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.4"><title>Links for six</title></head>
<body>
<h1>Links for six</h1>
<a href="https://files.pythonhosted.org/packages/b7/ce/six-1.17.0-py2.py3-none-any.whl#sha256=4721" data-requires-python="!=3.0.*,!=3.1.*,!=3.2.*,&gt;=2.7" data-dist-info-metadata="sha256=5620" data-core-metadata="sha256=5620">six-1.17.0-py2.py3-none-any.whl</a><br />
<a href="https://files.pythonhosted.org/packages/94/e7/six-1.17.0.tar.gz#sha256=ff70" data-requires-python="!=3.0.*,!=3.1.*,!=3.2.*,&gt;=2.7" >six-1.17.0.tar.gz</a><br />
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "pypi-proxy", "six");

        // URLs should be rewritten
        assert!(!result.contains("files.pythonhosted.org"));
        assert!(result.contains(
            r#"href="/pypi/pypi-proxy/simple/six/six-1.17.0-py2.py3-none-any.whl#sha256=4721""#
        ));
        assert!(
            result.contains(r#"href="/pypi/pypi-proxy/simple/six/six-1.17.0.tar.gz#sha256=ff70""#)
        );

        // data-requires-python should be preserved on both links
        assert!(result.contains("data-requires-python"));

        // PEP 658 metadata attributes must be stripped from the .whl link
        assert!(!result.contains("data-dist-info-metadata"));
        assert!(!result.contains("data-core-metadata"));

        // Structure should be preserved
        assert!(result.contains("<h1>Links for six</h1>"));
    }

    #[test]
    fn test_rewrite_strips_metadata_attr_before_href() {
        // Edge case: metadata attribute appears before href
        let html = r#"<a data-dist-info-metadata="sha256=abc" href="https://example.com/pkg-1.0.whl#sha256=def">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=def""#));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_preserves_non_metadata_attrs() {
        // Only PEP 658 attrs should be stripped; other data-* attrs remain
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=abc" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=def" data-gpg-sig="true">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains("data-requires-python"));
        assert!(result.contains("data-gpg-sig"));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_relative_dotdot_href() {
        // Nexus-style relative href should be rewritten to local proxy path
        let html = r#"<a href="../../packages/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "requests");
        assert!(result.contains(
            r#"href="/pypi/pypi-remote/simple/requests/requests-2.31.0.tar.gz#sha256=abc""#
        ));
    }

    #[test]
    fn test_rewrite_root_relative_href() {
        // Root-relative href (/packages/...) should also be rewritten
        let html =
            r#"<a href="/packages/ab/cd/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "six");
        assert!(result.contains(r#"href="/pypi/repo/simple/six/six-1.16.0.tar.gz#sha256=abc""#));
    }

    #[test]
    fn test_rewrite_plain_relative_href() {
        // Plain relative href (packages/file.tar.gz) from devpi
        let html = r#"<a href="packages/pkg-1.0.tar.gz#sha256=abc">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "devpi-remote", "pkg");
        assert!(
            result.contains(r#"href="/pypi/devpi-remote/simple/pkg/pkg-1.0.tar.gz#sha256=abc""#)
        );
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_relative_hrefs() {
        let html = concat!(
            r#"<a href="https://files.example.com/pkg-1.0.whl#sha256=aaa">pkg-1.0.whl</a>"#,
            "\n",
            r#"<a href="../../packages/pkg-1.0.tar.gz#sha256=bbb">pkg-1.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        // Both should be rewritten to local proxy paths
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=aaa""#));
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#sha256=bbb""#));
    }

    // -----------------------------------------------------------------------
    // find_upstream_url_for_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_upstream_url_basic() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=abc">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_no_match() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.15.0.tar.gz", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_relative_ignored_without_index_url() {
        // Relative URLs cannot be resolved without an index URL
        let html = r#"<a href="/pypi/local/simple/six/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_multiple_files() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/a/six-1.15.0.tar.gz#sha256=aaa">six-1.15.0.tar.gz</a>"#,
            "\n",
            r#"<a href="https://files.pythonhosted.org/packages/b/six-1.16.0-py2.py3-none-any.whl#sha256=bbb">six-1.16.0-py2.py3-none-any.whl</a>"#,
        );
        let result = find_upstream_url_for_file(html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/b/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_with_data_attrs() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-2.0.0.whl#sha256=abc" data-requires-python="&gt;=3.9">numpy-2.0.0.whl</a>"#;
        let result = find_upstream_url_for_file(html, "numpy-2.0.0.whl", None);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/numpy-2.0.0.whl".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_raw_index_has_absolute_urls() {
        // Simulates a real upstream simple index from pypi.org.
        // find_upstream_url_for_file must find the correct absolute URL
        // when given the raw (un-rewritten) upstream HTML.
        let raw_upstream_html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.0"/><title>Links for six</title></head>
<body>
<h1>Links for six</h1>
<a href="https://files.pythonhosted.org/packages/71/39/six-1.16.0-py2.py3-none-any.whl#sha256=8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254">six-1.16.0-py2.py3-none-any.whl</a><br/>
<a href="https://files.pythonhosted.org/packages/94/e7/six-1.16.0.tar.gz#sha256=1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926">six-1.16.0.tar.gz</a><br/>
</body>
</html>
"#;
        let result =
            find_upstream_url_for_file(raw_upstream_html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/71/39/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );

        let result = find_upstream_url_for_file(raw_upstream_html, "six-1.16.0.tar.gz", None);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/94/e7/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_fails_on_rewritten_html() {
        // After rewrite_upstream_urls(), all absolute URLs become local
        // /pypi/... paths. Without an index_url, these cannot be resolved.
        let rewritten_html = r#"<!DOCTYPE html>
<html>
<head><title>Links for six</title></head>
<body>
<a href="/pypi/pypi-proxy/simple/six/six-1.16.0-py2.py3-none-any.whl#sha256=8abb">six-1.16.0-py2.py3-none-any.whl</a><br/>
<a href="/pypi/pypi-proxy/simple/six/six-1.16.0.tar.gz#sha256=1e61">six-1.16.0.tar.gz</a><br/>
</body>
</html>
"#;
        let result =
            find_upstream_url_for_file(rewritten_html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // find_upstream_url_for_file - relative URL resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_upstream_url_relative_dotdot_path() {
        // Nexus-style relative href with ../../ prefix.
        // Base: /repository/pypi/simple/requests/
        //   ../ => /repository/pypi/simple/
        //   ../ => /repository/pypi/
        //   packages/... => /repository/pypi/packages/requests-2.31.0.tar.gz
        let html = r#"<a href="../../packages/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/requests/";
        let result = find_upstream_url_for_file(html, "requests-2.31.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://nexus.example.com/repository/pypi/packages/requests-2.31.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_plain_path() {
        // Simple relative path without ../ prefix
        let html = r#"<a href="packages/pkg-1.0.tar.gz#sha256=abc">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://devpi.local/root/pypi/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://devpi.local/root/pypi/simple/pkg/packages/pkg-1.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_root_relative_path() {
        // Root-relative path starting with /
        let html =
            r#"<a href="/packages/ab/cd/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/six/";
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://nexus.example.com/packages/ab/cd/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_relative_multiple_dotdot() {
        // Multiple levels of ../ traversal (Artifactory-style deep paths).
        // Base: /api/pypi/pypi-remote/simple/numpy/
        //   ../  => /api/pypi/pypi-remote/simple/
        //   ../  => /api/pypi/pypi-remote/
        //   ../  => /api/pypi/
        //   packages/... => /api/pypi/packages/numpy/1.24.0/numpy-1.24.0.tar.gz
        let html = r#"<a href="../../../packages/numpy/1.24.0/numpy-1.24.0.tar.gz#sha256=abc">numpy-1.24.0.tar.gz</a>"#;
        let index_url = "https://artifactory.corp.com/api/pypi/pypi-remote/simple/numpy/";
        let result = find_upstream_url_for_file(html, "numpy-1.24.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://artifactory.corp.com/api/pypi/packages/numpy/1.24.0/numpy-1.24.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_prefers_absolute_first() {
        // When both absolute and relative URLs exist, the first match wins.
        // Absolute URLs are found and returned without needing resolution.
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/six-1.16.0.tar.gz#sha256=aaa">six-1.16.0.tar.gz</a>"#,
            "\n",
            r#"<a href="../../packages/six-1.16.0.tar.gz#sha256=bbb">six-1.16.0.tar.gz</a>"#,
        );
        let index_url = "https://nexus.example.com/repository/pypi/simple/six/";
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_nexus_full_index() {
        // Simulates a real Nexus simple index page with relative hrefs.
        // ../../ from /repository/pypi/simple/requests/ resolves to
        // /repository/pypi/ so the final path is
        // /repository/pypi/packages/requests/2.31.0/requests-2.31.0.tar.gz
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Links for requests</title></head>
<body>
<h1>Links for requests</h1>
<a href="../../packages/requests/2.31.0/requests-2.31.0-py3-none-any.whl#sha256=aaa">requests-2.31.0-py3-none-any.whl</a><br/>
<a href="../../packages/requests/2.31.0/requests-2.31.0.tar.gz#sha256=bbb">requests-2.31.0.tar.gz</a><br/>
<a href="../../packages/requests/2.32.0/requests-2.32.0-py3-none-any.whl#sha256=ccc">requests-2.32.0-py3-none-any.whl</a><br/>
</body>
</html>
"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/requests/";
        let result = find_upstream_url_for_file(html, "requests-2.31.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://nexus.example.com/repository/pypi/packages/requests/2.31.0/requests-2.31.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_no_match() {
        // Relative URLs present but no filename match
        let html = r#"<a href="../../packages/other-1.0.tar.gz#sha256=abc">other-1.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/other/";
        let result = find_upstream_url_for_file(html, "nonexistent-1.0.tar.gz", Some(index_url));
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_rejects_javascript_scheme() {
        let html = r#"<a href="javascript:fetch('http://internal/secret')/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://registry.example.com/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        // javascript: hrefs must not produce a fetchable URL
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_rejects_data_scheme() {
        let html = r#"<a href="data:application/octet-stream;base64,abc/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://registry.example.com/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        assert_eq!(result, None);
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

    // -----------------------------------------------------------------------
    // build_file_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_file_response_wheel_content_type() {
        let content = Bytes::from_static(b"fake wheel data");
        let resp =
            build_file_response("numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", content);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/zip");
    }

    #[test]
    fn test_build_file_response_sdist_content_type() {
        let content = Bytes::from_static(b"fake sdist data");
        let resp = build_file_response("six-1.16.0.tar.gz", content);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
    }

    #[test]
    fn test_build_file_response_zip_extension() {
        let content = Bytes::from_static(b"some data");
        let resp = build_file_response("package-1.0.zip", content);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/zip");
    }

    #[test]
    fn test_build_file_response_unknown_extension() {
        let content = Bytes::from_static(b"some data");
        let resp = build_file_response("package-1.0.egg", content);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_build_file_response_content_disposition() {
        let content = Bytes::from_static(b"data");
        let resp = build_file_response("requests-2.31.0.tar.gz", content);
        assert_eq!(
            resp.headers().get("Content-Disposition").unwrap(),
            "attachment; filename=\"requests-2.31.0.tar.gz\""
        );
    }

    #[test]
    fn test_build_file_response_content_length() {
        let data = b"hello world data here";
        let content = Bytes::from_static(data);
        let resp = build_file_response("pkg-1.0.tar.gz", content);
        assert_eq!(
            resp.headers().get(CONTENT_LENGTH).unwrap(),
            &data.len().to_string()
        );
    }

    // -----------------------------------------------------------------------
    // pypi_content_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_pypi_content_type_whl() {
        assert_eq!(
            pypi_content_type("numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
            "application/zip"
        );
    }

    #[test]
    fn test_pypi_content_type_tar_gz() {
        assert_eq!(pypi_content_type("six-1.16.0.tar.gz"), "application/gzip");
    }

    #[test]
    fn test_pypi_content_type_tar_bz2() {
        assert_eq!(
            pypi_content_type("package-1.0.tar.bz2"),
            "application/x-bzip2"
        );
    }

    #[test]
    fn test_pypi_content_type_zip() {
        assert_eq!(pypi_content_type("package-1.0.zip"), "application/zip");
    }

    #[test]
    fn test_pypi_content_type_unknown() {
        assert_eq!(
            pypi_content_type("package-1.0.egg"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // split_url_base_and_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_url_normal() {
        let result =
            split_url_base_and_path("https://files.pythonhosted.org/packages/ab/cd/file.whl");
        assert_eq!(
            result,
            Some((
                "https://files.pythonhosted.org".to_string(),
                "packages/ab/cd/file.whl".to_string()
            ))
        );
    }

    #[test]
    fn test_split_url_with_port() {
        let result = split_url_base_and_path("http://localhost:8080/api/v1/packages");
        assert_eq!(
            result,
            Some((
                "http://localhost:8080".to_string(),
                "api/v1/packages".to_string()
            ))
        );
    }

    #[test]
    fn test_split_url_without_path() {
        // URL with host only and no trailing slash has no path component
        let result = split_url_base_and_path("https://example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_split_url_with_single_path_segment() {
        let result = split_url_base_and_path("https://example.com/file.whl");
        assert_eq!(
            result,
            Some(("https://example.com".to_string(), "file.whl".to_string()))
        );
    }

    #[test]
    fn test_split_url_no_scheme() {
        let result = split_url_base_and_path("not-a-url");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // build_simple_project_response — HTML (PEP 503)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_project_response_html_single_artifact() {
        let artifacts = vec![SimpleProjectArtifact {
            path: "my-package/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 12345,
            checksum_sha256: "abc123def456".to_string(),
            metadata: None,
        }];

        let headers = HeaderMap::new();
        let result =
            build_simple_project_response(&headers, "my-virtual", "my-package", &artifacts);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/html; charset=utf-8");
    }

    #[test]
    fn test_build_simple_project_response_html_uses_virtual_repo_key() {
        // Reproducer for #643: when a local repo is part of a virtual repo,
        // the simple index URLs must use the virtual repo key, not the member's.
        let artifacts = vec![SimpleProjectArtifact {
            path: "packages/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 5000,
            checksum_sha256: "aaa111bbb222".to_string(),
            metadata: None,
        }];

        let headers = HeaderMap::new();
        let result =
            build_simple_project_response(&headers, "pypi-virtual", "my-package", &artifacts);
        let response = result.unwrap();

        // Read the body to verify URLs point through the virtual repo
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("/pypi/pypi-virtual/simple/my-package/my_package-1.0.0.tar.gz"),
            "URL should use the virtual repo key, got: {}",
            html
        );
        assert!(
            html.contains("sha256=aaa111bbb222"),
            "URL should include sha256 hash"
        );
        assert!(
            html.contains("<h1>Links for my-package</h1>"),
            "HTML should include package heading"
        );
    }

    #[test]
    fn test_build_simple_project_response_html_with_requires_python() {
        let metadata = serde_json::json!({
            "pkg_info": {
                "requires_python": ">=3.8"
            }
        });

        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0-py3-none-any.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 4000,
            checksum_sha256: "deadbeef".to_string(),
            metadata: Some(metadata),
        }];

        let headers = HeaderMap::new();
        let result = build_simple_project_response(&headers, "virt", "pkg", &artifacts);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("data-requires-python=\"&gt;=3.8\""),
            "HTML should include escaped requires-python attribute"
        );
    }

    #[test]
    fn test_build_simple_project_response_html_multiple_artifacts() {
        let artifacts = vec![
            SimpleProjectArtifact {
                path: "pkg-1.0.0.tar.gz".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 1000,
                checksum_sha256: "aaa".to_string(),
                metadata: None,
            },
            SimpleProjectArtifact {
                path: "pkg-2.0.0.tar.gz".to_string(),
                version: Some("2.0.0".to_string()),
                size_bytes: 2000,
                checksum_sha256: "bbb".to_string(),
                metadata: None,
            },
        ];

        let headers = HeaderMap::new();
        let result = build_simple_project_response(&headers, "vrepo", "pkg", &artifacts);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("/pypi/vrepo/simple/pkg/pkg-1.0.0.tar.gz#sha256=aaa"));
        assert!(html.contains("/pypi/vrepo/simple/pkg/pkg-2.0.0.tar.gz#sha256=bbb"));
    }

    // -----------------------------------------------------------------------
    // build_simple_project_response — JSON (PEP 691)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_project_response_json_uses_virtual_repo_key() {
        // PEP 691 variant of the #643 reproducer: JSON response should also
        // route URLs through the virtual repo.
        let artifacts = vec![SimpleProjectArtifact {
            path: "packages/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 5000,
            checksum_sha256: "abc123".to_string(),
            metadata: None,
        }];

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result =
            build_simple_project_response(&headers, "pypi-virtual", "my-package", &artifacts);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "my-package");
        assert_eq!(json["meta"]["api-version"], "1.1");

        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "my_package-1.0.0.tar.gz");
        assert!(
            files[0]["url"]
                .as_str()
                .unwrap()
                .contains("/pypi/pypi-virtual/simple/my-package/"),
            "JSON URL should use virtual repo key"
        );
        assert_eq!(files[0]["hashes"]["sha256"], "abc123");
        assert_eq!(files[0]["size"], 5000);

        let versions = json["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0], "1.0.0");
    }

    #[test]
    fn test_build_simple_project_response_json_with_requires_python() {
        let metadata = serde_json::json!({
            "pkg_info": {
                "requires_python": ">=3.9,<4.0"
            }
        });

        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0-py3-none-any.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 3000,
            checksum_sha256: "cafe".to_string(),
            metadata: Some(metadata),
        }];

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result = build_simple_project_response(&headers, "repo", "pkg", &artifacts);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let files = json["files"].as_array().unwrap();
        assert_eq!(files[0]["requires-python"], ">=3.9,<4.0");
    }

    // -----------------------------------------------------------------------
    // build_simple_root_response (PEP 503 / PEP 691 root index)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_root_response_html() {
        let packages = vec![
            "flask".to_string(),
            "numpy".to_string(),
            "requests".to_string(),
        ];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/html; charset=utf-8");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("<h1>Simple Index</h1>"));
        assert!(html.contains("/pypi/pypi-virtual/simple/flask/"));
        assert!(html.contains("/pypi/pypi-virtual/simple/numpy/"));
        assert!(html.contains("/pypi/pypi-virtual/simple/requests/"));
    }

    #[test]
    fn test_build_simple_root_response_json() {
        let packages = vec!["flask".to_string(), "numpy".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["meta"]["api-version"], "1.1");
        let projects = json["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0]["name"], "flask");
        assert_eq!(projects[1]["name"], "numpy");
    }

    #[test]
    fn test_build_simple_root_response_empty_packages() {
        let packages: Vec<String> = vec![];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-local", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("<h1>Simple Index</h1>"));
        // No package links should appear
        assert!(!html.contains("<a href="));
    }

    #[test]
    fn test_build_simple_root_response_deduplicates_via_btreeset() {
        // Verify that duplicate package names (which would come from
        // multiple member repos in a virtual) are already deduplicated
        // by the BTreeSet in simple_root before reaching the response
        // builder. The response builder itself renders whatever it gets.
        let packages = vec!["flask".to_string(), "flask".to_string()];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Two entries appear because deduplication is the caller's job
        // (simple_root uses BTreeSet). This test documents the contract.
        let count = html.matches("/pypi/pypi-virtual/simple/flask/").count();
        assert_eq!(count, 2);
    }
}
