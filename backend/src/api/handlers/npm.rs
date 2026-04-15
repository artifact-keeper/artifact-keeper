//! npm Registry API handlers.
//!
//! Implements the endpoints required for `npm publish` and `npm install`.
//!
//! Routes are mounted at `/npm/{repo_key}/...`:
//!   GET  /npm/{repo_key}/{package}                    - Get package metadata
//!   GET  /npm/{repo_key}/{@scope}/{package}           - Get scoped package metadata
//!   GET  /npm/{repo_key}/{package}/-/{filename}       - Download tarball
//!   GET  /npm/{repo_key}/{@scope}/{package}/-/{filename} - Download scoped tarball
//!   PUT  /npm/{repo_key}/{package}                    - Publish package
//!   PUT  /npm/{repo_key}/{@scope}/{package}           - Publish scoped package

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{debug, info};

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::AppError;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Scoped package tarball: GET /npm/{repo_key}/@{scope}/{package}/-/{filename}
        .route(
            "/:repo_key/@:scope/:package/-/:filename",
            get(download_scoped_tarball),
        )
        // Scoped package metadata / publish: GET/PUT /npm/{repo_key}/@{scope}/{package}
        .route(
            "/:repo_key/@:scope/:package",
            get(get_scoped_metadata).put(publish_scoped),
        )
        // Unscoped package tarball: GET /npm/{repo_key}/{package}/-/{filename}
        .route("/:repo_key/:package/-/:filename", get(download_tarball))
        // Unscoped package metadata / publish: GET/PUT /npm/{repo_key}/{package}
        .route("/:repo_key/:package", get(get_metadata).put(publish))
}

use crate::api::middleware::auth::require_auth_with_bearer_fallback;

// ---------------------------------------------------------------------------
// Package name normalization
// ---------------------------------------------------------------------------

/// Normalize an npm package name by URL-decoding any percent-encoded characters.
///
/// npm and yarn clients often encode scoped package names in URLs, turning
/// `@openai/codex` into `@openai%2Fcodex` or `%40openai%2fcodex`. Axum's
/// `Path` extractor usually decodes these, but we apply an explicit decode as
/// a safety net so the name always reaches the database and upstream proxy in
/// its canonical form (e.g. `@openai/codex`).
fn normalize_package_name(raw: &str) -> String {
    urlencoding::decode(raw)
        .map(|cow| cow.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

/// Validate a decoded npm package name.
///
/// Rejects names with path traversal sequences, null bytes, and names that
/// violate the npm naming rules (empty, too long, leading dot/underscore,
/// non-lowercase for unscoped packages). Called after URL decoding to catch
/// percent-encoded attacks like `%2e%2e%2f`.
#[allow(clippy::result_large_err)]
fn validate_package_name(name: &str) -> Result<(), Response> {
    if name.is_empty() {
        return Err(map_status(
            StatusCode::BAD_REQUEST,
            "Package name cannot be empty",
        ));
    }
    if name.len() > 214 {
        return Err(map_status(StatusCode::BAD_REQUEST, "Package name too long"));
    }
    if name.contains('\0') {
        return Err(map_status(
            StatusCode::BAD_REQUEST,
            "Package name contains null bytes",
        ));
    }
    // After decoding, the only slash allowed is the single scope separator
    // in scoped packages (@scope/pkg). Reject traversal sequences.
    if name.contains("..") {
        return Err(map_status(
            StatusCode::BAD_REQUEST,
            "Package name contains path traversal",
        ));
    }
    // Unscoped names must not contain slashes at all
    if !name.starts_with('@') && name.contains('/') {
        return Err(map_status(
            StatusCode::BAD_REQUEST,
            "Unscoped package name contains '/'",
        ));
    }
    // Scoped names must have exactly one slash
    if let Some(rest) = name.strip_prefix('@') {
        if rest.matches('/').count() != 1 {
            return Err(map_status(
                StatusCode::BAD_REQUEST,
                "Scoped package name must have exactly one '/'",
            ));
        }
    }
    if name.starts_with('.') || name.starts_with('_') {
        return Err(map_status(
            StatusCode::BAD_REQUEST,
            "Package name cannot start with '.' or '_'",
        ));
    }
    Ok(())
}

fn map_status(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({"error": msg}))).into_response()
}

/// Encode a package name for use in upstream registry URLs.
///
/// Scoped packages like `@openai/codex` must be sent to upstream registries
/// with the scope separator encoded: `@openai%2Fcodex`. The public npm
/// registry accepts both forms, but private registries (Nexus, Verdaccio,
/// GitHub Packages) often require the encoded form. Unscoped packages are
/// returned unchanged.
fn encode_package_name_for_upstream(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = rest.split_once('/') {
            return format!("@{}%2F{}", scope, pkg);
        }
    }
    name.to_string()
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_npm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["npm", "yarn", "pnpm", "bower"], "an npm")
        .await
}

// ---------------------------------------------------------------------------
// GET metadata handlers
// ---------------------------------------------------------------------------

async fn get_metadata(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    get_package_metadata(&state, &repo_key, &package, &headers).await
}

async fn get_scoped_metadata(
    State(state): State<SharedState>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let scope = normalize_package_name(&scope);
    let package = normalize_package_name(&package);
    let full_name = format!("@{}/{}", scope, package);
    validate_package_name(&full_name)?;
    get_package_metadata(&state, &repo_key, &full_name, &headers).await
}

/// Minimal artifact info needed to construct npm package metadata.
struct NpmMetadataArtifact {
    path: String,
    version: Option<String>,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
}

/// Build an npm package metadata JSON response from a set of artifacts.
///
/// `repo_key` should be the key visible to the client (the virtual repo key
/// when serving through a virtual repository, or the repo's own key otherwise).
#[allow(clippy::result_large_err)]
fn build_npm_metadata_response(
    artifacts: &[NpmMetadataArtifact],
    package_name: &str,
    base_url: &str,
    repo_key: &str,
) -> Result<Response, Response> {
    let mut versions = serde_json::Map::new();
    let mut latest_version: Option<String> = None;

    for artifact in artifacts {
        let version = match &artifact.version {
            Some(v) => v.clone(),
            None => continue,
        };

        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        let tarball_url = format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        );

        let version_metadata = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version_data").cloned())
            .unwrap_or_else(|| serde_json::json!({}));

        let mut version_obj = if version_metadata.is_object() {
            version_metadata
        } else {
            serde_json::json!({})
        };

        let obj = version_obj.as_object_mut().unwrap();
        obj.entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(package_name.to_string()));
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(version.clone()));

        let hex = &artifact.checksum_sha256;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let integrity = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
        obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": tarball_url,
                "integrity": integrity,
            }),
        );

        versions.insert(version.clone(), version_obj);
        latest_version = Some(version);
    }

    let dist_tags = serde_json::json!({
        "latest": latest_version.unwrap_or_default()
    });

    let response = serde_json::json!({
        "name": package_name,
        "versions": versions,
        "dist-tags": dist_tags,
    });

    Ok(build_json_metadata_response(
        serde_json::to_string(&response).unwrap(),
    ))
}

/// Fetch all non-deleted artifacts for a given package from a single repository,
/// returning them as `NpmMetadataArtifact` values. Used by both the virtual
/// member loop and the local/staged repo fallback to avoid duplicating the
/// query and row-mapping logic.
async fn fetch_npm_artifacts(
    db: &PgPool,
    repository_id: uuid::Uuid,
    package_name: &str,
) -> Result<Vec<NpmMetadataArtifact>, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, a.created_at,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repository_id,
        package_name
    )
    .fetch_all(db)
    .await
    .map_err(map_db_err)?;

    Ok(rows
        .into_iter()
        .map(|a| NpmMetadataArtifact {
            path: a.path,
            version: a.version,
            checksum_sha256: a.checksum_sha256,
            metadata: a.metadata,
        })
        .collect())
}

/// Build and return the npm package metadata JSON for all versions.
async fn get_package_metadata(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let base_url = proxy_helpers::request_base_url(headers);

    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // For remote repos, always proxy metadata from upstream. Cached tarball
    // artifacts do not contain enough information to reconstruct the full
    // package metadata that npm clients expect.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            if let Some(ref proxy) = state.proxy_service {
                let encoded_name = encode_package_name_for_upstream(package_name);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    repo_key,
                    upstream_url,
                    &encoded_name,
                )
                .await?;

                return Ok(rewrite_and_respond(
                    content,
                    content_type,
                    &base_url,
                    repo_key,
                ));
            }
        }
        return Err(AppError::NotFound("Package not found".to_string()).into_response());
    }

    // For virtual repos, iterate through members in priority order.
    // Local/Staging members are checked first (query DB for artifacts),
    // then Remote members are proxied from upstream. First match wins.
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

        if members.is_empty() {
            return Err(
                AppError::NotFound("Virtual repository has no members".to_string()).into_response(),
            );
        }

        for member in &members {
            // For Local/Staging members, query artifacts from the DB.
            if member.repo_type == RepositoryType::Local
                || member.repo_type == RepositoryType::Staging
            {
                let meta = fetch_npm_artifacts(&state.db, member.id, package_name).await?;
                if !meta.is_empty() {
                    return build_npm_metadata_response(&meta, package_name, &base_url, repo_key);
                }
                continue;
            }

            // For Remote members, proxy metadata from upstream.
            if member.repo_type != RepositoryType::Remote {
                continue;
            }
            let Some(ref upstream_url) = member.upstream_url else {
                continue;
            };
            let Some(ref proxy) = state.proxy_service else {
                continue;
            };

            let encoded_name = encode_package_name_for_upstream(package_name);
            let result = proxy_helpers::proxy_fetch(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                &encoded_name,
            )
            .await;

            match result {
                Ok((content, content_type)) => {
                    return Ok(rewrite_and_respond(
                        content,
                        content_type,
                        &base_url,
                        repo_key,
                    ));
                }
                Err(_e) => {
                    debug!(
                        member_key = %member.key,
                        "npm metadata proxy fetch missed for virtual member"
                    );
                }
            }
        }

        return Err(
            AppError::NotFound("Package not found in any member repository".to_string())
                .into_response(),
        );
    }

    // For local/staged repos, build metadata from stored artifacts
    let meta_artifacts = fetch_npm_artifacts(&state.db, repo.id, package_name).await?;

    if meta_artifacts.is_empty() {
        return Err(AppError::NotFound("Package not found".to_string()).into_response());
    }

    build_npm_metadata_response(&meta_artifacts, package_name, &base_url, repo_key)
}

/// Content type for npm tarballs (.tgz). npm packages are always gzip-compressed
/// tar archives. Upstream registries (including npmjs.org) sometimes serve these
/// as `application/octet-stream`, but the correct MIME type is `application/gzip`.
/// Using the right content type is important because downstream services (SBOM
/// generation, Trivy, Grype) rely on it to decide how to extract and scan the
/// artifact contents.
const NPM_TARBALL_CONTENT_TYPE: &str = "application/gzip";

/// Build an HTTP response for an npm tarball download.
///
/// All three download paths (remote, virtual, local) return the same response
/// shape: the tarball bytes with `application/gzip` content type, a
/// `Content-Disposition` attachment header, and the content length. This helper
/// eliminates the repeated response-builder blocks.
fn build_tarball_response(
    content: Bytes,
    filename: &str,
    content_type: Option<String>,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| NPM_TARBALL_CONTENT_TYPE.to_string()),
        )
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap()
}

/// Build an OK response with a given content type and body.
fn build_ok_response(content_type: &str, body: impl Into<Body>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
}

/// Build a JSON response from rewritten npm metadata.
///
/// Both the remote and virtual metadata paths rewrite upstream tarball URLs and
/// return the modified JSON with `application/json` content type.
fn build_json_metadata_response(json_string: String) -> Response {
    build_ok_response("application/json", json_string)
}

/// Try to parse upstream content as JSON, rewrite tarball URLs, and return the
/// rewritten metadata. Falls back to a raw passthrough if the content is not
/// valid JSON. Used by both the remote and virtual metadata paths.
fn rewrite_and_respond(
    content: Bytes,
    content_type: Option<String>,
    base_url: &str,
    repo_key: &str,
) -> Response {
    if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&content) {
        rewrite_npm_tarball_urls(&mut json, base_url, repo_key);
        let rewritten = serde_json::to_string(&json).unwrap_or_default();
        return build_json_metadata_response(rewritten);
    }
    // Not valid JSON: pass through with the original content type
    let ct = content_type.unwrap_or_else(|| "application/json".to_string());
    build_ok_response(&ct, content)
}

// ---------------------------------------------------------------------------
// GET tarball download handlers
// ---------------------------------------------------------------------------

async fn download_tarball(
    State(state): State<SharedState>,
    Path((repo_key, package, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    serve_tarball(&state, &repo_key, &package, &filename).await
}

async fn download_scoped_tarball(
    State(state): State<SharedState>,
    Path((repo_key, scope, package, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let scope = normalize_package_name(&scope);
    let package = normalize_package_name(&package);
    let full_name = format!("@{}/{}", scope, package);
    validate_package_name(&full_name)?;
    serve_tarball(&state, &repo_key, &full_name, &filename).await
}

/// Fetch an npm tarball from a virtual member's local storage, matching
/// by the full upstream path or by the package name + filename pattern.
///
/// npm tarball filenames strip the scope prefix, so two different packages
/// can produce the same filename (e.g. `mdurl` and `@types/mdurl` both
/// produce `mdurl-2.0.0.tgz`). A bare filename suffix match with
/// `local_fetch_by_path_suffix` can return the wrong package's tarball.
/// This function narrows the match by checking the upstream proxy path
/// first (exact match for proxy-cached artifacts), then falling back to
/// a pattern that includes the decoded package name (for locally published
/// artifacts).
async fn npm_local_fetch(
    db: &PgPool,
    state: &SharedState,
    repo_id: uuid::Uuid,
    location: &crate::storage::StorageLocation,
    upstream_path: &str,
    package_name: &str,
    filename: &str,
) -> Result<(Bytes, Option<String>), Response> {
    // Try exact path match first (proxy-cached artifacts use the upstream
    // path verbatim, e.g. "@types%2Fmdurl/-/mdurl-2.0.0.tgz").
    if let Ok(result) =
        proxy_helpers::local_fetch_by_path(db, state, repo_id, location, upstream_path).await
    {
        return Ok(result);
    }

    // Fall back to a pattern that anchors the match on the decoded package
    // name, covering locally published artifacts whose path follows the
    // layout "{package_name}/{version}/{filename}".
    let pkg_path_prefix = format!("{}/%/", package_name);
    let artifact = sqlx::query!(
        r#"SELECT storage_key, content_type
        FROM artifacts
        WHERE repository_id = $1 AND path LIKE $2 || $3 AND is_deleted = false
        LIMIT 1"#,
        repo_id,
        pkg_path_prefix,
        filename
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        map_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = state
        .storage_for_repo(location)
        .map_err(|e| e.into_response())?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    Ok((content, Some(artifact.content_type)))
}

async fn serve_tarball(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    filename: &str,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    let encoded_name = encode_package_name_for_upstream(package_name);
    let upstream_path = format!("{}/-/{}", encoded_name, filename);

    // For remote repos, always proxy tarballs from upstream (hits cache if
    // already fetched). The proxy cache stores content under its own storage
    // key which the regular artifact storage cannot resolve.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let (content, _content_type) =
                proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, &upstream_path)
                    .await?;

            // The upstream registry may return application/octet-stream for
            // npm tarballs, which also gets persisted by the proxy cache.
            // Correct the cached artifact record so that SBOM generation and
            // security scanners can identify the file as a gzip archive.
            correct_cached_tarball_content_type(&state.db, repo.id, &upstream_path).await;

            return Ok(build_tarball_response(content, filename, None));
        }
        return Err(AppError::NotFound("Tarball not found".to_string()).into_response());
    }

    // Virtual repo: try each member in priority order
    if repo.repo_type == RepositoryType::Virtual {
        let db = state.db.clone();
        let upath = upstream_path.clone();
        let pkg = package_name.to_string();
        let fname = filename.to_string();
        let (content, content_type) = proxy_helpers::resolve_virtual_download(
            &state.db,
            state.proxy_service.as_deref(),
            repo.id,
            &upstream_path,
            |member_id, location| {
                let db = db.clone();
                let state = state.clone();
                let upath = upath.clone();
                let pkg = pkg.clone();
                let fname = fname.clone();
                async move {
                    npm_local_fetch(&db, &state, member_id, &location, &upath, &pkg, &fname).await
                }
            },
        )
        .await?;

        return Ok(build_tarball_response(content, filename, content_type));
    }

    // For local/staged repos, find artifact by filename. Include the package
    // name in the path match to avoid returning a different package's tarball
    // when two packages share the same filename (e.g. @types/mdurl and mdurl
    // both produce mdurl-2.0.0.tgz).
    let path_pattern = format!("{}/%/{}", package_name, filename);
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2
        LIMIT 1
        "#,
        repo.id,
        path_pattern
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    let artifact = match artifact {
        Some(a) => a,
        None => return Err(AppError::NotFound("Tarball not found".to_string()).into_response()),
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(build_tarball_response(content, filename, None))
}

/// Update the content_type of a cached proxy artifact from the incorrect
/// `application/octet-stream` to `application/gzip`. The upstream npm registry
/// often serves tarballs with a generic content type, and the proxy cache
/// stores whatever the upstream returns. This correction ensures that SBOM
/// generation and security scanners can properly identify and extract the
/// archive.
async fn correct_cached_tarball_content_type(db: &PgPool, repository_id: uuid::Uuid, path: &str) {
    let normalized = path.trim_start_matches('/');
    let result = sqlx::query!(
        r#"
        UPDATE artifacts
        SET content_type = $1, updated_at = NOW()
        WHERE repository_id = $2
          AND path = $3
          AND content_type != $1
        "#,
        NPM_TARBALL_CONTENT_TYPE,
        repository_id,
        normalized,
    )
    .execute(db)
    .await;

    if let Err(e) = result {
        tracing::warn!(
            "Failed to correct content_type for cached npm tarball {}: {}",
            path,
            e
        );
    }
}

// ---------------------------------------------------------------------------
// PUT publish handlers
// ---------------------------------------------------------------------------

async fn publish(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    publish_package(&state, auth, &repo_key, &package, &headers, body).await
}

async fn publish_scoped(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let scope = normalize_package_name(&scope);
    let package = normalize_package_name(&package);
    let full_name = format!("@{}/{}", scope, package);
    validate_package_name(&full_name)?;
    publish_package(&state, auth, &repo_key, &full_name, &headers, body).await
}

/// Parsed and validated npm publish payload ready for storage.
struct ParsedNpmPublish {
    versions: Vec<NpmVersionToPublish>,
}

/// A single version extracted from the npm publish payload.
struct NpmVersionToPublish {
    version: String,
    version_data: serde_json::Value,
    tarball_filename: String,
    tarball_bytes: Vec<u8>,
    sha256: String,
}

/// Parse and validate the raw npm publish JSON body into structured data.
/// Returns an error response if the payload is malformed.
#[allow(clippy::result_large_err)]
fn parse_npm_publish_payload(
    body: &Bytes,
    package_name: &str,
) -> Result<ParsedNpmPublish, Response> {
    let payload: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        AppError::Validation(format!("Invalid JSON payload: {}", e)).into_response()
    })?;

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(package_name);

    if name != package_name {
        return Err(AppError::Validation(format!(
            "Package name mismatch: URL says '{}' but payload says '{}'",
            package_name, name
        ))
        .into_response());
    }

    let versions_obj = payload
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            AppError::Validation("Missing 'versions' in payload".to_string()).into_response()
        })?;

    let attachments_obj = payload
        .get("_attachments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            AppError::Validation("Missing '_attachments' in payload".to_string()).into_response()
        })?;

    let mut versions = Vec::new();
    for (version, version_data) in versions_obj {
        let parsed =
            extract_version_tarball(package_name, version, version_data.clone(), attachments_obj)?;
        versions.push(parsed);
    }

    Ok(ParsedNpmPublish { versions })
}

/// Extract and decode the tarball for a single version from the attachments map.
#[allow(clippy::result_large_err)]
fn extract_version_tarball(
    package_name: &str,
    version: &str,
    version_data: serde_json::Value,
    attachments_obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<NpmVersionToPublish, Response> {
    let tarball_filename = if package_name.starts_with('@') {
        let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
        format!("{}-{}.tgz", short_name, version)
    } else {
        format!("{}-{}.tgz", package_name, version)
    };

    let attachment_data = attachments_obj
        .get(&tarball_filename)
        .or_else(|| attachments_obj.values().next())
        .ok_or_else(|| {
            AppError::Validation(format!("No attachment found for version {}", version))
                .into_response()
        })?;

    let base64_data = attachment_data
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::Validation("Missing 'data' in attachment".to_string()).into_response()
        })?;

    let tarball_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| AppError::Validation(format!("Invalid base64 data: {}", e)).into_response())?;

    let mut hasher = Sha256::new();
    hasher.update(&tarball_bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    Ok(NpmVersionToPublish {
        version: version.to_string(),
        version_data,
        tarball_filename,
        tarball_bytes,
        sha256,
    })
}

/// Store a single npm version: check duplicates, write to storage, insert DB
/// records, and update the package_versions table.
#[allow(clippy::too_many_arguments)]
async fn store_npm_version(
    state: &SharedState,
    repo_id: uuid::Uuid,
    repo_key: &str,
    location: &crate::storage::StorageLocation,
    package_name: &str,
    user_id: uuid::Uuid,
    ver: &NpmVersionToPublish,
) -> Result<(), Response> {
    let artifact_path = format!("{}/{}/{}", package_name, ver.version, ver.tarball_filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo_id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    if existing.is_some() {
        return Err(AppError::Conflict(format!(
            "Version {} of {} already exists",
            ver.version, package_name
        ))
        .into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo_id, &artifact_path).await;

    // Store the tarball
    let storage_key = format!(
        "npm/{}/{}/{}",
        package_name, ver.version, ver.tarball_filename
    );
    let storage = state.storage_for_repo_or_500(location)?;
    storage
        .put(&storage_key, Bytes::from(ver.tarball_bytes.clone()))
        .await
        .map_err(map_storage_err)?;

    let size_bytes = ver.tarball_bytes.len() as i64;

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
        repo_id,
        artifact_path,
        package_name,
        ver.version,
        size_bytes,
        ver.sha256,
        "application/gzip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(map_db_err)?;

    // Store metadata
    let npm_metadata = serde_json::json!({
        "name": package_name,
        "version": ver.version,
        "version_data": ver.version_data,
    });

    let _ = sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'npm', $2) \
         ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2",
    )
    .bind(artifact_id)
    .bind(&npm_metadata)
    .execute(&state.db)
    .await;

    // Populate packages / package_versions tables (best-effort)
    let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
    let description = ver
        .version_data
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    pkg_svc
        .try_create_or_update_from_artifact(
            repo_id,
            package_name,
            &ver.version,
            size_bytes,
            &ver.sha256,
            description.as_deref(),
            Some(serde_json::json!({ "format": "npm" })),
        )
        .await;

    info!(
        "npm publish: {} {} ({}) to repo {}",
        package_name, ver.version, ver.tarball_filename, repo_key
    );

    Ok(())
}

/// Handle npm publish. The request body is JSON with versions and base64-encoded attachments.
async fn publish_package(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id =
        require_auth_with_bearer_fallback(auth, headers, &state.db, &state.config, "npm").await?;
    let repo = resolve_npm_repo(&state.db, repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let parsed = parse_npm_publish_payload(&body, package_name)?;

    for ver in &parsed.versions {
        store_npm_version(
            state,
            repo.id,
            repo_key,
            &repo.storage_location(),
            package_name,
            user_id,
            ver,
        )
        .await?;
    }

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(build_json_metadata_response(
        serde_json::to_string(&serde_json::json!({"ok": true})).unwrap(),
    ))
}

// ---------------------------------------------------------------------------
// Proxy helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extracted pure functions for testability
// ---------------------------------------------------------------------------

/// Rewrite tarball URLs in npm metadata JSON to point to our local instance.
/// npm metadata contains `versions.{ver}.dist.tarball` pointing to the upstream registry.
/// We rewrite those to point to `{base_url}/npm/{repo_key}/{package}/-/{filename}`.
fn rewrite_npm_tarball_urls(json: &mut serde_json::Value, base_url: &str, repo_key: &str) {
    let versions = match json.get_mut("versions").and_then(|v| v.as_object_mut()) {
        Some(v) => v,
        None => return,
    };

    for (_version, version_data) in versions.iter_mut() {
        // Extract package name before taking mutable borrow on dist
        let pkg_name = version_data
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("_unknown")
            .to_string();

        if let Some(dist) = version_data.get_mut("dist") {
            // Extract the current tarball URL and compute the new one
            let new_url = dist
                .get("tarball")
                .and_then(|t| t.as_str())
                .and_then(|tarball| {
                    // e.g., https://registry.npmjs.org/express/-/express-4.18.2.tgz
                    tarball.rsplit_once("/-/").map(|(_, filename)| {
                        format!("{}/npm/{}/{}/-/{}", base_url, repo_key, pkg_name, filename)
                    })
                });

            if let Some(url) = new_url {
                if let Some(d) = dist.as_object_mut() {
                    d.insert("tarball".to_string(), serde_json::Value::String(url));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Extracted pure functions (test-only)
    // -----------------------------------------------------------------------

    /// Compute npm integrity field from a SHA256 hex digest.
    fn compute_npm_integrity(sha256_hex: &str) -> String {
        let bytes: Vec<u8> = (0..sha256_hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&sha256_hex[i..i + 2], 16).ok())
            .collect();
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        )
    }

    /// Build the tarball filename for an npm package.
    fn build_npm_tarball_filename(package_name: &str, version: &str) -> String {
        if package_name.starts_with('@') {
            let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
            format!("{}-{}.tgz", short_name, version)
        } else {
            format!("{}-{}.tgz", package_name, version)
        }
    }

    /// Build the artifact path for an npm tarball.
    fn build_npm_artifact_path(
        package_name: &str,
        version: &str,
        tarball_filename: &str,
    ) -> String {
        format!("{}/{}/{}", package_name, version, tarball_filename)
    }

    /// Build the storage key for an npm tarball.
    fn build_npm_storage_key(package_name: &str, version: &str, tarball_filename: &str) -> String {
        format!("npm/{}/{}/{}", package_name, version, tarball_filename)
    }

    /// Build a scoped package name from scope and package.
    fn build_scoped_package_name(scope: &str, package: &str) -> String {
        format!("@{}/{}", scope, package)
    }

    /// Validate an npm package name (basic checks).
    fn validate_npm_package_name(name: &str) -> std::result::Result<(), String> {
        if name.is_empty() {
            return Err("Package name cannot be empty".to_string());
        }
        if name.len() > 214 {
            return Err("Package name cannot exceed 214 characters".to_string());
        }
        if name.starts_with('.') || name.starts_with('_') {
            return Err("Package name cannot start with '.' or '_'".to_string());
        }
        if name != name.to_lowercase() && !name.starts_with('@') {
            return Err("Package name must be lowercase (unless scoped)".to_string());
        }
        Ok(())
    }

    /// Build the npm tarball URL for metadata responses.
    fn build_npm_tarball_url(
        base_url: &str,
        repo_key: &str,
        package_name: &str,
        filename: &str,
    ) -> String {
        format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        )
    }

    /// Info struct for building npm version metadata.
    #[allow(dead_code)]
    struct NpmArtifactInfo {
        version: String,
        filename: String,
        checksum_sha256: String,
        tarball_url: String,
        version_metadata: Option<serde_json::Value>,
        package_name: String,
    }

    /// Build a single npm version entry for the metadata response.
    fn build_npm_version_entry(info: &NpmArtifactInfo) -> serde_json::Value {
        let integrity = compute_npm_integrity(&info.checksum_sha256);

        let mut version_obj = info
            .version_metadata
            .as_ref()
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let obj = version_obj.as_object_mut().unwrap();
        obj.entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(info.package_name.clone()));
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(info.version.clone()));
        obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": info.tarball_url,
                "integrity": integrity,
            }),
        );

        version_obj
    }

    // -----------------------------------------------------------------------
    // rewrite_npm_tarball_urls
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_npm_tarball_urls_basic() {
        let mut json = serde_json::json!({
            "name": "express",
            "versions": {
                "4.18.2": {
                    "name": "express",
                    "version": "4.18.2",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                        "integrity": "sha512-abc"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "http://localhost:8080", "npm-remote");

        let tarball = json["versions"]["4.18.2"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(
            tarball,
            "http://localhost:8080/npm/npm-remote/express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_scoped_package() {
        let mut json = serde_json::json!({
            "name": "@angular/core",
            "versions": {
                "17.0.0": {
                    "name": "@angular/core",
                    "version": "17.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "https://my.registry.com", "npm-main");

        let tarball = json["versions"]["17.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(
            tarball,
            "https://my.registry.com/npm/npm-main/@angular/core/-/core-17.0.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_versions() {
        let mut json = serde_json::json!({
            "name": "empty-pkg"
        });
        // Should not panic
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
        // JSON unchanged
        assert!(json.get("versions").is_none());
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_dist() {
        let mut json = serde_json::json!({
            "versions": {
                "1.0.0": {
                    "name": "no-dist",
                    "version": "1.0.0"
                }
            }
        });
        // Should not panic
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_tarball_field() {
        let mut json = serde_json::json!({
            "versions": {
                "1.0.0": {
                    "name": "no-tarball",
                    "version": "1.0.0",
                    "dist": {
                        "integrity": "sha512-abc"
                    }
                }
            }
        });
        // Should not panic or modify anything
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_multiple_versions() {
        let mut json = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.20": {
                    "name": "lodash",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                    }
                },
                "4.17.21": {
                    "name": "lodash",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "http://local:8080", "npm");

        let t1 = json["versions"]["4.17.20"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        let t2 = json["versions"]["4.17.21"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(t1.starts_with("http://local:8080/npm/npm/lodash/-/"));
        assert!(t2.starts_with("http://local:8080/npm/npm/lodash/-/"));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/npm".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // compute_npm_integrity
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_npm_integrity_zeros() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = compute_npm_integrity(hex);
        assert!(result.starts_with("sha256-"));
        // All zeros base64-encoded
        assert_eq!(
            result,
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn test_compute_npm_integrity_deterministic() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r1 = compute_npm_integrity(hex);
        let r2 = compute_npm_integrity(hex);
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // build_npm_tarball_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_tarball_filename_unscoped() {
        assert_eq!(
            build_npm_tarball_filename("express", "4.18.2"),
            "express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped() {
        assert_eq!(
            build_npm_tarball_filename("@angular/core", "17.0.0"),
            "core-17.0.0.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped_deep() {
        assert_eq!(
            build_npm_tarball_filename("@babel/preset-env", "7.24.0"),
            "preset-env-7.24.0.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped_no_slash() {
        // Edge case: scoped package without a slash
        assert_eq!(
            build_npm_tarball_filename("@oddpackage", "1.0.0"),
            "@oddpackage-1.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_artifact_path_unscoped() {
        assert_eq!(
            build_npm_artifact_path("lodash", "4.17.21", "lodash-4.17.21.tgz"),
            "lodash/4.17.21/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn test_build_npm_artifact_path_scoped() {
        assert_eq!(
            build_npm_artifact_path("@vue/compiler-core", "3.4.0", "compiler-core-3.4.0.tgz"),
            "@vue/compiler-core/3.4.0/compiler-core-3.4.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_storage_key_unscoped() {
        assert_eq!(
            build_npm_storage_key("express", "4.18.2", "express-4.18.2.tgz"),
            "npm/express/4.18.2/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_storage_key_scoped() {
        assert_eq!(
            build_npm_storage_key("@vue/compiler-core", "3.4.0", "compiler-core-3.4.0.tgz"),
            "npm/@vue/compiler-core/3.4.0/compiler-core-3.4.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_scoped_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_scoped_package_name_basic() {
        assert_eq!(build_scoped_package_name("babel", "core"), "@babel/core");
    }

    #[test]
    fn test_build_scoped_package_name_vue() {
        assert_eq!(
            build_scoped_package_name("vue", "compiler-core"),
            "@vue/compiler-core"
        );
    }

    // -----------------------------------------------------------------------
    // validate_npm_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_npm_package_name_valid() {
        assert!(validate_npm_package_name("express").is_ok());
    }

    #[test]
    fn test_validate_npm_package_name_empty() {
        assert!(validate_npm_package_name("").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_too_long() {
        let long_name = "a".repeat(215);
        assert!(validate_npm_package_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_npm_package_name_starts_with_dot() {
        assert!(validate_npm_package_name(".hidden").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_starts_with_underscore() {
        assert!(validate_npm_package_name("_private").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_uppercase_rejected() {
        assert!(validate_npm_package_name("MyPackage").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_scoped_uppercase_ok() {
        assert!(validate_npm_package_name("@Scope/Package").is_ok());
    }

    #[test]
    fn test_validate_npm_package_name_max_length() {
        let name = "a".repeat(214);
        assert!(validate_npm_package_name(&name).is_ok());
    }

    // -----------------------------------------------------------------------
    // build_npm_tarball_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_tarball_url_basic() {
        assert_eq!(
            build_npm_tarball_url(
                "http://localhost:8080",
                "npm-hosted",
                "express",
                "express-4.18.2.tgz"
            ),
            "http://localhost:8080/npm/npm-hosted/express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_url_scoped() {
        assert_eq!(
            build_npm_tarball_url(
                "https://registry.example.com",
                "main",
                "@angular/core",
                "core-17.0.0.tgz"
            ),
            "https://registry.example.com/npm/main/@angular/core/-/core-17.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_version_entry
    // -----------------------------------------------------------------------

    fn make_artifact_info(
        pkg: &str,
        version: &str,
        sha256: &str,
        metadata: Option<serde_json::Value>,
    ) -> NpmArtifactInfo {
        let filename = build_npm_tarball_filename(pkg, version);
        let tarball_url = build_npm_tarball_url("http://localhost:8080", "repo", pkg, &filename);
        NpmArtifactInfo {
            version: version.to_string(),
            filename,
            checksum_sha256: sha256.to_string(),
            tarball_url,
            version_metadata: metadata,
            package_name: pkg.to_string(),
        }
    }

    #[test]
    fn test_build_npm_version_entry_variants() {
        // Basic entry without metadata: name, version, tarball URL, integrity
        let basic =
            build_npm_version_entry(&make_artifact_info("mylib", "1.0.0", SHA256_EMPTY, None));
        assert_eq!(basic["name"], "mylib");
        assert_eq!(basic["version"], "1.0.0");
        assert!(basic["dist"]["tarball"]
            .as_str()
            .unwrap()
            .contains("mylib-1.0.0.tgz"));
        assert!(basic["dist"]["integrity"]
            .as_str()
            .unwrap()
            .starts_with("sha256-"));

        // Entry with extra metadata fields: those fields are preserved in the output
        let with_meta = build_npm_version_entry(&make_artifact_info(
            "pkg",
            "2.0.0",
            SHA256_ZEROS,
            Some(serde_json::json!({"description": "A great library", "license": "MIT"})),
        ));
        assert_eq!(with_meta["name"], "pkg");
        assert_eq!(with_meta["version"], "2.0.0");
        assert_eq!(with_meta["description"], "A great library");
        assert_eq!(with_meta["license"], "MIT");

        // When metadata already contains name/version, or_insert_with does not overwrite
        let preserved = build_npm_version_entry(&make_artifact_info(
            "pkg",
            "1.0.0",
            SHA256_ABCD,
            Some(serde_json::json!({"name": "custom-name", "version": "0.9.0"})),
        ));
        assert_eq!(preserved["name"], "custom-name");
        assert_eq!(preserved["version"], "0.9.0");
    }

    // -----------------------------------------------------------------------
    // parse_npm_publish_payload
    // -----------------------------------------------------------------------

    fn json_to_bytes(payload: &serde_json::Value) -> Bytes {
        Bytes::from(serde_json::to_vec(payload).unwrap())
    }

    fn make_valid_publish_body(package_name: &str, version: &str) -> Bytes {
        let tarball_data = b"fake tarball content";
        let b64 = base64::engine::general_purpose::STANDARD.encode(tarball_data);
        let tarball_filename = build_npm_tarball_filename(package_name, version);

        let payload = serde_json::json!({
            "name": package_name,
            "versions": {
                version: {
                    "name": package_name,
                    "version": version,
                    "description": "A test package"
                }
            },
            "_attachments": {
                tarball_filename: {
                    "content_type": "application/octet-stream",
                    "data": b64,
                    "length": tarball_data.len()
                }
            }
        });
        Bytes::from(serde_json::to_vec(&payload).unwrap())
    }

    #[test]
    fn test_parse_npm_publish_payload_valid() {
        let body = make_valid_publish_body("express", "4.18.2");
        let result = parse_npm_publish_payload(&body, "express");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.versions.len(), 1);
        assert_eq!(parsed.versions[0].version, "4.18.2");
        assert_eq!(parsed.versions[0].tarball_filename, "express-4.18.2.tgz");
        assert!(!parsed.versions[0].tarball_bytes.is_empty());
        assert_eq!(parsed.versions[0].sha256.len(), 64);
    }

    #[test]
    fn test_parse_npm_publish_payload_scoped() {
        let body = make_valid_publish_body("@babel/core", "7.24.0");
        let result = parse_npm_publish_payload(&body, "@babel/core");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.versions[0].version, "7.24.0");
        assert_eq!(parsed.versions[0].tarball_filename, "core-7.24.0.tgz");
    }

    #[test]
    fn test_parse_npm_publish_payload_invalid_json() {
        let body = Bytes::from(b"not json at all".to_vec());
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_npm_publish_payload_rejects_invalid_payloads() {
        let cases: Vec<(serde_json::Value, &str, &str)> = vec![
            // Name mismatch between body and URL
            (
                serde_json::json!({
                    "name": "wrong-name",
                    "versions": { "1.0.0": {} },
                    "_attachments": { "wrong-name-1.0.0.tgz": { "data": "dGVzdA==" } }
                }),
                "correct-name",
                "name mismatch",
            ),
            // Missing versions field
            (
                serde_json::json!({ "name": "pkg", "_attachments": {} }),
                "pkg",
                "missing versions",
            ),
            // Missing attachments field
            (
                serde_json::json!({ "name": "pkg", "versions": { "1.0.0": {} } }),
                "pkg",
                "missing attachments",
            ),
        ];

        for (payload, url_name, label) in cases {
            let body = json_to_bytes(&payload);
            assert!(
                parse_npm_publish_payload(&body, url_name).is_err(),
                "expected error for case: {}",
                label
            );
        }
    }

    #[test]
    fn test_parse_npm_publish_payload_no_name_field_uses_url_name() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"data");
        let payload = serde_json::json!({
            "versions": {
                "1.0.0": { "version": "1.0.0" }
            },
            "_attachments": {
                "pkg-1.0.0.tgz": { "data": b64 }
            }
        });
        let body = json_to_bytes(&payload);
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_npm_publish_preserves_version_data() {
        let body = make_valid_publish_body("mylib", "2.0.0");
        let parsed = parse_npm_publish_payload(&body, "mylib").unwrap();
        let vd = &parsed.versions[0].version_data;
        assert_eq!(vd["description"], "A test package");
    }

    // -----------------------------------------------------------------------
    // extract_version_tarball
    // -----------------------------------------------------------------------

    /// Build an attachments map with a single entry containing base64-encoded data.
    fn make_attachments(filename: &str, data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let mut m = serde_json::Map::new();
        m.insert(filename.to_string(), serde_json::json!({ "data": b64 }));
        m
    }

    #[test]
    fn test_extract_version_tarball_unscoped() {
        let attachments = make_attachments("mylib-1.0.0.tgz", b"tarball bytes");

        let ver = extract_version_tarball(
            "mylib",
            "1.0.0",
            serde_json::json!({"version": "1.0.0"}),
            &attachments,
        )
        .unwrap();
        assert_eq!(ver.version, "1.0.0");
        assert_eq!(ver.tarball_filename, "mylib-1.0.0.tgz");
        assert_eq!(ver.tarball_bytes, b"tarball bytes");
        assert_eq!(ver.sha256.len(), 64);
    }

    #[test]
    fn test_extract_version_tarball_scoped() {
        let attachments = make_attachments("core-7.0.0.tgz", b"scoped data");

        let ver =
            extract_version_tarball("@babel/core", "7.0.0", serde_json::json!({}), &attachments)
                .unwrap();
        assert_eq!(ver.tarball_filename, "core-7.0.0.tgz");
    }

    #[test]
    fn test_extract_version_tarball_falls_back_to_first_attachment() {
        let attachments = make_attachments("different-name.tgz", b"fallback data");
        assert!(
            extract_version_tarball("mylib", "1.0.0", serde_json::json!({}), &attachments).is_ok()
        );
    }

    #[test]
    fn test_extract_version_tarball_rejects_bad_attachments() {
        let version_data = serde_json::json!({});

        // Empty attachments map
        let empty = serde_json::Map::new();
        assert!(extract_version_tarball("mylib", "1.0.0", version_data.clone(), &empty).is_err());

        // Attachment present but missing the "data" field
        let mut no_data = serde_json::Map::new();
        no_data.insert(
            "mylib-1.0.0.tgz".to_string(),
            serde_json::json!({ "content_type": "application/octet-stream" }),
        );
        assert!(extract_version_tarball("mylib", "1.0.0", version_data.clone(), &no_data).is_err());

        // Attachment has a "data" field with invalid base64
        let mut bad_b64 = serde_json::Map::new();
        bad_b64.insert(
            "mylib-1.0.0.tgz".to_string(),
            serde_json::json!({ "data": "!!!not-base64!!!" }),
        );
        assert!(extract_version_tarball("mylib", "1.0.0", version_data, &bad_b64).is_err());
    }

    #[test]
    fn test_extract_version_tarball_sha256_matches_content() {
        let content = b"deterministic content";
        let attachments = make_attachments("pkg-1.0.0.tgz", content);

        let ver =
            extract_version_tarball("pkg", "1.0.0", serde_json::json!({}), &attachments).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        assert_eq!(ver.sha256, format!("{:x}", hasher.finalize()));
    }

    // -----------------------------------------------------------------------
    // ParsedNpmPublish / NpmVersionToPublish structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_npm_version_to_publish_fields() {
        let ver = NpmVersionToPublish {
            version: "3.0.0".to_string(),
            version_data: serde_json::json!({"description": "test"}),
            tarball_filename: "pkg-3.0.0.tgz".to_string(),
            tarball_bytes: vec![1, 2, 3],
            sha256: "abc".to_string(),
        };
        assert_eq!(ver.version, "3.0.0");
        assert_eq!(ver.tarball_bytes.len(), 3);
        assert_eq!(ver.version_data["description"], "test");
    }

    #[test]
    fn test_parsed_npm_publish_multiple_versions() {
        let b64_a = base64::engine::general_purpose::STANDARD.encode(b"version a");
        let b64_b = base64::engine::general_purpose::STANDARD.encode(b"version b");

        let payload = serde_json::json!({
            "name": "multi",
            "versions": {
                "1.0.0": { "version": "1.0.0" },
                "2.0.0": { "version": "2.0.0" }
            },
            "_attachments": {
                "multi-1.0.0.tgz": { "data": b64_a },
                "multi-2.0.0.tgz": { "data": b64_b }
            }
        });
        let body = json_to_bytes(&payload);
        let parsed = parse_npm_publish_payload(&body, "multi").unwrap();
        assert_eq!(parsed.versions.len(), 2);

        let version_names: Vec<&str> = parsed.versions.iter().map(|v| v.version.as_str()).collect();
        assert!(version_names.contains(&"1.0.0"));
        assert!(version_names.contains(&"2.0.0"));
    }

    // -----------------------------------------------------------------------
    // normalize_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_decodes_scoped_package() {
        assert_eq!(normalize_package_name("%40openai%2fcodex"), "@openai/codex");
    }

    #[test]
    fn test_normalize_decodes_slash_only() {
        assert_eq!(normalize_package_name("@openai%2Fcodex"), "@openai/codex");
    }

    #[test]
    fn test_normalize_unscoped_unchanged() {
        assert_eq!(normalize_package_name("express"), "express");
    }

    #[test]
    fn test_normalize_already_decoded() {
        assert_eq!(normalize_package_name("@openai/codex"), "@openai/codex");
    }

    // -----------------------------------------------------------------------
    // encode_package_name_for_upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_upstream_scoped_package() {
        assert_eq!(
            encode_package_name_for_upstream("@openai/codex"),
            "@openai%2Fcodex"
        );
    }

    #[test]
    fn test_encode_upstream_unscoped_unchanged() {
        assert_eq!(encode_package_name_for_upstream("express"), "express");
    }

    #[test]
    fn test_encode_upstream_at_without_slash() {
        // Edge case: starts with @ but has no slash (not a valid scope, but handle gracefully)
        assert_eq!(
            encode_package_name_for_upstream("@noscopepkg"),
            "@noscopepkg"
        );
    }

    #[test]
    fn test_encode_upstream_deeply_scoped() {
        // Only the first slash should be encoded
        assert_eq!(
            encode_package_name_for_upstream("@scope/sub/pkg"),
            "@scope%2Fsub/pkg"
        );
    }

    #[test]
    fn test_normalize_then_encode_roundtrip() {
        let from_client = "@openai%2Fcodex";
        let normalized = normalize_package_name(from_client);
        assert_eq!(normalized, "@openai/codex");
        let for_upstream = encode_package_name_for_upstream(&normalized);
        assert_eq!(for_upstream, "@openai%2Fcodex");
    }

    // -----------------------------------------------------------------------
    // build_npm_metadata_response (used by virtual local/staging members)
    // -----------------------------------------------------------------------

    /// Shortcut: build a single-version NpmMetadataArtifact without metadata.
    fn make_artifact(path: &str, version: &str, sha256: &str) -> NpmMetadataArtifact {
        NpmMetadataArtifact {
            path: path.to_string(),
            version: Some(version.to_string()),
            checksum_sha256: sha256.to_string(),
            metadata: None,
        }
    }

    /// Call `build_npm_metadata_response` and return the parsed JSON body.
    async fn metadata_response_json(
        artifacts: &[NpmMetadataArtifact],
        package_name: &str,
        base_url: &str,
        repo_key: &str,
    ) -> serde_json::Value {
        let resp =
            build_npm_metadata_response(artifacts, package_name, base_url, repo_key).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    const SHA256_ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABCD: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[tokio::test]
    async fn test_build_npm_metadata_response_single_and_scoped_versions() {
        // Unscoped package: basic metadata fields and tarball URL structure
        let artifacts = vec![make_artifact(
            "mylib/1.0.0/mylib-1.0.0.tgz",
            "1.0.0",
            SHA256_EMPTY,
        )];
        let body =
            metadata_response_json(&artifacts, "mylib", "http://localhost:8080", "npm-virtual")
                .await;

        assert_eq!(body["name"], "mylib");
        assert_eq!(body["dist-tags"]["latest"], "1.0.0");
        let v = &body["versions"]["1.0.0"];
        assert_eq!(v["name"], "mylib");
        assert_eq!(v["version"], "1.0.0");
        assert_eq!(
            v["dist"]["tarball"],
            "http://localhost:8080/npm/npm-virtual/mylib/-/mylib-1.0.0.tgz"
        );
        assert!(v["dist"]["integrity"]
            .as_str()
            .unwrap()
            .starts_with("sha256-"));

        // Scoped package: tarball URL must encode the scope correctly
        let scoped = vec![make_artifact(
            "@babel/core/7.24.0/core-7.24.0.tgz",
            "7.24.0",
            SHA256_ABCD,
        )];
        let body2 = metadata_response_json(
            &scoped,
            "@babel/core",
            "http://localhost:8080",
            "npm-virtual",
        )
        .await;
        assert_eq!(body2["name"], "@babel/core");
        assert_eq!(
            body2["versions"]["7.24.0"]["dist"]["tarball"],
            "http://localhost:8080/npm/npm-virtual/@babel/core/-/core-7.24.0.tgz"
        );

        // Virtual repo key: tarball URLs must use the virtual repo key, not the
        // underlying member repo key.
        let virt = vec![make_artifact(
            "express/4.18.2/express-4.18.2.tgz",
            "4.18.2",
            SHA256_EMPTY,
        )];
        let body3 =
            metadata_response_json(&virt, "express", "http://localhost:8080", "my-virtual-repo")
                .await;
        let tarball = body3["versions"]["4.18.2"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(
            tarball.contains("my-virtual-repo"),
            "tarball URL should use virtual repo key, got: {}",
            tarball
        );
    }

    #[tokio::test]
    async fn test_build_npm_metadata_response_multiple_versions() {
        let artifacts = vec![
            make_artifact("lodash/4.17.20/lodash-4.17.20.tgz", "4.17.20", SHA256_ZEROS),
            make_artifact("lodash/4.17.21/lodash-4.17.21.tgz", "4.17.21", SHA256_ABCD),
        ];

        let body = metadata_response_json(
            &artifacts,
            "lodash",
            "https://my.registry.com",
            "npm-virtual",
        )
        .await;

        assert_eq!(body["name"], "lodash");
        assert_eq!(body["dist-tags"]["latest"], "4.17.21");
        assert!(body["versions"]["4.17.20"].is_object());
        assert!(body["versions"]["4.17.21"].is_object());
    }

    #[tokio::test]
    async fn test_build_npm_metadata_response_with_version_metadata() {
        let artifacts = vec![NpmMetadataArtifact {
            path: "fastlib/2.0.0/fastlib-2.0.0.tgz".to_string(),
            version: Some("2.0.0".to_string()),
            checksum_sha256: SHA256_ZEROS.to_string(),
            metadata: Some(serde_json::json!({
                "version_data": {
                    "description": "A fast library",
                    "license": "MIT",
                    "main": "index.js"
                }
            })),
        }];

        let body =
            metadata_response_json(&artifacts, "fastlib", "http://localhost:8080", "npm-hosted")
                .await;

        let v = &body["versions"]["2.0.0"];
        assert_eq!(v["description"], "A fast library");
        assert_eq!(v["license"], "MIT");
        assert_eq!(v["main"], "index.js");
        assert_eq!(v["name"], "fastlib");
        assert_eq!(v["version"], "2.0.0");
    }

    #[tokio::test]
    async fn test_build_npm_metadata_response_skips_versionless_artifacts() {
        let artifacts = vec![
            make_artifact("pkg/1.0.0/pkg-1.0.0.tgz", "1.0.0", SHA256_ZEROS),
            NpmMetadataArtifact {
                path: "pkg/unknown/pkg-unknown.tgz".to_string(),
                version: None,
                checksum_sha256: SHA256_ABCD.to_string(),
                metadata: None,
            },
        ];

        let body =
            metadata_response_json(&artifacts, "pkg", "http://localhost:8080", "npm-hosted").await;

        let versions = body["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions.contains_key("1.0.0"));
    }

    // Integrity preservation tests (issue #745)
    //
    // When proxying npm metadata from upstream, the rewrite function must
    // preserve the original integrity and shasum fields. Only the tarball
    // URL should change.
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_preserves_upstream_integrity_and_shasum() {
        let mut json = serde_json::json!({
            "name": "@types/mdurl",
            "versions": {
                "2.0.0": {
                    "name": "@types/mdurl",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@types/mdurl/-/mdurl-2.0.0.tgz",
                        "integrity": "sha512-RGdgjQUZba5p6QEFAVx2OGb8rQDL/cPRG7GiedRzMcJ1tYnUANBncjbSB1NRGwbvjcPeikRABz2nshyPk1bhWg==",
                        "shasum": "d43878b5b20222682163ae6f897b20447233bdfd",
                        "fileCount": 13,
                        "unpackedSize": 5407
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "https://registry.example.dev", "npm");

        let dist = &json["versions"]["2.0.0"]["dist"];

        // tarball URL must be rewritten to our local instance
        assert_eq!(
            dist["tarball"].as_str().unwrap(),
            "https://registry.example.dev/npm/npm/@types/mdurl/-/mdurl-2.0.0.tgz"
        );

        // integrity hash must be preserved verbatim from upstream
        assert_eq!(
            dist["integrity"].as_str().unwrap(),
            "sha512-RGdgjQUZba5p6QEFAVx2OGb8rQDL/cPRG7GiedRzMcJ1tYnUANBncjbSB1NRGwbvjcPeikRABz2nshyPk1bhWg=="
        );

        // shasum must also be preserved
        assert_eq!(
            dist["shasum"].as_str().unwrap(),
            "d43878b5b20222682163ae6f897b20447233bdfd"
        );

        // Other dist fields should also survive the rewrite
        assert_eq!(dist["fileCount"], 13);
        assert_eq!(dist["unpackedSize"], 5407);
    }

    #[test]
    fn test_rewrite_preserves_integrity_with_multiple_versions() {
        let mut json = serde_json::json!({
            "name": "mdurl",
            "versions": {
                "1.0.1": {
                    "name": "mdurl",
                    "version": "1.0.1",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/mdurl/-/mdurl-1.0.1.tgz",
                        "integrity": "sha512-aaa111==",
                        "shasum": "aaaa1111"
                    }
                },
                "2.0.0": {
                    "name": "mdurl",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/mdurl/-/mdurl-2.0.0.tgz",
                        "integrity": "sha512-bbb222==",
                        "shasum": "bbbb2222"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "http://localhost:8080", "npm-cache");

        // Both versions should have rewritten tarball URLs
        assert!(json["versions"]["1.0.1"]["dist"]["tarball"]
            .as_str()
            .unwrap()
            .starts_with("http://localhost:8080/npm/npm-cache/mdurl/-/"));
        assert!(json["versions"]["2.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap()
            .starts_with("http://localhost:8080/npm/npm-cache/mdurl/-/"));

        // Both versions must keep their own integrity values
        assert_eq!(
            json["versions"]["1.0.1"]["dist"]["integrity"]
                .as_str()
                .unwrap(),
            "sha512-aaa111=="
        );
        assert_eq!(
            json["versions"]["2.0.0"]["dist"]["integrity"]
                .as_str()
                .unwrap(),
            "sha512-bbb222=="
        );

        // shasum preserved too
        assert_eq!(
            json["versions"]["1.0.1"]["dist"]["shasum"]
                .as_str()
                .unwrap(),
            "aaaa1111"
        );
        assert_eq!(
            json["versions"]["2.0.0"]["dist"]["shasum"]
                .as_str()
                .unwrap(),
            "bbbb2222"
        );
    }

    // -----------------------------------------------------------------------
    // Path pattern disambiguation tests (issue #745)
    //
    // npm tarball filenames strip the scope prefix, so packages like
    // `mdurl` and `@types/mdurl` both produce `mdurl-2.0.0.tgz`. The
    // path pattern used for artifact lookup must include the package name
    // to prevent returning the wrong package's tarball.
    // -----------------------------------------------------------------------

    #[test]
    fn test_path_pattern_distinguishes_scoped_from_unscoped() {
        // Two packages with the same tarball filename
        let unscoped_path = "mdurl/2.0.0/mdurl-2.0.0.tgz";
        let scoped_path = "@types/mdurl/2.0.0/mdurl-2.0.0.tgz";

        // The path pattern includes the package name as a prefix
        let unscoped_pattern = format!("{}/%/{}", "mdurl", "mdurl-2.0.0.tgz");
        let scoped_pattern = format!("{}/%/{}", "@types/mdurl", "mdurl-2.0.0.tgz");

        // SQL LIKE with `%` as wildcard:
        // unscoped_pattern = "mdurl/%/mdurl-2.0.0.tgz"
        // scoped_pattern = "@types/mdurl/%/mdurl-2.0.0.tgz"

        // Simulate SQL LIKE matching: replace `%` with regex `.*`
        let unscoped_re = regex::Regex::new(&format!(
            "^{}$",
            regex::escape(&unscoped_pattern).replace("%", ".*")
        ))
        .unwrap();
        let scoped_re = regex::Regex::new(&format!(
            "^{}$",
            regex::escape(&scoped_pattern).replace("%", ".*")
        ))
        .unwrap();

        // Unscoped pattern matches only the unscoped path
        assert!(unscoped_re.is_match(unscoped_path));
        assert!(!unscoped_re.is_match(scoped_path));

        // Scoped pattern matches only the scoped path
        assert!(scoped_re.is_match(scoped_path));
        assert!(!scoped_re.is_match(unscoped_path));
    }

    #[test]
    fn test_path_pattern_matches_locally_published_layout() {
        // Locally published artifacts use: {package}/{version}/{filename}
        let path = "express/4.18.2/express-4.18.2.tgz";
        let pattern = format!("{}/%/{}", "express", "express-4.18.2.tgz");
        let re = regex::Regex::new(&format!("^{}$", regex::escape(&pattern).replace("%", ".*")))
            .unwrap();
        assert!(re.is_match(path));
    }

    #[test]
    fn test_path_pattern_scoped_locally_published() {
        let path = "@babel/core/7.24.0/core-7.24.0.tgz";
        let pattern = format!("{}/%/{}", "@babel/core", "core-7.24.0.tgz");
        let re = regex::Regex::new(&format!("^{}$", regex::escape(&pattern).replace("%", ".*")))
            .unwrap();
        assert!(re.is_match(path));
    }

    #[test]
    fn test_encode_package_name_for_upstream_unscoped() {
        assert_eq!(encode_package_name_for_upstream("express"), "express");
        assert_eq!(encode_package_name_for_upstream("lodash"), "lodash");
    }

    #[test]
    fn test_encode_package_name_for_upstream_scoped() {
        assert_eq!(
            encode_package_name_for_upstream("@types/mdurl"),
            "@types%2Fmdurl"
        );
        assert_eq!(
            encode_package_name_for_upstream("@angular/core"),
            "@angular%2Fcore"
        );
    }

    #[tokio::test]
    async fn test_build_npm_metadata_response_same_filename_different_packages() {
        // Regression test for issue #745: two packages with the same tarball
        // filename must produce metadata with the correct package name in each
        // version entry, preventing the wrong tarball from being served.
        let unscoped = vec![NpmMetadataArtifact {
            path: "mdurl/2.0.0/mdurl-2.0.0.tgz".to_string(),
            version: Some("2.0.0".to_string()),
            checksum_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            metadata: None,
        }];
        let scoped = vec![NpmMetadataArtifact {
            path: "@types/mdurl/2.0.0/mdurl-2.0.0.tgz".to_string(),
            version: Some("2.0.0".to_string()),
            checksum_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            metadata: None,
        }];

        let resp_unscoped =
            build_npm_metadata_response(&unscoped, "mdurl", "http://localhost:8080", "npm-hosted")
                .unwrap();
        let resp_scoped = build_npm_metadata_response(
            &scoped,
            "@types/mdurl",
            "http://localhost:8080",
            "npm-hosted",
        )
        .unwrap();

        let body_u = axum::body::to_bytes(resp_unscoped.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_u: serde_json::Value = serde_json::from_slice(&body_u).unwrap();
        let body_s = axum::body::to_bytes(resp_scoped.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_s: serde_json::Value = serde_json::from_slice(&body_s).unwrap();

        // The tarball URLs must reference different packages
        let tarball_u = json_u["versions"]["2.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        let tarball_s = json_s["versions"]["2.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();

        assert!(
            tarball_u.contains("/mdurl/-/"),
            "unscoped tarball URL should reference mdurl, got: {}",
            tarball_u
        );
        assert!(
            tarball_s.contains("/@types/mdurl/-/"),
            "scoped tarball URL should reference @types/mdurl, got: {}",
            tarball_s
        );
        assert_ne!(
            tarball_u, tarball_s,
            "tarball URLs for different packages must differ"
        );

        // Integrity hashes must differ because the checksums are different
        let integrity_u = json_u["versions"]["2.0.0"]["dist"]["integrity"]
            .as_str()
            .unwrap();
        let integrity_s = json_s["versions"]["2.0.0"]["dist"]["integrity"]
            .as_str()
            .unwrap();
        assert_ne!(
            integrity_u, integrity_s,
            "integrity for different packages must differ"
        );
    }

    // -----------------------------------------------------------------------
    // NPM_TARBALL_CONTENT_TYPE
    // -----------------------------------------------------------------------

    #[test]
    fn test_npm_tarball_content_type_values() {
        // npm tarballs are gzip-compressed tar archives. The content type must
        // be application/gzip so that SBOM generators and security scanners
        // (Trivy, Grype) can identify and extract the archive contents.
        // It must NOT be application/octet-stream, which upstream registries
        // like npmjs.org sometimes return.
        assert_eq!(NPM_TARBALL_CONTENT_TYPE, "application/gzip");
        assert_ne!(NPM_TARBALL_CONTENT_TYPE, "application/octet-stream");

        // The publish handler stores "application/gzip" in the content_type
        // column (see store_npm_version). Verify the constant matches.
        let publish_content_type = "application/gzip";
        assert_eq!(NPM_TARBALL_CONTENT_TYPE, publish_content_type);
    }
}
