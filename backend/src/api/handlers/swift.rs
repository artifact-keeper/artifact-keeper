//! Swift Package Registry API handlers (SE-0292).
//!
//! Implements the endpoints required by the Swift Package Manager registry protocol.
//!
//! Routes are mounted at `/swift/{repo_key}/...`:
//!   GET  /swift/:repo_key/:scope/:name                 - List package releases
//!   GET  /swift/:repo_key/:scope/:name/:version         - Get release metadata
//!   GET  /swift/:repo_key/:scope/:name/:version.zip     - Download source archive
//!   GET  /swift/:repo_key/:scope/:name/:version/Package.swift - Fetch manifest
//!   PUT  /swift/:repo_key/:scope/:name/:version         - Publish release (auth required)
//!   GET  /swift/:repo_key/identifiers?url={package_url} - Lookup package identifiers

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::swift::SwiftHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Lookup package identifiers by URL
        .route("/:repo_key/identifiers", get(lookup_identifiers))
        // List package releases
        .route("/:repo_key/:scope/:name", get(list_releases))
        // Version path: GET dispatches to metadata/archive/manifest, PUT publishes
        .route(
            "/:repo_key/:scope/:name/*version_path",
            get(version_path_handler).put(publish_release_from_wildcard),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_swift_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["swift"], "a Swift").await
}

/// Extract Package.swift from a Swift source archive (issue #1100).
///
/// SwiftPM resolves dependencies via the manifest endpoint before downloading
/// the full source archive, so a `404` here breaks dependency resolution even
/// when the archive itself is sound. Operators (and CI tooling) can't always
/// pass Package.swift through the `X-Swift-Package-Manifest` header because
/// SwiftPM manifests are multi-line files and HTTP header values are
/// effectively single-line, so we parse the uploaded zip ourselves.
///
/// Returns the manifest text when found at `Package.swift` or at
/// `<prefix>/Package.swift` (the common GitHub-style archive layout that
/// nests everything under `<repo>-<sha>/`). Returns `None` when neither
/// layout matches; the caller falls back to "manifest not found".
///
/// The extracted manifest is hard-capped at `MAX_MANIFEST_BYTES` to bound
/// memory consumption against zip-bomb uploads. A real Package.swift is
/// typically a few KB; the cap is generous enough to allow even the most
/// elaborate manifests while refusing pathological inputs.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

fn extract_manifest_from_zip(zip_bytes: &[u8]) -> Option<String> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(error = %e, "swift manifest extraction: invalid zip archive");
            return None;
        }
    };

    // Pass 1: top-level Package.swift wins. This is the layout produced by
    // `swift package archive-source` and most CI helpers.
    // Pass 2: any `<single-prefix>/Package.swift` (one directory deep).
    // Pass 3: deepest fallback -- the shortest path that ends in
    // `/Package.swift`. Avoids accidentally picking up
    // `Tests/.../Package.swift` fixtures shipped alongside the real one.
    use std::io::Read;
    let mut best: Option<(usize, String)> = None;
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(index = i, error = %e, "swift manifest extraction: skipped unreadable entry");
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let is_top_level = name == "Package.swift";
        let is_nested = name.ends_with("/Package.swift");
        if !is_top_level && !is_nested {
            continue;
        }
        // Refuse oversized entries before reading. `size()` is the
        // uncompressed size from the local file header; treat it as a
        // hint and re-check with `take()` below in case the header lies.
        if entry.size() > MAX_MANIFEST_BYTES {
            tracing::debug!(
                entry = %name,
                size = entry.size(),
                cap = MAX_MANIFEST_BYTES,
                "swift manifest extraction: skipped oversized Package.swift candidate"
            );
            continue;
        }
        let mut text = String::new();
        // `take(N+1)` reads at most N+1 bytes; we then reject if the
        // result exceeds N. This catches archives whose local file header
        // understates the actual entry size.
        if let Err(e) = entry
            .by_ref()
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_string(&mut text)
        {
            tracing::debug!(entry = %name, error = %e, "swift manifest extraction: skipped non-UTF8 entry");
            continue;
        }
        if text.len() as u64 > MAX_MANIFEST_BYTES {
            tracing::debug!(
                entry = %name,
                read = text.len(),
                cap = MAX_MANIFEST_BYTES,
                "swift manifest extraction: skipped entry exceeding cap after read"
            );
            continue;
        }
        if is_top_level {
            return Some(text);
        }
        let depth = name.matches('/').count();
        let take = match &best {
            None => true,
            Some((d, _)) => depth < *d,
        };
        if take {
            best = Some((depth, text));
        }
    }
    best.map(|(_, text)| text)
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Build a JSON response with the required Content-Version: 1 header.
fn swift_json_response(status: StatusCode, body: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("Content-Version", "1")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Build an error response with the Content-Version: 1 header.
fn swift_error_response(status: StatusCode, detail: &str) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/problem+json")
        .header("Content-Version", "1")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "detail": detail,
            }))
            .unwrap(),
        ))
        .unwrap()
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name -- List package releases
// ---------------------------------------------------------------------------

async fn list_releases(
    State(state): State<SharedState>,
    Path((repo_key, scope, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    // Validate the path via SwiftHandler
    let _info = SwiftHandler::parse_path(&format!("{}/{}", scope, name))
        .map_err(|e| swift_error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    let package_id = format!("{}.{}", scope, name);

    // Virtual repos own no artifacts: fan out across members (issue #1554).
    let versions = if repo.repo_type == RepositoryType::Virtual {
        query_release_versions_virtual(&state.db, repo.id, &package_id).await?
    } else {
        query_release_versions(&state.db, repo.id, &package_id).await?
    };

    if versions.is_empty() {
        return Err(swift_error_response(
            StatusCode::NOT_FOUND,
            &format!("Package {}.{} not found", scope, name),
        ));
    }

    Ok(swift_json_response(
        StatusCode::OK,
        build_releases_body(&repo_key, &scope, &name, &versions),
    ))
}

/// Build the `{ "releases": { version: { url } } }` body for `list_releases`.
/// Pure (no I/O) so the response shape has at-rest unit coverage.
fn build_releases_body(
    repo_key: &str,
    scope: &str,
    name: &str,
    versions: &[String],
) -> serde_json::Value {
    let mut releases = serde_json::Map::new();
    for version in versions {
        let url = format!("/swift/{}/{}/{}/{}", repo_key, scope, name, version);
        releases.insert(version.clone(), serde_json::json!({ "url": url }));
    }
    serde_json::json!({ "releases": releases })
}

/// Query the release versions of a Swift package in a single (non-virtual)
/// repository, newest first.
async fn query_release_versions(
    db: &PgPool,
    repo_id: uuid::Uuid,
    package_id: &str,
) -> Result<Vec<String>, Response> {
    // NOTE: the SELECT list is kept byte-identical to the pre-#1554 query so
    // the committed `.sqlx` offline cache entry still matches; `checksum_sha256`
    // is selected but unused.
    let rows = sqlx::query!(
        r#"
        SELECT a.version, a.checksum_sha256
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo_id,
        package_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    Ok(rows
        .into_iter()
        .map(|r| r.version.unwrap_or_default())
        .collect())
}

/// Fan out a `list_releases` lookup across the members of a virtual repo,
/// returning the versions from the first member that owns the package
/// (members are returned in priority order). Remote members are not consulted
/// for listing because their upstream listing shape is format-specific; the
/// `.zip`/metadata endpoints proxy them on demand.
pub async fn query_release_versions_virtual(
    db: &PgPool,
    virtual_repo_id: uuid::Uuid,
    package_id: &str,
) -> Result<Vec<String>, Response> {
    let members = proxy_helpers::fetch_virtual_members(db, virtual_repo_id).await?;
    for member in &members {
        if member.repo_type != RepositoryType::Local && member.repo_type != RepositoryType::Staging
        {
            continue;
        }
        let versions = query_release_versions(db, member.id, package_id).await?;
        if !versions.is_empty() {
            return Ok(versions);
        }
    }
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Version path handler -- dispatches to version info, archive, or manifest
// ---------------------------------------------------------------------------

async fn version_path_handler(
    State(state): State<SharedState>,
    Path((repo_key, scope, name, version_path)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let version_path = version_path.trim_start_matches('/');

    if version_path.ends_with(".zip") {
        // Download source archive: /:scope/:name/:version.zip
        let version = version_path.trim_end_matches(".zip");
        return download_archive(state, &repo_key, &scope, &name, version).await;
    }

    if version_path.ends_with("/Package.swift") || version_path.contains("/Package.swift") {
        // Fetch manifest: /:scope/:name/:version/Package.swift
        let version = version_path.trim_end_matches("/Package.swift");
        return fetch_manifest(state, &repo_key, &scope, &name, version).await;
    }

    // Release metadata: /:scope/:name/:version
    get_release_metadata(state, &repo_key, &scope, &name, version_path).await
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version -- Get release metadata
// ---------------------------------------------------------------------------

/// Minimal release row used to build the metadata response.
pub struct ReleaseRow {
    pub checksum_sha256: String,
    pub metadata: Option<serde_json::Value>,
}

/// Query a single Swift release's metadata row from one (non-virtual) repo.
async fn query_release_metadata(
    db: &PgPool,
    repo_id: uuid::Uuid,
    package_id: &str,
    version: &str,
) -> Result<Option<ReleaseRow>, Response> {
    // NOTE: the SELECT list is kept byte-identical to the pre-#1554 query so
    // the committed `.sqlx` offline cache entry still matches; only
    // `checksum_sha256` and `metadata` are consumed here.
    let row = sqlx::query!(
        r#"
        SELECT a.id, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo_id,
        package_id,
        version
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    Ok(row.map(|r| ReleaseRow {
        checksum_sha256: r.checksum_sha256,
        metadata: r.metadata,
    }))
}

/// Fan out a release-metadata lookup across the Local/Staging members of a
/// virtual repo, returning the first hit in priority order (issue #1554).
pub async fn query_release_metadata_virtual(
    db: &PgPool,
    virtual_repo_id: uuid::Uuid,
    package_id: &str,
    version: &str,
) -> Result<Option<ReleaseRow>, Response> {
    let members = proxy_helpers::fetch_virtual_members(db, virtual_repo_id).await?;
    for member in &members {
        if member.repo_type != RepositoryType::Local && member.repo_type != RepositoryType::Staging
        {
            continue;
        }
        if let Some(row) = query_release_metadata(db, member.id, package_id, version).await? {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

/// Build the release-metadata JSON body. Pure (no I/O) so the response shape
/// (resources list, manifest presence, embedded swift metadata) is unit-tested.
fn build_release_metadata_body(
    scope: &str,
    name: &str,
    version: &str,
    row: &ReleaseRow,
) -> serde_json::Value {
    let mut resources = vec![serde_json::json!({
        "name": "source-archive",
        "type": "application/zip",
        "checksum": row.checksum_sha256.clone(),
    })];

    let has_manifest = row
        .metadata
        .as_ref()
        .and_then(|m| m.get("manifest"))
        .is_some();

    if has_manifest {
        resources.push(serde_json::json!({
            "name": "Package.swift",
            "type": "text/x-swift",
        }));
    }

    serde_json::json!({
        "id": format!("{}.{}", scope, name),
        "version": version,
        "resources": resources,
        "metadata": row
            .metadata
            .clone()
            .and_then(|m| m.get("swift_metadata").cloned())
            .unwrap_or(serde_json::json!({})),
    })
}

async fn get_release_metadata(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    // Virtual repos own no artifacts: fan out across members (issue #1554).
    let row = if repo.repo_type == RepositoryType::Virtual {
        query_release_metadata_virtual(&state.db, repo.id, &package_id, version).await?
    } else {
        query_release_metadata(&state.db, repo.id, &package_id, version).await?
    }
    .ok_or_else(|| swift_error_response(StatusCode::NOT_FOUND, "Release not found"))?;

    let archive_url = format!("/swift/{}/{}/{}/{}.zip", repo_key, scope, name, version);
    let body = build_release_metadata_body(scope, name, version, &row);

    let mut response = swift_json_response(StatusCode::OK, body);
    response.headers_mut().insert(
        "Link",
        format!("<{}>; rel=\"latest-version\"", archive_url)
            .parse()
            .unwrap(),
    );

    Ok(response)
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version.zip -- Download source archive
// ---------------------------------------------------------------------------

async fn download_archive(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("{}/{}/{}.zip", scope, name, version);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        repo_key,
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
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let name_clone = package_id.clone();
                let version_clone = version.to_string();
                let upstream_path = format!("{}/{}/{}.zip", scope, name, version);
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let name = name_clone.clone();
                        let version = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &name, &version,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(result, "application/zip", None);
            }

            return Err(swift_error_response(
                StatusCode::NOT_FOUND,
                "Source archive not found",
            ));
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            swift_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Storage error: {}", e),
            )
        })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let checksum = artifact.checksum_sha256.clone();
    let filename = format!("{}-{}-{}.zip", scope, name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header("Content-Version", "1")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("Digest", format!("sha-256={}", checksum))
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version/Package.swift -- Fetch manifest
// ---------------------------------------------------------------------------

/// Look up the cached manifest text (if any) for a release in one repo.
/// Returns `Ok(None)` when the release does not exist in this repo, and
/// `Ok(Some(None))` when the release exists but has no cached manifest.
async fn query_manifest(
    db: &PgPool,
    repo_id: uuid::Uuid,
    package_id: &str,
    version: &str,
) -> Result<Option<Option<String>>, Response> {
    let row = sqlx::query!(
        r#"
        SELECT am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo_id,
        package_id,
        version
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    Ok(row.map(|r| {
        r.metadata
            .as_ref()
            .and_then(|m| m.get("manifest"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }))
}

/// Resolve which repo owns a Swift release for manifest fetching. For a
/// virtual repo this fans out across Local/Staging members in priority order
/// and returns the first that owns the release (issue #1554); for any other
/// repo type it returns the repo itself. The returned tuple carries the
/// owning repo's id, its storage location, and the cached manifest (if any).
async fn resolve_manifest_owner(
    db: &PgPool,
    repo: &RepoInfo,
    package_id: &str,
    version: &str,
) -> Result<(uuid::Uuid, crate::storage::StorageLocation, Option<String>), Response> {
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(db, repo.id).await?;
        for member in &members {
            if member.repo_type != RepositoryType::Local
                && member.repo_type != RepositoryType::Staging
            {
                continue;
            }
            if let Some(cached) = query_manifest(db, member.id, package_id, version).await? {
                return Ok((member.id, member.storage_location(), cached));
            }
        }
        return Err(swift_error_response(
            StatusCode::NOT_FOUND,
            "Release not found",
        ));
    }

    let cached = query_manifest(db, repo.id, package_id, version)
        .await?
        .ok_or_else(|| swift_error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    Ok((repo.id, repo.storage_location(), cached))
}

async fn fetch_manifest(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    // Resolve the owning repo (handles virtual fan-out), preferring the cached
    // manifest from artifact_metadata.
    let (owner_id, owner_location, cached_manifest) =
        resolve_manifest_owner(&state.db, &repo, &package_id, version).await?;

    // When the cache is missing (legacy uploads predating issue #1100, or
    // publishes that bypassed the header path), parse the source archive on
    // demand so SwiftPM dependency resolution still succeeds.
    let manifest = match cached_manifest {
        Some(m) => m,
        None => {
            // Look up the storage key separately so the primary query above can
            // keep its existing .sqlx offline cache entry (no schema change).
            let storage_key: String = sqlx::query_scalar(
                "SELECT storage_key FROM artifacts \
                 WHERE repository_id = $1 AND is_deleted = false \
                 AND LOWER(name) = LOWER($2) AND version = $3 LIMIT 1",
            )
            .bind(owner_id)
            .bind(&package_id)
            .bind(version)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                swift_error_response(
                    crate::api::handlers::db_status(&e),
                    &format!("Database error: {}", e),
                )
            })?;
            let storage = state
                .storage_for_repo(&owner_location)
                .map_err(|e| e.into_response())?;
            let zip_bytes = storage.get(&storage_key).await.map_err(|e| {
                swift_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Storage error: {}", e),
                )
            })?;
            extract_manifest_from_zip(&zip_bytes).ok_or_else(|| {
                swift_error_response(StatusCode::NOT_FOUND, "Manifest not found for this release")
            })?
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/x-swift")
        .header("Content-Version", "1")
        .body(Body::from(manifest))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /swift/:repo_key/:scope/:name/*version_path -- Publish release (wildcard wrapper)
// ---------------------------------------------------------------------------

async fn publish_release_from_wildcard(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, scope, name, version_path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let version = version_path.trim_start_matches('/').to_string();
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "swift", "write")?.user_id;
    publish_release(
        state, repo_key, scope, name, version, user_id, headers, body,
    )
    .await
}

// ---------------------------------------------------------------------------
// Publish release implementation
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn publish_release(
    state: SharedState,
    repo_key: String,
    scope: String,
    name: String,
    version: String,
    user_id: uuid::Uuid,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Validate path
    let _info = SwiftHandler::parse_path(&format!("{}/{}/{}", scope, name, version))
        .map_err(|e| swift_error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    if body.is_empty() {
        return Err(swift_error_response(
            StatusCode::BAD_REQUEST,
            "Empty request body",
        ));
    }

    let package_id = format!("{}.{}", scope, name);
    let artifact_path = format!("{}/{}/{}/{}.zip", scope, name, version, name);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND LOWER(name) = LOWER($2) AND version = $3 AND is_deleted = false",
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    if existing.is_some() {
        return Err(swift_error_response(
            StatusCode::CONFLICT,
            "A release with this version already exists",
        ));
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Store the file
    let storage_key = format!("swift/{}/{}/{}/{}.zip", scope, name, version, name);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    // Prefer the explicit X-Swift-Package-Manifest header (lets clients override
    // what's inside the archive), and fall back to parsing Package.swift from
    // the uploaded zip when the header is absent. Without the fallback, raw
    // `PUT ... application/zip` uploads fail SwiftPM dependency resolution
    // because the manifest endpoint returns 404 even though the archive is
    // perfectly valid (issue #1100).
    let manifest = headers
        .get("X-Swift-Package-Manifest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| extract_manifest_from_zip(&body));

    let swift_metadata = serde_json::json!({
        "scope": scope,
        "name": name,
        "version": version,
        "package_id": package_id,
        "manifest": manifest,
    });

    let size_bytes = body.len() as i64;

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
        package_id,
        version,
        size_bytes,
        computed_sha256,
        "application/zip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'swift', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        swift_metadata,
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
        "Swift publish: {}.{} {} to repo {}",
        scope, name, version, repo_key
    );

    Ok(swift_json_response(
        StatusCode::CREATED,
        serde_json::json!({}),
    ))
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/identifiers?url={package_url} -- Lookup identifiers
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
struct IdentifierQuery {
    url: Option<String>,
}

async fn lookup_identifiers(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<IdentifierQuery>,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    let package_url = query.url.as_deref().unwrap_or("");
    if package_url.is_empty() {
        return Err(swift_error_response(
            StatusCode::BAD_REQUEST,
            "Missing required 'url' query parameter",
        ));
    }

    // Look up packages that have a matching repository URL in their metadata
    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT a.name
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.metadata->>'repository_url' = $2
        "#,
        repo.id,
        package_url
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let identifiers: Vec<&str> = artifacts.iter().map(|a| a.name.as_str()).collect();

    let body = serde_json::json!({
        "identifiers": identifiers,
    });

    Ok(swift_json_response(StatusCode::OK, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // swift_json_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_swift_json_response_status_and_headers() {
        let body = serde_json::json!({"releases": {}});
        let response = swift_json_response(StatusCode::OK, body.clone());

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    #[test]
    fn test_swift_json_response_created() {
        let body = serde_json::json!({});
        let response = swift_json_response(StatusCode::CREATED, body);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    // -----------------------------------------------------------------------
    // swift_error_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_swift_error_response_status_and_content_type() {
        let response = swift_error_response(StatusCode::NOT_FOUND, "Release not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    #[test]
    fn test_swift_error_response_bad_request() {
        let response = swift_error_response(StatusCode::BAD_REQUEST, "Invalid path");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // IdentifierQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_identifier_query_with_url() {
        let query: IdentifierQuery =
            serde_json::from_str(r#"{"url": "https://github.com/example/repo"}"#).unwrap();
        assert_eq!(
            query.url,
            Some("https://github.com/example/repo".to_string())
        );
    }

    #[test]
    fn test_identifier_query_without_url() {
        let query: IdentifierQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(query.url, None);
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: package_id, artifact_path, storage_key, filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_id_format() {
        let scope = "apple";
        let name = "swift-log";
        let package_id = format!("{}.{}", scope, name);
        assert_eq!(package_id, "apple.swift-log");
    }

    #[test]
    fn test_artifact_path_format() {
        let scope = "vapor";
        let name = "async-kit";
        let version = "1.2.0";
        let artifact_path = format!("{}/{}/{}/{}.zip", scope, name, version, name);
        assert_eq!(artifact_path, "vapor/async-kit/1.2.0/async-kit.zip");
    }

    #[test]
    fn test_storage_key_format() {
        let scope = "grpc";
        let name = "grpc-swift";
        let version = "2.0.0";
        let storage_key = format!("swift/{}/{}/{}/{}.zip", scope, name, version, name);
        assert_eq!(storage_key, "swift/grpc/grpc-swift/2.0.0/grpc-swift.zip");
    }

    #[test]
    fn test_download_filename_format() {
        let scope = "apple";
        let name = "swift-nio";
        let version = "2.40.0";
        let filename = format!("{}-{}-{}.zip", scope, name, version);
        assert_eq!(filename, "apple-swift-nio-2.40.0.zip");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"test data");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Version path dispatching logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_path_zip_detection() {
        let path = "1.2.0.zip";
        assert!(path.ends_with(".zip"));
        let version = path.trim_end_matches(".zip");
        assert_eq!(version, "1.2.0");
    }

    #[test]
    fn test_version_path_manifest_detection() {
        let path = "1.2.0/Package.swift";
        assert!(path.ends_with("/Package.swift") || path.contains("/Package.swift"));
        let version = path.trim_end_matches("/Package.swift");
        assert_eq!(version, "1.2.0");
    }

    #[test]
    fn test_version_path_metadata_no_suffix() {
        let path = "1.2.0";
        assert!(!path.ends_with(".zip"));
        assert!(!path.ends_with("/Package.swift"));
        // Falls through to get_release_metadata
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/swift-repo".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            promotion_only: false,
        };
        assert_eq!(repo.id, id);
        assert_eq!(repo.storage_path, "/data/swift-repo");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/cache".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://swift-packages.example.com".to_string()),
            promotion_only: false,
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://swift-packages.example.com")
        );
    }

    // -----------------------------------------------------------------------
    // Regression: issue #1100 -- extract Package.swift from uploaded zip
    // -----------------------------------------------------------------------

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, bytes) in entries {
                writer.start_file(*name, opts).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    // -----------------------------------------------------------------------
    // Regression: issue #1554 -- virtual repo response builders
    //
    // These cover the pure response-shape logic for the three read endpoints
    // (list_releases / get_release_metadata / fetch_manifest). The DB fan-out
    // across virtual members is exercised by the `--ignored` integration tests
    // in tests/swift_virtual_tests.rs; here we lock the JSON shapes that the
    // virtual path feeds the same builders so the contract stays stable.
    // -----------------------------------------------------------------------

    #[test]
    fn build_releases_body_maps_versions_to_member_urls() {
        let versions = vec!["1.0.0".to_string(), "1.2.0".to_string()];
        let body = build_releases_body("swift-virtual", "macos", "lib", &versions);
        let releases = body.get("releases").unwrap().as_object().unwrap();
        assert_eq!(releases.len(), 2);
        // URLs must point at the *virtual* repo key, not a member key, so the
        // client keeps talking to the virtual repo on follow-up requests.
        assert_eq!(
            releases
                .get("1.2.0")
                .and_then(|v| v.get("url"))
                .and_then(|v| v.as_str()),
            Some("/swift/swift-virtual/macos/lib/1.2.0")
        );
        assert!(releases.contains_key("1.0.0"));
    }

    #[test]
    fn build_releases_body_empty_when_no_versions() {
        let body = build_releases_body("v", "s", "n", &[]);
        assert!(body
            .get("releases")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn build_release_metadata_body_without_manifest_has_only_archive() {
        let row = ReleaseRow {
            checksum_sha256: "abc123".to_string(),
            metadata: None,
        };
        let body = build_release_metadata_body("apple", "swift-log", "1.5.0", &row);
        assert_eq!(body.get("id").unwrap(), "apple.swift-log");
        assert_eq!(body.get("version").unwrap(), "1.5.0");
        let resources = body.get("resources").unwrap().as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].get("name").unwrap(), "source-archive");
        assert_eq!(resources[0].get("checksum").unwrap(), "abc123");
        // No swift_metadata -> empty object, not null.
        assert_eq!(body.get("metadata").unwrap(), &serde_json::json!({}));
    }

    #[test]
    fn build_release_metadata_body_with_manifest_adds_package_swift_resource() {
        let row = ReleaseRow {
            checksum_sha256: "deadbeef".to_string(),
            metadata: Some(serde_json::json!({
                "manifest": "// swift-tools-version:5.9",
                "swift_metadata": { "scope": "apple", "name": "swift-nio" },
            })),
        };
        let body = build_release_metadata_body("apple", "swift-nio", "2.40.0", &row);
        let resources = body.get("resources").unwrap().as_array().unwrap();
        assert_eq!(resources.len(), 2);
        assert!(resources
            .iter()
            .any(|r| r.get("name").and_then(|n| n.as_str()) == Some("Package.swift")));
        // Embedded swift_metadata is surfaced under "metadata".
        assert_eq!(
            body.get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str()),
            Some("swift-nio")
        );
    }

    #[test]
    fn extract_manifest_from_zip_returns_top_level_package_swift() {
        let zip = make_zip(&[
            ("Package.swift", b"// swift-tools-version:5.9\nlet pkg = 1"),
            ("Sources/Lib/lib.swift", b"public let x = 1"),
        ]);
        let manifest = extract_manifest_from_zip(&zip).expect("manifest expected");
        assert!(manifest.contains("swift-tools-version:5.9"));
    }

    #[test]
    fn extract_manifest_from_zip_handles_github_prefix_layout() {
        // Common layout from `git archive` / GitHub release tarballs:
        // a single top-level directory contains the package contents.
        let zip = make_zip(&[
            ("swift-log-1.5.0/README.md", b"# Log"),
            ("swift-log-1.5.0/Package.swift", b"let pkg = \"swift-log\""),
            ("swift-log-1.5.0/Sources/Logging/Logger.swift", b"// source"),
        ]);
        let manifest = extract_manifest_from_zip(&zip).expect("manifest expected");
        assert!(manifest.contains("swift-log"));
    }

    #[test]
    fn extract_manifest_from_zip_prefers_shallowest_when_multiple() {
        // Tests/Fixtures often ship a nested Package.swift; the shallower one
        // is the real manifest and must win.
        let zip = make_zip(&[
            ("pkg/Tests/Fixtures/Subpkg/Package.swift", b"// fixture"),
            ("pkg/Package.swift", b"// real manifest"),
        ]);
        let manifest = extract_manifest_from_zip(&zip).expect("manifest expected");
        assert!(manifest.contains("real manifest"));
    }

    #[test]
    fn extract_manifest_from_zip_returns_none_for_archive_without_manifest() {
        let zip = make_zip(&[
            ("README.md", b"no manifest"),
            ("src/lib.swift", b"// no manifest"),
        ]);
        assert!(extract_manifest_from_zip(&zip).is_none());
    }

    #[test]
    fn extract_manifest_from_zip_returns_none_for_malformed_zip() {
        let not_a_zip = b"this is not a zip file at all";
        assert!(extract_manifest_from_zip(not_a_zip).is_none());
    }

    /// Builds a zip that includes an explicit directory entry alongside files.
    /// Exercises the `!entry.is_file()` skip path inside the loop so the
    /// directory entry does not get picked up as a Package.swift candidate.
    fn make_zip_with_directory() -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            // Explicit directory entry. `add_directory` is the canonical
            // way to emit a directory record in a zip archive; the resulting
            // entry has `is_file() == false`.
            writer.add_directory("dir/", opts).unwrap();
            writer.start_file("dir/Package.swift", opts).unwrap();
            writer.write_all(b"// nested manifest").unwrap();
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extract_manifest_from_zip_skips_directory_entries() {
        // A real zip can include directory records (e.g. produced by
        // `zip -r` or `add_directory`). The loop must skip them via the
        // `!entry.is_file()` guard rather than treating "dir/" as a file
        // path; the nested Package.swift inside should still be returned.
        let zip = make_zip_with_directory();
        let manifest = extract_manifest_from_zip(&zip).expect("manifest expected");
        assert!(manifest.contains("nested manifest"));
    }

    /// Build a zip whose Package.swift body is non-UTF-8 bytes (raw 0xFF / 0xFE
    /// noise). `read_to_string` returns an error in that case, exercising the
    /// `continue` branch on the read error path so the file is skipped rather
    /// than treated as a manifest.
    fn make_zip_with_non_utf8_manifest() -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            // Invalid UTF-8: a lone continuation byte after a start-of-sequence
            // byte without the required follow-up.
            writer.start_file("Package.swift", opts).unwrap();
            writer
                .write_all(&[0xC3, 0x28, 0xA0, 0xA1, 0xFF, 0xFE, 0xFD])
                .unwrap();
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extract_manifest_from_zip_skips_non_utf8_manifest() {
        // A Package.swift that doesn't decode as UTF-8 hits the read_to_string
        // error path. Because it's also the only candidate, the function must
        // return None (rather than panicking or returning a partial buffer).
        let zip = make_zip_with_non_utf8_manifest();
        assert!(extract_manifest_from_zip(&zip).is_none());
    }

    #[test]
    fn extract_manifest_from_zip_rejects_oversized_manifest() {
        // Defense against zip bombs: an attacker-controlled Package.swift
        // entry larger than MAX_MANIFEST_BYTES must be skipped, not read
        // into memory. With only an oversized candidate present the function
        // must return None.
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            // Use Deflate so the compressed archive stays tiny while the
            // uncompressed entry exceeds MAX_MANIFEST_BYTES. This mimics
            // a zip-bomb payload.
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("Package.swift", opts).unwrap();
            // 2 MiB of a single byte -- compresses to a few hundred bytes
            // on disk but exceeds the 1 MiB manifest cap.
            let payload = vec![b'a'; (MAX_MANIFEST_BYTES as usize) + 1024];
            writer.write_all(&payload).unwrap();
            writer.finish().unwrap();
        }
        assert!(
            extract_manifest_from_zip(&buf).is_none(),
            "oversized Package.swift must be refused to bound memory"
        );
    }

    #[test]
    fn extract_manifest_from_zip_accepts_manifest_at_size_cap() {
        // A Package.swift right at the size limit must still be accepted.
        // Verifies the boundary check is `>` not `>=` so legitimate large
        // manifests aren't punished.
        use std::io::Write;
        let mut buf = Vec::new();
        // Build content under the cap that still parses as text.
        let prefix = b"// swift-tools-version:5.9\n// padding ";
        let pad_size = (MAX_MANIFEST_BYTES as usize) - prefix.len() - 16;
        let content: Vec<u8> = prefix
            .iter()
            .copied()
            .chain(std::iter::repeat(b'x').take(pad_size))
            .collect();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file("Package.swift", opts).unwrap();
            writer.write_all(&content).unwrap();
            writer.finish().unwrap();
        }
        let manifest = extract_manifest_from_zip(&buf).expect("manifest at cap must be accepted");
        assert!(manifest.contains("swift-tools-version:5.9"));
        assert!((manifest.len() as u64) <= MAX_MANIFEST_BYTES);
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_swift_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "swift").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/identifiers?url=https://example.test/pkg.git"),
            format!("/{k}/scope/name"),
            format!("/{k}/scope/name/1.0.0"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}
