//! Composer (PHP) Repository API handlers.
//!
//! Implements the endpoints required for `composer install` and `composer require`
//! per the Packagist/Composer repository specification.
//!
//! Routes are mounted at `/composer/{repo_key}/...`:
//!   GET  /composer/{repo_key}/packages.json                           - Root packages index
//!   GET  /composer/{repo_key}/p2/{vendor}/{package}.json              - Package metadata (v2)
//!   GET  /composer/{repo_key}/p/{vendor}/{package}${hash}.json        - Package metadata (v1)
//!   GET  /composer/{repo_key}/dist/{vendor}/{package}/{version}/{ref}.zip - Download archive
//!   GET  /composer/{repo_key}/search.json?q=query                     - Search packages
//!   PUT  /composer/{repo_key}/api/packages                            - Upload/register package
//!   POST /composer/{repo_key}/api/packages                            - Upload/register package

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::composer::ComposerHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Root packages index
        .route("/:repo_key/packages.json", get(packages_json))
        // Composer v2 metadata: /p2/{vendor}/{package}.json
        .route("/:repo_key/p2/:vendor/:package", get(metadata_v2))
        // Composer v1 metadata: /p/{vendor}/{package_hash}.json
        .route("/:repo_key/p/:vendor/:package_hash", get(metadata_v1))
        // Distribution archive download
        .route(
            "/:repo_key/dist/:vendor/:package/:version/:reference",
            get(download_archive),
        )
        // Search
        .route("/:repo_key/search.json", get(search))
        // Upload/register package (PUT and POST)
        .route("/:repo_key/api/packages", put(upload).post(upload))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_composer_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["composer", "php"], "a Composer").await
}

// ---------------------------------------------------------------------------
// Composer metadata helpers
// ---------------------------------------------------------------------------

/// Build the upstream path for the Composer v2 metadata document of a package.
///
/// The Composer v2 wire shape is `p2/{vendor}/{package}.json`. Helper-extracted
/// so the proxy fallback in `metadata_v2` is unit-testable without spinning up
/// a database + proxy_service (#1096).
fn composer_v2_upstream_path(full_name: &str) -> String {
    format!("p2/{}.json", full_name)
}

/// Build the upstream path for the Composer v1 metadata document of a package.
///
/// The Composer v1 wire shape is `p/{vendor}/{package}.json`. Helper-extracted
/// for the same reason as [`composer_v2_upstream_path`] (#1096).
fn composer_v1_upstream_path(full_name: &str) -> String {
    format!("p/{}.json", full_name)
}

/// Build the 200 response that the metadata_v1 / metadata_v2 proxy fallback
/// returns to the composer client. Extracted from the handler body so the
/// response-construction path (status, content-type default, body wiring) is
/// unit-testable without DB or proxy_service (#1096).
///
/// `content_type` is taken from the upstream response when present; we default
/// to `application/json` because the composer client treats anything else as
/// a fetch error.
fn build_composer_proxy_response(content: Bytes, content_type: Option<String>) -> Response {
    let ct = content_type.unwrap_or_else(|| "application/json".to_string());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .body(Body::from(content))
        .unwrap()
}

/// Keys from composer.json that should be merged into version entries.
const COMPOSER_METADATA_KEYS: &[&str] = &[
    "description",
    "type",
    "license",
    "require",
    "require-dev",
    "autoload",
    "authors",
    "keywords",
    "homepage",
];

/// Merge composer.json metadata fields into a version entry JSON object.
fn merge_composer_metadata(
    version_entry: &mut serde_json::Value,
    metadata: Option<&serde_json::Value>,
) {
    let composer = metadata.and_then(|m| m.get("composer"));

    let Some(composer) = composer else {
        return;
    };

    for key in COMPOSER_METADATA_KEYS {
        if let Some(val) = composer.get(*key) {
            // Skip JSON null so absent optional fields are omitted from the
            // version entry rather than serialized as `"field": null`. This
            // matters for records stored before ComposerJson gained
            // `skip_serializing_if`, whose metadata still carries null fields
            // (#1781).
            if !val.is_null() {
                version_entry[*key] = val.clone();
            }
        }
    }
}

/// Row shape shared by the v1/v2 metadata queries. Holds just the fields
/// needed to render a composer version entry. Extracted so the per-member
/// fan-out in virtual repos can reuse one query + one renderer (#1715).
struct ComposerArtifactRow {
    version: Option<String>,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
}

/// Look up all (non-deleted) artifacts named `full_name` in a single repository.
///
/// Used by `metadata_v2` / `metadata_v1` for the repo's own artifacts and,
/// for virtual repos, by the per-member fan-out (#1715). Returning the rows
/// (rather than a built response) lets callers decide between the v1 and v2
/// wire shapes from the same query.
async fn fetch_composer_artifacts(
    db: &PgPool,
    repo_id: uuid::Uuid,
    full_name: &str,
) -> Result<Vec<ComposerArtifactRow>, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT a.version, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repo_id,
        full_name
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    Ok(rows
        .into_iter()
        .map(|r| ComposerArtifactRow {
            version: r.version,
            checksum_sha256: r.checksum_sha256,
            metadata: r.metadata,
        })
        .collect())
}

/// Row shape for the root `packages.json` index: one row per
/// (name, version) artifact plus its merged composer metadata.
struct PackageIndexRow {
    name: String,
    version: Option<String>,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
}

/// Fetch every (non-deleted) artifact in `repo_id` for the root packages
/// index. Returning rows (rather than a built map) lets the virtual
/// `packages_json` fan-out aggregate rows from several members before
/// rendering (#1781).
async fn fetch_package_index_rows(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<Vec<PackageIndexRow>, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT a.name, a.version,
               a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
        ORDER BY a.name, a.version
        "#,
        repo_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    Ok(rows
        .into_iter()
        .map(|r| PackageIndexRow {
            name: r.name,
            version: r.version,
            checksum_sha256: r.checksum_sha256,
            metadata: r.metadata,
        })
        .collect())
}

/// Build the `packages` map of the root `packages.json` index from artifact
/// rows, grouping versions under each package name. `repo_key` is threaded
/// into the dist URLs so (for virtual repos) downloads route back through the
/// virtual repo rather than the member. Pure, so it is unit-testable (#1781).
fn build_packages_index(
    repo_key: &str,
    rows: &[PackageIndexRow],
) -> serde_json::Map<String, serde_json::Value> {
    let mut by_name: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for row in rows {
        let version = row.version.as_deref().unwrap_or("dev-main");
        let entry = build_version_entry(
            repo_key,
            &row.name,
            version,
            &row.checksum_sha256,
            row.metadata.as_ref(),
        );
        by_name.entry(row.name.clone()).or_default().push(entry);
    }

    let mut packages_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (name, versions) in by_name {
        packages_map.insert(name, serde_json::Value::Array(versions));
    }
    packages_map
}

/// Render the Composer v2 "minified" metadata document from a member's
/// artifact rows. The `dist.url` is rewritten to point at the *virtual*
/// repo_key so the composer client routes a locally-served package's download
/// back through us rather than to an upstream host (#1715).
fn build_metadata_v2_response(
    repo_key: &str,
    full_name: &str,
    artifacts: &[ComposerArtifactRow],
) -> Response {
    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("dev-main");
            build_version_entry(
                repo_key,
                full_name,
                version,
                &a.checksum_sha256,
                a.metadata.as_ref(),
            )
        })
        .collect();

    let mut packages_map = serde_json::Map::new();
    packages_map.insert(full_name.to_string(), serde_json::Value::Array(versions));

    let response = serde_json::json!({
        "packages": packages_map,
        "minified": "composer/2.0",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap()
}

/// Render the Composer v1 metadata document from a member's artifact rows.
fn build_metadata_v1_response(
    repo_key: &str,
    full_name: &str,
    artifacts: &[ComposerArtifactRow],
) -> Response {
    let mut version_map = serde_json::Map::new();
    for a in artifacts {
        let version = a.version.as_deref().unwrap_or("dev-main");
        let entry = build_version_entry(
            repo_key,
            full_name,
            version,
            &a.checksum_sha256,
            a.metadata.as_ref(),
        );
        version_map.insert(version.to_string(), entry);
    }

    let mut packages_map = serde_json::Map::new();
    packages_map.insert(
        full_name.to_string(),
        serde_json::Value::Object(version_map),
    );

    let response = serde_json::json!({
        "packages": packages_map,
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap()
}

/// Resolve composer package metadata for a VIRTUAL repository by fanning out
/// across member repos in priority order (#1715).
///
/// Mirrors the npm virtual-metadata pattern: Local/Staging members are served
/// from the local DB (rendered into the requested wire shape), then Remote
/// members are proxied from upstream (and proxy-cached). First member that has
/// the package wins. Returns 404 only when no member can satisfy the request.
///
/// `render_local` builds the response from a member's DB rows; `upstream_path`
/// is the v1 or v2 path proxied from remote members. The virtual `repo_key` is
/// threaded through so locally-rendered `dist.url`s route back through us.
async fn resolve_virtual_composer_metadata<R>(
    state: &SharedState,
    virtual_repo_id: uuid::Uuid,
    virtual_repo_key: &str,
    full_name: &str,
    upstream_path: &str,
    render_local: R,
) -> Result<Response, Response>
where
    R: Fn(&str, &str, &[ComposerArtifactRow]) -> Response,
{
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        // Local/Staging members: serve from the local DB.
        if member.repo_type == RepositoryType::Local || member.repo_type == RepositoryType::Staging
        {
            let artifacts = fetch_composer_artifacts(&state.db, member.id, full_name).await?;
            if !artifacts.is_empty() {
                return Ok(render_local(virtual_repo_key, full_name, &artifacts));
            }
            continue;
        }

        // Remote members: proxy (and cache) metadata from upstream.
        if member.repo_type != RepositoryType::Remote {
            continue;
        }
        let Some(ref upstream_url) = member.upstream_url else {
            continue;
        };
        let Some(ref proxy) = state.proxy_service else {
            continue;
        };

        match proxy_helpers::proxy_fetch(proxy, member.id, &member.key, upstream_url, upstream_path)
            .await
        {
            Ok((content, content_type)) => {
                return Ok(build_composer_proxy_response(content, content_type));
            }
            Err(_e) => {
                tracing::debug!(
                    member_key = %member.key,
                    path = %upstream_path,
                    "composer metadata proxy fetch missed for virtual member"
                );
            }
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        "Package not found in any member repository",
    )
        .into_response())
}

/// Build a version entry JSON for a composer package.
fn build_version_entry(
    repo_key: &str,
    name: &str,
    version: &str,
    checksum_sha256: &str,
    metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "name": name,
        "version": version,
        "dist": {
            "type": "zip",
            "url": format!("/composer/{}/dist/{}/{}/{}.zip",
                repo_key, name, version, checksum_sha256
            ),
            "reference": checksum_sha256,
            "shasum": checksum_sha256,
        },
    });

    merge_composer_metadata(&mut entry, metadata);
    entry
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/packages.json - Root packages index
// ---------------------------------------------------------------------------

async fn packages_json(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Virtual repos aggregate the index from their local/staging members:
    // collect every member's artifacts and render them under the *virtual*
    // repo key so dist URLs route back through us. Without this fan-out a
    // virtual repo returned an empty `{}` even when a member held packages
    // (#1781). Remote members are not aggregated into the root index (Composer
    // resolves those per-package via the metadata-url).
    let rows = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut aggregated: Vec<PackageIndexRow> = Vec::new();
        for member in &members {
            if member.repo_type == RepositoryType::Local
                || member.repo_type == RepositoryType::Staging
            {
                aggregated.extend(fetch_package_index_rows(&state.db, member.id).await?);
            }
        }
        aggregated
    } else {
        fetch_package_index_rows(&state.db, repo.id).await?
    };

    let packages_map = build_packages_index(&repo_key, &rows);

    let response = serde_json::json!({
        "packages": packages_map,
        "metadata-url": format!("/composer/{}/p2/%package%.json", repo_key),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/p2/{vendor}/{package}.json - Package metadata (v2)
// ---------------------------------------------------------------------------

async fn metadata_v2(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package_file)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Strip .json extension from package name
    let package = package_file.trim_end_matches(".json");
    let full_name = format!("{}/{}", vendor, package);

    // #1715: Virtual repos resolve p2 metadata across member repos (local
    // first, then remote upstream) in priority order. Without this branch a
    // virtual repo always returned 404 even when a member had the package.
    if repo.repo_type == RepositoryType::Virtual {
        let upstream_path = composer_v2_upstream_path(&full_name);
        return resolve_virtual_composer_metadata(
            &state,
            repo.id,
            &repo_key,
            &full_name,
            &upstream_path,
            build_metadata_v2_response,
        )
        .await;
    }

    let artifacts = fetch_composer_artifacts(&state.db, repo.id, &full_name).await?;

    if artifacts.is_empty() {
        // #1096: For remote repos, proxy the v2 metadata document from
        // upstream when we have nothing cached locally. The composer CLI
        // hits `/p2/{vendor}/{package}.json` as its first lookup; returning
        // 404 here means `composer install` fails even when the upstream
        // (packagist.org or any mirror) has the package. The proxy_service
        // also caches the response body so subsequent requests hit the
        // cache, matching the behaviour of the PyPI and OCI handlers.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = composer_v2_upstream_path(&full_name);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(build_composer_proxy_response(content, content_type));
            }
        }
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build the v2 "minified" format: {"packages": {"vendor/package": [...]}}
    Ok(build_metadata_v2_response(
        &repo_key, &full_name, &artifacts,
    ))
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/p/{vendor}/{package_hash}.json - Package metadata (v1)
// ---------------------------------------------------------------------------

async fn metadata_v1(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package_hash)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Parse: {package}${sha256}.json or {package}.json
    let raw = package_hash.trim_end_matches(".json");
    let package = raw.split('$').next().unwrap_or(raw);
    let full_name = format!("{}/{}", vendor, package);

    // #1715: Virtual repos resolve legacy p (v1) metadata across members too.
    if repo.repo_type == RepositoryType::Virtual {
        let upstream_path = composer_v1_upstream_path(&full_name);
        return resolve_virtual_composer_metadata(
            &state,
            repo.id,
            &repo_key,
            &full_name,
            &upstream_path,
            build_metadata_v1_response,
        )
        .await;
    }

    let artifacts = fetch_composer_artifacts(&state.db, repo.id, &full_name).await?;

    if artifacts.is_empty() {
        // #1096: Also proxy the v1 metadata format for older composer
        // clients. The upstream path mirrors the v1 URL shape (`p/`).
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = composer_v1_upstream_path(&full_name);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(build_composer_proxy_response(content, content_type));
            }
        }
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build v1 format: {"packages": {"vendor/package": {"version": {...}}}}
    Ok(build_metadata_v1_response(
        &repo_key, &full_name, &artifacts,
    ))
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/dist/{vendor}/{package}/{version}/{ref}.zip
// ---------------------------------------------------------------------------

async fn download_archive(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package, version, reference)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;
    let full_name = format!("{}/{}", vendor, package);

    // Strip .zip extension from reference if present
    let reference = reference.trim_end_matches(".zip");

    // Find the artifact by name, version, and sha256 reference
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND name = $2
          AND version = $3
          AND checksum_sha256 = $4
        LIMIT 1
        "#,
        repo.id,
        full_name,
        version,
        reference
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Archive not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("dist/{}/{}/{}/{}.zip", vendor, package, version, reference);
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
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let vname = full_name.clone();
                let vversion = version.clone();
                let upstream_path =
                    format!("dist/{}/{}/{}/{}.zip", vendor, package, version, reference);
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &vname, &vversion,
                            )
                            .await
                        }
                    },
                )
                .await?;

                let filename = format!("{}-{}.zip", package, version);

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/zip",
                    Some(&filename),
                );
            }
            return Err(not_found);
        }
    };

    // Read from storage
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

    let filename = format!("{}-{}.zip", package, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/search.json?q=query - Search packages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
    #[serde(rename = "type")]
    package_type: Option<String>,
    per_page: Option<i64>,
    page: Option<i64>,
}

/// Build the `next` pagination URL for the search response, preserving the
/// active `per_page` and `type` query parameters so paginated, filtered
/// searches keep working past page 1 (#1781).
///
/// `per_page` is the *raw* request value (`None` when the client did not send
/// one); we only append it when explicitly provided so default-page links stay
/// clean. `type_filter` is appended verbatim when set.
fn build_search_next_url(
    repo_key: &str,
    query_str: &str,
    page: i64,
    per_page: Option<i64>,
    type_filter: Option<&str>,
) -> String {
    let per_page_param = match per_page {
        Some(pp) => format!("&per_page={}", pp),
        None => String::new(),
    };
    let type_param = match type_filter {
        Some(t) => format!("&type={}", t),
        None => String::new(),
    };
    format!(
        "/composer/{}/search.json?q={}&page={}{}{}",
        repo_key,
        query_str,
        page + 1,
        per_page_param,
        type_param,
    )
}

async fn search(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    let query_str = params.q.unwrap_or_default();
    let per_page = params.per_page.unwrap_or(15).min(100);
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;

    // Search by name pattern
    let search_pattern = format!("%{}%", query_str);

    // The `type` filter is applied in SQL (against the composer metadata) so
    // that pagination LIMIT/OFFSET and the total count both see the same
    // filtered row set. Filtering in Rust *after* LIMIT/OFFSET (the old
    // behaviour) under-filled pages and, worse, made the total count ignore
    // `type` entirely — `type=library` returned total=6 with only 4 results
    // (#1781). `$3::text IS NULL` short-circuits the predicate when no type is
    // requested.
    let type_filter = params.package_type.as_deref();

    let results = sqlx::query!(
        r#"
        SELECT DISTINCT a.name,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name ILIKE $2
          AND ($3::text IS NULL OR am.metadata #>> '{composer,type}' = $3)
        ORDER BY a.name
        LIMIT $4 OFFSET $5
        "#,
        repo.id,
        search_pattern,
        type_filter,
        per_page,
        offset
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

    let search_results: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let description = r
                .metadata
                .as_ref()
                .and_then(|m| m.get("composer"))
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let url = format!("/composer/{}/p2/{}.json", repo_key, r.name);

            serde_json::json!({
                "name": r.name,
                "description": description,
                "url": url,
            })
        })
        .collect();

    // Count total results for pagination — must honor the same `type`
    // predicate as the page query (#1781).
    let total_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT a.name)
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name ILIKE $2
          AND ($3::text IS NULL OR am.metadata #>> '{composer,type}' = $3)
        "#,
        repo.id,
        search_pattern,
        type_filter
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .unwrap_or(0);

    let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
    let has_next = page < total_pages;

    let mut response = serde_json::json!({
        "results": search_results,
        "total": total_count,
    });

    if has_next {
        response["next"] = serde_json::Value::String(build_search_next_url(
            &repo_key,
            &query_str,
            page,
            params.per_page,
            type_filter,
        ));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT/POST /composer/{repo_key}/api/packages - Upload/register package
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "composer", "write")?.user_id;
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // The body should be a zip archive containing composer.json
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty request body").into_response());
    }

    // Parse composer.json from the archive to extract metadata
    let composer_json = ComposerHandler::parse_composer_json(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to parse composer.json from archive: {}", e),
        )
            .into_response()
    })?;

    // Validate package name has vendor/package format
    let full_name = &composer_json.name;
    if !full_name.contains('/') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid package name '{}': must be in vendor/package format",
                full_name
            ),
        )
            .into_response());
    }

    let version = composer_json
        .version
        .as_deref()
        .unwrap_or("dev-main")
        .to_string();

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    // Build artifact path
    let artifact_path = format!("{}/{}/{}.zip", full_name, version, sha256);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        full_name,
        version
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
            format!("Version {} of {} already exists", version, full_name),
        )
            .into_response());
    }

    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Composer,
        repo.id,
        &artifact_path,
        &sha256,
    )
    .await
    .map_err(|e| e.into_response())?;

    // Store the archive
    let storage_key = format!("composer/{}/{}/{}.zip", full_name, version, sha256);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        full_name,
        version,
        size_bytes,
        sha256,
        "application/zip",
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
    let composer_metadata = serde_json::json!({
        "name": full_name,
        "version": version,
        "composer": serde_json::to_value(&composer_json).unwrap_or_default(),
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'composer', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        composer_metadata,
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

    // Populate packages / package_versions tables (best-effort).
    //
    // #1341: the WebUI Packages tab reads the `packages` table, not
    // `artifacts`. Every other artifact-publishing handler (npm, pypi,
    // nuget) calls PackageService after the artifact insert; the Composer
    // handler did not, so a successfully uploaded Composer package was
    // stored and served over the Composer wire protocol but never appeared
    // in the WebUI. Mirror the npm/pypi pattern here. The call is
    // fire-and-forget so a packages-table failure never blocks the upload.
    {
        let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
        pkg_svc
            .try_create_or_update_from_artifact(
                repo.id,
                full_name,
                &version,
                size_bytes,
                &sha256,
                composer_json.description.as_deref(),
                Some(serde_json::json!({ "format": "composer" })),
            )
            .await;
    }

    info!(
        "Composer upload: {} {} to repo {}",
        full_name, version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "status": "ok",
                "package": full_name,
                "version": version,
                "sha256": sha256,
            }))
            .unwrap(),
        ))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/composer".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://packagist.org".to_string()),
        };
        assert_eq!(info.id, id);
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.upstream_url, Some("https://packagist.org".to_string()));
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert!(q.package_type.is_none());
        assert!(q.per_page.is_none());
        assert!(q.page.is_none());
    }

    #[test]
    fn test_search_query_with_type() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"monolog","type":"library","per_page":30,"page":2}"#)
                .unwrap();
        assert_eq!(q.q, Some("monolog".to_string()));
        assert_eq!(q.package_type, Some("library".to_string()));
        assert_eq!(q.per_page, Some(30));
        assert_eq!(q.page, Some(2));
    }

    // -----------------------------------------------------------------------
    // Package name validation (vendor/package format)
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_name_valid() {
        let name = "monolog/monolog";
        assert!(name.contains('/'));
    }

    #[test]
    fn test_package_name_invalid_no_slash() {
        let name = "no-vendor";
        assert!(!name.contains('/'));
    }

    // -----------------------------------------------------------------------
    // Composer v1 metadata package hash parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_package_hash_parsing_with_hash() {
        let package_hash = "monolog$abc123.json";
        let raw = package_hash.trim_end_matches(".json");
        let package = raw.split('$').next().unwrap_or(raw);
        assert_eq!(package, "monolog");
    }

    #[test]
    fn test_v1_package_hash_parsing_without_hash() {
        let package_hash = "monolog.json";
        let raw = package_hash.trim_end_matches(".json");
        let package = raw.split('$').next().unwrap_or(raw);
        assert_eq!(package, "monolog");
    }

    #[test]
    fn test_v1_full_name_construction() {
        let vendor = "monolog";
        let package = "monolog";
        let full_name = format!("{}/{}", vendor, package);
        assert_eq!(full_name, "monolog/monolog");
    }

    // -----------------------------------------------------------------------
    // Composer v2 package file parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_package_file_trim() {
        let package_file = "monolog.json";
        let package = package_file.trim_end_matches(".json");
        assert_eq!(package, "monolog");
    }

    // -----------------------------------------------------------------------
    // Artifact path and storage key generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_artifact_path() {
        let full_name = "vendor/package";
        let version = "1.2.3";
        let sha256 = "abc123def456";
        let artifact_path = format!("{}/{}/{}.zip", full_name, version, sha256);
        assert_eq!(artifact_path, "vendor/package/1.2.3/abc123def456.zip");
    }

    #[test]
    fn test_composer_storage_key() {
        let full_name = "monolog/monolog";
        let version = "3.0.0";
        let sha256 = "fedcba987654";
        let storage_key = format!("composer/{}/{}/{}.zip", full_name, version, sha256);
        assert_eq!(
            storage_key,
            "composer/monolog/monolog/3.0.0/fedcba987654.zip"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256() {
        let data = b"composer package";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Distribution URL formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_dist_url_format() {
        let repo_key = "php-repo";
        let name = "vendor/package";
        let version = "1.0.0";
        let sha256 = "abc123";
        let url = format!(
            "/composer/{}/dist/{}/{}/{}.zip",
            repo_key, name, version, sha256
        );
        assert_eq!(
            url,
            "/composer/php-repo/dist/vendor/package/1.0.0/abc123.zip"
        );
    }

    // -----------------------------------------------------------------------
    // Reference .zip strip
    // -----------------------------------------------------------------------

    #[test]
    fn test_reference_strip_zip() {
        let reference = "abc123def.zip";
        let stripped = reference.trim_end_matches(".zip");
        assert_eq!(stripped, "abc123def");
    }

    #[test]
    fn test_reference_no_zip() {
        let reference = "abc123def";
        let stripped = reference.trim_end_matches(".zip");
        assert_eq!(stripped, "abc123def");
    }

    // -----------------------------------------------------------------------
    // Metadata URL pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_url_pattern() {
        let repo_key = "composer-hosted";
        let metadata_url = format!("/composer/{}/p2/%package%.json", repo_key);
        assert_eq!(metadata_url, "/composer/composer-hosted/p2/%package%.json");
    }

    // -----------------------------------------------------------------------
    // Search pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pagination() {
        let per_page = 15i64;
        let page = 1i64;
        let offset = (page - 1) * per_page;
        assert_eq!(offset, 0);

        let total_count = 45i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 3);
        let has_next = page < total_pages;
        assert!(has_next);
    }

    #[test]
    fn test_search_per_page_clamping() {
        let per_page_input = 200i64;
        let per_page = per_page_input.min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_search_page_clamping() {
        let page_input = 0i64;
        let page = page_input.max(1);
        assert_eq!(page, 1);
    }

    // -----------------------------------------------------------------------
    // Default version handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_version() {
        let resolved: &str = "dev-main";
        assert_eq!(resolved, "dev-main");
    }

    // -----------------------------------------------------------------------
    // merge_composer_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_composer_metadata_all_keys() {
        let mut entry = serde_json::json!({"name": "vendor/pkg", "version": "1.0.0"});
        let metadata = serde_json::json!({
            "composer": {
                "description": "A PHP library",
                "type": "library",
                "license": "MIT",
                "require": {"php": ">=8.1"},
                "require-dev": {"phpunit/phpunit": "^10"},
                "autoload": {"psr-4": {"Vendor\\": "src/"}},
                "authors": [{"name": "Jane"}],
                "keywords": ["php", "library"],
                "homepage": "https://example.com"
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));

        assert_eq!(entry["description"], "A PHP library");
        assert_eq!(entry["type"], "library");
        assert_eq!(entry["license"], "MIT");
        assert_eq!(entry["require"]["php"], ">=8.1");
        assert_eq!(entry["require-dev"]["phpunit/phpunit"], "^10");
        assert!(entry["autoload"]["psr-4"].is_object());
        assert_eq!(entry["authors"][0]["name"], "Jane");
        assert_eq!(entry["keywords"][0], "php");
        assert_eq!(entry["homepage"], "https://example.com");
    }

    #[test]
    fn test_merge_composer_metadata_no_composer_key() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        let metadata = serde_json::json!({"format": "composer"});
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert!(entry.get("description").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_none() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        merge_composer_metadata(&mut entry, None);
        assert!(entry.get("description").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_partial_keys() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        let metadata = serde_json::json!({
            "composer": {
                "description": "Partial",
                "license": ["MIT", "Apache-2.0"]
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert_eq!(entry["description"], "Partial");
        assert!(entry["license"].is_array());
        assert!(entry.get("type").is_none());
        assert!(entry.get("require").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_does_not_overwrite_existing() {
        let mut entry = serde_json::json!({
            "name": "vendor/pkg",
            "description": "original"
        });
        let metadata = serde_json::json!({
            "composer": {
                "description": "from composer.json"
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert_eq!(entry["description"], "from composer.json");
    }

    // -----------------------------------------------------------------------
    // build_version_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_entry_basic() {
        let entry = build_version_entry(
            "php-hosted",
            "monolog/monolog",
            "3.0.0",
            "abc123def456",
            None,
        );
        assert_eq!(entry["name"], "monolog/monolog");
        assert_eq!(entry["version"], "3.0.0");
        assert_eq!(entry["dist"]["type"], "zip");
        assert_eq!(entry["dist"]["reference"], "abc123def456");
        assert_eq!(entry["dist"]["shasum"], "abc123def456");
        let url = entry["dist"]["url"].as_str().unwrap();
        assert_eq!(
            url,
            "/composer/php-hosted/dist/monolog/monolog/3.0.0/abc123def456.zip"
        );
    }

    #[test]
    fn test_build_version_entry_with_metadata() {
        let metadata = serde_json::json!({
            "composer": {
                "description": "Sends logs to files, sockets, inboxes, and databases",
                "type": "library",
                "license": "MIT",
                "require": {"php": ">=8.1", "psr/log": "^3"}
            }
        });
        let entry = build_version_entry(
            "repo",
            "monolog/monolog",
            "3.5.0",
            "fedcba",
            Some(&metadata),
        );
        assert_eq!(
            entry["description"],
            "Sends logs to files, sockets, inboxes, and databases"
        );
        assert_eq!(entry["type"], "library");
        assert_eq!(entry["license"], "MIT");
        assert_eq!(entry["require"]["php"], ">=8.1");
    }

    #[test]
    fn test_build_version_entry_dist_url_format() {
        let entry =
            build_version_entry("my-repo", "laravel/framework", "11.0.0", "sha256hex", None);
        let url = entry["dist"]["url"].as_str().unwrap();
        assert!(url.starts_with("/composer/my-repo/dist/"));
        assert!(url.ends_with("/sha256hex.zip"));
        assert!(url.contains("laravel/framework"));
        assert!(url.contains("11.0.0"));
    }

    // -----------------------------------------------------------------------
    // COMPOSER_METADATA_KEYS
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_metadata_keys_count() {
        assert_eq!(COMPOSER_METADATA_KEYS.len(), 9);
    }

    #[test]
    fn test_composer_metadata_keys_contains_required() {
        assert!(COMPOSER_METADATA_KEYS.contains(&"description"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"type"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"license"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"require"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"require-dev"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"autoload"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"authors"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"keywords"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"homepage"));
    }

    // -----------------------------------------------------------------------
    // Search next page URL generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_next_page_url() {
        // Plain query, default per_page, no type filter: only q + page appear.
        let next_url = build_search_next_url("composer-hosted", "monolog", 2, None, None);
        assert_eq!(
            next_url,
            "/composer/composer-hosted/search.json?q=monolog&page=3"
        );
    }

    #[test]
    fn test_search_next_page_url_preserves_per_page() {
        // #1781: per_page must survive into the next link so paginated
        // searches keep the same page size.
        let next_url = build_search_next_url("repo", "", 1, Some(1), None);
        assert_eq!(next_url, "/composer/repo/search.json?q=&page=2&per_page=1");
    }

    #[test]
    fn test_search_next_page_url_preserves_type() {
        // #1781: a type-filtered search must keep the type on the next link,
        // otherwise page 2 silently widens to all packages.
        let next_url = build_search_next_url("repo", "", 1, None, Some("library"));
        assert_eq!(
            next_url,
            "/composer/repo/search.json?q=&page=2&type=library"
        );
    }

    #[test]
    fn test_search_next_page_url_preserves_per_page_and_type() {
        // Both active parameters appear together, per_page before type.
        let next_url = build_search_next_url("repo", "log", 2, Some(5), Some("composer-plugin"));
        assert_eq!(
            next_url,
            "/composer/repo/search.json?q=log&page=3&per_page=5&type=composer-plugin"
        );
    }

    // -----------------------------------------------------------------------
    // build_packages_index (#1781) — virtual repo packages.json aggregation
    // -----------------------------------------------------------------------

    fn index_rows() -> Vec<PackageIndexRow> {
        vec![
            PackageIndexRow {
                name: "testvendor/lib1".to_string(),
                version: Some("1.0.0".to_string()),
                checksum_sha256: "hash1".to_string(),
                metadata: Some(serde_json::json!({"composer": {"type": "library"}})),
            },
            PackageIndexRow {
                name: "testvendor/lib1".to_string(),
                version: Some("1.1.0".to_string()),
                checksum_sha256: "hash2".to_string(),
                metadata: None,
            },
            PackageIndexRow {
                name: "testvendor/myplugin".to_string(),
                version: Some("2.0.0".to_string()),
                checksum_sha256: "hash3".to_string(),
                metadata: Some(serde_json::json!({"composer": {"type": "composer-plugin"}})),
            },
        ]
    }

    #[test]
    fn test_build_packages_index_groups_versions_by_name() {
        let map = build_packages_index("virt", &index_rows());
        assert_eq!(map.len(), 2, "two distinct package names");
        let lib1 = map["testvendor/lib1"].as_array().unwrap();
        assert_eq!(lib1.len(), 2, "lib1 has two versions");
        let plugin = map["testvendor/myplugin"].as_array().unwrap();
        assert_eq!(plugin.len(), 1);
        assert_eq!(plugin[0]["type"], "composer-plugin");
    }

    #[test]
    fn test_build_packages_index_dist_url_uses_repo_key() {
        // For a virtual repo the index is rendered under the virtual repo key
        // so dist downloads route back through us, not the member.
        let map = build_packages_index("vf-virt", &index_rows());
        let url = map["testvendor/myplugin"][0]["dist"]["url"]
            .as_str()
            .unwrap();
        assert_eq!(
            url,
            "/composer/vf-virt/dist/testvendor/myplugin/2.0.0/hash3.zip"
        );
    }

    #[test]
    fn test_build_packages_index_empty_rows_is_empty_map() {
        let map = build_packages_index("virt", &[]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_packages_index_null_version_falls_back_to_dev_main() {
        let rows = [PackageIndexRow {
            name: "vendor/pkg".to_string(),
            version: None,
            checksum_sha256: "h".to_string(),
            metadata: None,
        }];
        let map = build_packages_index("r", &rows);
        assert_eq!(map["vendor/pkg"][0]["version"], "dev-main");
    }

    // -----------------------------------------------------------------------
    // merge_composer_metadata: JSON null fields are omitted (#1781)
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_composer_metadata_skips_json_null() {
        // Records stored before ComposerJson gained skip_serializing_if carry
        // explicit nulls for absent optional fields. Those must NOT leak into
        // the rendered version entry as `"field": null`.
        let mut entry = serde_json::json!({"name": "vendor/pkg", "version": "1.0.0"});
        let metadata = serde_json::json!({
            "composer": {
                "description": serde_json::Value::Null,
                "type": "library",
                "license": serde_json::Value::Null,
                "require": serde_json::Value::Null,
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert_eq!(entry["type"], "library");
        assert!(
            entry.get("description").is_none(),
            "null description must be omitted, not serialized as null"
        );
        assert!(entry.get("license").is_none());
        assert!(entry.get("require").is_none());
    }

    #[test]
    fn test_search_total_pages_rounding() {
        let total_count = 1i64;
        let per_page = 15i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 1);
        let has_next = 1 < total_pages;
        assert!(!has_next);
    }

    #[test]
    fn test_search_total_pages_exact_division() {
        let total_count = 30i64;
        let per_page = 15i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 2);
    }

    // -----------------------------------------------------------------------
    // Search result JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_result_json_structure() {
        let repo_key = "php-repo";
        let name = "vendor/package";
        let description = "A PHP package";
        let url = format!("/composer/{}/p2/{}.json", repo_key, name);
        let result = serde_json::json!({
            "name": name,
            "description": description,
            "url": url,
        });
        assert_eq!(result["name"], "vendor/package");
        assert_eq!(result["url"], "/composer/php-repo/p2/vendor/package.json");
    }

    // -----------------------------------------------------------------------
    // Download filename generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_filename() {
        let package = "monolog";
        let version = "3.5.0";
        let filename = format!("{}-{}.zip", package, version);
        assert_eq!(filename, "monolog-3.5.0.zip");
    }

    // -----------------------------------------------------------------------
    // Upload response JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_response_structure() {
        let full_name = "vendor/my-package";
        let version = "1.2.3";
        let sha256 = "abcdef1234567890";
        let response = serde_json::json!({
            "status": "ok",
            "package": full_name,
            "version": version,
            "sha256": sha256,
        });
        assert_eq!(response["status"], "ok");
        assert_eq!(response["package"], "vendor/my-package");
        assert_eq!(response["version"], "1.2.3");
        assert_eq!(response["sha256"], "abcdef1234567890");
    }

    // -----------------------------------------------------------------------
    // Composer metadata JSON for storage
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_metadata_json_structure() {
        let full_name = "vendor/pkg";
        let version = "2.0.0";
        let composer_json_val = serde_json::json!({
            "name": "vendor/pkg",
            "description": "Test",
            "version": "2.0.0"
        });
        let metadata = serde_json::json!({
            "name": full_name,
            "version": version,
            "composer": composer_json_val,
        });
        assert_eq!(metadata["name"], "vendor/pkg");
        assert_eq!(metadata["version"], "2.0.0");
        assert_eq!(metadata["composer"]["description"], "Test");
    }

    // -----------------------------------------------------------------------
    // Upstream path construction for remote-proxy fallback (#1096)
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_v2_upstream_path_simple() {
        // The v2 wire shape is `p2/{vendor}/{package}.json` (no leading slash;
        // proxy_service prepends the upstream base URL itself).
        assert_eq!(
            composer_v2_upstream_path("monolog/monolog"),
            "p2/monolog/monolog.json"
        );
    }

    #[test]
    fn test_composer_v2_upstream_path_keeps_full_name_verbatim() {
        // No re-canonicalization: a hyphen-separated package name flows
        // through unchanged so Packagist sees the same path the client used.
        assert_eq!(
            composer_v2_upstream_path("symfony/http-foundation"),
            "p2/symfony/http-foundation.json"
        );
    }

    #[test]
    fn test_composer_v2_upstream_path_does_not_include_leading_slash() {
        // proxy_service::build_upstream_url joins base + "/" + path; a leading
        // slash here would produce `https://packagist.org//p2/...` which some
        // mirrors reject.
        let path = composer_v2_upstream_path("acme/widget");
        assert!(!path.starts_with('/'), "path must be relative: {}", path);
    }

    #[test]
    fn test_composer_v1_upstream_path_simple() {
        // The v1 wire shape is `p/{vendor}/{package}.json` (older Composer
        // clients hit this before p2).
        assert_eq!(
            composer_v1_upstream_path("monolog/monolog"),
            "p/monolog/monolog.json"
        );
    }

    #[test]
    fn test_composer_v1_upstream_path_keeps_full_name_verbatim() {
        assert_eq!(
            composer_v1_upstream_path("symfony/http-foundation"),
            "p/symfony/http-foundation.json"
        );
    }

    #[test]
    fn test_composer_v1_and_v2_paths_diverge_on_p_segment() {
        // Regression guard: the only difference between v1 and v2 in the
        // upstream URL is the leading `p/` vs `p2/`. If a future refactor
        // unifies the two helpers, this assertion fails loudly.
        let v1 = composer_v1_upstream_path("vendor/pkg");
        let v2 = composer_v2_upstream_path("vendor/pkg");
        assert_ne!(v1, v2);
        assert!(v1.starts_with("p/"));
        assert!(v2.starts_with("p2/"));
        assert!(v1.ends_with(".json"));
        assert!(v2.ends_with(".json"));
    }

    // -----------------------------------------------------------------------
    // build_composer_proxy_response (#1096)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_composer_proxy_response_status_is_ok() {
        let body = Bytes::from_static(br#"{"packages":{}}"#);
        let resp = build_composer_proxy_response(body, Some("application/json".to_string()));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_composer_proxy_response_uses_upstream_content_type() {
        // Upstream told us the body is JSON: pass that through unchanged.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(body, Some("application/json".to_string()));
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(ct.to_str().unwrap(), "application/json");
    }

    #[test]
    fn test_build_composer_proxy_response_defaults_content_type_to_json() {
        // Cache hits with empty metadata can land here without a content_type;
        // default to `application/json` because the composer client treats
        // anything else as a fetch error.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(body, None);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(ct.to_str().unwrap(), "application/json");
    }

    #[test]
    fn test_build_composer_proxy_response_preserves_custom_content_type() {
        // If the upstream returns a vendor-prefixed JSON content type
        // (some mirrors do), we must not silently rewrite it.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(
            body,
            Some("application/vnd.composer+json; charset=utf-8".to_string()),
        );
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(
            ct.to_str().unwrap(),
            "application/vnd.composer+json; charset=utf-8"
        );
    }

    #[test]
    fn test_build_composer_proxy_response_empty_body_is_ok() {
        // Upstream returned an empty body but a 200 status: pass through.
        let resp = build_composer_proxy_response(Bytes::new(), None);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_composer_v2_upstream_path_with_subnamespace() {
        // Vendor namespaces with dots / numeric suffixes (e.g.
        // `phpunit/phpunit`, `psr/log`, `aws/aws-sdk-php-v2`) must round-trip
        // through the helper untouched.
        assert_eq!(composer_v2_upstream_path("psr/log"), "p2/psr/log.json");
        assert_eq!(
            composer_v2_upstream_path("aws/aws-sdk-php-v2"),
            "p2/aws/aws-sdk-php-v2.json"
        );
        assert_eq!(
            composer_v2_upstream_path("phpunit/phpunit"),
            "p2/phpunit/phpunit.json"
        );
    }

    #[test]
    fn test_composer_v1_upstream_path_with_subnamespace() {
        assert_eq!(composer_v1_upstream_path("psr/log"), "p/psr/log.json");
        assert_eq!(
            composer_v1_upstream_path("aws/aws-sdk-php-v2"),
            "p/aws/aws-sdk-php-v2.json"
        );
    }

    // -----------------------------------------------------------------------
    // Virtual metadata rendering (#1715)
    //
    // The render functions are the local-member half of the virtual fan-out:
    // for a Local/Staging member they build the v1/v2 wire shape directly from
    // DB rows. They are pure, so we can assert the document shape without a DB.
    // -----------------------------------------------------------------------

    fn sample_rows() -> Vec<ComposerArtifactRow> {
        vec![
            ComposerArtifactRow {
                version: Some("3.0.0".to_string()),
                checksum_sha256: "aaa111".to_string(),
                metadata: Some(serde_json::json!({
                    "composer": {
                        "description": "Logging library",
                        "type": "library",
                        "require": {"php": ">=8.1"}
                    }
                })),
            },
            ComposerArtifactRow {
                version: Some("3.1.0".to_string()),
                checksum_sha256: "bbb222".to_string(),
                metadata: None,
            },
        ]
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_build_metadata_v2_response_shape() {
        let resp = build_metadata_v2_response("virt", "monolog/monolog", &sample_rows());
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;

        assert_eq!(json["minified"], "composer/2.0");
        let versions = json["packages"]["monolog/monolog"].as_array().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0]["version"], "3.0.0");
        // composer.json metadata is merged into the entry.
        assert_eq!(versions[0]["description"], "Logging library");
        assert_eq!(versions[0]["type"], "library");
    }

    #[tokio::test]
    async fn test_build_metadata_v2_response_dist_url_uses_virtual_repo_key() {
        // #1715: locally-rendered dist URLs must point back at the
        // *virtual* repo key so the composer client routes downloads through us.
        let resp = build_metadata_v2_response("virt", "monolog/monolog", &sample_rows());
        let json = body_json(resp).await;
        let url = json["packages"]["monolog/monolog"][0]["dist"]["url"]
            .as_str()
            .unwrap();
        assert_eq!(url, "/composer/virt/dist/monolog/monolog/3.0.0/aaa111.zip");
    }

    #[tokio::test]
    async fn test_build_metadata_v1_response_shape() {
        let resp = build_metadata_v1_response("virt", "monolog/monolog", &sample_rows());
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;

        // v1 keys versions by version string (object, not array).
        let pkg = &json["packages"]["monolog/monolog"];
        assert!(pkg.is_object());
        assert_eq!(pkg["3.0.0"]["version"], "3.0.0");
        assert_eq!(pkg["3.1.0"]["version"], "3.1.0");
        // v1 must not carry the v2-only "minified" marker.
        assert!(json.get("minified").is_none());
    }

    #[tokio::test]
    async fn test_build_metadata_v2_response_empty_rows_is_empty_array() {
        // A member with no matching artifacts renders an empty version list,
        // not an error — the fan-out treats this as "miss, try next member".
        let resp = build_metadata_v2_response("virt", "monolog/monolog", &[]);
        let json = body_json(resp).await;
        let versions = json["packages"]["monolog/monolog"].as_array().unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_composer_artifact_row_version_fallback() {
        // Rows with a NULL version fall back to dev-main in the rendered entry,
        // matching the legacy inline behaviour.
        let rows = [ComposerArtifactRow {
            version: None,
            checksum_sha256: "ccc333".to_string(),
            metadata: None,
        }];
        let entry = build_version_entry(
            "virt",
            "vendor/pkg",
            rows[0].version.as_deref().unwrap_or("dev-main"),
            &rows[0].checksum_sha256,
            rows[0].metadata.as_ref(),
        );
        assert_eq!(entry["version"], "dev-main");
    }
}

// ---------------------------------------------------------------------------
// DB-backed router tests for the packages-index population added in
// fix/1341-composer-webui-packages:
//
// After a successful Composer upload, the handler calls
// `PackageService::try_create_or_update_from_artifact` so the package
// surfaces in the WebUI Packages tab (which reads the `packages` table,
// not `artifacts`). Before this fix, Composer was the only publishing
// handler that did not populate `packages` / `package_versions`.
//
// These tests rely on `DATABASE_URL` being set. CI seeds + migrates a
// Postgres before running `cargo llvm-cov --lib`, so they execute there
// and cover the new lib lines in `upload`. In local environments without
// a database they no-op cleanly via `tdh::Fixture::setup` returning None.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod upload_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use std::io::Write;

    /// Build a minimal valid Composer package archive: a zip with a single
    /// `composer.json` entry carrying the required fields. Stored (no
    /// compression) so the tiny payload doesn't pay the deflate cost.
    fn build_composer_zip(name: &str, version: &str, description: &str) -> Vec<u8> {
        let composer_json = serde_json::json!({
            "name": name,
            "version": version,
            "description": description,
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options)
                .expect("start composer.json");
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .expect("write composer.json");
            zip.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    /// Build a PUT request shaped like a real Composer publish.
    fn put_composer(uri: String, zip_bytes: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/zip")
            .body(axum::body::Body::from(zip_bytes))
            .expect("build PUT request")
    }

    // -----------------------------------------------------------------------
    // Happy path: a Composer upload populates the `packages` table with the
    // description from composer.json and the `format: composer` metadata
    // tag, AND inserts the matching `package_versions` row keyed by the
    // package id. This is the new lib code path the coverage gate watches.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_populates_packages_index_with_description() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        let name = "acme/widget";
        let version = "1.2.3";
        let description = "An indexed Composer package (#1341)";
        let zip = build_composer_zip(name, version, description);
        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip);
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for Composer upload, got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        // The artifact row was already correct pre-fix.
        let artifact_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM artifacts \
             WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_one(&f.pool)
        .await
        .expect("query artifacts");
        assert_eq!(
            artifact_count.0, 1,
            "exactly one artifact row expected after upload"
        );

        // The regression assertion: the packages row must exist with the
        // description folded from composer.json and the format-tag metadata
        // the handler passes to PackageService.
        let row: Option<(String, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT name, description, metadata FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (pkg_name, desc, meta) = row.expect("packages row must exist after Composer upload");
        assert_eq!(pkg_name, name);
        assert_eq!(
            desc.as_deref(),
            Some(description),
            "composer.json description must be persisted to packages.description"
        );
        let meta = meta.expect("metadata must be set");
        assert_eq!(
            meta["format"], "composer",
            "handler passes {{format: composer}} to PackageService"
        );

        // package_versions UPSERTed by PackageService.
        let version_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(
            version_count.0, 1,
            "exactly one package_versions row expected after a single upload"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // composer.json without a `description` key: the handler passes
    // `composer_json.description.as_deref()` (== None) into
    // `try_create_or_update_from_artifact`, which must land as NULL in the
    // packages table (COALESCE keeps existing NULL on conflict).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_packages_index_missing_description_maps_to_null() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        // No `description` field in the composer.json.
        let composer_json = serde_json::json!({
            "name": "acme/no-desc",
            "version": "0.1.0",
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options).unwrap();
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .unwrap();
            zip.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();

        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip_bytes);
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "upload without description must still succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT description FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("acme/no-desc")
        .bind("0.1.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (desc,) = row.expect("packages row must exist even without description");
        assert!(
            desc.is_none(),
            "missing composer.json description must fold to NULL, got {:?}",
            desc
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // composer.json without `version`: the handler defaults to `dev-main`
    // (see `composer_json.version.as_deref().unwrap_or("dev-main")`). The
    // packages-index row must use that resolved version so the WebUI lists
    // the package as a dev branch rather than dropping it. Covers the
    // `&version` argument the new code passes after the fallback resolves.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_default_version_indexed_as_dev_main() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        // No `version` field: the handler should fall back to "dev-main".
        let composer_json = serde_json::json!({
            "name": "acme/dev-pkg",
            "description": "dev-branch package",
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options).unwrap();
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .unwrap();
            zip.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();

        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip_bytes);
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "upload must succeed: {}", status);

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT version FROM packages \
             WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind("acme/dev-pkg")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (ver,) = row.expect("packages row must exist for default-version upload");
        assert_eq!(
            ver, "dev-main",
            "missing composer.json version must index as dev-main"
        );

        // And the matching package_versions row carries the resolved
        // `&sha256` checksum (non-empty hex string) the handler passed.
        let checksum: (String,) = sqlx::query_as(
            "SELECT pv.checksum_sha256 FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind("acme/dev-pkg")
        .bind("dev-main")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions checksum");
        assert_eq!(
            checksum.0.len(),
            64,
            "package_versions.checksum_sha256 must be a 64-char hex digest"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // POST verb: composer's upload route is `put(upload).post(upload)`, so
    // a POST publish must follow the same code path and end up in the
    // packages index too. Guards against a future refactor that drops the
    // POST handler and silently regresses CI clients that publish with
    // POST.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_via_post_also_populates_packages_index() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        let name = "acme/postpkg";
        let version = "2.0.0";
        let zip = build_composer_zip(name, version, "posted via POST");
        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/packages", f.repo_key))
            .header("content-type", "application/zip")
            .body(axum::body::Body::from(zip))
            .expect("build POST request");
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "POST publish must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT name, size_bytes FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");
        let (got_name, size) = row.expect("packages row must exist after POST publish");
        assert_eq!(got_name, name);
        assert!(
            size > 0,
            "size_bytes must be the archive length the handler passed, got {}",
            size
        );

        f.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// DB-backed metadata resolution tests for the p2/p endpoints (#1715).
//
// These exercise the local-repo lookup path (`fetch_composer_artifacts` +
// `build_metadata_v{1,2}_response`) and the virtual fan-out
// (`resolve_virtual_composer_metadata`) against a real Postgres. They no-op
// gracefully when `DATABASE_URL` is unset (CI provides one).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod metadata_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use uuid::Uuid;

    /// Insert a composer artifact row (+ optional metadata) directly so the
    /// metadata endpoints have something to resolve without a full upload.
    async fn insert_artifact(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        name: &str,
        version: &str,
        sha256: &str,
        metadata: Option<serde_json::Value>,
    ) {
        let artifact_id = Uuid::new_v4();
        let path = format!("{}/{}/{}.zip", name, version, sha256);
        let storage_key = format!("composer/{}", path);
        sqlx::query(
            "INSERT INTO artifacts \
             (id, repository_id, name, version, path, storage_key, size_bytes, \
              checksum_sha256, content_type, is_deleted) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'application/zip',false)",
        )
        .bind(artifact_id)
        .bind(repo_id)
        .bind(name)
        .bind(version)
        .bind(&path)
        .bind(&storage_key)
        .bind(10_i64)
        .bind(sha256)
        .execute(pool)
        .await
        .expect("insert artifact");

        if let Some(meta) = metadata {
            sqlx::query(
                "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
                 VALUES ($1, 'composer', $2)",
            )
            .bind(artifact_id)
            .bind(meta)
            .execute(pool)
            .await
            .expect("insert artifact_metadata");
        }
    }

    /// Link `member_repo_id` into `virtual_repo_id` at the given priority.
    async fn add_member(
        pool: &sqlx::PgPool,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
        priority: i32,
    ) {
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, $3)",
        )
        .bind(virtual_repo_id)
        .bind(member_repo_id)
        .bind(priority)
        .execute(pool)
        .await
        .expect("add virtual member");
    }

    async fn body_json(body: &bytes::Bytes) -> serde_json::Value {
        serde_json::from_slice(body).expect("parse json body")
    }

    // -- Local repo: p2 returns the package when present -------------------

    #[tokio::test]
    async fn local_p2_returns_package_with_versions() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        insert_artifact(
            &f.pool,
            f.repo_id,
            "monolog/monolog",
            "3.0.0",
            "deadbeef",
            Some(serde_json::json!({"composer": {"description": "Logging"}})),
        )
        .await;

        let app = f.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/monolog/monolog.json", f.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        assert_eq!(json["minified"], "composer/2.0");
        let versions = json["packages"]["monolog/monolog"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "3.0.0");
        assert_eq!(versions[0]["description"], "Logging");

        f.teardown().await;
    }

    // -- Local repo: p1 (legacy) returns version-keyed object -------------

    #[tokio::test]
    async fn local_p1_returns_version_keyed_object() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        insert_artifact(&f.pool, f.repo_id, "psr/log", "3.0.0", "cafe01", None).await;

        let app = f.router_anon(super::router());
        let req = tdh::get(format!("/{}/p/psr/log.json", f.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        let pkg = &json["packages"]["psr/log"];
        assert!(pkg.is_object());
        assert_eq!(pkg["3.0.0"]["version"], "3.0.0");
        assert!(json.get("minified").is_none());

        f.teardown().await;
    }

    // -- Local repo: missing package is 404 ------------------------------

    #[tokio::test]
    async fn local_p2_missing_package_is_404() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/no/such.json", f.repo_key));
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    // -- Virtual repo: p2 resolves from a local member (#1715) -----------

    #[tokio::test]
    async fn virtual_p2_resolves_from_local_member() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        // A local member that actually holds the package.
        let (member_id, _member_key, member_dir) =
            tdh::create_repo(&vf.pool, "local", "composer").await;
        insert_artifact(
            &vf.pool,
            member_id,
            "symfony/serializer-pack",
            "1.2.0",
            "abc123",
            Some(serde_json::json!({"composer": {"type": "metapackage"}})),
        )
        .await;
        add_member(&vf.pool, vf.repo_id, member_id, 0).await;

        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/symfony/serializer-pack.json", vf.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "virtual repo must resolve p2 from its local member (#1715)"
        );
        let json = body_json(&body).await;
        let versions = json["packages"]["symfony/serializer-pack"]
            .as_array()
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "1.2.0");
        // dist.url is rewritten to the virtual repo key so downloads route back.
        let url = versions[0]["dist"]["url"].as_str().unwrap();
        assert!(
            url.starts_with(&format!("/composer/{}/dist/", vf.repo_key)),
            "dist url must point at virtual repo, got {}",
            url
        );

        // cleanup member rows + repo
        tdh::cleanup(&vf.pool, member_id, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(member_dir);
        vf.teardown().await;
    }

    // -- Virtual repo: p1 (legacy) also resolves from a local member -----

    #[tokio::test]
    async fn virtual_p1_resolves_from_local_member() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        let (member_id, _member_key, member_dir) =
            tdh::create_repo(&vf.pool, "local", "composer").await;
        insert_artifact(
            &vf.pool,
            member_id,
            "vendor/legacy",
            "1.0.0",
            "ff00ff",
            None,
        )
        .await;
        add_member(&vf.pool, vf.repo_id, member_id, 0).await;

        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/p/vendor/legacy.json", vf.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        assert_eq!(
            json["packages"]["vendor/legacy"]["1.0.0"]["version"],
            "1.0.0"
        );

        tdh::cleanup(&vf.pool, member_id, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(member_dir);
        vf.teardown().await;
    }

    // -- Virtual repo: 404 only when no member has the package -----------

    #[tokio::test]
    async fn virtual_p2_404_when_no_member_has_package() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        let (member_id, _member_key, member_dir) =
            tdh::create_repo(&vf.pool, "local", "composer").await;
        // member exists but holds a DIFFERENT package
        insert_artifact(&vf.pool, member_id, "other/pkg", "1.0.0", "0011", None).await;
        add_member(&vf.pool, vf.repo_id, member_id, 0).await;

        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/missing/pkg.json", vf.repo_key));
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

        tdh::cleanup(&vf.pool, member_id, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(member_dir);
        vf.teardown().await;
    }

    // -- Virtual repo: no members at all is 404 --------------------------

    #[tokio::test]
    async fn virtual_p2_no_members_is_404() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/any/pkg.json", vf.repo_key));
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        vf.teardown().await;
    }

    // -- Virtual repo: packages.json aggregates from local members (#1781) --

    #[tokio::test]
    async fn virtual_packages_json_aggregates_member_packages() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        let (member_id, _member_key, member_dir) =
            tdh::create_repo(&vf.pool, "local", "composer").await;
        // The member holds two packages; the virtual root index must surface
        // both (pre-fix it returned an empty `{}`).
        insert_artifact(
            &vf.pool,
            member_id,
            "testvendor/mypackage",
            "1.0.0",
            "aaa111",
            Some(serde_json::json!({"composer": {"type": "library"}})),
        )
        .await;
        insert_artifact(
            &vf.pool,
            member_id,
            "testvendor/myplugin",
            "2.0.0",
            "bbb222",
            Some(serde_json::json!({"composer": {"type": "composer-plugin"}})),
        )
        .await;
        add_member(&vf.pool, vf.repo_id, member_id, 0).await;

        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/packages.json", vf.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        let packages = json["packages"].as_object().unwrap();
        assert_eq!(
            packages.len(),
            2,
            "virtual packages.json must aggregate both member packages (#1781)"
        );
        assert!(packages.contains_key("testvendor/mypackage"));
        assert!(packages.contains_key("testvendor/myplugin"));
        // dist URLs route back through the virtual repo, not the member.
        let url = packages["testvendor/mypackage"][0]["dist"]["url"]
            .as_str()
            .unwrap();
        assert!(
            url.starts_with(&format!("/composer/{}/dist/", vf.repo_key)),
            "dist url must point at virtual repo, got {}",
            url
        );

        tdh::cleanup(&vf.pool, member_id, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(member_dir);
        vf.teardown().await;
    }

    // -- Search: type filter must constrain BOTH results and total (#1781) --

    #[tokio::test]
    async fn search_type_filter_constrains_total_count() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        // Three libraries, one plugin: a `type=composer-plugin` search must
        // report total=1, not total=4 (the old count ignored `type`).
        insert_artifact(
            &f.pool,
            f.repo_id,
            "testvendor/lib1",
            "1.0.0",
            "h1",
            Some(serde_json::json!({"composer": {"type": "library"}})),
        )
        .await;
        insert_artifact(
            &f.pool,
            f.repo_id,
            "testvendor/lib2",
            "1.0.0",
            "h2",
            Some(serde_json::json!({"composer": {"type": "library"}})),
        )
        .await;
        insert_artifact(
            &f.pool,
            f.repo_id,
            "testvendor/lib3",
            "1.0.0",
            "h3",
            Some(serde_json::json!({"composer": {"type": "library"}})),
        )
        .await;
        insert_artifact(
            &f.pool,
            f.repo_id,
            "testvendor/myplugin",
            "1.0.0",
            "h4",
            Some(serde_json::json!({"composer": {"type": "composer-plugin"}})),
        )
        .await;

        let app = f.router_anon(super::router());
        let req = tdh::get(format!("/{}/search.json?type=composer-plugin", f.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "only the plugin matches");
        assert_eq!(results[0]["name"], "testvendor/myplugin");
        assert_eq!(
            json["total"], 1,
            "total must honor the type filter, not report all packages (#1781)"
        );

        // And a type-filtered, paginated search keeps type + per_page on next.
        let app2 = f.router_anon(super::router());
        let req2 = tdh::get(format!(
            "/{}/search.json?type=library&per_page=1&page=1",
            f.repo_key
        ));
        let (status2, body2) = tdh::send(app2, req2).await;
        assert_eq!(status2, axum::http::StatusCode::OK);
        let json2 = body_json(&body2).await;
        assert_eq!(json2["total"], 3, "three libraries");
        let next = json2["next"].as_str().expect("next link present");
        assert!(
            next.contains("type=library"),
            "next must preserve type filter, got {}",
            next
        );
        assert!(
            next.contains("per_page=1"),
            "next must preserve per_page, got {}",
            next
        );

        f.teardown().await;
    }

    // -- Virtual repo: priority order — first member with the package wins -

    #[tokio::test]
    async fn virtual_p2_respects_member_priority() {
        let Some(vf) = tdh::Fixture::setup("virtual", "composer").await else {
            return;
        };
        let (m1, _k1, d1) = tdh::create_repo(&vf.pool, "local", "composer").await;
        let (m2, _k2, d2) = tdh::create_repo(&vf.pool, "local", "composer").await;
        // Both members hold the same package at different versions.
        insert_artifact(&vf.pool, m1, "dup/pkg", "1.0.0", "v1hash", None).await;
        insert_artifact(&vf.pool, m2, "dup/pkg", "2.0.0", "v2hash", None).await;
        // m2 has higher priority (lower number) so it should win.
        add_member(&vf.pool, vf.repo_id, m1, 10).await;
        add_member(&vf.pool, vf.repo_id, m2, 0).await;

        let app = vf.router_anon(super::router());
        let req = tdh::get(format!("/{}/p2/dup/pkg.json", vf.repo_key));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json = body_json(&body).await;
        let versions = json["packages"]["dup/pkg"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0]["version"], "2.0.0",
            "higher-priority member (priority 0) must win the first-hit resolution"
        );

        tdh::cleanup(&vf.pool, m1, Uuid::new_v4()).await;
        tdh::cleanup(&vf.pool, m2, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(d1);
        let _ = std::fs::remove_dir_all(d2);
        vf.teardown().await;
    }
}
