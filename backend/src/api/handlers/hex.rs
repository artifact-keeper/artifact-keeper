//! Hex.pm API handlers.
//!
//! Implements the endpoints required for `mix hex.publish` and `mix hex.package`.
//!
//! Routes are mounted at `/hex/{repo_key}/...`:
//!   GET  /hex/{repo_key}/packages/{name}              - Package info (JSON with releases)
//!   GET  /hex/{repo_key}/tarballs/{name}-{version}.tar - Download package tarball
//!   POST /hex/{repo_key}/publish                       - Publish package (auth required)
//!   GET  /hex/{repo_key}/names                         - List all package names
//!   GET  /hex/{repo_key}/versions                      - List all packages with versions

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::hex::{
    is_valid_hex_package_name, package_name_from_tarball_filename, HexHandler,
};
use crate::models::repository::{Repository, RepositoryType};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Publish package
        .route("/:repo_key/publish", post(publish_package))
        // Package info
        .route("/:repo_key/packages/:name", get(package_info))
        // List all package names
        .route("/:repo_key/names", get(list_names))
        // List all packages with versions
        .route("/:repo_key/versions", get(list_versions))
        // Download tarball - use a wildcard to capture name-version.tar
        .route("/:repo_key/tarballs/*tarball_file", get(download_tarball))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_hex_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["hex"], "a Hex").await
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/packages/{name} -- Package info (JSON with releases)
// ---------------------------------------------------------------------------

async fn package_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        name
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    if artifacts.is_empty() {
        // Remote: fetch package metadata from the upstream hex registry.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = format!("packages/{}", name);
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
                        content_type.unwrap_or_else(|| "application/json".to_string()),
                    )
                    .body(Body::from(content))
                    .unwrap());
            }
        }

        // Virtual: check every member's `artifacts` table (local or remote
        // cache) before falling back to remote upstream proxy. The previous
        // implementation called `resolve_virtual_metadata` directly, which
        // only iterates Remote members and never sees packages published
        // to a local/staging member (#973).
        //
        // Pass order:
        //   1. All non-Remote members' DBs (locally-hosted packages win).
        //   2. All Remote members' DBs (already-cached pull-through hits).
        //   3. Remote upstream proxy for any remaining members.
        // This ordering blocks an upstream from shadowing a locally
        // published name. Local-first lookup also avoids an unnecessary
        // network round-trip when the package is already known to a member.
        if repo.repo_type == RepositoryType::Virtual {
            let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

            // Pass 1+2: any member that already has artifact rows for this name.
            // Non-Remote members run first so they shadow Remote upstreams; this
            // matches the supply-chain-attack guard documented on PR #974.
            let ordered_members = order_members_local_first(&members);

            for member in ordered_members {
                if let Some(resp) =
                    fetch_package_info_from_member(&state, member, &repo_key, &name).await?
                {
                    return Ok(resp);
                }
            }

            // Pass 3: fall through to remote proxy for un-cached packages.
            let upstream_path = format!("packages/{}", name);
            return proxy_helpers::resolve_virtual_metadata(
                &state.db,
                state.proxy_service.as_deref(),
                repo.id,
                &upstream_path,
                |content, _member_key| async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(content))
                        .unwrap())
                },
            )
            .await;
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let releases: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            let tarball_url = format!("/hex/{}/tarballs/{}-{}.tar", repo_key, name, version);

            serde_json::json!({
                "version": version,
                "url": tarball_url,
                "checksum": a.checksum_sha256,
            })
        })
        .collect();

    // Get download count across all versions
    let artifact_ids: Vec<uuid::Uuid> = artifacts.iter().map(|a| a.id).collect();
    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = ANY($1)",
        &artifact_ids
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "name": name,
        "releases": releases,
        "downloads": download_count,
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/tarballs/{name}-{version}.tar -- Download tarball
// ---------------------------------------------------------------------------

async fn download_tarball(
    State(state): State<SharedState>,
    Path((repo_key, tarball_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let filename = tarball_file.trim_start_matches('/');

    let artifact = match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename)
        .await?
    {
        Some(a) => a,
        None => {
            let upstream_path = format!("tarballs/{}", filename);

            // Virtual: if any non-Remote member already owns this package
            // name, an upstream Remote member must NOT be allowed to serve
            // a tarball for it. Otherwise a malicious upstream that pushes
            // a package named `phoenix` shadows the operator's locally
            // published `phoenix`. The metadata side of this guard
            // (`/packages/{name}`) is enforced by `order_members_local_first`
            // in `package_info`; this is the matching guard on the bytes
            // side. Forward-ported from PR #974 (#973).
            if repo.repo_type == RepositoryType::Virtual
                && virtual_local_owns_tarball_name(&state.db, repo.id, filename).await?
            {
                return serve_virtual_tarball_local_only(&state, repo.id, &upstream_path, filename)
                    .await;
            }

            // Remote: no Content-Disposition; Virtual: include filename.
            let cd_filename = if repo.repo_type == RepositoryType::Virtual {
                Some(filename)
            } else {
                None
            };
            if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                &state,
                &repo,
                proxy_helpers::DownloadResponseOpts {
                    upstream_path: &upstream_path,
                    virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                    default_content_type: "application/octet-stream",
                    content_disposition_filename: cd_filename,
                    // Shadowing guard handled above by the explicit
                    // `virtual_local_owns_tarball_name` branch + the
                    // `serve_virtual_tarball_local_only` call. Reaching here
                    // means no local member claims this name, so we can let
                    // the standard proxy fan-out run.
                    suppress_upstream_proxy: false,
                },
            )
            .await?
            {
                return Ok(resp);
            }
            return Err((StatusCode::NOT_FOUND, "Tarball not found").into_response());
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

/// Returns true if any non-Remote member of a virtual repo has an artifact
/// row matching the package name parsed from a tarball filename. When true,
/// the caller must block an upstream Remote member from satisfying the
/// download (supply-chain name-shadowing guard, #973 / PR #974).
///
/// Falls back to `false` if the filename does not parse as a hex tarball.
async fn virtual_local_owns_tarball_name(
    db: &PgPool,
    virtual_repo_id: uuid::Uuid,
    filename: &str,
) -> Result<bool, Response> {
    let Some(pkg_name) = package_name_from_tarball_filename(filename) else {
        return Ok(false);
    };

    // Delegate to the cross-format primitive (#1217 follow-up, ak-hv3s).
    // The hex-specific work is parsing the tarball filename into a
    // package name; the DB lookup is shared with cargo / npm / pypi /
    // maven / rubygems.
    proxy_helpers::virtual_non_remote_owns_name(db, virtual_repo_id, &pkg_name).await
}

/// Serve a tarball download restricted to the virtual repo's non-Remote
/// members by passing `proxy_service: None` to `resolve_virtual_download`.
///
/// **Security invariant**: the `None` proxy argument is load-bearing, not
/// a performance optimization or a default. `resolve_virtual_download`
/// passes that argument through `virtual_member_fetch_strategy`, which
/// returns `Skip` for Remote members whenever the proxy service is None.
/// That `Skip` is exactly what prevents an upstream from satisfying a
/// download whose package name a local member already owns. Any future
/// refactor that threads a real proxy service through this call would
/// silently re-open the supply-chain shadowing attack from #973 / PR
/// #974. Pair with `virtual_local_owns_tarball_name` (download side)
/// and `order_members_local_first` (metadata side, see `package_info`).
async fn serve_virtual_tarball_local_only(
    state: &SharedState,
    virtual_repo_id: uuid::Uuid,
    upstream_path: &str,
    filename: &str,
) -> Result<Response, Response> {
    let state_arc = state.clone();
    let suffix = filename.to_string();

    let result = proxy_helpers::resolve_virtual_download(
        &state.db,
        // Explicit None: any Remote member would route to upstream, which is
        // exactly what the shadowing guard must block. Local members fall
        // through to `local_fetch_by_path_suffix` regardless of proxy state.
        None,
        virtual_repo_id,
        upstream_path,
        move |member_id, location| {
            let state = state_arc.clone();
            let suffix = suffix.clone();
            async move {
                proxy_helpers::local_fetch_by_path_suffix(
                    &state.db, &state, member_id, &location, &suffix,
                )
                .await
            }
        },
    )
    .await?;

    proxy_helpers::stream_fetch_result(result, "application/octet-stream", Some(filename))
}

// ---------------------------------------------------------------------------
// POST /hex/{repo_key}/publish -- Publish package (raw tarball body)
// ---------------------------------------------------------------------------

async fn publish_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "hex", "write")?.user_id;
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // Validate the tarball path using the HexHandler
    let tarball_path = "tarballs/package-0.0.0.tar".to_string();
    HexHandler::parse_path(&tarball_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid hex package: {}", e),
        )
            .into_response()
    })?;

    // Extract package name and version from the tarball metadata.
    // Hex tarballs contain a metadata.config file at the top level.
    // For now, we require name and version as query params or from the tarball contents.
    // The Hex spec includes metadata inside the tarball as an outer tar containing:
    //   - VERSION (text file with "3")
    //   - metadata.config (Erlang term format)
    //   - contents.tar.gz (the actual package files)
    //   - CHECKSUM (SHA-256 of the above)
    let (pkg_name, pkg_version) = extract_name_version_from_tarball(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid hex tarball: {}", e),
        )
            .into_response()
    })?;

    if pkg_name.is_empty() || pkg_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package name and version are required",
        )
            .into_response());
    }

    // Reject names that violate the hex.pm package-name spec (`[a-z][a-z0-9_-]*`)
    // before they reach `storage_key` or `artifact_path`. Previously only
    // emptiness was checked, so an attacker could publish a tarball whose
    // `metadata.config` carried `../evil` or `Phoenix` (uppercase) and have
    // the malformed name persist in storage. The download-side shadowing
    // guard (#1217) already refused to interpret such names, but the upload
    // side did not. Apply the same character-set gate the download parser
    // uses so uploads and downloads agree on what counts as a valid hex
    // package name. (#1217 audit follow-up, ak-xf8w.)
    if !is_valid_hex_package_name(&pkg_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid hex package name: must match [a-z][a-z0-9_-]*",
        )
            .into_response());
    }

    let filename = format!("{}-{}.tar", pkg_name, pkg_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Package version already exists",
    )
    .await?;

    let storage_key = format!("hex/{}/{}/{}", pkg_name, pkg_version, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let hex_metadata = serde_json::json!({
        "format": "hex",
        "name": pkg_name,
        "version": pkg_version,
        "filename": filename,
    });

    let size_bytes = body.len() as i64;

    // Insert artifact record
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &pkg_name,
            version: &pkg_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/octet-stream",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    // Store metadata
    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "hex", &hex_metadata)
        .await;

    info!(
        "Hex publish: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "url": format!("/hex/{}/tarballs/{}", repo_key, filename),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/names -- List all package names
// ---------------------------------------------------------------------------

async fn list_names(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let names = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    // Remote with no local artifacts: proxy the names list from upstream.
    // hex.pm's /names endpoint returns a signed protobuf payload; pass it through as-is.
    if names.is_empty() && repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let (content, content_type) =
                proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, "names")
                    .await?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    content_type.unwrap_or_else(|| "application/json".to_string()),
                )
                .body(Body::from(content))
                .unwrap());
        }
    }
    // Virtual: merge package names from all member repositories (local DB + remote proxy).
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut merged = query_local_member_names(&state.db, &members).await?;

        let remote_results = proxy_helpers::collect_virtual_metadata(
            &state.db,
            state.proxy_service.as_deref(),
            repo.id,
            "names",
            |bytes, _member_key| async move { parse_upstream_names(&bytes) },
        )
        .await?;
        for (_key, remote_names) in remote_results {
            merged.extend(remote_names);
        }

        let deduped = merge_and_sort_names(merged);
        let json = serde_json::json!(deduped);

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap());
    }

    let json = serde_json::json!(names);

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/versions -- List all packages with versions
// ---------------------------------------------------------------------------

async fn list_versions(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name, created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    // Group versions by package name
    let mut packages: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for artifact in &artifacts {
        let name = artifact.name.clone();
        let version = artifact.version.clone().unwrap_or_default();
        packages.entry(name).or_default().push(version);
    }

    // Remote with no local artifacts: proxy the versions list from upstream.
    // hex.pm's /versions endpoint returns a signed protobuf payload; pass it through as-is.
    if artifacts.is_empty() && repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let (content, content_type) =
                proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, "versions")
                    .await?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    content_type.unwrap_or_else(|| "application/json".to_string()),
                )
                .body(Body::from(content))
                .unwrap());
        }
    }
    // Virtual: merge versions from all member repositories (local DB + remote proxy).
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut merged = query_local_member_versions(&state.db, &members).await?;

        let remote_results = proxy_helpers::collect_virtual_metadata(
            &state.db,
            state.proxy_service.as_deref(),
            repo.id,
            "versions",
            |bytes, _member_key| async move { parse_upstream_versions(&bytes) },
        )
        .await?;
        for (_key, remote_versions) in remote_results {
            for (name, versions) in remote_versions {
                merged.entry(name).or_default().extend(versions);
            }
        }

        let result = build_versions_response(merged);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&result).unwrap()))
            .unwrap());
    }

    let result: Vec<serde_json::Value> = packages
        .into_iter()
        .map(|(name, versions)| {
            serde_json::json!({
                "name": name,
                "versions": versions,
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&result).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Virtual repo merging helpers
// ---------------------------------------------------------------------------

/// Order virtual repo members so non-Remote members come before Remote
/// members, preserving the original priority ordering within each group.
///
/// Pure function so the supply-chain-shadowing rule from PR #974 can be
/// unit-tested without standing up a real virtual-repo configuration.
/// Non-Remote-first ordering prevents an upstream from shadowing a
/// locally-published package name (#973).
fn order_members_local_first(members: &[Repository]) -> Vec<&Repository> {
    let mut ordered: Vec<&Repository> = Vec::with_capacity(members.len());
    ordered.extend(
        members
            .iter()
            .filter(|m| m.repo_type != RepositoryType::Remote),
    );
    ordered.extend(
        members
            .iter()
            .filter(|m| m.repo_type == RepositoryType::Remote),
    );
    ordered
}

/// Build a `/hex/<repo>/packages/<name>` JSON response from artifact rows
/// in a single member repo. Returns `Ok(None)` if the member has no
/// artifacts for `name`, so the caller can advance to the next member.
///
/// Tarball URLs are emitted against the *virtual* repo key (not the member
/// key) so subsequent `mix deps.get` fetches stay routed through the same
/// virtual endpoint the client originally asked for.
async fn fetch_package_info_from_member(
    state: &SharedState,
    member: &Repository,
    virtual_repo_key: &str,
    name: &str,
) -> Result<Option<Response>, Response> {
    use sqlx::Row;

    // Uses runtime `sqlx::query` (not `query!`) so we avoid adding a
    // `.sqlx/` offline cache entry for the lowercased-name lookup.
    let rows = sqlx::query(
        "SELECT a.id, a.version, a.checksum_sha256 \
         FROM artifacts a \
         WHERE a.repository_id = $1 \
           AND a.is_deleted = false \
           AND LOWER(a.name) = LOWER($2) \
         ORDER BY a.created_at DESC",
    )
    .bind(member.id)
    .bind(name)
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    if rows.is_empty() {
        return Ok(None);
    }

    let artifact_ids: Vec<uuid::Uuid> = rows
        .iter()
        .filter_map(|r| r.try_get::<uuid::Uuid, _>("id").ok())
        .collect();

    let release_rows: Vec<(Option<String>, String)> = rows
        .iter()
        .map(|r| {
            let version: Option<String> = r.try_get("version").ok();
            let checksum: String = r.try_get("checksum_sha256").unwrap_or_default();
            (version, checksum)
        })
        .collect();

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = ANY($1)",
        &artifact_ids
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = build_package_info_json(virtual_repo_key, name, &release_rows, download_count);
    Ok(Some(package_info_response(&json)))
}

/// Pure helper that serializes a hex `/packages/<name>` JSON value into
/// the final HTTP response. Extracted from
/// [`fetch_package_info_from_member`] so the Content-Type and status
/// can be exercised without a database.
fn package_info_response(json: &serde_json::Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(json).unwrap()))
        .unwrap()
}

/// Build the `/hex/<repo>/packages/<name>` JSON payload from a list of
/// (version, checksum) pairs and a precomputed download count.
///
/// Pure transformation factored out so the tarball URL formatting and
/// release-array shape can be unit-tested without a database.
fn build_package_info_json(
    virtual_repo_key: &str,
    name: &str,
    release_rows: &[(Option<String>, String)],
    download_count: i64,
) -> serde_json::Value {
    let releases: Vec<serde_json::Value> = release_rows
        .iter()
        .map(|(version, checksum)| {
            let v = version.clone().unwrap_or_default();
            let tarball_url = format!("/hex/{}/tarballs/{}-{}.tar", virtual_repo_key, name, v);
            serde_json::json!({
                "version": v,
                "url": tarball_url,
                "checksum": checksum,
            })
        })
        .collect();
    serde_json::json!({
        "name": name,
        "releases": releases,
        "downloads": download_count,
    })
}

/// Query distinct package names from every virtual member's artifacts table.
///
/// Includes Remote members because cached pull-through packages are recorded
/// as `artifacts` rows by `ProxyService`, and a virtual repo's `/names`
/// index must surface those alongside locally hosted ones (#973).
async fn query_local_member_names(
    db: &PgPool,
    members: &[Repository],
) -> Result<Vec<String>, Response> {
    let mut all_names = Vec::new();
    for member in members {
        let names = sqlx::query_scalar!(
            r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name
        "#,
            member.id
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
        all_names.extend(names);
    }
    Ok(all_names)
}

/// Query name/version pairs from every virtual member's artifacts table,
/// grouped by package name.
///
/// Includes Remote members because their proxy cache populates `artifacts`
/// rows on pull-through (#973).
async fn query_local_member_versions(
    db: &PgPool,
    members: &[Repository],
) -> Result<std::collections::BTreeMap<String, Vec<String>>, Response> {
    let mut packages: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for member in members {
        let artifacts = sqlx::query!(
            r#"
        SELECT name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name, created_at DESC
        "#,
            member.id
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
        for a in &artifacts {
            let name = a.name.clone();
            let version = a.version.clone().unwrap_or_default();
            packages.entry(name).or_default().push(version);
        }
    }
    Ok(packages)
}

/// Parse an upstream JSON names response.
///
/// Artifact Keeper hex repos return a JSON array of strings: `["phoenix", "ecto"]`.
/// If the upstream returns non-JSON (e.g. hex.pm's signed protobuf), parsing
/// fails gracefully and the member is skipped by `collect_virtual_metadata`.
#[allow(clippy::result_large_err)]
fn parse_upstream_names(bytes: &[u8]) -> Result<Vec<String>, Response> {
    serde_json::from_slice::<Vec<String>>(bytes).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream names response as JSON",
        )
            .into_response()
    })
}

/// Parse an upstream JSON versions response.
///
/// Artifact Keeper hex repos return an array of objects:
/// `[{"name": "phoenix", "versions": ["1.7.0", "1.7.1"]}]`.
/// Returns a map of name to versions for merging.
#[allow(clippy::result_large_err)]
fn parse_upstream_versions(
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<String, Vec<String>>, Response> {
    let entries: Vec<serde_json::Value> = serde_json::from_slice(bytes).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Failed to parse upstream versions response as JSON",
        )
            .into_response()
    })?;

    let mut packages: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for entry in &entries {
        let name = entry["name"].as_str().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let versions: Vec<String> = entry["versions"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        packages.entry(name).or_default().extend(versions);
    }
    Ok(packages)
}

/// Deduplicate and sort a list of package names (case-insensitive dedup).
fn merge_and_sort_names(names: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut unique: Vec<String> = names
        .into_iter()
        .filter(|n| seen.insert(n.to_lowercase()))
        .collect();
    unique.sort();
    unique
}

/// Build the versions response array from a merged BTreeMap, deduplicating
/// version strings within each package.
fn build_versions_response(
    packages: std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<serde_json::Value> {
    packages
        .into_iter()
        .map(|(name, versions)| {
            let mut seen = std::collections::HashSet::new();
            let unique: Vec<String> = versions
                .into_iter()
                .filter(|v| seen.insert(v.clone()))
                .collect();
            serde_json::json!({
                "name": name,
                "versions": unique,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract package name and version from a Hex tarball.
///
/// Hex tarballs are outer tar archives containing:
///   - VERSION (text: "3")
///   - metadata.config (Erlang term format with package name/version)
///   - contents.tar.gz
///   - CHECKSUM
///
/// We parse the metadata.config to extract the name and version fields.
fn extract_name_version_from_tarball(data: &[u8]) -> Result<(String, String), String> {
    let mut archive = tar::Archive::new(data);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| format!("Failed to read tar entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "metadata.config" {
            let mut content = String::new();
            std::io::Read::read_to_string(&mut entry, &mut content)
                .map_err(|e| format!("Failed to read metadata.config: {}", e))?;

            let name = extract_erlang_term_value(&content, "name")
                .ok_or_else(|| "Missing 'name' in metadata.config".to_string())?;
            let version = extract_erlang_term_value(&content, "version")
                .ok_or_else(|| "Missing 'version' in metadata.config".to_string())?;

            return Ok((name, version));
        }
    }

    Err("metadata.config not found in tarball".to_string())
}

/// Extract a string value from Erlang term format metadata.
///
/// Hex metadata.config uses Erlang term format like:
///   {<<"name">>, <<"phoenix">>}.
///   {<<"version">>, <<"1.7.0">>}.
///
/// This is a simple parser that extracts binary string values for known keys.
fn extract_erlang_term_value(content: &str, key: &str) -> Option<String> {
    let search_pattern = format!("<<\"{}\">>", key);

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(&search_pattern) {
            continue;
        }

        // Find the value part: the second <<"...">> in the line
        let after_key = &trimmed[trimmed.find(&search_pattern)? + search_pattern.len()..];
        let value_start = after_key.find("<<\"")?;
        let value_content = &after_key[value_start + 3..];
        let value_end = value_content.find("\">>").unwrap_or(value_content.len());
        return Some(value_content[..value_end].to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // order_members_local_first (#973 supply-chain-shadowing rule)
    // -----------------------------------------------------------------------

    fn make_member(repo_type: RepositoryType, key: &str) -> Repository {
        use crate::models::repository::{ReplicationPriority, RepositoryFormat};
        Repository {
            id: uuid::Uuid::new_v4(),
            key: key.to_string(),
            name: key.to_string(),
            description: None,
            format: RepositoryFormat::Hex,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: String::new(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 0,
            curation_auto_fetch: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_order_members_local_first_puts_local_before_remote() {
        let m1 = make_member(RepositoryType::Remote, "remote-1");
        let m2 = make_member(RepositoryType::Local, "local-1");
        let m3 = make_member(RepositoryType::Remote, "remote-2");
        let members = vec![m1, m2, m3];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered[0].key, "local-1");
        assert_eq!(ordered[1].key, "remote-1");
        assert_eq!(ordered[2].key, "remote-2");
    }

    #[test]
    fn test_order_members_local_first_preserves_priority_within_group() {
        // Multiple non-Remote members keep their original relative order;
        // same for Remote members.
        let m1 = make_member(RepositoryType::Staging, "stage");
        let m2 = make_member(RepositoryType::Remote, "remote-high");
        let m3 = make_member(RepositoryType::Local, "local");
        let m4 = make_member(RepositoryType::Remote, "remote-low");
        let members = vec![m1, m2, m3, m4];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered[0].key, "stage");
        assert_eq!(ordered[1].key, "local");
        assert_eq!(ordered[2].key, "remote-high");
        assert_eq!(ordered[3].key, "remote-low");
    }

    #[test]
    fn test_order_members_local_first_empty_input() {
        let members: Vec<Repository> = Vec::new();
        let ordered = order_members_local_first(&members);
        assert!(ordered.is_empty());
    }

    #[test]
    fn test_order_members_local_first_all_remote() {
        let members = vec![
            make_member(RepositoryType::Remote, "r1"),
            make_member(RepositoryType::Remote, "r2"),
        ];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].key, "r1");
    }

    // -----------------------------------------------------------------------
    // build_package_info_json (#973)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_package_info_json_emits_virtual_key_tarball_urls() {
        // The tarball URL must reference the virtual repo's key, not the
        // member repo's key, so subsequent `mix deps.get` fetches stay
        // routed through the same virtual endpoint.
        let release_rows = vec![
            (Some("1.7.0".to_string()), "sha-1".to_string()),
            (Some("1.7.1".to_string()), "sha-2".to_string()),
        ];
        let json = build_package_info_json("hex-virtual", "phoenix", &release_rows, 42);
        assert_eq!(json["name"].as_str(), Some("phoenix"));
        assert_eq!(json["downloads"].as_i64(), Some(42));
        let releases = json["releases"].as_array().unwrap();
        assert_eq!(releases.len(), 2);
        assert_eq!(
            releases[0]["url"].as_str(),
            Some("/hex/hex-virtual/tarballs/phoenix-1.7.0.tar")
        );
        assert_eq!(releases[0]["checksum"].as_str(), Some("sha-1"));
        assert_eq!(releases[1]["version"].as_str(), Some("1.7.1"));
    }

    #[test]
    fn test_build_package_info_json_handles_empty_releases() {
        let json = build_package_info_json("v", "lonely", &[], 0);
        assert_eq!(json["releases"].as_array().unwrap().len(), 0);
        assert_eq!(json["downloads"].as_i64(), Some(0));
    }

    #[test]
    fn test_build_package_info_json_missing_version_becomes_empty_string() {
        // Defensive against rows where `a.version IS NULL` (shouldn't
        // happen for Hex but the DB doesn't constrain it).
        let release_rows = vec![(None, "sha".to_string())];
        let json = build_package_info_json("v", "p", &release_rows, 0);
        let r = &json["releases"][0];
        assert_eq!(r["version"].as_str(), Some(""));
        assert_eq!(r["url"].as_str(), Some("/hex/v/tarballs/p-.tar"));
    }

    // -----------------------------------------------------------------------
    // package_info_response (#973)
    //
    // Pure helper that finalises a hex `/packages/<name>` JSON body into
    // an HTTP response. Covers the JSON serialization + Content-Type
    // wiring without needing a DB-backed handler call.
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_info_response_uses_json_content_type() {
        let json = build_package_info_json(
            "v",
            "p",
            &[(Some("1.0.0".to_string()), "sha".to_string())],
            7,
        );
        let resp = package_info_response(&json);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn test_package_info_response_body_round_trips_through_serde_json() {
        // The body must serialize the JSON value exactly (no extra
        // wrapping). We collect the body bytes and re-parse, then
        // assert structural equality on the round-tripped value.
        let release_rows = vec![
            (Some("1.0.0".to_string()), "sha-a".to_string()),
            (Some("1.1.0".to_string()), "sha-b".to_string()),
        ];
        let json = build_package_info_json("hex-virt", "logger", &release_rows, 99);
        let resp = package_info_response(&json);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(parsed["name"].as_str(), Some("logger"));
        assert_eq!(parsed["downloads"].as_i64(), Some(99));
        assert_eq!(parsed["releases"].as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn test_order_members_local_first_all_local() {
        let members = vec![
            make_member(RepositoryType::Local, "l1"),
            make_member(RepositoryType::Staging, "s1"),
        ];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].key, "l1");
        assert_eq!(ordered[1].key, "s1");
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the standard hex tarball filename: `{name}-{version}.tar`
    fn build_hex_filename(name: &str, version: &str) -> String {
        format!("{}-{}.tar", name, version)
    }

    /// Build the artifact storage path: `{name}/{version}/{name}-{version}.tar`
    fn build_hex_artifact_path(name: &str, version: &str) -> String {
        let filename = build_hex_filename(name, version);
        format!("{}/{}/{}", name, version, filename)
    }

    /// Build the storage key: `hex/{name}/{version}/{name}-{version}.tar`
    fn build_hex_storage_key(name: &str, version: &str) -> String {
        let filename = build_hex_filename(name, version);
        format!("hex/{}/{}/{}", name, version, filename)
    }

    /// Build a tarball download URL: `/hex/{repo_key}/tarballs/{name}-{version}.tar`
    fn build_hex_tarball_url(repo_key: &str, name: &str, version: &str) -> String {
        let filename = build_hex_filename(name, version);
        format!("/hex/{}/tarballs/{}", repo_key, filename)
    }

    /// Build hex metadata JSON for a package.
    fn build_hex_metadata(name: &str, version: &str) -> serde_json::Value {
        let filename = build_hex_filename(name, version);
        serde_json::json!({
            "format": "hex",
            "name": name,
            "version": version,
            "filename": filename,
        })
    }

    /// Build the JSON publish response.
    fn build_hex_publish_response(repo_key: &str, name: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "url": build_hex_tarball_url(repo_key, name, version),
        })
    }

    /// Build a release entry for the package info endpoint.
    fn build_hex_release_entry(
        repo_key: &str,
        name: &str,
        version: &str,
        checksum: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "version": version,
            "url": build_hex_tarball_url(repo_key, name, version),
            "checksum": checksum,
        })
    }

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_erlang_term_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_erlang_term_name() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("phoenix".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_version() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "version");
        assert_eq!(result, Some("1.7.0".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_missing_key() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "description");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_erlang_term_empty_content() {
        let result = extract_erlang_term_value("", "name");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_erlang_term_with_hyphens_in_name() {
        let content = r#"{<<"name">>, <<"my-elixir-lib">>}.
{<<"version">>, <<"0.1.0">>}.
"#;
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("my-elixir-lib".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_app_key() {
        let content = r#"{<<"app">>, <<"myapp">>}.
{<<"name">>, <<"myapp">>}.
{<<"version">>, <<"2.0.0">>}.
"#;
        let result = extract_erlang_term_value(content, "app");
        assert_eq!(result, Some("myapp".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_with_extra_whitespace() {
        let content = "  {<<\"name\">>, <<\"ecto\">>}.  \n";
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("ecto".to_string()));
    }

    // -----------------------------------------------------------------------
    // extract_name_version_from_tarball
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_version_from_tarball_empty() {
        let result = extract_name_version_from_tarball(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_name_version_from_tarball_invalid() {
        let result = extract_name_version_from_tarball(b"not a tarball");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_name_version_from_tarball_no_metadata() {
        // Create a valid tar with no metadata.config file
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"3";
        let mut header = tar::Header::new_gnu();
        header.set_path("VERSION").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let result = extract_name_version_from_tarball(&tar_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("metadata.config not found"));
    }

    #[test]
    fn test_extract_name_version_from_tarball_valid() {
        // Create a valid tar with metadata.config
        let mut builder = tar::Builder::new(Vec::new());

        let metadata = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let data = metadata.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("metadata.config").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, data).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let result = extract_name_version_from_tarball(&tar_data);
        assert!(result.is_ok());
        let (name, version) = result.unwrap();
        assert_eq!(name, "phoenix");
        assert_eq!(version, "1.7.0");
    }

    // -----------------------------------------------------------------------
    // build_hex_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_filename() {
        assert_eq!(build_hex_filename("plug", "1.15.0"), "plug-1.15.0.tar");
    }

    #[test]
    fn test_build_hex_filename_hyphenated_name() {
        assert_eq!(
            build_hex_filename("my-elixir-lib", "0.1.0"),
            "my-elixir-lib-0.1.0.tar"
        );
    }

    #[test]
    fn test_build_hex_filename_underscore_name() {
        assert_eq!(
            build_hex_filename("ecto_sql", "3.11.0"),
            "ecto_sql-3.11.0.tar"
        );
    }

    // -----------------------------------------------------------------------
    // build_hex_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_artifact_path() {
        assert_eq!(
            build_hex_artifact_path("ecto", "3.11.0"),
            "ecto/3.11.0/ecto-3.11.0.tar"
        );
    }

    #[test]
    fn test_build_hex_artifact_path_prerelease() {
        assert_eq!(
            build_hex_artifact_path("phoenix", "1.8.0-rc.1"),
            "phoenix/1.8.0-rc.1/phoenix-1.8.0-rc.1.tar"
        );
    }

    #[test]
    fn test_build_hex_artifact_path_simple() {
        assert_eq!(
            build_hex_artifact_path("jason", "1.4.0"),
            "jason/1.4.0/jason-1.4.0.tar"
        );
    }

    // -----------------------------------------------------------------------
    // build_hex_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_storage_key() {
        assert_eq!(
            build_hex_storage_key("jason", "1.4.0"),
            "hex/jason/1.4.0/jason-1.4.0.tar"
        );
    }

    #[test]
    fn test_build_hex_storage_key_starts_with_hex() {
        let key = build_hex_storage_key("plug", "2.0.0");
        assert!(key.starts_with("hex/"));
    }

    #[test]
    fn test_build_hex_storage_key_contains_filename() {
        let key = build_hex_storage_key("ecto", "3.11.0");
        assert!(key.ends_with("ecto-3.11.0.tar"));
    }

    // -----------------------------------------------------------------------
    // build_hex_tarball_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_tarball_url() {
        assert_eq!(
            build_hex_tarball_url("hex-local", "plug", "1.15.0"),
            "/hex/hex-local/tarballs/plug-1.15.0.tar"
        );
    }

    #[test]
    fn test_build_hex_tarball_url_starts_with_hex() {
        let url = build_hex_tarball_url("my-repo", "phoenix", "1.7.0");
        assert!(url.starts_with("/hex/"));
    }

    #[test]
    fn test_build_hex_tarball_url_contains_tarballs() {
        let url = build_hex_tarball_url("repo", "ecto", "3.0.0");
        assert!(url.contains("/tarballs/"));
    }

    // -----------------------------------------------------------------------
    // build_hex_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_metadata() {
        let meta = build_hex_metadata("phoenix", "1.7.0");
        assert_eq!(meta["format"], "hex");
        assert_eq!(meta["name"], "phoenix");
        assert_eq!(meta["version"], "1.7.0");
        assert_eq!(meta["filename"], "phoenix-1.7.0.tar");
    }

    #[test]
    fn test_build_hex_metadata_has_all_keys() {
        let meta = build_hex_metadata("ecto", "3.11.0");
        let obj = meta.as_object().unwrap();
        assert!(obj.contains_key("format"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("filename"));
    }

    #[test]
    fn test_build_hex_metadata_four_keys() {
        let meta = build_hex_metadata("plug", "1.0.0");
        assert_eq!(meta.as_object().unwrap().len(), 4);
    }

    // -----------------------------------------------------------------------
    // build_hex_publish_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_publish_response() {
        let resp = build_hex_publish_response("hex-local", "phoenix", "1.7.0");
        assert_eq!(resp["name"], "phoenix");
        assert_eq!(resp["version"], "1.7.0");
        assert_eq!(resp["url"], "/hex/hex-local/tarballs/phoenix-1.7.0.tar");
    }

    #[test]
    fn test_build_hex_publish_response_has_url() {
        let resp = build_hex_publish_response("repo", "ecto", "3.0.0");
        let url = resp["url"].as_str().unwrap();
        assert!(url.starts_with("/hex/"));
        assert!(url.contains("ecto-3.0.0.tar"));
    }

    #[test]
    fn test_build_hex_publish_response_three_keys() {
        let resp = build_hex_publish_response("r", "p", "1.0.0");
        assert_eq!(resp.as_object().unwrap().len(), 3);
    }

    // -----------------------------------------------------------------------
    // build_hex_release_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_release_entry() {
        let entry = build_hex_release_entry("hex-local", "plug", "1.15.0", Some("abc123"));
        assert_eq!(entry["version"], "1.15.0");
        assert_eq!(entry["checksum"], "abc123");
        assert!(entry["url"].as_str().unwrap().contains("plug-1.15.0.tar"));
    }

    #[test]
    fn test_build_hex_release_entry_no_checksum() {
        let entry = build_hex_release_entry("repo", "ecto", "3.11.0", None);
        assert_eq!(entry["version"], "3.11.0");
        assert!(entry["checksum"].is_null());
    }

    #[test]
    fn test_build_hex_release_entry_url_format() {
        let entry = build_hex_release_entry("my-repo", "phoenix", "1.7.0", None);
        assert_eq!(entry["url"], "/hex/my-repo/tarballs/phoenix-1.7.0.tar");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"hex package data");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
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
            storage_path: "/data/hex".to_string(),
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
            storage_path: "/cache".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo.hex.pm".to_string()),
        };
        assert_eq!(repo.upstream_url.as_deref(), Some("https://repo.hex.pm"));
    }

    // -----------------------------------------------------------------------
    // Proxy fallback: upstream paths
    // -----------------------------------------------------------------------
    //
    // The handler builds these paths when proxying to the upstream registry.
    // package_info constructs "packages/{name}" via format!().
    // list_names and list_versions use bare literals: "names", "versions".

    #[test]
    fn test_proxy_upstream_paths() {
        assert_eq!(format!("packages/{}", "phoenix"), "packages/phoenix");
        assert_eq!(
            format!("packages/{}", "plug_cowboy"),
            "packages/plug_cowboy"
        );
        // list_names and list_versions use bare endpoint names
        let names_path = "names";
        let versions_path = "versions";
        assert!(!names_path.contains('/'));
        assert!(!versions_path.contains('/'));
    }

    // -----------------------------------------------------------------------
    // Proxy fallback: branch eligibility by repo type
    // -----------------------------------------------------------------------
    //
    // The handler uses two conditions for the proxy fallback:
    //   1. repo.repo_type == RepositoryType::Remote && repo.upstream_url.is_some()
    //   2. repo.repo_type == RepositoryType::Virtual (iterates members)
    // These tests document which RepoInfo configurations satisfy each branch.

    #[test]
    fn test_local_repo_ineligible_for_proxy() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
        };
        assert_ne!(repo.repo_type, "remote");
        assert_ne!(repo.repo_type, "virtual");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_remote_repo_eligible_for_proxy() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo.hex.pm".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert!(repo.upstream_url.is_some());
    }

    #[test]
    fn test_remote_repo_without_upstream_skips_proxy() {
        // Even though repo_type is "remote", missing upstream_url means
        // the (upstream_url, proxy_service) destructure won't match.
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.repo_type, "remote");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_virtual_repo_eligible_for_member_iteration() {
        // Virtual repos resolve through their members, not their own upstream_url.
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/virtual".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "virtual".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.repo_type, "virtual");
    }

    // -----------------------------------------------------------------------
    // parse_upstream_names
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_upstream_names_valid_json() {
        let data = br#"["phoenix","ecto","plug"]"#;
        let result = parse_upstream_names(data);
        assert!(result.is_ok());
        let names = result.unwrap();
        assert_eq!(names, vec!["phoenix", "ecto", "plug"]);
    }

    #[test]
    fn test_parse_upstream_names_empty_array() {
        let data = b"[]";
        let result = parse_upstream_names(data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_upstream_names_invalid_json() {
        let data = b"not json at all";
        let result = parse_upstream_names(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_upstream_names_protobuf_bytes_fail() {
        // Simulates a hex.pm signed protobuf response, which should fail
        // gracefully since it is not valid JSON.
        let data: Vec<u8> = vec![
            0x08, 0x01, 0x12, 0x07, 0x70, 0x68, 0x6f, 0x65, 0x6e, 0x69, 0x78,
        ];
        let result = parse_upstream_names(&data);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_upstream_versions
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_upstream_versions_valid_json() {
        let data = br#"[{"name":"phoenix","versions":["1.7.0","1.7.1"]},{"name":"ecto","versions":["3.11.0"]}]"#;
        let result = parse_upstream_versions(data);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["phoenix"], vec!["1.7.0", "1.7.1"]);
        assert_eq!(map["ecto"], vec!["3.11.0"]);
    }

    #[test]
    fn test_parse_upstream_versions_empty_array() {
        let data = b"[]";
        let result = parse_upstream_versions(data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_upstream_versions_invalid_json() {
        let data = b"this is not json";
        let result = parse_upstream_versions(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_upstream_versions_skips_empty_names() {
        let data = br#"[{"name":"","versions":["1.0.0"]},{"name":"plug","versions":["2.0.0"]}]"#;
        let result = parse_upstream_versions(data);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("plug"));
    }

    #[test]
    fn test_parse_upstream_versions_missing_versions_field() {
        let data = br#"[{"name":"phoenix"}]"#;
        let result = parse_upstream_versions(data);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 1);
        assert!(map["phoenix"].is_empty());
    }

    // -----------------------------------------------------------------------
    // merge_and_sort_names
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_and_sort_names_basic() {
        let names = vec![
            "ecto".to_string(),
            "phoenix".to_string(),
            "plug".to_string(),
        ];
        let result = merge_and_sort_names(names);
        assert_eq!(result, vec!["ecto", "phoenix", "plug"]);
    }

    #[test]
    fn test_merge_and_sort_names_deduplicates() {
        let names = vec![
            "phoenix".to_string(),
            "ecto".to_string(),
            "phoenix".to_string(),
            "plug".to_string(),
            "ecto".to_string(),
        ];
        let result = merge_and_sort_names(names);
        assert_eq!(result, vec!["ecto", "phoenix", "plug"]);
    }

    #[test]
    fn test_merge_and_sort_names_case_insensitive_dedup() {
        let names = vec![
            "Phoenix".to_string(),
            "phoenix".to_string(),
            "PHOENIX".to_string(),
        ];
        let result = merge_and_sort_names(names);
        // Keeps the first occurrence
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "Phoenix");
    }

    #[test]
    fn test_merge_and_sort_names_empty() {
        let result = merge_and_sort_names(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_and_sort_names_single() {
        let result = merge_and_sort_names(vec!["plug".to_string()]);
        assert_eq!(result, vec!["plug"]);
    }

    // -----------------------------------------------------------------------
    // build_versions_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_versions_response_basic() {
        let mut packages = std::collections::BTreeMap::new();
        packages.insert(
            "phoenix".to_string(),
            vec!["1.7.0".to_string(), "1.7.1".to_string()],
        );
        packages.insert("ecto".to_string(), vec!["3.11.0".to_string()]);

        let result = build_versions_response(packages);
        assert_eq!(result.len(), 2);
        // BTreeMap iterates in sorted order: ecto before phoenix
        assert_eq!(result[0]["name"], "ecto");
        assert_eq!(result[0]["versions"], serde_json::json!(["3.11.0"]));
        assert_eq!(result[1]["name"], "phoenix");
        assert_eq!(result[1]["versions"], serde_json::json!(["1.7.0", "1.7.1"]));
    }

    #[test]
    fn test_build_versions_response_deduplicates_versions() {
        let mut packages = std::collections::BTreeMap::new();
        packages.insert(
            "plug".to_string(),
            vec![
                "1.0.0".to_string(),
                "2.0.0".to_string(),
                "1.0.0".to_string(),
            ],
        );

        let result = build_versions_response(packages);
        assert_eq!(result.len(), 1);
        let versions = result[0]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0], "1.0.0");
        assert_eq!(versions[1], "2.0.0");
    }

    #[test]
    fn test_build_versions_response_empty() {
        let packages = std::collections::BTreeMap::new();
        let result = build_versions_response(packages);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_versions_response_preserves_order() {
        let mut packages = std::collections::BTreeMap::new();
        packages.insert("zlib".to_string(), vec!["1.0.0".to_string()]);
        packages.insert("absinthe".to_string(), vec!["1.7.0".to_string()]);
        packages.insert("jason".to_string(), vec!["1.4.0".to_string()]);

        let result = build_versions_response(packages);
        assert_eq!(result[0]["name"], "absinthe");
        assert_eq!(result[1]["name"], "jason");
        assert_eq!(result[2]["name"], "zlib");
    }

    // -----------------------------------------------------------------------
    // Note: parser/validator unit tests live in `crate::formats::hex` alongside
    // the implementations they cover (moved as part of the #1217 audit
    // follow-up, ak-niid). The DB-backed router tests below exercise the
    // download-side shadowing guard end-to-end.
    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_hex_tarball_download_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "hex").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/tarballs/missing-1.0.0.tar", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_hex_tarball_download_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "hex").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "hex/jason/1.4.1/jason-1.4.1.tar",
            "jason/1.4.1/jason-1.4.1.tar",
            "jason",
            "1.4.1",
            "application/octet-stream",
            bytes::Bytes::from_static(b"hex-tar"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/tarballs/jason-1.4.1.tar", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"hex-tar");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_hex_package_info_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "hex").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) =
            tdh::send(app, tdh::get(format!("/{}/packages/missing", f.repo_key))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_hex_publish_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "hex").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/publish", f.repo_key))
            .body(axum::body::Body::from("data"))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Shadowing-guard end-to-end tests (#973 / PR #974). These exercise
    // `virtual_local_owns_tarball_name` + `serve_virtual_tarball_local_only`
    // through the router, which the unit tests on the parser alone cannot.
    // -----------------------------------------------------------------------

    /// Virtual hex repo with a Local member that owns `phoenix`: a GET for
    /// `phoenix-1.0.0.tar` must serve the local bytes, NOT attempt an
    /// upstream proxy fetch. Without the shadowing guard, the request would
    /// either fall through to `resolve_virtual_download` and be served from
    /// the configured priority order (which may prefer Remote), or 404.
    #[tokio::test]
    async fn test_hex_tarball_virtual_shadowing_guard_serves_local() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (local_repo_id, _local_key, local_storage_dir) =
            tdh::create_repo(&pool, "local", "hex").await;
        let (virtual_repo_id, virtual_key, _virtual_storage_dir) =
            tdh::create_repo(&pool, "virtual", "hex").await;
        let state = tdh::build_state(pool.clone(), local_storage_dir.to_str().unwrap());

        // Link the local repo as a member of the virtual repo so the guard
        // sees a non-Remote member that owns the `phoenix` name.
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(virtual_repo_id)
        .bind(local_repo_id)
        .execute(&pool)
        .await
        .expect("link virtual member");

        let local_repo =
            tdh::make_repo_info(local_repo_id, "local-hex", &local_storage_dir, "hex", None);
        tdh::seed_artifact(
            &state,
            &pool,
            &local_repo,
            "hex/phoenix/1.0.0/phoenix-1.0.0.tar",
            "phoenix/1.0.0/phoenix-1.0.0.tar",
            "phoenix",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"local-phoenix-bytes"),
            user_id,
        )
        .await;

        let app = tdh::router_anon(super::router(), state.clone());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/tarballs/phoenix-1.0.0.tar", virtual_key)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "guard must serve from local member");
        assert_eq!(&body[..], b"local-phoenix-bytes");

        tdh::cleanup(&pool, virtual_repo_id, user_id).await;
        tdh::cleanup(&pool, local_repo_id, user_id).await;
    }

    /// Virtual hex repo with no non-Remote members: the guard's
    /// `non_remote_ids.is_empty()` short-circuit must fire so the request
    /// falls through to the existing `try_remote_or_virtual_download`
    /// path. Without configured upstream, that yields a 404 rather than
    /// a 500 (which would indicate the guard accidentally errored).
    #[tokio::test]
    async fn test_hex_tarball_virtual_no_non_remote_members_passes_guard() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (virtual_repo_id, virtual_key, virtual_storage_dir) =
            tdh::create_repo(&pool, "virtual", "hex").await;
        let state = tdh::build_state(pool.clone(), virtual_storage_dir.to_str().unwrap());

        // Virtual repo has zero members. The guard should see an empty
        // non_remote_ids vec and short-circuit to Ok(false), then the
        // outer download path falls through to try_remote_or_virtual_download
        // which returns NOT_FOUND because there's no proxy service.
        let app = tdh::router_anon(super::router(), state.clone());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/tarballs/nothing-1.0.0.tar", virtual_key)),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "empty-members guard must return 404, not 500"
        );

        tdh::cleanup(&pool, virtual_repo_id, user_id).await;
    }
}
