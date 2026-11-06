//! Puppet Forge API handlers.
//!
//! Implements the endpoints required for Puppet module management.
//!
//! Routes are mounted at `/puppet/{repo_key}/...`:
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}                  - Module info
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}/releases         - Release list
//!   GET  /puppet/{repo_key}/v3/releases?module={owner}-{name}         - Release list (Forge v3)
//!   GET  /puppet/{repo_key}/v3/releases/{owner}-{name}-{version}       - Release info
//!   GET  /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz   - Download
//!   POST /puppet/{repo_key}/v3/releases                                - Publish module

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, RawQuery, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::puppet::PuppetHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/v3/modules/:owner_name", get(module_info))
        .route(
            "/:repo_key/v3/modules/:owner_name/releases",
            get(release_list),
        )
        .route(
            "/:repo_key/v3/releases/:owner_name_version",
            get(release_info),
        )
        .route("/:repo_key/v3/files/*file_path", get(download_module))
        .route(
            "/:repo_key/v3/releases",
            get(list_releases).post(publish_module),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_puppet_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["puppet"], "a Puppet").await
}

/// Build the `file_uri` advertised in the Forge module/release metadata.
///
/// The URI is relative to the repository's Forge API root, as the Forge's own
/// `/v3/files/...` URIs are: the puppet client appends it to its
/// `--module_repository` URL (`http://host/puppet/{repo}`), so a URI that
/// repeated the `/puppet/{repo}` prefix would be fetched as
/// `/puppet/{repo}/puppet/{repo}/v3/files/...` and 404 (#5229).
///
/// The download route (`GET /puppet/{repo}/v3/files/{file}`) resolves a hosted
/// module by its trailing filename suffix (#2587), so the advertised URI must
/// carry the artifact's actual stored basename. A module published through the
/// native Forge upload is stored at `{owner}-{name}-{version}.tar.gz`,
/// byte-identical to the reconstructed filename; one pushed through the generic
/// upload flow is stored at its bare path with generically-derived coordinates,
/// so reconstructing the canonical filename would advertise a path the download
/// route cannot resolve (the Puppet analogue of the RPM `<location>` fix,
/// #2587 / #2589).
fn release_file_uri(path: &str, owner: &str, name: &str, version: &str) -> String {
    let filename = proxy_helpers::advertised_download_filename(
        path,
        &format!("{}-{}-{}.tar.gz", owner, name, version),
    );
    format!("/v3/files/{}", filename)
}

/// The Forge `metadata` object of a release: the module's `metadata.json`.
///
/// A native publish stores the uploaded module JSON under `module_json`; that
/// is the document the Forge serves. The puppet client builds each release
/// from `metadata.name` and `metadata.version` and rejects one without them,
/// so both are always set from the stored coordinates, and `dependencies`
/// defaults to empty for a module stored without one (a generic upload).
fn forge_release_metadata(
    stored: Option<&serde_json::Value>,
    owner: &str,
    name: &str,
    version: &str,
) -> serde_json::Value {
    let mut meta = stored
        .and_then(|m| m.get("module_json"))
        .filter(|m| m.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    meta["name"] = serde_json::json!(format!("{}-{}", owner, name));
    meta["version"] = serde_json::json!(version);
    if !meta.get("dependencies").is_some_and(|d| d.is_array()) {
        meta["dependencies"] = serde_json::json!([]);
    }
    meta
}

/// One release in the Forge v3 release shape (`GET /v3/releases`).
fn forge_release_json(
    owner: &str,
    name: &str,
    artifact: &proxy_helpers::ArtifactWithMetadata,
) -> serde_json::Value {
    let version = artifact.version.clone().unwrap_or_default();
    let slug = format!("{}-{}-{}", owner, name, version);
    serde_json::json!({
        "uri": format!("/v3/releases/{}", slug),
        "slug": slug,
        "version": version,
        "module": {
            "uri": format!("/v3/modules/{}-{}", owner, name),
            "slug": format!("{}-{}", owner, name),
            "name": name,
            "deprecated_at": null,
            "owner": { "slug": owner, "username": owner },
        },
        "metadata": forge_release_metadata(artifact.metadata.as_ref(), owner, name, &version),
        "file_uri": release_file_uri(&artifact.path, owner, name, &version),
        "file_size": artifact.size_bytes,
        "file_sha256": artifact.checksum_sha256,
    })
}

/// Parse an "owner-name" string into (owner, name) by splitting on the first hyphen.
#[allow(clippy::result_large_err)]
fn parse_owner_name(s: &str) -> Result<(String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid module identifier '{}': expected owner-name", s),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let name = s[first_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Owner and name must not be empty").into_response());
    }

    Ok((owner, name))
}

/// Parse an "owner-name-version" string into (owner, name, version).
#[allow(clippy::result_large_err)]
fn parse_owner_name_version(s: &str) -> Result<(String, String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let remainder = &s[first_hyphen + 1..];

    let last_hyphen = remainder.rfind('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let name = remainder[..last_hyphen].to_string();
    let version = remainder[last_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version must not be empty",
        )
            .into_response());
    }

    Ok((owner, name, version))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name} — Module info
// ---------------------------------------------------------------------------

async fn module_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;

    // Validate via format handler
    let validate_path = format!("v3/modules/{}-{}", owner, name);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let artifact = proxy_helpers::find_artifact_by_name_lowercase(
        &state.db,
        repo.id,
        &format!("{}-{}", owner, name),
    )
    .await?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Module not found").into_response())?;

    let current_version = artifact.version.clone().unwrap_or_default();

    let json = serde_json::json!({
        "slug": format!("{}-{}", owner, name),
        "name": name,
        "owner": { "slug": owner, "username": owner },
        "current_release": {
            "version": current_version,
            "slug": format!("{}-{}-{}", owner, name, current_version),
            "file_uri": release_file_uri(&artifact.path, &owner, &name, &current_version),
        },
        "releases": [],
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name}/releases — Release list
// ---------------------------------------------------------------------------

async fn release_list(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;
    let releases = hosted_releases(&state.db, repo.id, &owner, &name).await?;
    let query = ReleasesQuery::default();
    Ok(super::json_response(&paginate_releases(
        releases, &query, &owner, &name,
    )))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/releases?module={owner}-{name} — Release list
// ---------------------------------------------------------------------------

/// Default and maximum page size of the Forge v3 list endpoints.
const FORGE_DEFAULT_LIMIT: usize = 20;
const FORGE_MAX_LIMIT: usize = 100;

/// Release fields a Virtual repository never asks its Remote members for.
///
/// They hold each release's rendered README, CHANGELOG, LICENSE and
/// REFERENCE, which nothing resolving or installing a module reads. A page
/// of [`FORGE_MAX_LIMIT`] `puppetlabs-stdlib` releases with them is larger
/// than the proxy's metadata ceiling, so the merge failed with 502.
const VIRTUAL_UPSTREAM_EXCLUDED_FIELDS: &str = "readme,changelog,license,reference";

/// The `GET /v3/releases` query parameters this handler honours.
///
/// `puppet module install` sends `module`, `sort_by=version`,
/// `exclude_fields` and, when configured, `module_groups`. The other Forge
/// filters (`module_groups`, `with_pdk`, `operatingsystem`,
/// `puppet_requirement`, ...) are accepted and ignored: they narrow the Forge
/// catalog by attributes a private repository does not track.
#[derive(Debug, Default, Deserialize)]
struct ReleasesQuery {
    module: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    sort_by: Option<String>,
    exclude_fields: Option<String>,
}

/// The Forge list query string for one page, relative to the API root.
fn releases_page_uri(
    owner: &str,
    name: &str,
    limit: usize,
    offset: usize,
    q: &ReleasesQuery,
) -> String {
    let mut uri = format!(
        "/v3/releases?module={}&limit={}&offset={}",
        urlencoding::encode(&format!("{}-{}", owner, name)),
        limit,
        offset
    );
    if let Some(sort_by) = &q.sort_by {
        uri.push_str(&format!("&sort_by={}", urlencoding::encode(sort_by)));
    }
    if let Some(fields) = &q.exclude_fields {
        uri.push_str(&format!("&exclude_fields={}", urlencoding::encode(fields)));
    }
    uri
}

/// Order, page and wrap `releases` in the Forge `{pagination, results}`
/// envelope.
///
/// `releases` arrive newest-published first. `sort_by=version` (what the
/// puppet client asks for, and the default here) orders them by descending
/// SemVer; a version that is not SemVer sorts after every one that is.
/// `pagination.next` is relative to the API root, like the Forge's, because
/// the client appends it to its `--module_repository` URL to fetch the next
/// page, and stops at `null`.
fn paginate_releases(
    mut releases: Vec<serde_json::Value>,
    q: &ReleasesQuery,
    owner: &str,
    name: &str,
) -> serde_json::Value {
    if q.sort_by.as_deref().unwrap_or("version") == "version" {
        let key = |r: &serde_json::Value| {
            r.get("version")
                .and_then(|v| v.as_str())
                .and_then(|v| semver::Version::parse(v).ok())
        };
        releases.sort_by_key(|r| std::cmp::Reverse(key(r)));
    }
    let excluded: Vec<&str> = q
        .exclude_fields
        .as_deref()
        .unwrap_or("")
        .split([',', ' '])
        .filter(|f| !f.is_empty())
        .collect();

    let total = releases.len();
    let limit = q
        .limit
        .unwrap_or(FORGE_DEFAULT_LIMIT)
        .clamp(1, FORGE_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let results: Vec<serde_json::Value> = releases
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|mut r| {
            if let Some(obj) = r.as_object_mut() {
                for field in &excluded {
                    obj.remove(*field);
                }
            }
            r
        })
        .collect();
    let page = |off: usize| releases_page_uri(owner, name, limit, off, q);
    let next = (offset + limit < total).then(|| page(offset + limit));
    let previous = (offset > 0).then(|| page(offset.saturating_sub(limit)));

    serde_json::json!({
        "pagination": {
            "limit": limit,
            "offset": offset,
            "first": page(0),
            "previous": previous,
            "current": page(offset),
            "next": next,
            "total": total,
        },
        "results": results,
    })
}

/// Every stored release of `owner-name` in one hosted repository, newest
/// published first, in the Forge release shape.
async fn hosted_releases(
    db: &PgPool,
    repo_id: uuid::Uuid,
    owner: &str,
    name: &str,
) -> Result<Vec<serde_json::Value>, Response> {
    let artifacts = proxy_helpers::list_artifacts_by_name_lowercase(
        db,
        repo_id,
        &format!("{}-{}", owner, name),
    )
    .await?;
    Ok(artifacts
        .iter()
        .map(|a| forge_release_json(owner, name, a))
        .collect())
}

/// The `results` of an upstream Forge release list.
#[allow(clippy::result_large_err)]
fn upstream_release_results(bytes: &[u8]) -> Result<Vec<serde_json::Value>, Response> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|doc| doc.get("results").and_then(|r| r.as_array()).cloned())
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "Upstream Forge release list has no results array",
            )
                .into_response()
        })
}

/// Keep the first release of each version: virtual members are walked in
/// priority order with hosted members first, so a locally published version
/// shadows the same version upstream.
fn dedup_releases_by_version(releases: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    releases
        .into_iter()
        .filter(|r| {
            let version = r.get("version").and_then(|v| v.as_str()).unwrap_or("");
            seen.insert(version.to_string())
        })
        .collect()
}

/// `GET /v3/releases?module={owner}-{name}`: the endpoint `puppet module
/// install` resolves a module through (#5229).
///
/// * Hosted: the module's stored releases, paged in the Forge shape.
/// * Remote: the upstream Forge's answer to the same query, forwarded as-is.
///   Its `file_uri` and `pagination.next` are relative to the Forge API root,
///   which is this repository's root, so the client downloads and pages
///   through this repository.
/// * Virtual: the hosted members' releases merged with the first
///   [`FORGE_MAX_LIMIT`] releases of each Remote member, one entry per
///   version (hosted first), paged here.
async fn list_releases(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<ReleasesQuery>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;

    if repo.repo_type == RepositoryType::Remote {
        let (Some(upstream_url), Some(proxy)) = (&repo.upstream_url, &state.proxy_service) else {
            return Err(
                (StatusCode::NOT_FOUND, "Remote repository has no upstream").into_response()
            );
        };
        let path = match raw_query.as_deref() {
            Some(q) if !q.is_empty() => format!("v3/releases?{}", q),
            _ => "v3/releases".to_string(),
        };
        let proxy_helpers::CachedBody {
            content,
            content_type,
            content_encoding,
            stale_since,
        } = proxy_helpers::proxy_fetch_capped_encoded(
            proxy,
            repo.id,
            &repo_key,
            upstream_url,
            &path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await?;
        return Ok(proxy_helpers::forward_verbatim_metadata(
            content,
            content_type,
            "application/json",
            content_encoding,
            stale_since,
        ));
    }

    let module = query.module.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "The module query parameter is required (module=<owner>-<name>)",
        )
            .into_response()
    })?;
    let (owner, name) = parse_owner_name(&module.replace('/', "-"))?;

    if repo.repo_type != RepositoryType::Virtual {
        let releases = hosted_releases(&state.db, repo.id, &owner, &name).await?;
        return Ok(super::json_response(&paginate_releases(
            releases, &query, &owner, &name,
        )));
    }

    let members =
        proxy_helpers::authorized_virtual_members(&state.db, auth.as_ref(), repo.id).await?;
    let mut releases = Vec::new();
    for member in members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
    {
        releases.extend(hosted_releases(&state.db, member.id, &owner, &name).await?);
    }
    let upstream_path = format!(
        "v3/releases?module={}&limit={}&sort_by=version&exclude_fields={}",
        urlencoding::encode(&format!("{}-{}", owner, name)),
        FORGE_MAX_LIMIT,
        VIRTUAL_UPSTREAM_EXCLUDED_FIELDS
    );
    let remote = proxy_helpers::collect_virtual_metadata(
        &state.db,
        auth.as_ref(),
        state.proxy_service.as_deref(),
        repo.id,
        &upstream_path,
        |bytes, _member_key| async move { upstream_release_results(&bytes) },
    )
    .await?;
    for (_key, results) in remote.documents {
        releases.extend(results);
    }
    let releases = dedup_releases_by_version(releases);
    let mut response = super::json_response(&paginate_releases(releases, &query, &owner, &name));
    remote.partial.mark(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/releases/{owner}-{name}-{version} — Release info
// ---------------------------------------------------------------------------

async fn release_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name_version)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name, version) = parse_owner_name_version(&owner_name_version)?;

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, name, version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let module_name = format!("{}-{}", owner, name);
    let artifact =
        proxy_helpers::find_artifact_by_name_version(&state.db, repo.id, &module_name, &version)
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Release not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, name, version),
        "version": version,
        "module": {
            "slug": format!("{}-{}", owner, name),
            "name": name,
            "owner": { "slug": owner, "username": owner },
        },
        "file_uri": release_file_uri(&artifact.path, &owner, &name, &version),
        "file_size": artifact.size_bytes,
        "file_sha256": artifact.checksum_sha256,
        "downloads": download_count,
        "metadata": forge_release_metadata(artifact.metadata.as_ref(), &owner, &name, &version),
    });

    Ok(super::json_response(&json))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz — Download
// ---------------------------------------------------------------------------

async fn download_module(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, file_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;

    let filename = file_path.trim_start_matches('/');

    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("v3/files/{}", filename);
                // Remote: no Content-Disposition; Virtual: include filename.
                let (default_ct, cd_filename) = if repo.repo_type == RepositoryType::Virtual {
                    ("application/gzip", Some(filename))
                } else {
                    ("application/octet-stream", None)
                };
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    auth.as_ref(),
                    &repo,
                    &ctx,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                        default_content_type: default_ct,
                        content_disposition_filename: cd_filename,
                        suppress_upstream_proxy: false,
                    },
                )
                .await?
                {
                    return Ok(resp);
                }
                return Err((StatusCode::NOT_FOUND, "Module file not found").into_response());
            }
        };

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        "application/gzip",
        Some(filename),
        &ctx,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /puppet/{repo_key}/v3/releases — Publish module (multipart)
// ---------------------------------------------------------------------------

async fn publish_module(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "puppet", "write:artifacts")?.user_id;
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let (tarball, module_json) =
        proxy_helpers::parse_multipart_file_with_json(multipart, &["module"]).await?;

    let (owner, module_name, module_version) = if let Some(ref json) = module_json {
        let owner = json
            .get("owner")
            .or_else(|| json.get("author"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (owner, name, version)
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing module metadata JSON").into_response());
    };

    if owner.is_empty() || module_name.is_empty() || module_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, module_name, module_version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid module: {}", e)).into_response())?;

    let full_name = format!("{}-{}", owner, module_name);
    let filename = format!("{}-{}-{}.tar.gz", owner, module_name, module_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", full_name, module_version, filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Module version already exists",
    )
    .await?;

    let storage_key = format!("puppet/{}/{}/{}", full_name, module_version, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, tarball.clone()).await?;

    let puppet_metadata = serde_json::json!({
        "owner": owner,
        "module_name": module_name,
        "version": module_version,
        "filename": filename,
        "module_json": module_json,
    });

    let size_bytes = tarball.len() as i64;

    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &full_name,
            version: &module_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/gzip",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    proxy_helpers::record_artifact_metadata(
        &state.db,
        artifact_id,
        repo.id,
        "puppet",
        &puppet_metadata,
    )
    .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    // Catalog row + the one artifact.uploaded webhook event this publish fires
    // (#3659, #3939). Not inside `insert_artifact`: its other callers already
    // register, so emitting there would double-deliver.
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        "puppet",
        &full_name,
        &module_version,
        size_bytes,
        &computed_sha256,
        puppet_metadata
            .pointer("/module_json/summary")
            .and_then(|d| d.as_str()),
    )
    .await;

    // #4725: fan out to subscribed push peers.
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        &headers,
        repo.id,
        artifact_id,
        &artifact_path,
        size_bytes,
    )
    .await;

    info!(
        "Puppet publish: {}-{} {} ({}) to repo {}",
        owner, module_name, module_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, module_name, module_version),
        "file_uri": format!("/v3/files/{}", filename),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_owner_name_valid() {
        let result = parse_owner_name("puppetlabs-stdlib");
        assert!(result.is_ok());
        let (owner, name) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "stdlib");
    }

    #[test]
    fn test_release_file_uri_native_path_is_byte_identical() {
        assert_eq!(
            release_file_uri(
                "puppetlabs-stdlib-9.0.0.tar.gz",
                "puppetlabs",
                "stdlib",
                "9.0.0"
            ),
            "/v3/files/puppetlabs-stdlib-9.0.0.tar.gz"
        );
    }

    #[test]
    fn test_release_file_uri_bare_path_advertises_stored_basename() {
        // Generic upload at a bare/arbitrary path: advertise the real basename
        // so the suffix download route (with #2587 exact-path fallback) serves
        // it, instead of the canonical filename that would 404.
        assert_eq!(
            release_file_uri("blob.tar.gz", "puppetlabs", "stdlib", "9.0.0"),
            "/v3/files/blob.tar.gz"
        );
        assert_eq!(
            release_file_uri("uploads/x/m.tar.gz", "puppetlabs", "stdlib", "9.0.0"),
            "/v3/files/m.tar.gz"
        );
    }

    fn release(version: &str) -> serde_json::Value {
        serde_json::json!({ "version": version, "file_uri": "/v3/files/x", "readme": "r" })
    }

    fn versions(doc: &serde_json::Value) -> Vec<String> {
        doc["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["version"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn test_forge_release_metadata_uses_module_json_and_pins_coordinates() {
        let stored = serde_json::json!({
            "owner": "acme",
            "module_json": {
                "name": "demo",
                "version": "9.9.9",
                "author": "Acme",
                "dependencies": [{"name": "puppetlabs/stdlib", "version_requirement": ">= 1.0.0"}],
            },
        });
        let meta = forge_release_metadata(Some(&stored), "acme", "demo", "1.0.0");
        assert_eq!(meta["name"], "acme-demo");
        assert_eq!(meta["version"], "1.0.0");
        assert_eq!(meta["author"], "Acme");
        assert_eq!(meta["dependencies"][0]["name"], "puppetlabs/stdlib");
    }

    #[test]
    fn test_forge_release_metadata_without_module_json() {
        for stored in [None, Some(serde_json::json!({"module_json": null}))] {
            let meta = forge_release_metadata(stored.as_ref(), "acme", "demo", "1.0.0");
            assert_eq!(
                meta,
                serde_json::json!({"name": "acme-demo", "version": "1.0.0", "dependencies": []})
            );
        }
    }

    #[test]
    fn test_paginate_releases_sorts_by_semver_and_pages() {
        let all = ["1.0.0", "10.0.0", "2.0.0", "not-semver", "1.5.0"]
            .map(release)
            .to_vec();
        let q = ReleasesQuery {
            limit: Some(2),
            sort_by: Some("version".into()),
            exclude_fields: Some("readme,changelog".into()),
            ..Default::default()
        };
        let doc = paginate_releases(all.clone(), &q, "acme", "demo");
        assert_eq!(versions(&doc), ["10.0.0", "2.0.0"]);
        assert_eq!(doc["pagination"]["total"], 5);
        assert!(doc["pagination"]["previous"].is_null());
        let next = doc["pagination"]["next"].as_str().unwrap();
        assert_eq!(
            next,
            "/v3/releases?module=acme-demo&limit=2&offset=2&sort_by=version&exclude_fields=readme%2Cchangelog"
        );
        assert!(doc["results"][0].get("readme").is_none());
        assert_eq!(doc["results"][0]["file_uri"], "/v3/files/x");

        let q = ReleasesQuery {
            limit: Some(2),
            offset: Some(4),
            ..Default::default()
        };
        let doc = paginate_releases(all, &q, "acme", "demo");
        assert_eq!(versions(&doc), ["not-semver"]);
        assert!(doc["pagination"]["next"].is_null());
        assert_eq!(
            doc["pagination"]["previous"],
            "/v3/releases?module=acme-demo&limit=2&offset=2"
        );
    }

    #[test]
    fn test_paginate_releases_release_date_keeps_publish_order_and_clamps_limit() {
        let q = ReleasesQuery {
            limit: Some(1000),
            sort_by: Some("release_date".into()),
            ..Default::default()
        };
        let doc = paginate_releases(["1.0.0", "2.0.0"].map(release).to_vec(), &q, "a", "b");
        assert_eq!(versions(&doc), ["1.0.0", "2.0.0"]);
        assert_eq!(doc["pagination"]["limit"], FORGE_MAX_LIMIT);
        assert!(doc["pagination"]["next"].is_null());
    }

    #[test]
    fn test_dedup_releases_by_version_keeps_first() {
        let mut first = release("1.0.0");
        first["file_uri"] = serde_json::json!("/v3/files/local");
        let out = dedup_releases_by_version(vec![first, release("1.0.0"), release("0.9.0")]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["file_uri"], "/v3/files/local");
    }

    #[test]
    fn test_upstream_release_results() {
        let ok = upstream_release_results(br#"{"pagination":{},"results":[{"version":"1.0.0"}]}"#);
        assert_eq!(ok.unwrap().len(), 1);
        for bad in [&b"not json"[..], br#"{"results":{}}"#] {
            let err = upstream_release_results(bad).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        }
    }

    #[test]
    fn test_parse_owner_name_multiple_hyphens() {
        let result = parse_owner_name("puppetlabs-my-module");
        assert!(result.is_ok());
        let (owner, name) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "my-module");
    }

    #[test]
    fn test_parse_owner_name_no_hyphen() {
        let result = parse_owner_name("nohyphen");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_empty_owner() {
        let result = parse_owner_name("-name");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_empty_name() {
        let result = parse_owner_name("owner-");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_valid() {
        let result = parse_owner_name_version("puppetlabs-stdlib-1.2.3");
        assert!(result.is_ok());
        let (owner, name, version) = result.unwrap();
        assert_eq!(owner, "puppetlabs");
        assert_eq!(name, "stdlib");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_owner_name_version_complex_name() {
        let result = parse_owner_name_version("myorg-my-complex-module-2.0.0");
        assert!(result.is_ok());
        let (owner, name, version) = result.unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(name, "my-complex-module");
        assert_eq!(version, "2.0.0");
    }

    #[test]
    fn test_parse_owner_name_version_no_hyphen() {
        let result = parse_owner_name_version("nohyphen");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_only_one_hyphen() {
        let result = parse_owner_name_version("owner-rest");
        // "rest" has no last_hyphen, since remainder="rest" and rfind('-') returns None
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_owner_name_version_empty_parts() {
        let result = parse_owner_name_version("-name-version");
        assert!(result.is_err());
    }

    #[test]
    fn test_puppet_module_slug_format() {
        let owner = "puppetlabs";
        let name = "apache";
        let version = "5.0.0";
        let slug = format!("{}-{}-{}", owner, name, version);
        assert_eq!(slug, "puppetlabs-apache-5.0.0");
    }

    #[test]
    fn test_puppet_filename_format() {
        let owner = "puppetlabs";
        let module_name = "ntp";
        let module_version = "9.0.1";
        let filename = format!("{}-{}-{}.tar.gz", owner, module_name, module_version);
        assert_eq!(filename, "puppetlabs-ntp-9.0.1.tar.gz");
    }

    #[test]
    fn test_puppet_storage_key_format() {
        let full_name = "puppetlabs-ntp";
        let module_version = "9.0.1";
        let filename = "puppetlabs-ntp-9.0.1.tar.gz";
        let storage_key = format!("puppet/{}/{}/{}", full_name, module_version, filename);
        assert_eq!(
            storage_key,
            "puppet/puppetlabs-ntp/9.0.1/puppetlabs-ntp-9.0.1.tar.gz"
        );
    }

    #[test]
    fn test_puppet_metadata_json() {
        let owner = "puppetlabs";
        let module_name = "stdlib";
        let module_version = "8.0.0";
        let filename = "puppetlabs-stdlib-8.0.0.tar.gz";

        let metadata = serde_json::json!({
            "owner": owner,
            "module_name": module_name,
            "version": module_version,
            "filename": filename,
            "module_json": serde_json::json!(null),
        });

        assert_eq!(metadata["owner"], "puppetlabs");
        assert_eq!(metadata["module_name"], "stdlib");
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_puppet_download_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/v3/files/missing-mod-1.0.0.tar.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_puppet_download_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "puppet/puppetlabs-stdlib-9.0.0.tar.gz",
            "puppetlabs-stdlib/9.0.0/puppetlabs-stdlib-9.0.0.tar.gz",
            "puppetlabs-stdlib",
            "9.0.0",
            "application/gzip",
            bytes::Bytes::from_static(b"puppet-tar"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/v3/files/puppetlabs-stdlib-9.0.0.tar.gz",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"puppet-tar");
        f.teardown().await;
    }

    /// Publish `acme-ntp` `version` natively to the fixture repo.
    async fn publish_acme_ntp(f: &tdh::Fixture, version: &str, body: &str) {
        let module = format!(
            r#"{{"owner":"acme","name":"ntp","version":"{version}","summary":"time sync","dependencies":[{{"name":"puppetlabs/stdlib","version_requirement":">= 4.0.0"}}]}}"#
        );
        let multipart = format!(
            "--B\r\nContent-Disposition: form-data; name=\"module\"\r\n\r\n{module}\r\n\
             --B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"m.tar.gz\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n{body}\r\n--B--\r\n"
        );
        let (status, resp) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::post(
                format!("/{}/v3/releases", f.repo_key),
                "multipart/form-data; boundary=B",
                bytes::Bytes::from(multipart),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "puppet publish failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// The query `puppet module install` sends (Puppet::Forge#fetch).
    const CLIENT_QUERY: &str = "sort_by=version&exclude_fields=readme,changelog,license,uri,module,tags,supported,file_size,downloads,created_at,updated_at,deleted_at";

    /// #5229: `GET /v3/releases?module=` answered 405 (only POST was routed),
    /// so `puppet module install --module_repository` could not install from
    /// a hosted repository. It must list the releases in the Forge shape the
    /// client reads, and the advertised `file_uri`, appended to the
    /// repository URL as the client does, must download the module.
    #[tokio::test]
    async fn test_puppet_v3_releases_lists_hosted_module_5229() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        publish_acme_ntp(&f, "1.0.0", "old-bytes").await;
        publish_acme_ntp(&f, "2.0.1", "module-bytes").await;
        let app = f.router_anon(super::router());

        let (status, body) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/{}/v3/releases?module=acme-ntp&{CLIENT_QUERY}",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc["pagination"]["total"], 2);
        assert!(doc["pagination"]["next"].is_null());
        assert_eq!(versions(&doc), ["2.0.1", "1.0.0"]);
        let newest = &doc["results"][0];
        assert_eq!(newest["metadata"]["name"], "acme-ntp");
        assert_eq!(newest["metadata"]["version"], "2.0.1");
        assert_eq!(
            newest["metadata"]["dependencies"][0]["name"],
            "puppetlabs/stdlib"
        );
        assert!(newest.get("module").is_none(), "exclude_fields honoured");
        let mut hasher = Sha256::new();
        hasher.update(b"module-bytes");
        assert_eq!(newest["file_sha256"], format!("{:x}", hasher.finalize()));
        let file_uri = newest["file_uri"].as_str().unwrap();
        assert_eq!(file_uri, "/v3/files/acme-ntp-2.0.1.tar.gz");

        // The client fetches `<module_repository>` + `file_uri`.
        let (status, tarball) =
            tdh::send(app.clone(), tdh::get(format!("/{}{file_uri}", f.repo_key))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&tarball[..], b"module-bytes");

        // An unknown module is an empty list, as on the Forge.
        let (status, body) = tdh::send(
            app.clone(),
            tdh::get(format!("/{}/v3/releases?module=acme-none", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc["pagination"]["total"], 0);

        // `module` is required for a hosted listing.
        let (status, _) = tdh::send(app, tdh::get(format!("/{}/v3/releases", f.repo_key))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        f.teardown().await;
    }

    /// #5229: a Remote repository forwards the upstream Forge's release list
    /// for the client's query. Its `file_uri`s are relative to the Forge API
    /// root, i.e. to this repository, so the client downloads through it.
    #[tokio::test]
    async fn test_puppet_v3_releases_remote_forwards_upstream_5229() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};
        let Some(f) = tdh::Fixture::setup("remote", "puppet").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        let upstream = r#"{"pagination":{"next":null,"total":1},"results":[{"version":"9.0.0","file_uri":"/v3/files/puppetlabs-stdlib-9.0.0.tar.gz","metadata":{"name":"puppetlabs-stdlib","version":"9.0.0"}}]}"#;
        Mock::given(method("GET"))
            .and(path("/v3/releases"))
            .and(query_param("module", "puppetlabs-stdlib"))
            .and(query_param("sort_by", "version"))
            .respond_with(ResponseTemplate::new(200).set_body_string(upstream))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{}/v3/releases?module=puppetlabs-stdlib&{CLIENT_QUERY}",
                f.repo_key
            )),
        )
        .await;
        f.teardown().await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(&body[..], upstream.as_bytes());
    }

    /// #5229: a Virtual repository merges its hosted members' releases with
    /// its Remote members', one entry per version, the hosted one first.
    #[tokio::test]
    async fn test_puppet_v3_releases_virtual_merges_members_5229() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        publish_acme_ntp(&f, "2.0.1", "module-bytes").await;
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/v3/releases"))
            .and(query_param("module", "acme-ntp"))
            .and(query_param(
                "exclude_fields",
                VIRTUAL_UPSTREAM_EXCLUDED_FIELDS,
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"pagination":{"next":null},"results":[
                    {"version":"2.0.1","file_uri":"/v3/files/upstream-impostor.tar.gz","metadata":{"name":"acme-ntp","version":"2.0.1"}},
                    {"version":"3.0.0","file_uri":"/v3/files/acme-ntp-3.0.0.tar.gz","metadata":{"name":"acme-ntp","version":"3.0.0"}}]}"#,
            ))
            .mount(&server)
            .await;
        let (virtual_id, virtual_key, vdir) = tdh::create_repo(&f.pool, "virtual", "puppet").await;
        tdh::publish_repo(&f.pool, virtual_id).await;
        tdh::link_virtual_member(&f.pool, virtual_id, f.repo_id, 0).await;
        let (remote_id, _, rdir) =
            tdh::attach_remote_member(&f.pool, virtual_id, "puppet", &server.uri(), 1).await;
        let cache = tempfile::tempdir().expect("tempdir");
        let proxy =
            tdh::build_proxy_service_with_fs(f.pool.clone(), cache.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(f.pool.clone(), cache.path().to_str().unwrap(), proxy);
        let app = tdh::router_with_auth(
            super::router(),
            state,
            tdh::make_auth(f.user_id, &f.username),
        );

        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{virtual_key}/v3/releases?module=acme-ntp&{CLIENT_QUERY}"
            )),
        )
        .await;
        tdh::cleanup_member_repo(&f.pool, remote_id, &rdir).await;
        tdh::cleanup_member_repo(&f.pool, virtual_id, &vdir).await;
        f.teardown().await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(versions(&doc), ["3.0.0", "2.0.1"]);
        assert_eq!(
            doc["results"][1]["file_uri"], "/v3/files/acme-ntp-2.0.1.tar.gz",
            "the hosted 2.0.1 must shadow the upstream one"
        );
    }

    #[tokio::test]
    async fn test_puppet_module_info_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/v3/modules/none-missing", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_puppet_publish_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::post(
            format!("/{}/v3/releases", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_puppet_publish_to_remote_405() {
        let Some(f) = tdh::Fixture::setup("remote", "puppet").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::post(
            format!("/{}/v3/releases", f.repo_key),
            "multipart/form-data; boundary=B",
            bytes::Bytes::from_static(b"--B--\r\n"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    /// #3939: a hosted publish registers its catalog row (with the module's
    /// `summary` as the description) and fires exactly one
    /// `artifact.uploaded`; before, a Puppet publish fired none.
    #[tokio::test]
    async fn test_puppet_publish_registers_and_emits_artifact_uploaded() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let module = r#"{"owner":"acme","name":"ntp","version":"2.0.1","summary":"time sync"}"#;
        let body = format!(
            "--B\r\nContent-Disposition: form-data; name=\"module\"\r\n\r\n{module}\r\n\
             --B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"m.tar.gz\"\r\n\
             Content-Type: application/octet-stream\r\n\r\nmodule-bytes\r\n--B--\r\n"
        );
        let mut events = f.state.event_bus.subscribe();
        let (status, resp) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::post(
                format!("/{}/v3/releases", f.repo_key),
                "multipart/form-data; boundary=B",
                bytes::Bytes::from(body),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "puppet publish failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        tdh::assert_one_artifact_uploaded(&mut events, &f.pool, f.repo_id, "acme-ntp", "2.0.1")
            .await;
        let row = tdh::catalog_row(&f.pool, f.repo_id, "acme-ntp").await;
        f.teardown().await;
        let row = row.expect("a puppet publish must write a packages row");
        assert_eq!(row.version, "2.0.1");
        assert_eq!(row.description.as_deref(), Some("time sync"));
    }

    /// #4725: a hosted puppet publish must queue a push sync task for a
    /// subscribed push peer, and a publish arriving as peer replication must
    /// not be fanned back out. Fails on `main` (nothing queued).
    #[tokio::test]
    async fn puppet_upload_queues_push_sync_task_4725() {
        let Some(f) = tdh::Fixture::setup("local", "puppet").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&f.pool, f.repo_id, "puppet").await;

        fn multipart_body(version: &str) -> String {
            let module = format!(
                r#"{{"owner":"acme","name":"ntp","version":"{version}","summary":"time sync"}}"#
            );
            format!(
                "--B\r\nContent-Disposition: form-data; name=\"module\"\r\n\r\n{module}\r\n\
                 --B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"m.tar.gz\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\nmodule-bytes\r\n--B--\r\n"
            )
        }

        let (status, resp) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::post(
                format!("/{}/v3/releases", f.repo_key),
                "multipart/form-data; boundary=B",
                bytes::Bytes::from(multipart_body("2.0.1")),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "puppet publish failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        // A replicated publish (as the sync worker sends it) stores the module
        // but must not queue another task.
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/v3/releases", f.repo_key))
            .header("x-artifact-keeper-replication", "true")
            .header("content-type", "multipart/form-data; boundary=B")
            .body(axum::body::Body::from(multipart_body("3.0.1")))
            .unwrap();
        let (status, resp) = tdh::send(f.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "replicated puppet publish failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let queued = tdh::queued_push_paths(&f.pool, peer_id, f.repo_id).await;
        tdh::delete_push_peer(&f.pool, peer_id).await;
        f.teardown().await;
        assert_eq!(
            queued,
            vec!["acme-ntp/2.0.1/acme-ntp-2.0.1.tar.gz".to_string()],
            "only the client publish queues a push task; the replicated one must not"
        );
    }
}
