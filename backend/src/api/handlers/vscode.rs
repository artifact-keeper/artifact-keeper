//! VS Code Extensions (VSIX Marketplace) API handlers.
//!
//! Implements a VS Code Marketplace-compatible API for extension hosting.
//!
//! Routes are mounted at `/vscode/{repo_key}/...`:
//!   GET  /vscode/{repo_key}/api/extensionquery                              - Query extensions
//!   GET  /vscode/{repo_key}/extensions/{publisher}/{name}/{version}/download - Download VSIX
//!   POST /vscode/{repo_key}/api/extensions                                  - Publish extension
//!   GET  /vscode/{repo_key}/api/extensions/{publisher}/{name}/latest         - Latest version info
//!
//! The `/gallery/...` routes are an Open VSX gateway for public Remote
//! repositories. They intentionally coexist with the legacy routes above:
//! hosted VSIX publishing and its existing clients continue using the legacy
//! surface.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::models::repository::{RepositoryFormat, RepositoryType};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Open VSX gallery gateway. Keep these separate from the legacy
        // `/api/...` surface below for backwards compatibility.
        .route("/:repo_key/gallery/manifest", get(gallery_manifest))
        .route(
            "/:repo_key/gallery/extensionquery",
            // The application router disables Axum's global default limit for
            // artifact uploads. Gallery queries are small JSON metadata, so
            // retain a tight route-local ceiling before `Bytes` buffers them.
            post(gallery_extension_query)
                .layer(DefaultBodyLimit::max(GALLERY_QUERY_BODY_MAX_BYTES)),
        )
        .route(
            "/:repo_key/gallery/:publisher/:name/latest",
            get(gallery_latest_version),
        )
        // code-server derives this from serviceUrl. Keep the direct VSCodium
        // template above too; both are gallery-protocol latest lookups.
        .route(
            "/:repo_key/gallery/vscode/:publisher/:name/latest",
            get(gallery_latest_version),
        )
        .route(
            "/:repo_key/gallery/publishers/:publisher/vsextensions/:name/:version/vspackage",
            get(gallery_vspackage),
        )
        .route(
            "/:repo_key/asset/:publisher/:name/:version/:target_platform/:asset_type",
            get(gallery_asset),
        )
        .route("/:repo_key/item", get(gallery_item))
        // Query extensions (marketplace API)
        .route("/:repo_key/api/extensionquery", get(query_extensions))
        // Download VSIX
        .route(
            "/:repo_key/extensions/:publisher/:name/:version/download",
            get(download_vsix),
        )
        // Publish extension
        .route("/:repo_key/api/extensions", post(publish_extension))
        // Latest version info
        .route(
            "/:repo_key/api/extensions/:publisher/:name/latest",
            get(latest_version),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_vscode_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["vscode"], "a VS Code").await
}

// ---------------------------------------------------------------------------
// Open VSX gallery gateway (public Remote repositories only)
// ---------------------------------------------------------------------------

/// Gallery metadata is forwarded, parsed for URL rewriting, and serialized
/// again, so it needs a deliberately smaller cap than the large package-index
/// formats. The live Open VSX dogfood latest/query response was about 400 KiB;
/// 2 MiB leaves five times the observed live-query headroom without admitting
/// 128 MiB JSON documents.
const GALLERY_METADATA_MAX_BYTES: usize = 2 * 1024 * 1024;
/// One gallery query can simultaneously retain wire bytes, a parsed JSON tree,
/// and serialized output. Charge a conservative multiple of the wire cap
/// against the shared metadata budget for that whole working set; JSON DOM
/// allocations are much larger than wire bytes for many tiny values, so use a
/// 32× allowance. At the default 1 GiB budget this admits at most 16 cap-sized
/// gallery queries rather than several GiB of real memory.
const GALLERY_METADATA_BUDGET_RESERVATION_BYTES: usize = GALLERY_METADATA_MAX_BYTES * 32;
const GALLERY_QUERY_BODY_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TARGET_PLATFORM: &str = "universal";

#[derive(serde::Deserialize)]
struct GalleryAssetQuery {
    #[serde(rename = "targetPlatform")]
    target_platform: Option<String>,
}

struct GalleryAssetCoordinate<'a> {
    repo_key: &'a str,
    publisher: &'a str,
    name: &'a str,
    version: &'a str,
    target_platform: &'a str,
}

struct GalleryAssetSource<'a> {
    upstream_url: &'a str,
    cache_path: &'a str,
    default_content_type: &'a str,
}

/// Parsed gallery metadata plus the reservation that covers the simultaneous
/// wire buffer, parsed JSON, and serialized AK response. Keep the permit until
/// the handler has rewritten and serialized the response, not merely until the
/// upstream read completes.
struct BufferedGalleryQuery {
    value: serde_json::Value,
    _budget_permit: tokio::sync::OwnedSemaphorePermit,
}

fn unsupported_gallery_repo(repo: &RepoInfo, requirement: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        format!(
            "VS Code Open VSX gallery gateway currently supports public Remote repositories only ({} is {}; {})",
            repo.key, repo.repo_type, requirement
        ),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
async fn gallery_upstream<'a>(db: &PgPool, repo: &'a RepoInfo) -> Result<&'a str, Response> {
    if repo.repo_type != RepositoryType::Remote {
        return Err(unsupported_gallery_repo(
            repo,
            "gallery access requires Remote",
        ));
    }
    // The visibility middleware intentionally permits authenticated reads from
    // private repositories. Gallery clients cannot safely configure that auth,
    // however, so this protocol capability is explicitly public-only even for
    // an authenticated caller. Keep this check in the common gallery gate so
    // manifest, query, latest, item, asset, and vspackage routes cannot drift.
    let is_public =
        sqlx::query_scalar::<_, bool>("SELECT is_public FROM repositories WHERE id = $1")
            .bind(repo.id)
            .fetch_optional(db)
            .await
            .map_err(crate::api::handlers::db_err)?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;
    if !is_public {
        return Err(unsupported_gallery_repo(
            repo,
            "private gallery access is unsupported in this prototype",
        ));
    }
    let upstream_url = repo.upstream_url.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "Remote VS Code repository is missing its Open VSX gallery upstream URL",
        )
            .into_response()
    })?;
    if !upstream_url
        .trim_end_matches('/')
        .ends_with("/vscode/gallery")
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Remote VS Code upstream URL must end in /vscode/gallery",
        )
            .into_response());
    }
    Ok(upstream_url)
}

fn json_response(value: &serde_json::Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(value).expect("JSON value serializes"),
        ))
        .expect("valid JSON response")
}

fn gallery_base_url(base_url: &RequestBaseUrl, repo_key: &str) -> String {
    format!(
        "{}/vscode/{}/gallery",
        base_url.as_str().trim_end_matches('/'),
        urlencoding::encode(repo_key)
    )
}

fn gallery_asset_base_url(
    base_url: &RequestBaseUrl,
    repo_key: &str,
    publisher: &str,
    name: &str,
    version: &str,
    target_platform: &str,
) -> String {
    format!(
        "{}/vscode/{}/asset/{}/{}/{}/{}",
        base_url.as_str().trim_end_matches('/'),
        urlencoding::encode(repo_key),
        urlencoding::encode(publisher),
        urlencoding::encode(name),
        urlencoding::encode(version),
        urlencoding::encode(target_platform),
    )
}

fn normal_target_platform(platform: Option<&str>) -> &str {
    platform
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_TARGET_PLATFORM)
}

/// Identity used by the shared age-gate policy. Gallery publisher and
/// extension names are case-insensitive, while Open VSX platform variants are
/// independently immutable coordinates. Keep the platform in the version
/// field because that is the shared review/first-seen key shape.
fn vscode_age_gate_package(publisher: &str, name: &str) -> String {
    format!("{}.{}", publisher, name).to_ascii_lowercase()
}

fn vscode_age_gate_version(version: &str, target_platform: Option<&str>) -> String {
    format!(
        "{}@{}",
        version,
        normal_target_platform(target_platform).to_ascii_lowercase()
    )
}

/// `lastUpdated` is Open VSX gallery's publish-time evidence. Deliberately
/// return `None` for absent or malformed values: upstream-publish-time mode
/// treats no evidence as ineligible, while first-seen ignores it and uses the
/// positive existence evidence supplied by the containing gallery document.
fn gallery_last_updated(version: &serde_json::Value) -> Option<DateTime<Utc>> {
    version
        .get("lastUpdated")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

/// Gallery coordinates become both upstream URL components and cache-key
/// components. Route matching already excludes literal slashes, but retain an
/// explicit boundary for decoded paths and for values supplied by upstream
/// metadata before we rewrite them into AK URLs.
fn is_safe_gallery_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', '?', '#'])
        && !value.chars().any(char::is_control)
}

#[allow(clippy::result_large_err)]
fn validate_gallery_request_segment(value: &str) -> Result<(), Response> {
    if is_safe_gallery_segment(value) {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid VS Code gallery path").into_response())
    }
}

#[allow(clippy::result_large_err)]
fn validate_gallery_response_segment(value: &str) -> Result<(), Response> {
    if is_safe_gallery_segment(value) {
        Ok(())
    } else {
        Err(invalid_gallery_response())
    }
}

fn invalid_gallery_response() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        "Open VSX gallery returned an invalid extensionquery response",
    )
        .into_response()
}

/// Rewrite all gallery asset references to AK. We do not retain an upstream
/// absolute URL in the response: Open VSX's gallery adapter has stable sibling
/// `/vscode/asset/...` endpoints, so delivery can reconstruct the upstream
/// target from repository configuration instead of treating metadata as an
/// arbitrary fetch capability.
#[allow(clippy::result_large_err)]
fn rewrite_gallery_asset_urls(
    response: &mut serde_json::Value,
    base_url: &RequestBaseUrl,
    repo_key: &str,
) -> Result<(), Response> {
    let results = response
        .get_mut("results")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(invalid_gallery_response)?;

    for result in results {
        let extensions = result
            .get_mut("extensions")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(invalid_gallery_response)?;
        for extension in extensions {
            let publisher = extension
                .get("publisher")
                .and_then(|publisher| publisher.get("publisherName"))
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            let name = extension
                .get("extensionName")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            let (Some(publisher), Some(name)) = (publisher, name) else {
                return Err(invalid_gallery_response());
            };
            validate_gallery_response_segment(&publisher)?;
            validate_gallery_response_segment(&name)?;
            let versions = extension
                .get_mut("versions")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(invalid_gallery_response)?;

            for version in versions {
                let version_name = version
                    .get("version")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
                    .ok_or_else(invalid_gallery_response)?;
                validate_gallery_response_segment(&version_name)?;
                let target_platform = normal_target_platform(
                    version
                        .get("targetPlatform")
                        .and_then(|value| value.as_str()),
                );
                validate_gallery_response_segment(target_platform)?;
                let asset_base = gallery_asset_base_url(
                    base_url,
                    repo_key,
                    &publisher,
                    &name,
                    &version_name,
                    target_platform,
                );

                for field in ["assetUri", "fallbackAssetUri"] {
                    if let Some(value) = version.get(field) {
                        if !value.is_string() {
                            return Err(invalid_gallery_response());
                        }
                        version[field] = serde_json::Value::String(asset_base.clone());
                    }
                }

                if let Some(files_value) = version.get_mut("files") {
                    let files = files_value
                        .as_array_mut()
                        .ok_or_else(invalid_gallery_response)?;
                    for file in files {
                        let Some(source_value) = file.get("source") else {
                            continue;
                        };
                        let source = source_value.as_str().ok_or_else(invalid_gallery_response)?;
                        // `assetType` is the gallery protocol's stable name.
                        // A few adapters omit it; use the source's final path
                        // component so the reference still remains on AK.
                        let asset_type = file
                            .get("assetType")
                            .and_then(|value| value.as_str())
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .or_else(|| {
                                source
                                    .split('?')
                                    .next()
                                    .and_then(|path| path.rsplit('/').next())
                                    .filter(|value| !value.is_empty())
                                    .map(str::to_owned)
                            });
                        let asset_type = asset_type.ok_or_else(invalid_gallery_response)?;
                        validate_gallery_response_segment(&asset_type)?;
                        file["source"] = serde_json::Value::String(format!(
                            "{}/{}",
                            asset_base,
                            urlencoding::encode(&asset_type)
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

async fn fetch_gallery_query(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    body: Bytes,
) -> Result<BufferedGalleryQuery, Response> {
    let upstream_url = gallery_upstream(&state.db, repo).await?;
    // Validate client input before it is eligible to reach an upstream. This
    // also makes the contract explicit: the gateway forwards JSON semantics,
    // not arbitrary POST bytes.
    serde_json::from_slice::<serde_json::Value>(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid VS Code gallery query JSON",
        )
            .into_response()
    })?;

    let proxy = state.proxy_service.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is unavailable",
        )
            .into_response()
    })?;
    let (content, _content_type, budget_permit) =
        proxy_helpers::proxy_post_json_uncached_capped_budgeted(
            proxy,
            repo.id,
            repo_key,
            upstream_url,
            "extensionquery",
            body,
            proxy_helpers::MetadataWorkingSetLimits {
                max_bytes: GALLERY_METADATA_MAX_BYTES,
                reservation_bytes: GALLERY_METADATA_BUDGET_RESERVATION_BYTES,
            },
        )
        .await?;
    let response: serde_json::Value = serde_json::from_slice(&content).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Open VSX gallery returned malformed JSON",
        )
            .into_response()
    })?;
    if !response
        .get("results")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(invalid_gallery_response());
    }
    Ok(BufferedGalleryQuery {
        value: response,
        _budget_permit: budget_permit,
    })
}

fn gallery_extension_identity(extension: &serde_json::Value) -> Option<(String, String, String)> {
    let publisher = extension
        .get("publisher")
        .and_then(|publisher| publisher.get("publisherName"))
        .and_then(serde_json::Value::as_str)?;
    let name = extension
        .get("extensionName")
        .and_then(serde_json::Value::as_str)?;
    validate_gallery_response_segment(publisher).ok()?;
    validate_gallery_response_segment(name).ok()?;
    Some((
        publisher.to_string(),
        name.to_string(),
        vscode_age_gate_package(publisher, name),
    ))
}

fn gallery_version_coordinate(version: &serde_json::Value) -> Option<String> {
    let name = version.get("version").and_then(serde_json::Value::as_str)?;
    let platform = normal_target_platform(
        version
            .get("targetPlatform")
            .and_then(serde_json::Value::as_str),
    );
    validate_gallery_response_segment(name).ok()?;
    validate_gallery_response_segment(platform).ok()?;
    Some(vscode_age_gate_version(name, Some(platform)))
}

/// Reconcile the gallery's per-result count after age-gate filtering. Gallery
/// `TotalCount` is the total number of matching extensions across every page,
/// not the length of this response page, so subtract only extensions removed
/// entirely. Some adapters omit result metadata; preserve that shape.
fn reconcile_gallery_result_count(result: &mut serde_json::Value, removed: usize) {
    let Some(metadata) = result
        .get_mut("resultMetadata")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for entry in metadata {
        if entry
            .get("metadataType")
            .and_then(serde_json::Value::as_str)
            != Some("ResultCount")
        {
            continue;
        }
        let Some(items) = entry
            .get_mut("metadataItems")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        for item in items {
            if item.get("name").and_then(serde_json::Value::as_str) == Some("TotalCount") {
                let Some(count) = item.get("count").and_then(serde_json::Value::as_u64) else {
                    continue;
                };
                item["count"] = serde_json::json!(count.saturating_sub(removed as u64));
            }
        }
    }
}

/// Apply the shared age-gate listing semantics to every returned extension
/// identity before asset URLs are rewritten. This is intentionally separate
/// from `fetch_gallery_query`: delivery must be able to fetch raw gallery
/// metadata as exact existence evidence without recursively filtering it.
async fn filter_gallery_response_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    response: &mut serde_json::Value,
) -> Result<(), Response> {
    use crate::services::age_gate_service::{resolve_repo_params, AgeGateService};

    let params = resolve_repo_params(&state.db, repo.id)
        .await
        .map_err(|error| error.into_response())?;
    if !AgeGateService::gating_requested(&params) {
        return Ok(());
    }
    AgeGateService::require_enforceable(&params).map_err(|error| error.into_response())?;
    let service = state.age_gate_service.as_deref().ok_or_else(|| {
        proxy_helpers::age_gate_unavailable_response(&params.key, "VS Code gallery metadata")
    })?;

    let results = response
        .get_mut("results")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(invalid_gallery_response)?;
    let mut filtered_any = false;
    for result in results {
        let extensions = result
            .get_mut("extensions")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(invalid_gallery_response)?;
        let extension_count_before = extensions.len();
        for extension in extensions.iter_mut() {
            let (_, _, package) =
                gallery_extension_identity(extension).ok_or_else(invalid_gallery_response)?;
            let versions = extension
                .get_mut("versions")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(invalid_gallery_response)?;
            let candidates = versions
                .iter()
                .map(|version| {
                    Ok((
                        gallery_version_coordinate(version).ok_or_else(invalid_gallery_response)?,
                        gallery_last_updated(version),
                    ))
                })
                .collect::<Result<Vec<_>, Response>>()?;
            let blocked = service
                .evaluate_versions_batch(&params, &package, &candidates)
                .await
                .map_err(|error| error.into_response())?;
            if !blocked.is_empty() {
                filtered_any = true;
                let original = std::mem::take(versions);
                *versions = original
                    .into_iter()
                    .filter_map(|version| {
                        let coordinate = gallery_version_coordinate(&version)?;
                        (!blocked.contains(&coordinate)).then_some(version)
                    })
                    .collect();
            }
        }
        extensions.retain(|extension| {
            extension
                .get("versions")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|versions| !versions.is_empty())
        });
        let removed_extensions = extension_count_before.saturating_sub(extensions.len());
        reconcile_gallery_result_count(result, removed_extensions);
    }
    if filtered_any {
        crate::services::metrics_service::record_age_gate_filtered_metadata(&params.key, "vscode");
    }
    Ok(())
}

/// Locate one platform-qualified version in an unfiltered Open VSX gallery
/// response. `Some(None)` means it exists but lacks trustworthy publish-time
/// evidence; callers must pass that through to the shared fail-closed seam.
fn find_gallery_exact_version(
    response: &serde_json::Value,
    package: &str,
    version: &str,
    target_platform: &str,
) -> Option<Option<DateTime<Utc>>> {
    let target = normal_target_platform(Some(target_platform)).to_ascii_lowercase();
    for result in response.get("results")?.as_array()? {
        for extension in result.get("extensions")?.as_array()? {
            let publisher = extension.get("publisher")?.get("publisherName")?.as_str()?;
            let name = extension.get("extensionName")?.as_str()?;
            if vscode_age_gate_package(publisher, name) != package {
                continue;
            }
            for candidate in extension.get("versions")?.as_array()? {
                let candidate_version = candidate.get("version")?.as_str()?;
                let candidate_platform = normal_target_platform(
                    candidate
                        .get("targetPlatform")
                        .and_then(serde_json::Value::as_str),
                )
                .to_ascii_lowercase();
                if candidate_version == version && candidate_platform == target {
                    return Some(gallery_last_updated(candidate));
                }
            }
        }
    }
    None
}

/// Re-resolve exact gallery metadata before every cache lookup or upstream
/// byte fetch. The raw query is deliberately not passed through the listing
/// filter, which avoids recursive policy evaluation and gives first-seen mode
/// positive existence evidence for precisely the requested platform variant.
async fn enforce_gallery_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    publisher: &str,
    name: &str,
    version: &str,
    target_platform: &str,
) -> Result<(), Response> {
    use crate::services::age_gate_service::{resolve_repo_params, AgeGateService};

    let params = resolve_repo_params(&state.db, repo.id)
        .await
        .map_err(|error| error.into_response())?;
    if !AgeGateService::gating_requested(&params) {
        return Ok(());
    }
    AgeGateService::require_enforceable(&params).map_err(|error| error.into_response())?;
    let service = state.age_gate_service.as_deref().ok_or_else(|| {
        proxy_helpers::age_gate_unavailable_response(&params.key, "VS Code gallery asset")
    })?;
    let package = vscode_age_gate_package(publisher, name);
    let coordinate = vscode_age_gate_version(version, Some(target_platform));
    let query = serde_json::json!({
        "filters": [{
            "criteria": [{ "filterType": 7, "value": package }],
            "pageNumber": 1,
            "pageSize": 1,
            "sortBy": 0,
            "sortOrder": 0,
        }],
        "flags": 511,
    });
    let raw = fetch_gallery_query(
        state,
        repo,
        repo_key,
        Bytes::from(serde_json::to_vec(&query).expect("gallery query serializes")),
    )
    .await?;
    let published_at = find_gallery_exact_version(&raw.value, &package, version, target_platform)
        .ok_or_else(|| {
        (StatusCode::NOT_FOUND, "Extension version not found").into_response()
    })?;
    let basis = service
        .download_basis(&params, &package, &coordinate, published_at, true)
        .await
        .map_err(|error| error.into_response())?;
    // The shared seam returns an LKG for protocols that can safely substitute
    // one. VS Code cannot: platform/engine/channel compatibility matters, so
    // convert that outcome back to the same structured terminal 451 as Go.
    if let Some(blocked) = proxy_helpers::enforce_age_gate(
        state.age_gate_service.as_deref(),
        &params,
        &package,
        &coordinate,
        basis,
    )
    .await?
    {
        return Err(proxy_helpers::age_gate_blocked_response(
            blocked.review_id,
            &package,
            &coordinate,
            params.age_gate_min_age_days,
            basis.map(|time| AgeGateService::package_age_days(time, Utc::now())),
        ));
    }
    Ok(())
}

fn build_gallery_manifest(base_url: &RequestBaseUrl, repo_key: &str) -> serde_json::Value {
    let gallery = gallery_base_url(base_url, repo_key);
    let item = format!(
        "{}/vscode/{}/item",
        base_url.as_str().trim_end_matches('/'),
        repo_key
    );
    serde_json::json!({
        "version": "",
        "resources": [
            { "id": format!("{gallery}/extensionquery"), "type": "ExtensionQueryService" },
            { "id": format!("{gallery}/{{publisher}}/{{name}}/latest"), "type": "ExtensionLatestVersionUriTemplate" },
            { "id": format!("{item}?itemName={{publisher}}.{{name}}"), "type": "ExtensionDetailsViewUriTemplate" }
        ],
        "capabilities": { "extensionQuery": {
            "filtering": [
                { "name": "Tag", "value": 1 },
                { "name": "ExtensionId", "value": 4 },
                { "name": "Category", "value": 5 },
                { "name": "ExtensionName", "value": 7 },
                { "name": "Target", "value": 8 },
                { "name": "Featured", "value": 9 },
                { "name": "SearchText", "value": 10 },
                { "name": "ExcludeWithFlags", "value": 12 }
            ],
            "sorting": [
                { "name": "NoneOrRelevance", "value": 0 },
                { "name": "LastUpdatedDate", "value": 1 },
                { "name": "Title", "value": 2 },
                { "name": "PublisherName", "value": 3 },
                { "name": "InstallCount", "value": 4 },
                { "name": "AverageRating", "value": 6 },
                { "name": "PublishedDate", "value": 10 },
                { "name": "WeightedRating", "value": 12 }
            ],
            "flags": [
                { "name": "None", "value": 0 },
                { "name": "IncludeVersions", "value": 1 },
                { "name": "IncludeFiles", "value": 2 },
                { "name": "IncludeCategoryAndTags", "value": 4 },
                { "name": "IncludeSharedAccounts", "value": 8 },
                { "name": "IncludeVersionProperties", "value": 16 },
                { "name": "ExcludeNonValidated", "value": 32 },
                { "name": "IncludeInstallationTargets", "value": 64 },
                { "name": "IncludeAssetUri", "value": 128 },
                { "name": "IncludeStatistics", "value": 256 },
                { "name": "IncludeLatestVersionOnly", "value": 512 },
                { "name": "Unpublished", "value": 4096 },
                { "name": "IncludeNameConflictInfo", "value": 32768 },
                { "name": "IncludeLatestPrereleaseAndStableVersionOnly", "value": 65536 }
            ]
        } }
    })
}

async fn gallery_manifest(
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
    State(state): State<SharedState>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    gallery_upstream(&state.db, &repo).await?;
    Ok(json_response(&build_gallery_manifest(&base_url, &repo_key)))
}

async fn gallery_extension_query(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    let mut response = fetch_gallery_query(&state, &repo, &repo_key, body).await?;
    filter_gallery_response_age_gate(&state, &repo, &mut response.value).await?;
    rewrite_gallery_asset_urls(&mut response.value, &base_url, &repo_key)?;
    Ok(json_response(&response.value))
}

async fn gallery_latest_version(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name)): Path<(String, String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    validate_gallery_request_segment(&publisher)?;
    validate_gallery_request_segment(&name)?;
    let query = serde_json::json!({
        // Open VSX requires the paging fields on every filter, including this
        // one-result latest-version lookup. VS Code clients normally include
        // them on `extensionquery`; supply them here because this request is
        // generated by AK itself.
        "filters": [{
            "criteria": [{ "filterType": 7, "value": format!("{publisher}.{name}") }],
            "pageNumber": 1,
            "pageSize": 1,
            "sortBy": 0,
            "sortOrder": 0,
        }],
        "flags": 511,
    });
    let mut response = fetch_gallery_query(
        &state,
        &repo,
        &repo_key,
        Bytes::from(serde_json::to_vec(&query).expect("gallery query serializes")),
    )
    .await?;
    filter_gallery_response_age_gate(&state, &repo, &mut response.value).await?;
    rewrite_gallery_asset_urls(&mut response.value, &base_url, &repo_key)?;
    // `ExtensionLatestVersionUriTemplate` is consumed by VS Code as a
    // single raw gallery extension, unlike the POST extensionquery envelope.
    // An empty query result is the ordinary "extension not found" case.
    let extension = response
        .value
        .pointer("/results/0/extensions/0")
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension not found").into_response())?;
    Ok(json_response(&extension))
}

async fn gallery_vspackage(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name, version)): Path<(String, String, String, String)>,
    Query(query): Query<GalleryAssetQuery>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    let upstream_url = gallery_upstream(&state.db, &repo).await?;
    let target_platform = normal_target_platform(query.target_platform.as_deref());
    for segment in [
        publisher.as_str(),
        name.as_str(),
        version.as_str(),
        target_platform,
    ] {
        validate_gallery_request_segment(segment)?;
    }
    let upstream_path = format!(
        "publishers/{}/vsextensions/{}/{}/vspackage{}",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        query
            .target_platform
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("?targetPlatform={}", urlencoding::encode(value)))
            .unwrap_or_default(),
    );
    let cache_path = format!(
        "gallery/{}/{}/{}/{}/vspackage",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        urlencoding::encode(target_platform),
    );
    let upstream_asset_url = format!(
        "{}/{}",
        upstream_url.trim_end_matches('/'),
        upstream_path.trim_start_matches('/'),
    );
    let coordinate = GalleryAssetCoordinate {
        repo_key: &repo_key,
        publisher: &publisher,
        name: &name,
        version: &version,
        target_platform,
    };
    let source = GalleryAssetSource {
        upstream_url: &upstream_asset_url,
        cache_path: &cache_path,
        default_content_type: "application/vsix",
    };
    proxy_gallery_asset(&state, &repo, &coordinate, &source).await
}

async fn gallery_asset(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name, version, target_platform, asset_type)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    let upstream_url = gallery_upstream(&state.db, &repo).await?;
    let target_platform = normal_target_platform(Some(&target_platform));
    for segment in [
        publisher.as_str(),
        name.as_str(),
        version.as_str(),
        target_platform,
        asset_type.as_str(),
    ] {
        validate_gallery_request_segment(segment)?;
    }
    let upstream_url = openvsx_asset_url(
        upstream_url,
        &publisher,
        &name,
        &version,
        &asset_type,
        target_platform,
    )?;
    let cache_path = format!(
        "gallery/{}/{}/{}/{}/asset-{:x}",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        urlencoding::encode(target_platform),
        Sha256::digest(asset_type.as_bytes()),
    );
    let coordinate = GalleryAssetCoordinate {
        repo_key: &repo_key,
        publisher: &publisher,
        name: &name,
        version: &version,
        target_platform,
    };
    let source = GalleryAssetSource {
        upstream_url: &upstream_url,
        cache_path: &cache_path,
        default_content_type: "application/octet-stream",
    };
    proxy_gallery_asset(&state, &repo, &coordinate, &source).await
}

async fn proxy_gallery_asset(
    state: &SharedState,
    repo: &RepoInfo,
    coordinate: &GalleryAssetCoordinate<'_>,
    source: &GalleryAssetSource<'_>,
) -> Result<Response, Response> {
    // The raw exact-metadata query and shared gate run before ProxyService can
    // inspect its cache, so a direct AK asset URL or a warm cache entry never
    // bypasses a newly enabled policy or manual review decision.
    enforce_gallery_age_gate(
        state,
        repo,
        coordinate.repo_key,
        coordinate.publisher,
        coordinate.name,
        coordinate.version,
        coordinate.target_platform,
    )
    .await?;
    let proxy = state.proxy_service.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is unavailable",
        )
            .into_response()
    })?;
    // Gallery metadata is never used as a fetch URL. Validate this derived
    // configured-adapter sibling anyway so a malformed remote URL gets a
    // controlled response before the shared SSRF-safe HTTP client is invoked.
    validate_outbound_url(source.upstream_url, "VS Code gallery asset URL").map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Configured Open VSX gallery URL is disallowed: {error}"),
        )
            .into_response()
    })?;
    proxy_helpers::proxy_fetch_streaming_response_with_cache_key(
        proxy,
        repo.id,
        coordinate.repo_key,
        source.upstream_url,
        source.upstream_url,
        source.cache_path,
        source.default_content_type,
        RepositoryFormat::Vscode,
    )
    .await
}

/// Build Open VSX's gallery-adapter asset endpoint from the configured gallery
/// root. Open VSX exposes assets next to `/vscode/gallery`, under
/// `/vscode/asset`; deriving it avoids trusting a gallery response's absolute
/// URL while retaining the adapter's target-platform semantics.
#[allow(clippy::result_large_err)]
fn openvsx_asset_url(
    gallery_url: &str,
    publisher: &str,
    name: &str,
    version: &str,
    asset_type: &str,
    target_platform: &str,
) -> Result<String, Response> {
    let asset_root = gallery_url
        .trim_end_matches('/')
        .strip_suffix("/gallery")
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "Open VSX upstream URL must end in /vscode/gallery",
            )
                .into_response()
        })?;
    Ok(format!(
        "{asset_root}/asset/{}/{}/{}/{}?targetPlatform={}",
        urlencoding::encode(publisher),
        urlencoding::encode(name),
        urlencoding::encode(version),
        urlencoding::encode(asset_type),
        urlencoding::encode(target_platform),
    ))
}

async fn gallery_item(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    gallery_upstream(&state.db, &repo).await?;
    Ok(Redirect::temporary(&format!(
        "{}/repositories/{}",
        base_url.as_str().trim_end_matches('/'),
        urlencoding::encode(&repo_key)
    ))
    .into_response())
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/api/extensionquery — Query extensions
// ---------------------------------------------------------------------------

async fn query_extensions(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(a.name)) a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY LOWER(a.name), a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let extensions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let publisher = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("publisher"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let ext_name = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("extension_name"))
                .and_then(|v| v.as_str())
                .unwrap_or(&a.name);
            let version = a.version.clone().unwrap_or_default();

            serde_json::json!({
                "publisher": { "publisherName": publisher },
                "extensionName": ext_name,
                "versions": [{
                    "version": version,
                    "assetUri": build_vscode_download_url(&repo_key, publisher, ext_name, &version),
                }],
            })
        })
        .collect();

    let result = serde_json::json!({
        "results": [{
            "extensions": extensions,
            "resultMetadata": [{
                "metadataType": "ResultCount",
                "metadataItems": [{ "name": "TotalCount", "count": extensions.len() }],
            }],
        }],
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&result).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/extensions/{publisher}/{name}/{version}/download
// ---------------------------------------------------------------------------

async fn download_vsix(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, publisher, name, version)): Path<(String, String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let extension_id = build_extension_id(&publisher, &name);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        extension_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("extensions/{}/{}/{}/download", publisher, name, version);
                    // #1608 Phase 4: stream the extension archive (.vsix) to the
                    // client while teeing to the proxy cache, instead of
                    // buffering the whole extension in memory. Single-flight via
                    // the merged coordinator (#1609).
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        "application/octet-stream",
                    )
                    .await;
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path =
                    format!("extensions/{}/{}/{}/download", publisher, name, version);
                let vname = extension_id.clone();
                let vversion = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth.as_ref(),
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

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
            }
            return Err(not_found);
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let filename = build_vsix_download_filename(&publisher, &name, &version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vsix")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /vscode/{repo_key}/api/extensions — Publish extension (auth required)
// ---------------------------------------------------------------------------

async fn publish_extension(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "vscode", "write:artifacts")?.user_id;
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty VSIX file").into_response());
    }
    // Extract publisher/name/version from VSIX headers or require them as query params.
    // For simplicity, extract from the Content-Disposition header or require metadata headers.
    let publisher = headers
        .get("x-publisher")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing x-publisher header").into_response())?;

    let ext_name = headers
        .get("x-extension-name")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing x-extension-name header").into_response()
        })?;

    let ext_version = headers
        .get("x-extension-version")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing x-extension-version header",
            )
                .into_response()
        })?;

    let extension_id = build_extension_id(&publisher, &ext_name);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = build_vscode_artifact_path(&publisher, &ext_name, &ext_version);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Extension version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage_key = build_vscode_storage_key(&publisher, &ext_name, &ext_version);
    proxy_helpers::guard_cross_repo_write(&state, repo.id, &repo.storage_backend, &storage_key)
        .await?;
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

    let vscode_metadata = build_vscode_metadata(&publisher, &ext_name, &ext_version);

    let size_bytes = body.len() as i64;

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
        extension_id,
        ext_version,
        size_bytes,
        computed_sha256,
        "application/vsix",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'vscode', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        vscode_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "VS Code extension publish: {} {} to repo {}",
        extension_id, ext_version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&build_vscode_publish_response(
                &publisher,
                &ext_name,
                &ext_version,
            ))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /vscode/{repo_key}/api/extensions/{publisher}/{name}/latest
// ---------------------------------------------------------------------------

async fn latest_version(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;

    let extension_id = build_extension_id(&publisher, &name);

    let artifact = sqlx::query!(
        r#"
        SELECT a.name, a.version, a.size_bytes, a.checksum_sha256,
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
        extension_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension not found").into_response())?;

    let version = artifact.version.clone().unwrap_or_default();

    let json = serde_json::json!({
        "publisher": publisher,
        "name": name,
        "version": version,
        "sha256": artifact.checksum_sha256,
        "size": artifact.size_bytes,
        "downloadUrl": build_vscode_download_url(&repo_key, &publisher, &name, &version),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// ID/path/URL builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build a VS Code extension ID from publisher and name.
fn build_extension_id(publisher: &str, name: &str) -> String {
    format!("{}.{}", publisher, name)
}

/// Build a VSIX filename from publisher, name, and version.
fn build_vsix_filename(publisher: &str, name: &str, version: &str) -> String {
    let extension_id = build_extension_id(publisher, name);
    format!("{}-{}.vsix", extension_id, version)
}

/// Build the artifact path for a VS Code extension.
fn build_vscode_artifact_path(publisher: &str, name: &str, version: &str) -> String {
    let filename = build_vsix_filename(publisher, name, version);
    format!("{}/{}/{}", publisher, name, filename)
}

/// Build the storage key for a VS Code extension.
fn build_vscode_storage_key(publisher: &str, name: &str, version: &str) -> String {
    let filename = build_vsix_filename(publisher, name, version);
    format!("vscode/{}/{}/{}", publisher, name, filename)
}

/// Build the download URL for a VS Code extension.
fn build_vscode_download_url(repo_key: &str, publisher: &str, name: &str, version: &str) -> String {
    format!(
        "/vscode/{}/extensions/{}/{}/{}/download",
        repo_key, publisher, name, version
    )
}

/// Build the Content-Disposition filename for a VSIX download.
fn build_vsix_download_filename(publisher: &str, name: &str, version: &str) -> String {
    format!("{}.{}-{}.vsix", publisher, name, version)
}

/// Build the metadata JSON for a published VS Code extension.
fn build_vscode_metadata(publisher: &str, name: &str, version: &str) -> serde_json::Value {
    let filename = build_vsix_filename(publisher, name, version);
    serde_json::json!({
        "publisher": publisher,
        "extension_name": name,
        "version": version,
        "filename": filename,
    })
}

/// Build the publish success response JSON.
fn build_vscode_publish_response(publisher: &str, name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "publisher": publisher,
        "name": name,
        "version": version,
        "message": "Successfully published extension",
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn gallery_age_gate_coordinates_are_casefolded_and_platform_qualified() {
        assert_eq!(
            vscode_age_gate_package("RedHat", "VSCode-YAML"),
            "redhat.vscode-yaml"
        );
        assert_eq!(
            vscode_age_gate_version("1.24.0", Some("linux-x64")),
            "1.24.0@linux-x64"
        );
        assert_eq!(
            vscode_age_gate_version("1.24.0", Some("WIN32-X64")),
            "1.24.0@win32-x64"
        );
        assert_eq!(
            vscode_age_gate_version("1.24.0", Some("")),
            "1.24.0@universal"
        );
        assert_eq!(vscode_age_gate_version("1.24.0", None), "1.24.0@universal");
    }

    #[test]
    fn gallery_publish_time_evidence_is_rfc3339_or_missing() {
        let old = serde_json::json!({ "lastUpdated": "2024-01-02T03:04:05Z" });
        assert!(gallery_last_updated(&old).is_some());
        assert!(gallery_last_updated(&serde_json::json!({})).is_none());
        assert!(gallery_last_updated(&serde_json::json!({ "lastUpdated": "yesterday" })).is_none());
    }

    #[test]
    fn exact_gallery_lookup_keeps_platform_variants_independent() {
        let response = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": "RedHat" },
                "extensionName": "VSCode-YAML",
                "versions": [
                    { "version": "1.24.0", "targetPlatform": "linux-x64", "lastUpdated": "2024-01-02T03:04:05Z" },
                    { "version": "1.24.0", "targetPlatform": "win32-x64", "lastUpdated": "not-a-time" },
                    { "version": "1.24.0", "lastUpdated": "2024-01-02T03:04:05Z" }
                ]
            }] }]
        });
        assert!(
            find_gallery_exact_version(&response, "redhat.vscode-yaml", "1.24.0", "linux-x64")
                .flatten()
                .is_some()
        );
        assert_eq!(
            find_gallery_exact_version(&response, "redhat.vscode-yaml", "1.24.0", "win32-x64"),
            Some(None)
        );
        assert!(find_gallery_exact_version(
            &response,
            "redhat.vscode-yaml",
            "1.24.0",
            "darwin-arm64"
        )
        .is_none());
        assert!(
            find_gallery_exact_version(&response, "redhat.vscode-yaml", "1.24.0", "")
                .flatten()
                .is_some()
        );
    }

    #[test]
    fn gallery_result_count_reconciles_after_age_filtering() {
        let mut result = serde_json::json!({
            "extensions": [],
            "resultMetadata": [{
                "metadataType": "ResultCount",
                "metadataItems": [{ "name": "TotalCount", "count": 99 }]
            }]
        });
        reconcile_gallery_result_count(&mut result, 2);
        assert_eq!(result["resultMetadata"][0]["metadataItems"][0]["count"], 97);
    }

    async fn rewire_remote_gallery_with_age_gate(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        gallery_url: &str,
        mode: &str,
        min_age_days: i32,
    ) -> (SharedState, tempfile::TempDir) {
        use crate::api::handlers::test_db_helpers as tdh;

        sqlx::query(
            "UPDATE repositories
             SET upstream_url = $1, is_public = true, age_gate_enabled = true,
                 age_gate_mode = $2, age_gate_min_age_days = $3
             WHERE id = $4",
        )
        .bind(gallery_url)
        .bind(mode)
        .bind(min_age_days)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("configure VS Code age gate");
        let cache = tempfile::tempdir().expect("cache directory");
        let proxy = tdh::build_proxy_service_with_fs(
            fx.pool.clone(),
            cache.path().to_str().expect("UTF-8 cache path"),
        );
        let state = tdh::build_state_with_proxy_and_age_gate(
            fx.pool.clone(),
            cache.path().to_str().expect("UTF-8 cache path"),
            proxy,
        );
        (state, cache)
    }

    fn gallery_extension_response(versions: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "results": [{
                "extensions": [{
                    "publisher": { "publisherName": "RedHat" },
                    "extensionName": "VSCode-YAML",
                    "versions": versions
                }],
                "resultMetadata": [{
                    "metadataType": "ResultCount",
                    "metadataItems": [{ "name": "TotalCount", "count": 1 }]
                }]
            }]
        })
    }

    #[tokio::test]
    async fn gallery_age_gate_filters_young_missing_and_malformed_versions_before_rewrite() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let old = (Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        let young = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .respond_with(ResponseTemplate::new(200).set_body_json(gallery_extension_response(
                serde_json::json!([
                    { "version": "1.0.0", "targetPlatform": "linux-x64", "lastUpdated": old, "assetUri": "https://upstream/old" },
                    { "version": "2.0.0", "targetPlatform": "linux-x64", "lastUpdated": young, "assetUri": "https://upstream/young" },
                    { "version": "3.0.0", "targetPlatform": "linux-x64", "assetUri": "https://upstream/missing" },
                    { "version": "4.0.0", "targetPlatform": "linux-x64", "lastUpdated": "not-rfc3339", "assetUri": "https://upstream/malformed" }
                ]),
            )))
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) =
            rewire_remote_gallery_with_age_gate(&fx, &gallery_root, "upstream_publish_time", 30)
                .await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"{\"filters\":[],\"flags\":511}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = response["results"][0]["extensions"][0]["versions"]
            .as_array()
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "1.0.0");
        assert_eq!(
            response["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"],
            1
        );
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_latest_returns_not_found_when_age_filter_leaves_no_version() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(gallery_extension_response(
                    serde_json::json!([{
                        "version": "1.0.0",
                        "targetPlatform": "linux-x64",
                        "lastUpdated": (Utc::now() - chrono::Duration::days(1)).to_rfc3339(),
                        "assetUri": "https://upstream/young"
                    }]),
                )),
            )
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) =
            rewire_remote_gallery_with_age_gate(&fx, &gallery_root, "upstream_publish_time", 30)
                .await;
        for path in [
            format!("/{}/gallery/RedHat/VSCode-YAML/latest", fx.repo_key),
            format!("/{}/gallery/vscode/RedHat/VSCode-YAML/latest", fx.repo_key),
        ] {
            let (status, _) = tdh::send(
                tdh::router_anon(super::router(), state.clone()),
                tdh::get(path),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_age_gate_first_seen_observes_the_platform_qualified_coordinate() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .respond_with(ResponseTemplate::new(200).set_body_json(gallery_extension_response(
                serde_json::json!([
                    { "version": "1.0.0", "targetPlatform": "linux-x64", "assetUri": "https://upstream/linux" },
                    { "version": "1.0.0", "targetPlatform": "win32-x64", "assetUri": "https://upstream/windows" }
                ]),
            )))
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) =
            rewire_remote_gallery_with_age_gate(&fx, &gallery_root, "first_seen", 30).await;
        let query = || {
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"{\"filters\":[],\"flags\":511}"),
            )
        };
        let (initial_status, initial_body) =
            tdh::send(tdh::router_anon(super::router(), state.clone()), query()).await;
        assert_eq!(initial_status, StatusCode::OK);
        assert!(
            serde_json::from_slice::<serde_json::Value>(&initial_body).unwrap()["results"][0]
                ["extensions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        // Age only Linux's observation. Windows must remain withheld even
        // though it shares publisher, extension, and version text.
        sqlx::query(
            "UPDATE age_gate_version_observations
             SET first_seen_at = NOW() - INTERVAL '31 days'
             WHERE repository_id = $1 AND package_name = 'redhat.vscode-yaml'
               AND package_version = '1.0.0@linux-x64'",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        let (aged_status, aged_body) =
            tdh::send(tdh::router_anon(super::router(), state), query()).await;
        assert_eq!(aged_status, StatusCode::OK);
        let aged_json = serde_json::from_slice::<serde_json::Value>(&aged_body).unwrap();
        let versions = aged_json["results"][0]["extensions"][0]["versions"]
            .as_array()
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["targetPlatform"], "linux-x64");
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_delivery_age_gate_blocks_before_cache_then_honors_manual_review() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let young = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(gallery_extension_response(
                    serde_json::json!([{
                        "version": "1.0.0",
                        "targetPlatform": "linux-x64",
                        "lastUpdated": young
                    }]),
                )),
            )
            .mount(&server)
            .await;
        let bytes = b"reviewed-vsix";
        Mock::given(method("GET"))
            .and(path(
                "/vscode/gallery/publishers/RedHat/vsextensions/VSCode-YAML/1.0.0/vspackage",
            ))
            .and(query_param("targetPlatform", "linux-x64"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            // First request is 451, second fills the cache after approval,
            // and the final rejected request must be stopped before this
            // cache entry is read or this upstream endpoint is retried.
            .expect(1)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, cache) =
            rewire_remote_gallery_with_age_gate(&fx, &gallery_root, "upstream_publish_time", 30)
                .await;
        let request = || {
            tdh::get(format!(
                "/{}/gallery/publishers/RedHat/vsextensions/VSCode-YAML/1.0.0/vspackage?targetPlatform=linux-x64",
                fx.repo_key
            ))
        };
        let (blocked_status, blocked_body) =
            tdh::send(tdh::router_anon(super::router(), state.clone()), request()).await;
        assert_eq!(blocked_status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        let blocked: serde_json::Value = serde_json::from_slice(&blocked_body).unwrap();
        assert_eq!(blocked["error"], "age_gate_blocked");
        assert_eq!(blocked["package"], "redhat.vscode-yaml");
        assert_eq!(blocked["version"], "1.0.0@linux-x64");
        let review_id: uuid::Uuid = serde_json::from_value(blocked["review_id"].clone()).unwrap();
        state
            .age_gate_service
            .as_ref()
            .unwrap()
            .approve(review_id, fx.user_id, Some("reviewed"))
            .await
            .unwrap();

        let (allowed_status, allowed_body) =
            tdh::send(tdh::router_anon(super::router(), state.clone()), request()).await;
        assert_eq!(allowed_status, StatusCode::OK);
        assert_eq!(&allowed_body[..], bytes);
        tdh::wait_for_cache_commit(cache.path(), bytes.len() as u64).await;
        state
            .age_gate_service
            .as_ref()
            .unwrap()
            .reject(review_id, fx.user_id, Some("rejected"))
            .await
            .unwrap();
        let (rejected_status, rejected_body) =
            tdh::send(tdh::router_anon(super::router(), state), request()).await;
        assert_eq!(rejected_status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rejected_body).unwrap()["review_id"],
            review_id.to_string()
        );
        drop(server);
        fx.teardown().await;
    }
    #[tokio::test]
    async fn gallery_age_gate_without_service_fails_closed_for_metadata_and_delivery() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        sqlx::query(
            "UPDATE repositories
             SET upstream_url = 'https://open-vsx.example/vscode/gallery',
                 age_gate_enabled = true, age_gate_mode = 'upstream_publish_time'
             WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        // State intentionally has no AgeGateService. Delivery checks this
        // before cache/proxy construction.
        let app = fx.router_anon(super::router());
        let (delivery_status, _) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/gallery/publishers/publisher/vsextensions/extension/1.0.0/vspackage",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(delivery_status, StatusCode::SERVICE_UNAVAILABLE);
        let repo = resolve_vscode_repo(&fx.pool, &fx.repo_key).await.unwrap();
        let mut metadata = gallery_extension_response(serde_json::json!([{
            "version": "1.0.0",
            "lastUpdated": "2024-01-01T00:00:00Z"
        }]));
        let metadata_error = filter_gallery_response_age_gate(&fx.state, &repo, &mut metadata)
            .await
            .expect_err("configured gallery metadata cannot fail open without the service");
        assert_eq!(metadata_error.status(), StatusCode::SERVICE_UNAVAILABLE);
        fx.teardown().await;
    }

    #[test]
    fn gallery_manifest_uses_vscode_resource_wire_shape() {
        let base_url = RequestBaseUrl("https://ak.example".to_string());
        let manifest = build_gallery_manifest(&base_url, "extensions");
        assert_eq!(manifest["resources"][0]["type"], "ExtensionQueryService");
        assert_eq!(
            manifest["resources"][0]["id"],
            "https://ak.example/vscode/extensions/gallery/extensionquery"
        );
        assert_eq!(
            manifest["resources"][1]["type"],
            "ExtensionLatestVersionUriTemplate"
        );
        assert_eq!(
            manifest["resources"][1]["id"],
            "https://ak.example/vscode/extensions/gallery/{publisher}/{name}/latest"
        );
        assert_eq!(
            manifest["resources"][2]["id"],
            "https://ak.example/vscode/extensions/item?itemName={publisher}.{name}"
        );
        assert_eq!(manifest["version"], "");
        assert!(manifest["resources"][0].get("url").is_none());
        let query = &manifest["capabilities"]["extensionQuery"];
        assert_eq!(
            query["filtering"],
            serde_json::json!([
                { "name": "Tag", "value": 1 },
                { "name": "ExtensionId", "value": 4 },
                { "name": "Category", "value": 5 },
                { "name": "ExtensionName", "value": 7 },
                { "name": "Target", "value": 8 },
                { "name": "Featured", "value": 9 },
                { "name": "SearchText", "value": 10 },
                { "name": "ExcludeWithFlags", "value": 12 }
            ])
        );
        assert_eq!(
            query["sorting"],
            serde_json::json!([
                { "name": "NoneOrRelevance", "value": 0 },
                { "name": "LastUpdatedDate", "value": 1 },
                { "name": "Title", "value": 2 },
                { "name": "PublisherName", "value": 3 },
                { "name": "InstallCount", "value": 4 },
                { "name": "AverageRating", "value": 6 },
                { "name": "PublishedDate", "value": 10 },
                { "name": "WeightedRating", "value": 12 }
            ])
        );
        assert_eq!(
            query["flags"].as_array().unwrap()[11],
            serde_json::json!({ "name": "Unpublished", "value": 4096 })
        );
        assert_eq!(
            query["flags"].as_array().unwrap()[13],
            serde_json::json!({
                "name": "IncludeLatestPrereleaseAndStableVersionOnly",
                "value": 65536
            })
        );
    }

    #[test]
    fn openvsx_asset_url_uses_gallery_adapter_sibling_and_platform() {
        assert_eq!(
            openvsx_asset_url(
                "https://open-vsx.example/vscode/gallery",
                "publisher",
                "extension",
                "1.2.3",
                "README.md",
                "linux-x64",
            )
            .unwrap(),
            "https://open-vsx.example/vscode/asset/publisher/extension/1.2.3/README.md?targetPlatform=linux-x64"
        );
        assert!(openvsx_asset_url(
            "https://open-vsx.example/not-gallery",
            "publisher",
            "extension",
            "1.2.3",
            "README.md",
            "universal",
        )
        .is_err());
    }

    #[test]
    fn malformed_gallery_extension_cannot_leave_upstream_assets_in_response() {
        let mut malformed = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": "publisher" },
                "extensionName": "extension",
                "versions": [{ "assetUri": "https://upstream.example/assets" }]
            }] }]
        });
        assert!(rewrite_gallery_asset_urls(
            &mut malformed,
            &RequestBaseUrl("https://ak.example".to_string()),
            "extensions",
        )
        .is_err());
    }

    #[test]
    fn gallery_rewrite_rejects_unsafe_upstream_coordinates() {
        let mut response = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": "publisher" },
                "extensionName": "extension",
                "versions": [{
                    "version": "1.2.3",
                    "targetPlatform": "../other-platform",
                    "assetUri": "https://upstream.example/assets"
                }]
            }] }]
        });

        assert!(rewrite_gallery_asset_urls(
            &mut response,
            &RequestBaseUrl("https://ak.example".to_string()),
            "extensions",
        )
        .is_err());
    }

    #[test]
    fn gallery_path_segments_reject_url_and_cache_key_escapes() {
        for value in ["", ".", "..", "a/b", "a\\b", "a?b", "a#b", "a\u{7f}b"] {
            assert!(!is_safe_gallery_segment(value), "{value:?}");
        }
        assert!(is_safe_gallery_segment(
            "Microsoft.VisualStudio.Services.VSIXPackage"
        ));
        assert!(is_safe_gallery_segment("linux-x64"));
    }

    #[test]
    fn gallery_metadata_cap_charges_the_full_parse_and_serialize_working_set() {
        assert_eq!(
            GALLERY_METADATA_MAX_BYTES,
            2 * 1024 * 1024,
            "gallery responses use the conservative gallery-specific wire cap"
        );
        assert_eq!(
            GALLERY_METADATA_BUDGET_RESERVATION_BYTES,
            GALLERY_METADATA_MAX_BYTES * 32,
            "raw Bytes + adversarially expanded JSON + serialized response need a whole-request charge"
        );
        assert_eq!(
            proxy_helpers::DEFAULT_PROXY_METADATA_BUDGET_BYTES
                / GALLERY_METADATA_BUDGET_RESERVATION_BYTES,
            16,
            "the default shared budget admits at most 16 cap-sized gallery queries"
        );

        let budget =
            proxy_helpers::ProxyMetadataBudget::new(GALLERY_METADATA_BUDGET_RESERVATION_BYTES * 2);
        let first = budget
            .try_reserve(GALLERY_METADATA_BUDGET_RESERVATION_BYTES)
            .expect("first gallery working set fits");
        let second = budget
            .try_reserve(GALLERY_METADATA_BUDGET_RESERVATION_BYTES)
            .expect("second gallery working set fits");
        assert!(
            budget
                .try_reserve(GALLERY_METADATA_BUDGET_RESERVATION_BYTES)
                .is_none(),
            "a third concurrent parsed gallery response exceeds its reserved working-set budget"
        );
        drop((first, second));
    }

    #[tokio::test]
    async fn gallery_extensionquery_rejects_oversized_body_before_database_work() {
        use crate::api::handlers::test_db_helpers as tdh;

        let state = tdh::build_state(tdh::lazy_pool(), "/tmp/vscode-gallery-body-limit");
        let app = tdh::router_anon(super::router(), state);
        let (status, _) = tdh::send(
            app,
            tdh::post(
                "/any/gallery/extensionquery".to_string(),
                "application/json",
                Bytes::from(vec![b'x'; GALLERY_QUERY_BODY_MAX_BYTES + 1]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn gallery_extensionquery_rejects_malformed_client_json_without_proxying() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        // Gallery endpoints require a gallery-root upstream even though this
        // malformed body must be rejected before any upstream request.
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, _) = tdh::send(
            app,
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"not-json"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        drop(server);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_routes_reject_non_remote_repositories() {
        use crate::api::handlers::test_db_helpers as tdh;

        for repo_type in ["local", "virtual"] {
            let Some(fx) = tdh::Fixture::setup(repo_type, "vscode").await else {
                return;
            };
            for request in [
                tdh::get(format!("/{}/gallery/manifest", fx.repo_key)),
                tdh::post(
                    format!("/{}/gallery/extensionquery", fx.repo_key),
                    "application/json",
                    Bytes::from_static(b"{}"),
                ),
            ] {
                let app = fx.router_anon(super::router());
                let (status, _) = tdh::send(app, request).await;
                assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{repo_type}");
            }
            fx.teardown().await;
        }
    }

    #[tokio::test]
    async fn gallery_routes_reject_private_remote_even_for_authenticated_reader() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        sqlx::query("UPDATE repositories SET is_public = false WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("make Remote gallery repository private");

        // Exercise the production routing stack with a real bearer for a
        // repository member. Visibility middleware permits this authenticated
        // private read, so the assertion proves the gallery's own public-Remote
        // capability gate still rejects every new route before proxy/cache work.
        let bearer = tdh::bearer_for(&fx.state, fx.user_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());
        for mut request in [
            tdh::get(format!("/vscode/{}/gallery/manifest", fx.repo_key)),
            tdh::post(
                format!("/vscode/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"{}"),
            ),
            tdh::get(format!(
                "/vscode/{}/gallery/publisher/extension/latest",
                fx.repo_key
            )),
            tdh::get(format!(
                "/vscode/{}/gallery/vscode/publisher/extension/latest",
                fx.repo_key
            )),
            tdh::get(format!(
                "/vscode/{}/gallery/publishers/publisher/vsextensions/extension/1.2.3/vspackage",
                fx.repo_key
            )),
            tdh::get(format!(
                "/vscode/{}/asset/publisher/extension/1.2.3/universal/vspackage",
                fx.repo_key
            )),
            tdh::get(format!("/vscode/{}/item", fx.repo_key)),
        ] {
            request.headers_mut().insert(
                "authorization",
                bearer
                    .parse::<axum::http::HeaderValue>()
                    .expect("valid bearer header"),
            );
            let (status, _) = tdh::send(app.clone(), request).await;
            assert_eq!(
                status,
                StatusCode::NOT_IMPLEMENTED,
                "private Remote gallery route must remain unsupported"
            );
        }
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_routes_reject_percent_decoded_unsafe_coordinates_before_proxying() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;

        // Axum extracts a decoded Path<String>, not a raw URL segment. Pin all
        // representative escapes at router level so none can reach upstream URL
        // or cache-key construction in gallery_asset/gallery_vspackage.
        for (case, uri) in [
            (
                "encoded slash on asset",
                format!(
                    "/{}/asset/publisher%2Fescape/extension/1.2.3/universal/vspackage",
                    fx.repo_key
                ),
            ),
            (
                "encoded dot segment on asset",
                format!(
                    "/{}/asset/publisher/extension/%2e%2e/universal/vspackage",
                    fx.repo_key
                ),
            ),
            (
                "encoded backslash on vspackage",
                format!(
                    "/{}/gallery/publishers/publisher/vsextensions/extension%5Cescape/1.2.3/vspackage",
                    fx.repo_key
                ),
            ),
            (
                "encoded control on vspackage",
                format!(
                    "/{}/gallery/publishers/publisher/vsextensions/extension/1.2.3%00/vspackage",
                    fx.repo_key
                ),
            ),
        ] {
            let (status, _) = tdh::send(
                tdh::router_anon(super::router(), state.clone()),
                tdh::get(uri),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
        }
        // wiremock's expect(0) is the load-bearing proof that validation ran
        // before proxy/cache construction could issue an upstream request.
        drop(server);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn legacy_api_extensionquery_remains_distinct_from_gallery_gateway() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "vscode").await else {
            return;
        };
        let app = fx.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/api/extensionquery", fx.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(serde_json::from_slice::<serde_json::Value>(&body)
            .unwrap()
            .get("results")
            .is_some());
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_openvsx_extensionquery_posts_and_rewrites_every_asset_url() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let query = serde_json::json!({"filters": [], "flags": 511});
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(header(
                "accept",
                "application/json;api-version=3.0-preview.1",
            ))
            .and(body_json(&query))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "extensions": [{
                        "publisher": { "publisherName": "publisher" },
                        "extensionName": "extension",
                        "unknownExtensionField": "preserved",
                        "versions": [{
                            "version": "1.2.3",
                            "targetPlatform": "linux-x64",
                            "assetUri": "https://upstream.example/assets",
                            "fallbackAssetUri": "https://cdn.example/assets",
                            "files": [{
                                "assetType": "README.md",
                                "source": "https://cdn.example/README.md",
                                "unknownFileField": true
                            }]
                        }]
                    }]
                }]
            })))
            .mount(&server)
            .await;

        let readme_bytes = b"# proxied readme\n";
        Mock::given(method("GET"))
            .and(path("/vscode/asset/publisher/extension/1.2.3/README.md"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(readme_bytes))
            .mount(&server)
            .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;
        let app = tdh::router_anon(super::router(), state.clone());
        let (status, body) = tdh::send(
            app,
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&query).unwrap()),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "gateway must return query result");
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let version = &response["results"][0]["extensions"][0]["versions"][0];
        let expected_base = format!(
            "http://localhost/vscode/{}/asset/publisher/extension/1.2.3/linux-x64",
            fx.repo_key
        );
        assert_eq!(version["assetUri"], expected_base);
        assert_eq!(version["fallbackAssetUri"], expected_base);
        assert_eq!(
            version["files"][0]["source"],
            format!("{expected_base}/README.md")
        );
        assert_eq!(version["files"][0]["unknownFileField"], true);
        assert_eq!(
            response["results"][0]["extensions"][0]["unknownExtensionField"],
            "preserved"
        );
        assert!(!body
            .windows(b"upstream.example".len())
            .any(|w| w == b"upstream.example"));
        assert!(!body
            .windows(b"cdn.example".len())
            .any(|w| w == b"cdn.example"));

        // VS Code composes normal resources as `assetUri + '/' + assetType`.
        // A trailing slash in our base would make this `//README.md` and miss
        // the route, so execute the composed path through the real router.
        let composed = format!("{}/README.md", version["assetUri"].as_str().unwrap());
        let composed_url = reqwest::Url::parse(&composed).unwrap();
        // This unit test exercises the VS Code subrouter directly; production
        // mounts it at `/vscode`, so remove that outer mount before dispatch.
        let subrouter_path = composed_url.path().strip_prefix("/vscode").unwrap();
        let (asset_status, asset_body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(subrouter_path.to_string()),
        )
        .await;
        assert_eq!(asset_status, StatusCode::OK);
        assert_eq!(&asset_body[..], readme_bytes);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_extensionquery_maps_malformed_upstream_json_to_bad_gateway() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, _) = tdh::send(
            app,
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"{\"filters\":[],\"flags\":511}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_latest_returns_one_extension_not_query_envelope() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let expected_query = serde_json::json!({
            "filters": [{
                "criteria": [{ "filterType": 7, "value": "publisher.extension" }],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 0,
                "sortOrder": 0,
            }],
            "flags": 511,
        });
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(expected_query))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{ "extensions": [{
                    "publisher": { "publisherName": "publisher" },
                    "extensionName": "extension",
                    "versions": [{
                        "version": "1.2.3",
                        "targetPlatform": "linux-x64",
                        "assetUri": "https://upstream.example/assets",
                        "fallbackAssetUri": "https://cdn.example/assets"
                    }]
                }] }]
            })))
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;
        let app = tdh::router_anon(super::router(), state.clone());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/gallery/publisher/extension/latest",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let extension: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(extension["extensionName"], "extension");
        assert!(extension.get("results").is_none());
        assert!(extension["versions"][0]["assetUri"]
            .as_str()
            .unwrap()
            .contains(&format!("/vscode/{}/asset/", fx.repo_key)));

        let (code_server_status, code_server_body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{}/gallery/vscode/publisher/extension/latest",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(code_server_status, StatusCode::OK);
        let code_server_extension: serde_json::Value =
            serde_json::from_slice(&code_server_body).unwrap();
        assert_eq!(code_server_extension["extensionName"], "extension");
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_vspackage_preserves_binary_bytes_and_isolates_platform_cache() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let linux = b"\x00linux-vsix\xff".to_vec();
        let windows = b"\x01windows-vsix\xfe".to_vec();
        let upstream_path =
            "/vscode/gallery/publishers/publisher/vsextensions/extension/1.2.3/vspackage";
        Mock::given(method("GET"))
            .and(path(upstream_path))
            .and(query_param("targetPlatform", "linux-x64"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(linux.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(upstream_path))
            .and(query_param("targetPlatform", "win32-x64"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(windows.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;

        let request = |platform: &str| {
            tdh::get(format!(
                "/{}/gallery/publishers/publisher/vsextensions/extension/1.2.3/vspackage?targetPlatform={platform}",
                fx.repo_key
            ))
        };
        let (linux_status, linux_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            request("linux-x64"),
        )
        .await;
        assert_eq!(linux_status, StatusCode::OK);
        assert_eq!(&linux_body[..], &linux);
        tdh::wait_for_cache_commit(cache.path(), linux.len() as u64).await;

        let (windows_status, windows_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            request("win32-x64"),
        )
        .await;
        assert_eq!(windows_status, StatusCode::OK);
        assert_eq!(&windows_body[..], &windows);

        let (warm_status, warm_body) = tdh::send(
            tdh::router_anon(super::router(), state),
            request("linux-x64"),
        )
        .await;
        assert_eq!(warm_status, StatusCode::OK);
        assert_eq!(&warm_body[..], &linux);
        // Each mock has expect(1): the final Linux request must use the
        // completed cache entry rather than refetching the binary upstream.
        drop(server);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn gallery_asset_uses_openvsx_sibling_endpoint_with_platform() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let body = b"# extension readme\n";
        Mock::given(method("GET"))
            .and(path(
                "/vscode/asset/publisher/extension/1.2.3/Microsoft.VisualStudio.Services.Content.Details",
            ))
            .and(query_param("targetPlatform", "linux-x64"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &gallery_root).await;
        let (status, received) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{}/asset/publisher/extension/1.2.3/linux-x64/Microsoft.VisualStudio.Services.Content.Details",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&received[..], body);
        drop(server);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_remote_vsix_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/extensions/ms-python/python/1.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/extensions/ms-python/python/1.0.0/download",
                key = fx.repo_key
            )),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from streamed remote download, got {status}");
        }
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        teardown().await;
    }
    use super::*;

    // -----------------------------------------------------------------------
    // extract_credentials — Bearer token
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_credentials — Basic auth
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_credentials — edge cases
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // build_extension_id
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_extension_id() {
        assert_eq!(
            build_extension_id("ms-python", "python"),
            "ms-python.python"
        );
    }

    #[test]
    fn test_build_extension_id_complex() {
        assert_eq!(
            build_extension_id("esbenp", "prettier-vscode"),
            "esbenp.prettier-vscode"
        );
    }

    #[test]
    fn test_build_extension_id_single_char() {
        assert_eq!(build_extension_id("a", "b"), "a.b");
    }

    // -----------------------------------------------------------------------
    // build_vsix_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vsix_filename() {
        assert_eq!(
            build_vsix_filename("ms-python", "python", "2024.1.0"),
            "ms-python.python-2024.1.0.vsix"
        );
    }

    #[test]
    fn test_build_vsix_filename_prerelease() {
        assert_eq!(
            build_vsix_filename("ms-vscode", "cpptools", "1.18.0-insiders"),
            "ms-vscode.cpptools-1.18.0-insiders.vsix"
        );
    }

    #[test]
    fn test_build_vsix_filename_ends_with_vsix() {
        let f = build_vsix_filename("a", "b", "1.0.0");
        assert!(f.ends_with(".vsix"));
    }

    // -----------------------------------------------------------------------
    // build_vscode_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vscode_artifact_path() {
        assert_eq!(
            build_vscode_artifact_path("ms-python", "python", "2024.1.0"),
            "ms-python/python/ms-python.python-2024.1.0.vsix"
        );
    }

    #[test]
    fn test_build_vscode_artifact_path_contains_publisher() {
        let path = build_vscode_artifact_path("esbenp", "prettier-vscode", "10.1.0");
        assert!(path.starts_with("esbenp/"));
    }

    #[test]
    fn test_build_vscode_artifact_path_contains_name() {
        let path = build_vscode_artifact_path("redhat", "vscode-yaml", "1.14.0");
        assert!(path.contains("/vscode-yaml/"));
    }

    // -----------------------------------------------------------------------
    // build_vscode_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vscode_storage_key() {
        assert_eq!(
            build_vscode_storage_key("esbenp", "prettier-vscode", "10.1.0"),
            "vscode/esbenp/prettier-vscode/esbenp.prettier-vscode-10.1.0.vsix"
        );
    }

    #[test]
    fn test_build_vscode_storage_key_starts_with_vscode() {
        let key = build_vscode_storage_key("ms-python", "python", "1.0.0");
        assert!(key.starts_with("vscode/"));
    }

    #[test]
    fn test_build_vscode_storage_key_ends_with_vsix() {
        let key = build_vscode_storage_key("ms-vscode", "cpptools", "1.18.0");
        assert!(key.ends_with(".vsix"));
    }

    // -----------------------------------------------------------------------
    // build_vscode_download_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vscode_download_url() {
        assert_eq!(
            build_vscode_download_url("vscode-local", "ms-vscode", "cpptools", "1.18.0"),
            "/vscode/vscode-local/extensions/ms-vscode/cpptools/1.18.0/download"
        );
    }

    #[test]
    fn test_build_vscode_download_url_starts_with_vscode() {
        let url = build_vscode_download_url("repo", "pub", "ext", "1.0.0");
        assert!(url.starts_with("/vscode/"));
    }

    #[test]
    fn test_build_vscode_download_url_ends_with_download() {
        let url = build_vscode_download_url("repo", "pub", "ext", "1.0.0");
        assert!(url.ends_with("/download"));
    }

    // -----------------------------------------------------------------------
    // build_vsix_download_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vsix_download_filename() {
        assert_eq!(
            build_vsix_download_filename("redhat", "vscode-yaml", "1.14.0"),
            "redhat.vscode-yaml-1.14.0.vsix"
        );
    }

    #[test]
    fn test_build_vsix_download_filename_contains_publisher() {
        let f = build_vsix_download_filename("ms-python", "python", "2024.1.0");
        assert!(f.starts_with("ms-python."));
    }

    #[test]
    fn test_build_vsix_download_filename_ends_with_vsix() {
        let f = build_vsix_download_filename("a", "b", "1.0.0");
        assert!(f.ends_with(".vsix"));
    }

    // -----------------------------------------------------------------------
    // build_vscode_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vscode_metadata() {
        let meta = build_vscode_metadata("ms-python", "python", "2024.1.0");
        assert_eq!(meta["publisher"], "ms-python");
        assert_eq!(meta["extension_name"], "python");
        assert_eq!(meta["version"], "2024.1.0");
        assert_eq!(meta["filename"], "ms-python.python-2024.1.0.vsix");
    }

    #[test]
    fn test_build_vscode_metadata_has_four_keys() {
        let meta = build_vscode_metadata("a", "b", "1.0.0");
        assert_eq!(meta.as_object().unwrap().len(), 4);
    }

    #[test]
    fn test_build_vscode_metadata_has_all_keys() {
        let meta = build_vscode_metadata("pub", "ext", "1.0.0");
        let obj = meta.as_object().unwrap();
        assert!(obj.contains_key("publisher"));
        assert!(obj.contains_key("extension_name"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("filename"));
    }

    // -----------------------------------------------------------------------
    // build_vscode_publish_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_vscode_publish_response() {
        let resp = build_vscode_publish_response("ms-python", "python", "2024.1.0");
        assert_eq!(resp["publisher"], "ms-python");
        assert_eq!(resp["name"], "python");
        assert_eq!(resp["version"], "2024.1.0");
        assert_eq!(resp["message"], "Successfully published extension");
    }

    #[test]
    fn test_build_vscode_publish_response_has_message() {
        let resp = build_vscode_publish_response("a", "b", "1.0.0");
        assert!(resp["message"].as_str().unwrap().contains("published"));
    }

    #[test]
    fn test_build_vscode_publish_response_four_keys() {
        let resp = build_vscode_publish_response("a", "b", "1.0.0");
        assert_eq!(resp.as_object().unwrap().len(), 4);
    }

    // -----------------------------------------------------------------------
    // SHA256 computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let data = b"fake VSIX content";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        assert_eq!(hash.len(), 64);

        // Same data produces same hash
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let hash2 = format!("{:x}", hasher2.finalize());
        assert_eq!(hash, hash2);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/vscode-local".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(repo.storage_path, "/data/vscode-local");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/vscode-remote".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some(
                "https://marketplace.visualstudio.com/_apis/public/gallery".to_string(),
            ),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(repo.repo_type, "remote");
        assert!(repo.upstream_url.is_some());
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_vscode_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "vscode").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/extensions/pub/name/1.0.0/download"),
            format!("/{k}/api/extensions/pub/name/latest"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}
