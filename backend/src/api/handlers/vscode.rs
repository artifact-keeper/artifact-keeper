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
use std::borrow::Cow;
use tracing::info;

use crate::api::extractors::{request_base_url_from_host_header, RequestBaseUrl};
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
/// formats. Every document buffered under this cap is a bounded shape: a
/// per-extension detail query measures ~25 KiB and a client search page
/// ~1.2 MiB. A whole version history is never buffered here — that document is
/// projected through the skeleton path below, under its own cap.
const GALLERY_METADATA_MAX_BYTES: usize = 2 * 1024 * 1024;
/// One gallery query can simultaneously retain wire bytes, a parsed JSON tree,
/// and serialized output. Charge a conservative multiple of the wire cap
/// against the shared metadata budget for that whole working set; JSON DOM
/// allocations are much larger than wire bytes for many tiny values, so use a
/// 32× allowance. At the default 1 GiB budget this admits at most 16 cap-sized
/// gallery queries rather than several GiB of real memory.
const GALLERY_METADATA_BUDGET_RESERVATION_BYTES: usize = GALLERY_METADATA_MAX_BYTES * 32;
const GALLERY_QUERY_BODY_MAX_BYTES: usize = 1024 * 1024;
/// The version skeleton is the only gallery document whose size scales with an
/// extension's release history rather than with the client's page size. The
/// worst known case, rust-analyzer's 12,592 versions, measures 9.95 MiB at
/// [`GALLERY_SKELETON_QUERY_FLAGS`] (~790 B/version). 16 MiB admits it with
/// headroom while still refusing an unbounded document.
const GALLERY_SKELETON_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Skeleton bytes are deserialized into [`GallerySkeletonVersion`] rather than
/// into a `serde_json::Value` tree, so the 32× DOM allowance behind
/// [`GALLERY_METADATA_BUDGET_RESERVATION_BYTES`] does not apply. The honest
/// peak is still three things resident at once: the wire buffer (up to the
/// cap), serde's full materialization of every version's `properties` into
/// owned `String`s before this module discards all but two of them, and the
/// retained projection. For the measured 12,592-version worst case that is
/// ~10 MiB + ~11 MiB + ~2 MiB, so charge 4× the cap rather than pretending the
/// discarded properties are free.
const GALLERY_SKELETON_BUDGET_MULTIPLE: usize = 4;
const GALLERY_SKELETON_BUDGET_RESERVATION_BYTES: usize =
    GALLERY_SKELETON_MAX_BYTES * GALLERY_SKELETON_BUDGET_MULTIPLE;
/// `IncludeVersions`: the flag that makes Open VSX attach an extension's whole
/// version history to a result.
const GALLERY_INCLUDE_VERSIONS_FLAG: u32 = 1;
/// `IncludeFiles`: VS Code resolves an asset by filtering `versions[].files`
/// FIRST, so a version served without it is not installable.
const GALLERY_INCLUDE_FILES_FLAG: u32 = 2;
/// `IncludeVersionProperties`: carries the `PreRelease` and `Engine` properties
/// that decide channel and engine compatibility.
const GALLERY_VERSION_PROPERTIES_FLAG: u32 = 16;
/// `IncludeAssetUri`: without it Open VSX emits explicit `null` asset URIs, and
/// a synthesized version must match that shape rather than invent one.
const GALLERY_INCLUDE_ASSET_URI_FLAG: u32 = 128;
/// `IncludeLatestVersionOnly`. Open VSX honours it for single-ID queries
/// (`filterType` 4 or 7) and ignores it for every other query shape, which is
/// why bounding a multi-ID or search query means composing per identity rather
/// than rewriting the client's flags in place.
const GALLERY_LATEST_VERSION_ONLY_FLAG: u32 = 512;
/// The smallest query that still carries every version's `lastUpdated` and its
/// `PreRelease`/`Engine` properties. Files, asset URIs, statistics, and
/// categories are deliberately not requested: AK derives every asset reference
/// from repository configuration, so per-version upstream delivery metadata is
/// never needed and only inflates the buffered document.
const GALLERY_SKELETON_QUERY_FLAGS: u32 =
    GALLERY_INCLUDE_VERSIONS_FLAG | GALLERY_VERSION_PROPERTIES_FLAG;
/// Exact-version age-gate resolution reads only `version`, `targetPlatform`,
/// and `lastUpdated`, so it asks for nothing else: this runs on every gated
/// asset request — every icon on a search results page — and is never cached.
/// Dropping the properties measures 2.12 MiB against 9.95 MiB for the worst
/// known history. It still travels the skeleton path rather than the gallery
/// metadata path, because 2.12 MiB does not fit under the 2 MiB metadata cap.
const GALLERY_EXACT_VERSION_QUERY_FLAGS: u32 = GALLERY_INCLUDE_VERSIONS_FLAG;
/// The latest-version route serves one extension record with the same
/// client-visible metadata the previous 511 query returned;
/// `IncludeLatestVersionOnly` keeps Open VSX from attaching the whole version
/// history to it. This route addresses a single extension by name, which is a
/// shape Open VSX honours the flag for.
const GALLERY_LATEST_VERSION_QUERY_FLAGS: u32 = 511 | GALLERY_LATEST_VERSION_ONLY_FLAG;
/// `ExtensionId` and `ExtensionName`: the two criteria that address exactly one
/// extension, and therefore the two Open VSX honours
/// [`GALLERY_LATEST_VERSION_ONLY_FLAG`] for.
const GALLERY_EXTENSION_ID_FILTER: u64 = 4;
const GALLERY_EXTENSION_NAME_FILTER: u64 = 7;
/// `Target` and `ExcludeWithFlags` do not select extensions, they qualify the
/// selection — VS Code sends both alongside its identity criteria on a normal
/// update check. They neither prevent composition nor address an extension, so
/// they are repeated verbatim on every per-identity sub-query instead.
const GALLERY_TARGET_FILTER: u64 = 8;
const GALLERY_EXCLUDE_WITH_FLAGS_FILTER: u64 = 12;
/// Versions retained per (target platform, release channel) when a version
/// history is projected into a response. Upstream returns newest-first, so the
/// first K of each bucket are its newest; bucketing by platform AND channel is
/// what keeps the newest *stable* build reachable for an extension that
/// publishes mostly pre-releases (rust-analyzer's newest stable sits at index
/// 10,970 of 12,592, so any positional truncation loses the stable channel).
/// K = 30 bounds one extension's output to roughly 10 platforms × 2 channels ×
/// 30 × ~350 B ≈ 210 KiB.
const GALLERY_VERSIONS_PER_CHANNEL: usize = 30;
/// Composition issues two upstream queries per requested extension. Bound how
/// many extensions are in flight so a client query cannot fan out into
/// simultaneous upstream requests and budget reservations without limit.
const GALLERY_COMPOSITION_CONCURRENCY: usize = 4;
/// Composed responses admitted at once.
///
/// A composed page accumulates during the fan-out, before it can be charged
/// against the shared byte budget (see [`serve_composed_gallery_response`] for
/// why that charge cannot wrap the fan-out). This bounds how many such
/// accumulations exist at once, capping their total at
/// `GALLERY_COMPOSITION_ADMISSION × GALLERY_COMPOSED_IDENTITY_CAP ×
/// GALLERY_COMPOSED_EXTENSION_BYTES`.
///
/// It is deliberately a DIFFERENT resource from the byte budget, acquired in a
/// strict order — admission, then per-sub-query byte reservations, then the
/// composed byte reservation — and nothing that holds a byte reservation ever
/// waits for admission. A cycle, and therefore a deadlock, cannot form.
const GALLERY_COMPOSITION_ADMISSION: usize = 20;
/// Qualifier criteria one composed query may carry.
///
/// Every qualifier is replayed verbatim on every per-identity sub-query, so an
/// unbounded list multiplies into the outbound bodies: a full
/// [`GALLERY_QUERY_BODY_MAX_BYTES`] of qualifiers over a full identity page is
/// ~50 MiB of upstream requests. A body carrying more than this is NOT
/// composed with a truncated list — a qualifier changes which versions
/// upstream resolves, so composing without one answers a different question
/// than the client asked. It falls back to passthrough instead. VS Code sends
/// at most two.
const GALLERY_COMPOSED_QUALIFIER_CAP: usize = 8;
/// Ceiling on how many extensions one composed response may carry.
///
/// Concurrency bounds simultaneity, not total work: a
/// [`GALLERY_QUERY_BODY_MAX_BYTES`] body admits roughly 36,000 identity
/// criteria, which composition would turn into ~72,000 upstream round-trips,
/// as many repository lookups, and an unbounded composed document. The gallery
/// protocol is paged, so truncating to a page is the protocol-shaped answer
/// rather than an error; 50 is the largest `pageSize` VS Code sends.
const GALLERY_COMPOSED_IDENTITY_CAP: usize = 50;
/// Bounded serialized output for one composed extension: roughly 10 target
/// platforms × 2 release channels × [`GALLERY_VERSIONS_PER_CHANNEL`] entries ×
/// ~750 B per entry (coordinate, timestamp, two properties, and the four
/// synthesized file references) ≈ 450 KiB. Rounded up to 512 KiB.
const GALLERY_COMPOSED_EXTENSION_BYTES: usize = 512 * 1024;
/// The composed page is held as a `serde_json::Value` tree AND as the
/// serialized response body at the same time, so charge twice the bounded
/// output of a full page. At the default 1 GiB budget this admits 20
/// concurrent composed responses.
const GALLERY_COMPOSITION_BUDGET_RESERVATION_BYTES: usize =
    GALLERY_COMPOSED_IDENTITY_CAP * GALLERY_COMPOSED_EXTENSION_BYTES * 2;
/// The two version properties VS Code reads to resolve release channel and
/// engine compatibility, and therefore the only two the skeleton retains.
const GALLERY_PRERELEASE_PROPERTY: &str = "Microsoft.VisualStudio.Code.PreRelease";
const GALLERY_ENGINE_PROPERTY: &str = "Microsoft.VisualStudio.Code.Engine";
/// Asset types a synthesized version advertises in its `files` list.
///
/// VS Code's asset resolution filters `versions[].files` BEFORE it looks at
/// `assetUri`, so a version served without a file list is not installable no
/// matter how correct its asset URI is. Every entry is derived from the same
/// AK asset base the rewrite pass builds, so a synthesized list is
/// byte-identical in shape to a rewritten one and resolves through the same
/// [`gallery_asset`] route.
const GALLERY_SYNTHESIZED_ASSET_TYPES: [&str; 4] = [
    "Microsoft.VisualStudio.Services.VSIXPackage",
    "Microsoft.VisualStudio.Code.Manifest",
    "Microsoft.VisualStudio.Services.Content.Details",
    "Microsoft.VisualStudio.Services.Icons.Default",
];
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

fn unsupported_gallery_repo_type(repo: &RepoInfo) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        format!(
            "VS Code gallery routes require a Remote repository ({} is {})",
            repo.key, repo.repo_type
        ),
    )
        .into_response()
}

fn private_gallery_forbidden(repo: &RepoInfo) -> Response {
    (
        StatusCode::FORBIDDEN,
        format!(
            "VS Code gallery routes are public-only: repository {} is private. Gallery clients cannot present a credential, so private galleries are not supported. Make the repository public or use the /vscode/{}/extensions/... routes.",
            repo.key, repo.key
        ),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
async fn gallery_upstream<'a>(db: &PgPool, repo: &'a RepoInfo) -> Result<&'a str, Response> {
    if repo.repo_type != RepositoryType::Remote {
        return Err(unsupported_gallery_repo_type(repo));
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
        return Err(private_gallery_forbidden(repo));
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

/// Validate one upstream version coordinate and return the AK asset base URL it
/// maps to. Both the rewrite pass over an upstream document and the synthesis
/// of a version entry AK builds itself go through this, so a synthesized
/// `assetUri` cannot drift from a rewritten one — a drift would send clients to
/// a URL shape [`gallery_asset`] does not route. `target_platform` must already
/// be normalized by [`normal_target_platform`]; the coordinate reaches both a
/// client-visible URL and a proxy cache key, so it is validated as untrusted
/// upstream input regardless of which caller supplied it.
#[allow(clippy::result_large_err)]
fn gallery_version_asset_base(
    base_url: &RequestBaseUrl,
    repo_key: &str,
    publisher: &str,
    name: &str,
    version: &str,
    target_platform: &str,
) -> Result<String, Response> {
    validate_gallery_response_segment(version)?;
    validate_target_platform(target_platform, true)?;
    Ok(gallery_asset_base_url(
        base_url,
        repo_key,
        publisher,
        name,
        version,
        target_platform,
    ))
}

fn normal_target_platform(platform: Option<&str>) -> Cow<'_, str> {
    let value = platform
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_TARGET_PLATFORM);
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

/// Identity used by the shared age-gate policy. Gallery publisher and
/// extension names are case-insensitive, while Open VSX platform variants are
/// independently immutable coordinates. Keep the platform in the version
/// field because that is the shared review/first-seen key shape.
fn vscode_age_gate_package(publisher: &str, name: &str) -> String {
    format!("{}.{}", publisher, name).to_ascii_lowercase()
}

fn vscode_age_gate_version(version: &str, target_platform: Option<&str>) -> String {
    format!("{}@{}", version, normal_target_platform(target_platform))
}

/// `lastUpdated` is Open VSX gallery's publish-time evidence. Deliberately
/// return `None` for absent or malformed values: upstream-publish-time mode
/// treats no evidence as ineligible, while first-seen ignores it and uses the
/// positive existence evidence supplied by the containing gallery document.
fn gallery_last_updated(version: &serde_json::Value) -> Option<DateTime<Utc>> {
    version
        .get("lastUpdated")
        .and_then(serde_json::Value::as_str)
        .and_then(gallery_parse_last_updated)
}

fn gallery_parse_last_updated(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// Gallery coordinates become both upstream URL components and cache-key
/// components. Route matching already excludes literal slashes, but retain an
/// explicit boundary for decoded paths and for values supplied by upstream
/// metadata before we rewrite them into AK URLs.
fn is_safe_gallery_segment(value: &str) -> bool {
    // Coordinates also become filesystem path components under the proxy cache
    // root, where a component over 255 bytes is ENAMETOOLONG on ext4 and xfs.
    // Refuse them here rather than surfacing a storage error later.
    !value.is_empty()
        && value.len() <= 255
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

fn is_safe_target_platform(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

#[allow(clippy::result_large_err)]
fn validate_target_platform(value: &str, upstream_response: bool) -> Result<(), Response> {
    if is_safe_target_platform(value) {
        Ok(())
    } else if upstream_response {
        Err(invalid_gallery_response())
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid VS Code target platform").into_response())
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

/// Rewrite every gallery **asset-delivery** reference to AK — `assetUri`,
/// `fallbackAssetUri`, and each `files[].source`. Those are the fields VS Code
/// composes install and update fetches from, and none of them retains an
/// upstream absolute URL afterwards: Open VSX's gallery adapter has stable
/// sibling `/vscode/asset/...` endpoints, so delivery reconstructs the upstream
/// target from repository configuration instead of treating metadata as an
/// arbitrary fetch capability.
///
/// Non-asset URLs the gallery carries elsewhere — `versions[].properties[]`
/// entries such as `Microsoft.VisualStudio.Services.Links.Source` or
/// `Microsoft.VisualStudio.Code.SponsorLink`, and `publisher.domain` — are
/// passed through unchanged. They are display/navigation links the client
/// opens in a browser, not part of the install path, so they are out of scope
/// for egress control here. Do not read this function as "no upstream URL
/// survives anywhere in the document".
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
                let target_platform = normal_target_platform(
                    version
                        .get("targetPlatform")
                        .and_then(|value| value.as_str()),
                );
                let asset_base = gallery_version_asset_base(
                    base_url,
                    repo_key,
                    &publisher,
                    &name,
                    &version_name,
                    target_platform.as_ref(),
                )?;

                for field in ["assetUri", "fallbackAssetUri"] {
                    if let Some(value) = version.get(field) {
                        // Open VSX emits explicit nulls when a client omits
                        // IncludeAssetUri. A null carries no fetch capability,
                        // so preserve it; rewrite only real asset references.
                        if value.is_null() {
                            continue;
                        }
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

fn gallery_response_too_large() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        "Open VSX gallery response exceeded the gateway's buffered-metadata ceiling",
    )
        .into_response()
}

fn malformed_gallery_json() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        "Open VSX gallery returned malformed JSON",
    )
        .into_response()
}

/// POST one `extensionquery` and buffer its response under `limits`.
///
/// `Ok(None)` reports the byte-ceiling abort specifically, so callers that can
/// re-ask upstream for a bounded projection of the same query act on the wire
/// shape rather than on a rendered error. Every other upstream failure keeps
/// its own status.
async fn post_gallery_query(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    body: Bytes,
    limits: proxy_helpers::MetadataWorkingSetLimits,
) -> Result<Option<(Bytes, tokio::sync::OwnedSemaphorePermit)>, Response> {
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
    match proxy_helpers::proxy_post_json_uncached_capped_budgeted(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        "extensionquery",
        body,
        limits,
    )
    .await?
    {
        proxy_helpers::CappedMetadataPost::Buffered {
            content,
            budget_permit,
            ..
        } => Ok(Some((content, budget_permit))),
        proxy_helpers::CappedMetadataPost::OverCap => Ok(None),
    }
}

/// Buffer and parse one gallery query under the shared metadata cap.
/// `Ok(None)` is the byte-ceiling abort; see [`post_gallery_query`].
async fn fetch_gallery_query_bounded(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    body: Bytes,
) -> Result<Option<BufferedGalleryQuery>, Response> {
    let Some((content, budget_permit)) = post_gallery_query(
        state,
        repo,
        repo_key,
        body,
        proxy_helpers::MetadataWorkingSetLimits {
            max_bytes: GALLERY_METADATA_MAX_BYTES,
            reservation_bytes: GALLERY_METADATA_BUDGET_RESERVATION_BYTES,
        },
    )
    .await?
    else {
        return Ok(None);
    };
    let response: serde_json::Value =
        serde_json::from_slice(&content).map_err(|_| malformed_gallery_json())?;
    if !response
        .get("results")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(invalid_gallery_response());
    }
    Ok(Some(BufferedGalleryQuery {
        value: response,
        _budget_permit: budget_permit,
    }))
}

/// [`fetch_gallery_query_bounded`] for the AK-generated queries whose shape is
/// already bounded by construction (single identity, `IncludeLatestVersionOnly`
/// or versions-only). Hitting the ceiling there is an upstream fault, not a
/// query the gateway can narrow further.
async fn fetch_gallery_query(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    body: Bytes,
) -> Result<BufferedGalleryQuery, Response> {
    fetch_gallery_query_bounded(state, repo, repo_key, body)
        .await?
        .ok_or_else(gallery_response_too_large)
}

/// Build the one-identity `extensionquery` AK issues on a client's behalf.
///
/// Open VSX requires the paging fields on every filter, including a one-result
/// lookup; VS Code clients normally include them, so AK-generated queries must
/// supply them too. `qualifiers` are the client's own non-selecting criteria
/// (`Target`, `ExcludeWithFlags`) repeated verbatim, so a sub-query resolves
/// the same version set the client's original query would have.
fn gallery_single_id_query(
    identity: &GalleryCriterion,
    qualifiers: &[GalleryCriterion],
    flags: u32,
) -> serde_json::Value {
    let mut criteria = vec![gallery_criterion_json(identity)];
    criteria.extend(qualifiers.iter().map(gallery_criterion_json));
    let mut query = serde_json::json!({
        "filters": [{
            "criteria": [],
            "pageNumber": 1,
            "pageSize": 1,
            "sortBy": 0,
            "sortOrder": 0,
        }],
        "flags": flags,
    });
    query["filters"][0]["criteria"] = serde_json::Value::Array(criteria);
    query
}

fn gallery_criterion_json(criterion: &GalleryCriterion) -> serde_json::Value {
    serde_json::json!({
        "filterType": criterion.filter_type,
        "value": criterion.value,
    })
}

fn gallery_query_body(query: &serde_json::Value) -> Bytes {
    Bytes::from(serde_json::to_vec(query).expect("gallery query serializes"))
}

/// Read `flags` off a client body without depending on the whole typed
/// projection parsing.
fn gallery_query_flags(body: &Bytes) -> Option<u32> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("flags")
        .and_then(serde_json::Value::as_u64)
        .and_then(|flags| u32::try_from(flags).ok())
}

/// Re-issue a client's own query under different flags, preserving every other
/// field it carried (paging, sorting, asset types) so the extensions it matches
/// stay the ones the original query would have matched.
fn gallery_query_with_flags(body: &Bytes, flags: u32) -> Option<Bytes> {
    let mut query: serde_json::Value = serde_json::from_slice(body).ok()?;
    query
        .as_object_mut()?
        .insert("flags".to_string(), serde_json::json!(flags));
    serde_json::to_vec(&query).ok().map(Bytes::from)
}

/// One `extensionquery` filter criterion, in the protocol's own wire shape.
struct GalleryCriterion {
    filter_type: u64,
    value: String,
}

/// The plan for answering a pure-identity query by composition: which
/// extensions to compose, in the client's order, and the qualifier criteria
/// every per-identity sub-query must repeat.
struct GalleryComposition {
    identities: Vec<GalleryCriterion>,
    qualifiers: Vec<GalleryCriterion>,
}

/// The subset of an `extensionquery` body this gateway reasons about. Unknown
/// fields are ignored: a query is only ever re-shaped by rewriting `flags` on
/// the client's own JSON, never by reserializing this projection.
#[derive(serde::Deserialize)]
struct GalleryQueryRequest {
    #[serde(default)]
    filters: Vec<GalleryQueryFilter>,
    #[serde(default)]
    flags: u32,
}

#[derive(serde::Deserialize)]
struct GalleryQueryFilter {
    #[serde(default)]
    criteria: Vec<GalleryQueryCriterion>,
    #[serde(rename = "pageSize", default)]
    page_size: Option<u64>,
}

#[derive(serde::Deserialize)]
struct GalleryQueryCriterion {
    #[serde(rename = "filterType", default)]
    filter_type: u64,
    #[serde(default)]
    value: Option<String>,
}

/// How many extensions a composed answer to `request` may carry: the client's
/// own page size, clamped into `1..=GALLERY_COMPOSED_IDENTITY_CAP`.
///
/// Honouring `pageSize` here is protocol-consistent rather than a liberty:
/// upstream applies it to the same query, so a client that asks for a page and
/// receives one is getting what the gallery protocol promises. It is also what
/// makes the identity bound a truncation instead of an error.
fn gallery_composed_identity_limit(request: &GalleryQueryRequest) -> usize {
    request
        .filters
        .first()
        .and_then(|filter| filter.page_size)
        .and_then(|page_size| usize::try_from(page_size).ok())
        .unwrap_or(GALLERY_COMPOSED_IDENTITY_CAP)
        .clamp(1, GALLERY_COMPOSED_IDENTITY_CAP)
}

/// The composition plan for a pure-identity query.
///
/// `None` means the query is not one this gateway composes: it mixes in a
/// selecting criterion this gateway cannot address one extension at a time
/// (search text, category, featured), does not ask for versions, or already
/// asked for latest-only — Open VSX bounds that last shape itself for a
/// single-identity query, so composing it would change what the client receives
/// for no benefit.
///
/// Identities beyond the page limit are truncated rather than refused, matching
/// the paging semantics the protocol already has.
fn gallery_composable_criteria(request: &GalleryQueryRequest) -> Option<GalleryComposition> {
    if request.flags & GALLERY_INCLUDE_VERSIONS_FLAG == 0
        || request.flags & GALLERY_LATEST_VERSION_ONLY_FLAG != 0
    {
        return None;
    }
    let limit = gallery_composed_identity_limit(request);
    let mut identities: Vec<GalleryCriterion> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for filter in &request.filters {
        for criterion in &filter.criteria {
            let selects = criterion.filter_type == GALLERY_EXTENSION_ID_FILTER
                || criterion.filter_type == GALLERY_EXTENSION_NAME_FILTER;
            let qualifies = criterion.filter_type == GALLERY_TARGET_FILTER
                || criterion.filter_type == GALLERY_EXCLUDE_WITH_FLAGS_FILTER;
            if !selects && !qualifies {
                return None;
            }
            let value = criterion.value.as_deref().unwrap_or_default();
            if value.is_empty() {
                return None;
            }
            if !selects || !seen.insert((criterion.filter_type, value.to_string())) {
                continue;
            }
            // Identities beyond the page are dropped, not refused: the protocol
            // already pages, so a client can ask for the rest.
            if identities.len() < limit {
                identities.push(GalleryCriterion {
                    filter_type: criterion.filter_type,
                    value: value.to_string(),
                });
            }
        }
    }
    if identities.is_empty() {
        return None;
    }
    Some(GalleryComposition {
        identities,
        qualifiers: gallery_query_qualifiers(request)?,
    })
}

/// The client's non-selecting criteria — the ones that qualify a selection
/// rather than making one — deduplicated and in the client's order.
///
/// Both composition paths need these: every per-identity sub-query repeats them
/// verbatim, so a sub-query issued without them resolves a different version
/// set than the client's original query would have. `None` means there are more
/// than [`GALLERY_COMPOSED_QUALIFIER_CAP`] of them, which callers must treat as
/// "do not compose" rather than "compose unqualified" — dropping a qualifier
/// answers a different question, where dropping an identity merely answers a
/// shorter page of the same one.
fn gallery_query_qualifiers(request: &GalleryQueryRequest) -> Option<Vec<GalleryCriterion>> {
    let mut qualifiers: Vec<GalleryCriterion> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for filter in &request.filters {
        for criterion in &filter.criteria {
            if criterion.filter_type != GALLERY_TARGET_FILTER
                && criterion.filter_type != GALLERY_EXCLUDE_WITH_FLAGS_FILTER
            {
                continue;
            }
            let value = criterion.value.as_deref().unwrap_or_default();
            if value.is_empty() || !seen.insert((criterion.filter_type, value.to_string())) {
                continue;
            }
            if qualifiers.len() >= GALLERY_COMPOSED_QUALIFIER_CAP {
                return None;
            }
            qualifiers.push(GalleryCriterion {
                filter_type: criterion.filter_type,
                value: value.to_string(),
            });
        }
    }
    Some(qualifiers)
}

/// The identities an upstream result page names, as single-extension criteria,
/// deduplicated and bounded by the same page cap composition applies to a
/// client's own identity list.
#[allow(clippy::result_large_err)]
fn gallery_response_identities(
    response: &serde_json::Value,
    limit: usize,
) -> Result<Vec<GalleryCriterion>, Response> {
    let results = response
        .get("results")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid_gallery_response)?;
    let mut criteria = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in results {
        let extensions = result
            .get("extensions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid_gallery_response)?;
        for extension in extensions {
            if criteria.len() >= limit {
                return Ok(criteria);
            }
            let (publisher, name, _) =
                gallery_extension_identity(extension).ok_or_else(invalid_gallery_response)?;
            let value = format!("{publisher}.{name}");
            if !seen.insert(value.clone()) {
                continue;
            }
            criteria.push(GalleryCriterion {
                filter_type: GALLERY_EXTENSION_NAME_FILTER,
                value,
            });
        }
    }
    Ok(criteria)
}

/// One version as [`GALLERY_SKELETON_QUERY_FLAGS`] returns it. Everything this
/// gateway does not need is dropped at deserialize time; that is what keeps a
/// 12,592-version history a bounded typed working set instead of a
/// `serde_json::Value` tree carrying a node per JSON key.
#[derive(serde::Deserialize)]
struct GallerySkeletonWireVersion {
    version: String,
    #[serde(rename = "targetPlatform", default)]
    target_platform: Option<String>,
    #[serde(rename = "lastUpdated", default)]
    last_updated: Option<String>,
    #[serde(default)]
    properties: Option<Vec<GallerySkeletonWireProperty>>,
}

#[derive(serde::Deserialize)]
struct GallerySkeletonWireProperty {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct GallerySkeletonWireExtension {
    #[serde(default)]
    publisher: Option<GallerySkeletonWirePublisher>,
    #[serde(rename = "extensionName", default)]
    extension_name: Option<String>,
    #[serde(default)]
    versions: Vec<GallerySkeletonWireVersion>,
}

#[derive(serde::Deserialize)]
struct GallerySkeletonWirePublisher {
    #[serde(rename = "publisherName", default)]
    publisher_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct GallerySkeletonWireResult {
    #[serde(default)]
    extensions: Vec<GallerySkeletonWireExtension>,
}

#[derive(serde::Deserialize)]
struct GallerySkeletonWireDocument {
    #[serde(default)]
    results: Vec<GallerySkeletonWireResult>,
}

/// A validated skeleton entry. `target_platform` is already normalized, so
/// `universal` covers both an explicit value and an absent one — Open VSX omits
/// the field for platform-independent builds.
#[derive(Debug)]
struct GallerySkeletonVersion {
    version: String,
    target_platform: String,
    last_updated: Option<DateTime<Utc>>,
    prerelease: bool,
    engine: Option<String>,
}

/// Validate and normalize the version skeleton of ONE extension.
///
/// Every caller attributes these versions to `package` — as the publish-time
/// evidence behind a gated download, or as the version list spliced into that
/// extension's detail record. Open VSX is not obliged to answer a
/// single-identity lookup with exactly one extension, so a page that names
/// others must not contribute: without this guard a gated request for
/// `a.b@1.0.0` could take its publish time from a different extension that
/// happens to have published a `1.0.0`, which is an age-gate bypass.
///
/// Coordinates become AK URL and proxy cache-key components, so they are
/// checked here exactly as the rewrite pass checks an upstream document's own
/// version entries. An entry that fails is SKIPPED rather than failing the
/// document: one malformed coordinate anywhere in a 12,592-version history
/// would otherwise permanently 502 both search and `/latest` for that
/// extension, and every entry that does reach a client still passes through
/// [`gallery_version_asset_base`].
fn gallery_skeleton_versions(
    document: GallerySkeletonWireDocument,
    package: &str,
) -> Vec<GallerySkeletonVersion> {
    let mut versions = Vec::new();
    let mut other_extensions = 0usize;
    for result in document.results {
        for extension in result.extensions {
            let publisher = extension
                .publisher
                .and_then(|publisher| publisher.publisher_name)
                .unwrap_or_default();
            let name = extension.extension_name.unwrap_or_default();
            if vscode_age_gate_package(&publisher, &name) != package {
                other_extensions += 1;
                continue;
            }
            for wire in extension.versions {
                let target_platform =
                    normal_target_platform(wire.target_platform.as_deref()).into_owned();
                if validate_gallery_response_segment(&wire.version).is_err()
                    || validate_target_platform(&target_platform, true).is_err()
                {
                    continue;
                }
                let mut prerelease = false;
                let mut engine = None;
                for property in wire.properties.unwrap_or_default() {
                    let GallerySkeletonWireProperty { key, value } = property;
                    if key.as_deref() == Some(GALLERY_PRERELEASE_PROPERTY) {
                        prerelease = value.as_deref() == Some("true");
                    } else if key.as_deref() == Some(GALLERY_ENGINE_PROPERTY) {
                        engine = value;
                    }
                }
                versions.push(GallerySkeletonVersion {
                    version: wire.version,
                    target_platform,
                    last_updated: wire
                        .last_updated
                        .as_deref()
                        .and_then(gallery_parse_last_updated),
                    prerelease,
                    engine,
                });
            }
        }
    }
    if versions.is_empty() && other_extensions > 0 {
        // Distinguishes "upstream has no such extension" from "the identity
        // guard rejected everything it did return", which otherwise look
        // identical downstream (a 404 on a gated fetch, an empty walk-back).
        tracing::debug!(
            "Open VSX version skeleton for {} named only other extensions ({} skipped)",
            package,
            other_extensions
        );
    }
    versions
}

/// Fetch and project `package`'s whole version history.
///
/// `flags` selects how much of each version upstream attaches: callers that
/// resolve channel and engine compatibility ask for
/// [`GALLERY_SKELETON_QUERY_FLAGS`], while the publish-time-only lookup asks
/// for [`GALLERY_EXACT_VERSION_QUERY_FLAGS`] and pays roughly a fifth of the
/// bytes. Both deserialize into the same typed projection — absent properties
/// are simply absent.
///
/// The wire document is buffered under [`GALLERY_SKELETON_MAX_BYTES`] and
/// deserialized straight into that projection; the wire buffer and its budget
/// reservation are released when this returns, so only the projection survives
/// into selection and composition.
async fn fetch_gallery_skeleton(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    identity: &GalleryCriterion,
    qualifiers: &[GalleryCriterion],
    flags: u32,
    package: &str,
) -> Result<Vec<GallerySkeletonVersion>, Response> {
    let query = gallery_single_id_query(identity, qualifiers, flags);
    let Some((content, _budget_permit)) = post_gallery_query(
        state,
        repo,
        repo_key,
        gallery_query_body(&query),
        proxy_helpers::MetadataWorkingSetLimits {
            max_bytes: GALLERY_SKELETON_MAX_BYTES,
            reservation_bytes: GALLERY_SKELETON_BUDGET_RESERVATION_BYTES,
        },
    )
    .await?
    else {
        return Err(gallery_response_too_large());
    };
    let document: GallerySkeletonWireDocument =
        serde_json::from_slice(&content).map_err(|_| malformed_gallery_json())?;
    Ok(gallery_skeleton_versions(document, package))
}

/// Order gallery versions newest-first, entries without trustworthy
/// publish-time evidence last.
///
/// Open VSX normally returns a version history in this order already, but
/// nothing in the protocol guarantees it, and every bound in this module is
/// positional: a single non-monotonic page would silently make the bounded
/// selection keep the OLDEST entries of each bucket and make the `/latest`
/// walk-back serve the oldest allowed release. Undated entries sort last
/// because they are exactly the ones the age gate treats as ineligible.
fn sort_skeleton_newest_first(versions: &mut [GallerySkeletonVersion]) {
    versions.sort_by_key(|version| std::cmp::Reverse(version.last_updated));
}

/// [`sort_skeleton_newest_first`] for already-rendered gallery version entries.
/// This is also what gives a coordinate the detail query reported but the
/// skeleton did not — a publish that landed between the two round-trips — a
/// correct position instead of an arbitrary one.
fn sort_gallery_versions_newest_first(versions: &mut [serde_json::Value]) {
    versions.sort_by_key(|version| std::cmp::Reverse(gallery_last_updated(version)));
}

/// Keep the newest [`GALLERY_VERSIONS_PER_CHANNEL`] entries of every
/// (target platform, release channel) bucket.
fn select_bounded_gallery_versions(
    mut versions: Vec<GallerySkeletonVersion>,
) -> Vec<GallerySkeletonVersion> {
    sort_skeleton_newest_first(&mut versions);
    let mut per_bucket: std::collections::HashMap<(String, bool), usize> =
        std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut selected = Vec::new();
    for version in versions {
        // A platform variant is one coordinate. An upstream that lists it twice
        // must not spend two of that bucket's slots or emit two entries the
        // client would have to disambiguate.
        if !seen.insert(vscode_age_gate_version(
            &version.version,
            Some(&version.target_platform),
        )) {
            continue;
        }
        let kept = per_bucket
            .entry((version.target_platform.clone(), version.prerelease))
            .or_insert(0);
        if *kept >= GALLERY_VERSIONS_PER_CHANNEL {
            continue;
        }
        *kept += 1;
        selected.push(version);
    }
    selected
}

/// Build the gallery `versions[]` entry AK serves for a skeleton selection.
///
/// Asset delivery metadata mirrors what the client asked for, exactly as
/// upstream would have answered: `assetUri`/`fallbackAssetUri` only under
/// `IncludeAssetUri`, `files` only under `IncludeFiles`. The file list is not
/// optional decoration — VS Code filters `versions[].files` before it looks at
/// `assetUri`, so a synthesized version without it is not installable.
fn synthesize_gallery_version(
    version: &GallerySkeletonVersion,
    asset_base: &str,
    flags: u32,
) -> serde_json::Value {
    let mut properties = Vec::new();
    if version.prerelease {
        properties.push(serde_json::json!({
            "key": GALLERY_PRERELEASE_PROPERTY,
            "value": "true",
        }));
    }
    if let Some(engine) = version.engine.as_deref() {
        properties.push(serde_json::json!({
            "key": GALLERY_ENGINE_PROPERTY,
            "value": engine,
        }));
    }
    let mut synthesized = serde_json::json!({
        "version": version.version,
        "properties": properties,
    });
    // Upstream omits `targetPlatform` on a platform-independent build. Match
    // that shape so one coordinate never reaches a client in two encodings.
    if version.target_platform != DEFAULT_TARGET_PLATFORM {
        synthesized["targetPlatform"] = serde_json::json!(version.target_platform);
    }
    if let Some(last_updated) = version.last_updated {
        synthesized["lastUpdated"] = serde_json::json!(last_updated.to_rfc3339());
    }
    if flags & GALLERY_INCLUDE_ASSET_URI_FLAG != 0 {
        synthesized["assetUri"] = serde_json::json!(asset_base);
        synthesized["fallbackAssetUri"] = serde_json::json!(asset_base);
    }
    if flags & GALLERY_INCLUDE_FILES_FLAG != 0 {
        let files = GALLERY_SYNTHESIZED_ASSET_TYPES
            .iter()
            .copied()
            .map(|asset_type| {
                serde_json::json!({
                    "assetType": asset_type,
                    // Byte-identical to what `rewrite_gallery_asset_urls`
                    // produces for a detail-derived entry.
                    "source": format!("{}/{}", asset_base, urlencoding::encode(asset_type)),
                })
            })
            .collect::<Vec<_>>();
        synthesized["files"] = serde_json::Value::Array(files);
    }
    synthesized
}

/// Wrap composed extensions in the `results` envelope clients expect.
///
/// `result_metadata` carries an upstream page's own metadata forward when
/// composition answered a query upstream had already counted — its `TotalCount`
/// is the total across every page, which the composed page length would
/// silently replace with "this page is everything" and stop a paging client
/// early. Composition driven by the client's own identity list has no such
/// upstream count, so the composed length is the honest answer there.
/// [`reconcile_gallery_result_count`] adjusts either shape if the age gate
/// removes extensions.
fn gallery_results_envelope(
    extensions: Vec<serde_json::Value>,
    result_metadata: Option<serde_json::Value>,
) -> serde_json::Value {
    let total = extensions.len();
    // Assign the extensions rather than interpolating them: `json!` serializes
    // an interpolated value, which would deep-copy the whole composed payload
    // that the bounded selection exists to keep small.
    let mut envelope = serde_json::json!({
        "results": [{
            "extensions": [],
            "resultMetadata": [{
                "metadataType": "ResultCount",
                "metadataItems": [{ "name": "TotalCount", "count": total }],
            }],
        }],
    });
    envelope["results"][0]["extensions"] = serde_json::Value::Array(extensions);
    if let Some(result_metadata) = result_metadata {
        envelope["results"][0]["resultMetadata"] = result_metadata;
    }
    envelope
}

/// Compose one extension's bounded record from a detail query and a skeleton.
///
/// The detail query supplies the extension envelope and its fully detailed
/// latest-per-platform versions; the skeleton supplies the rest of the bounded
/// selection, and a detail entry wins wherever both describe the same
/// coordinate — it carries the files and statistics the synthesized entry
/// deliberately omits. `Ok(None)` means upstream knows no such extension.
async fn compose_gallery_extension(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    base_url: &RequestBaseUrl,
    identity: &GalleryCriterion,
    qualifiers: &[GalleryCriterion],
    flags: u32,
) -> Result<Option<serde_json::Value>, Response> {
    let detail_query = gallery_single_id_query(
        identity,
        qualifiers,
        flags | GALLERY_LATEST_VERSION_ONLY_FLAG,
    );
    let detail =
        fetch_gallery_query(state, repo, repo_key, gallery_query_body(&detail_query)).await?;
    let extension = detail.value.pointer("/results/0/extensions/0").cloned();
    // The detail document has served its purpose. Release its share of the
    // shared buffered-metadata budget before the skeleton fetch reserves its
    // own, rather than holding both across the second round-trip.
    drop(detail);
    let Some(mut extension) = extension else {
        return Ok(None);
    };
    let (publisher, name, package) =
        gallery_extension_identity(&extension).ok_or_else(invalid_gallery_response)?;
    // The skeleton is keyed on the identity the DETAIL response reported, not
    // on the criterion the client sent: a `filterType` 4 criterion is a GUID,
    // and either shape can match a page that also names other extensions.
    let skeleton = select_bounded_gallery_versions(
        fetch_gallery_skeleton(
            state,
            repo,
            repo_key,
            identity,
            qualifiers,
            GALLERY_SKELETON_QUERY_FLAGS,
            &package,
        )
        .await?,
    );

    let detailed = match extension
        .get_mut("versions")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(detailed) => std::mem::take(detailed),
        None => Vec::new(),
    };
    let mut detailed_by_coordinate = std::collections::HashMap::new();
    for version in detailed {
        let coordinate =
            gallery_version_coordinate(&version).ok_or_else(invalid_gallery_response)?;
        detailed_by_coordinate.insert(coordinate, version);
    }

    let mut versions = Vec::with_capacity(skeleton.len() + detailed_by_coordinate.len());
    for selected in &skeleton {
        let coordinate =
            vscode_age_gate_version(&selected.version, Some(&selected.target_platform));
        if let Some(detailed) = detailed_by_coordinate.remove(&coordinate) {
            versions.push(detailed);
            continue;
        }
        let asset_base = gallery_version_asset_base(
            base_url,
            repo_key,
            &publisher,
            &name,
            &selected.version,
            &selected.target_platform,
        )?;
        versions.push(synthesize_gallery_version(selected, &asset_base, flags));
    }
    // A version the detail query reported but the skeleton did not — a publish
    // that landed between the two round-trips — is the one a client is most
    // likely to install, so it must not be dropped by the merge. The sort below
    // is what puts it in the right place rather than at an arbitrary end.
    versions.extend(detailed_by_coordinate.into_values());
    sort_gallery_versions_newest_first(&mut versions);
    extension["versions"] = serde_json::Value::Array(versions);
    Ok(Some(extension))
}

/// Compose one bounded `results` envelope for a set of identities.
///
/// One identity that fails fails the whole response, deliberately: a partial
/// page is indistinguishable to a client from an authoritative "these are the
/// extensions", and silently dropping an extension a client asked about is a
/// worse failure than a visible one.
async fn compose_gallery_query(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    base_url: &RequestBaseUrl,
    composition: &GalleryComposition,
    flags: u32,
    result_metadata: Option<serde_json::Value>,
) -> Result<serde_json::Value, Response> {
    let mut extensions = Vec::with_capacity(composition.identities.len());
    // Chunked joins keep at most GALLERY_COMPOSITION_CONCURRENCY extensions —
    // and therefore that many upstream requests and budget reservations — in
    // flight, while preserving the client's criteria order in the output. The
    // TOTAL is bounded separately, by GALLERY_COMPOSED_IDENTITY_CAP.
    for chunk in composition
        .identities
        .chunks(GALLERY_COMPOSITION_CONCURRENCY)
    {
        let composed = futures::future::join_all(chunk.iter().map(|identity| {
            compose_gallery_extension(
                state,
                repo,
                repo_key,
                base_url,
                identity,
                &composition.qualifiers,
                flags,
            )
        }))
        .await;
        for extension in composed {
            if let Some(extension) = extension? {
                extensions.push(extension);
            }
        }
    }
    Ok(gallery_results_envelope(extensions, result_metadata))
}

/// The passthrough seam: age-gate an upstream `results` envelope, then render
/// it. Composed responses run the same two steps with a budget reservation
/// between them — see [`serve_composed_gallery_response`].
async fn finish_gallery_response(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    base_url: &RequestBaseUrl,
    mut response: serde_json::Value,
) -> Result<Response, Response> {
    filter_gallery_response_age_gate(state, repo, &mut response).await?;
    render_gallery_response(&mut response, base_url, repo_key)
}

/// Rewrite every asset reference onto AK and serialize.
///
/// Nothing reaches a client except through here, and the age gate always runs
/// before it — for a composed document and a passed-through one alike — so a
/// synthesized version can never skip the gate or keep an upstream asset
/// reference. Split out from [`finish_gallery_response`] because this is the
/// only phase whose memory a composed page needs to reserve for: the parsed
/// tree and the serialized body are resident together here, and nowhere else.
#[allow(clippy::result_large_err)]
fn render_gallery_response(
    response: &mut serde_json::Value,
    base_url: &RequestBaseUrl,
    repo_key: &str,
) -> Result<Response, Response> {
    rewrite_gallery_asset_urls(response, base_url, repo_key)?;
    Ok(json_response(response))
}

/// Process-wide admission control for composed responses. Sized once and never
/// closed, mirroring [`proxy_helpers::proxy_metadata_budget`].
fn gallery_composition_admission() -> &'static tokio::sync::Semaphore {
    static ADMISSION: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    ADMISSION.get_or_init(|| tokio::sync::Semaphore::new(GALLERY_COMPOSITION_ADMISSION))
}

/// Compose a bounded page and serve it under two separate bounds.
///
/// [`GALLERY_COMPOSITION_ADMISSION`] is taken first and held throughout: the
/// composed page accumulates during the fan-out, and that accumulation needs a
/// bound of its own because the byte reservation below deliberately does not
/// cover it. Wrapping the fan-out in a byte reservation instead would turn a
/// strictly nested pattern into hold-and-wait — every sub-query reserves from
/// the same shared byte semaphore, so enough outer holders could leave less
/// free budget than one sub-query needs and none of them could ever proceed.
/// A counting admission semaphore has no such interaction: it is a different
/// resource, always acquired before any byte reservation and never after one.
///
/// The byte reservation then covers exactly the phase that holds the parsed
/// tree and the serialized body at the same time. The age gate runs BEFORE it,
/// because gate filtering is up to [`GALLERY_COMPOSED_IDENTITY_CAP`]
/// sequential database round-trips, and charging the shared memory budget for
/// that latency would shrink it for everyone without bounding any memory.
async fn serve_composed_gallery_response(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    base_url: &RequestBaseUrl,
    composition: &GalleryComposition,
    flags: u32,
    result_metadata: Option<serde_json::Value>,
) -> Result<Response, Response> {
    let _admission = gallery_composition_admission()
        .acquire()
        .await
        .expect("gallery composition admission semaphore is never closed");
    let mut composed = compose_gallery_query(
        state,
        repo,
        repo_key,
        base_url,
        composition,
        flags,
        result_metadata,
    )
    .await?;
    filter_gallery_response_age_gate(state, repo, &mut composed).await?;
    let _budget_permit = proxy_helpers::proxy_metadata_budget()
        .reserve(GALLERY_COMPOSITION_BUDGET_RESERVATION_BYTES)
        .await;
    render_gallery_response(&mut composed, base_url, repo_key)
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
    validate_target_platform(platform.as_ref(), true).ok()?;
    Some(vscode_age_gate_version(name, Some(platform.as_ref())))
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

/// Surfaces named in the shared fail-closed age-gate response. They identify
/// which capability was refused, so an operator can tell a withheld listing
/// apart from a withheld download.
const GALLERY_METADATA_GATE_SURFACE: &str = "VS Code gallery metadata";
const GALLERY_ASSET_GATE_SURFACE: &str = "VS Code gallery asset";

/// Resolve the age-gate policy seam for a gallery request.
///
/// `Ok(None)` means this repository never asked for gating. Every other
/// non-`Ok(Some)` outcome is terminal and fails closed: a gate that is enabled
/// but unenforceable for this (format, mode) pair, or an enabled gate with no
/// service behind it, must never degrade into serving ungated metadata.
#[allow(clippy::result_large_err)]
async fn gallery_age_gate_seam<'a>(
    state: &'a SharedState,
    repo: &RepoInfo,
    surface: &str,
) -> Result<
    Option<(
        crate::services::age_gate_service::AgeGateRepoParams,
        &'a crate::services::age_gate_service::AgeGateService,
    )>,
    Response,
> {
    use crate::services::age_gate_service::{resolve_repo_params, AgeGateService};

    let params = resolve_repo_params(&state.db, repo.id)
        .await
        .map_err(|error| error.into_response())?;
    if !AgeGateService::gating_requested(&params) {
        return Ok(None);
    }
    AgeGateService::require_enforceable(&params).map_err(|error| error.into_response())?;
    let service = state
        .age_gate_service
        .as_deref()
        .ok_or_else(|| proxy_helpers::age_gate_unavailable_response(&params.key, surface))?;
    Ok(Some((params, service)))
}

/// Apply the shared age-gate listing semantics to every returned extension
/// identity before asset URLs are rewritten. This is intentionally separate
/// from `fetch_gallery_query`: delivery must be able to fetch raw gallery
/// metadata as exact existence evidence without recursively filtering it.
// `Response` is the error type across this whole module's `Result`s, which is
// what every other fallible helper here already allows. Newer clippy also
// applies `result_large_err` to the inner `.map(|version| ...)` closure that
// collects into `Result<Vec<_>, Response>`, which is why this sits on the
// function rather than only on the module's `#[allow(clippy::result_large_err)]`
// helpers — without it `cargo clippy -- -D warnings` fails on stable 1.97.
#[allow(clippy::result_large_err)]
async fn filter_gallery_response_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    response: &mut serde_json::Value,
) -> Result<(), Response> {
    let Some((params, service)) =
        gallery_age_gate_seam(state, repo, GALLERY_METADATA_GATE_SURFACE).await?
    else {
        return Ok(());
    };

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

/// Locate one platform-qualified version in an extension's version skeleton.
/// `Some(None)` means it exists but lacks trustworthy publish-time evidence;
/// callers must pass that through to the shared fail-closed seam.
fn find_gallery_exact_version(
    skeleton: &[GallerySkeletonVersion],
    version: &str,
    target_platform: &str,
) -> Option<Option<DateTime<Utc>>> {
    let target = normal_target_platform(Some(target_platform));
    skeleton
        .iter()
        .find(|candidate| {
            // `*target` derefs the `Cow` to `str`: `typed_path` and `bstr` add
            // competing `AsRef`/`PartialEq` impls that make `target.as_ref()`
            // ambiguous (E0283) here.
            candidate.version == version && *candidate.target_platform == *target
        })
        .map(|candidate| candidate.last_updated)
}

/// Re-resolve exact gallery metadata before every cache lookup or upstream
/// byte fetch. The raw query is deliberately not passed through the listing
/// filter, which avoids recursive policy evaluation and gives first-seen mode
/// positive existence evidence for precisely the requested platform variant.
///
/// This check only needs `version`, `targetPlatform`, and `lastUpdated`, which
/// is exactly the version skeleton — and the skeleton is the only shape of that
/// evidence with a cap it actually fits under. rust-analyzer's history measures
/// 2,120,608 bytes as a plain `IncludeVersions` query, just over the 2 MiB
/// gallery metadata ceiling, so resolving it that way would have turned every
/// gated asset request for such an extension into a 502.
async fn enforce_gallery_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    publisher: &str,
    name: &str,
    version: &str,
    target_platform: &str,
) -> Result<(), Response> {
    use crate::services::age_gate_service::AgeGateService;

    let Some((params, service)) =
        gallery_age_gate_seam(state, repo, GALLERY_ASSET_GATE_SURFACE).await?
    else {
        return Ok(());
    };
    let package = vscode_age_gate_package(publisher, name);
    let coordinate = vscode_age_gate_version(version, Some(target_platform));
    let identity = GalleryCriterion {
        filter_type: GALLERY_EXTENSION_NAME_FILTER,
        value: package.clone(),
    };
    let skeleton = fetch_gallery_skeleton(
        state,
        repo,
        repo_key,
        &identity,
        &[],
        GALLERY_EXACT_VERSION_QUERY_FLAGS,
        &package,
    )
    .await?;
    let published_at = find_gallery_exact_version(&skeleton, version, target_platform)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Extension version not found").into_response())?;
    // The projected history has served its purpose. Release it before the
    // age-gate DB round-trips below rather than holding it across them.
    drop(skeleton);
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

fn gallery_response_base_url(headers: &HeaderMap) -> RequestBaseUrl {
    RequestBaseUrl(request_base_url_from_host_header(headers))
}

fn build_gallery_manifest(base_url: &RequestBaseUrl, repo_key: &str) -> serde_json::Value {
    let gallery = gallery_base_url(base_url, repo_key);
    let item = format!(
        "{}/vscode/{}/item",
        base_url.as_str().trim_end_matches('/'),
        urlencoding::encode(repo_key)
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
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    gallery_upstream(&state.db, &repo).await?;
    let base_url = gallery_response_base_url(&headers);
    Ok(json_response(&build_gallery_manifest(&base_url, &repo_key)))
}

async fn gallery_extension_query(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    let base_url = gallery_response_base_url(&headers);
    // A body this projection cannot read is still a body the upstream may
    // accept, so an unreadable query degrades to passthrough rather than to a
    // rejection this gateway would be inventing.
    let request = serde_json::from_slice::<GalleryQueryRequest>(&body).ok();
    // Flags decide whether a ceiling abort is recoverable, so read them off the
    // JSON directly when the whole projection did not parse: one unexpected
    // field shape elsewhere in the body must not silently disable recovery.
    let flags = request
        .as_ref()
        .map(|request| request.flags)
        .or_else(|| gallery_query_flags(&body))
        .unwrap_or(0);

    // Named extensions WITH their version history is the VSCodium update
    // follow-up. Open VSX answers it with the complete history — 28 MiB for one
    // popular extension, 55 MiB for a ten-extension page — so compose the
    // bounded equivalent instead of attempting a passthrough whose only
    // outcomes are a multi-second stall and the metadata ceiling.
    if let Some(composition) = request.as_ref().and_then(gallery_composable_criteria) {
        return serve_composed_gallery_response(
            &state,
            &repo,
            &repo_key,
            &base_url,
            &composition,
            flags,
            None,
        )
        .await;
    }

    if let Some(response) =
        fetch_gallery_query_bounded(&state, &repo, &repo_key, body.clone()).await?
    {
        return finish_gallery_response(&state, &repo, &repo_key, &base_url, response.value).await;
    }

    // The passthrough hit the ceiling. A text search that asked for versions is
    // recoverable: the SAME query with identities only is bounded, and each
    // identity it names composes into the bounded per-extension record. Without
    // `IncludeVersions` the response is already as narrow as it can be asked
    // for, so there is nothing left to narrow.
    if flags & GALLERY_INCLUDE_VERSIONS_FLAG == 0 {
        return Err(gallery_response_too_large());
    }
    let identity_flags =
        (flags | GALLERY_LATEST_VERSION_ONLY_FLAG) & !GALLERY_INCLUDE_VERSIONS_FLAG;
    let identity_body =
        gallery_query_with_flags(&body, identity_flags).ok_or_else(gallery_response_too_large)?;
    let identities = fetch_gallery_query(&state, &repo, &repo_key, identity_body).await?;
    let limit = request.as_ref().map_or(
        GALLERY_COMPOSED_IDENTITY_CAP,
        gallery_composed_identity_limit,
    );
    // Upstream chose these identities under the client's qualifiers, so the
    // per-identity sub-queries must carry them too — otherwise composition
    // answers a differently-qualified question than the search did. A body with
    // more qualifiers than one composed query may replay surfaces the ceiling
    // rather than composing an unqualified answer.
    let qualifiers = match request.as_ref() {
        Some(request) => {
            gallery_query_qualifiers(request).ok_or_else(gallery_response_too_large)?
        }
        None => Vec::new(),
    };
    let composition = GalleryComposition {
        identities: gallery_response_identities(&identities.value, limit)?,
        qualifiers,
    };
    // Upstream already counted this query across every page. Carry that count
    // forward rather than replacing it with the composed page length.
    let result_metadata = identities
        .value
        .pointer("/results/0/resultMetadata")
        .cloned();
    drop(identities);
    serve_composed_gallery_response(
        &state,
        &repo,
        &repo_key,
        &base_url,
        &composition,
        flags,
        result_metadata,
    )
    .await
}

fn gallery_extension_not_found() -> Response {
    (StatusCode::NOT_FOUND, "Extension not found").into_response()
}

async fn gallery_latest_version(
    State(state): State<SharedState>,
    Path((repo_key, publisher, name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    validate_gallery_request_segment(&publisher)?;
    validate_gallery_request_segment(&name)?;
    let identity = GalleryCriterion {
        filter_type: GALLERY_EXTENSION_NAME_FILTER,
        value: format!("{publisher}.{name}"),
    };
    let query = gallery_single_id_query(&identity, &[], GALLERY_LATEST_VERSION_QUERY_FLAGS);
    let mut response =
        fetch_gallery_query(&state, &repo, &repo_key, gallery_query_body(&query)).await?;
    // Keep the pre-filter record: when the gate withholds every latest version,
    // the walk-back below reuses this extension's envelope — display name,
    // publisher, statistics — and replaces only its versions.
    let unfiltered = response.value.pointer("/results/0/extensions/0").cloned();
    filter_gallery_response_age_gate(&state, &repo, &mut response.value).await?;
    let base_url = gallery_response_base_url(&headers);
    rewrite_gallery_asset_urls(&mut response.value, &base_url, &repo_key)?;
    // `ExtensionLatestVersionUriTemplate` is consumed by VS Code as a
    // single raw gallery extension, unlike the POST extensionquery envelope.
    // An empty query result is the ordinary "extension not found" case.
    if let Some(extension) = response.value.pointer("/results/0/extensions/0").cloned() {
        return Ok(json_response(&extension));
    }
    drop(response);
    let Some(extension) = unfiltered else {
        return Err(gallery_extension_not_found());
    };
    let walked_back =
        gallery_latest_walk_back(&state, &repo, &repo_key, &base_url, &identity, extension)
            .await?
            .ok_or_else(gallery_extension_not_found)?;
    Ok(json_response(&walked_back))
}

/// Resolve the newest gate-allowed version per target platform after the gate
/// withheld every latest version.
///
/// Open VSX reports latest-per-platform only, so the version a gated repository
/// should actually serve is not in the detail response at all: without this the
/// route 404s an extension whose older releases are perfectly servable. The
/// skeleton is the bounded way to see those releases — the alternative, asking
/// upstream for the full history in client shape, is the 28 MiB document this
/// gateway exists to avoid buffering. `Ok(None)` means the gate allows nothing,
/// which is the only outcome that is genuinely a 404.
///
/// The gate is batch-evaluated over the whole bounded selection (up to
/// ~10 platforms × 2 channels × [`GALLERY_VERSIONS_PER_CHANNEL`] coordinates)
/// rather than the single latest coordinate the route used to resolve. That is
/// deliberate and bounded: in `first_seen` mode it also records a first-seen
/// observation for each of those coordinates, which is what lets a later
/// request serve them once they have aged.
async fn gallery_latest_walk_back(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    base_url: &RequestBaseUrl,
    identity: &GalleryCriterion,
    mut extension: serde_json::Value,
) -> Result<Option<serde_json::Value>, Response> {
    let Some((params, service)) =
        gallery_age_gate_seam(state, repo, GALLERY_METADATA_GATE_SURFACE).await?
    else {
        return Ok(None);
    };
    let (publisher, name, package) =
        gallery_extension_identity(&extension).ok_or_else(invalid_gallery_response)?;
    let skeleton = select_bounded_gallery_versions(
        fetch_gallery_skeleton(
            state,
            repo,
            repo_key,
            identity,
            &[],
            GALLERY_SKELETON_QUERY_FLAGS,
            &package,
        )
        .await?,
    );
    let candidates = skeleton
        .iter()
        .map(|version| {
            (
                vscode_age_gate_version(&version.version, Some(&version.target_platform)),
                version.last_updated,
            )
        })
        .collect::<Vec<_>>();
    let blocked = service
        .evaluate_versions_batch(&params, &package, &candidates)
        .await
        .map_err(|error| error.into_response())?;

    let mut served_platforms = std::collections::HashSet::new();
    let mut versions = Vec::new();
    for version in &skeleton {
        let coordinate = vscode_age_gate_version(&version.version, Some(&version.target_platform));
        if blocked.contains(&coordinate) {
            continue;
        }
        // Upstream order is newest-first, so the first survivor of a platform
        // is the newest release the gate allows for it.
        if !served_platforms.insert(version.target_platform.clone()) {
            continue;
        }
        let asset_base = gallery_version_asset_base(
            base_url,
            repo_key,
            &publisher,
            &name,
            &version.version,
            &version.target_platform,
        )?;
        versions.push(synthesize_gallery_version(
            version,
            &asset_base,
            GALLERY_LATEST_VERSION_QUERY_FLAGS,
        ));
    }
    if versions.is_empty() {
        return Ok(None);
    }
    extension["versions"] = serde_json::Value::Array(versions);
    // This envelope came from the raw upstream document, so it has not been
    // through the rewrite pass. Run it now over the same wrapper shape the
    // served paths use, so no upstream asset reference survives on it.
    let mut envelope = gallery_results_envelope(vec![extension], None);
    rewrite_gallery_asset_urls(&mut envelope, base_url, repo_key)?;
    Ok(envelope.pointer("/results/0/extensions/0").cloned())
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
        target_platform.as_ref(),
    ] {
        validate_gallery_request_segment(segment)?;
    }
    validate_target_platform(target_platform.as_ref(), false)?;
    // Send the SAME normalized platform the cache key is built from. Deriving
    // the upstream query from the raw `Option` instead made "no targetPlatform"
    // and "targetPlatform=universal" two different upstream URLs sharing one
    // cache path — and `classify_vscode_gallery_asset` marks that path shape
    // Immutable, so whichever arrived first would define the bytes served to
    // the other forever. `openvsx_asset_url` already always sends the param.
    let upstream_path = format!(
        "publishers/{}/vsextensions/{}/{}/vspackage?targetPlatform={}",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        urlencoding::encode(target_platform.as_ref()),
    );
    let cache_path = format!(
        "gallery/{}/{}/{}/{}/vspackage",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        urlencoding::encode(target_platform.as_ref()),
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
        target_platform: target_platform.as_ref(),
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
        target_platform.as_ref(),
        asset_type.as_str(),
    ] {
        validate_gallery_request_segment(segment)?;
    }
    validate_target_platform(target_platform.as_ref(), false)?;
    let upstream_url = openvsx_asset_url(
        upstream_url,
        &publisher,
        &name,
        &version,
        &asset_type,
        target_platform.as_ref(),
    )?;
    let cache_path = format!(
        "gallery/{}/{}/{}/{}/asset-{:x}",
        urlencoding::encode(&publisher),
        urlencoding::encode(&name),
        urlencoding::encode(&version),
        urlencoding::encode(target_platform.as_ref()),
        Sha256::digest(asset_type.as_bytes()),
    );
    let coordinate = GalleryAssetCoordinate {
        repo_key: &repo_key,
        publisher: &publisher,
        name: &name,
        version: &version,
        target_platform: target_platform.as_ref(),
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
    // Curation is the operator's allowlist / emergency-deny control and it is
    // enforced by the handler on every other curated proxy download path (npm
    // `serve_tarball`, pypi `serve_file`, cargo `download`, nuget, oci). The
    // shared streaming helper below takes no `db` and therefore cannot apply
    // it, so a gateway that omits this call leaves an enabled curation rule
    // silently inert — the #3235 class. Run it before the age gate so a denied
    // publisher costs no upstream metadata round-trip.
    //
    // The package identity is the same casefolded `publisher.extension` the
    // age gate uses, so one rule written by the operator governs both gates.
    proxy_helpers::enforce_curation(
        &state.db,
        repo,
        &vscode_age_gate_package(coordinate.publisher, coordinate.name),
        Some(coordinate.version),
    )
    .await?;
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
) -> Result<Response, Response> {
    let repo = resolve_vscode_repo(&state.db, &repo_key).await?;
    gallery_upstream(&state.db, &repo).await?;
    // Deliberately relative: a redirect built from forwarding headers would be
    // header-controlled. This reaches the same page and cannot leave origin.
    Ok(
        Redirect::temporary(&format!("/repositories/{}", urlencoding::encode(&repo_key)))
            .into_response(),
    )
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

/// Refuse the legacy `/extensions/.../download` proxy pull-through while the
/// repository's publish-age gate is enabled.
///
/// `AgeGateService::gating_requested` is `repo_type == Remote && age_gate_enabled`;
/// this mirrors it off [`RepoInfo`], which already carries both columns, so no
/// extra query is needed. The response is the shared `age_gate_unavailable`
/// fail-closed shape — "the gate is enabled but could not be evaluated" is
/// exactly the situation, and clients already understand that status here.
#[allow(clippy::result_large_err)]
fn reject_ungateable_legacy_pull_through(repo: &RepoInfo) -> Result<(), Response> {
    if repo.repo_type == RepositoryType::Remote && repo.age_gate_enabled {
        return Err(proxy_helpers::age_gate_unavailable_response(
            &repo.key,
            "VS Code legacy extension download (use the /gallery/... routes)",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn legacy_download_upstream_path(
    publisher: &str,
    name: &str,
    version: &str,
) -> Result<String, Response> {
    for segment in [publisher, name, version] {
        validate_gallery_request_segment(segment)?;
    }
    Ok(format!(
        "extensions/{}/{}/{}/download",
        urlencoding::encode(publisher),
        urlencoding::encode(name),
        urlencoding::encode(version),
    ))
}

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
            // This legacy route synthesizes an upstream download path; it has no
            // gallery document to resolve publish time from and no platform in
            // its coordinate, so it cannot evaluate the age gate. Before this
            // change `vscode` was not in the age-gate matrix at all, so that was
            // harmless — now that a `vscode` repository can have the gate turned
            // on, an ungated pull-through here would be a one-URL bypass of the
            // gallery gate on the same repository. Refuse while the gate is on,
            // using the shared fail-closed response; `/gallery/...` is the gated
            // route. Locally-hosted artifacts (the `Ok` arm) are unaffected —
            // the gate governs proxy pull-through only.
            reject_ungateable_legacy_pull_through(&repo)?;
            let upstream_path = legacy_download_upstream_path(&publisher, &name, &version)?;
            proxy_helpers::enforce_curation(
                &state.db,
                &repo,
                &vscode_age_gate_package(&publisher, &name),
                Some(&version),
            )
            .await?;
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
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
        assert_eq!(normal_target_platform(Some(" Linux-X64 ")), "linux-x64");
    }

    #[test]
    fn gallery_publish_time_evidence_is_rfc3339_or_missing() {
        let old = serde_json::json!({ "lastUpdated": "2024-01-02T03:04:05Z" });
        assert!(gallery_last_updated(&old).is_some());
        assert!(gallery_last_updated(&serde_json::json!({})).is_none());
        assert!(gallery_last_updated(&serde_json::json!({ "lastUpdated": "yesterday" })).is_none());
    }

    fn skeleton_version(
        version: &str,
        target_platform: Option<&str>,
        last_updated: Option<&str>,
    ) -> GallerySkeletonVersion {
        GallerySkeletonVersion {
            version: version.to_string(),
            target_platform: normal_target_platform(target_platform).into_owned(),
            last_updated: last_updated.and_then(gallery_parse_last_updated),
            prerelease: false,
            engine: None,
        }
    }

    #[test]
    fn exact_gallery_lookup_keeps_platform_variants_independent() {
        let skeleton = [
            skeleton_version("1.24.0", Some("linux-x64"), Some("2024-01-02T03:04:05Z")),
            skeleton_version("1.24.0", Some("win32-x64"), Some("not-a-time")),
            skeleton_version("1.24.0", None, Some("2024-01-02T03:04:05Z")),
        ];
        assert!(find_gallery_exact_version(&skeleton, "1.24.0", "linux-x64")
            .flatten()
            .is_some());
        assert_eq!(
            find_gallery_exact_version(&skeleton, "1.24.0", "win32-x64"),
            Some(None),
            "a platform variant without trustworthy evidence must reach the fail-closed seam"
        );
        assert!(find_gallery_exact_version(&skeleton, "1.24.0", "darwin-arm64").is_none());
        assert!(find_gallery_exact_version(&skeleton, "1.24.0", "")
            .flatten()
            .is_some());
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

    async fn rewire_remote_gallery(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        gallery_url: &str,
    ) -> (SharedState, tempfile::TempDir) {
        use crate::api::handlers::test_db_helpers as tdh;

        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("make Remote gallery repository public");

        tdh::rewire_remote_proxy(fx, gallery_url).await
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

    /// The 404 leg of the walk-back: a 404 must mean "the gate allows nothing
    /// at all", so it is only correct once the whole version history has been
    /// consulted and every coordinate in it was withheld.
    #[tokio::test]
    async fn gallery_latest_returns_not_found_when_age_filter_leaves_no_version() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let young = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let also_young = (Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        // Both latest routes are exercised below, so each sub-query runs twice.
        mount_gallery_query(
            &server,
            expected_single_id_query("RedHat.VSCode-YAML", 1023),
            detail_query_response("RedHat", "VSCode-YAML", &[("2.0.0", "linux-x64", &young)]),
            2,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_single_id_query("RedHat.VSCode-YAML", 17),
            dated_skeleton_wire_versions(&[
                ("2.0.0", "linux-x64", &young),
                ("1.0.0", "linux-x64", &also_young),
            ]),
            2,
        )
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
        // The skeleton mock's expect(2) is what proves the walk-back ran and
        // found nothing, rather than the route 404ing before consulting it.
        drop(server);
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
        use wiremock::matchers::{body_json, method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let young = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        // The exact-version check resolves publish time through the skeleton
        // path — a 16 MiB cap and a typed projection, because a large history
        // does not fit under the 2 MiB gallery metadata cap — but asks only for
        // `IncludeVersions`: this runs on every gated asset request, and the
        // properties it would otherwise pay for are never read here.
        let expected_metadata_query = expected_single_id_query("redhat.vscode-yaml", 1);
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(expected_metadata_query))
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
                 is_public = true, age_gate_enabled = true, age_gate_mode = 'upstream_publish_time'
             WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        // State intentionally has no AgeGateService. Delivery checks this
        // before cache/proxy construction.
        let app = fx.router_anon(super::router());
        let (delivery_status, delivery_body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/gallery/publishers/publisher/vsextensions/extension/1.0.0/vspackage",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(delivery_status, StatusCode::SERVICE_UNAVAILABLE);
        // `fx.state` also has no ProxyService, and "Proxy service is
        // unavailable" is ALSO a 503 — so the status alone cannot distinguish
        // "failed closed on the age gate" from "fell through the age gate and
        // then tripped over the missing proxy". Assert the structured body,
        // which only the fail-closed seam produces.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&delivery_body).unwrap()["error"],
            "age_gate_unavailable",
            "delivery must fail closed ON THE AGE GATE, before proxy construction"
        );
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
    fn gallery_manifest_encodes_repo_key_in_every_resource_url() {
        let manifest = build_gallery_manifest(
            &RequestBaseUrl("https://ak.example".to_string()),
            "team/extensions",
        );
        for resource in manifest["resources"].as_array().unwrap() {
            assert!(resource["id"]
                .as_str()
                .unwrap()
                .contains("team%2Fextensions"));
        }
    }

    #[test]
    fn gallery_manifest_ignores_forged_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "registry.example".parse().unwrap());
        headers.insert("x-forwarded-host", "evil.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let base_url = gallery_response_base_url(&headers);
        let manifest = build_gallery_manifest(&base_url, "extensions");
        for resource in manifest["resources"].as_array().unwrap() {
            let id = resource["id"].as_str().unwrap();
            assert!(id.starts_with("https://registry.example/"), "{id}");
            assert!(!id.contains("evil.example"), "{id}");
        }
    }

    #[test]
    fn legacy_download_upstream_path_validates_then_percent_encodes() {
        assert_eq!(
            legacy_download_upstream_path("Publisher Name", "My Extension", "1.0.0+build").unwrap(),
            "extensions/Publisher%20Name/My%20Extension/1.0.0%2Bbuild/download"
        );
        assert!(legacy_download_upstream_path("bad?publisher", "extension", "1.0.0").is_err());
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
    fn gallery_rewrite_preserves_null_asset_references() {
        let mut response = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": "publisher" },
                "extensionName": "extension",
                "versions": [{
                    "version": "1.2.3",
                    "targetPlatform": "universal",
                    "assetUri": null,
                    "fallbackAssetUri": null,
                    "files": [{
                        "assetType": "Microsoft.VisualStudio.Code.Manifest",
                        "source": "https://upstream.example/manifest"
                    }]
                }]
            }] }]
        });

        rewrite_gallery_asset_urls(
            &mut response,
            &RequestBaseUrl("https://ak.example".to_string()),
            "extensions",
        )
        .unwrap();

        let version = &response["results"][0]["extensions"][0]["versions"][0];
        assert!(version["assetUri"].is_null());
        assert!(version["fallbackAssetUri"].is_null());
        assert_eq!(
            version["files"][0]["source"],
            "https://ak.example/vscode/extensions/asset/publisher/extension/1.2.3/universal/Microsoft.VisualStudio.Code.Manifest"
        );
    }

    #[test]
    fn gallery_rewrite_rejects_non_string_non_null_asset_references() {
        for malformed_value in [serde_json::json!({}), serde_json::json!(1)] {
            for field in ["assetUri", "fallbackAssetUri"] {
                let mut response = serde_json::json!({
                    "results": [{ "extensions": [{
                        "publisher": { "publisherName": "publisher" },
                        "extensionName": "extension",
                        "versions": [{
                            "version": "1.2.3",
                            "targetPlatform": "universal",
                            (field): malformed_value.clone(),
                        }]
                    }] }]
                });

                let error = rewrite_gallery_asset_urls(
                    &mut response,
                    &RequestBaseUrl("https://ak.example".to_string()),
                    "extensions",
                )
                .expect_err("non-string asset fields must fail closed");
                assert_eq!(error.status(), StatusCode::BAD_GATEWAY, "{field}");
            }
        }
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
        // A coordinate is also a cache-path component, and a component past the
        // filesystem name limit is a storage error waiting to happen.
        assert!(is_safe_gallery_segment(&"x".repeat(255)));
        assert!(!is_safe_gallery_segment(&"x".repeat(256)));
        assert!(is_safe_target_platform("linux-x64"));
        assert!(is_safe_target_platform("future.web-2"));
        assert!(!is_safe_target_platform("Linux-X64"));
        assert!(!is_safe_target_platform("linux_x64"));
        assert!(!is_safe_target_platform(&"x".repeat(65)));
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

    /// The skeleton is the one gallery document sized by an extension's release
    /// history, so its cap, its reservation multiple, and the per-channel
    /// selection bound are pinned together: relaxing any one of them alone
    /// reopens the unbounded-history path this design closed.
    #[test]
    fn gallery_skeleton_bounds_are_pinned_to_the_measured_worst_case() {
        assert_eq!(
            GALLERY_SKELETON_MAX_BYTES,
            16 * 1024 * 1024,
            "the skeleton cap admits the measured 9.95 MiB worst-case version history"
        );
        assert_eq!(
            GALLERY_SKELETON_BUDGET_MULTIPLE, 4,
            "wire buffer, serde's full property materialization, and the retained projection"
        );
        assert_eq!(
            GALLERY_SKELETON_BUDGET_RESERVATION_BYTES,
            GALLERY_SKELETON_MAX_BYTES * GALLERY_SKELETON_BUDGET_MULTIPLE
        );
        assert_eq!(GALLERY_SKELETON_BUDGET_RESERVATION_BYTES, 64 * 1024 * 1024);
        assert_eq!(GALLERY_METADATA_BUDGET_RESERVATION_BYTES, 64 * 1024 * 1024);
        assert_eq!(GALLERY_VERSIONS_PER_CHANNEL, 30);
        assert_eq!(GALLERY_COMPOSITION_CONCURRENCY, 4);
        assert_eq!(
            GALLERY_SKELETON_QUERY_FLAGS, 17,
            "IncludeVersions | IncludeVersionProperties: lastUpdated plus PreRelease/Engine"
        );
        assert_eq!(GALLERY_LATEST_VERSION_QUERY_FLAGS, 1023);
        assert_eq!(
            GALLERY_EXACT_VERSION_QUERY_FLAGS, 1,
            "the per-gated-download lookup asks for nothing it does not read"
        );
    }

    /// Concurrency bounds simultaneity; these bound TOTAL work and total
    /// resident bytes for one composed response. Both are load-bearing: a 1 MiB
    /// client body can name tens of thousands of identities.
    #[test]
    fn gallery_composition_bounds_total_work_and_resident_bytes() {
        assert_eq!(GALLERY_COMPOSED_IDENTITY_CAP, 50);
        assert_eq!(GALLERY_COMPOSED_EXTENSION_BYTES, 512 * 1024);
        assert_eq!(GALLERY_COMPOSED_QUALIFIER_CAP, 8);
        assert_eq!(
            GALLERY_COMPOSITION_BUDGET_RESERVATION_BYTES,
            GALLERY_COMPOSED_IDENTITY_CAP * GALLERY_COMPOSED_EXTENSION_BYTES * 2
        );
        assert_eq!(
            proxy_helpers::DEFAULT_PROXY_METADATA_BUDGET_BYTES
                / GALLERY_COMPOSITION_BUDGET_RESERVATION_BYTES,
            20,
            "the default shared budget admits at most 20 concurrent composed responses"
        );
        // The accumulation phase is bounded by admission rather than by bytes,
        // so its worst case must be stated in bytes here instead.
        assert_eq!(GALLERY_COMPOSITION_ADMISSION, 20);
        assert_eq!(
            GALLERY_COMPOSITION_ADMISSION
                * GALLERY_COMPOSED_IDENTITY_CAP
                * GALLERY_COMPOSED_EXTENSION_BYTES,
            500 * 1024 * 1024,
            "concurrent composed pages accumulate at most 500 MiB before any is charged"
        );

        let page_size = |value: serde_json::Value| {
            gallery_composed_identity_limit(
                &serde_json::from_value::<GalleryQueryRequest>(value).expect("query parses"),
            )
        };
        assert_eq!(
            page_size(serde_json::json!({ "filters": [{ "pageSize": 10 }], "flags": 1 })),
            10,
            "a client that asked for ten extensions gets ten"
        );
        assert_eq!(
            page_size(serde_json::json!({ "filters": [{ "pageSize": 5000 }], "flags": 1 })),
            GALLERY_COMPOSED_IDENTITY_CAP
        );
        assert_eq!(
            page_size(serde_json::json!({ "filters": [{ "pageSize": 0 }], "flags": 1 })),
            1
        );
        assert_eq!(
            page_size(serde_json::json!({ "filters": [{}], "flags": 1 })),
            GALLERY_COMPOSED_IDENTITY_CAP
        );
    }

    #[test]
    fn gallery_composition_only_claims_pure_identity_version_queries() {
        let request = |body: serde_json::Value| {
            serde_json::from_value::<GalleryQueryRequest>(body).expect("query parses")
        };
        let names = |criteria: &[GalleryCriterion]| {
            criteria
                .iter()
                .map(|criterion| (criterion.filter_type, criterion.value.clone()))
                .collect::<Vec<_>>()
        };

        // The VSCodium update follow-up, in the shape VS Code really sends it:
        // identity selectors interleaved with Target/ExcludeWithFlags
        // qualifiers.
        let composition = gallery_composable_criteria(&request(serde_json::json!({
            "filters": [{ "criteria": [
                { "filterType": 8, "value": "Microsoft.VisualStudio.Code" },
                { "filterType": 7, "value": "redhat.vscode-yaml" },
                { "filterType": 4, "value": "guid-1" },
                { "filterType": 7, "value": "redhat.vscode-yaml" },
                { "filterType": 12, "value": "4096" }
            ]}],
            "flags": 439
        })))
        .expect("pure-identity version query composes");
        assert_eq!(
            names(composition.identities.as_slice()),
            vec![
                (7, "redhat.vscode-yaml".to_string()),
                (4, "guid-1".to_string())
            ],
            "client order is preserved and repeated identities collapse"
        );
        assert_eq!(
            names(composition.qualifiers.as_slice()),
            vec![
                (8, "Microsoft.VisualStudio.Code".to_string()),
                (12, "4096".to_string())
            ],
            "qualifiers do not select an extension, so they are carried, not counted"
        );

        // The identity list is truncated to the client's page, never refused.
        let paged = gallery_composable_criteria(&request(serde_json::json!({
            "filters": [{
                "criteria": [
                    { "filterType": 7, "value": "a.a" },
                    { "filterType": 7, "value": "b.b" },
                    { "filterType": 7, "value": "c.c" }
                ],
                "pageSize": 2
            }],
            "flags": 439
        })))
        .expect("a paged identity query still composes");
        assert_eq!(
            names(paged.identities.as_slice()),
            vec![(7, "a.a".to_string()), (7, "b.b".to_string())]
        );

        let mut too_many_qualifiers = serde_json::json!({
            "filters": [{ "criteria": [] }],
            "flags": 439
        });
        let mut criteria = (0..=GALLERY_COMPOSED_QUALIFIER_CAP)
            .map(|index| serde_json::json!({ "filterType": 12, "value": index.to_string() }))
            .collect::<Vec<_>>();
        criteria.push(serde_json::json!({ "filterType": 7, "value": "a.b" }));
        too_many_qualifiers["filters"][0]["criteria"] = serde_json::Value::Array(criteria);

        for (case, body) in [
            (
                "search text is not an identity",
                serde_json::json!({
                    "filters": [{ "criteria": [{ "filterType": 10, "value": "yaml" }]}],
                    "flags": 439
                }),
            ),
            (
                "no IncludeVersions leaves nothing to bound",
                serde_json::json!({
                    "filters": [{ "criteria": [{ "filterType": 7, "value": "a.b" }]}],
                    "flags": 438
                }),
            ),
            (
                "IncludeLatestVersionOnly is already bounded upstream",
                serde_json::json!({
                    "filters": [{ "criteria": [{ "filterType": 7, "value": "a.b" }]}],
                    "flags": 951
                }),
            ),
            (
                "an empty identity cannot address an extension",
                serde_json::json!({
                    "filters": [{ "criteria": [{ "filterType": 7, "value": "" }]}],
                    "flags": 439
                }),
            ),
            (
                "no criteria at all",
                serde_json::json!({ "filters": [], "flags": 439 }),
            ),
            (
                // Qualifiers are replayed on every sub-query and each one
                // changes what upstream resolves, so a list too long to replay
                // falls back to passthrough rather than being truncated.
                "more qualifiers than one composed query may replay",
                too_many_qualifiers,
            ),
        ] {
            assert!(
                gallery_composable_criteria(&request(body)).is_none(),
                "{case}"
            );
        }
    }

    /// The identity [`skeleton_wire_versions`] attributes its versions to.
    const SKELETON_PACKAGE: &str = "redhat.vscode-yaml";

    /// Build a skeleton wire document with one version per `(version,
    /// platform, prerelease)` triple, newest first, as Open VSX returns it.
    fn skeleton_wire_versions(entries: &[(&str, Option<&str>, bool)]) -> serde_json::Value {
        skeleton_wire_versions_for("RedHat", "VSCode-YAML", entries)
    }

    fn skeleton_wire_versions_for(
        publisher: &str,
        name: &str,
        entries: &[(&str, Option<&str>, bool)],
    ) -> serde_json::Value {
        let versions = entries
            .iter()
            .map(|(version, platform, prerelease)| {
                let mut entry = serde_json::json!({
                    "version": version,
                    "lastUpdated": "2024-01-02T03:04:05Z",
                    "properties": [
                        { "key": GALLERY_PRERELEASE_PROPERTY, "value": prerelease.to_string() },
                        { "key": GALLERY_ENGINE_PROPERTY, "value": "^1.90.0" },
                        { "key": "Microsoft.VisualStudio.Services.Links.Source", "value": "https://upstream.example/src" }
                    ],
                    "assetUri": serde_json::Value::Null,
                    "fallbackAssetUri": serde_json::Value::Null,
                    "files": serde_json::Value::Null,
                });
                if let Some(platform) = platform {
                    entry["targetPlatform"] = serde_json::json!(platform);
                }
                entry
            })
            .collect::<Vec<_>>();
        let mut document = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": publisher },
                "extensionName": name,
                "versions": []
            }] }]
        });
        document["results"][0]["extensions"][0]["versions"] = serde_json::Value::Array(versions);
        document
    }

    fn parse_skeleton(entries: &[(&str, Option<&str>, bool)]) -> Vec<GallerySkeletonVersion> {
        let document: GallerySkeletonWireDocument =
            serde_json::from_value(skeleton_wire_versions(entries)).expect("skeleton parses");
        gallery_skeleton_versions(document, SKELETON_PACKAGE)
    }

    #[test]
    fn gallery_skeleton_keeps_only_the_fields_synthesis_needs() {
        let parsed = parse_skeleton(&[("2.0.0", Some("LINUX-X64"), true), ("1.0.0", None, false)]);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].version, "2.0.0");
        assert_eq!(parsed[0].target_platform, "linux-x64");
        assert!(parsed[0].prerelease);
        assert_eq!(parsed[0].engine.as_deref(), Some("^1.90.0"));
        assert!(parsed[0].last_updated.is_some());
        // An absent targetPlatform is the universal build, not a missing one.
        assert_eq!(parsed[1].target_platform, DEFAULT_TARGET_PLATFORM);
        assert!(!parsed[1].prerelease);

        // A coordinate that would escape a path segment is dropped, not fatal:
        // one bad entry in a 12,592-version history must not take the whole
        // extension offline for search AND /latest.
        let mixed = parse_skeleton(&[
            ("1.0.0", Some("../escape"), false),
            ("1.0.0", Some("linux-x64"), false),
        ]);
        assert_eq!(mixed.len(), 1);
        assert_eq!(mixed[0].target_platform, "linux-x64");
    }

    /// A version list is only evidence about the extension it belongs to.
    /// Upstream may answer a single-identity lookup with a page that names
    /// others; borrowing their publish times would let a gated download for one
    /// extension inherit another's age.
    #[test]
    fn gallery_skeleton_ignores_versions_of_other_extensions() {
        let mut document =
            skeleton_wire_versions_for("Someone", "Else", &[("9.9.9", Some("linux-x64"), false)]);
        let wanted = skeleton_wire_versions(&[("1.0.0", Some("linux-x64"), false)]);
        document["results"][0]["extensions"]
            .as_array_mut()
            .unwrap()
            .push(wanted["results"][0]["extensions"][0].clone());

        let parsed: GallerySkeletonWireDocument =
            serde_json::from_value(document).expect("skeleton parses");
        let versions = gallery_skeleton_versions(parsed, SKELETON_PACKAGE);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
    }

    #[test]
    fn gallery_selection_orders_by_publish_time_not_upstream_position() {
        let selected = select_bounded_gallery_versions(vec![
            skeleton_version("1.0.0", Some("linux-x64"), Some("2024-01-01T00:00:00Z")),
            skeleton_version("3.0.0", Some("linux-x64"), None),
            skeleton_version("2.0.0", Some("linux-x64"), Some("2025-01-01T00:00:00Z")),
            skeleton_version("2.0.0", Some("linux-x64"), Some("2025-01-01T00:00:00Z")),
        ]);
        assert_eq!(
            selected
                .iter()
                .map(|version| version.version.as_str())
                .collect::<Vec<_>>(),
            vec!["2.0.0", "1.0.0", "3.0.0"],
            "newest first, undated last, and a coordinate listed twice spends one slot"
        );
    }

    #[test]
    fn gallery_selection_is_bounded_per_platform_and_channel() {
        let prerelease_versions = (0..GALLERY_VERSIONS_PER_CHANNEL + 5)
            .map(|index| format!("2.0.{index}"))
            .collect::<Vec<_>>();
        let mut entries = Vec::new();
        for version in &prerelease_versions {
            entries.push((version.as_str(), Some("linux-x64"), true));
            entries.push((version.as_str(), Some("win32-x64"), true));
        }
        // The one stable build sits below every pre-release, exactly like
        // rust-analyzer's newest stable at index 10,970 of 12,592.
        entries.push(("1.0.0", Some("linux-x64"), false));

        let selected = select_bounded_gallery_versions(parse_skeleton(&entries));
        let linux_prerelease = selected
            .iter()
            .filter(|version| version.target_platform == "linux-x64" && version.prerelease)
            .collect::<Vec<_>>();
        assert_eq!(linux_prerelease.len(), GALLERY_VERSIONS_PER_CHANNEL);
        assert_eq!(
            linux_prerelease[0].version, "2.0.0",
            "upstream newest-first order is preserved"
        );
        assert_eq!(
            selected
                .iter()
                .filter(|version| version.target_platform == "win32-x64")
                .count(),
            GALLERY_VERSIONS_PER_CHANNEL
        );
        assert!(
            selected
                .iter()
                .any(|version| version.version == "1.0.0" && !version.prerelease),
            "bucketing by channel keeps the stable build a positional cut would lose"
        );
    }

    #[test]
    fn gallery_synthesis_owns_every_asset_reference_it_emits() {
        let base_url = RequestBaseUrl("https://ak.example".to_string());
        let parsed = parse_skeleton(&[("1.2.3", Some("linux-x64"), true), ("1.0.0", None, false)]);
        let platform_base = gallery_version_asset_base(
            &base_url,
            "extensions",
            "RedHat",
            "VSCode-YAML",
            "1.2.3",
            "linux-x64",
        )
        .unwrap();
        let synthesized = synthesize_gallery_version(&parsed[0], &platform_base, 1023);
        assert_eq!(
            synthesized["assetUri"],
            "https://ak.example/vscode/extensions/asset/RedHat/VSCode-YAML/1.2.3/linux-x64"
        );
        assert_eq!(synthesized["fallbackAssetUri"], synthesized["assetUri"]);
        assert_eq!(synthesized["targetPlatform"], "linux-x64");
        assert_eq!(
            synthesized["properties"],
            serde_json::json!([
                { "key": GALLERY_PRERELEASE_PROPERTY, "value": "true" },
                { "key": GALLERY_ENGINE_PROPERTY, "value": "^1.90.0" }
            ]),
            "only the two properties that decide channel and engine survive"
        );
        // VS Code filters `files` BEFORE it consults `assetUri`, so a version
        // without a file list is not installable however correct its URI is.
        let files = synthesized["files"].as_array().expect("synthesized files");
        assert_eq!(files.len(), GALLERY_SYNTHESIZED_ASSET_TYPES.len());
        assert_eq!(
            files[0],
            serde_json::json!({
                "assetType": "Microsoft.VisualStudio.Services.VSIXPackage",
                "source": format!("{platform_base}/Microsoft.VisualStudio.Services.VSIXPackage"),
            })
        );

        // Asset metadata mirrors what the client asked for, exactly as upstream
        // would have answered a query without those flags.
        let bare = synthesize_gallery_version(&parsed[0], &platform_base, 1);
        for field in ["assetUri", "fallbackAssetUri", "files"] {
            assert!(bare.get(field).is_none(), "{field}");
        }

        let universal_base = gallery_version_asset_base(
            &base_url,
            "extensions",
            "RedHat",
            "VSCode-YAML",
            "1.0.0",
            DEFAULT_TARGET_PLATFORM,
        )
        .unwrap();
        let universal = synthesize_gallery_version(&parsed[1], &universal_base, 1023);
        assert!(
            universal.get("targetPlatform").is_none(),
            "a universal build keeps upstream's own omitted-platform shape"
        );
        assert_eq!(
            universal["properties"],
            serde_json::json!([{ "key": GALLERY_ENGINE_PROPERTY, "value": "^1.90.0" }])
        );
    }

    #[test]
    fn gallery_results_envelope_counts_what_it_carries() {
        let composed =
            gallery_results_envelope(vec![serde_json::json!({ "extensionName": "a" })], None);
        assert_eq!(
            composed["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"],
            1
        );
        assert_eq!(
            composed["results"][0]["extensions"][0]["extensionName"],
            "a"
        );

        // An upstream page already counted every page of the query. Replacing
        // that with the composed page length would tell a paging client it had
        // reached the end.
        let upstream = gallery_results_envelope(
            vec![serde_json::json!({ "extensionName": "a" })],
            Some(serde_json::json!([{
                "metadataType": "ResultCount",
                "metadataItems": [{ "name": "TotalCount", "count": 4096 }]
            }])),
        );
        assert_eq!(
            upstream["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"],
            4096
        );
    }

    #[test]
    fn gallery_query_flag_rewrite_refuses_a_body_it_cannot_reshape() {
        let versions_and_latest_only = 1 | 512;
        let rewritten = gallery_query_with_flags(
            &Bytes::from_static(b"{\"filters\":[],\"flags\":439,\"assetTypes\":[\"x\"]}"),
            versions_and_latest_only,
        )
        .expect("an object body is reshaped in place");
        let rewritten: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(rewritten["flags"], versions_and_latest_only);
        assert_eq!(
            rewritten["assetTypes"][0], "x",
            "every other field the client sent is preserved"
        );

        // A body that is valid JSON but not an object has no `flags` member to
        // rewrite, and one that is not JSON at all never had one.
        assert!(gallery_query_with_flags(&Bytes::from_static(b"[1,2]"), 1).is_none());
        assert!(gallery_query_with_flags(&Bytes::from_static(b"nope"), 1).is_none());
        assert_eq!(
            gallery_query_flags(&Bytes::from_static(b"{\"flags\":439}")),
            Some(439)
        );
        assert!(gallery_query_flags(&Bytes::from_static(b"{}")).is_none());
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
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        // `expect(0)` is what makes the `without_proxying` half of this test's
        // name an assertion rather than a claim: without it a 400 produced
        // AFTER an upstream round-trip would still be green.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        // Gallery endpoints require a gallery-root upstream even though this
        // malformed body must be rejected before any upstream request.
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
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
            let (status, body) = tdh::send(app.clone(), request).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "private Remote gallery route is forbidden by the public-only contract"
            );
            assert!(!String::from_utf8_lossy(&body).contains("prototype"));
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
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;

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
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let app = tdh::router_anon(super::router(), state.clone());
        let mut request = tdh::post(
            format!("/{}/gallery/extensionquery", fx.repo_key),
            "application/json",
            Bytes::from(serde_json::to_vec(&query).unwrap()),
        );
        request
            .headers_mut()
            .insert("host", "registry.example".parse().expect("valid Host"));
        request.headers_mut().insert(
            "x-forwarded-host",
            "evil.example".parse().expect("valid forwarded host"),
        );
        request.headers_mut().insert(
            "x-forwarded-proto",
            "https".parse().expect("valid forwarded proto"),
        );
        let (status, body) = tdh::send(app, request).await;

        assert_eq!(status, StatusCode::OK, "gateway must return query result");
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let version = &response["results"][0]["extensions"][0]["versions"][0];
        let expected_base = format!(
            "https://registry.example/vscode/{}/asset/publisher/extension/1.2.3/linux-x64",
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
        assert!(!body
            .windows(b"evil.example".len())
            .any(|w| w == b"evil.example"));

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

    /// The single-identity `extensionquery` wire shape AK issues on a client's
    /// behalf, restated here independently of the production builder.
    fn expected_single_id_query(value: &str, flags: u32) -> serde_json::Value {
        expected_qualified_id_query(value, &[], flags)
    }

    /// [`expected_single_id_query`] with the client's own non-selecting
    /// criteria repeated after the identity, in that order.
    fn expected_qualified_id_query(
        value: &str,
        qualifiers: &[(u64, &str)],
        flags: u32,
    ) -> serde_json::Value {
        let mut criteria = vec![serde_json::json!({ "filterType": 7, "value": value })];
        criteria.extend(qualifiers.iter().map(
            |(filter_type, value)| serde_json::json!({ "filterType": filter_type, "value": value }),
        ));
        let mut query = serde_json::json!({
            "filters": [{
                "criteria": [],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 0,
                "sortOrder": 0,
            }],
            "flags": flags,
        });
        query["filters"][0]["criteria"] = serde_json::Value::Array(criteria);
        query
    }

    /// A client query naming extensions and asking for their whole version
    /// history — the VSCodium update follow-up shape.
    fn client_identity_query(values: &[&str], flags: u32) -> serde_json::Value {
        let criteria = values
            .iter()
            .map(|value| serde_json::json!({ "filterType": 7, "value": value }))
            .collect::<Vec<_>>();
        let mut filter = serde_json::json!({
            "criteria": [],
            "pageNumber": 1,
            "pageSize": 50,
            "sortBy": 0,
            "sortOrder": 0,
        });
        filter["criteria"] = serde_json::Value::Array(criteria);
        let mut query = serde_json::json!({ "filters": [], "flags": flags });
        query["filters"] = serde_json::Value::Array(vec![filter]);
        query
    }

    /// One extension as an `IncludeLatestVersionOnly` detail query returns it:
    /// a full envelope plus its latest-per-platform versions, each carrying the
    /// upstream delivery URLs the gateway must rewrite. Entries are
    /// `(version, targetPlatform, lastUpdated)`.
    fn detail_query_response(
        publisher: &str,
        name: &str,
        versions: &[(&str, &str, &str)],
    ) -> serde_json::Value {
        let versions = versions
            .iter()
            .map(|(version, platform, last_updated)| {
                serde_json::json!({
                    "version": version,
                    "targetPlatform": platform,
                    "lastUpdated": last_updated,
                    "assetUri": "https://upstream.example/assets",
                    "fallbackAssetUri": "https://cdn.example/assets",
                    "files": [{
                        "assetType": "README.md",
                        "source": "https://cdn.example/README.md"
                    }]
                })
            })
            .collect::<Vec<_>>();
        let mut response = serde_json::json!({
            "results": [{ "extensions": [{
                "publisher": { "publisherName": publisher },
                "extensionName": name,
                "displayName": name,
                "versions": []
            }] }]
        });
        response["results"][0]["extensions"][0]["versions"] = serde_json::Value::Array(versions);
        response
    }

    /// [`skeleton_wire_versions`] with an explicit publish time per entry:
    /// `(version, targetPlatform, lastUpdated)`.
    fn dated_skeleton_wire_versions(entries: &[(&str, &str, &str)]) -> serde_json::Value {
        let platforms = entries
            .iter()
            .map(|(version, platform, _)| (*version, Some(*platform), false))
            .collect::<Vec<_>>();
        let mut document = skeleton_wire_versions(&platforms);
        for (index, (_, _, last_updated)) in entries.iter().enumerate() {
            document["results"][0]["extensions"][0]["versions"][index]["lastUpdated"] =
                serde_json::json!(last_updated);
        }
        document
    }

    async fn mount_gallery_query(
        server: &wiremock::MockServer,
        request_body: serde_json::Value,
        response_body: serde_json::Value,
        expected_calls: u64,
    ) {
        use wiremock::matchers::{body_json, method, path};

        wiremock::Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(request_body))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(response_body))
            .expect(expected_calls)
            .mount(server)
            .await;
    }

    fn gallery_versions_of(response: &serde_json::Value, index: usize) -> Vec<serde_json::Value> {
        response["results"][0]["extensions"][index]["versions"]
            .as_array()
            .expect("composed extension carries versions")
            .clone()
    }

    fn assert_no_upstream_hosts(body: &Bytes) {
        for host in [b"upstream.example".as_slice(), b"cdn.example".as_slice()] {
            assert!(
                !body.windows(host.len()).any(|window| window == host),
                "composed response must not retain an upstream host: {}",
                String::from_utf8_lossy(host)
            );
        }
    }

    /// The VSCodium update follow-up must never be forwarded as-is: upstream
    /// answers it with the whole version history (28.1 MiB for one popular
    /// extension). It is answered from a bounded detail + skeleton pair, and the
    /// stable build deep in a pre-release-heavy history must survive.
    #[tokio::test]
    async fn gallery_query_composes_bounded_versions_instead_of_the_full_history() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let client_query = client_identity_query(&["redhat.vscode-yaml"], 439);
        // `expect(0)` is what makes this an assertion rather than a claim: the
        // unbounded query must not reach upstream at all.
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(client_query.clone()))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        mount_gallery_query(
            &server,
            expected_single_id_query("redhat.vscode-yaml", 951),
            detail_query_response(
                "RedHat",
                "VSCode-YAML",
                &[
                    // Newer than anything the skeleton lists: a publish that
                    // landed between the two round-trips.
                    ("4.0.0", "linux-x64", "2025-06-01T00:00:00Z"),
                    ("3.0.0-rc.1", "linux-x64", "2024-06-01T00:00:00Z"),
                ],
            ),
            1,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_single_id_query("redhat.vscode-yaml", 17),
            skeleton_wire_versions(&[
                ("3.0.0-rc.1", Some("linux-x64"), true),
                ("2.0.0-rc.1", Some("linux-x64"), true),
                ("1.5.0", Some("linux-x64"), false),
            ]),
            1,
        )
        .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&client_query).unwrap()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = gallery_versions_of(&response, 0);
        assert_eq!(versions.len(), 4);

        let asset_prefix = format!("/vscode/{}/asset/RedHat/VSCode-YAML/", fx.repo_key);
        for version in &versions {
            for field in ["assetUri", "fallbackAssetUri"] {
                let value = version[field].as_str().expect("AK-owned asset reference");
                assert!(value.contains(&asset_prefix), "{field}: {value}");
            }
        }
        // Newest first by publish time, so the coordinate only the detail query
        // knew about leads rather than trailing the merge.
        assert_eq!(
            versions
                .iter()
                .map(|version| version["version"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["4.0.0", "3.0.0-rc.1", "2.0.0-rc.1", "1.5.0"]
        );
        // Detail-derived entries keep the files the skeleton never carried,
        // rewritten onto AK.
        assert!(versions[0]["files"][0]["source"]
            .as_str()
            .expect("rewritten file source")
            .ends_with(&format!("{asset_prefix}4.0.0/linux-x64/README.md")));
        // The stable build below every pre-release is still reachable, and a
        // synthesized entry advertises the file list VS Code resolves an
        // install through.
        assert_eq!(
            versions[3]["properties"],
            serde_json::json!([{ "key": GALLERY_ENGINE_PROPERTY, "value": "^1.90.0" }]),
            "a stable synthesized entry carries no PreRelease property"
        );
        let synthesized_files = versions[3]["files"]
            .as_array()
            .expect("a synthesized entry must be installable");
        assert_eq!(
            synthesized_files.len(),
            GALLERY_SYNTHESIZED_ASSET_TYPES.len()
        );
        assert!(synthesized_files[0]["source"]
            .as_str()
            .unwrap()
            .ends_with(&format!(
                "{asset_prefix}1.5.0/linux-x64/Microsoft.VisualStudio.Services.VSIXPackage"
            )));
        assert_eq!(
            response["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"],
            1
        );
        assert_no_upstream_hosts(&body);
        drop(server);
        fx.teardown().await;
    }

    /// Real VS Code bodies carry `Target` and `ExcludeWithFlags` qualifiers
    /// alongside their identity selectors. Treating those as "not an identity
    /// query" would send the whole update check back down the 28 MiB
    /// passthrough, so they qualify composition instead of disqualifying it —
    /// and every sub-query must repeat them or it resolves a different set.
    #[tokio::test]
    async fn gallery_query_composes_through_target_and_exclude_qualifiers() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let qualifiers: [(u64, &str); 2] = [(8, "Microsoft.VisualStudio.Code"), (12, "4096")];
        let mut client_query = client_identity_query(&["redhat.vscode-yaml"], 439);
        client_query["filters"][0]["criteria"] = serde_json::json!([
            { "filterType": 8, "value": "Microsoft.VisualStudio.Code" },
            { "filterType": 7, "value": "redhat.vscode-yaml" },
            { "filterType": 12, "value": "4096" }
        ]);
        mount_gallery_query(
            &server,
            expected_qualified_id_query("redhat.vscode-yaml", &qualifiers, 951),
            detail_query_response(
                "RedHat",
                "VSCode-YAML",
                &[("2.0.0", "linux-x64", "2024-06-01T00:00:00Z")],
            ),
            1,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_qualified_id_query("redhat.vscode-yaml", &qualifiers, 17),
            skeleton_wire_versions(&[
                ("2.0.0", Some("linux-x64"), false),
                ("1.0.0", Some("linux-x64"), false),
            ]),
            1,
        )
        .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&client_query).unwrap()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(gallery_versions_of(&response, 0).len(), 2);
        // Both mocks carry expect(1): the qualifiers reached upstream on both
        // sub-queries, which is the whole point of this test.
        drop(server);
        fx.teardown().await;
    }

    /// A text search that also asks for versions cannot be composed up front —
    /// only upstream knows which extensions it matches. When its passthrough
    /// aborts on the metadata ceiling, an identity-only pre-pass of the SAME
    /// query recovers those identities and each one composes.
    #[tokio::test]
    async fn gallery_query_recovers_from_the_ceiling_with_an_identity_pre_pass() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        // A real search body carries the same Target qualifier an update check
        // does. Upstream picked its results under that qualifier, so the
        // per-identity sub-queries below must carry it too.
        let qualifiers: [(u64, &str); 1] = [(8, "Microsoft.VisualStudio.Code")];
        let search_query = serde_json::json!({
            "filters": [{
                "criteria": [
                    { "filterType": 10, "value": "yaml" },
                    { "filterType": 8, "value": "Microsoft.VisualStudio.Code" }
                ],
                "pageNumber": 1,
                "pageSize": 50,
                "sortBy": 0,
                "sortOrder": 0,
            }],
            "flags": 439
        });
        let mut identity_query = search_query.clone();
        // (439 | IncludeLatestVersionOnly) & !IncludeVersions
        identity_query["flags"] = serde_json::json!(950);

        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(search_query.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("x".repeat(GALLERY_METADATA_MAX_BYTES + 1024)),
            )
            .expect(1)
            .mount(&server)
            .await;
        mount_gallery_query(
            &server,
            identity_query,
            serde_json::json!({
                "results": [{
                    "extensions": [{
                        "publisher": { "publisherName": "RedHat" },
                        "extensionName": "VSCode-YAML"
                    }],
                    "resultMetadata": [{
                        "metadataType": "ResultCount",
                        "metadataItems": [{ "name": "TotalCount", "count": 4096 }]
                    }]
                }]
            }),
            1,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_qualified_id_query("RedHat.VSCode-YAML", &qualifiers, 951),
            detail_query_response(
                "RedHat",
                "VSCode-YAML",
                &[("2.0.0", "linux-x64", "2024-06-01T00:00:00Z")],
            ),
            1,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_qualified_id_query("RedHat.VSCode-YAML", &qualifiers, 17),
            skeleton_wire_versions(&[
                ("2.0.0", Some("linux-x64"), false),
                ("1.0.0", Some("linux-x64"), false),
            ]),
            1,
        )
        .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&search_query).unwrap()),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a ceiling abort on a versions query must recover, not 502"
        );
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = gallery_versions_of(&response, 0);
        assert_eq!(versions.len(), 2);
        assert!(versions[1]["assetUri"]
            .as_str()
            .unwrap()
            .contains(&format!("/vscode/{}/asset/", fx.repo_key)));
        // The pre-pass response counted every page of the search. Composing one
        // page must not overwrite that with "1" and stop a paging client.
        assert_eq!(
            response["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"], 4096,
            "the upstream cross-page count is carried forward, not replaced"
        );
        assert_no_upstream_hosts(&body);
        drop(server);
        fx.teardown().await;
    }

    /// A ceiling abort is only recoverable because the client asked for
    /// versions. Without that flag the response is already as narrow as the
    /// protocol lets it be asked for, and there is nothing to compose.
    #[tokio::test]
    async fn gallery_query_without_versions_surfaces_the_ceiling() {
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
                ResponseTemplate::new(200)
                    .set_body_string("x".repeat(GALLERY_METADATA_MAX_BYTES + 1024)),
            )
            // Exactly one attempt: there is no identity pre-pass to make.
            .expect(1)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, _) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from_static(b"{\"filters\":[],\"flags\":438}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        drop(server);
        fx.teardown().await;
    }

    /// The skeleton has its own, much larger cap, but it is still a cap: an
    /// extension whose history exceeds it fails visibly rather than being
    /// buffered without bound.
    #[tokio::test]
    async fn gallery_skeleton_over_its_own_cap_fails_closed() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let client_query = client_identity_query(&["redhat.vscode-yaml"], 439);
        mount_gallery_query(
            &server,
            expected_single_id_query("redhat.vscode-yaml", 951),
            detail_query_response(
                "RedHat",
                "VSCode-YAML",
                &[("2.0.0", "linux-x64", "2024-06-01T00:00:00Z")],
            ),
            1,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/vscode/gallery/extensionquery"))
            .and(body_json(expected_single_id_query(
                "redhat.vscode-yaml",
                17,
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("x".repeat(GALLERY_SKELETON_MAX_BYTES + 1024)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, _) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&client_query).unwrap()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        drop(server);
        fx.teardown().await;
    }

    /// Composition answers every identity the client listed, in the order it
    /// listed them, and `TotalCount` reports what the envelope actually
    /// carries — an identity upstream does not know is simply absent.
    #[tokio::test]
    async fn gallery_query_composes_multiple_identities_in_client_order() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let client_query = client_identity_query(
            &["second.extension", "missing.extension", "first.extension"],
            3,
        );
        for (identity, publisher, name) in [
            ("second.extension", "Second", "Extension"),
            ("first.extension", "First", "Extension"),
        ] {
            mount_gallery_query(
                &server,
                expected_single_id_query(identity, 3 | 512),
                detail_query_response(
                    publisher,
                    name,
                    &[("1.0.0", "linux-x64", "2024-06-01T00:00:00Z")],
                ),
                1,
            )
            .await;
            mount_gallery_query(
                &server,
                expected_single_id_query(identity, 17),
                // The skeleton must name the SAME extension the detail query
                // reported, or its versions are not evidence about it.
                skeleton_wire_versions_for(publisher, name, &[("1.0.0", Some("linux-x64"), false)]),
                1,
            )
            .await;
        }
        // The unknown identity costs one detail query and no skeleton query.
        mount_gallery_query(
            &server,
            expected_single_id_query("missing.extension", 3 | 512),
            serde_json::json!({ "results": [{ "extensions": [] }] }),
            1,
        )
        .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::post(
                format!("/{}/gallery/extensionquery", fx.repo_key),
                "application/json",
                Bytes::from(serde_json::to_vec(&client_query).unwrap()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let extensions = response["results"][0]["extensions"]
            .as_array()
            .expect("composed envelope carries extensions");
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0]["publisher"]["publisherName"], "Second");
        assert_eq!(extensions[1]["publisher"]["publisherName"], "First");
        assert_eq!(
            response["results"][0]["resultMetadata"][0]["metadataItems"][0]["count"], 2,
            "TotalCount reports the composed envelope, not the client's identity list"
        );
        drop(server);
        fx.teardown().await;
    }

    /// With the gate on, the latest version is frequently too young to serve.
    /// Open VSX only reports latest-per-platform, so without a walk-back the
    /// route 404s an extension whose older releases are perfectly servable.
    #[tokio::test]
    async fn gallery_latest_walks_back_to_the_newest_gate_allowed_version() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let young = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let old = (Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        mount_gallery_query(
            &server,
            expected_single_id_query("RedHat.VSCode-YAML", 1023),
            detail_query_response("RedHat", "VSCode-YAML", &[("2.0.0", "linux-x64", &young)]),
            1,
        )
        .await;
        mount_gallery_query(
            &server,
            expected_single_id_query("RedHat.VSCode-YAML", 17),
            dated_skeleton_wire_versions(&[
                ("2.0.0", "linux-x64", &young),
                ("1.0.0", "linux-x64", &old),
            ]),
            1,
        )
        .await;

        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) =
            rewire_remote_gallery_with_age_gate(&fx, &gallery_root, "upstream_publish_time", 7)
                .await;
        let (status, body) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{}/gallery/RedHat/VSCode-YAML/latest",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a gated latest lookup resolves an older allowed release"
        );
        let extension: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(extension["displayName"], "VSCode-YAML");
        let versions = extension["versions"].as_array().expect("versions");
        assert_eq!(versions.len(), 1, "one release per target platform");
        assert_eq!(versions[0]["version"], "1.0.0");
        assert_eq!(versions[0]["targetPlatform"], "linux-x64");
        assert!(versions[0]["assetUri"]
            .as_str()
            .expect("AK-owned asset reference")
            .ends_with(&format!(
                "/vscode/{}/asset/RedHat/VSCode-YAML/1.0.0/linux-x64",
                fx.repo_key
            )));
        assert_no_upstream_hosts(&body);
        drop(server);
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
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
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
            "flags": 1023,
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
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
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
        // The upstream also carries `fallbackAssetUri`. Checking `assetUri`
        // alone leaves the most-used route green while leaking a CDN URL to the
        // client, so scan the whole serialized body — the same egress assertion
        // `test_openvsx_extensionquery_posts_and_rewrites_every_asset_url` makes.
        for host in [b"upstream.example".as_slice(), b"cdn.example".as_slice()] {
            assert!(
                !body.windows(host.len()).any(|window| window == host),
                "latest-version response must not retain an upstream host: {}",
                String::from_utf8_lossy(host)
            );
        }

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
        let (state, cache) = rewire_remote_gallery(&fx, &gallery_root).await;

        let request = |platform: &str| {
            tdh::get(format!(
                "/{}/gallery/publishers/publisher/vsextensions/extension/1.2.3/vspackage?targetPlatform={platform}",
                fx.repo_key
            ))
        };
        let (linux_status, linux_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            request("LINUX-X64"),
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

    /// Curation must cover the legacy Remote pull-through as well as the new
    /// gallery delivery paths. Otherwise an emergency deny blocks the gallery
    /// URL while the same VSIX remains downloadable through `/extensions`.
    #[tokio::test]
    async fn legacy_remote_download_honors_curation_before_upstream_fetch() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        let allowed_bytes = b"allowed-legacy-vsix";
        Mock::given(method("GET"))
            .and(path("/extensions/Other/extension/1.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(allowed_bytes))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/extensions/Blocked/extension/1.0.0/download"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        enable_curation_block(&fx, "blocked.extension").await;
        let request = |publisher: &str| {
            tdh::get(format!(
                "/{}/extensions/{publisher}/extension/1.0.0/download",
                fx.repo_key
            ))
        };

        let (blocked_status, blocked_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            request("Blocked"),
        )
        .await;
        assert_eq!(blocked_status, StatusCode::FORBIDDEN);
        let blocked: serde_json::Value = serde_json::from_slice(&blocked_body).unwrap();
        assert_eq!(blocked["error"], "curation_blocked");
        assert_eq!(blocked["package"], "blocked.extension");

        let (allowed_status, allowed_body) =
            tdh::send(tdh::router_anon(super::router(), state), request("Other")).await;
        assert_eq!(allowed_status, StatusCode::OK);
        assert_eq!(&allowed_body[..], allowed_bytes);

        drop(server);
        drop_curation_rules(&fx).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn legacy_remote_download_rejects_unsafe_decoded_path_segments() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (status, _) = tdh::send(
            fx.router_anon(super::router()),
            tdh::get(format!(
                "/{}/extensions/bad%3Fpublisher/extension/1.0.0/download",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        fx.teardown().await;
    }

    /// `/item` is the only format-handler route that emits a `Location` a
    /// browser follows. Building it from `RequestBaseUrl` — which falls back to
    /// `X-Forwarded-Host` when `AK_EXTERNAL_URL` is unset — would make it a
    /// header-controlled open redirect, so the target must stay relative.
    #[tokio::test]
    async fn gallery_item_redirect_ignores_a_forged_forwarded_host() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let server = MockServer::start().await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;

        let mut request = tdh::get(format!("/{}/item", fx.repo_key));
        request.headers_mut().insert(
            "x-forwarded-host",
            "evil.example".parse().expect("valid header"),
        );
        request
            .headers_mut()
            .insert("x-forwarded-proto", "https".parse().expect("valid header"));
        let response = {
            use tower::ServiceExt;
            tdh::router_anon(super::router(), state)
                .oneshot(request)
                .await
                .expect("router responds")
        };
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("redirect carries a Location")
            .to_str()
            .expect("ASCII Location");
        assert!(
            !location.contains("evil.example"),
            "Location must not echo a client-supplied host: {location}"
        );
        // Positive control: the redirect still points at the right page, so the
        // assertion above cannot be satisfied by an empty or broken Location.
        assert_eq!(location, format!("/repositories/{}", fx.repo_key));
        fx.teardown().await;
    }

    /// Insert a curation `block` rule for `pattern` on the fixture repository
    /// and switch curation on. Mirrors `proxy_helpers::tests::seed_curated_repo`.
    async fn enable_curation_block(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        pattern: &str,
    ) {
        sqlx::query(
            "UPDATE repositories SET curation_enabled = true, \
             curation_default_action = 'allow' WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("enable curation");
        sqlx::query(
            "INSERT INTO curation_rules (staging_repo_id, package_pattern, version_constraint, \
             architecture, action, priority, reason, created_by) \
             VALUES ($1, $2, '*', '*', 'block', 100, 'gallery curation test', $3)",
        )
        .bind(fx.repo_id)
        .bind(pattern)
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("insert curation block rule");
    }

    async fn drop_curation_rules(fx: &crate::api::handlers::test_db_helpers::Fixture) {
        let _ = sqlx::query("DELETE FROM curation_rules WHERE staging_repo_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
    }

    /// A curation `block` rule must stop a gallery VSIX/asset serve, and must
    /// stop it BEFORE any upstream byte fetch. The allowed extension in the
    /// same fixture is the positive control: without it, a fixture in which
    /// every request fails for an unrelated reason would satisfy the negative
    /// assertion on its own.
    #[tokio::test]
    async fn gallery_delivery_honors_curation_block_before_upstream_fetch() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        let (server, _ssrf_allowlist) = tdh::non_loopback_mock_server().await;
        let allowed_bytes = b"allowed-vsix";
        Mock::given(method("GET"))
            .and(path(
                "/vscode/gallery/publishers/Blocked/vsextensions/extension/1.0.0/vspackage",
            ))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        // The blocked path's `expect(0)` pins that curation runs before any
        // fetch. The allowed path's `expect(1)` is the positive control.
        Mock::given(method("GET"))
            // The upstream path keeps the caller's casing; only the curation /
            // age-gate identity is casefolded.
            .and(path(
                "/vscode/gallery/publishers/Other/vsextensions/extension/1.0.0/vspackage",
            ))
            // The client sends NO `targetPlatform`, and the cache key it lands
            // on is the normalized `universal` one — so the upstream request
            // must carry `targetPlatform=universal` too. Deriving the upstream
            // query from the raw option instead put two different upstream URLs
            // behind one permanently-immutable cache key.
            .and(query_param("targetPlatform", "universal"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(allowed_bytes))
            .expect(1)
            .mount(&server)
            .await;
        let gallery_root = format!("{}/vscode/gallery", server.uri());
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
        enable_curation_block(&fx, "blocked.extension").await;

        let vspackage = |publisher: &str| {
            tdh::get(format!(
                "/{}/gallery/publishers/{publisher}/vsextensions/extension/1.0.0/vspackage",
                fx.repo_key
            ))
        };

        // Negative: the curated coordinate is refused with the shared 403.
        let (blocked_status, blocked_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            vspackage("Blocked"),
        )
        .await;
        assert_eq!(
            blocked_status,
            StatusCode::FORBIDDEN,
            "a curation block rule must stop the gallery download"
        );
        let blocked: serde_json::Value = serde_json::from_slice(&blocked_body).unwrap();
        assert_eq!(blocked["error"], "curation_blocked");
        // Casefolded `publisher.extension` — one operator rule governs the
        // curation gate and the age gate alike.
        assert_eq!(blocked["package"], "blocked.extension");

        // Positive control, same fixture, same curation-enabled repository: a
        // non-matching extension still serves its bytes.
        let (allowed_status, allowed_body) = tdh::send(
            tdh::router_anon(super::router(), state.clone()),
            vspackage("Other"),
        )
        .await;
        assert_eq!(allowed_status, StatusCode::OK);
        assert_eq!(&allowed_body[..], allowed_bytes);

        // `expect(1)` on the single mounted mock: the blocked request never
        // reached upstream, and the allowed one did exactly once.
        drop(server);
        drop_curation_rules(&fx).await;
        fx.teardown().await;
    }

    /// The legacy `/extensions/{publisher}/{name}/{version}/download` route
    /// cannot evaluate the age gate, so it must not remain a pull-through while
    /// the gate is enabled — otherwise it is a one-URL bypass of the gallery
    /// gate on the same repository.
    #[tokio::test]
    async fn legacy_remote_download_refuses_while_age_gate_is_enabled() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "vscode").await else {
            return;
        };
        // Plain loopback wiremock, exactly as the sibling
        // `test_remote_vsix_download_streams_upstream_blob_1608` uses for this
        // same route.
        let server = MockServer::start().await;
        let vsix = b"legacy-upstream-vsix";
        Mock::given(method("GET"))
            .and(path("/extensions/publisher/extension/1.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vsix))
            // Exactly one serve: the gated request must not reach upstream, the
            // ungated positive control must.
            .expect(1)
            .mount(&server)
            .await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let request = || {
            tdh::get(format!(
                "/{}/extensions/publisher/extension/1.0.0/download",
                fx.repo_key
            ))
        };

        // Positive control FIRST, with the gate off: the route really does
        // proxy, so the negative assertion below cannot be satisfied by a
        // fixture that was broken all along.
        let (open_status, open_body) =
            tdh::send(tdh::router_anon(super::router(), state.clone()), request()).await;
        assert_eq!(open_status, StatusCode::OK);
        assert_eq!(&open_body[..], vsix);

        sqlx::query(
            "UPDATE repositories SET age_gate_enabled = true, \
             age_gate_mode = 'upstream_publish_time', age_gate_min_age_days = 30 WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("enable the age gate");

        let (gated_status, gated_body) =
            tdh::send(tdh::router_anon(super::router(), state), request()).await;
        assert_eq!(
            gated_status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the ungateable legacy route must fail closed while the gate is on"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&gated_body).unwrap()["error"],
            "age_gate_unavailable"
        );
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
        let (state, _cache) = rewire_remote_gallery(&fx, &gallery_root).await;
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
