//! NuGet v3 Server API handlers.
//!
//! Implements the endpoints required for `dotnet nuget push` and
//! `dotnet add package` against a NuGet v3 feed.
//!
//! Routes are mounted at `/nuget/{repo_key}/...`:
//!   GET  /nuget/{repo_key}/v3/index.json                                      — Service index
//!   GET  /nuget/{repo_key}/v3/search                                          — Search packages
//!   GET  /nuget/{repo_key}/v3/registration/{id}/index.json                    — Package registration
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/index.json                   — Version list
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg — Download
//!   PUT  /nuget/{repo_key}/api/v2/package                                     — Push package

use axum::body::Body;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::curation_service::version_compare;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Service index (NuGet discovery document)
        .route("/:repo_key/v3/index.json", get(service_index))
        // Search
        .route("/:repo_key/v3/search", get(search_packages))
        // Package registration
        .route(
            "/:repo_key/v3/registration/:id/index.json",
            get(registration_index),
        )
        // Flat container — version list
        .route(
            "/:repo_key/v3/flatcontainer/:id/index.json",
            get(flatcontainer_versions),
        )
        // Flat container — download .nupkg
        .route(
            "/:repo_key/v3/flatcontainer/:id/:version/:filename",
            get(flatcontainer_download),
        )
        // Push package (dotnet nuget push).
        // Register both with and without trailing slash because `dotnet nuget
        // push` appends a trailing slash to the PackagePublish/2.0.0 URL
        // discovered from the v3 service index.
        .route("/:repo_key/api/v2/package", put(push_package))
        .route("/:repo_key/api/v2/package/", put(push_package))
        // NuGet/Chocolatey V2 (OData) read protocol (#2775). Chocolatey and the
        // classic `nuget` V2 client speak OData, not V3. A single catch-all
        // dispatches the service document, `$metadata`, the `FindPackagesById()`
        // / `Packages(...)` / `Search()` OData queries and the `package/{id}/
        // {version}` content route. Remote repos proxy (and URL-rewrite) their
        // upstream V2 feed; hosted repos answer from local rows.
        .route("/:repo_key/v2", get(v2_service_document))
        .route("/:repo_key/v2/", get(v2_service_document))
        .route("/:repo_key/v2/*odata", get(v2_odata))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_nuget_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(
        db,
        repo_key,
        &["nuget", "chocolatey", "powershell"],
        "a NuGet",
    )
    .await
}

/// Resolve the set of repository IDs whose local `artifacts` rows should back
/// a read query for `repo`.
///
/// * For a hosted / local repo this is simply `[repo.id]`.
/// * For a virtual repo it is the IDs of all **non-remote** member repos
///   (Local / Staging), so local listing/search endpoints federate across
///   members. Remote members are handled separately via the proxy fallback
///   because their content is fetched on demand rather than stored locally.
///
/// Returns the resolved IDs alongside the list of virtual members (empty for
/// non-virtual repos) so callers can additionally proxy remote members.
async fn effective_local_repo_ids(
    db: &PgPool,
    repo: &RepoInfo,
) -> Result<(Vec<uuid::Uuid>, Vec<crate::models::repository::Repository>), Response> {
    if repo.repo_type != RepositoryType::Virtual {
        return Ok((vec![repo.id], Vec::new()));
    }

    let members = proxy_helpers::fetch_virtual_members(db, repo.id).await?;
    let local_ids: Vec<uuid::Uuid> = members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect();
    Ok((local_ids, members))
}

/// Detect a NuGet pre-release version. Per the SemVer rules NuGet follows, a
/// pre-release version carries a `-` separated suffix after the version core
/// (e.g. `2.0.0-beta.1`). Stable versions have no such suffix.
fn is_prerelease_version(version: &str) -> bool {
    version.contains('-')
}

/// Pick the version to surface as "latest" for a package in search results.
///
/// When `include_prerelease` is false, the highest **stable** version wins and
/// pre-release versions are only considered when no stable version exists.
/// When true, the highest version overall (stable or pre-release) wins.
/// Returns `"0.0.0"` when `versions` is empty.
fn select_latest_version(versions: &[String], include_prerelease: bool) -> &str {
    let highest = |candidates: &[&String]| -> Option<String> {
        candidates
            .iter()
            .max_by(|a, b| version_compare(a, b).cmp(&0))
            .map(|s| s.to_string())
    };

    if !include_prerelease {
        let stable: Vec<&String> = versions
            .iter()
            .filter(|v| !is_prerelease_version(v))
            .collect();
        if let Some(best) = highest(&stable) {
            // Return a borrow of the original slice element matching `best`.
            return versions
                .iter()
                .find(|v| **v == best)
                .map(String::as_str)
                .unwrap_or("0.0.0");
        }
    }

    let all: Vec<&String> = versions.iter().collect();
    match highest(&all) {
        Some(best) => versions
            .iter()
            .find(|v| **v == best)
            .map(String::as_str)
            .unwrap_or("0.0.0"),
        None => "0.0.0",
    }
}

// ---------------------------------------------------------------------------
// Remote (proxy) upstream discovery + URL rewriting (#2775)
// ---------------------------------------------------------------------------
//
// NuGet V3 has no fixed on-disk layout: the `RegistrationsBaseUrl` and
// `PackageBaseAddress` resources live at whatever host/path the upstream feed
// advertises in its service index (nuget.org serves flat-container from
// `/v3-flatcontainer/` and registrations from `/v3/registration5-gz-semver2/`).
// A proxy therefore MUST read the upstream service index first and resolve those
// bases before it can fetch registrations or package content — appending a
// hard-coded `v3/flatcontainer/...` path to the configured upstream URL (the old
// behaviour) does not resolve against a real feed. Once fetched, every upstream
// URL embedded in a registration document is rewritten back to this proxy so the
// client's follow-up downloads come through us and get cached.

/// Base URLs resolved from an upstream NuGet V3 service index.
#[derive(Debug, Clone, Default)]
struct NugetUpstreamResources {
    registration_base: Option<String>,
    package_base: Option<String>,
    search_base: Option<String>,
}

/// Normalise a configured upstream URL to its `index.json` service document.
/// Accepts either the full `.../index.json` URL (what a `nuget` source is
/// usually set to) or a bare base, appending `index.json` in the latter case.
fn nuget_service_index_url(upstream_url: &str) -> String {
    let trimmed = upstream_url.trim_end_matches('/');
    if trimmed.ends_with("index.json") {
        trimmed.to_string()
    } else {
        format!("{}/index.json", trimmed)
    }
}

/// Pick the `@id` of the first resource whose `@type` equals `exact`, falling
/// back to the first whose `@type` starts with `prefix` (NuGet advertises the
/// same base under versioned `@type`s, e.g. `RegistrationsBaseUrl/3.6.0`).
fn pick_resource<'a>(
    resources: &'a [serde_json::Value],
    exact: &str,
    prefix: &str,
) -> Option<&'a str> {
    resources
        .iter()
        .find(|r| r.get("@type").and_then(|t| t.as_str()) == Some(exact))
        .or_else(|| {
            resources.iter().find(|r| {
                r.get("@type")
                    .and_then(|t| t.as_str())
                    .map(|t| t.starts_with(prefix))
                    .unwrap_or(false)
            })
        })
        .and_then(|r| r.get("@id").and_then(|v| v.as_str()))
}

/// Parse an upstream service-index document into the resource base URLs the
/// proxy needs. Pure (no IO) so it is unit-testable without a live upstream.
fn parse_upstream_resources(index: &serde_json::Value) -> NugetUpstreamResources {
    let empty = Vec::new();
    let resources = index
        .get("resources")
        .and_then(|r| r.as_array())
        .unwrap_or(&empty);
    NugetUpstreamResources {
        registration_base: pick_resource(resources, "RegistrationsBaseUrl", "RegistrationsBaseUrl")
            .map(|s| s.trim_end_matches('/').to_string()),
        package_base: pick_resource(resources, "PackageBaseAddress/3.0.0", "PackageBaseAddress")
            .map(|s| s.trim_end_matches('/').to_string()),
        // Feeds advertise search under bare `SearchQueryService` and versioned
        // spellings (`/3.0.0-beta`, `/3.0.0-rc`, ...); the exact/prefix pair
        // covers all of them (#3130).
        search_base: pick_resource(resources, "SearchQueryService", "SearchQueryService")
            .map(|s| s.trim_end_matches('/').to_string()),
    }
}

/// Fetch + parse the upstream service index for a Remote NuGet V3 repo.
async fn discover_upstream_resources(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
) -> Result<NugetUpstreamResources, Response> {
    let index_url = nuget_service_index_url(upstream_url);
    let (content, _ct) = proxy_helpers::proxy_fetch_capped_with_cache_key(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &index_url,      // absolute fetch path — passed through verbatim
        "v3/index.json", // clean, stable proxy-cache key
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;
    let index: serde_json::Value = serde_json::from_slice(&content).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Upstream NuGet service index was not valid JSON",
        )
            .into_response()
    })?;
    Ok(parse_upstream_resources(&index))
}

/// The AK-facing registration/flat-container base URLs for `repo_key`.
fn ak_v3_bases(ak_base: &str, repo_key: &str) -> (String, String) {
    (
        format!("{}/nuget/{}/v3/registration", ak_base, repo_key),
        format!("{}/nuget/{}/v3/flatcontainer", ak_base, repo_key),
    )
}

/// Rewrite every upstream base URL embedded in a proxied registration document
/// back to this proxy's routes so the client's follow-up requests
/// (`packageContent` downloads, registration page fetches) come through us
/// rather than hitting the upstream host directly. Pure + string-based so it
/// works regardless of the document's shape (inline or paged items) and is
/// unit-testable.
fn rewrite_v3_registration(
    body: &str,
    resources: &NugetUpstreamResources,
    ak_base: &str,
    repo_key: &str,
) -> String {
    let (ak_reg, ak_flat) = ak_v3_bases(ak_base, repo_key);
    let mut out = body.to_string();
    if let Some(pkg) = &resources.package_base {
        out = out.replace(pkg, &ak_flat);
    }
    if let Some(reg) = &resources.registration_base {
        out = out.replace(reg, &ak_reg);
    }
    out
}

/// True when `resource_url`'s origin (host + effective port) matches the
/// configured `upstream_url`'s origin.
///
/// NuGet V3 discovers the `RegistrationsBaseUrl` / `PackageBaseAddress` bases
/// from the upstream *service index response*, then fetches from them carrying
/// the repo's configured upstream credentials (`apply_upstream_auth`, keyed by
/// repo). A malicious or compromised upstream service index could therefore
/// name an attacker-controlled host in those resources and have the proxy send
/// the configured credentials there (credential exfiltration, #2925). Pinning
/// the discovered bases to the operator-configured upstream origin keeps
/// credentialed fetches on the host the operator actually trusts.
///
/// Comparison is host + effective port (`port_or_known_default`, so an
/// `https`→`http` downgrade to the same host is also rejected because 443 ≠ 80)
/// and case-insensitive on the host.
///
/// How real feeds relate to this check is SPLIT by resource type (#3130):
///
/// * **Registration / flat-container**: nuget.org, GitHub Packages, Azure
///   DevOps Artifacts and other private feeds serve these from the same host
///   as their `index.json`, so origin-pinning them ([`guard_upstream_base`])
///   does not affect legitimate proxying.
/// * **Search**: nuget.org itself advertises `SearchQueryService` on sibling
///   hosts — `azuresearch-usnc.nuget.org` / `azuresearch-ussc.nuget.org` —
///   while its `index.json` lives on `api.nuget.org`. An off-origin search
///   base is therefore NOT refused; instead [`guard_search_base`] reports the
///   mismatch and the caller fetches it **without** the repo's configured
///   upstream credentials, preserving the #2925 invariant (credentials only
///   ever go to the operator-configured origin) without breaking search.
fn same_upstream_origin(upstream_url: &str, resource_url: &str) -> bool {
    match (
        reqwest::Url::parse(upstream_url),
        reqwest::Url::parse(resource_url),
    ) {
        (Ok(up), Ok(res)) => {
            up.host_str().map(str::to_ascii_lowercase)
                == res.host_str().map(str::to_ascii_lowercase)
                && up.port_or_known_default() == res.port_or_known_default()
        }
        _ => false,
    }
}

/// Resolve a discovered upstream base URL, rejecting a service index that omits
/// it, advertises a non-http(s) base, or points the base at a host other than
/// the configured upstream (#2925 — see [`same_upstream_origin`]).
///
/// The anti-SSRF hard block for the actual outbound request is enforced by the
/// proxy fetch layer's connect-time DNS guard (`is_blocked_resolved_ip`,
/// #1832/#2570), which is DNS-rebind safe — every remote-proxy download in the
/// codebase relies on it. A hostile upstream that points a base at a loopback /
/// link-local / cloud-metadata address is refused there, before any bytes are
/// read, for both the discovered registration/flat-container fetches here and
/// the V2 OData fetches below. The origin check added here is complementary: it
/// keeps the configured upstream *credentials* from being sent to any host the
/// service index names other than the configured upstream itself.
#[allow(clippy::result_large_err)]
fn guard_upstream_base(
    base: Option<&String>,
    upstream_url: &str,
    what: &str,
) -> Result<String, Response> {
    let base = require_http_base(base, what)?;
    if !same_upstream_origin(upstream_url, &base) {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Upstream {what} points off the configured upstream host; \
                 refusing to send upstream credentials off-host"
            ),
        )
            .into_response());
    }
    Ok(base)
}

/// Presence + scheme validation shared by every discovered-base guard: the
/// service index must advertise the resource and it must be an http(s) URL.
#[allow(clippy::result_large_err)]
fn require_http_base(base: Option<&String>, what: &str) -> Result<String, Response> {
    let base = base.ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Upstream NuGet feed advertises no {what}"),
        )
            .into_response()
    })?;
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Upstream {what} is not an http(s) URL"),
        )
            .into_response());
    }
    Ok(base.clone())
}

/// Resolve the discovered `SearchQueryService` base (#3130).
///
/// Unlike registration / flat-container ([`guard_upstream_base`]) an
/// off-origin search base is NOT refused: real feeds legitimately advertise
/// search on a sibling host (nuget.org's `index.json` on `api.nuget.org`
/// names `azuresearch-*.nuget.org`). The #2925 invariant — never send the
/// repo's configured upstream credentials to a host the operator did not
/// configure — is preserved by the caller instead: the returned `bool`
/// reports whether the base shares the configured upstream's origin, and an
/// off-origin base is fetched anonymously (no credentials loaded at all).
/// A missing or non-http(s) base is still refused.
#[allow(clippy::result_large_err)]
fn guard_search_base(
    base: Option<&String>,
    upstream_url: &str,
) -> Result<(String, bool), Response> {
    let base = require_http_base(base, "SearchQueryService")?;
    let same_origin = same_upstream_origin(upstream_url, &base);
    Ok((base, same_origin))
}

/// Proxy + rewrite an upstream V3 registration index for one remote upstream.
/// `fetch_repo_*`/`upstream_url` address the upstream (and own the proxy-cache
/// key); `client_repo_key` is the repo the client is talking to and is used to
/// build the rewritten AK URLs.
#[allow(clippy::too_many_arguments)]
async fn proxy_v3_registration(
    proxy: &crate::services::proxy_service::ProxyService,
    fetch_repo_id: uuid::Uuid,
    fetch_repo_key: &str,
    upstream_url: &str,
    package_id_lower: &str,
    ak_base: &str,
    client_repo_key: &str,
) -> Result<Response, Response> {
    let resources =
        discover_upstream_resources(proxy, fetch_repo_id, fetch_repo_key, upstream_url).await?;
    let reg_base = guard_upstream_base(
        resources.registration_base.as_ref(),
        upstream_url,
        "RegistrationsBaseUrl",
    )?;
    let fetch_url = format!("{}/{}/index.json", reg_base, package_id_lower);
    let cache_path = format!("v3/registration/{}/index.json", package_id_lower);
    let (content, content_type) = proxy_helpers::proxy_fetch_capped_with_cache_key(
        proxy,
        fetch_repo_id,
        fetch_repo_key,
        upstream_url,
        &fetch_url,
        &cache_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;
    let body = String::from_utf8_lossy(&content);
    let rewritten = rewrite_v3_registration(&body, &resources, ak_base, client_repo_key);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| "application/json".to_string()),
        )
        .body(Body::from(rewritten))
        .unwrap())
}

/// Build the normalized query string for an upstream V3 search fetch.
///
/// `q` is user-controlled free text, so it is percent-encoded — it must not be
/// able to smuggle extra query parameters or break out of the URL — and
/// lowercased (NuGet search is case-insensitive) so equivalent queries share
/// one upstream fetch/cache entry. Defaults are included explicitly so the
/// same effective query always yields the same string.
fn build_search_fetch_query(q: &str, skip: i64, take: i64, prerelease: bool) -> String {
    format!(
        "q={}&skip={}&take={}&prerelease={}",
        urlencoding::encode(&q.to_lowercase()),
        skip,
        take,
        prerelease
    )
}

/// Build the proxy-cache key for an upstream V3 search response.
///
/// Unlike registrations (keyed by package id alone), a search response depends
/// on **every** query parameter — a shared key would serve the first query's
/// cached results to every later query. The key therefore hashes the full
/// normalized parameter set ([`build_search_fetch_query`]); hashing (rather
/// than sanitizing the raw string into the key) prevents distinct queries from
/// colliding after filesystem-unsafe characters are squashed.
fn build_search_cache_key(q: &str, skip: i64, take: i64, prerelease: bool) -> String {
    let normalized = build_search_fetch_query(q, skip, take, prerelease);
    let digest = Sha256::digest(normalized.as_bytes());
    format!("v3/search/{:x}", digest)
}

/// Proxy an upstream V3 search query for one remote upstream and rewrite the
/// embedded upstream registration/flat-container URLs back to this proxy
/// (#3130). Returns the rewritten payload as JSON so callers can either serve
/// it directly (Remote repos) or merge it with local rows (Virtual repos).
///
/// The discovered `SearchQueryService` base goes through
/// [`guard_search_base`]: a same-origin base is fetched with the repo's
/// configured upstream credentials through the proxy cache exactly like
/// registration documents; an off-origin base (nuget.org's `azuresearch-*`)
/// is fetched WITHOUT credentials and WITHOUT the cache, preserving the #2925
/// invariant that configured upstream credentials only ever go to the
/// operator-configured origin.
#[allow(clippy::too_many_arguments)]
async fn proxy_v3_search(
    proxy: &crate::services::proxy_service::ProxyService,
    fetch_repo_id: uuid::Uuid,
    fetch_repo_key: &str,
    upstream_url: &str,
    query_term: &str,
    skip: i64,
    take: i64,
    prerelease: bool,
    ak_base: &str,
    client_repo_key: &str,
) -> Result<serde_json::Value, Response> {
    let resources =
        discover_upstream_resources(proxy, fetch_repo_id, fetch_repo_key, upstream_url).await?;
    let (search_base, same_origin) =
        guard_search_base(resources.search_base.as_ref(), upstream_url)?;
    let fetch_url = format!(
        "{}?{}",
        search_base,
        build_search_fetch_query(query_term, skip, take, prerelease)
    );
    let (content, _content_type) = if same_origin {
        let cache_path = build_search_cache_key(query_term, skip, take, prerelease);
        proxy_helpers::proxy_fetch_capped_with_cache_key(
            proxy,
            fetch_repo_id,
            fetch_repo_key,
            upstream_url,
            &fetch_url,
            &cache_path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await?
    } else {
        // Off-origin advertised search host: fetch anonymously and uncached.
        // Every cached-entry code path (single-flight refill, stale
        // revalidation) attaches the repo's configured credentials, so the
        // uncached anonymous fetch is the narrowest surface that provably
        // cannot carry them (#2925). The SSRF connect-time DNS guard and the
        // byte ceiling still apply.
        proxy_helpers::proxy_fetch_capped_anonymous(
            proxy,
            fetch_repo_id,
            fetch_repo_key,
            &fetch_url,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await?
    };
    let body = String::from_utf8_lossy(&content);
    let rewritten = rewrite_v3_registration(&body, &resources, ak_base, client_repo_key);
    serde_json::from_str(&rewritten).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Upstream NuGet search response was not valid JSON",
        )
            .into_response()
    })
}

/// Merge upstream search `data` entries into the local result set, deduped
/// case-insensitively by package id with local entries winning, bounded by
/// `take`. Returns how many upstream entries were added.
fn merge_upstream_search_data(
    data: &mut Vec<serde_json::Value>,
    upstream: &serde_json::Value,
    take: usize,
) -> usize {
    let mut seen: std::collections::HashSet<String> = data
        .iter()
        .filter_map(|e| e.get("id").and_then(|v| v.as_str()))
        .map(str::to_ascii_lowercase)
        .collect();
    let mut added = 0;
    let Some(entries) = upstream.get("data").and_then(|d| d.as_array()) else {
        return added;
    };
    for entry in entries {
        if data.len() >= take {
            break;
        }
        let Some(id) = entry.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if seen.insert(id.to_ascii_lowercase()) {
            data.push(entry.clone());
            added += 1;
        }
    }
    added
}

/// Resolve the upstream fetch URL and the stable proxy-cache key for a
/// flat-container `sub_path` (`{id}/index.json`, `{id}/{version}/{file}`).
///
/// NuGet V3 has no fixed layout, so the package-content base must come from the
/// upstream service index rather than being concatenated onto the configured
/// upstream URL (#2775). Extracted from [`proxy_v3_flatcontainer`] so the
/// verified `.nupkg` repair path (#2929) can buffer and hash the body itself
/// while still resolving its URL through exactly the same discovery — the
/// buffered repair that predated #2919 built the URL by concatenation and 404'd
/// against every real feed.
async fn flatcontainer_fetch_target(
    proxy: &crate::services::proxy_service::ProxyService,
    fetch_repo_id: uuid::Uuid,
    fetch_repo_key: &str,
    upstream_url: &str,
    sub_path: &str,
) -> Result<(String, String), Response> {
    let resources =
        discover_upstream_resources(proxy, fetch_repo_id, fetch_repo_key, upstream_url).await?;
    let pkg_base = guard_upstream_base(
        resources.package_base.as_ref(),
        upstream_url,
        "PackageBaseAddress",
    )?;
    Ok((
        format!("{}/{}", pkg_base, sub_path),
        format!("v3/flatcontainer/{}", sub_path),
    ))
}

/// Byte ceiling on a *verified* (buffered) `.nupkg` repair (#2929).
///
/// The unverified repair streams and is therefore unbounded by design. A
/// verified repair cannot stream — the digest is only known once the last byte
/// has arrived — so it has to hold the body, and holding an unbounded body is
/// how a repair path becomes a memory-exhaustion primitive (#2928). 128 MiB
/// covers the large native-runtime packages that motivated #2919
/// (`Microsoft.CodeAnalysis.*`, `Microsoft.ML.*`, `SkiaSharp.NativeAssets.*`)
/// while staying far below the buffered proxy-scan ceiling the process already
/// tolerates. Exceeding it is a hard error, never a silent downgrade to an
/// unverified stream: see the repair arm in `flatcontainer_download`.
const VERIFIED_NUPKG_REPAIR_MAX_BYTES: usize = 128 * 1024 * 1024;

/// Proxy an upstream V3 flat-container document (version list or `.nupkg`).
/// `sub_path` is the portion after the package-content base, e.g.
/// `{id}/index.json` or `{id}/{version}/{file}`. Version lists carry no URLs so
/// no rewriting is needed. Downloads stream (never buffered) under a stable
/// cache key.
async fn proxy_v3_flatcontainer(
    proxy: &crate::services::proxy_service::ProxyService,
    fetch_repo_id: uuid::Uuid,
    fetch_repo_key: &str,
    upstream_url: &str,
    sub_path: &str,
    streaming: bool,
) -> Result<Response, Response> {
    let (fetch_url, cache_path) =
        flatcontainer_fetch_target(proxy, fetch_repo_id, fetch_repo_key, upstream_url, sub_path)
            .await?;
    if streaming {
        proxy_helpers::proxy_fetch_streaming_response_with_cache_key(
            proxy,
            fetch_repo_id,
            fetch_repo_key,
            upstream_url,
            &fetch_url,
            &cache_path,
            "application/octet-stream",
            RepositoryFormat::Nuget,
        )
        .await
    } else {
        // Unlike the registration / search / OData arms, this one serves the
        // upstream body VERBATIM (a version list carries no URLs, so nothing is
        // rewritten). That makes it the one NuGet caller that has to forward the
        // upstream coding, hence the `_encoded` variant — surfaced by the #3184
        // widening of `fetch_artifact_with_cache_path_capped`.
        let (content, content_type, content_encoding) =
            proxy_helpers::proxy_fetch_capped_with_cache_key_encoded(
                proxy,
                fetch_repo_id,
                fetch_repo_key,
                upstream_url,
                &fetch_url,
                &cache_path,
                proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            )
            .await?;
        let mut builder = Response::builder().status(StatusCode::OK).header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| "application/json".to_string()),
        );
        if let Some(enc) = content_encoding.as_deref() {
            builder = builder.header(CONTENT_ENCODING, enc);
        }
        Ok(builder.body(Body::from(content)).unwrap())
    }
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/index.json — Service index
// ---------------------------------------------------------------------------

async fn service_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let _repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    // Determine the base URL from reverse-proxy / Host headers.
    let base = build_nuget_base_url(base_url.as_str(), &repo_key);

    let index = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-beta",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-rc",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-beta",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-rc",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/flatcontainer/", base),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Package content"
            },
            {
                "@id": format!("{}/api/v2/package", base),
                "@type": "PackagePublish/2.0.0",
                "comment": "Push packages"
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string_pretty(&index).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/search — Search packages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct SearchQuery {
    q: Option<String>,
    skip: Option<i64>,
    take: Option<i64>,
    #[serde(rename = "prerelease")]
    prerelease: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct SearchPackageRow {
    name: String,
    versions: Vec<String>,
    description: Option<String>,
}

async fn search_packages(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    let query_term = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20).min(100);
    let prerelease = params.prerelease.unwrap_or(false);

    // Determine base URL for building resource links.
    let base = build_nuget_base_url(base_url.as_str(), &repo_key);

    // Search distinct package names matching the query term.
    let search_pattern = build_nuget_search_pattern(&query_term);

    // Federate over virtual members (local/staging) when the repo is virtual;
    // otherwise query the repo itself.
    let (repo_ids, members) = effective_local_repo_ids(&state.db, &repo).await?;

    // Pull the latest-by-created_at description per package via a LATERAL
    // join so the search payload carries the package summary instead of a
    // hardcoded empty string.
    let packages: Vec<SearchPackageRow> = sqlx::query_as(
        r#"
        SELECT a.name AS name,
               ARRAY_AGG(DISTINCT a.version) FILTER (WHERE a.version IS NOT NULL) AS versions,
               (
                   SELECT am.metadata->>'description'
                   FROM artifacts a2
                   LEFT JOIN artifact_metadata am ON am.artifact_id = a2.id
                   WHERE a2.repository_id = ANY($1::uuid[])
                     AND a2.is_deleted = false
                     AND LOWER(a2.name) = LOWER(a.name)
                   ORDER BY a2.created_at DESC
                   LIMIT 1
               ) AS description
        FROM artifacts a
        WHERE a.repository_id = ANY($1::uuid[])
          AND a.is_deleted = false
          AND LOWER(a.name) LIKE $2
        GROUP BY LOWER(a.name), a.name
        ORDER BY LOWER(a.name)
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(&repo_ids)
    .bind(&search_pattern)
    .bind(take)
    .bind(skip)
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    // Get total count for pagination.
    let total_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT LOWER(name))::bigint
        FROM artifacts
        WHERE repository_id = ANY($1::uuid[])
          AND is_deleted = false
          AND LOWER(name) LIKE $2
        "#,
    )
    .bind(&repo_ids)
    .bind(&search_pattern)
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let mut data: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            let id = &p.name;
            // When prerelease=false, prefer the highest *stable* version and
            // only fall back to a pre-release if no stable version exists.
            let latest = select_latest_version(&p.versions, prerelease);

            // Build version list entry for the latest version.
            let versions = vec![serde_json::json!({
                "version": latest,
                "@id": format!("{}/v3/registration/{}/{}.json", base, id, latest),
            })];

            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/index.json", base, id),
                "@type": "Package",
                "registration": format!("{}/v3/registration/{}/index.json", base, id),
                "id": id,
                "version": latest,
                "description": p.description.clone().unwrap_or_default(),
                "totalDownloads": 0,
                "versions": versions
            })
        })
        .collect();

    let mut total_hits = total_count;

    // Remote repo: proxy the search to the upstream feed (#3130). The service
    // index advertises SearchQueryService, so answering purely from local
    // `artifacts` rows returned an empty result for an uncached remote. Any
    // failure (no advertised SearchQueryService, a non-http(s) base, fetch
    // error, non-JSON payload) degrades to the local result rather than
    // 5xx-ing — a hard error here breaks the client's package-manager UI
    // entirely.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            match proxy_v3_search(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &query_term,
                skip,
                take,
                prerelease,
                base_url.as_str(),
                &repo_key,
            )
            .await
            {
                Ok(upstream) => {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_string(&upstream).unwrap()))
                        .unwrap());
                }
                Err(resp) => {
                    warn!(
                        repo_key = %repo_key,
                        status = %resp.status(),
                        "upstream NuGet search failed; falling back to local results"
                    );
                }
            }
        }
    }

    // Virtual repo: merge each remote member's upstream results into the local
    // ones, deduped case-insensitively by package id with local entries
    // winning. `totalHits` takes the max of the local and upstream totals —
    // the true merged total is unknowable without enumerating both corpora,
    // and max never double-counts a package present on both sides.
    if repo.repo_type == RepositoryType::Virtual {
        if let Some(proxy) = &state.proxy_service {
            for member in &members {
                if member.repo_type != RepositoryType::Remote {
                    continue;
                }
                let Some(upstream_url) = member.upstream_url.as_deref() else {
                    continue;
                };
                match proxy_v3_search(
                    proxy,
                    member.id,
                    &member.key,
                    upstream_url,
                    &query_term,
                    skip,
                    take,
                    prerelease,
                    base_url.as_str(),
                    &repo_key,
                )
                .await
                {
                    Ok(upstream) => {
                        let upstream_total = upstream
                            .get("totalHits")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        total_hits = total_hits.max(upstream_total);
                        merge_upstream_search_data(&mut data, &upstream, take as usize);
                    }
                    Err(resp) => {
                        warn!(
                            repo_key = %repo_key,
                            member_key = %member.key,
                            status = %resp.status(),
                            "upstream NuGet search failed for virtual member; skipping"
                        );
                    }
                }
            }
        }
    }

    let response = serde_json::json!({
        "totalHits": total_hits,
        "data": data
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/registration/{id}/index.json — Registration index
// ---------------------------------------------------------------------------

async fn registration_index(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    let base = build_nuget_base_url(base_url.as_str(), &repo_key);

    // Resolve the set of local repo IDs to query: the repo itself, or all
    // local/staging members for a virtual repo.
    let (repo_ids, members) = effective_local_repo_ids(&state.db, &repo).await?;

    // Fetch all versions of this package across the effective repo IDs.
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.version as "version?", a.path, a.size_bytes,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = ANY($1::uuid[])
          AND a.is_deleted = false
          AND LOWER(a.name) = $2
        ORDER BY a.created_at ASC
        "#,
        &repo_ids,
        package_id_lower
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if artifacts.is_empty() {
        // Cache miss: proxy the registration index from upstream. NuGet V3 does
        // not expose registrations at a fixed path, so discover the upstream
        // `RegistrationsBaseUrl` from its service index, fetch the document, and
        // rewrite its embedded URLs back to this proxy (#2775).

        // Remote repo: fetch directly from its upstream.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                return proxy_v3_registration(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &package_id_lower,
                    base_url.as_str(),
                    &repo_key,
                )
                .await;
            }
        }

        // Virtual repo: try each remote member's upstream in priority order.
        if repo.repo_type == RepositoryType::Virtual {
            if let Some(proxy) = &state.proxy_service {
                for member in &members {
                    if member.repo_type != RepositoryType::Remote {
                        continue;
                    }
                    let Some(upstream_url) = member.upstream_url.as_deref() else {
                        continue;
                    };
                    if let Ok(resp) = proxy_v3_registration(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &package_id_lower,
                        base_url.as_str(),
                        &repo_key,
                    )
                    .await
                    {
                        return Ok(resp);
                    }
                }
            }
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("0.0.0");
            let description = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let authors = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("authors"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // The registration leaf `@id` must dereference to a route the
            // server actually serves. There is no per-version leaf route
            // (`/v3/registration/{id}/{version}.json` 404s); the only served
            // registration route is the index. Point the leaf (and its
            // catalogEntry) at that index with a `#{version}` fragment — the
            // fragment identifies the inlined item and is stripped by the
            // client before the GET, so it resolves to `registration_index`
            // (200). This mirrors the page `@id` below (`index.json#page/0`).
            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/index.json#{}", base, package_id_lower, version),
                "catalogEntry": {
                    "@id": format!("{}/v3/registration/{}/index.json#{}", base, package_id_lower, version),
                    "id": package_id_lower,
                    "version": version,
                    "description": description,
                    "authors": authors,
                    "packageContent": format!(
                        "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                        base, package_id_lower, version, package_id_lower, version
                    ),
                    "listed": true,
                },
                "packageContent": format!(
                    "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                    base, package_id_lower, version, package_id_lower, version
                ),
            })
        })
        .collect();

    let lower_version = artifacts
        .first()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");
    let upper_version = artifacts
        .last()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");

    let response = serde_json::json!({
        "@id": format!("{}/v3/registration/{}/index.json", base, package_id_lower),
        "count": 1,
        "items": [
            {
                "@id": format!("{}/v3/registration/{}/index.json#page/0", base, package_id_lower),
                "count": items.len(),
                "lower": lower_version,
                "upper": upper_version,
                "items": items,
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/index.json — Version list
// ---------------------------------------------------------------------------

async fn flatcontainer_versions(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    // Resolve the set of local repo IDs to query: the repo itself, or all
    // local/staging members for a virtual repo.
    let (repo_ids, members) = effective_local_repo_ids(&state.db, &repo).await?;

    let mut versions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = ANY($1::uuid[])
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version IS NOT NULL
        "#,
    )
    .bind(&repo_ids)
    .bind(&package_id_lower)
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    versions.sort_by(|a, b| match version_compare(a, b) {
        n if n < 0 => std::cmp::Ordering::Less,
        n if n > 0 => std::cmp::Ordering::Greater,
        _ => std::cmp::Ordering::Equal,
    });

    if versions.is_empty() {
        // Cache miss: proxy the flat-container version index from upstream via
        // the discovered `PackageBaseAddress` (#2775). The version list carries
        // no URLs, so it is served through verbatim.
        let sub_path = format!("{}/index.json", package_id_lower);

        // Remote repo: fetch directly from its upstream.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                return proxy_v3_flatcontainer(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &sub_path,
                    false,
                )
                .await;
            }
        }

        // Virtual repo: try each remote member's upstream in priority order.
        if repo.repo_type == RepositoryType::Virtual {
            if let Some(proxy) = &state.proxy_service {
                for member in &members {
                    if member.repo_type != RepositoryType::Remote {
                        continue;
                    }
                    let Some(upstream_url) = member.upstream_url.as_deref() else {
                        continue;
                    };
                    if let Ok(resp) = proxy_v3_flatcontainer(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &sub_path,
                        false,
                    )
                    .await
                    {
                        return Ok(resp);
                    }
                }
            }
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let response = build_flatcontainer_versions_json(&versions);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{filename} — Download
// ---------------------------------------------------------------------------

async fn flatcontainer_download(
    State(state): State<SharedState>,
    Path((repo_key, package_id, version, filename)): Path<(String, String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    // Curation enforcement (#2930): block a curated package before it is
    // resolved locally or proxied from an upstream V3 feed. No-op for hosted
    // repos / curation off.
    proxy_helpers::enforce_curation(&state.db, &repo, &package_id_lower, Some(&version)).await?;

    // Find the artifact matching this package/version.
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id_lower,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package version not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Resolve the upstream `PackageBaseAddress` from the service
                    // index and stream the .nupkg from there (#2775).
                    let sub_path = format!("{}/{}/{}", package_id_lower, version, filename);
                    return proxy_v3_flatcontainer(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &sub_path,
                        true,
                    )
                    .await;
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                // Remote members need V3 service-index discovery to resolve the
                // real `PackageBaseAddress`, so try them explicitly first (#2775).
                if let Some(proxy) = state.proxy_service.as_deref() {
                    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
                    let sub_path = format!("{}/{}/{}", package_id_lower, version, filename);
                    for member in &members {
                        if member.repo_type != RepositoryType::Remote {
                            continue;
                        }
                        let Some(upstream_url) = member.upstream_url.as_deref() else {
                            continue;
                        };
                        if let Ok(resp) = proxy_v3_flatcontainer(
                            proxy,
                            member.id,
                            &member.key,
                            upstream_url,
                            &sub_path,
                            true,
                        )
                        .await
                        {
                            return Ok(resp);
                        }
                    }
                }

                let db = state.db.clone();
                let vname = package_id_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!(
                    "v3/flatcontainer/{}/{}/{}",
                    package_id_lower, version, filename
                );
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

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    Some(&filename),
                );
            }
            return Err(not_found);
        }
    };

    // Read from storage.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    // Every repo type streams a present blob straight from storage so a large
    // `.nupkg` never buffers in heap.
    //
    // A Remote repo additionally self-heals the "row exists but the object is
    // gone" state: the `artifacts` row survives (a pre-#1278 proxy-cache row, a
    // hydrated/replicated copy, or a package published into the remote) while the
    // blob has been evicted or lost. That repair used to buffer the re-pull
    // through `proxy_fetch_capped(.., DEFAULT_METADATA_MAX_BYTES)` against
    // `{upstream_url}/v3/flatcontainer/{id}/{version}/{file}`, which was wrong
    // twice over:
    //
    //  1. A `.nupkg` is an artifact, not metadata. The capped fetch does not
    //     truncate — it 502s the moment the body would exceed the 8 MiB metadata
    //     ceiling — so the repair failed outright for every package that is
    //     legitimately larger (`Microsoft.CodeAnalysis.*`, `Microsoft.ML.*`,
    //     `SkiaSharp.NativeAssets.*`, essentially all native-runtime packages).
    //     Same defect class the PyPI wheel recovery path fixed by streaming in
    //     #2192 / #1608 Phase 4c.
    //  2. More fundamentally, the path was concatenated onto `upstream_url`
    //     directly, bypassing the service-index discovery every other V3 call
    //     site performs (#2775). NuGet V3 has no fixed layout: nuget.org serves
    //     package content from `https://api.nuget.org/v3-flatcontainer/`, and a
    //     configured upstream is normally the `.../v3/index.json` document, so the
    //     concatenation produced `.../v3/index.json/v3/flatcontainer/...` — a
    //     guaranteed 404. The repair was broken against a real feed regardless of
    //     body size.
    //
    // The repair resolves `PackageBaseAddress` from the upstream service index
    // and keys the proxy cache on `v3/flatcontainer/{id}/{version}/{file}` — the
    // exact path the old buffered fetch keyed on — so entries cached by the
    // previous code are still hits rather than orphans. Which *transfer* shape it
    // uses depends on whether the row carries a digest we can enforce.
    //
    // #2929 — VERIFY-THEN-SERVE when it does.
    //
    // The repair pulls fresh bytes from upstream and writes them back under THIS
    // row's storage key. `check_artifact_download` a few lines above authorised
    // this download on THIS row, and the row records `checksum_sha256`. So the
    // hash an admin reviewed when releasing this artifact from quarantine is the
    // hash the client must actually receive; if the repair serves something else,
    // the quarantine decision was made about a blob nobody ever delivered and the
    // control is weaker than it reads.
    //
    // Enforcing that requires the whole body in hand BEFORE any of it is written
    // back or forwarded, which is why this arm buffers where the primary
    // cache-miss arm streams. Streaming and aborting mid-body on a mismatch is
    // not an equivalent option: the digest is only known after the last byte has
    // already been forwarded, so the client is left holding a truncated file it
    // may cache or retry into — a failure that is silent at exactly the moment it
    // most needs to be loud. On a mismatch nothing is written back, so the entry
    // stays missing: a transient bad upstream self-heals on the next request and a
    // persistently wrong one keeps erroring instead of poisoning the cache.
    //
    // The refetch still commits to the SHARED proxy cache under
    // `v3/flatcontainer/...` before this gate sees the bytes, exactly as the
    // streaming repair does. That is contained rather than ignored: the artifact
    // row is looked up ABOVE this point, so while the row exists every request
    // for it lands here and is re-gated — a mismatching cached body is refused
    // again rather than served warm (the repair is idempotent in that sense).
    // The proxy-cache entry only becomes directly reachable through the
    // no-row arm, where there is no recorded digest and no row-scoped quarantine
    // decision to honour in the first place. Keeping unverified bytes out of the
    // proxy cache as well needs a buffered-verified fetch primitive that does not
    // exist yet; it is a cache-hygiene improvement, not a hole in this gate.
    //
    // Buffering is bounded by `VERIFIED_NUPKG_REPAIR_MAX_BYTES` (#2928), applied
    // twice: pre-flight against the row's recorded `size_bytes`, and again as the
    // capped fetch's own ceiling in case the row understates what upstream serves.
    // Over-limit is a hard error. It deliberately does NOT fall back to the
    // unverified streaming repair — silently downgrading integrity for big
    // packages would make the guarantee depend on package size, which is the one
    // property an attacker controls.
    //
    // When the row has no enforceable digest (see `normalize_expected_sha256`),
    // there is nothing to verify against and the repair takes exactly the route
    // the primary cache-miss arm takes: `proxy_v3_flatcontainer(.., streaming =
    // true)` streams the body to the client while teeing it into the proxy cache,
    // unbounded and unchanged from #2919. Gating is preserved on that path: the
    // streaming leader re-applies the Package Age Policy hold (#1770/#1771 — a
    // policy-enabled repo refuses to open a new streaming fetch at all) plus the
    // sidecar `quarantine_until` on a proxy-cache hit, and it single-flights the
    // cold-cache open itself (#1631 layer 2 / #1694) so the buffered helper's
    // hydration lease is not lost. Its response carries the proxy's streaming
    // shape rather than this handler's `Content-Length`/`Content-Disposition` —
    // identical to the primary Remote arm, and NuGet clients name the file from
    // the request URL.
    //
    // A blob that IS present is streamed straight from storage as before: this
    // arm only governs the repair, and re-hashing every stored byte on every hit
    // is a different (much more expensive) control than #2929 asks for.
    //
    // `content_length` normally comes from the row, as for any streamed blob. The
    // verified repair overrides it with the length it actually holds: a row whose
    // `size_bytes` has drifted from its (verified-correct) body would otherwise
    // emit a `Content-Length` the body never satisfies, leaving the client
    // hanging or treating a complete file as truncated.
    let mut content_length = artifact.size_bytes;
    let body: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>> =
        match storage.get_stream(&artifact.storage_key).await {
            Ok(stream) => stream,
            Err(crate::error::AppError::NotFound(missing)) => {
                let remote_proxy = if repo.repo_type == RepositoryType::Remote {
                    match (&repo.upstream_url, &state.proxy_service) {
                        (Some(upstream_url), Some(proxy)) => Some((upstream_url, proxy)),
                        _ => None,
                    }
                } else {
                    None
                };

                let Some((upstream_url, proxy)) = remote_proxy else {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Storage error: {}", missing),
                    )
                        .into_response());
                };

                let sub_path = format!("{}/{}/{}", package_id_lower, version, filename);

                match proxy_helpers::normalize_expected_sha256(&artifact.checksum_sha256) {
                    Some(expected) => {
                        tracing::warn!(
                            artifact_id = %artifact.id,
                            storage_key = %artifact.storage_key,
                            "nuget proxy cache entry is missing on disk; re-fetching from the \
                             discovered PackageBaseAddress (buffered, digest-verified)"
                        );

                        if artifact.size_bytes > VERIFIED_NUPKG_REPAIR_MAX_BYTES as i64 {
                            tracing::error!(
                                target: "security",
                                artifact_id = %artifact.id,
                                storage_key = %artifact.storage_key,
                                size_bytes = artifact.size_bytes,
                                limit_bytes = VERIFIED_NUPKG_REPAIR_MAX_BYTES,
                                "refusing to repair a missing .nupkg: verification requires \
                                 buffering the whole body and this row exceeds the ceiling; \
                                 serving it unverified would silently drop the #2929 guarantee"
                            );
                            return Err((
                                StatusCode::INSUFFICIENT_STORAGE,
                                "cached package is missing and is too large to repair under \
                                 checksum verification; restore it from backup or re-publish",
                            )
                                .into_response());
                        }

                        let (fetch_url, cache_path) = flatcontainer_fetch_target(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &sub_path,
                        )
                        .await?;

                        let content = proxy_helpers::get_cached_or_refetch(
                            &state.db,
                            artifact.id,
                            storage.as_ref(),
                            &artifact.storage_key,
                            Some(expected.as_str()),
                            || async {
                                let (bytes, _content_type) =
                                    proxy_helpers::proxy_fetch_capped_with_cache_key(
                                        proxy,
                                        repo.id,
                                        &repo_key,
                                        upstream_url,
                                        &fetch_url,
                                        &cache_path,
                                        VERIFIED_NUPKG_REPAIR_MAX_BYTES,
                                    )
                                    .await?;
                                Ok(bytes)
                            },
                        )
                        .await?;

                        content_length = content.len() as i64;
                        Box::pin(futures::stream::once(async move { Ok(content) }))
                    }
                    None => {
                        tracing::warn!(
                            artifact_id = %artifact.id,
                            storage_key = %artifact.storage_key,
                            "nuget proxy cache entry is missing on disk; re-fetching from the \
                             discovered PackageBaseAddress (streaming, no enforceable digest \
                             recorded)"
                        );
                        let response = proxy_v3_flatcontainer(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &sub_path,
                            true,
                        )
                        .await?;
                        // Recorded after the upstream body is open so a failed
                        // repair is not counted as a download; the shared
                        // `record_download` below is skipped by this early return.
                        crate::services::artifact_service::record_download(
                            &state.db,
                            artifact.id,
                            &ctx,
                        )
                        .await;
                        return Ok(response);
                    }
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Storage error: {}", e),
                )
                    .into_response());
            }
        };

    // Record download.
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    use futures::StreamExt as _;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content_length.to_string())
        .body(Body::from_stream(
            body.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// NuGet / Chocolatey V2 (OData) read protocol (#2775)
// ---------------------------------------------------------------------------
//
// Chocolatey (`choco`) and the classic `nuget` V2 client speak OData, not V3.
// A remote repo proxies its upstream V2 feed and rewrites the absolute URLs it
// embeds (`<content src>`, entry `<id>`, `xml:base`) back to this proxy so the
// client's follow-up downloads come through us. A hosted repo answers the same
// OData shapes from local rows.

/// Build an XML `Response` with the given status/content-type/body.
fn xml_response(status: StatusCode, content_type: &str, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap()
}

/// Extract a single-quoted OData string argument named `key` from a query or
/// key segment, e.g. `id='Foo'` -> `Foo`. Pure + case-insensitive on the key.
fn odata_string_arg(haystack: &str, key: &str) -> Option<String> {
    let lower = haystack.to_lowercase();
    let needle = format!("{}=", key.to_lowercase());
    let start = lower.find(&needle)? + needle.len();
    let rest = &haystack[start..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('\'')?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Parse the `(Id='x',Version='y')` key of a `Packages(...)` OData segment.
fn parse_packages_key(segment: &str) -> (Option<String>, Option<String>) {
    (
        odata_string_arg(segment, "Id"),
        odata_string_arg(segment, "Version"),
    )
}

/// Rewrite the upstream feed base to this proxy's V2 base throughout a proxied
/// OData document. String-based so it covers `<id>`, `<content src>` and
/// `xml:base` uniformly regardless of the feed's exact shape. Pure.
fn rewrite_v2_odata(body: &str, upstream_base: &str, ak_v2_base: &str) -> String {
    let up = upstream_base.trim_end_matches('/');
    let ak = ak_v2_base.trim_end_matches('/');
    body.replace(up, ak)
}

/// A `<content src=.../>` .nupkg download link relative to the AK V2 base.
fn v2_content_src(ak_v2_base: &str, id: &str, version: &str) -> String {
    format!(
        "{}/package/{}/{}",
        ak_v2_base.trim_end_matches('/'),
        id,
        version
    )
}

/// GET /nuget/{repo_key}/v2 — OData service document (collection listing).
async fn v2_service_document(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let _repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let base = format!("{}/nuget/{}/v2/", base_url.as_str(), repo_key);
    let doc = format!(
        r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<service xml:base="{base}" xmlns="http://www.w3.org/2007/app" xmlns:atom="http://www.w3.org/2005/Atom">
  <workspace>
    <atom:title>Default</atom:title>
    <collection href="Packages">
      <atom:title>Packages</atom:title>
    </collection>
  </workspace>
</service>"#
    );
    Ok(xml_response(
        StatusCode::OK,
        "application/xml;charset=utf-8",
        doc,
    ))
}

/// Minimal static OData `$metadata` (EDMX) advertising the V1FeedPackage entity
/// set. Sufficient for `choco`/`nuget` V2 clients to bind the feed.
const V2_METADATA_EDMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx">
  <edmx:DataServices xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" m:DataServiceVersion="2.0">
    <Schema Namespace="NuGet.Server.DataServices" xmlns="http://schemas.microsoft.com/ado/2006/04/edm">
      <EntityType Name="V2FeedPackage" m:HasStream="true">
        <Key><PropertyRef Name="Id"/><PropertyRef Name="Version"/></Key>
        <Property Name="Id" Type="Edm.String" Nullable="false"/>
        <Property Name="Version" Type="Edm.String" Nullable="false"/>
        <Property Name="Authors" Type="Edm.String"/>
        <Property Name="Description" Type="Edm.String"/>
        <Property Name="PackageHash" Type="Edm.String"/>
        <Property Name="PackageHashAlgorithm" Type="Edm.String"/>
        <Property Name="PackageSize" Type="Edm.Int64"/>
      </EntityType>
      <EntityContainer Name="FeedContext" m:IsDefaultEntityContainer="true">
        <EntitySet Name="Packages" EntityType="NuGet.Server.DataServices.V2FeedPackage"/>
        <FunctionImport Name="FindPackagesById" EntitySet="Packages" ReturnType="Collection(NuGet.Server.DataServices.V2FeedPackage)" m:HttpMethod="GET">
          <Parameter Name="id" Type="Edm.String"/>
        </FunctionImport>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#;

/// A single hosted-repo OData `<entry>` for a package version.
struct V2Entry {
    id: String,
    version: String,
    authors: String,
    description: String,
    hash_sha256_b64: Option<String>,
    size: i64,
}

fn build_v2_entry(ak_v2_base: &str, e: &V2Entry) -> String {
    let content_src = v2_content_src(ak_v2_base, &e.id, &e.version);
    let entry_id = format!(
        "{}/Packages(Id='{}',Version='{}')",
        ak_v2_base.trim_end_matches('/'),
        e.id,
        e.version
    );
    let hash = e.hash_sha256_b64.clone().unwrap_or_default();
    format!(
        r#"  <entry>
    <id>{entry_id}</id>
    <title type="text">{id}</title>
    <content type="application/zip" src="{content_src}"/>
    <m:properties>
      <d:Id>{id}</d:Id>
      <d:Version>{version}</d:Version>
      <d:Authors>{authors}</d:Authors>
      <d:Description>{description}</d:Description>
      <d:PackageHash>{hash}</d:PackageHash>
      <d:PackageHashAlgorithm>SHA256</d:PackageHashAlgorithm>
      <d:PackageSize m:type="Edm.Int64">{size}</d:PackageSize>
    </m:properties>
  </entry>
"#,
        entry_id = entry_id,
        id = xml_escape(&e.id),
        content_src = content_src,
        version = xml_escape(&e.version),
        authors = xml_escape(&e.authors),
        description = xml_escape(&e.description),
        hash = hash,
        size = e.size,
    )
}

fn build_v2_feed(ak_v2_base: &str, entries: &[V2Entry]) -> String {
    let base = format!("{}/", ak_v2_base.trim_end_matches('/'));
    let body: String = entries
        .iter()
        .map(|e| build_v2_entry(ak_v2_base, e))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<feed xml:base="{base}" xmlns="http://www.w3.org/2005/Atom" xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
  <title type="text">Packages</title>
{body}</feed>"#
    )
}

/// Minimal XML text escape for entity content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// GET /nuget/{repo_key}/v2/*odata — OData query, `$metadata`, or download.
async fn v2_odata(
    State(state): State<SharedState>,
    Path((repo_key, odata)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    base_url: RequestBaseUrl,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let ak_v2_base = format!("{}/nuget/{}/v2", base_url.as_str(), repo_key);
    let odata = odata.trim_end_matches('/').to_string();

    // OData $metadata document (static; sufficient for choco/nuget to bind).
    if odata.eq_ignore_ascii_case("$metadata") {
        return Ok(xml_response(
            StatusCode::OK,
            "application/xml;charset=utf-8",
            V2_METADATA_EDMX.to_string(),
        ));
    }

    // Package content download: /v2/package/{id}/{version}.
    if let Some(rest) = odata.strip_prefix("package/") {
        let mut it = rest.splitn(2, '/');
        let id = it.next().unwrap_or_default().to_string();
        let version = it.next().unwrap_or_default().to_string();
        return v2_download(&state, &repo, &repo_key, &id, &version, &ctx).await;
    }

    // Otherwise an OData query: FindPackagesById(), Packages(...), Search(), ...
    // Remote: proxy the upstream feed and rewrite its embedded URLs (#2775).
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let up = upstream_url.trim_end_matches('/');
            let fetch_url = match &query {
                Some(q) if !q.is_empty() => format!("{}/{}?{}", up, odata, q),
                _ => format!("{}/{}", up, odata),
            };
            let cache_path = format!(
                "v2/{}",
                sanitize_cache_segment(&format!("{}_{}", odata, query.as_deref().unwrap_or("")))
            );
            let (content, content_type) = proxy_helpers::proxy_fetch_capped_with_cache_key(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &fetch_url,
                &cache_path,
                proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            )
            .await?;
            let body = String::from_utf8_lossy(&content);
            let rewritten = rewrite_v2_odata(&body, up, &ak_v2_base);
            return Ok(xml_response(
                StatusCode::OK,
                &content_type.unwrap_or_else(|| "application/atom+xml;charset=utf-8".to_string()),
                rewritten,
            ));
        }
    }

    // Hosted / local: build the OData feed from local rows.
    let (id_filter, version_filter) = if odata.starts_with("Packages(") {
        parse_packages_key(&odata)
    } else if odata.eq_ignore_ascii_case("FindPackagesById()") {
        (odata_string_arg(query.as_deref().unwrap_or(""), "id"), None)
    } else {
        // Search() and bare Packages: list everything (bounded).
        (None, None)
    };

    let entries = load_hosted_v2_entries(
        &state,
        &repo,
        id_filter.as_deref(),
        version_filter.as_deref(),
    )
    .await?;
    let feed = build_v2_feed(&ak_v2_base, &entries);
    Ok(xml_response(
        StatusCode::OK,
        "application/atom+xml;charset=utf-8",
        feed,
    ))
}

/// Replace characters that would break a proxy-cache storage path.
fn sanitize_cache_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Load hosted V2 feed entries for a repo, optionally filtered by package
/// id/version. Federates over virtual local members like the V3 handlers.
async fn load_hosted_v2_entries(
    state: &SharedState,
    repo: &RepoInfo,
    id_filter: Option<&str>,
    version_filter: Option<&str>,
) -> Result<Vec<V2Entry>, Response> {
    let (repo_ids, _members) = effective_local_repo_ids(&state.db, repo).await?;
    let id_lower = id_filter.map(|s| s.to_lowercase());
    let rows = sqlx::query!(
        r#"
        SELECT a.name AS name, a.version AS "version?", a.size_bytes AS size_bytes,
               a.checksum_sha256 AS "checksum_sha256?",
               am.metadata AS "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = ANY($1::uuid[])
          AND a.is_deleted = false
          AND a.version IS NOT NULL
          AND ($2::text IS NULL OR LOWER(a.name) = $2)
          AND ($3::text IS NULL OR a.version = $3)
        ORDER BY a.name ASC, a.created_at ASC
        LIMIT 500
        "#,
        &repo_ids,
        id_lower.as_deref(),
        version_filter,
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let meta = r.metadata;
            let authors = meta
                .as_ref()
                .and_then(|m| m.get("authors"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let description = meta
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let hash_sha256_b64 = r
                .checksum_sha256
                .as_ref()
                .and_then(|hex| hex::decode(hex).ok().map(|bytes| base64_standard(&bytes)));
            V2Entry {
                id: r.name,
                version: r.version.unwrap_or_default(),
                authors,
                description,
                hash_sha256_b64,
                size: r.size_bytes,
            }
        })
        .collect())
}

/// GET /nuget/{repo_key}/v2/package/{id}/{version} — download the .nupkg.
/// Remote repos stream from their upstream V2 feed; hosted repos serve from
/// storage.
async fn v2_download(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    id: &str,
    version: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    // Curation enforcement (#2930): gate the V2 .nupkg download seam too, so a
    // block rule holds regardless of whether the client uses the V3 flat
    // container or the legacy V2 package route. No-op for hosted / curation off.
    proxy_helpers::enforce_curation(&state.db, repo, &id.to_lowercase(), Some(version)).await?;

    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let up = upstream_url.trim_end_matches('/');
            let fetch_url = format!("{}/package/{}/{}", up, id, version);
            let cache_path = format!("v2/package/{}/{}/package.nupkg", id.to_lowercase(), version);
            return proxy_helpers::proxy_fetch_streaming_response_with_cache_key(
                proxy,
                repo.id,
                repo_key,
                upstream_url,
                &fetch_url,
                &cache_path,
                "application/octet-stream",
                RepositoryFormat::Nuget,
            )
            .await;
        }
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Hosted / local: look the artifact up and stream from storage.
    let id_lower = id.to_lowercase();
    let (repo_ids, _members) = effective_local_repo_ids(&state.db, repo).await?;
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = ANY($1::uuid[])
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version = $3
        LIMIT 1
        "#,
        &repo_ids,
        id_lower,
        version,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package version not found").into_response())?;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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
    crate::services::artifact_service::record_download(&state.db, artifact.id, ctx).await;
    use futures::StreamExt as _;
    let filename = build_nupkg_filename(&id_lower, version);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(
            stream.map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
        ))
        .unwrap())
}

/// Standard base64 encode (used for the OData `PackageHash`).
fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// PUT /nuget/{repo_key}/api/v2/package — Push package
// ---------------------------------------------------------------------------

async fn push_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    // `repo_visibility_middleware` resolves the caller for every format route
    // — including the `X-NuGet-ApiKey` push credential (#2642) — and rejects an
    // unauthenticated or invalid-credential write with 401 before this handler
    // runs, so the auth extension is always present here.
    //
    // Require it rather than re-authenticating locally: a second credential
    // path in the handler would be strictly weaker than the middleware's,
    // because it can only reach `require_scope_response` with `None`, which is
    // a no-op — silently skipping the GHSA-vvc3-h39c-mrq5 write-scope check.
    let auth = auth.ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;
    // GHSA-vvc3-h39c-mrq5: enforce write scope before doing anything else.
    crate::api::middleware::auth::require_scope_response(Some(&auth), "write:artifacts")?;
    let user_id = auth.user_id;
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Ingest the body as a stream — dotnet sends multipart/form-data, other
    // clients (curl, older tooling) send the raw .nupkg. Both spool to a bounded
    // scratch file while computing SHA-256/SHA-1/MD5 incrementally, never
    // buffering the whole package in memory.
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (staged, digests) = if content_type.contains("multipart/form-data") {
        // Streaming-multipart branch: parse the envelope off the body stream
        // (no full-body buffer) and spool the first file part.
        let boundary = multer::parse_boundary(content_type)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Missing multipart boundary").into_response())?;
        let mut multipart = multer::Multipart::new(body.into_data_stream(), boundary);
        let field = multipart
            .next_field()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid multipart body: {e}"),
                )
                    .into_response()
            })?
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid multipart body").into_response())?;
        proxy_helpers::stage_stream_content_addressed(&state, field).await?
    } else {
        // Raw-binary branch: the entire body is the .nupkg.
        proxy_helpers::stage_stream_content_addressed(&state, body.into_data_stream()).await?
    };

    if staged.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package body").into_response());
    }

    // Parse .nuspec from the SEEKABLE staged file (the ZIP reader needs
    // Read + Seek); run the blocking archive read off the async runtime.
    // #2561: permit held across the blocking decode, fast-fail 503 on saturation.
    let staged_path = staged.path().to_path_buf();
    let nuspec = crate::util::bounded_archive::with_ingest_extraction_async(|| {
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&staged_path)
                .map_err(|e| format!("Cannot open staged package: {e}"))?;
            parse_nuspec_from_reader(file)
        })
    })
    .await
    .map_err(|e| e.into_response())?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("nuspec parse task failed: {e}"),
        )
            .into_response()
    })?
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read .nuspec from package: {e}"),
        )
            .into_response()
    })?;

    let package_id = nuspec.id.to_lowercase();
    let version = nuspec.version.clone();

    if package_id.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package ID and version are required in .nuspec",
        )
            .into_response());
    }

    let size_bytes = staged.size_bytes();
    let filename = build_nupkg_filename(&package_id, &version);
    let artifact_path = build_nuget_artifact_path(&package_id, &version);

    // Converge onto the shared content-addressed streaming service method:
    // deduplication, the release-immutability backstop (a duplicate id.version or
    // a different-bytes swap of a released coordinate -> 409), ON CONFLICT
    // tombstone resurrection, quarantine hold, and peer sync fan-out. New uploads
    // store under the content-addressed SHA-256 key; OLD `nuget/...` rows keep
    // their storage_key (download reads storage_key per-row) — no migration.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let artifact_service = state.create_artifact_service(storage);
    let content_stream = proxy_helpers::open_staged_upload_stream(&staged).await?;
    let artifact = artifact_service
        .upload_stream_with_sync_options(
            repo.id,
            &artifact_path,
            &package_id,
            Some(&version),
            "application/octet-stream",
            content_stream,
            digests,
            size_bytes,
            Some(user_id),
            true,
        )
        .await
        .map_err(|e| e.into_response())?;
    // Scratch file no longer needed once the service has consumed the stream.
    drop(staged);

    // Build metadata JSON.
    let metadata = build_nuget_push_metadata(&nuspec);

    // Store metadata.
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'nuget', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact.id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Populate packages / package_versions tables (best-effort) so the
    // package shows up in the UI Packages tab. Mirrors npm.rs / pypi.rs.
    let description = if nuspec.description.is_empty() {
        None
    } else {
        Some(nuspec.description.as_str())
    };
    crate::services::package_service::PackageService::new(state.db.clone())
        .try_create_or_update_from_artifact(
            repo.id,
            &nuspec.id,
            &version,
            size_bytes,
            &artifact.checksum_sha256,
            description,
            Some(serde_json::json!({ "format": "nuget" })),
        )
        .await;

    // Update repository timestamp.
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "NuGet push: {} {} ({}) to repo {}",
        nuspec.id, version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// .nupkg / .nuspec helpers
// ---------------------------------------------------------------------------

/// Metadata extracted from a .nuspec file.
struct NuspecInfo {
    id: String,
    version: String,
    description: String,
    authors: String,
}

/// Parse the .nuspec XML from inside a .nupkg (ZIP) archive.
///
/// Reads directly from any `Read + Seek` source — the streaming push path passes
/// the SEEKABLE staged scratch `File` so the archive is never re-buffered in
/// memory. Uses simple string matching rather than a full XML parser.
fn parse_nuspec_from_reader<R: std::io::Read + std::io::Seek>(
    reader: R,
) -> Result<NuspecInfo, String> {
    // Bound the decompression: entry-count cap + per-metadata-entry cap so a
    // crafted .nupkg cannot inflate the .nuspec unbounded during metadata
    // parsing (#2556). Zip is random-access, so unmatched entries are never
    // inflated.
    let nuspec_bytes = crate::util::bounded_archive::read_metadata_from_zip(reader, |name| {
        name.ends_with(".nuspec")
    })
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "No .nuspec file found in package".to_string())?;
    let nuspec_xml =
        String::from_utf8(nuspec_bytes).map_err(|e| format!("Cannot read .nuspec: {}", e))?;

    if nuspec_xml.is_empty() {
        return Err("No .nuspec file found in package".to_string());
    }

    // Simple tag extraction.
    let id = extract_xml_tag(&nuspec_xml, "id").unwrap_or_default();
    let version = extract_xml_tag(&nuspec_xml, "version").unwrap_or_default();
    let description = extract_xml_tag(&nuspec_xml, "description").unwrap_or_default();
    let authors = extract_xml_tag(&nuspec_xml, "authors").unwrap_or_default();

    Ok(NuspecInfo {
        id,
        version,
        description,
        authors,
    })
}

/// Extract the text content of a simple XML tag (no attributes, no nesting).
/// e.g. `<id>Foo</id>` returns `Some("Foo")`.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start_pos = xml.find(&open)?;
    // Skip past the opening tag (handle possible attributes or xmlns).
    let after_open = &xml[start_pos + open.len()..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end_pos = content.find(&close)?;
    Some(content[..end_pos].trim().to_string())
}

// ---------------------------------------------------------------------------
// Path/URL builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build the base URL for NuGet service index resources from the request base
/// (`{scheme}://{host}`) and repo key.
fn build_nuget_base_url(request_base: &str, repo_key: &str) -> String {
    format!("{}/nuget/{}", request_base, repo_key)
}

/// Build the flatcontainer versions JSON response.
fn build_flatcontainer_versions_json(versions: &[String]) -> serde_json::Value {
    serde_json::json!({
        "versions": versions
    })
}

/// Build the canonical `.nupkg` filename (`{id}.{version}.nupkg`; the caller
/// passes the lowercased package id).
fn build_nupkg_filename(package_id: &str, version: &str) -> String {
    format!("{}.{}.nupkg", package_id, version)
}

/// Build the NuGet artifact path for a .nupkg.
fn build_nuget_artifact_path(package_id: &str, version: &str) -> String {
    let filename = build_nupkg_filename(package_id, version);
    format!("{}/{}/{}", package_id, version, filename)
}

/// Build the NuGet push metadata JSON.
fn build_nuget_push_metadata(info: &NuspecInfo) -> serde_json::Value {
    serde_json::json!({
        "id": info.id,
        "version": info.version,
        "description": info.description,
        "authors": info.authors,
        "filename": build_nupkg_filename(&info.id.to_lowercase(), &info.version),
    })
}

/// Build the search pattern for NuGet package queries.
fn build_nuget_search_pattern(query_term: &str) -> String {
    format!("%{}%", query_term.to_lowercase())
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::to_bytes;
    use axum::http::HeaderValue;
    use bytes::Bytes;
    use chrono::Utc;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn lazy_pool() -> sqlx::PgPool {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy_with(
                PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(1)
                    .username("invalid")
                    .password("invalid")
                    .database("invalid"),
            )
    }

    fn test_state_with_secret(secret: &str) -> SharedState {
        let config = crate::config::Config {
            jwt_secret: secret.to_string(),
            ..crate::config::Config::default()
        };

        let storage_root =
            std::env::temp_dir().join(format!("ak-nuget-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_root).expect("create temp storage dir");

        let storage: Arc<dyn crate::storage::StorageBackend> =
            Arc::new(crate::storage::filesystem::FilesystemStorage::new(
                storage_root.to_str().expect("utf8 storage path"),
            ));
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));

        Arc::new(crate::api::AppState::new(
            config,
            lazy_pool(),
            storage,
            registry,
        ))
    }

    fn mint_access_jwt(secret: &str, username: &str) -> String {
        let now = Utc::now().timestamp();
        let claims = crate::services::auth_service::Claims {
            sub: uuid::Uuid::new_v4(),
            username: username.to_string(),
            email: format!("{}@example.test", username),
            is_admin: false,
            allowed_repo_ids: None,
            iat: now,
            iat_ms: Some(Utc::now().timestamp_millis()),
            exp: now + 300,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
            scopes: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode jwt")
    }

    /// The handler must never authenticate a push itself.
    ///
    /// `repo_visibility_middleware` is the single credential authority for
    /// format routes: it resolves `X-NuGet-ApiKey` on the push route (#2642)
    /// and 401s an unauthenticated or invalid-credential write before this
    /// handler runs. The handler previously carried its own `X-NuGet-ApiKey`
    /// fallback (`user:pass` -> `authenticate()`, or a raw JWT); those shapes
    /// are unreachable now, and that path was strictly weaker — it could only
    /// reach `require_scope_response` with `None`, which is a no-op that skips
    /// the GHSA-vvc3-h39c-mrq5 write-scope check.
    ///
    /// Pin the deletion: a missing auth extension is 401 no matter what the
    /// header carries, so the parallel auth path cannot be reintroduced by
    /// accident.
    #[tokio::test]
    async fn test_push_package_rejects_unauthenticated_push_whatever_the_api_key_header() {
        let secret = "test-secret-at-least-32-bytes-long-for-testing";
        let jwt = mint_access_jwt(secret, "ci-user");

        // No header, plus both credential shapes the removed fallback accepted.
        let api_keys = [
            None,
            Some(format!("ci-user:{}", jwt)),
            Some(jwt.clone()),
            Some("apikey-value".to_string()),
        ];

        for api_key in api_keys {
            let state = test_state_with_secret(secret);
            let mut headers = HeaderMap::new();
            if let Some(key) = &api_key {
                headers.insert(
                    "X-NuGet-ApiKey",
                    HeaderValue::from_str(key).expect("api key header"),
                );
            }

            let resp = push_package(
                State(state),
                Extension(None),
                Path("nuget-test".to_string()),
                headers,
                Body::from("dummy"),
            )
            .await
            .expect_err("no auth extension must fail before repo resolution");

            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let body = to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("read body");
            assert_eq!(
                std::str::from_utf8(&body).unwrap(),
                "Authentication required",
                "X-NuGet-ApiKey {api_key:?} must not authenticate at the handler"
            );
        }
    }

    // NOTE: the test-local `build_registration_item` / `build_nuget_service_index`
    // copies were removed (#2657). They fabricated advertised-URL documents and
    // asserted a builder matched its own literal, so they could not catch a
    // production document advertising a URL that 404s — the exact class behind
    // #2587. The registration leaf `@id` those copies emitted
    // (`.../registration/{id}/{version}.json`) is a route the server does NOT
    // serve; production emits `.../index.json#{version}` instead. The real
    // service-index resources, registration leaf `@id`, and `packageContent`
    // are now driven through the mounted router in
    // `read_db_tests::test_advertised_v3_urls_resolve_against_real_router`.

    // -----------------------------------------------------------------------
    // Upstream search proxying (#3130)
    // -----------------------------------------------------------------------

    /// A minimal upstream service index advertising search under `@type`
    /// `search_type`, with resources on the same host as the index itself.
    fn upstream_index_with_search_type(search_type: &str) -> serde_json::Value {
        serde_json::json!({
            "version": "3.0.0",
            "resources": [
                {
                    "@id": "https://feed.example.com/v3/registration/",
                    "@type": "RegistrationsBaseUrl"
                },
                {
                    "@id": "https://feed.example.com/v3-flatcontainer/",
                    "@type": "PackageBaseAddress/3.0.0"
                },
                {
                    "@id": "https://feed.example.com/query",
                    "@type": search_type
                }
            ]
        })
    }

    #[test]
    fn test_parse_upstream_resources_picks_each_search_query_service_spelling() {
        // NuGet feeds advertise the search resource under several `@type`
        // spellings; each must resolve the search base (#3130).
        for search_type in [
            "SearchQueryService",
            "SearchQueryService/3.0.0-beta",
            "SearchQueryService/3.0.0-rc",
        ] {
            let parsed = parse_upstream_resources(&upstream_index_with_search_type(search_type));
            assert_eq!(
                parsed.search_base.as_deref(),
                Some("https://feed.example.com/query"),
                "@type {search_type} must resolve the search base"
            );
        }
    }

    #[test]
    fn test_parse_upstream_resources_no_search_resource() {
        let index = serde_json::json!({
            "version": "3.0.0",
            "resources": [
                {"@id": "https://feed.example.com/v3/registration/", "@type": "RegistrationsBaseUrl"}
            ]
        });
        assert_eq!(parse_upstream_resources(&index).search_base, None);
    }

    #[test]
    fn test_guard_search_base_same_origin_is_credentialed() {
        // A same-origin search base fetches exactly as before: with the
        // repo's configured upstream credentials (`same_origin == true`).
        let upstream = "https://feed.example.com/v3/index.json";
        let same_origin = Some("https://feed.example.com/query".to_string());
        let (base, credentialed) = guard_search_base(same_origin.as_ref(), upstream)
            .expect("same-origin SearchQueryService is allowed");
        assert_eq!(base, "https://feed.example.com/query");
        assert!(credentialed, "same-origin search base fetches credentialed");
    }

    #[test]
    fn test_guard_search_base_off_origin_allowed_but_anonymous() {
        // nuget.org advertises SearchQueryService on azuresearch-*.nuget.org
        // while index.json lives on api.nuget.org: an off-origin search base
        // is ALLOWED, but flagged for an anonymous (credential-free) fetch —
        // the #2925 invariant is enforced by stripping credentials, not by
        // refusing the fetch.
        let upstream = "https://api.nuget.org/v3/index.json";
        let off_origin = Some("https://azuresearch-usnc.nuget.org/query".to_string());
        let (base, credentialed) = guard_search_base(off_origin.as_ref(), upstream)
            .expect("off-origin SearchQueryService is allowed (anonymous)");
        assert_eq!(base, "https://azuresearch-usnc.nuget.org/query");
        assert!(
            !credentialed,
            "off-origin search base must never fetch with the repo's configured credentials"
        );
    }

    #[test]
    fn test_guard_search_base_rejects_non_http_and_missing() {
        let upstream = "https://feed.example.com/v3/index.json";
        // A non-http(s) base is still refused.
        let ftp = Some("ftp://feed.example.com/query".to_string());
        let err = guard_search_base(ftp.as_ref(), upstream)
            .expect_err("non-http(s) SearchQueryService must be refused");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        // A feed that advertises no search resource is refused (the caller
        // degrades to the local result).
        let err = guard_search_base(None, upstream)
            .expect_err("absent SearchQueryService must be refused");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_guard_upstream_base_registration_still_rejects_off_origin() {
        // #2925 regression pin: the search-only anonymous allowance must NOT
        // leak into registration / flat-container resolution — those remain
        // origin-pinned and refuse an off-origin base outright.
        let upstream = "https://feed.example.com/v3/index.json";
        let off_origin = Some("https://evil.example.net/reg".to_string());
        let err = guard_upstream_base(off_origin.as_ref(), upstream, "RegistrationsBaseUrl")
            .expect_err("off-origin RegistrationsBaseUrl must be refused");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_rewrite_search_payload_rebinds_registration_urls_to_proxy() {
        // The upstream search payload embeds upstream registration URLs; they
        // must be rewritten to AK's own base so the client's follow-up
        // registration fetches come back through the proxy.
        let resources = NugetUpstreamResources {
            registration_base: Some("https://feed.example.com/v3/registration".to_string()),
            package_base: Some("https://feed.example.com/v3-flatcontainer".to_string()),
            search_base: Some("https://feed.example.com/query".to_string()),
        };
        let body = r#"{"totalHits":1,"data":[{
            "@id":"https://feed.example.com/v3/registration/newtonsoft.json/index.json",
            "registration":"https://feed.example.com/v3/registration/newtonsoft.json/index.json",
            "id":"Newtonsoft.Json",
            "versions":[{"version":"13.0.1",
                "@id":"https://feed.example.com/v3/registration/newtonsoft.json/13.0.1.json"}]
        }]}"#;
        let out = rewrite_v3_registration(body, &resources, "http://ak.local:8080", "nuget-remote");
        assert!(
            out.contains("http://ak.local:8080/nuget/nuget-remote/v3/registration/newtonsoft.json/index.json"),
            "registration URLs must be rebound to the proxy: {out}"
        );
        assert!(
            !out.contains("https://feed.example.com/v3/registration"),
            "no upstream registration URL may survive the rewrite: {out}"
        );
    }

    #[test]
    fn test_search_cache_key_encodes_every_parameter() {
        // Regression test for cross-query cache contamination: the proxy-cache
        // key must differ whenever any search parameter differs, or every
        // query would serve the first query's cached results.
        let base = build_search_cache_key("newtonsoft", 0, 20, false);
        assert_ne!(base, build_search_cache_key("serilog", 0, 20, false), "q");
        assert_ne!(
            base,
            build_search_cache_key("newtonsoft", 5, 20, false),
            "skip"
        );
        assert_ne!(
            base,
            build_search_cache_key("newtonsoft", 0, 50, false),
            "take"
        );
        assert_ne!(
            base,
            build_search_cache_key("newtonsoft", 0, 20, true),
            "prerelease"
        );

        // Deterministic normalization: equivalent queries share a key.
        assert_eq!(base, build_search_cache_key("NewtonSoft", 0, 20, false));
    }

    #[test]
    fn test_search_fetch_query_encodes_user_controlled_q() {
        // `q` is attacker/user-controlled free text: it must not be able to
        // inject extra query parameters or break out of the URL.
        let query = build_search_fetch_query("a&take=1000#frag", 0, 20, false);
        assert_eq!(
            query,
            "q=a%26take%3D1000%23frag&skip=0&take=20&prerelease=false"
        );
    }

    #[test]
    fn test_merge_upstream_search_data_dedupes_local_wins() {
        let mut data = vec![serde_json::json!({"id": "Newtonsoft.Json", "version": "1.0.0-local"})];
        let upstream = serde_json::json!({
            "totalHits": 3,
            "data": [
                {"id": "newtonsoft.json", "version": "13.0.1"},
                {"id": "Serilog", "version": "3.1.1"},
                {"id": "Dapper", "version": "2.1.0"}
            ]
        });
        let added = merge_upstream_search_data(&mut data, &upstream, 2);
        assert_eq!(added, 1, "bounded by take and deduped case-insensitively");
        assert_eq!(data.len(), 2);
        assert_eq!(
            data[0]["version"], "1.0.0-local",
            "the local entry wins over the upstream duplicate"
        );
        assert_eq!(data[1]["id"], "Serilog");
    }

    // -----------------------------------------------------------------------
    // extract_xml_tag
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_tag_simple() {
        let xml = "<id>MyPackage</id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_whitespace() {
        let xml = "<id>  MyPackage  </id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_namespace() {
        let xml = r#"<id xmlns="http://example.com">PackageWithNS</id>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("PackageWithNS".to_string())
        );
    }

    #[test]
    fn test_extract_xml_tag_missing() {
        let xml = "<name>Hello</name>";
        assert_eq!(extract_xml_tag(xml, "id"), None);
    }

    #[test]
    fn test_extract_xml_tag_empty_content() {
        let xml = "<id></id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_in_nuspec() {
        let xml = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <description>Popular JSON framework</description>
    <authors>James Newton-King</authors>
  </metadata>
</package>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(extract_xml_tag(xml, "version"), Some("13.0.1".to_string()));
        assert_eq!(
            extract_xml_tag(xml, "description"),
            Some("Popular JSON framework".to_string())
        );
        assert_eq!(
            extract_xml_tag(xml, "authors"),
            Some("James Newton-King".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // parse_nuspec_from_nupkg (byte-slice wrapper over parse_nuspec_from_reader)
    // -----------------------------------------------------------------------

    /// Test-only convenience over [`parse_nuspec_from_reader`] for the existing
    /// in-memory `.nupkg` fixtures. Production callers pass the seekable staged
    /// `File` directly.
    fn parse_nuspec_from_nupkg(nupkg: &[u8]) -> Result<NuspecInfo, String> {
        parse_nuspec_from_reader(std::io::Cursor::new(nupkg))
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_valid() {
        // Create a minimal ZIP with a .nuspec file
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("MyPackage.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package>
  <metadata>
    <id>MyPackage</id>
    <version>1.2.3</version>
    <description>A test package</description>
    <authors>Test Author</authors>
  </metadata>
</package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "MyPackage");
        assert_eq!(nuspec.version, "1.2.3");
        assert_eq!(nuspec.description, "A test package");
        assert_eq!(nuspec.authors, "Test Author");
    }

    #[test]
    fn test_parse_nuspec_oversized_entry_rejected_2556() {
        // A .nuspec entry that inflates past the per-metadata-entry cap is a
        // decompression bomb and must be rejected (bounded memory), while the
        // compressed .nupkg stays tiny (highly repetitive deflate payload).
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Big.nuspec", options).unwrap();
        let oversized = vec![
            b'A';
            (crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES + 1024)
                as usize
        ];
        std::io::Write::write_all(&mut zip, &oversized).unwrap();
        let cursor = zip.finish().unwrap();
        assert!(
            cursor.get_ref().len() < 128 * 1024,
            "compressed nupkg is tiny"
        );

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_err(), "oversized .nuspec must be rejected");
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_no_nuspec() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("readme.txt", options).unwrap();
        std::io::Write::write_all(&mut zip, b"no nuspec here").unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("No .nuspec file found"));
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_invalid_zip() {
        let result = parse_nuspec_from_nupkg(b"not a zip file");
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Invalid ZIP archive"));
    }

    #[test]
    fn test_parse_nuspec_missing_fields() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Partial.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package><metadata><id>OnlyId</id></metadata></package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "OnlyId");
        assert_eq!(nuspec.version, "");
        assert_eq!(nuspec.description, "");
        assert_eq!(nuspec.authors, "");
    }

    // -----------------------------------------------------------------------
    // NuspecInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuspec_info_construction() {
        let info = NuspecInfo {
            id: "TestPkg".to_string(),
            version: "2.0.0".to_string(),
            description: "A library".to_string(),
            authors: "Author Name".to_string(),
        };
        assert_eq!(info.id, "TestPkg");
        assert_eq!(info.version, "2.0.0");
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert_eq!(q.skip, None);
        assert_eq!(q.take, None);
        assert_eq!(q.prerelease, None);
    }

    #[test]
    fn test_search_query_with_values() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"json","skip":10,"take":50,"prerelease":true}"#).unwrap();
        assert_eq!(q.q, Some("json".to_string()));
        assert_eq!(q.skip, Some(10));
        assert_eq!(q.take, Some(50));
        assert_eq!(q.prerelease, Some(true));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/nuget".to_string(),
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
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // SHA256 checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_checksum() {
        let data = b"nuget package data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        // Same input => same output
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let checksum2 = format!("{:x}", hasher2.finalize());
        assert_eq!(checksum, checksum2);
    }

    // -----------------------------------------------------------------------
    // Path/storage key construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_artifact_path() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let artifact_path = format!("{}/{}/{}", package_id, version, filename);
        assert_eq!(
            artifact_path,
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_nuget_storage_key() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let storage_key = format!("nuget/{}/{}/{}", package_id, version, filename);
        assert_eq!(
            storage_key,
            "nuget/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // Service index base URL
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_index_base_url() {
        let scheme = "https";
        let host = "myregistry.example.com";
        let repo_key = "nuget-hosted";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "https://myregistry.example.com/nuget/nuget-hosted");
    }

    #[test]
    fn test_service_index_default_host() {
        let scheme = "http";
        let host = "localhost";
        let repo_key = "main";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "http://localhost/nuget/main");
    }

    // -----------------------------------------------------------------------
    // build_nuget_base_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_base_url_https() {
        assert_eq!(
            build_nuget_base_url("https://registry.example.com", "nuget-hosted"),
            "https://registry.example.com/nuget/nuget-hosted"
        );
    }

    #[test]
    fn test_build_nuget_base_url_http_localhost() {
        assert_eq!(
            build_nuget_base_url("http://localhost", "main"),
            "http://localhost/nuget/main"
        );
    }

    #[test]
    fn test_build_nuget_base_url_with_port() {
        assert_eq!(
            build_nuget_base_url("http://localhost:8080", "nuget-local"),
            "http://localhost:8080/nuget/nuget-local"
        );
    }

    // The `build_nuget_service_index` / `build_registration_item` self-referential
    // tests were removed with their builders (#2657); the real service-index
    // resources, registration leaf `@id`, and `packageContent` are now driven
    // through the mounted router in
    // `read_db_tests::test_advertised_v3_urls_resolve_against_real_router`.

    // -----------------------------------------------------------------------
    // build_flatcontainer_versions_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_flatcontainer_versions_json_basic() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "3.0.0".to_string(),
        ];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "1.0.0");
        assert_eq!(arr[2], "3.0.0");
    }

    #[test]
    fn test_build_flatcontainer_versions_json_empty() {
        let versions: Vec<String> = vec![];
        let json = build_flatcontainer_versions_json(&versions);
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_flatcontainer_versions_json_single() {
        let versions = vec!["1.0.0-beta".to_string()];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "1.0.0-beta");
    }

    // -----------------------------------------------------------------------
    // build_nuget_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_artifact_path_basic() {
        assert_eq!(
            build_nuget_artifact_path("newtonsoft.json", "13.0.1"),
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_build_nuget_artifact_path_prerelease() {
        assert_eq!(
            build_nuget_artifact_path("mypackage", "1.0.0-beta.1"),
            "mypackage/1.0.0-beta.1/mypackage.1.0.0-beta.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_push_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_push_metadata_basic() {
        let info = NuspecInfo {
            id: "TestPackage".to_string(),
            version: "2.0.0".to_string(),
            description: "A test package".to_string(),
            authors: "Author".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        assert_eq!(meta["id"], "TestPackage");
        assert_eq!(meta["version"], "2.0.0");
        assert_eq!(meta["description"], "A test package");
        assert_eq!(meta["authors"], "Author");
        assert_eq!(meta["filename"], "testpackage.2.0.0.nupkg");
    }

    #[test]
    fn test_build_nuget_push_metadata_preserves_original_id() {
        let info = NuspecInfo {
            id: "Newtonsoft.Json".to_string(),
            version: "13.0.1".to_string(),
            description: "JSON framework".to_string(),
            authors: "James NK".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        // id is preserved as-is (with original casing)
        assert_eq!(meta["id"], "Newtonsoft.Json");
        // filename is lowercased
        assert_eq!(meta["filename"], "newtonsoft.json.13.0.1.nupkg");
    }

    // -----------------------------------------------------------------------
    // build_nuget_search_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_search_pattern_basic() {
        assert_eq!(build_nuget_search_pattern("json"), "%json%");
    }

    #[test]
    fn test_build_nuget_search_pattern_case_insensitive() {
        assert_eq!(build_nuget_search_pattern("Newton"), "%newton%");
    }

    #[test]
    fn test_build_nuget_search_pattern_empty() {
        assert_eq!(build_nuget_search_pattern(""), "%%");
    }

    #[test]
    fn test_build_nuget_search_pattern_with_dots() {
        assert_eq!(
            build_nuget_search_pattern("Newtonsoft.Json"),
            "%newtonsoft.json%"
        );
    }

    // -----------------------------------------------------------------------
    // is_prerelease_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_prerelease_version_stable() {
        assert!(!is_prerelease_version("1.0.0"));
        assert!(!is_prerelease_version("13.0.1"));
        assert!(!is_prerelease_version("2.0.0"));
    }

    #[test]
    fn test_is_prerelease_version_prerelease() {
        assert!(is_prerelease_version("2.0.0-beta.1"));
        assert!(is_prerelease_version("1.0.0-rc1"));
        assert!(is_prerelease_version("3.1.0-alpha"));
    }

    // -----------------------------------------------------------------------
    // select_latest_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_latest_version_excludes_prerelease_by_default() {
        // prerelease=false: the stable 1.0.0 wins over 2.0.0-beta.1, matching
        // the QA finding where prerelease=false wrongly returned 2.0.0-beta.1.
        let versions = vec!["1.0.0".to_string(), "2.0.0-beta.1".to_string()];
        assert_eq!(select_latest_version(&versions, false), "1.0.0");
    }

    #[test]
    fn test_select_latest_version_includes_prerelease_when_requested() {
        // prerelease=true: the highest overall version (the beta) wins.
        let versions = vec!["1.0.0".to_string(), "2.0.0-beta.1".to_string()];
        assert_eq!(select_latest_version(&versions, true), "2.0.0-beta.1");
    }

    #[test]
    fn test_select_latest_version_falls_back_to_prerelease_when_no_stable() {
        // Only a pre-release exists; even with prerelease=false it must be
        // surfaced rather than the "0.0.0" placeholder.
        let versions = vec!["1.0.0-alpha".to_string()];
        assert_eq!(select_latest_version(&versions, false), "1.0.0-alpha");
    }

    #[test]
    fn test_select_latest_version_highest_stable() {
        let versions = vec![
            "1.0.0".to_string(),
            "1.2.0".to_string(),
            "1.1.0".to_string(),
        ];
        assert_eq!(select_latest_version(&versions, false), "1.2.0");
    }

    #[test]
    fn test_select_latest_version_empty() {
        let versions: Vec<String> = vec![];
        assert_eq!(select_latest_version(&versions, false), "0.0.0");
        assert_eq!(select_latest_version(&versions, true), "0.0.0");
    }

    /// Warm-cache hit on the Remote arm: the `artifacts` row AND the blob are
    /// both present, so the handler serves the payload straight from storage and
    /// never touches the upstream (the `upstream_url` here does not resolve).
    ///
    /// Renamed from `..._routes_through_cached_or_refetch_helper`, which
    /// mis-described it: seeding the blob means the missing-blob repair closure is
    /// never invoked, so the old name claimed coverage the assertions did not
    /// have. The repair branch itself is covered by
    /// `test_flatcontainer_download_repairs_missing_blob_via_discovered_package_base`
    /// and `test_flatcontainer_download_repair_streams_body_above_metadata_cap`.
    #[tokio::test]
    async fn test_flatcontainer_download_remote_warm_cache_hit_served_from_storage() {
        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };

        let nupkg_bytes: &[u8] = b"cached-nupkg-from-disk";
        let package_id = "newtonsoft.json";
        let package_id_lower = package_id.to_lowercase();
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id_lower, version);

        // Upstream URL only needs to parse; no network I/O is performed here.
        let upstream = "https://upstream.example.test".to_string();
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);

        let repo_info = fx.repo_info("remote", Some(&upstream));

        // Seed storage and DB row. The handler looks up by name (lowercased)
        // and version, so the exact `path` inserted is unimportant here.
        let storage_key = format!("nuget/{}/{}/{}", package_id_lower, version, filename);
        let artifact_path = format!(
            "v3/flatcontainer/{}/{}/{}",
            package_id_lower, version, filename
        );

        tdh::seed_artifact(
            &state,
            &fx.pool,
            &repo_info,
            &storage_key,
            &artifact_path,
            &package_id_lower,
            version,
            "application/octet-stream",
            Bytes::from_static(nupkg_bytes),
            fx.user_id,
        )
        .await;

        // Call the handler directly via extractors.
        let result = super::flatcontainer_download(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                package_id_lower.clone(),
                version.to_string(),
                filename.clone(),
            )),
            Default::default(),
        )
        .await;

        // Cleanup first so a panic does not leave DB state behind.
        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        let response = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                cleanup().await;
                panic!("flatcontainer_download Remote arm must serve cached payload, got {status}");
            }
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("Content-Type")
                .to_str()
                .unwrap(),
            "application/octet-stream",
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .expect("Content-Length")
                .to_str()
                .unwrap(),
            nupkg_bytes.len().to_string(),
        );
        assert_eq!(
            response
                .headers()
                .get("Content-Disposition")
                .expect("Content-Disposition")
                .to_str()
                .unwrap(),
            format!("attachment; filename=\"{}\"", filename),
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        assert_eq!(&body_bytes[..], nupkg_bytes);

        cleanup().await;
    }
}

// ---------------------------------------------------------------------------
// DB-backed router tests for the `push_package` paths added in
// fix/nuget-push-trailing-slash-and-package-index:
//
//   1. The route is registered both with and without a trailing slash so
//      `dotnet nuget push` (which appends a slash to the PackagePublish URL)
//      hits the same handler. Each variant is exercised end-to-end.
//   2. After a successful push, the handler calls
//      `PackageService::try_create_or_update_from_artifact` so the package
//      surfaces in the UI Packages tab. The description is folded from an
//      empty `<description/>` in the nuspec to `Option::None` so the
//      `packages.description` column is NULL rather than the empty string.
//
// These tests rely on `DATABASE_URL` being set (CI seeds + migrates a
// Postgres before running `cargo llvm-cov --lib`). They no-op cleanly
// in environments without Postgres.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod push_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use std::io::Write;

    /// Build a minimal valid `.nupkg` (ZIP archive with a single `.nuspec`)
    /// using the given package id, version, and description. Mirrors the
    /// shape produced by `dotnet pack`. Authors is fixed since the new code
    /// path does not branch on it.
    fn build_nupkg(id: &str, version: &str, description: &str) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{}.nuspec", id), options).unwrap();
        let nuspec = format!(
            "<?xml version=\"1.0\"?>\n\
             <package>\n  <metadata>\n\
             <id>{}</id>\n\
             <version>{}</version>\n\
             <description>{}</description>\n\
             <authors>Test Author</authors>\n\
             </metadata>\n</package>",
            id, version, description
        );
        zip.write_all(nuspec.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();
        cursor.into_inner()
    }

    /// Send a PUT to `uri` carrying `nupkg_bytes` as a raw application/octet
    /// stream body (the raw-binary ingest branch, i.e. no multipart boundary).
    async fn put_nupkg(uri: String, nupkg_bytes: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(nupkg_bytes))
            .expect("build PUT request")
    }

    // -----------------------------------------------------------------------
    // Route registration: trailing slash and no trailing slash both
    // reach `push_package`. We confirm via end-to-end success (HTTP 201 or
    // similar 2xx) for each URL shape.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn push_package_route_accepts_no_trailing_slash() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("RouteNoSlashPkg", "1.0.0", "no-slash route");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for /api/v2/package, got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        // Verify the artifact landed in the DB.
        let exists: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM artifacts \
             WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("routenoslashpkg")
        .bind("1.0.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query artifact");
        assert!(exists.is_some(), "artifact row must exist after push");

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_package_route_accepts_trailing_slash() {
        // The bug this PR fixes: `dotnet nuget push` appends a trailing
        // slash to the PackagePublish/2.0.0 URL from the v3 index. Before
        // the fix, this returned 405/404. After the fix the route maps to
        // `push_package` and the push succeeds end-to-end.
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("RouteWithSlashPkg", "2.0.0", "trailing-slash route");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package/", f.repo_key), pkg).await;
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for /api/v2/package/ (with slash), got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let exists: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM artifacts \
             WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("routewithslashpkg")
        .bind("2.0.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query artifact");
        assert!(
            exists.is_some(),
            "trailing-slash push must create the artifact row"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Packages-index population: `try_create_or_update_from_artifact` runs
    // on every successful push and the description-folding branch must map
    // a non-empty `<description>` to `Some(...)` (persisted) and an empty
    // one to `None` (NULL column).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn push_package_populates_packages_index_with_description() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("IndexedPkg", "3.1.4", "an indexed package");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "push failed: {}", status);

        // The handler passes the original-case `nuspec.id` to
        // `PackageService::try_create_or_update_from_artifact`, so the
        // packages row is keyed by the original casing. (The artifacts row
        // uses the lowercased name from the duplicate-check path; the two
        // tables intentionally diverge for legacy reasons.)
        let row: Option<(String, String, Option<String>, Option<serde_json::Value>)> =
            sqlx::query_as(
                "SELECT name, version, description, metadata FROM packages \
                 WHERE repository_id = $1 AND name = $2",
            )
            .bind(f.repo_id)
            .bind("IndexedPkg")
            .fetch_optional(&f.pool)
            .await
            .expect("query packages");

        let (name, version, desc, meta) = row.expect("packages row must exist after push");
        assert_eq!(name, "IndexedPkg");
        assert_eq!(version, "3.1.4");
        assert_eq!(
            desc.as_deref(),
            Some("an indexed package"),
            "non-empty <description> must be persisted as Some(...)"
        );
        // The metadata JSON the handler passes is `{ "format": "nuget" }`.
        let meta = meta.expect("metadata must be set");
        assert_eq!(meta["format"], "nuget");

        // package_versions should be populated too (UPSERT in the service).
        let version_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind("IndexedPkg")
        .bind("3.1.4")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(
            version_count.0, 1,
            "exactly one package_versions row expected after a single push"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_multiple_versions_collapses_into_one_package_row() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let app = f.router_with_auth(super::router());

        let first = build_nupkg("MultiVersionPkg", "9.0.0", "first");
        let first_req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), first).await;
        let (first_status, _) = tdh::send(app.clone(), first_req).await;
        assert!(
            first_status.is_success(),
            "first push failed: {}",
            first_status
        );

        let second = build_nupkg("MultiVersionPkg", "10.0.0", "second");
        let second_req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), second).await;
        let (second_status, _) = tdh::send(app, second_req).await;
        assert!(
            second_status.is_success(),
            "second push failed: {}",
            second_status
        );

        let package_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM packages WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind("MultiVersionPkg")
        .fetch_one(&f.pool)
        .await
        .expect("query packages");
        assert_eq!(
            package_rows.0, 1,
            "multiple versions should collapse into a single packages row"
        );

        let package: (String,) =
            sqlx::query_as("SELECT version FROM packages WHERE repository_id = $1 AND name = $2")
                .bind(f.repo_id)
                .bind("MultiVersionPkg")
                .fetch_one(&f.pool)
                .await
                .expect("query package version");
        assert_eq!(package.0, "10.0.0");

        let version_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2",
        )
        .bind(f.repo_id)
        .bind("MultiVersionPkg")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(version_rows.0, 2, "both versions should remain addressable");

        f.teardown().await;
    }

    #[tokio::test]
    async fn push_package_packages_index_empty_description_maps_to_null() {
        // Covers the `if nuspec.description.is_empty() { None } else
        // { Some(...) }` branch added in this PR: an empty <description/>
        // must land as NULL in the packages table rather than an empty
        // string.
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        let pkg = build_nupkg("NoDescPkg", "0.1.0", "");
        let app = f.router_with_auth(super::router());
        let req = put_nupkg(format!("/{}/api/v2/package", f.repo_key), pkg).await;
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "push failed: {}", status);

        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT description FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("NoDescPkg")
        .bind("0.1.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (desc,) = row.expect("packages row must exist after push");
        assert!(
            desc.is_none(),
            "empty <description> must fold to NULL, got {:?}",
            desc
        );

        f.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// DB-backed read-endpoint regression tests (#1778).
//
// These cover the QA findings that the search/registration/flatcontainer read
// endpoints:
//   * hardcoded an empty `description` in search results,
//   * ignored the `prerelease` flag,
//   * returned 404 instead of federating across virtual-repo members.
//
// They no-op cleanly when `DATABASE_URL` is unset.
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test
// assertions is not an artifact path (#1608)
#[cfg(test)]
mod read_db_tests {
    // Bring the handler + the #2775 proxy/rewrite helpers into scope for the
    // remote pull-through tests below.
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use std::io::Write;
    use uuid::Uuid;

    /// Build a minimal valid `.nupkg` (ZIP with a single `.nuspec`).
    fn build_nupkg(id: &str, version: &str, description: &str) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{}.nuspec", id), options).unwrap();
        let nuspec = format!(
            "<?xml version=\"1.0\"?>\n\
             <package>\n  <metadata>\n\
             <id>{}</id>\n\
             <version>{}</version>\n\
             <description>{}</description>\n\
             <authors>Test Author</authors>\n\
             </metadata>\n</package>",
            id, version, description
        );
        zip.write_all(nuspec.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();
        cursor.into_inner()
    }

    /// Push a package into the repo identified by `repo_key` via the handler.
    async fn push_pkg(
        f: &tdh::Fixture,
        repo_key: &str,
        id: &str,
        version: &str,
        description: &str,
    ) {
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/api/v2/package", repo_key),
            bytes::Bytes::from(build_nupkg(id, version, description)),
        );
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "push of {}.{} failed: {} {:?}",
            id,
            version,
            status,
            String::from_utf8_lossy(&body)
        );
    }

    /// GET a NuGet read endpoint anonymously (read paths require no auth).
    async fn get_json(f: &tdh::Fixture, uri: String) -> (StatusCode, serde_json::Value) {
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(app, tdh::get(uri)).await;
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    // Finding: search always returned a hardcoded empty `description`.
    #[tokio::test]
    async fn search_returns_package_description() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        push_pkg(
            &f,
            &f.repo_key,
            "Qa.DescPkg",
            "1.0.0",
            "a documented package",
        )
        .await;

        let (status, json) = get_json(&f, format!("/{}/v3/search?q=qa.descpkg", f.repo_key)).await;
        assert_eq!(status, StatusCode::OK);
        let data = json["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1, "expected one hit; body={json}");
        assert_eq!(
            data[0]["description"], "a documented package",
            "search must surface the package description; body={json}"
        );

        f.teardown().await;
    }

    // Finding: the `prerelease` flag was parsed but ignored — search always
    // returned the highest version including pre-releases.
    #[tokio::test]
    async fn search_respects_prerelease_flag() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        push_pkg(&f, &f.repo_key, "Qa.PrerelPkg", "1.0.0", "stable").await;
        push_pkg(&f, &f.repo_key, "Qa.PrerelPkg", "2.0.0-beta.1", "beta").await;

        // prerelease=false → the stable 1.0.0 must win.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/search?q=qa.prerelpkg&prerelease=false", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["data"][0]["version"], "1.0.0",
            "prerelease=false must surface the stable version; body={json}"
        );

        // prerelease=true → the higher pre-release wins.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/search?q=qa.prerelpkg&prerelease=true", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["data"][0]["version"], "2.0.0-beta.1",
            "prerelease=true must surface the pre-release; body={json}"
        );

        f.teardown().await;
    }

    /// Create a virtual repo and link `member_id` as its sole member.
    async fn create_virtual_with_member(pool: &sqlx::PgPool, member_id: Uuid) -> (Uuid, String) {
        let (vid, vkey, _dir) = tdh::create_repo(pool, "virtual", "nuget").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(vid)
        .bind(member_id)
        .execute(pool)
        .await
        .expect("link virtual member");
        (vid, vkey)
    }

    async fn drop_virtual(pool: &sqlx::PgPool, vid: Uuid) {
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(vid)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(vid)
            .execute(pool)
            .await;
    }

    // Findings: registration/index, flatcontainer/index, and search all
    // returned 404 / empty instead of federating across virtual members.
    #[tokio::test]
    async fn virtual_repo_federates_read_endpoints_over_local_member() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        // Seed a package into the local member.
        push_pkg(&f, &f.repo_key, "Qa.FedPkg", "1.0.0", "federated package").await;

        let (vid, vkey) = create_virtual_with_member(&f.pool, f.repo_id).await;

        // registration/index must federate to the member and return 200.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/registration/qa.fedpkg/index.json", vkey),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "virtual registration must federate; body={json}"
        );
        let items = json["items"][0]["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["catalogEntry"]["version"], "1.0.0");

        // flatcontainer/index must federate to the member and return 200.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/flatcontainer/qa.fedpkg/index.json", vkey),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "virtual flatcontainer must federate; body={json}"
        );
        assert_eq!(json["versions"][0], "1.0.0");

        // search must federate to the member and return the hit.
        let (status, json) = get_json(&f, format!("/{}/v3/search?q=qa.fed", vkey)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["totalHits"], 1,
            "virtual search must federate over members; body={json}"
        );
        assert_eq!(json["data"][0]["id"], "qa.fedpkg");

        drop_virtual(&f.pool, vid).await;
        f.teardown().await;
    }

    // Finding (#2656): the registration leaf `@id` advertised
    // `/v3/registration/{id}/{version}.json`, a route the server never
    // registers, so a NuGet client that dereferences the leaf `@id` got a 404.
    // This test derives the request path FROM the emitted `@id` (not a
    // hard-coded literal) and asserts it resolves to a real served route.
    // Pre-fix the derived path is `.../{version}.json` → 404; post-fix it is
    // `.../index.json#{version}` (fragment stripped by the client) → 200.
    #[tokio::test]
    async fn registration_leaf_id_resolves_to_a_served_route() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };
        push_pkg(&f, &f.repo_key, "Qa.LeafPkg", "1.0.0", "leaf id package").await;

        // Fetch the registration index and pull out the inlined leaf `@id`.
        let (status, json) = get_json(
            &f,
            format!("/{}/v3/registration/qa.leafpkg/index.json", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "registration index; body={json}");
        let leaf_id = json["items"][0]["items"][0]["@id"]
            .as_str()
            .expect("registration leaf @id")
            .to_string();

        // Turn the advertised absolute `@id` into a request path for the
        // handler router. `base` is `{base_url}/nuget/{repo_key}`; the test
        // router is mounted without the `/nuget` nest, and a client drops the
        // `#fragment` before issuing the GET.
        let from_nuget = &leaf_id[leaf_id
            .find("/nuget/")
            .expect("@id must be built off the /nuget base path")..];
        let path_no_fragment = from_nuget.split('#').next().unwrap();
        let served_path = path_no_fragment
            .strip_prefix("/nuget")
            .expect("path under /nuget")
            .to_string();

        // A GET against the exact advertised leaf path must be a real route.
        let (leaf_status, leaf_json) = get_json(&f, served_path.clone()).await;
        assert_eq!(
            leaf_status,
            StatusCode::OK,
            "leaf @id {leaf_id} must dereference to a served route (got {leaf_status} for {served_path}); body={leaf_json}"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #2775 — remote pull-through proxying (V3 discovery + V2 OData)
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_service_index_url_normalizes() {
        assert_eq!(
            nuget_service_index_url("https://api.nuget.org/v3/index.json"),
            "https://api.nuget.org/v3/index.json"
        );
        assert_eq!(
            nuget_service_index_url("https://api.nuget.org/v3/index.json/"),
            "https://api.nuget.org/v3/index.json"
        );
        assert_eq!(
            nuget_service_index_url("https://api.nuget.org/v3"),
            "https://api.nuget.org/v3/index.json"
        );
    }

    #[test]
    fn test_parse_upstream_resources_picks_registration_and_package_bases() {
        // Real nuget.org advertises the bases at non-trivial paths under
        // versioned @types — a hard-coded `v3/flatcontainer` path never resolves.
        let index = serde_json::json!({
            "version": "3.0.0",
            "resources": [
                {"@id": "https://azuresearch-usnc.nuget.org/query", "@type": "SearchQueryService"},
                {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"},
                {"@id": "https://api.nuget.org/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"}
            ]
        });
        let r = parse_upstream_resources(&index);
        assert_eq!(
            r.registration_base.as_deref(),
            Some("https://api.nuget.org/v3/registration5-gz-semver2")
        );
        assert_eq!(
            r.package_base.as_deref(),
            Some("https://api.nuget.org/v3-flatcontainer")
        );
    }

    // #2925 — upstream credentials must stay pinned to the configured upstream
    // host. A discovered service-index resource base that names a foreign host
    // is refused by `guard_upstream_base`, so the repo's configured upstream
    // credentials are never sent to a host the service index chose.
    #[test]
    fn test_same_upstream_origin_matches_same_host() {
        // nuget.org: index.json and the discovered bases share host `api.nuget.org`.
        assert!(same_upstream_origin(
            "https://api.nuget.org/v3/index.json",
            "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json",
        ));
        // Host comparison is case-insensitive.
        assert!(same_upstream_origin(
            "https://API.NuGet.org/v3/index.json",
            "https://api.nuget.org/v3-flatcontainer/",
        ));
    }

    #[test]
    fn test_same_upstream_origin_rejects_foreign_host_and_downgrade() {
        // Foreign host named by a hostile service index → not the same origin.
        assert!(!same_upstream_origin(
            "https://api.nuget.org/v3/index.json",
            "https://attacker.example/v3-flatcontainer/",
        ));
        // Same registrable domain but different host is still a different origin.
        assert!(!same_upstream_origin(
            "https://api.nuget.org/v3/index.json",
            "https://evil.nuget.org.attacker.example/reg/",
        ));
        // http downgrade to the same host is rejected (443 != 80).
        assert!(!same_upstream_origin(
            "https://api.nuget.org/v3/index.json",
            "http://api.nuget.org/v3-flatcontainer/",
        ));
        // Different explicit port is a different origin.
        assert!(!same_upstream_origin(
            "https://api.nuget.org/v3/index.json",
            "https://api.nuget.org:8443/v3-flatcontainer/",
        ));
    }

    #[test]
    fn test_guard_upstream_base_refuses_offhost_resource() {
        // A service index that points the flat-container base at an attacker
        // host is refused before any credentialed fetch is issued.
        let upstream = "https://api.nuget.org/v3/index.json";
        let foreign = Some("https://attacker.example/flat".to_string());
        let err = guard_upstream_base(foreign.as_ref(), upstream, "PackageBaseAddress")
            .expect_err("off-host base must be refused");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_guard_upstream_base_accepts_same_host_resource() {
        // The legitimate same-host base is accepted and returned unchanged.
        let upstream = "https://api.nuget.org/v3/index.json";
        let same = Some("https://api.nuget.org/v3-flatcontainer".to_string());
        let base = guard_upstream_base(same.as_ref(), upstream, "PackageBaseAddress")
            .expect("same-host base must be accepted");
        assert_eq!(base, "https://api.nuget.org/v3-flatcontainer");
    }

    #[test]
    fn test_rewrite_v3_registration_points_urls_at_proxy() {
        let resources = NugetUpstreamResources {
            registration_base: Some(
                "https://api.nuget.org/v3/registration5-gz-semver2".to_string(),
            ),
            package_base: Some("https://api.nuget.org/v3-flatcontainer".to_string()),
            search_base: None,
        };
        let upstream_doc = r#"{
            "@id":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json",
            "packageContent":"https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        }"#;
        let out = rewrite_v3_registration(upstream_doc, &resources, "https://ak.example", "myfeed");
        assert!(
            out.contains(
                "https://ak.example/nuget/myfeed/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
            ),
            "packageContent must be rewritten to the AK proxy: {out}"
        );
        assert!(out.contains(
            "https://ak.example/nuget/myfeed/v3/registration/newtonsoft.json/index.json"
        ));
        assert!(
            !out.contains("api.nuget.org"),
            "no upstream host may remain in the rewritten document: {out}"
        );
    }

    #[test]
    fn test_odata_arg_parsing() {
        assert_eq!(
            odata_string_arg("id='Newtonsoft.Json'", "id").as_deref(),
            Some("Newtonsoft.Json")
        );
        let (id, ver) = parse_packages_key("Packages(Id='cake',Version='2.0.0')");
        assert_eq!(id.as_deref(), Some("cake"));
        assert_eq!(ver.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn test_rewrite_v2_odata_rebinds_feed_base_to_proxy() {
        let body = r#"<feed xml:base="https://community.chocolatey.org/api/v2/"><entry><id>https://community.chocolatey.org/api/v2/Packages(Id='git',Version='2.0')</id><content type="application/zip" src="https://community.chocolatey.org/api/v2/package/git/2.0"/></entry></feed>"#;
        let out = rewrite_v2_odata(
            body,
            "https://community.chocolatey.org/api/v2/",
            "https://ak.example/nuget/choco/v2",
        );
        assert!(
            out.contains(r#"src="https://ak.example/nuget/choco/v2/package/git/2.0""#),
            "download link must be rewritten to the AK proxy: {out}"
        );
        assert!(
            !out.contains("community.chocolatey.org"),
            "no upstream host may remain: {out}"
        );
    }

    #[test]
    fn test_build_v2_feed_download_links_point_at_proxy() {
        let entries = vec![V2Entry {
            id: "Cake".to_string(),
            version: "2.0.0".to_string(),
            authors: "Cake".to_string(),
            description: "desc".to_string(),
            hash_sha256_b64: Some("abc==".to_string()),
            size: 42,
        }];
        let feed = build_v2_feed("https://ak.example/nuget/choco/v2", &entries);
        assert!(
            feed.contains(r#"src="https://ak.example/nuget/choco/v2/package/Cake/2.0.0""#),
            "{feed}"
        );
        assert!(feed.contains("<d:Version>2.0.0</d:Version>"));
    }

    // Mount an upstream V3 service index at `/v3/index.json` advertising the
    // registration/flat bases under `/reg/` and `/flat/` on the mock server,
    // plus (optionally) a `SearchQueryService` at `search_base` — which may be
    // on a different origin, as nuget.org's azuresearch-* is (#3130).
    async fn mount_v3_index_with(upstream: &wiremock::MockServer, search_base: Option<&str>) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let mut resources = vec![
            serde_json::json!({"@id": format!("{}/reg/", upstream.uri()), "@type": "RegistrationsBaseUrl"}),
            serde_json::json!({"@id": format!("{}/flat/", upstream.uri()), "@type": "PackageBaseAddress/3.0.0"}),
        ];
        if let Some(search) = search_base {
            resources
                .push(serde_json::json!({"@id": search, "@type": "SearchQueryService/3.0.0-rc"}));
        }
        let index = serde_json::json!({"version": "3.0.0", "resources": resources});
        Mock::given(method("GET"))
            .and(path("/v3/index.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(serde_json::to_string(&index).unwrap()),
            )
            .mount(upstream)
            .await;
    }

    async fn mount_v3_index(upstream: &wiremock::MockServer) {
        mount_v3_index_with(upstream, None).await;
    }

    /// Mount a `/query` search endpoint returning one upstream-hosted result.
    async fn mount_search_endpoint(server: &wiremock::MockServer, reg_base: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let payload = serde_json::json!({
            "totalHits": 1,
            "data": [{
                "id": "Newtonsoft.Json",
                "version": "13.0.1",
                "registration": format!("{}/newtonsoft.json/index.json", reg_base)
            }]
        });
        Mock::given(method("GET"))
            .and(path("/query"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(serde_json::to_string(&payload).unwrap()),
            )
            .mount(server)
            .await;
    }

    /// Configure bearer upstream credentials + `upstream_url` on the fixture
    /// repo, run a `q=newtonsoft` search through the real handler, and return
    /// the parsed response JSON.
    async fn run_search_against(
        fx: &tdh::Fixture,
        index_host: &wiremock::MockServer,
    ) -> serde_json::Value {
        let creds = crate::services::upstream_auth::build_credentials_json(
            &crate::services::upstream_auth::UpstreamAuthType::Bearer {
                token: "sekret-token".to_string(),
            },
        );
        crate::services::upstream_auth::save_upstream_auth(&fx.pool, fx.repo_id, "bearer", &creds)
            .await
            .expect("save upstream auth");
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", index_host.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::search_packages(
            axum::extract::State(state),
            axum::extract::Path(fx.repo_key.clone()),
            axum::extract::Query(SearchQuery {
                q: Some("newtonsoft".to_string()),
                skip: None,
                take: None,
                prerelease: None,
            }),
            crate::api::extractors::RequestBaseUrl("https://ak.example".to_string()),
        )
        .await
        .expect("remote search must succeed");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&body).expect("search response is JSON")
    }

    /// Same-origin `SearchQueryService`: the search fetch must carry the
    /// repo's configured upstream credentials, exactly like every other
    /// same-origin discovered-resource fetch (#3130).
    #[tokio::test]
    async fn test_remote_v3_search_same_origin_fetches_with_credentials() {
        use wiremock::MockServer;
        // `save_upstream_auth` encrypts via `encryption_key()`; skip when no
        // key env is configured (same guard as the upstream_auth DB tests).
        if std::env::var("JWT_SECRET").is_err() && std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            return;
        }
        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;
        let search_base = format!("{}/query", upstream.uri());
        mount_v3_index_with(&upstream, Some(&search_base)).await;
        mount_search_endpoint(&upstream, &format!("{}/reg", upstream.uri())).await;

        let json = run_search_against(&fx, &upstream).await;

        let reqs = upstream.received_requests().await.expect("recorded");
        let auth = reqs
            .iter()
            .find(|r| r.url.path() == "/query")
            .expect("upstream search endpoint must be queried")
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        fx.teardown().await;

        assert_eq!(json["data"][0]["id"], "Newtonsoft.Json");
        assert_eq!(
            auth.as_deref(),
            Some("Bearer sekret-token"),
            "a same-origin search fetch must carry the configured upstream credentials"
        );
    }

    /// Off-origin `SearchQueryService` (the nuget.org azuresearch shape): the
    /// search is ALLOWED and served, but the actual outbound request to the
    /// off-origin host must carry NO Authorization header — while the
    /// same-origin index fetch in the same flow proves the credentials were
    /// configured and applied where permitted (#3130 / #2925).
    #[tokio::test]
    async fn test_remote_v3_search_off_origin_is_served_but_anonymous() {
        use wiremock::MockServer;
        if std::env::var("JWT_SECRET").is_err() && std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            return;
        }
        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        // Two servers on different ports = different origins.
        let index_host = MockServer::start().await;
        let search_host = MockServer::start().await;
        mount_v3_index_with(&index_host, Some(&format!("{}/query", search_host.uri()))).await;
        mount_search_endpoint(&search_host, &format!("{}/reg", index_host.uri())).await;

        let json = run_search_against(&fx, &index_host).await;

        let index_reqs = index_host.received_requests().await.expect("recorded");
        let index_fetch_credentialed = index_reqs
            .iter()
            .find(|r| r.url.path() == "/v3/index.json")
            .expect("service index must be fetched")
            .headers
            .get("authorization")
            .is_some();
        let search_reqs = search_host.received_requests().await.expect("recorded");
        let search_req = search_reqs
            .iter()
            .find(|r| r.url.path() == "/query")
            .expect("off-origin search host must be queried")
            .clone();
        let search_auth_header = search_req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let q_forwarded = search_req
            .url
            .query_pairs()
            .any(|(k, v)| k == "q" && v == "newtonsoft");
        fx.teardown().await;

        assert!(
            index_fetch_credentialed,
            "control: the same-origin index fetch must carry the configured credentials, \
             proving they exist and are applied where permitted"
        );
        assert_eq!(
            search_auth_header, None,
            "the outbound off-origin search request must carry NO Authorization header"
        );
        assert!(q_forwarded, "client query must be forwarded upstream");
        assert_eq!(
            json["data"][0]["id"], "Newtonsoft.Json",
            "off-origin upstream search results are served to the client"
        );
    }

    #[tokio::test]
    async fn test_remote_v3_registration_discovers_and_rewrites_urls() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;
        mount_v3_index(&upstream).await;

        let reg_doc = serde_json::json!({
            "@id": format!("{}/reg/newtonsoft.json/index.json", upstream.uri()),
            "count": 1,
            "items": [{
                "catalogEntry": {
                    "id": "newtonsoft.json",
                    "version": "13.0.1",
                    "packageContent": format!("{}/flat/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg", upstream.uri())
                }
            }]
        });
        Mock::given(method("GET"))
            .and(path("/reg/newtonsoft.json/index.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(serde_json::to_string(&reg_doc).unwrap()),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", upstream.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::registration_index(
            axum::extract::State(state.clone()),
            axum::extract::Path((fx.repo_key.clone(), "Newtonsoft.Json".to_string())),
            crate::api::extractors::RequestBaseUrl("https://ak.example".to_string()),
        )
        .await;

        let resp = match resp {
            Ok(r) => r,
            Err(r) => {
                let s = r.status();
                fx.teardown().await;
                panic!("remote registration proxy must succeed, got {s}");
            }
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&body).to_string();
        let up_uri = upstream.uri();
        fx.teardown().await;

        // The repo key is random per fixture, so match on the stable AK host +
        // flatcontainer path suffix rather than a literal key.
        assert!(
            text.contains("https://ak.example/nuget/")
                && text.contains("/v3/flatcontainer/newtonsoft.json/13.0.1/"),
            "packageContent must be rewritten to the AK flatcontainer route: {text}"
        );
        assert!(
            !text.contains(&up_uri),
            "no upstream URL may leak to the client: {text}"
        );
    }

    #[tokio::test]
    async fn test_remote_v3_flatcontainer_versions_discovered() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;
        mount_v3_index(&upstream).await;

        Mock::given(method("GET"))
            .and(path("/flat/newtonsoft.json/index.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(r#"{"versions":["12.0.3","13.0.1"]}"#),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", upstream.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::flatcontainer_versions(
            axum::extract::State(state.clone()),
            axum::extract::Path((fx.repo_key.clone(), "Newtonsoft.Json".to_string())),
        )
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(r) => {
                let s = r.status();
                fx.teardown().await;
                panic!("remote flatcontainer version list must succeed, got {s}");
            }
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&body).to_string();
        fx.teardown().await;
        assert!(
            text.contains("13.0.1"),
            "version list must be proxied: {text}"
        );
    }

    #[tokio::test]
    async fn test_remote_v3_flatcontainer_download_streams() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;
        mount_v3_index(&upstream).await;

        let nupkg = b"PK\x03\x04-mock-nupkg-bytes";
        Mock::given(method("GET"))
            .and(path(
                "/flat/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(nupkg.as_ref()),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", upstream.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::flatcontainer_download(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                "newtonsoft.json".to_string(),
                "13.0.1".to_string(),
                "newtonsoft.json.13.0.1.nupkg".to_string(),
            )),
            Default::default(),
        )
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(r) => {
                let s = r.status();
                fx.teardown().await;
                panic!("remote flatcontainer download must succeed, got {s}");
            }
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        fx.teardown().await;
        assert_eq!(
            &body[..],
            nupkg.as_ref(),
            "streamed .nupkg must match upstream"
        );
    }

    // -----------------------------------------------------------------------
    // Missing-blob repair on the Remote arm
    //
    // `flatcontainer_download` reaches this branch only when a Remote repo has an
    // `artifacts` row for the package (a pre-#1278 proxy-cache row, a hydrated /
    // replicated copy, or a package published into the remote) while the object
    // itself is gone from storage. The row means the primary cache-miss arm above
    // is never entered, so this path needs its own coverage: it used to buffer the
    // re-pull at the 8 MiB metadata ceiling AND build the upstream URL by
    // concatenating `v3/flatcontainer/...` onto `upstream_url`, bypassing the
    // service-index discovery (#2775) that resolves the real `PackageBaseAddress`.
    // -----------------------------------------------------------------------

    /// Insert an `artifacts` row WITHOUT writing its blob — the "row exists but
    /// the object is missing from storage" state the Remote arm self-heals.
    /// `tdh::seed_artifact` cannot be used here: it puts the object, which turns
    /// every request into a warm cache hit and skips the repair branch entirely
    /// (exactly the gap the renamed warm-hit test used to hide).
    async fn seed_row_without_blob(
        fx: &tdh::Fixture,
        name: &str,
        version: &str,
        filename: &str,
        size_bytes: i64,
    ) -> Uuid {
        // Not a bare 64-hex SHA-256, so `normalize_expected_sha256` reads it as
        // "no enforceable digest" and the repair takes the UNVERIFIED streaming
        // route — which is what the two tests using this seed are about.
        seed_row_without_blob_with_checksum(
            fx,
            name,
            version,
            filename,
            size_bytes,
            "test-seed-missing-blob",
        )
        .await
    }

    /// As [`seed_row_without_blob`], but pins the row's `checksum_sha256`.
    ///
    /// A bare lowercase 64-hex value here is what routes the repair through the
    /// digest-verified buffered path (#2929).
    async fn seed_row_without_blob_with_checksum(
        fx: &tdh::Fixture,
        name: &str,
        version: &str,
        filename: &str,
        size_bytes: i64,
        checksum_sha256: &str,
    ) -> Uuid {
        let artifact_path = format!("v3/flatcontainer/{}/{}/{}", name, version, filename);
        let storage_key = format!("nuget/{}/{}/{}", name, version, filename);
        proxy_helpers::insert_artifact(
            &fx.pool,
            proxy_helpers::NewArtifact {
                repository_id: fx.repo_id,
                path: &artifact_path,
                name,
                version,
                size_bytes,
                checksum_sha256,
                content_type: "application/octet-stream",
                storage_key: &storage_key,
                uploaded_by: fx.user_id,
            },
        )
        .await
        .expect("insert artifacts row without blob")
    }

    /// Drive `flatcontainer_download` against an upstream that serves
    /// `upstream_body`, for a row seeded with `row_checksum` and no blob.
    ///
    /// Returns `(result, upstream_request_paths)`. The caller asserts; teardown
    /// happens here so a failing assertion never leaks fixture rows.
    async fn run_repair_with_row_checksum(
        package_id: &str,
        version: &str,
        upstream_body: &[u8],
        row_checksum: &str,
        calls: usize,
    ) -> Option<(Vec<Result<(StatusCode, Vec<u8>), StatusCode>>, Vec<String>)> {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let fx = tdh::Fixture::setup("remote", "nuget").await?;
        let upstream = MockServer::start().await;
        mount_v3_index(&upstream).await;

        let filename = format!("{}.{}.nupkg", package_id, version);
        let discovered_path = format!("/flat/{}/{}/{}", package_id, version, filename);
        Mock::given(method("GET"))
            .and(path(discovered_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(upstream_body.to_vec()),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", upstream.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        seed_row_without_blob_with_checksum(
            &fx,
            package_id,
            version,
            &filename,
            upstream_body.len() as i64,
            row_checksum,
        )
        .await;

        let mut outcomes = Vec::new();
        for _ in 0..calls {
            let resp = super::flatcontainer_download(
                axum::extract::State(state.clone()),
                axum::extract::Path((
                    fx.repo_key.clone(),
                    package_id.to_string(),
                    version.to_string(),
                    filename.clone(),
                )),
                Default::default(),
            )
            .await;
            outcomes.push(match resp {
                Ok(r) => {
                    let status = r.status();
                    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
                    Ok((status, body.to_vec()))
                }
                Err(r) => Err(r.status()),
            });
        }

        let requested: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        fx.teardown().await;
        Some((outcomes, requested))
    }

    /// #2929: a repaired `.nupkg` whose bytes match the row's recorded
    /// `checksum_sha256` is served, and the write-back makes the next request a
    /// local hit rather than a second upstream pull.
    ///
    /// The companion to the mismatch test below: without this one, "refuse every
    /// repair" would also satisfy that assertion.
    #[tokio::test]
    async fn test_flatcontainer_repair_serves_a_body_matching_the_rows_digest_2929() {
        let body = b"PK\x03\x04-repaired-and-verified-nupkg-bytes".repeat(8);
        let digest = crate::services::storage_service::StorageService::calculate_hash(&body);

        let Some((outcomes, requested)) =
            run_repair_with_row_checksum("verified.package", "1.0.0", &body, &digest, 2).await
        else {
            return;
        };

        let (status, served) = match &outcomes[0] {
            Ok(v) => v.clone(),
            Err(status) => panic!("a digest-matching repair must succeed, got {status}"),
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            &served[..],
            &body[..],
            "the verified repair must serve the upstream bytes in full"
        );

        match &outcomes[1] {
            Ok((status, served)) => {
                assert_eq!(*status, StatusCode::OK, "the warm read must succeed");
                assert_eq!(&served[..], &body[..], "the warm read must be identical");
            }
            Err(status) => panic!("the warm read must succeed, got {status}"),
        }

        let pulls = requested.iter().filter(|p| p.starts_with("/flat/")).count();
        assert_eq!(
            pulls, 1,
            "a verified repair must write back, so the second request is a local \
             hit; upstream saw {requested:?}"
        );
    }

    /// #2929 — the load-bearing one. VERIFY THEN SERVE.
    ///
    /// `check_artifact_download` authorises on the artifact row, so the hash an
    /// admin reviewed when releasing that row from quarantine has to be the hash
    /// the client actually receives. The repair re-pulls from upstream and writes
    /// back under the row's own storage key; if those bytes are never compared to
    /// the row's `checksum_sha256`, the quarantine decision was made about a blob
    /// nobody ever delivered.
    ///
    /// So a mismatching body must reach the client NOT AT ALL — not "truncated
    /// after the mismatch was noticed", which is why this path buffers instead of
    /// streaming. And it must not be written back: the second call below must
    /// fail exactly like the first, proving the bad body did not become a warm
    /// entry that later requests are served from.
    #[tokio::test]
    async fn test_flatcontainer_repair_refuses_a_body_failing_the_rows_digest_2929() {
        let body = b"PK\x03\x04-bytes-that-are-not-what-the-row-records".repeat(8);
        // Well-formed so it is actually enforced rather than being discarded as
        // "no digest available" by `normalize_expected_sha256`.
        let wrong = "b".repeat(64);
        assert_ne!(
            wrong,
            crate::services::storage_service::StorageService::calculate_hash(&body),
            "fixture digest must differ or the test proves nothing"
        );

        let Some((outcomes, requested)) =
            run_repair_with_row_checksum("forged.package", "2.0.0", &body, &wrong, 2).await
        else {
            return;
        };

        for (i, outcome) in outcomes.iter().enumerate() {
            match outcome {
                Err(status) => assert_eq!(
                    *status,
                    StatusCode::BAD_GATEWAY,
                    "call {i}: a digest mismatch must fail the repair explicitly"
                ),
                Ok((status, served)) => panic!(
                    "call {i}: a body failing the row's recorded digest must never be \
                     served (#2929); got {status} with {} bytes",
                    served.len()
                ),
            }
        }

        assert!(
            requested.iter().any(|p| p.starts_with("/flat/")),
            "the repair must actually have pulled upstream, or the refusal is \
             vacuous; upstream saw {requested:?}"
        );
    }

    /// The repair must re-pull through the **discovered** `PackageBaseAddress`,
    /// not a naive `{upstream_url}/v3/flatcontainer/...` concatenation.
    ///
    /// The upstream mock matches the discovered path with `.expect(1)`, and the
    /// test additionally inspects every request the upstream received: the outcome
    /// alone cannot distinguish the fix, because the pre-fix code fetched
    /// `{upstream}/v3/index.json/v3/flatcontainer/{id}/{version}/{file}` — which
    /// 404s against a real feed (nuget.org serves package content from
    /// `https://api.nuget.org/v3-flatcontainer/`), making the repair path broken
    /// on nuget.org regardless of package size.
    #[tokio::test]
    async fn test_flatcontainer_download_repairs_missing_blob_via_discovered_package_base() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;
        mount_v3_index(&upstream).await;

        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let nupkg = b"PK\x03\x04-repaired-nupkg-bytes";
        // The service index mounted above advertises `{upstream}/flat/` as the
        // PackageBaseAddress, so this is the only path a discovering client asks
        // for. Nothing is mounted for `v3/flatcontainer/...`.
        let discovered_path = format!("/flat/{}/{}/{}", package_id, version, filename);

        Mock::given(method("GET"))
            .and(path(discovered_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(nupkg.as_ref()),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(format!("{}/v3/index.json", upstream.uri()))
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        seed_row_without_blob(&fx, package_id, version, &filename, nupkg.len() as i64).await;

        let resp = super::flatcontainer_download(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                package_id.to_string(),
                version.to_string(),
                filename.clone(),
            )),
            Default::default(),
        )
        .await;

        // Collect everything before tearing down, and assert afterwards, so a
        // failure never leaves fixture rows or the storage dir behind.
        let outcome = match resp {
            Ok(r) => {
                let status = r.status();
                let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
                Ok((status, body))
            }
            Err(r) => Err(r.status()),
        };
        let requested: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        fx.teardown().await;

        assert!(
            requested.contains(&discovered_path),
            "repair must fetch the discovered PackageBaseAddress path \
             ({discovered_path}); upstream saw {requested:?}"
        );
        assert!(
            !requested.iter().any(|p| p.contains("v3/flatcontainer")),
            "repair must not concatenate `v3/flatcontainer/...` onto upstream_url; \
             upstream saw {requested:?}"
        );
        let (status, body) = match outcome {
            Ok(v) => v,
            Err(status) => panic!("missing-blob repair must succeed, got {status}"),
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            &body[..],
            nupkg.as_ref(),
            "repaired .nupkg must match upstream byte for byte"
        );
    }

    /// A repaired body larger than the buffered metadata ceiling
    /// (`DEFAULT_METADATA_MAX_BYTES`, 8 MiB) must be served in full. The old
    /// repair used `proxy_fetch_capped`, which does not truncate — it 502s as soon
    /// as the body would exceed the cap — so the repair failed outright for every
    /// package that legitimately exceeds it (`Microsoft.CodeAnalysis.*`,
    /// `Microsoft.ML.*`, `SkiaSharp.NativeAssets.*`, native-runtime packages).
    ///
    /// The body is non-uniform so a truncated or otherwise mangled stream cannot
    /// pass the byte-equality assertion by accident.
    #[tokio::test]
    async fn test_flatcontainer_download_repair_streams_body_above_metadata_cap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "nuget").await else {
            return;
        };
        let upstream = MockServer::start().await;

        let package_id = "microsoft.codeanalysis.csharp";
        let version = "4.9.2";
        let filename = format!("{}.{}.nupkg", package_id, version);

        // 9 MiB > the 8 MiB buffered-metadata ceiling, with a non-repeating byte
        // pattern so truncation at any offset is detectable.
        let big: Vec<u8> = (0..9 * 1024 * 1024usize).map(|i| (i % 251) as u8).collect();
        assert!(big.len() > proxy_helpers::DEFAULT_METADATA_MAX_BYTES);

        // This fixture deliberately isolates the *cap* defect from the *URL*
        // defect, which would otherwise mask it. `mount_v3_index` advertises the
        // base at `/flat/` while `upstream_url` is the service-index document, so
        // the pre-fix concatenation produced an unmounted
        // `/v3/index.json/v3/flatcontainer/...` and the request 404'd before a
        // single byte was buffered — passing for the wrong reason.
        //
        // Here `upstream_url` is the bare base and the advertised
        // PackageBaseAddress is `{upstream}/v3/flatcontainer/`, so the naive
        // concatenation and the discovered address resolve to the *same* URL.
        // Both the old and new code therefore reach the body, and the only thing
        // that can fail is the 8 MiB ceiling. This is the shape a bare-base or
        // AK-to-AK remote actually has (see the service index built at
        // `nuget::service_index`), so it is a real configuration, not a contrivance.
        let index = serde_json::json!({
            "version": "3.0.0",
            "resources": [
                {
                    "@id": format!("{}/v3/flatcontainer/", upstream.uri()),
                    "@type": "PackageBaseAddress/3.0.0"
                }
            ]
        });
        // `nuget_service_index_url` trims the trailing slash and appends
        // `index.json`, so a bare base is discovered at `/index.json` — not
        // `/v3/index.json`, which is where a service-index-document upstream
        // would be.
        Mock::given(method("GET"))
            .and(path("/index.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(serde_json::to_string(&index).unwrap()),
            )
            .mount(&upstream)
            .await;

        let discovered_path = format!("/v3/flatcontainer/{}/{}/{}", package_id, version, filename);
        Mock::given(method("GET"))
            .and(path(discovered_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(big.clone()),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        // Bare base, not the service-index document — see the note above.
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        seed_row_without_blob(&fx, package_id, version, &filename, big.len() as i64).await;

        let resp = super::flatcontainer_download(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                package_id.to_string(),
                version.to_string(),
                filename.clone(),
            )),
            Default::default(),
        )
        .await;

        let outcome = match resp {
            Ok(r) => {
                let status = r.status();
                let body = to_bytes(r.into_body(), 32 << 20).await.unwrap();
                Ok((status, body))
            }
            Err(r) => Err(r.status()),
        };
        let requested: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        fx.teardown().await;

        let (status, body) = match outcome {
            Ok(v) => v,
            Err(status) => panic!(
                "repair of a {} byte .nupkg must not be capped, got {status}; \
                 upstream saw {requested:?}",
                big.len()
            ),
        };
        // The point of the fixture: the body path really was requested, so a
        // failure above is the cap and not a misrouted URL.
        assert!(
            requested.iter().any(|p| p == &discovered_path),
            "upstream must have been asked for {discovered_path}; saw {requested:?}"
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body.len(),
            big.len(),
            "repaired .nupkg above the metadata cap must be served in full"
        );
        assert_eq!(
            &body[..],
            &big[..],
            "repaired .nupkg must be byte-identical"
        );
    }

    #[tokio::test]
    async fn test_remote_v2_find_packages_by_id_proxies_and_rewrites() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "chocolatey").await else {
            return;
        };
        let upstream = MockServer::start().await;

        let feed = format!(
            r#"<feed xml:base="{up}/"><entry><id>{up}/Packages(Id='git',Version='2.0')</id><content type="application/zip" src="{up}/package/git/2.0"/></entry></feed>"#,
            up = upstream.uri()
        );
        Mock::given(method("GET"))
            .and(path("/FindPackagesById()"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/atom+xml")
                    .set_body_string(feed),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::v2_odata(
            axum::extract::State(state.clone()),
            axum::extract::Path((fx.repo_key.clone(), "FindPackagesById()".to_string())),
            axum::extract::RawQuery(Some("id='git'".to_string())),
            crate::api::extractors::RequestBaseUrl("https://ak.example".to_string()),
            Default::default(),
        )
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(r) => {
                let s = r.status();
                fx.teardown().await;
                panic!("remote V2 FindPackagesById must succeed, got {s}");
            }
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&body).to_string();
        let up_uri = upstream.uri();
        fx.teardown().await;
        assert!(
            text.contains("/v2/package/git/2.0"),
            "content src must be rewritten to the AK V2 route: {text}"
        );
        assert!(
            text.contains("https://ak.example/nuget/"),
            "rewritten URLs must be AK-hosted: {text}"
        );
        assert!(
            !text.contains(&up_uri),
            "no upstream URL may leak to the choco client: {text}"
        );
    }

    #[tokio::test]
    async fn test_remote_v2_package_download_streams() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "chocolatey").await else {
            return;
        };
        let upstream = MockServer::start().await;
        let nupkg = b"PK\x03\x04-choco-nupkg";
        Mock::given(method("GET"))
            .and(path("/package/git/2.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(nupkg.as_ref()),
            )
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state = tdh::build_state_with_proxy(fx.pool.clone(), &storage_path, proxy);

        let resp = super::v2_odata(
            axum::extract::State(state.clone()),
            axum::extract::Path((fx.repo_key.clone(), "package/git/2.0".to_string())),
            axum::extract::RawQuery(None),
            crate::api::extractors::RequestBaseUrl("https://ak.example".to_string()),
            Default::default(),
        )
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(r) => {
                let s = r.status();
                fx.teardown().await;
                panic!("remote V2 package download must succeed, got {s}");
            }
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        fx.teardown().await;
        assert_eq!(
            &body[..],
            nupkg.as_ref(),
            "streamed choco .nupkg must match upstream"
        );
    }

    // -----------------------------------------------------------------------
    // Advertised-location conformance (#2657 / #2587 class)
    //
    // These assert the URLs a NuGet V3 document hands a client against the REAL
    // router, mounted exactly where `api::routes` nests it (`/nuget`). The
    // `build_*` unit tests in the sibling `tests` module only prove a
    // *test-local* builder emits the string it was written to emit; they cannot
    // catch a production document advertising a URL that 404s. Regression guard:
    // the registration leaf `@id` was once emitted as
    // `.../registration/{id}/{version}.json`, for which no route exists — every
    // protocol-conformant client 404'd resolving a package version while
    // `search`/`index` passed (the #2587 rpm `<location>` shape, in NuGet).
    // -----------------------------------------------------------------------

    /// The NuGet routes mounted exactly where `api::routes` nests them. The
    /// advertised `@id`/`packageContent` URLs are absolute and carry the
    /// `/nuget` prefix, so a router mounted at the root could not resolve them —
    /// the mount point is part of what these tests pin.
    fn mounted_router() -> Router<SharedState> {
        Router::new().nest("/nuget", super::router())
    }

    /// Resolve a (possibly relative) advertised URL the way a client does —
    /// against the URL of the document that advertised it — and return the
    /// path+query to request, dropping any `#fragment` (a client strips the
    /// fragment before the GET, so the server never sees it).
    fn resolve_advertised(document_url: &str, advertised: &str) -> String {
        let base = reqwest::Url::parse(document_url).expect("document url");
        let joined = base.join(advertised).expect("advertised url must resolve");
        joined[url::Position::BeforePath..url::Position::AfterQuery].to_string()
    }

    /// Every URL a NuGet V3 client dereferences — the service-index resources,
    /// the registration index, its per-version leaf `@id`, and the
    /// `packageContent` .nupkg link — must resolve against the real router, not
    /// merely against a test-local string builder.
    #[tokio::test]
    async fn test_advertised_v3_urls_resolve_against_real_router() {
        let Some(f) = tdh::Fixture::setup("local", "nuget").await else {
            return;
        };

        let package_id = "Qa.AdUrlPkg";
        let package_id_lower = package_id.to_lowercase();
        let version = "1.2.3";
        let nupkg = build_nupkg(package_id, version, "advertised-url probe");

        // Publish through the real push handler so the document is rendered from
        // real `artifacts` rows.
        {
            let app = f.router_with_auth(mounted_router());
            let (status, body) = tdh::send(
                app,
                tdh::put(
                    format!("/nuget/{}/api/v2/package", f.repo_key),
                    bytes::Bytes::from(nupkg.clone()),
                ),
            )
            .await;
            if !status.is_success() {
                f.teardown().await;
                panic!("push failed: {status} {}", String::from_utf8_lossy(&body));
            }
        }

        // Helper: GET a path anonymously (read paths need no auth) and parse JSON.
        async fn get_json(f: &tdh::Fixture, path: String) -> (StatusCode, serde_json::Value) {
            let app = f.router_anon(mounted_router());
            let (status, body) = tdh::send(app, tdh::get(path)).await;
            (
                status,
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
            )
        }

        // 1. Service index → the RegistrationsBaseUrl and PackageBaseAddress
        //    resources a client discovers first.
        let index_path = format!("/nuget/{}/v3/index.json", f.repo_key);
        let index_doc_url = format!("http://ak.test{index_path}");
        let (index_status, index) = get_json(&f, index_path.clone()).await;

        let resource_id = |ty: &str| -> String {
            index
                .get("resources")
                .and_then(|r| r.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|res| res.get("@type").and_then(|v| v.as_str()) == Some(ty))
                })
                .and_then(|res| res.get("@id").and_then(|v| v.as_str()))
                .unwrap_or_default()
                .to_string()
        };
        let reg_base = resource_id("RegistrationsBaseUrl");
        let flat_base = resource_id("PackageBaseAddress/3.0.0");

        // 2. Registration index — resolved by appending `{id}/index.json` to the
        //    advertised RegistrationsBaseUrl, exactly as a client builds it.
        let reg_index_advertised = format!("{}{}/index.json", reg_base, package_id_lower);
        let reg_index_path = resolve_advertised(&index_doc_url, &reg_index_advertised);
        let reg_doc_url = format!("http://ak.test{reg_index_path}");
        let (reg_status, reg) = get_json(&f, reg_index_path.clone()).await;

        // 3. The registration leaf `@id` + `packageContent` the document
        //    advertises for the published version.
        let leaf = reg
            .get("items")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|page| page.get("items"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let leaf_id = leaf
            .get("@id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let package_content = leaf
            .get("packageContent")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let leaf_path = if leaf_id.is_empty() {
            String::new()
        } else {
            resolve_advertised(&reg_doc_url, &leaf_id)
        };
        let content_path = if package_content.is_empty() {
            String::new()
        } else {
            resolve_advertised(&reg_doc_url, &package_content)
        };

        // 4. Flat-container version list — appended to the advertised
        //    PackageBaseAddress the same way a client resolves it.
        let flat_advertised = format!("{}{}/index.json", flat_base, package_id_lower);
        let flat_path = resolve_advertised(&index_doc_url, &flat_advertised);

        // Follow each advertised URL against the real router.
        let leaf_status = if leaf_path.is_empty() {
            StatusCode::NOT_FOUND
        } else {
            get_json(&f, leaf_path.clone()).await.0
        };
        let (content_status, content_body) = if content_path.is_empty() {
            (StatusCode::NOT_FOUND, bytes::Bytes::new())
        } else {
            let app = f.router_anon(mounted_router());
            tdh::send(app, tdh::get(content_path.clone())).await
        };
        let flat_status = get_json(&f, flat_path.clone()).await.0;

        f.teardown().await;

        assert_eq!(index_status, StatusCode::OK, "service index");
        assert_ne!(
            reg_base, "",
            "service index must advertise a RegistrationsBaseUrl"
        );
        assert_ne!(
            flat_base, "",
            "service index must advertise a PackageBaseAddress"
        );
        assert_eq!(
            reg_status,
            StatusCode::OK,
            "advertised registration index ({reg_index_path})"
        );
        assert_eq!(
            leaf_status,
            StatusCode::OK,
            "the registration leaf @id ({leaf_id}) must resolve, not 404"
        );
        assert_eq!(
            content_status,
            StatusCode::OK,
            "the advertised packageContent ({package_content}) must resolve, not 404"
        );
        assert_eq!(
            &content_body[..],
            nupkg.as_slice(),
            "packageContent must serve the published .nupkg bytes"
        );
        assert_eq!(
            flat_status,
            StatusCode::OK,
            "the advertised PackageBaseAddress version list ({flat_path}) must resolve, not 404"
        );
    }
}
