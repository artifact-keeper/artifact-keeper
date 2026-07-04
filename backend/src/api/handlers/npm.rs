//! npm Registry API handlers.
//!
//! Implements the endpoints required for `npm publish` and `npm install`.
//!
//! Routes are mounted at `/npm/{repo_key}/...`:
//!   GET  /npm/{repo_key}/{package}                    - Get package metadata (packument)
//!   GET  /npm/{repo_key}/{@scope}/{package}           - Get scoped package metadata
//!   GET  /npm/{repo_key}/{package}/{version}          - Get version-specific metadata
//!   GET  /npm/{repo_key}/{@scope}/{package}/{version} - Get scoped version-specific metadata
//!   GET  /npm/{repo_key}/{package}/-/{filename}       - Download tarball
//!   GET  /npm/{repo_key}/{@scope}/{package}/-/{filename} - Download scoped tarball
//!   PUT  /npm/{repo_key}/{package}                    - Publish package
//!   PUT  /npm/{repo_key}/{@scope}/{package}           - Publish scoped package

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, VARY,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Extension;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
use tower_http::compression::CompressionLayer;
use tracing::{debug, info};

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::AppError;
use crate::models::repository::RepositoryType;
use crate::services::npm_packument_cache::{
    self as packument_cache, CachedPackument, NpmPackumentCache,
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Security advisories bulk lookup (npm audit): POST /npm/{repo_key}/-/npm/v1/security/advisories/bulk
        // Quick audit (older npm versions / yarn): POST /npm/{repo_key}/-/npm/v1/security/audits/quick
        // These literal-segment routes must precede the `:package` catch-alls
        // below so axum matches them first. See issue #1400.
        .route(
            "/:repo_key/-/npm/v1/security/advisories/bulk",
            post(security_advisories_bulk),
        )
        .route(
            "/:repo_key/-/npm/v1/security/audits/quick",
            post(security_audits_quick),
        )
        // dist-tags (npm dist-tag ls/add/rm + `npm install pkg@<tag>` resolution).
        // npm percent-encodes scoped names here (`@scope%2Fname`), so a single
        // `:package` segment captures both scoped and unscoped. Literal `-/package`
        // keeps these ahead of the `:package` catch-alls (see issue #1543).
        .route(
            "/:repo_key/-/package/:package/dist-tags",
            get(dist_tags_get),
        )
        .route(
            "/:repo_key/-/package/:package/dist-tags/:tag",
            put(dist_tags_put).delete(dist_tags_delete),
        )
        // npm /-/ meta namespace: GET /npm/{repo_key}/-/*rest
        //
        // The npm registry protocol reserves `/-/` as a meta namespace for
        // registry-level operations (ping, whoami, search, login, audit, etc.).
        // Without an explicit catch-all here, requests like `/-/ping` fall into
        // the `/:package/:version` catch-all with `package="-"` and
        // `version="ping"`, producing a spurious 404 ("Version 'ping' not found
        // for package '-'"). This route must appear before every `:package`
        // catch-all so axum resolves it first. More specific `/-/…` routes
        // registered above (audit endpoints, dist-tags) continue to shadow this
        // wildcard because axum prefers literal segments over `*` wildcards.
        // See the filed issue for the full reproducer and impact analysis.
        .route("/:repo_key/-/*rest", get(npm_meta_get))
        // Scoped package tarball: GET /npm/{repo_key}/@{scope}/{package}/-/{filename}
        .route(
            "/:repo_key/@:scope/:package/-/:filename",
            get(download_scoped_tarball),
        )
        // Scoped version metadata: GET /npm/{repo_key}/@{scope}/{package}/{version}
        .route(
            "/:repo_key/@:scope/:package/:version",
            get(get_scoped_version_metadata),
        )
        // Scoped package metadata / publish: GET/PUT /npm/{repo_key}/@{scope}/{package}
        .route(
            "/:repo_key/@:scope/:package",
            get(get_scoped_metadata).put(publish_scoped),
        )
        // Unscoped package tarball: GET /npm/{repo_key}/{package}/-/{filename}
        .route("/:repo_key/:package/-/:filename", get(download_tarball))
        // Unscoped version metadata: GET /npm/{repo_key}/{package}/{version}
        .route("/:repo_key/:package/:version", get(get_version_metadata))
        // Unscoped package metadata / publish: GET/PUT /npm/{repo_key}/{package}
        .route("/:repo_key/:package", get(get_metadata).put(publish))
        // gzip/br for metadata JSON; excludes already-compressed tarball bodies.
        .layer(npm_metadata_compression_layer())
}

/// gzip/br compression for npm metadata. Tarballs are served as
/// `application/gzip`; that and `application/octet-stream` are excluded as
/// defence-in-depth so tarball bytes are never recompressed.
fn npm_metadata_compression_layer() -> CompressionLayer<impl Predicate> {
    CompressionLayer::new().gzip(true).br(true).compress_when(
        DefaultPredicate::new()
            .and(NotForContentType::const_new("application/gzip"))
            .and(NotForContentType::const_new("application/octet-stream")),
    )
}

// ---------------------------------------------------------------------------
// Computed-packument response cache (#2162)
// ---------------------------------------------------------------------------

/// Buffering cap when caching a computed packument body. Packuments are
/// bounded JSON; this matches the cap `dist_tags_get` already uses when it
/// buffers the same responses.
const NPM_PACKUMENT_BUFFER_CAP: usize = 32 * 1024 * 1024;

/// True when the client advertises `gzip` (or `*`) in `Accept-Encoding`, i.e.
/// the metadata compression layer would have gzipped the response. Only gzip
/// is pre-encoded; brotli-only clients are served the identity variant (which
/// the compression layer may still compress on the fly).
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ae| {
            ae.split(',').any(|tok| {
                let name = tok.split(';').next().unwrap_or("").trim();
                name.eq_ignore_ascii_case("gzip") || name == "*"
            })
        })
}

/// Only JSON metadata is cached; error responses and non-JSON passthroughs
/// are cheap to recompute and must never be pinned in the cache.
fn is_cacheable_packument_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .ends_with("json")
}

/// gzip-compress a JSON body at the level the metadata compression layer
/// uses, so a pre-encoded hit is byte-comparable in size to the layer output.
fn gzip_encode(data: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::with_capacity(data.len() / 2), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Build a `Response` from a cached computed packument. The
/// `Content-Encoding` header (present when the body is gzip) makes the
/// metadata compression layer skip this response, so the pre-encoded bytes
/// are served verbatim. `Vary` covers both request dimensions of the cache
/// key: tower-http only adds `Vary: accept-encoding` when it compresses, so
/// pre-encoded hits must declare it themselves or a shared HTTP cache could
/// serve one client's encoding (or Accept variant) to another.
fn cached_packument_response(entry: &CachedPackument) -> Response {
    let mut response = Response::new(Body::from(entry.bytes.clone()));
    let headers = response.headers_mut();
    // Stored values originate from valid responses, but a corrupt shared
    // cache entry must degrade to a safe default, never a panic.
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&entry.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
    );
    if let Some(ref encoding) = entry.content_encoding {
        if let Ok(value) = HeaderValue::from_str(encoding) {
            headers.insert(CONTENT_ENCODING, value);
        }
    }
    headers.insert(VARY, HeaderValue::from_static("Accept, Accept-Encoding"));
    response
}

/// Cache-fronted packument fetch used by the GET-metadata handlers.
///
/// Only remote and virtual repositories are cached: that is where the
/// upstream round-trip being eliminated lives. Local (hosted) packuments are
/// a cheap indexed DB read, and caching them would break read-your-writes
/// across replicas with the in-process backend (a publish on one pod would
/// leave other pods serving the pre-publish entry for the fresh window).
///
/// Fresh hits serve the pre-computed, pre-encoded response with no upstream
/// fetch, tarball-URL rewrite, abbreviation or serialize/compress. Stale hits
/// serve immediately while one background task refreshes the entry. Misses
/// compute inline under single-flight, so a burst on one packument costs one
/// upstream fetch.
async fn get_package_metadata_cached(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    base_url: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let want_abbreviated = wants_abbreviated_metadata(headers);
    // One indexed lookup to classify the repo before consulting the cache;
    // its cost is negligible next to the upstream round-trip a hit saves.
    let repo = resolve_npm_repo(&state.db, repo_key).await?;
    let cache_eligible =
        repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual;
    let Some(cache) = state.npm_packument_cache.clone().filter(|_| cache_eligible) else {
        return get_package_metadata(state, repo_key, package_name, base_url, want_abbreviated)
            .await;
    };
    let want_gzip = accepts_gzip(headers);
    let key = packument_cache::cache_key(
        repo_key,
        package_name,
        want_abbreviated,
        want_gzip,
        base_url,
    );
    let flight = packument_cache::flight_key(repo_key, package_name, want_abbreviated, base_url);

    cache
        .serve(
            &key,
            &flight,
            || {
                compute_and_store_packument(
                    state,
                    &cache,
                    repo_key,
                    package_name,
                    base_url,
                    want_abbreviated,
                    want_gzip,
                )
            },
            |claim| {
                let state = state.clone();
                let cache = cache.clone();
                let repo_key = repo_key.to_string();
                let package_name = package_name.to_string();
                let base_url = base_url.to_string();
                tokio::spawn(async move {
                    // Hold the claim for the task's lifetime so a stale burst
                    // triggers exactly one refresh; dropping it (success,
                    // failure, or cancellation) re-arms the next refresh.
                    let _claim = claim;
                    if compute_and_store_packument(
                        &state,
                        &cache,
                        &repo_key,
                        &package_name,
                        &base_url,
                        want_abbreviated,
                        want_gzip,
                    )
                    .await
                    .is_err()
                    {
                        debug!(
                            repo_key,
                            package = package_name,
                            "npm packument background refresh failed; stale entry remains"
                        );
                    }
                });
            },
            || {
                AppError::ServiceUnavailable(
                    "Timed out waiting for npm packument refresh".to_string(),
                )
                .into_response()
            },
        )
        .await
        .map(|entry| cached_packument_response(&entry))
}

/// True when a response status is an authoritative "this package does not
/// exist (any more)" rather than a transient failure. A 404/410 observed by
/// a refresh must EVICT the cached packument so unpublishes and takedowns
/// propagate immediately; transient failures (5xx, timeouts) must NOT evict,
/// so stale entries keep serving through upstream blips (the point of SWR).
fn is_definitive_missing_status(status: StatusCode) -> bool {
    matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE)
}

/// Compute a packument via [`get_package_metadata`] and cache the result.
///
/// Successful JSON responses are stored in both encodings — identity always,
/// gzip when the body compresses — so any later client hits regardless of its
/// `Accept-Encoding`. The entry matching `want_gzip` is returned for serving.
/// Error responses and non-JSON passthroughs are returned unchanged via
/// `Err` and left uncached; an authoritative 404/410 additionally evicts the
/// package's cached variants (see [`is_definitive_missing_status`]).
#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped; the exempt call is marked inline below (#1608)
async fn compute_and_store_packument(
    state: &SharedState,
    cache: &NpmPackumentCache,
    repo_key: &str,
    package_name: &str,
    base_url: &str,
    want_abbreviated: bool,
    want_gzip: bool,
) -> Result<CachedPackument, Response> {
    // Capture the invalidation generation BEFORE computing, so a publish
    // that lands mid-compute wins over the data computed from before it.
    let store_guard = cache.begin_store(repo_key, package_name);
    let response =
        match get_package_metadata(state, repo_key, package_name, base_url, want_abbreviated).await
        {
            Ok(response) => response,
            Err(error_response) => {
                if is_definitive_missing_status(error_response.status()) {
                    cache.invalidate_package(repo_key, package_name).await;
                }
                return Err(error_response);
            }
        };
    if response.status() != StatusCode::OK {
        if is_definitive_missing_status(response.status()) {
            cache.invalidate_package(repo_key, package_name).await;
        }
        return Err(response);
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    if !is_cacheable_packument_content_type(&content_type) {
        return Err(response);
    }

    // STREAMING-EXEMPT: capped metadata read (a computed npm packument JSON, not an artifact blob); bounded to <=32 MiB via NPM_PACKUMENT_BUFFER_CAP so a hostile/broken upstream cannot OOM us; over-cap is surfaced as an error and left uncached; tracked under #1608
    let body_bytes = axum::body::to_bytes(response.into_body(), NPM_PACKUMENT_BUFFER_CAP)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to read packument body: {}", e)).into_response()
        })?;

    let identity_entry = CachedPackument {
        bytes: body_bytes.clone(),
        content_type: content_type.clone(),
        content_encoding: None,
    };
    cache
        .store_guarded(
            &store_guard,
            &packument_cache::cache_key(repo_key, package_name, want_abbreviated, false, base_url),
            identity_entry.clone(),
        )
        .await;

    // Encoder failure is not fatal: the identity variant serves this client
    // and later gzip clients recompute.
    let gzip_entry = match gzip_encode(&body_bytes) {
        Ok(gz) => {
            let entry = CachedPackument {
                bytes: Bytes::from(gz),
                content_type,
                content_encoding: Some("gzip".to_string()),
            };
            cache
                .store_guarded(
                    &store_guard,
                    &packument_cache::cache_key(
                        repo_key,
                        package_name,
                        want_abbreviated,
                        true,
                        base_url,
                    ),
                    entry.clone(),
                )
                .await;
            Some(entry)
        }
        Err(_) => None,
    };

    Ok(match (want_gzip, gzip_entry) {
        (true, Some(entry)) => entry,
        _ => identity_entry,
    })
}

/// Derive the npm package name from an artifact path
/// (`{package}/{version}/{filename}`, where a scoped package contributes two
/// leading segments). Returns `None` for paths that do not follow the npm
/// layout. Used by the REST artifact-delete path to invalidate the computed
/// packument cache without parsing metadata.
pub(crate) fn npm_package_name_from_artifact_path(path: &str) -> Option<&str> {
    // rsplitn(3) yields [filename, version, package-possibly-with-slashes].
    let mut segments = path.rsplitn(3, '/');
    let _filename = segments.next().filter(|s| !s.is_empty())?;
    let _version = segments.next().filter(|s| !s.is_empty())?;
    segments.next().filter(|s| !s.is_empty())
}

/// Invalidate the computed-packument cache for a package after a local write
/// (publish, dist-tag change, artifact delete), in the hosting repo and in
/// every virtual repo that includes it — the packument a virtual repo serves
/// for this package changes too. Mirrors how cargo publish invalidates its
/// index cache.
pub(crate) async fn invalidate_packument_caches(
    state: &SharedState,
    repo_id: uuid::Uuid,
    repo_key: &str,
    package: &str,
) {
    let Some(cache) = state.npm_packument_cache.as_ref() else {
        return;
    };
    cache.invalidate_package(repo_key, package).await;

    let virtual_keys: Vec<String> = sqlx::query_scalar(
        "SELECT r.key FROM repositories r \
         INNER JOIN virtual_repo_members vrm ON r.id = vrm.virtual_repo_id \
         WHERE vrm.member_repo_id = $1",
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for virtual_key in &virtual_keys {
        cache.invalidate_package(virtual_key, package).await;
    }
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
    super::with_retry_after_on_503(
        (status, axum::Json(serde_json::json!({"error": msg}))).into_response(),
    )
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

/// Build the upstream tarball path for a (possibly scoped) package.
///
/// Unlike the metadata endpoint, the npm tarball URL keeps the scope
/// separator as a literal `/`: `@scope/pkg/-/pkg-1.0.0.tgz`. The public
/// registry and AK's own scoped-tarball route
/// (`/:repo_key/@:scope/:package/-/:filename`) both expect `@scope` and
/// `pkg` as separate path segments. Percent-encoding the slash here (as
/// `encode_package_name_for_upstream` does for metadata) collapses them into
/// a single `@scope%2Fpkg` segment, which no upstream tarball route matches,
/// so the proxy fetch 404s (B7). The scope separator must therefore stay
/// un-encoded for tarballs even though metadata requires `%2F`.
fn build_tarball_upstream_path(package_name: &str, filename: &str) -> String {
    format!("{}/-/{}", package_name, filename)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_npm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["npm", "yarn", "pnpm", "bower"], "an npm")
        .await
}

// ---------------------------------------------------------------------------
// npm security advisories (npm audit) -- issue #1400
// ---------------------------------------------------------------------------

/// Build the empty `advisories/bulk` response shape that npm clients expect
/// when no advisories are known for any of the requested packages. An empty
/// JSON object signals "no advisories" without producing a parse error.
fn empty_advisories_bulk_response() -> Response {
    build_json_metadata_response(serde_json::Value::Object(serde_json::Map::new()).to_string())
}

/// Build the empty `audits/quick` response shape for the legacy npm audit
/// endpoint. Returns a well-formed report with zero vulnerabilities so older
/// npm and yarn clients treat the audit as a success rather than failing the
/// command.
fn empty_audits_quick_response() -> Response {
    let body = serde_json::json!({
        "actions": [],
        "advisories": {},
        "muted": [],
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
            },
            "dependencies": 0,
            "devDependencies": 0,
            "optionalDependencies": 0,
            "totalDependencies": 0,
        }
    });
    build_json_metadata_response(body.to_string())
}

/// Forward an npm audit POST request to the configured upstream registry.
///
/// Used by Remote repos to proxy advisory and audit calls to npmjs.org (or
/// whichever upstream is configured) so `npm audit` works for cached/mirrored
/// dependencies. The full client body is forwarded verbatim. On any upstream
/// transport failure (timeout, DNS, TLS, etc.) the helper returns an empty
/// well-formed response so the audit degrades gracefully instead of failing
/// the client command. See issue #1400.
#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (tail expr); the exempt call is marked inline below (#1608)
async fn proxy_npm_audit_post(
    upstream_url: &str,
    path: &str,
    body: Bytes,
    empty_fallback: fn() -> Response,
) -> Response {
    let base = upstream_url.trim_end_matches('/');
    let url = format!("{}{}", base, path);
    let client = crate::services::http_client::default_client();
    let req = client
        .post(&url)
        .header(CONTENT_TYPE, "application/json")
        .body(body);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            // STREAMING-EXEMPT: capped metadata read (upstream npm audit advisory JSON, not an artifact blob); bounded to <=16 MiB via axum::body::to_bytes so a hostile/broken upstream cannot OOM us; over-cap degrades to empty advisories; tracked under #1608
            match axum::body::to_bytes(Body::from_stream(resp.bytes_stream()), 16 * 1024 * 1024)
                .await
            {
                Ok(bytes) => {
                    if !status.is_success() {
                        debug!(
                            target: "npm_audit",
                            upstream = %url,
                            status = %status,
                            "npm audit upstream returned non-success; serving empty advisories"
                        );
                        return empty_fallback();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, content_type)
                        .body(Body::from(bytes))
                        .unwrap_or_else(|_| empty_fallback())
                }
                Err(err) => {
                    debug!(
                        target: "npm_audit",
                        upstream = %url,
                        error = %err,
                        "failed to read npm audit upstream body; serving empty advisories"
                    );
                    empty_fallback()
                }
            }
        }
        Err(err) => {
            debug!(
                target: "npm_audit",
                upstream = %url,
                error = %err,
                "failed to reach npm audit upstream; serving empty advisories"
            );
            empty_fallback()
        }
    }
}

// ---------------------------------------------------------------------------
// npm /-/ meta namespace — GET handler
// ---------------------------------------------------------------------------

/// Forward a GET request to the upstream registry at the given meta path.
///
/// Returns the upstream status + body verbatim. On any transport error (DNS,
/// TLS, timeout) returns `None` so the caller can fall through to the local
/// fallback.
#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (tail expr); the exempt call is marked inline below (#1608)
async fn proxy_npm_meta_get(upstream_url: &str, meta_path: &str) -> Option<Response> {
    let base = upstream_url.trim_end_matches('/');
    // Reconstruct the `/-/<rest>` meta path. axum 0.7 wildcard captures do NOT
    // include a leading slash (`*rest` on `/-/ping` yields `ping`, not `/ping`),
    // so prepend `/-/` and strip any stray leading slash to be robust either way.
    let path_with_dash = format!("/-/{}", meta_path.trim_start_matches('/'));
    let url = format!("{}{}", base, path_with_dash);
    let client = crate::services::http_client::default_client();

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(err) => {
            debug!(
                target: "npm_meta",
                upstream = %url,
                error = %err,
                "npm meta GET upstream unreachable"
            );
            return None;
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // STREAMING-EXEMPT: capped metadata read (upstream npm registry packument/meta JSON, not an artifact blob); bounded to <=16 MiB via axum::body::to_bytes so a hostile/broken upstream cannot OOM us; over-cap falls through to local fallback; tracked under #1608
    match axum::body::to_bytes(Body::from_stream(resp.bytes_stream()), 16 * 1024 * 1024).await {
        Ok(bytes) => Some(
            Response::builder()
                .status(status)
                .header(CONTENT_TYPE, content_type)
                .body(Body::from(bytes))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "upstream error").into_response()
                }),
        ),
        Err(err) => {
            debug!(
                target: "npm_meta",
                upstream = %url,
                error = %err,
                "npm meta GET failed to read upstream body"
            );
            None
        }
    }
}

/// Handler for `GET /npm/{repo_key}/-/*rest`.
///
/// Implements the npm registry `/-/<endpoint>` meta namespace:
///
/// - **Remote / Virtual repos** — forwards the request transparently to the
///   configured upstream (or the first reachable Remote member, for Virtual).
///   This is the correct behaviour for proxy/group repos: the upstream already
///   handles these endpoints correctly, so AK acts as a pass-through.
///
/// - **Local / Staging repos** — the registry is self-contained; no upstream
///   to forward to. Minimal built-in responses:
///   - `/-/ping` → `200 {}` (standard liveness probe)
///   - `/-/whoami` → `200 {"username":"<name>"}` when authenticated,
///     `401 {"error":"unauthenticated"}` otherwise
///   - All other `/-/` paths → `501 Not Implemented`
///
/// Without this route, the `/:package/:version` catch-all previously matched
/// `/-/ping` with `package="-"` and `version="ping"`, producing a confusing
/// 404 ("Version 'ping' not found for package '-'"). See the linked issue.
async fn npm_meta_get(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, rest)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, &repo_key).await?;

    // Remote: proxy the whole request to upstream verbatim.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            if let Some(resp) = proxy_npm_meta_get(upstream_url, &rest).await {
                return Ok(resp);
            }
        }
        // Upstream misconfigured or unreachable — fall through to local stub.
    }

    // Virtual: try the first Remote member whose upstream is reachable.
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                continue;
            }
            let Some(ref upstream_url) = member.upstream_url else {
                continue;
            };
            if let Some(resp) = proxy_npm_meta_get(upstream_url, &rest).await {
                return Ok(resp);
            }
        }
        // No reachable Remote member — fall through to local stub.
    }

    // Local / Staging (or Remote/Virtual without a reachable upstream):
    // serve minimal built-in responses for the standard meta endpoints.
    let endpoint = rest.trim_start_matches('/');

    if endpoint == "ping" {
        return Ok(build_json_metadata_response("{}".to_string()));
    }

    if endpoint == "whoami" {
        return match auth {
            Some(a) => Ok(build_json_metadata_response(
                serde_json::json!({"username": a.username}).to_string(),
            )),
            None => Err((
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "unauthenticated"})),
            )
                .into_response()),
        };
    }

    // All other /-/ endpoints are not implemented for local repos.
    Err((
        StatusCode::NOT_IMPLEMENTED,
        axum::Json(
            serde_json::json!({"error": format!("/-/{} is not implemented for local repositories", endpoint)}),
        ),
    )
        .into_response())
}

/// Handler for `POST /npm/{repo_key}/-/npm/v1/security/advisories/bulk`.
///
/// This endpoint is used by `npm audit` (npm >= 7) to look up known security
/// advisories for the dependency graph. Remote repositories forward the
/// request to the configured upstream registry. Local, Staging, and Virtual
/// repositories return an empty advisory map so `npm audit` reports zero
/// vulnerabilities instead of failing with a 404. See issue #1400.
async fn security_advisories_bulk(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, &repo_key).await?;

    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            return Ok(proxy_npm_audit_post(
                upstream_url,
                "/-/npm/v1/security/advisories/bulk",
                body,
                empty_advisories_bulk_response,
            )
            .await);
        }
    }

    Ok(empty_advisories_bulk_response())
}

/// Handler for `POST /npm/{repo_key}/-/npm/v1/security/audits/quick`.
///
/// Legacy npm audit endpoint (npm v6) and the path some yarn versions use.
/// Same Remote-proxy / empty-fallback behaviour as the bulk endpoint above.
/// See issue #1400.
async fn security_audits_quick(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, &repo_key).await?;

    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            return Ok(proxy_npm_audit_post(
                upstream_url,
                "/-/npm/v1/security/audits/quick",
                body,
                empty_audits_quick_response,
            )
            .await);
        }
    }

    Ok(empty_audits_quick_response())
}

// ---------------------------------------------------------------------------
// GET metadata handlers
// ---------------------------------------------------------------------------

async fn get_metadata(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    base_url: RequestBaseUrl,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    get_package_metadata_cached(&state, &repo_key, &package, base_url.as_str(), &headers).await
}

async fn get_scoped_metadata(
    State(state): State<SharedState>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    base_url: RequestBaseUrl,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let scope = normalize_package_name(&scope);
    let package = normalize_package_name(&package);
    let full_name = format!("@{}/{}", scope, package);
    validate_package_name(&full_name)?;
    get_package_metadata_cached(&state, &repo_key, &full_name, base_url.as_str(), &headers).await
}

async fn get_version_metadata(
    State(state): State<SharedState>,
    Path((repo_key, package, version)): Path<(String, String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    get_package_version_metadata(&state, &repo_key, &package, &version, base_url.as_str()).await
}

async fn get_scoped_version_metadata(
    State(state): State<SharedState>,
    Path((repo_key, scope, package, version)): Path<(String, String, String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let scope = normalize_package_name(&scope);
    let package = normalize_package_name(&package);
    let full_name = format!("@{}/{}", scope, package);
    validate_package_name(&full_name)?;
    get_package_version_metadata(&state, &repo_key, &full_name, &version, base_url.as_str()).await
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
    stored_dist_tags: &serde_json::Map<String, serde_json::Value>,
    want_abbreviated: bool,
) -> Result<Response, Response> {
    let mut versions = serde_json::Map::new();
    let mut version_list: Vec<String> = Vec::new();

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
        version_list.push(version);
    }

    // Emit the stored dist-tags map verbatim, then ensure a usable `latest`:
    // keep an explicit `latest` that still resolves to a known version,
    // otherwise derive it as the highest non-prerelease semver (issue #1543).
    let mut dist_tags = stored_dist_tags.clone();
    let latest_resolves = dist_tags
        .get("latest")
        .and_then(|v| v.as_str())
        .map(|l| version_list.iter().any(|v| v == l))
        .unwrap_or(false);
    if !latest_resolves {
        if let Some(latest) = derive_latest_version(&version_list) {
            dist_tags.insert("latest".to_string(), serde_json::Value::String(latest));
        }
    }

    let response = serde_json::json!({
        "name": package_name,
        "versions": versions,
        "dist-tags": serde_json::Value::Object(dist_tags),
    });

    Ok(respond_with_packument(response, want_abbreviated))
}

/// Choose the `latest` dist-tag for a set of versions when none is recorded.
///
/// Per npm convention `latest` should be the highest **non-prerelease** semver,
/// never auto-set to a prerelease by recency. We compare on the numeric
/// `major.minor.patch` core (build metadata and prerelease suffixes are
/// stripped); a version carrying a `-prerelease` suffix is excluded from the
/// stable candidates. Falls back to the highest version overall when every
/// version is a prerelease, and to the last (most-recently-created) version
/// when nothing parses as semver. Returns `None` only for an empty input.
fn derive_latest_version(versions: &[String]) -> Option<String> {
    // Parse into (major, minor, patch, is_prerelease); `None` if not semver-ish.
    fn parse(v: &str) -> Option<(u64, u64, u64, bool)> {
        let core = v.split('+').next().unwrap_or(v); // drop +build metadata
        let (mmp, is_pre) = match core.split_once('-') {
            Some((head, _pre)) => (head, true),
            None => (core, false),
        };
        let mut parts = mmp.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
        let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
        Some((major, minor, patch, is_pre))
    }

    let mut best_stable: Option<(&String, (u64, u64, u64))> = None;
    let mut best_any: Option<(&String, (u64, u64, u64))> = None;
    for v in versions {
        if let Some((major, minor, patch, is_pre)) = parse(v) {
            let key = (major, minor, patch);
            // Prefer the later-listed (more recent) version on ties.
            if best_any.as_ref().map_or(true, |(_, k)| key >= *k) {
                best_any = Some((v, key));
            }
            if !is_pre && best_stable.as_ref().map_or(true, |(_, k)| key >= *k) {
                best_stable = Some((v, key));
            }
        }
    }

    best_stable
        .map(|(v, _)| v.clone())
        .or_else(|| best_any.map(|(v, _)| v.clone()))
        .or_else(|| versions.last().cloned())
}

/// Fetch the stored npm dist-tags map for a package from the `npm_dist_tags`
/// table, which holds exactly one row per (repository_id, name). Best-effort:
/// returns an empty map when there is no row, no tags, or on any query error
/// (the caller still derives a `latest` from the versions).
async fn fetch_npm_dist_tags(
    db: &PgPool,
    repository_id: uuid::Uuid,
    package_name: &str,
) -> serde_json::Map<String, serde_json::Value> {
    // PRIMARY KEY (repository_id, name) guarantees at most one row, so
    // fetch_optional is safe here (unlike a per-version `packages` read).
    let stored: Option<serde_json::Value> = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT tags FROM npm_dist_tags WHERE repository_id = $1 AND name = $2",
    )
    .bind(repository_id)
    .bind(package_name)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    stored
        .as_ref()
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
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

/// Return the package metadata: the full packument, or the abbreviated document
/// when the client requests it.
async fn get_package_metadata(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    base_url: &str,
    want_abbreviated: bool,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // For remote repos, always proxy metadata from upstream. Cached tarball
    // artifacts do not contain enough information to reconstruct the full
    // package metadata that npm clients expect.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            if let Some(ref proxy) = state.proxy_service {
                let encoded_name = encode_package_name_for_upstream(package_name);
                let (content, content_type) = proxy_helpers::proxy_fetch_capped(
                    proxy,
                    repo.id,
                    repo_key,
                    upstream_url,
                    &encoded_name,
                    proxy_helpers::LARGE_METADATA_MAX_BYTES,
                )
                .await?;

                return Ok(rewrite_and_respond(
                    content,
                    content_type,
                    base_url,
                    repo_key,
                    want_abbreviated,
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
                    let dist_tags = fetch_npm_dist_tags(&state.db, member.id, package_name).await;
                    return build_npm_metadata_response(
                        &meta,
                        package_name,
                        base_url,
                        repo_key,
                        &dist_tags,
                        want_abbreviated,
                    );
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
            let result = proxy_helpers::proxy_fetch_capped(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                &encoded_name,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            )
            .await;

            match result {
                Ok((content, content_type)) => {
                    return Ok(rewrite_and_respond(
                        content,
                        content_type,
                        base_url,
                        repo_key,
                        want_abbreviated,
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

    let dist_tags = fetch_npm_dist_tags(&state.db, repo.id, package_name).await;
    build_npm_metadata_response(
        &meta_artifacts,
        package_name,
        base_url,
        repo_key,
        &dist_tags,
        want_abbreviated,
    )
}

/// Fetch the full packument and extract a single version's metadata.
///
/// For remote and virtual repos the full packument is fetched from upstream
/// (or the first matching member) and parsed as JSON. For local/staging repos
/// the packument is built from stored artifacts. In either case the
/// `versions[version]` object is extracted and returned. Returns 404 when
/// the package exists but does not contain the requested version.
async fn get_package_version_metadata(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    version: &str,
    base_url: &str,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Build or fetch the full packument as a JSON value.
    let packument: serde_json::Value = if repo.repo_type == RepositoryType::Remote {
        fetch_remote_packument(state, &repo, repo_key, package_name, base_url).await?
    } else if repo.repo_type == RepositoryType::Virtual {
        fetch_virtual_packument(state, &repo, repo_key, package_name, base_url).await?
    } else {
        let artifacts = fetch_npm_artifacts(&state.db, repo.id, package_name).await?;
        if artifacts.is_empty() {
            return Err(AppError::NotFound("Package not found".to_string()).into_response());
        }
        // Version extraction ignores dist-tags; pass an empty map.
        // Always build the full packument here so the version can be extracted.
        let resp = build_npm_metadata_response(
            &artifacts,
            package_name,
            base_url,
            repo_key,
            &serde_json::Map::new(),
            false,
        )?;
        #[allow(clippy::disallowed_methods)]
        // STREAMING-EXEMPT: capped-metadata read (upstream index/advisory/packument, not an artifact blob); bounded response buffered; tracked under #1608
        let body_bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to read packument body: {}", e)).into_response()
            })?;
        serde_json::from_slice(&body_bytes).map_err(|e| {
            AppError::Internal(format!("Failed to parse packument JSON: {}", e)).into_response()
        })?
    };

    // Extract the requested version from the packument.
    let version_obj = packument
        .get("versions")
        .and_then(|v| v.get(version))
        .cloned()
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Version '{}' not found for package '{}'",
                version, package_name
            ))
            .into_response()
        })?;

    Ok(build_json_metadata_response(
        serde_json::to_string(&version_obj).unwrap(),
    ))
}

/// Fetch the full packument JSON from a remote repository's upstream.
async fn fetch_remote_packument(
    state: &SharedState,
    repo: &proxy_helpers::RepoInfo,
    repo_key: &str,
    package_name: &str,
    base_url: &str,
) -> Result<serde_json::Value, Response> {
    let upstream_url = repo
        .upstream_url
        .as_deref()
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()).into_response())?;
    let proxy = state
        .proxy_service
        .as_ref()
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()).into_response())?;
    let encoded_name = encode_package_name_for_upstream(package_name);
    let (content, _ct) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        &encoded_name,
        proxy_helpers::LARGE_METADATA_MAX_BYTES,
    )
    .await?;
    let mut json: serde_json::Value = serde_json::from_slice(&content).map_err(|e| {
        AppError::Internal(format!("Invalid JSON from upstream: {}", e)).into_response()
    })?;
    rewrite_npm_tarball_urls(&mut json, base_url, repo_key);
    Ok(json)
}

/// Fetch the full packument JSON by iterating virtual repo members.
async fn fetch_virtual_packument(
    state: &SharedState,
    repo: &proxy_helpers::RepoInfo,
    repo_key: &str,
    package_name: &str,
    base_url: &str,
) -> Result<serde_json::Value, Response> {
    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
    if members.is_empty() {
        return Err(
            AppError::NotFound("Virtual repository has no members".to_string()).into_response(),
        );
    }

    for member in &members {
        if member.repo_type == RepositoryType::Local || member.repo_type == RepositoryType::Staging
        {
            let meta = fetch_npm_artifacts(&state.db, member.id, package_name).await?;
            if !meta.is_empty() {
                // Always build the full packument here so the version can be extracted.
                let resp = build_npm_metadata_response(
                    &meta,
                    package_name,
                    base_url,
                    repo_key,
                    &serde_json::Map::new(),
                    false,
                )?;
                #[allow(clippy::disallowed_methods)]
                // STREAMING-EXEMPT: capped-metadata read (upstream index/advisory/packument, not an artifact blob); bounded response buffered; tracked under #1608
                let body_bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!("Failed to read packument body: {}", e))
                            .into_response()
                    })?;
                return serde_json::from_slice(&body_bytes).map_err(|e| {
                    AppError::Internal(format!("Failed to parse packument JSON: {}", e))
                        .into_response()
                });
            }
            continue;
        }

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
        let result = proxy_helpers::proxy_fetch_capped(
            proxy,
            member.id,
            &member.key,
            upstream_url,
            &encoded_name,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await;

        match result {
            Ok((content, _ct)) => {
                let mut json: serde_json::Value =
                    serde_json::from_slice(&content).map_err(|e| {
                        AppError::Internal(format!("Invalid JSON from upstream: {}", e))
                            .into_response()
                    })?;
                rewrite_npm_tarball_urls(&mut json, base_url, repo_key);
                return Ok(json);
            }
            Err(_e) => {
                debug!(
                    member_key = %member.key,
                    "npm metadata proxy fetch missed for virtual member"
                );
            }
        }
    }

    Err(
        AppError::NotFound("Package not found in any member repository".to_string())
            .into_response(),
    )
}

/// Content type for npm tarballs (.tgz). npm packages are always gzip-compressed
/// tar archives. Upstream registries (including npmjs.org) sometimes serve these
/// as `application/octet-stream`, but the correct MIME type is `application/gzip`.
/// Using the right content type is important because downstream services (SBOM
/// generation, Trivy, Grype) rely on it to decide how to extract and scan the
/// artifact contents.
const NPM_TARBALL_CONTENT_TYPE: &str = "application/gzip";

/// Build a streaming tarball response from a storage stream.
fn build_tarball_response_stream(
    stream: futures::stream::BoxStream<'static, crate::error::Result<Bytes>>,
    filename: &str,
    content_type: Option<String>,
    content_length: Option<u64>,
) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| NPM_TARBALL_CONTENT_TYPE.to_string()),
        )
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        );
    if let Some(len) = content_length {
        builder = builder.header(CONTENT_LENGTH, len.to_string());
    }
    builder.body(Body::from_stream(stream)).unwrap()
}

/// Decide the `Content-Type` for an npm tarball served from a Virtual repo.
///
/// Virtual downloads are satisfied by a member repo's proxy-cache, and the
/// sidecar records whatever content type the upstream sent — for npm that is
/// frequently `application/octet-stream` (and occasionally a bogus
/// text/HTML type on error pages that slipped into cache). npm tarballs are
/// always gzip, and downstream SBOM/scanner tooling (Trivy, Grype) keys off
/// the content type, so the virtual path must normalize to `application/gzip`
/// just like the direct remote-repo path does. We therefore ignore the cached
/// content type entirely and always return [`NPM_TARBALL_CONTENT_TYPE`].
fn npm_virtual_tarball_content_type(_cached: Option<String>) -> Option<String> {
    Some(NPM_TARBALL_CONTENT_TYPE.to_string())
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
    want_abbreviated: bool,
) -> Response {
    if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&content) {
        // Abbreviate after the tarball rewrite so abbreviated `dist.tarball`
        // URLs point at this proxy.
        rewrite_npm_tarball_urls(&mut json, base_url, repo_key);
        return respond_with_packument(json, want_abbreviated);
    }
    // Not valid JSON: pass through with the original content type (never abbreviate).
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
) -> Result<proxy_helpers::StreamingFetchResult, Response> {
    // Try exact path match first (proxy-cached artifacts use the upstream
    // path verbatim, e.g. "@types/mdurl/-/mdurl-2.0.0.tgz" -- the scope
    // separator stays un-encoded for tarballs; see
    // `build_tarball_upstream_path`).
    if let Ok(result) =
        proxy_helpers::local_fetch_by_path(db, state, repo_id, location, upstream_path).await
    {
        return Ok(result);
    }

    // Fall back to a pattern that anchors the match on the decoded package
    // name, covering locally published artifacts whose path follows the
    // layout "{package_name}/{version}/{filename}".
    //
    // Escape `%` and `_` from user-supplied package_name and filename so
    // they're treated as literals; the literal `/%/` separator below
    // remains a wildcard. ESCAPE '\' on the SQL side selects backslash as
    // the escape character. See `super::escape_like_literal`.
    let pkg_path_prefix = format!("{}/%/", super::escape_like_literal(package_name));
    let filename_escaped = super::escape_like_literal(filename);
    let artifact = sqlx::query_as::<_, proxy_helpers::LocalArtifactRow>(
        "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 AND path LIKE $2 || $3 ESCAPE '\\' AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(&pkg_path_prefix)
    .bind(&filename_escaped)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        map_status(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    proxy_helpers::check_quarantine_row(&artifact)?;

    let storage = state
        .storage_for_repo(location)
        .map_err(|e| e.into_response())?;
    // Stream the body for the common case, but preserve the #1016 / hydration
    // contract: a storage miss falls back to the coordinated buffered retry and
    // is re-wrapped as a one-shot stream so the caller sees a uniform result.
    let body: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>> =
        match storage.get_stream(&artifact.storage_key).await {
            Ok(stream) => stream,
            Err(crate::error::AppError::NotFound(_)) => {
                let bytes = proxy_helpers::coordinated_retry_get(
                    db,
                    artifact.id,
                    &artifact.storage_key,
                    &*storage,
                )
                .await?;
                Box::pin(futures::stream::once(async move { Ok(bytes) }))
            }
            Err(e) => return Err(map_storage_err(e)),
        };

    Ok(proxy_helpers::StreamingFetchResult {
        body,
        content_type: Some(artifact.content_type.clone()),
        content_length: Some(artifact.size_bytes as u64),
    })
}

async fn serve_tarball(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    filename: &str,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Tarball URLs keep the scope separator as a literal `/`
    // (`@scope/pkg/-/file.tgz`); only metadata uses `%2F`. Encoding it here
    // collapsed the scope and package into one path segment that no upstream
    // tarball route matched, so the remote-proxy fetch 404'd (B7).
    let upstream_path = build_tarball_upstream_path(package_name, filename);

    // For remote repos, always proxy tarballs from upstream (hits cache if
    // already fetched). The proxy cache stores content under its own storage
    // key which the regular artifact storage cannot resolve.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            // #2192 / #1608 Phase 4c: an npm tarball is a package BLOB, not
            // metadata. The buffered fallback (#2181) capped it at
            // LARGE_METADATA_MAX_BYTES and 502'd a tarball larger than the cap
            // even though other download paths already stream. Stream it (teed
            // into the proxy cache under `upstream_path`) so a large tarball
            // succeeds with 200 and subsequent pulls are served warm.
            let result = proxy_helpers::proxy_fetch_streaming_with_cache_key(
                proxy,
                repo.id,
                repo_key,
                upstream_url,
                &upstream_path,
                &upstream_path,
            )
            .await?;

            // The upstream registry may return application/octet-stream for
            // npm tarballs, which also gets persisted by the proxy cache.
            // Correct the cached artifact record so that SBOM generation and
            // security scanners can identify the file as a gzip archive.
            correct_cached_tarball_content_type(&state.db, repo.id, &upstream_path).await;

            // Force the outbound Content-Type to application/gzip regardless of
            // what the upstream advertised — parity with the buffered path
            // (build_tarball_response(None)) and the virtual path
            // (npm_virtual_tarball_content_type).
            return Ok(build_tarball_response_stream(
                result.body,
                filename,
                npm_virtual_tarball_content_type(result.content_type),
                result.content_length,
            ));
        }
        return Err(AppError::NotFound("Tarball not found".to_string()).into_response());
    }

    // Virtual repo: try each member in priority order
    if repo.repo_type == RepositoryType::Virtual {
        let db = state.db.clone();
        let upath = upstream_path.clone();
        let pkg = package_name.to_string();
        let fname = filename.to_string();

        // Supply-chain shadowing guard (#1217 follow-up, ak-hv3s).
        // If a non-Remote member of this Virtual repo owns the npm
        // package name, block Remote members from satisfying the
        // download. The `package_name` parameter is the npm-canonical
        // name (eg. `@types/node` or `lodash`) extracted by the router;
        // `artifacts.name` stores the same shape, so a direct case-
        // insensitive comparison is what `virtual_non_remote_owns_name`
        // performs. Passing `None` to `resolve_virtual_download` is the
        // load-bearing security primitive: see hex.rs's
        // `serve_virtual_tarball_local_only` for the rationale on why
        // any refactor here must keep this `None`.
        //
        // Fail-closed: skip the guard for names that fail
        // `is_valid_npm_name` (path traversal, uppercase, homoglyphs).
        // Such names cannot reach `artifacts.name` so the guard would
        // always return false; skipping it spares the DB an existence
        // check on every malformed request.
        let local_owns = if crate::formats::npm::is_valid_npm_name(package_name) {
            proxy_helpers::virtual_non_remote_owns_name(&state.db, repo.id, package_name).await?
        } else {
            false
        };
        let proxy_for_virtual = if local_owns {
            None
        } else {
            state.proxy_service.as_deref()
        };

        let result = proxy_helpers::resolve_virtual_download(
            &state.db,
            proxy_for_virtual,
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

        // Always serve npm virtual-repo tarballs as `application/gzip`,
        // overriding whatever content type the proxy-cache sidecar recorded
        // for the cached member artifact (see `npm_virtual_tarball_content_type`).
        return Ok(build_tarball_response_stream(
            result.body,
            filename,
            npm_virtual_tarball_content_type(result.content_type),
            result.content_length,
        ));
    }

    // For local/staged repos, find artifact by filename. Include the package
    // name in the path match to avoid returning a different package's tarball
    // when two packages share the same filename (e.g. @types/mdurl and mdurl
    // both produce mdurl-2.0.0.tgz).
    //
    // Escape `%` and `_` in user-supplied package_name and filename so they
    // are treated as literals; the `/%/` separator remains a wildcard.
    // ESCAPE '\' on the SQL side selects backslash as the escape character.
    // See `super::escape_like_literal`.
    let path_pattern = format!(
        "{}/%/{}",
        super::escape_like_literal(package_name),
        super::escape_like_literal(filename)
    );
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 ESCAPE '\'
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

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(build_tarball_response_stream(
        stream,
        filename,
        None,
        Some(artifact.size_bytes as u64),
    ))
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
    /// The `dist-tags` object from the publish body (e.g. `{"latest": "1.0.0"}`,
    /// or `{"next": "2.0.0-rc.1"}` for `npm publish --tag next`).
    dist_tags: serde_json::Map<String, serde_json::Value>,
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

    // npm sends the tag being published in `dist-tags` (default `latest`, or the
    // value of `--tag <tag>`). Capture it so it can be persisted (issue #1543).
    let dist_tags = payload
        .get("dist-tags")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    Ok(ParsedNpmPublish {
        versions,
        dist_tags,
    })
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

    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Npm,
        repo_id,
        &artifact_path,
        &ver.sha256,
    )
    .await
    .map_err(|e| e.into_response())?;

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

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo_id, artifact_id)
        .await;

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
    // GHSA-vvc3-h39c-mrq5: read-scoped API tokens were being accepted on
    // `npm publish`. Enforce the write scope before falling through to the
    // Bearer-fallback helper.
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write")?;
    let user_id =
        require_auth_with_bearer_fallback(auth, headers, &state.db, &state.config, "npm").await?;
    let repo = resolve_npm_repo(&state.db, repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

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

    // Persist custom dist-tags from the publish body into npm_dist_tags
    // (one row per repository_id+name; jsonb `||` overwrites matching keys).
    //
    // We deliberately DROP `latest` here. A plain `npm publish` always sends
    // {"latest": "<this version>"}, so persisting it verbatim would pin
    // `latest` to the just-published version — including a prerelease published
    // without `--tag` (e.g. `2.0.0-rc.1`), which is exactly the bug #1543
    // targets. `latest` is computed by semver in build_npm_metadata_response
    // (highest non-prerelease); an explicit `npm dist-tag add <pkg>@<v> latest`
    // (dist_tags_put) still sets it deterministically.
    let mut publish_tags = parsed.dist_tags.clone();
    publish_tags.remove("latest");
    if !publish_tags.is_empty() {
        let tags_value = serde_json::Value::Object(publish_tags);
        let _ = sqlx::query(
            "INSERT INTO npm_dist_tags (repository_id, name, tags) VALUES ($1, $2, $3::jsonb) \
             ON CONFLICT (repository_id, name) DO UPDATE \
             SET tags = npm_dist_tags.tags || EXCLUDED.tags, updated_at = NOW()",
        )
        .bind(repo.id)
        .bind(package_name)
        .bind(&tags_value)
        .execute(&state.db)
        .await;
    }

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    invalidate_packument_caches(state, repo.id, repo_key, package_name).await;

    Ok(build_json_metadata_response(
        serde_json::to_string(&serde_json::json!({"ok": true})).unwrap(),
    ))
}

// ---------------------------------------------------------------------------
// dist-tags endpoints (`npm dist-tag ls/add/rm`)
// ---------------------------------------------------------------------------

/// `GET /npm/{repo}/-/package/{pkg}/dist-tags` — list the package's dist-tags.
///
/// Delegates to the packument path so local, virtual and remote repos all
/// resolve consistently, then returns just its `dist-tags` object.
async fn dist_tags_get(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;

    // dist-tags are present in both the full and abbreviated packument, but we
    // parse the response body ourselves below; request the full packument so the
    // shape is stable regardless of any Accept header on the request.
    let resp = get_package_metadata(&state, &repo_key, &package, base_url.as_str(), false).await?;
    if !resp.status().is_success() {
        return Ok(resp);
    }
    #[allow(clippy::disallowed_methods)]
    // STREAMING-EXEMPT: capped-metadata read (upstream index/advisory/packument, not an artifact blob); bounded response buffered; tracked under #1608
    let body_bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to read packument body: {}", e)).into_response()
        })?;
    let packument: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        AppError::Internal(format!("Failed to parse packument JSON: {}", e)).into_response()
    })?;
    let dist_tags = packument
        .get("dist-tags")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    Ok(build_json_metadata_response(
        serde_json::to_string(&dist_tags).unwrap(),
    ))
}

/// `PUT /npm/{repo}/-/package/{pkg}/dist-tags/{tag}` — point `tag` at a version
/// (`npm dist-tag add pkg@ver tag`). The body is a JSON string of the version.
async fn dist_tags_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, package, tag)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write")?;
    let _user_id =
        require_auth_with_bearer_fallback(auth, &headers, &state.db, &state.config, "npm").await?;
    let repo = resolve_npm_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if tag.is_empty() {
        return Err(
            AppError::Validation("dist-tag name must not be empty".to_string()).into_response(),
        );
    }

    // Body is a bare JSON string, e.g. "1.2.3".
    let version = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| {
            AppError::Validation("dist-tag body must be a JSON version string".to_string())
                .into_response()
        })?;

    // The target version must exist in this repo for this package.
    let existing: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM artifacts \
         WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
    )
    .bind(repo.id)
    .bind(&package)
    .bind(&version)
    .fetch_one(&state.db)
    .await
    .map_err(map_db_err)?;
    if existing == 0 {
        return Err(
            AppError::NotFound(format!("Version {} of {} not found", version, package))
                .into_response(),
        );
    }

    let mut patch = serde_json::Map::new();
    patch.insert(tag.clone(), serde_json::Value::String(version));
    let patch_value = serde_json::Value::Object(patch);
    // Upsert the (repository_id, name) row — the version-existence check above
    // already 404s a tag pointed at a nonexistent version, and the package's
    // dist-tags row may not exist yet (first tag for the package).
    sqlx::query(
        "INSERT INTO npm_dist_tags (repository_id, name, tags) VALUES ($1, $2, $3::jsonb) \
         ON CONFLICT (repository_id, name) DO UPDATE \
         SET tags = npm_dist_tags.tags || EXCLUDED.tags, updated_at = NOW()",
    )
    .bind(repo.id)
    .bind(&package)
    .bind(&patch_value)
    .execute(&state.db)
    .await
    .map_err(map_db_err)?;

    invalidate_packument_caches(&state, repo.id, &repo_key, &package).await;

    Ok(build_json_metadata_response(
        serde_json::to_string(&serde_json::json!({"ok": true})).unwrap(),
    ))
}

/// `DELETE /npm/{repo}/-/package/{pkg}/dist-tags/{tag}` — remove a dist-tag.
/// `latest` cannot be removed (a package must always have a `latest`).
async fn dist_tags_delete(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, package, tag)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let package = normalize_package_name(&package);
    validate_package_name(&package)?;
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write")?;
    let _user_id =
        require_auth_with_bearer_fallback(auth, &headers, &state.db, &state.config, "npm").await?;
    let repo = resolve_npm_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if tag == "latest" {
        return Err(
            AppError::Validation("the 'latest' dist-tag cannot be removed".to_string())
                .into_response(),
        );
    }

    let _ = sqlx::query(
        "UPDATE npm_dist_tags SET tags = tags - $1, updated_at = NOW() \
         WHERE repository_id = $2 AND name = $3",
    )
    .bind(&tag)
    .bind(repo.id)
    .bind(&package)
    .execute(&state.db)
    .await
    .map_err(map_db_err)?;

    invalidate_packument_caches(&state, repo.id, &repo_key, &package).await;

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

// ---------------------------------------------------------------------------
// Abbreviated ("corgi") install metadata. Format reference:
// https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md
// ---------------------------------------------------------------------------

/// Media type for the abbreviated install document.
const NPM_ABBREVIATED_CONTENT_TYPE: &str = "application/vnd.npm.install-v1+json";

/// True when the client's `Accept` header requests the abbreviated document.
fn wants_abbreviated_metadata(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains(NPM_ABBREVIATED_CONTENT_TYPE))
}

/// Version-object keys kept in the abbreviated document. Matches the field set
/// registry.npmjs.org serves for `application/vnd.npm.install-v1+json`.
const ABBREVIATED_VERSION_KEYS: &[&str] = &[
    "name",
    "version",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bin",
    "dist",
    "engines",
    "_hasShrinkwrap",
    "hasInstallScript",
    "deprecated",
    "os",
    "cpu",
    "libc",
    "acceptDependencies",
    "funding",
];

/// Transform a full packument into the abbreviated install document.
fn abbreviate_packument(full: &serde_json::Value) -> serde_json::Value {
    let obj = match full.as_object() {
        Some(o) => o,
        // Non-object: pass through unchanged.
        None => return full.clone(),
    };

    let mut out = serde_json::Map::new();

    if let Some(name) = obj.get("name") {
        out.insert("name".to_string(), name.clone());
    }
    if let Some(dist_tags) = obj.get("dist-tags") {
        out.insert("dist-tags".to_string(), dist_tags.clone());
    }

    // Fall back to `time.modified` when top-level `modified` is absent.
    let modified = obj
        .get("modified")
        .cloned()
        .or_else(|| obj.get("time").and_then(|t| t.get("modified")).cloned());
    if let Some(modified) = modified {
        out.insert("modified".to_string(), modified);
    }

    let mut abbreviated_versions = serde_json::Map::new();
    if let Some(versions) = obj.get("versions").and_then(|v| v.as_object()) {
        for (version, version_data) in versions {
            abbreviated_versions.insert(version.clone(), abbreviate_version(version_data));
        }
    }
    out.insert(
        "versions".to_string(),
        serde_json::Value::Object(abbreviated_versions),
    );

    serde_json::Value::Object(out)
}

/// Reduce a single version object to the abbreviated key set.
fn abbreviate_version(version_data: &serde_json::Value) -> serde_json::Value {
    let Some(obj) = version_data.as_object() else {
        return version_data.clone();
    };
    let mut out = serde_json::Map::new();
    for &key in ABBREVIATED_VERSION_KEYS {
        if let Some(value) = obj.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    serde_json::Value::Object(out)
}

/// Serialize a packument as a metadata response, abbreviating first when requested.
fn respond_with_packument(value: serde_json::Value, want_abbreviated: bool) -> Response {
    if want_abbreviated {
        let abbreviated = abbreviate_packument(&value);
        return build_ok_response(
            NPM_ABBREVIATED_CONTENT_TYPE,
            serde_json::to_string(&abbreviated).expect("packument serialization is infallible"),
        );
    }
    build_json_metadata_response(
        serde_json::to_string(&value).expect("packument serialization is infallible"),
    )
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
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
    // abbreviated metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_abbreviate_packument_strips_non_install_fields() {
        let full = serde_json::json!({
            "name": "example",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "# Example\nlots of prose",
            "maintainers": [{ "name": "alice", "email": "alice@example.com" }],
            "users": { "bob": true },
            "_id": "example",
            "_rev": "3-abc",
            "description": "a top-level description",
            "time": { "modified": "2024-01-02T03:04:05.000Z", "1.0.0": "2024-01-01T00:00:00.000Z" },
            "versions": {
                "1.0.0": {
                    "name": "example",
                    "version": "1.0.0",
                    "description": "per-version description",
                    "dependencies": { "left-pad": "^1.3.0" },
                    "devDependencies": { "jest": "^29.0.0" },
                    "scripts": { "test": "jest", "postinstall": "node ./hack.js" },
                    "dist": {
                        "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                        "integrity": "sha512-deadbeef"
                    },
                    "engines": { "node": ">=18" },
                    "_npmUser": { "name": "alice" },
                    "gitHead": "abcdef",
                    "readme": "per-version readme",
                    "maintainers": [{ "name": "alice" }],
                    "keywords": ["a", "b"]
                }
            }
        });

        let abbreviated = abbreviate_packument(&full);
        let obj = abbreviated.as_object().expect("abbreviated is an object");

        // Top level: kept.
        assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("example"));
        assert!(obj.contains_key("dist-tags"));
        assert!(obj.contains_key("versions"));
        // `modified` derived from `time.modified`.
        assert_eq!(
            obj.get("modified").and_then(|v| v.as_str()),
            Some("2024-01-02T03:04:05.000Z")
        );
        // Top level: dropped.
        assert!(!obj.contains_key("readme"));
        assert!(!obj.contains_key("maintainers"));
        assert!(!obj.contains_key("users"));
        assert!(!obj.contains_key("_id"));
        assert!(!obj.contains_key("_rev"));
        assert!(!obj.contains_key("description"));
        assert!(!obj.contains_key("time"));

        // Per-version: kept install-relevant fields.
        let ver = abbreviated["versions"]["1.0.0"]
            .as_object()
            .expect("version object");
        assert!(ver.contains_key("name"));
        assert!(ver.contains_key("version"));
        assert!(ver.contains_key("dependencies"));
        assert!(ver.contains_key("dist"));
        assert!(ver.contains_key("engines"));
        // devDependencies is kept: registry.npmjs.org includes it in the
        // abbreviated document, and this proxy mirrors that.
        assert!(ver.contains_key("devDependencies"));
        // Per-version: dropped (non-install fields).
        assert!(!ver.contains_key("scripts"));
        assert!(!ver.contains_key("description"));
        assert!(!ver.contains_key("_npmUser"));
        assert!(!ver.contains_key("gitHead"));
        assert!(!ver.contains_key("readme"));
        assert!(!ver.contains_key("maintainers"));
        assert!(!ver.contains_key("keywords"));
    }

    #[test]
    fn test_abbreviate_packument_prefers_top_level_modified() {
        let full = serde_json::json!({
            "name": "example",
            "dist-tags": {},
            "modified": "2025-05-05T00:00:00.000Z",
            "time": { "modified": "2024-01-01T00:00:00.000Z" },
            "versions": {}
        });
        let abbreviated = abbreviate_packument(&full);
        assert_eq!(
            abbreviated.get("modified").and_then(|v| v.as_str()),
            Some("2025-05-05T00:00:00.000Z")
        );
    }

    #[test]
    fn test_abbreviate_packument_scoped_name_keeps_versions() {
        let full = serde_json::json!({
            "name": "@scope/pkg",
            "dist-tags": { "latest": "2.1.0" },
            "versions": {
                "2.1.0": {
                    "name": "@scope/pkg",
                    "version": "2.1.0",
                    "dependencies": { "left-pad": "^1.0.0" },
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.1.0.tgz",
                        "integrity": "sha512-abc"
                    },
                    "readme": "drop me"
                }
            }
        });

        let abbreviated = abbreviate_packument(&full);
        assert_eq!(abbreviated["name"], "@scope/pkg");
        let versions = abbreviated["versions"]
            .as_object()
            .expect("versions object");
        assert!(versions.contains_key("2.1.0"));
        let ver = &abbreviated["versions"]["2.1.0"];
        assert!(ver.get("dist").is_some());
        assert!(ver.get("readme").is_none());
    }

    #[test]
    fn test_abbreviate_packument_no_versions_key_yields_empty_object() {
        let full = serde_json::json!({
            "name": "no-versions",
            "dist-tags": {}
        });

        let abbreviated = abbreviate_packument(&full);
        let versions = abbreviated["versions"]
            .as_object()
            .expect("versions is an object");
        assert!(versions.is_empty());
    }

    #[test]
    fn test_abbreviate_packument_no_modified_anywhere_omits_key() {
        let full = serde_json::json!({
            "name": "no-modified",
            "dist-tags": {},
            "versions": {}
        });

        let abbreviated = abbreviate_packument(&full);
        let obj = abbreviated.as_object().expect("abbreviated is an object");
        assert!(!obj.contains_key("modified"));
    }

    #[test]
    fn test_abbreviate_version_minimal_object_keeps_dist_only() {
        let version_data = serde_json::json!({
            "name": "minimal",
            "version": "1.2.3",
            "dist": {
                "tarball": "https://registry.npmjs.org/minimal/-/minimal-1.2.3.tgz",
                "integrity": "sha512-xyz"
            }
        });

        let abbreviated = abbreviate_version(&version_data);
        let obj = abbreviated.as_object().expect("version is an object");
        assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("minimal"));
        assert_eq!(obj.get("version").and_then(|v| v.as_str()), Some("1.2.3"));
        assert_eq!(
            obj["dist"]["tarball"].as_str(),
            Some("https://registry.npmjs.org/minimal/-/minimal-1.2.3.tgz")
        );
        assert_eq!(obj["dist"]["integrity"].as_str(), Some("sha512-xyz"));
        // No keys invented beyond what was present.
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn test_abbreviate_version_preserves_rewritten_proxy_tarball() {
        let proxy_tarball = "http://localhost:8080/npm/npm-virtual/lodash/-/lodash-4.17.21.tgz";
        let version_data = serde_json::json!({
            "name": "lodash",
            "version": "4.17.21",
            "dist": {
                "tarball": proxy_tarball,
                "integrity": "sha512-rewritten"
            }
        });

        let abbreviated = abbreviate_version(&version_data);
        assert_eq!(
            abbreviated["dist"]["tarball"].as_str(),
            Some(proxy_tarball),
            "rewritten proxy tarball URL must survive abbreviation verbatim"
        );
    }

    #[test]
    fn test_wants_abbreviated_metadata() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(!wants_abbreviated_metadata(&headers));

        headers.insert(
            axum::http::header::ACCEPT,
            "application/json".parse().unwrap(),
        );
        assert!(!wants_abbreviated_metadata(&headers));

        headers.insert(
            axum::http::header::ACCEPT,
            "application/vnd.npm.install-v1+json".parse().unwrap(),
        );
        assert!(wants_abbreviated_metadata(&headers));

        // npm sends both, comma-separated.
        headers.insert(
            axum::http::header::ACCEPT,
            "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*; q=0.1"
                .parse()
                .unwrap(),
        );
        assert!(wants_abbreviated_metadata(&headers));
    }

    /// Regression for #1931: a request advertising the abbreviated ("corgi")
    /// `Accept` must receive the abbreviated install document, while the default
    /// request still gets the full packument. Before the fix the `Accept` header
    /// was ignored and the full packument (`application/json`) was always
    /// returned, so the first assertion fails on the pre-fix code. Skips when no
    /// test database is configured.
    #[tokio::test]
    async fn test_abbreviated_accept_returns_corgi_document() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let path = "widget/1.0.0/widget-1.0.0.tgz".to_string();
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &format!("npm/{path}"),
            &path,
            "widget",
            "1.0.0",
            "application/gzip",
            Bytes::from_static(b"tgz"),
            fx.user_id,
        )
        .await;

        let mut abbreviated_headers = HeaderMap::new();
        abbreviated_headers.insert(
            ACCEPT,
            axum::http::HeaderValue::from_static(NPM_ABBREVIATED_CONTENT_TYPE),
        );
        let abbreviated = super::get_package_metadata(
            &fx.state,
            &fx.repo_key,
            "widget",
            "http://localhost",
            super::wants_abbreviated_metadata(&abbreviated_headers),
        )
        .await;
        let full = super::get_package_metadata(
            &fx.state,
            &fx.repo_key,
            "widget",
            "http://localhost",
            super::wants_abbreviated_metadata(&HeaderMap::new()),
        )
        .await;

        fx.teardown().await;

        let abbreviated = abbreviated.unwrap_or_else(|r| r);
        assert_eq!(
            abbreviated
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(NPM_ABBREVIATED_CONTENT_TYPE),
            "abbreviated Accept must yield the abbreviated content type"
        );

        let full = full.unwrap_or_else(|r| r);
        assert_eq!(
            full.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "default request must still return the full packument"
        );

        let body = axum::body::to_bytes(abbreviated.into_body(), 1024 * 1024)
            .await
            .expect("read abbreviated body");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse abbreviated json");
        assert!(
            json["versions"]["1.0.0"]["dist"]["tarball"].is_string(),
            "abbreviated version keeps dist.tarball, got {json:?}"
        );
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
            promotion_only: false,
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
    // build_tarball_upstream_path (B7)
    //
    // Tarball URLs keep the scope separator as a literal `/`; only metadata
    // uses `%2F`. These pin that the tarball path is NOT percent-encoded so a
    // future refactor that routes it through `encode_package_name_for_upstream`
    // (which would 404 the remote-proxy tarball fetch) fails here.
    // -----------------------------------------------------------------------

    #[test]
    fn test_tarball_upstream_path_scoped_keeps_literal_slash() {
        let path = build_tarball_upstream_path("@e2escope/testpkg", "testpkg-1.0.0.tgz");
        assert_eq!(path, "@e2escope/testpkg/-/testpkg-1.0.0.tgz");
        assert!(
            !path.contains("%2F") && !path.contains("%2f"),
            "scoped tarball path must NOT encode the scope separator (B7); got {path}"
        );
    }

    #[test]
    fn test_tarball_upstream_path_unscoped() {
        assert_eq!(
            build_tarball_upstream_path("express", "express-4.18.2.tgz"),
            "express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_tarball_upstream_path_diverges_from_metadata_encoding() {
        // Metadata encodes the slash; tarballs must not. Pin that the two
        // helpers produce different shapes for the same scoped package so a
        // refactor cannot accidentally collapse them into one.
        let name = "@types/mdurl";
        let meta = encode_package_name_for_upstream(name);
        let tarball = build_tarball_upstream_path(name, "mdurl-2.0.0.tgz");
        assert_eq!(meta, "@types%2Fmdurl");
        assert_eq!(tarball, "@types/mdurl/-/mdurl-2.0.0.tgz");
        assert!(tarball.starts_with(&format!("{name}/-/")));
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
        let resp = build_npm_metadata_response(
            artifacts,
            package_name,
            base_url,
            repo_key,
            &serde_json::Map::new(),
            false,
        )
        .unwrap();
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

        let resp_unscoped = build_npm_metadata_response(
            &unscoped,
            "mdurl",
            "http://localhost:8080",
            "npm-hosted",
            &serde_json::Map::new(),
            false,
        )
        .unwrap();
        let resp_scoped = build_npm_metadata_response(
            &scoped,
            "@types/mdurl",
            "http://localhost:8080",
            "npm-hosted",
            &serde_json::Map::new(),
            false,
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

    #[tokio::test]
    async fn test_build_tarball_response_stream_sets_headers() {
        // The streaming tarball response (used for the get_stream download path)
        // must emit the gzip content-type (or the supplied upstream type), a
        // Content-Disposition with the filename, and Content-Length when known.
        use futures::StreamExt as _;
        let body: futures::stream::BoxStream<'static, crate::error::Result<Bytes>> =
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"tgz-bytes"))
            }));
        let resp = build_tarball_response_stream(body, "pkg-1.0.0.tgz", None, Some(9));
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(
            h.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some(NPM_TARBALL_CONTENT_TYPE)
        );
        assert_eq!(
            h.get("content-disposition").and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"pkg-1.0.0.tgz\"")
        );
        assert_eq!(
            h.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()),
            Some("9")
        );
        // Body must stream the supplied bytes verbatim.
        let collected = resp
            .into_body()
            .into_data_stream()
            .fold(Vec::new(), |mut acc, c| async move {
                acc.extend_from_slice(&c.unwrap());
                acc
            })
            .await;
        assert_eq!(&collected[..], b"tgz-bytes");
    }

    #[tokio::test]
    async fn test_build_tarball_response_stream_uses_upstream_ct_and_omits_length() {
        // An upstream-provided content-type wins over the default, and Content-
        // Length is omitted when unknown (chunked transfer).
        let body: futures::stream::BoxStream<'static, crate::error::Result<Bytes>> =
            Box::pin(futures::stream::iter(Vec::new()));
        let resp = build_tarball_response_stream(
            body,
            "x.tgz",
            Some("application/x-custom".to_string()),
            None,
        );
        let h = resp.headers();
        assert_eq!(
            h.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/x-custom")
        );
        assert!(h.get(CONTENT_LENGTH).is_none());
    }

    // -----------------------------------------------------------------------
    // Regression: virtual-repo tarball content-type override (#1774)
    // -----------------------------------------------------------------------

    #[test]
    fn test_npm_virtual_tarball_content_type_always_gzip() {
        // A Virtual npm repo serves tarballs out of a member's proxy cache.
        // Upstream registries (and stale error-page caches) frequently record
        // a non-gzip content type; the virtual download path must NOT leak that
        // through, or downstream SBOM/scanner tooling mis-detects the archive.
        // Regardless of the cached content type, the served type must be gzip,
        // matching the direct remote-repo path.
        for cached in [
            None,
            Some("application/octet-stream".to_string()),
            Some("text/html".to_string()),
            Some("application/gzip".to_string()),
        ] {
            assert_eq!(
                npm_virtual_tarball_content_type(cached),
                Some(NPM_TARBALL_CONTENT_TYPE.to_string()),
            );
        }
    }

    #[tokio::test]
    async fn test_virtual_tarball_response_overrides_octet_stream() {
        // End-to-end of the helper + response builder: an octet-stream cache
        // record must be served as application/gzip on the streaming response.
        let body: futures::stream::BoxStream<'static, crate::error::Result<Bytes>> =
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"tgz"))
            }));
        let ct = npm_virtual_tarball_content_type(Some("application/octet-stream".to_string()));
        let resp = build_tarball_response_stream(body, "is-array-1.0.1.tgz", ct, Some(3));
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(NPM_TARBALL_CONTENT_TYPE),
        );
    }

    // -----------------------------------------------------------------------
    // Regression tests for #1377 — scoped tarball remote-proxy flow.
    // -----------------------------------------------------------------------

    /// Regression: a Remote npm repo must be able to fetch a scoped-package
    /// tarball through the proxy. The upstream URL the proxy hits must be
    /// `@scope/pkg/-/{filename}` with the scope separator kept as a literal
    /// `/`. Unlike npm metadata (which encodes the separator as `%2F`),
    /// tarball routes expect `@scope` and `pkg` as separate path segments;
    /// percent-encoding the slash collapses them into one `@scope%2Fpkg`
    /// segment that no upstream tarball route matches, so the proxy fetch
    /// 404s. See `build_tarball_upstream_path` (B7 / #1377). The handler must
    /// also unwrap axum's path extractor correctly so the test request
    /// `/repo/@scope/pkg/-/file.tgz` reaches `download_scoped_tarball` (not
    /// the unscoped fallback).
    #[tokio::test]
    async fn test_remote_proxy_download_scoped_tarball_hits_encoded_upstream_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let tarball_bytes = b"\x1f\x8b\x08mock-scoped-tarball-bytes";

        // Upstream must see the scope separator as a literal `/`
        // (`@scope/pkg/-/file.tgz`), matching the canonical npm tarball
        // route. wiremock's `path` matcher receives the request path with
        // scope and package as separate segments; this is the shape
        // `build_tarball_upstream_path` produces (B7 / #1377).
        Mock::given(method("GET"))
            .and(path("/@e2escope/testpkg/-/testpkg-1.0.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(tarball_bytes.as_ref()),
            )
            .mount(&mock_server)
            .await;

        // Re-point the fixture's Remote repo at the mock upstream so the
        // proxy_fetch call lands on wiremock instead of the placeholder URL.
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);

        // Invoke the scoped-tarball handler directly. The router decodes
        // `%2F` on the way in, so we feed the canonical (unencoded) path
        // segments via the Path extractor.
        let result = super::download_scoped_tarball(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                fx.repo_key.clone(),
                "e2escope".to_string(),
                "testpkg".to_string(),
                "testpkg-1.0.0.tgz".to_string(),
            )),
        )
        .await;

        // Cleanup first so a panic does not leak DB state.
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
                panic!(
                    "Remote npm proxy must serve scoped tarball; \
                     download_scoped_tarball returned {status} (issue #1377)"
                );
            }
        };

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        assert_eq!(&body_bytes[..], tarball_bytes.as_ref());

        cleanup().await;
    }

    // #2192 / #1608 Phase 4c: an npm tarball larger than the old buffered cap
    // (LARGE_METADATA_MAX_BYTES = 16 MiB) must now STREAM with 200 instead of
    // 502, the outbound Content-Type must still be forced to application/gzip,
    // and the second request must be served WARM from the teed proxy cache
    // without a second upstream round-trip.
    #[tokio::test]
    async fn test_remote_proxy_streams_large_tarball_and_warms_cache() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        // 17 MiB > 16 MiB LARGE_METADATA_MAX_BYTES: 502s on the buffered path.
        let mut tarball_bytes = vec![0x1fu8, 0x8b, 0x08];
        tarball_bytes.resize(17 * 1024 * 1024, 0x7e);

        Mock::given(method("GET"))
            .and(path("/bigpkg/-/bigpkg-1.0.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(tarball_bytes.clone()),
            )
            // Warm-cache proof: fetched from upstream at most once across the
            // two requests below.
            .expect(1)
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);

        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        for i in 0..2 {
            // Before the second request, wait for the streaming write-back to
            // commit so the cache is deterministically WARM.
            if i == 1 {
                tdh::wait_for_cached_blob(&fx.storage_dir, tarball_bytes.len() as u64).await;
            }
            let result = super::download_tarball(
                axum::extract::State(state.clone()),
                axum::extract::Path((
                    fx.repo_key.clone(),
                    "bigpkg".to_string(),
                    "bigpkg-1.0.0.tgz".to_string(),
                )),
            )
            .await;

            let response = match result {
                Ok(r) => r,
                Err(r) => {
                    let status = r.status();
                    cleanup().await;
                    panic!("large tarball must stream with 200, got {status}");
                }
            };
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some(NPM_TARBALL_CONTENT_TYPE),
                "outbound tarball content type must be forced to application/gzip"
            );
            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read streamed body");
            assert_eq!(body_bytes.len(), tarball_bytes.len());
        }

        // `.expect(1)` on the mock is verified on server drop.
        drop(mock_server);
        cleanup().await;
    }

    // -----------------------------------------------------------------------
    // npm audit advisories endpoint (issue #1400)
    // -----------------------------------------------------------------------

    /// The empty `advisories/bulk` response must be a JSON object so npm
    /// parses it as "zero advisories" instead of bailing out. An array or
    /// non-JSON body causes the npm client to print a parse error.
    #[test]
    fn test_empty_advisories_bulk_response_shape() {
        let resp = super::empty_advisories_bulk_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            ct.contains("application/json"),
            "advisories/bulk must be JSON, got {ct}"
        );

        let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 64 * 1024))
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert!(
            parsed.is_object(),
            "advisories/bulk response must be a JSON object, got {parsed:?}"
        );
        assert_eq!(
            parsed.as_object().map(|m| m.len()).unwrap_or(0),
            0,
            "empty response must have no keys"
        );
    }

    /// The empty `audits/quick` response must include `actions`, `advisories`,
    /// `muted`, and `metadata.vulnerabilities` keys so the legacy npm v6 audit
    /// command does not error out on missing fields.
    #[test]
    fn test_empty_audits_quick_response_shape() {
        let resp = super::empty_audits_quick_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 64 * 1024))
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert!(parsed.get("actions").map(|v| v.is_array()).unwrap_or(false));
        assert!(parsed
            .get("advisories")
            .map(|v| v.is_object())
            .unwrap_or(false));
        assert!(parsed.get("muted").map(|v| v.is_array()).unwrap_or(false));
        let vulns = parsed
            .pointer("/metadata/vulnerabilities")
            .expect("metadata.vulnerabilities required");
        for level in ["info", "low", "moderate", "high", "critical"] {
            assert_eq!(
                vulns.get(level).and_then(|v| v.as_u64()),
                Some(0),
                "level {level} must be present and zero"
            );
        }
    }

    /// Integration: a Hosted (Local) npm repo must serve `npm audit` with an
    /// empty advisories object instead of returning 404. Without this, npm
    /// audit fails the entire CI build. Tests the full router path so the
    /// route table actually includes the new endpoint.
    #[tokio::test]
    async fn test_local_repo_advisories_bulk_returns_empty_object() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let app = tdh::router_anon(super::router(), state);

        let uri = format!("/{}/-/npm/v1/security/advisories/bulk", fx.repo_key);
        let body = serde_json::json!({
            "express": ["4.17.0"],
        })
        .to_string();
        let req = tdh::post(uri, "application/json", Bytes::from(body));
        let (status, bytes) = tdh::send(app, req).await;

        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        if status != StatusCode::OK {
            cleanup().await;
            panic!("Local npm repo must answer audit with 200, got {status}");
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response must be JSON");
        assert!(
            parsed.is_object() && parsed.as_object().unwrap().is_empty(),
            "Local repo audit must return empty object, got {parsed:?}"
        );

        cleanup().await;
    }

    /// Integration: a Remote npm repo must forward the audit POST body
    /// verbatim to the configured upstream registry and return the upstream
    /// response body to the client. Mirrors the `npm audit` flow in
    /// production where artifact-keeper is configured as the proxy and the
    /// upstream is npmjs.org.
    #[tokio::test]
    async fn test_remote_repo_advisories_bulk_proxies_to_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let upstream_response = serde_json::json!({
            "express": [
                {
                    "id": 1234,
                    "url": "https://github.com/advisories/GHSA-xxxx",
                    "title": "Test advisory",
                    "severity": "high",
                    "vulnerable_versions": "<4.17.3",
                }
            ]
        });
        let client_request = serde_json::json!({"express": ["4.17.0"]});

        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .and(body_json(client_request.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(upstream_response.clone()),
            )
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let app = tdh::router_anon(super::router(), state);

        let uri = format!("/{}/-/npm/v1/security/advisories/bulk", fx.repo_key);
        let req = tdh::post(
            uri,
            "application/json",
            Bytes::from(client_request.to_string()),
        );
        let (status, bytes) = tdh::send(app, req).await;

        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        if status != StatusCode::OK {
            cleanup().await;
            panic!("Remote npm repo must proxy audit to upstream with 200, got {status}");
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response must be JSON");
        assert_eq!(
            parsed, upstream_response,
            "Remote audit response must be the upstream payload verbatim"
        );

        cleanup().await;
    }

    /// Integration: a Remote npm repo whose upstream is unreachable must
    /// degrade gracefully and return an empty advisories object so the
    /// developer's `npm audit` command still exits cleanly. This is the
    /// fallback contract callers depend on when the upstream is offline.
    #[tokio::test]
    async fn test_remote_repo_advisories_bulk_falls_back_when_upstream_down() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        // Point at a localhost port that nothing is listening on. This is
        // SSRF-safe through default_client because the request itself never
        // completes; we just need a guaranteed connection failure.
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind("http://127.0.0.1:1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let app = tdh::router_anon(super::router(), state);

        let uri = format!("/{}/-/npm/v1/security/advisories/bulk", fx.repo_key);
        let req = tdh::post(
            uri,
            "application/json",
            Bytes::from(r#"{"express":["4.17.0"]}"#.as_bytes().to_vec()),
        );
        let (status, bytes) = tdh::send(app, req).await;

        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        if status != StatusCode::OK {
            cleanup().await;
            panic!(
                "Remote npm repo must degrade to empty advisories on upstream \
                 failure, got {status}"
            );
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response must be JSON");
        assert!(
            parsed.is_object() && parsed.as_object().unwrap().is_empty(),
            "fallback response must be an empty object, got {parsed:?}"
        );

        cleanup().await;
    }

    // -----------------------------------------------------------------------
    // dist-tags (#1543): `latest` derivation + custom-tag persistence/emit.
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_latest_prefers_stable_over_prerelease() {
        // 2.0.0-rc.1 is created last, but `latest` must be the highest stable.
        let versions = vec![
            "1.0.0".to_string(),
            "1.1.0".to_string(),
            "2.0.0-rc.1".to_string(),
        ];
        assert_eq!(derive_latest_version(&versions), Some("1.1.0".to_string()));
    }

    #[test]
    fn test_derive_latest_picks_highest_stable_numerically() {
        // 1.10.0 > 1.2.0 numerically (not lexically).
        let versions = vec![
            "1.2.0".to_string(),
            "1.10.0".to_string(),
            "1.3.0".to_string(),
        ];
        assert_eq!(derive_latest_version(&versions), Some("1.10.0".to_string()));
    }

    #[test]
    fn test_derive_latest_all_prerelease_falls_back_to_highest_core() {
        let versions = vec![
            "2.0.0-rc.1".to_string(),
            "2.0.0-rc.2".to_string(),
            "1.9.0-beta".to_string(),
        ];
        // No stable version exists -> highest core, later-listed wins the tie.
        assert_eq!(
            derive_latest_version(&versions),
            Some("2.0.0-rc.2".to_string())
        );
    }

    #[test]
    fn test_derive_latest_non_semver_falls_back_to_last() {
        let versions = vec!["alpha".to_string(), "nightly".to_string()];
        assert_eq!(
            derive_latest_version(&versions),
            Some("nightly".to_string())
        );
    }

    #[test]
    fn test_derive_latest_ignores_build_metadata() {
        let versions = vec!["1.0.0+build.5".to_string(), "1.0.1".to_string()];
        assert_eq!(derive_latest_version(&versions), Some("1.0.1".to_string()));
    }

    #[test]
    fn test_derive_latest_empty_is_none() {
        assert_eq!(derive_latest_version(&[]), None);
    }

    /// #1543 end-to-end: a custom dist-tag is served in the packument and
    /// `latest` is the highest non-prerelease version, not the most recently
    /// created one. Skips when no test database is configured.
    #[tokio::test]
    async fn test_packument_dist_tags_served_and_latest_is_stable() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let repo = fx.repo_info("local", None);

        // Seed three versions; the prerelease is created LAST (the worst case
        // for the old recency-based `latest`).
        for ver in ["1.0.0", "1.1.0", "2.0.0-rc.1"] {
            let path = format!("widget/{ver}/widget-{ver}.tgz");
            let storage_key = format!("npm/{path}");
            tdh::seed_artifact(
                &fx.state,
                &fx.pool,
                &repo,
                &storage_key,
                &path,
                "widget",
                ver,
                "application/gzip",
                Bytes::from_static(b"tgz"),
                fx.user_id,
            )
            .await;
        }

        // Record a custom `next` tag as `npm publish --tag next` would, in the
        // dedicated per-package table (PK repository_id, name). Note there are
        // THREE versions seeded above: the per-(repo,name) row makes the read
        // single-row regardless of version count.
        sqlx::query("INSERT INTO npm_dist_tags (repository_id, name, tags) VALUES ($1, $2, $3)")
            .bind(fx.repo_id)
            .bind("widget")
            .bind(serde_json::json!({ "next": "2.0.0-rc.1" }))
            .execute(&fx.pool)
            .await
            .expect("seed npm_dist_tags");

        let result = super::get_package_metadata(
            &fx.state,
            &fx.repo_key,
            "widget",
            "http://localhost",
            false,
        )
        .await;

        // Tear down before asserting so a failure never leaks DB/storage state.
        fx.teardown().await;

        let resp = match result {
            Ok(r) => r,
            Err(r) => panic!("get_package_metadata failed: HTTP {}", r.status()),
        };
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read packument body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse packument json");
        let dist_tags = &json["dist-tags"];

        // Custom tag preserved...
        assert_eq!(dist_tags["next"], "2.0.0-rc.1");
        // ...and `latest` is the highest STABLE version, not the prerelease.
        assert_eq!(dist_tags["latest"], "1.1.0");
    }

    /// #1543 finding-2: a plain `npm publish` of a PRERELEASE must not pin
    /// `latest` to it. Every publish body carries `"dist-tags":{"latest":
    /// "<this version>"}`; the publish path drops `latest` so it stays the
    /// semver-derived highest stable. Skips when no test database is configured.
    #[tokio::test]
    async fn test_publish_prerelease_does_not_clobber_latest() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let repo = fx.repo_info("local", None);

        // A stable release already exists.
        let path = "widget/1.1.0/widget-1.1.0.tgz".to_string();
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &format!("npm/{path}"),
            &path,
            "widget",
            "1.1.0",
            "application/gzip",
            Bytes::from_static(b"tgz"),
            fx.user_id,
        )
        .await;

        // `npm publish` of a prerelease with NO explicit --tag: the client
        // still sends `dist-tags: { latest: <this version> }`.
        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let publish_body = serde_json::json!({
            "name": "widget",
            "versions": {
                "2.0.0-rc.1": { "name": "widget", "version": "2.0.0-rc.1" }
            },
            "_attachments": {
                "widget-2.0.0-rc.1.tgz": { "data": tarball_b64 }
            },
            "dist-tags": { "latest": "2.0.0-rc.1" }
        });
        let publish = super::publish_package(
            &fx.state,
            Some(tdh::make_auth(fx.user_id, &fx.username)),
            &fx.repo_key,
            "widget",
            &HeaderMap::new(),
            Bytes::from(serde_json::to_vec(&publish_body).expect("serialize publish body")),
        )
        .await;

        // Read back the stored tags and the served packument.
        let stored = super::fetch_npm_dist_tags(&fx.pool, fx.repo_id, "widget").await;
        let meta = super::get_package_metadata(
            &fx.state,
            &fx.repo_key,
            "widget",
            "http://localhost",
            false,
        )
        .await;

        fx.teardown().await;

        assert!(
            publish.is_ok(),
            "prerelease publish should succeed: {:?}",
            publish.err().map(|r| r.status())
        );
        // The publish-body `latest` was dropped, never persisted.
        assert!(
            !stored.contains_key("latest"),
            "publish must not persist `latest` from the body; stored: {stored:?}"
        );
        let resp = meta.expect("packument");
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read packument body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse packument json");
        // `latest` resolves to the highest STABLE (1.1.0), not the just-published
        // prerelease — the whole point of #1543.
        assert_eq!(
            json["dist-tags"]["latest"], "1.1.0",
            "latest must stay the highest stable, not the published prerelease"
        );
    }

    /// #2022: a direct `npm publish` to a `promotion_only` repository must be
    /// rejected with 409 CONFLICT; the same publish to a normal repository must
    /// still succeed. Skips when no test database is configured.
    #[tokio::test]
    async fn test_publish_blocked_on_promotion_only_repo() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let publish_body = serde_json::json!({
            "name": "widget",
            "versions": { "1.0.0": { "name": "widget", "version": "1.0.0" } },
            "_attachments": { "widget-1.0.0.tgz": { "data": tarball_b64 } },
        });
        let body_bytes =
            Bytes::from(serde_json::to_vec(&publish_body).expect("serialize publish body"));

        // Flag the repo promotion_only -> direct publish is rejected with 409.
        fx.set_promotion_only(true).await;
        let blocked = super::publish_package(
            &fx.state,
            Some(tdh::make_auth(fx.user_id, &fx.username)),
            &fx.repo_key,
            "widget",
            &HeaderMap::new(),
            body_bytes.clone(),
        )
        .await;

        // Clear the flag -> the same publish succeeds.
        fx.set_promotion_only(false).await;
        let allowed = super::publish_package(
            &fx.state,
            Some(tdh::make_auth(fx.user_id, &fx.username)),
            &fx.repo_key,
            "widget",
            &HeaderMap::new(),
            body_bytes,
        )
        .await;

        fx.teardown().await;

        let err = blocked.expect_err("publish to promotion_only repo must be rejected");
        assert_eq!(
            err.status(),
            StatusCode::CONFLICT,
            "promotion_only direct publish must return 409"
        );
        assert!(
            allowed.is_ok(),
            "publish to a normal repo must still succeed: {:?}",
            allowed.err().map(|r| r.status())
        );
    }

    #[test]
    fn test_parse_npm_publish_payload_extracts_dist_tags() {
        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let body = serde_json::json!({
            "name": "widget",
            "versions": {
                "2.0.0-rc.1": { "name": "widget", "version": "2.0.0-rc.1" }
            },
            "_attachments": {
                "widget-2.0.0-rc.1.tgz": { "data": tarball_b64 }
            },
            "dist-tags": { "next": "2.0.0-rc.1" }
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let parsed = parse_npm_publish_payload(&bytes, "widget").expect("payload should parse");
        assert_eq!(
            parsed.dist_tags.get("next").and_then(|v| v.as_str()),
            Some("2.0.0-rc.1")
        );
        assert_eq!(parsed.versions.len(), 1);
    }

    /// #1543: the dist-tags endpoints backing `npm dist-tag add/ls/rm`.
    /// Skips when no test database is configured.
    #[tokio::test]
    async fn test_dist_tags_endpoints_put_get_delete() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let repo = fx.repo_info("local", None);

        // Seed two versions so the PUT existence check passes.
        for ver in ["1.0.0", "2.0.0-rc.1"] {
            let path = format!("widget/{ver}/widget-{ver}.tgz");
            let storage_key = format!("npm/{path}");
            tdh::seed_artifact(
                &fx.state,
                &fx.pool,
                &repo,
                &storage_key,
                &path,
                "widget",
                ver,
                "application/gzip",
                Bytes::from_static(b"tgz"),
                fx.user_id,
            )
            .await;
        }
        // No npm_dist_tags pre-seed: dist_tags_put UPSERTs the row itself, and
        // its target-version check reads `artifacts` (seeded above), so the two
        // real versions are all the setup the handlers need.

        // PUT next -> 2.0.0-rc.1 (a real version)
        let put_next = super::dist_tags_put(
            axum::extract::State(fx.state.clone()),
            axum::Extension(Some(tdh::make_auth(fx.user_id, &fx.username))),
            axum::extract::Path((
                fx.repo_key.clone(),
                "widget".to_string(),
                "next".to_string(),
            )),
            HeaderMap::new(),
            Bytes::from_static(b"\"2.0.0-rc.1\""),
        )
        .await;

        // PUT a tag pointing at a version that does not exist -> error.
        let put_missing = super::dist_tags_put(
            axum::extract::State(fx.state.clone()),
            axum::Extension(Some(tdh::make_auth(fx.user_id, &fx.username))),
            axum::extract::Path((
                fx.repo_key.clone(),
                "widget".to_string(),
                "beta".to_string(),
            )),
            HeaderMap::new(),
            Bytes::from_static(b"\"9.9.9\""),
        )
        .await;

        // GET the dist-tags map.
        let get_tags = super::dist_tags_get(
            axum::extract::State(fx.state.clone()),
            axum::extract::Path((fx.repo_key.clone(), "widget".to_string())),
            RequestBaseUrl("http://localhost".to_string()),
        )
        .await;

        // DELETE the custom tag.
        let del_next = super::dist_tags_delete(
            axum::extract::State(fx.state.clone()),
            axum::Extension(Some(tdh::make_auth(fx.user_id, &fx.username))),
            axum::extract::Path((
                fx.repo_key.clone(),
                "widget".to_string(),
                "next".to_string(),
            )),
            HeaderMap::new(),
        )
        .await;

        // `latest` cannot be deleted.
        let del_latest = super::dist_tags_delete(
            axum::extract::State(fx.state.clone()),
            axum::Extension(Some(tdh::make_auth(fx.user_id, &fx.username))),
            axum::extract::Path((
                fx.repo_key.clone(),
                "widget".to_string(),
                "latest".to_string(),
            )),
            HeaderMap::new(),
        )
        .await;

        fx.teardown().await;

        assert!(
            put_next.is_ok(),
            "PUT of an existing version should succeed"
        );
        assert!(
            put_missing.is_err(),
            "PUT of a nonexistent version should fail"
        );

        // GET returns the custom tag plus a derived stable `latest`
        // (1.0.0 is stable; 2.0.0-rc.1 is a prerelease, so latest != next).
        let resp = match get_tags {
            Ok(r) => r,
            Err(r) => panic!("dist_tags_get failed: HTTP {}", r.status()),
        };
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read dist-tags body");
        let tags: serde_json::Value = serde_json::from_slice(&body).expect("parse dist-tags json");
        assert_eq!(tags["next"], "2.0.0-rc.1");
        assert_eq!(tags["latest"], "1.0.0");

        assert!(del_next.is_ok(), "DELETE of a custom tag should succeed");
        assert!(del_latest.is_err(), "DELETE of `latest` must be rejected");
    }

    // -----------------------------------------------------------------------
    // npm /-/ meta namespace (/-/ping, /-/whoami, etc.)
    // -----------------------------------------------------------------------

    /// Local repo: `/-/ping` must return `200 {}` so health-check tooling
    /// (connectors, IDE integrations, `npm ping`) works against local repos.
    #[tokio::test]
    async fn test_local_repo_meta_ping_returns_200() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let app = fx.router_anon(super::router());
        let uri = format!("/{}/-/ping", fx.repo_key);
        let req = tdh::get(uri);
        let (status, bytes) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(status, StatusCode::OK, "/-/ping must return 200");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("/-/ping body must be JSON");
        assert!(
            parsed.is_object() && parsed.as_object().unwrap().is_empty(),
            "/-/ping must return empty JSON object {{}}, got {parsed:?}"
        );
    }

    /// Local repo: `/-/whoami` with auth returns `200 {"username":"<name>"}`.
    #[tokio::test]
    async fn test_local_repo_meta_whoami_authenticated_returns_username() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let app = fx.router_with_auth(super::router());
        let uri = format!("/{}/-/whoami", fx.repo_key);
        let req = tdh::get(uri);
        let (status, bytes) = tdh::send(app, req).await;

        let username = fx.username.clone();
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "authenticated /-/whoami must return 200"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("/-/whoami body must be JSON");
        assert_eq!(
            parsed.get("username").and_then(|v| v.as_str()),
            Some(username.as_str()),
            "/-/whoami must echo the authenticated username"
        );
    }

    /// Local repo: `/-/whoami` without auth returns 401.
    #[tokio::test]
    async fn test_local_repo_meta_whoami_unauthenticated_returns_401() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let app = fx.router_anon(super::router());
        let uri = format!("/{}/-/whoami", fx.repo_key);
        let req = tdh::get(uri);
        let (status, _) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "unauthenticated /-/whoami must return 401"
        );
    }

    /// Remote repo: `/-/ping` is forwarded to the upstream registry and the
    /// upstream response (200 `{}`) is returned verbatim to the client.
    #[tokio::test]
    async fn test_remote_repo_meta_ping_proxied_to_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/-/ping"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{}"),
            )
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let app = tdh::router_anon(super::router(), fx.state.clone());
        let uri = format!("/{}/-/ping", fx.repo_key);
        let req = tdh::get(uri);
        let (status, bytes) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Remote /-/ping must be proxied; got {status}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("upstream ping body must be JSON");
        assert!(
            parsed.is_object() && parsed.as_object().unwrap().is_empty(),
            "proxied /-/ping must return the upstream payload, got {parsed:?}"
        );
    }

    /// Regression guard: requests that previously fell into the /:package/:version
    /// catch-all (package="-", version="ping") must no longer produce
    /// `404 Version 'ping' not found for package '-'`.
    #[tokio::test]
    async fn test_local_repo_meta_ping_does_not_produce_package_not_found_404() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };

        let app = fx.router_anon(super::router());
        let uri = format!("/{}/-/ping", fx.repo_key);
        let req = tdh::get(uri);
        let (status, bytes) = tdh::send(app, req).await;

        fx.teardown().await;

        // The old behaviour was 404 with body mentioning package `-`.
        // The new route must never return that error.
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "/-/ping must not 404; the catch-all regression is back"
        );
        if status == StatusCode::NOT_FOUND {
            let body = String::from_utf8_lossy(&bytes);
            assert!(
                !body.contains("package '-'") && !body.contains("Version 'ping'"),
                "/-/ping must not be treated as package lookup, got: {body}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Computed-packument cache helpers (#2162)
    // -----------------------------------------------------------------------

    fn accept_encoding_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, value.parse().unwrap());
        headers
    }

    #[test]
    fn test_accepts_gzip_detection() {
        assert!(accepts_gzip(&accept_encoding_headers("gzip, deflate, br")));
        assert!(accepts_gzip(&accept_encoding_headers("br, GZIP")));
        assert!(accepts_gzip(&accept_encoding_headers("*")));
        assert!(accepts_gzip(&accept_encoding_headers("gzip;q=0.8")));
        assert!(!accepts_gzip(&accept_encoding_headers("br, deflate")));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }

    #[test]
    fn test_is_cacheable_packument_content_type() {
        assert!(is_cacheable_packument_content_type("application/json"));
        assert!(is_cacheable_packument_content_type(
            "application/json; charset=utf-8"
        ));
        assert!(is_cacheable_packument_content_type(
            NPM_ABBREVIATED_CONTENT_TYPE
        ));
        assert!(!is_cacheable_packument_content_type("application/gzip"));
        assert!(!is_cacheable_packument_content_type("text/html"));
        assert!(!is_cacheable_packument_content_type(""));
    }

    #[test]
    fn test_gzip_encode_round_trips() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let original = br#"{"name":"widget","versions":{}}"#;
        let encoded = gzip_encode(original).expect("gzip encode");
        assert_ne!(encoded.as_slice(), original.as_ref());
        let mut decoder = GzDecoder::new(&encoded[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).expect("gzip decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_cached_packument_response_headers() {
        let gz = CachedPackument {
            bytes: Bytes::from_static(b"gz"),
            content_type: NPM_ABBREVIATED_CONTENT_TYPE.to_string(),
            content_encoding: Some("gzip".to_string()),
        };
        let response = cached_packument_response(&gz);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_ENCODING], "gzip");
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            NPM_ABBREVIATED_CONTENT_TYPE
        );
        // Pre-encoded hits must declare both cache-key request dimensions:
        // tower-http only adds Vary when IT compresses.
        assert_eq!(response.headers()[VARY], "Accept, Accept-Encoding");

        let identity = CachedPackument {
            bytes: Bytes::from_static(b"{}"),
            content_type: "application/json".to_string(),
            content_encoding: None,
        };
        let response = cached_packument_response(&identity);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(CONTENT_ENCODING).is_none(),
            "identity entries must not claim a content encoding"
        );
        assert_eq!(response.headers()[VARY], "Accept, Accept-Encoding");
    }

    #[test]
    fn test_cached_packument_response_survives_corrupt_header_values() {
        // A corrupt shared-cache entry (invalid header characters) must
        // degrade to safe defaults, never panic the request path.
        let corrupt = CachedPackument {
            bytes: Bytes::from_static(b"{}"),
            content_type: "bad\r\nvalue".to_string(),
            content_encoding: Some("also\nbad".to_string()),
        };
        let response = cached_packument_response(&corrupt);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert!(response.headers().get(CONTENT_ENCODING).is_none());
    }

    #[test]
    fn test_is_definitive_missing_status() {
        assert!(is_definitive_missing_status(StatusCode::NOT_FOUND));
        assert!(is_definitive_missing_status(StatusCode::GONE));
        // Transient failures must NOT evict: stale entries keep serving
        // through upstream blips.
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::UNAUTHORIZED,
        ] {
            assert!(
                !is_definitive_missing_status(status),
                "{status} must not evict"
            );
        }
    }

    #[test]
    fn test_npm_package_name_from_artifact_path() {
        assert_eq!(
            npm_package_name_from_artifact_path("lodash/4.17.21/lodash-4.17.21.tgz"),
            Some("lodash")
        );
        assert_eq!(
            npm_package_name_from_artifact_path("@scope/pkg/1.0.0/pkg-1.0.0.tgz"),
            Some("@scope/pkg")
        );
        // Malformed paths must be rejected, not mis-derived.
        assert_eq!(npm_package_name_from_artifact_path("lodash"), None);
        assert_eq!(npm_package_name_from_artifact_path("lodash/4.17.21"), None);
        assert_eq!(npm_package_name_from_artifact_path(""), None);
        assert_eq!(npm_package_name_from_artifact_path("//file.tgz"), None);
    }
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_npm_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/mypkg"),
            format!("/{k}/mypkg/1.0.0"),
            format!("/{k}/mypkg/-/mypkg-1.0.0.tgz"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Computed-packument cache (#2162)
    // -----------------------------------------------------------------------

    /// Fetch a packument through the cache-fronted path and parse it.
    async fn fetch_packument_json(
        state: &crate::api::SharedState,
        repo_key: &str,
        package: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let response = super::get_package_metadata_cached(
            state,
            repo_key,
            package,
            "http://localhost",
            &axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|error_response| error_response);
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read packument body");
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// Minimal `npm publish` body for one version.
    fn publish_body(package: &str, version: &str) -> bytes::Bytes {
        use base64::Engine;
        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "name": package,
                "versions": { version: { "name": package, "version": version } },
                "_attachments": {
                    format!("{package}-{version}.tgz"): { "data": tarball_b64 }
                }
            }))
            .expect("serialize publish body"),
        )
    }

    /// End-to-end #2162: a second packument request must be served by the
    /// computed-packument cache. After the first request the upstream is
    /// re-pointed at an unroutable address AND the proxy's raw metadata cache
    /// is wiped, so only the computed-response cache can answer — and the
    /// wiremock `expect(1)` proves upstream was hit exactly once.
    #[tokio::test]
    async fn test_remote_packument_second_request_served_from_computed_cache() {
        use axum::http::StatusCode;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let upstream_packument = serde_json::json!({
            "name": "cache-widget",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "cache-widget",
                    "version": "1.0.0",
                    "dist": {
                        "tarball":
                            "https://registry.example.test/cache-widget/-/cache-widget-1.0.0.tgz"
                    }
                }
            }
        });
        Mock::given(method("GET"))
            .and(path("/cache-widget"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&upstream_packument))
            .expect(1)
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);

        let (status_first, first) =
            fetch_packument_json(&state, &fx.repo_key, "cache-widget").await;

        // Break every non-cache path: unroutable upstream + wiped raw proxy
        // cache. Only the computed-packument cache can serve the next request.
        sqlx::query("UPDATE repositories SET upstream_url = 'http://127.0.0.1:1' WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("break upstream_url");
        std::fs::remove_dir_all(&fx.storage_dir).expect("wipe proxy cache");
        std::fs::create_dir_all(&fx.storage_dir).expect("recreate storage dir");

        let (status_second, second) =
            fetch_packument_json(&state, &fx.repo_key, "cache-widget").await;

        fx.teardown().await;

        assert_eq!(status_first, StatusCode::OK, "first request must proxy");
        assert_eq!(
            status_second,
            StatusCode::OK,
            "second request must be served by the computed-packument cache"
        );
        assert_eq!(
            first, second,
            "cache must serve the identical computed body"
        );
        let tarball = second["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .expect("tarball url");
        assert!(
            tarball.contains(&format!("/npm/{}/cache-widget/-/", fx.repo_key)),
            "cached body must keep the rewritten tarball URL, got {tarball}"
        );
        // Dropping the mock server verifies `expect(1)`: exactly one
        // upstream fetch across both requests.
    }

    /// Attach a freshly created local npm repo as a member of the fixture's
    /// virtual repo. Returns the member's `(id, key, storage_dir)`.
    async fn attach_local_member(fx: &tdh::Fixture) -> (uuid::Uuid, String, std::path::PathBuf) {
        let (member_id, member_key, member_dir) = tdh::create_repo(&fx.pool, "local", "npm").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(fx.repo_id)
        .bind(member_id)
        .execute(&fx.pool)
        .await
        .expect("attach virtual member");
        tdh::grant_repo_access(&fx.pool, member_id, fx.user_id).await;
        (member_id, member_key, member_dir)
    }

    /// Drop everything [`attach_local_member`] created.
    async fn cleanup_member(
        fx: &tdh::Fixture,
        member_id: uuid::Uuid,
        member_dir: &std::path::Path,
    ) {
        for sql in [
            "DELETE FROM virtual_repo_members WHERE member_repo_id = $1",
            "DELETE FROM artifact_metadata WHERE artifact_id IN \
             (SELECT id FROM artifacts WHERE repository_id = $1)",
            "DELETE FROM npm_dist_tags WHERE repository_id = $1",
            "DELETE FROM role_assignments WHERE repository_id = $1",
            "DELETE FROM artifacts WHERE repository_id = $1",
            "DELETE FROM repositories WHERE id = $1",
        ] {
            let _ = sqlx::query(sql).bind(member_id).execute(&fx.pool).await;
        }
        let _ = std::fs::remove_dir_all(member_dir);
    }

    /// End-to-end #2162: local writes must invalidate the virtual repos that
    /// include the written repo (only remote/virtual packuments are cached).
    /// The middle step proves the virtual entry actually serves from cache (a
    /// row seeded behind its back stays invisible); the publish and dist-tag
    /// steps prove both write paths propagate the invalidation.
    #[tokio::test]
    async fn test_publish_and_dist_tag_invalidate_virtual_packument_cache() {
        use axum::extract::{Path, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::Extension;

        let Some(fx) = tdh::Fixture::setup("virtual", "npm").await else {
            return;
        };
        let (member_id, member_key, member_dir) = attach_local_member(&fx).await;
        let auth = || Some(tdh::make_auth(fx.user_id, &fx.username));

        let published = super::publish_package(
            &fx.state,
            auth(),
            &member_key,
            "cachepkg",
            &HeaderMap::new(),
            publish_body("cachepkg", "1.0.0"),
        )
        .await;
        assert!(published.is_ok(), "publish 1.0.0 must succeed");

        // Warm the virtual repo's computed-packument cache.
        let (status, warm) = fetch_packument_json(&fx.state, &fx.repo_key, "cachepkg").await;
        assert_eq!(status, StatusCode::OK);
        assert!(warm["versions"]["1.0.0"].is_object(), "got {warm:?}");

        // Seed a version directly in the member's tables, bypassing the
        // publish path: a virtual cache HIT must not see it.
        let member_repo = tdh::make_repo_info(member_id, &member_key, &member_dir, "local", None);
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &member_repo,
            "npm/cachepkg/9.9.9/cachepkg-9.9.9.tgz",
            "cachepkg/9.9.9/cachepkg-9.9.9.tgz",
            "cachepkg",
            "9.9.9",
            "application/gzip",
            bytes::Bytes::from_static(b"tgz"),
            fx.user_id,
        )
        .await;
        let (_, cached) = fetch_packument_json(&fx.state, &fx.repo_key, "cachepkg").await;
        assert!(
            cached["versions"]["9.9.9"].is_null(),
            "a fresh virtual cache hit must serve the cached packument, not recompute; \
             got {cached:?}"
        );

        // Publish 2.0.0 to the MEMBER: the virtual repo's cache must be
        // invalidated, so the next read recomputes and now sees BOTH
        // out-of-band versions.
        let republished = super::publish_package(
            &fx.state,
            auth(),
            &member_key,
            "cachepkg",
            &HeaderMap::new(),
            publish_body("cachepkg", "2.0.0"),
        )
        .await;
        assert!(republished.is_ok(), "publish 2.0.0 must succeed");
        let (_, after_publish) = fetch_packument_json(&fx.state, &fx.repo_key, "cachepkg").await;
        assert!(
            after_publish["versions"]["2.0.0"].is_object()
                && after_publish["versions"]["9.9.9"].is_object(),
            "a member publish must invalidate the virtual computed-packument cache; \
             got {after_publish:?}"
        );

        // Dist-tag add on the member must invalidate the virtual entry too.
        let tagged = super::dist_tags_put(
            State(fx.state.clone()),
            Extension(auth()),
            Path((
                member_key.clone(),
                "cachepkg".to_string(),
                "beta".to_string(),
            )),
            HeaderMap::new(),
            bytes::Bytes::from_static(b"\"1.0.0\""),
        )
        .await;
        assert!(tagged.is_ok(), "dist-tag add must succeed");
        let (_, after_tag) = fetch_packument_json(&fx.state, &fx.repo_key, "cachepkg").await;

        cleanup_member(&fx, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            after_tag["dist-tags"]["beta"].as_str(),
            Some("1.0.0"),
            "a member dist-tag add must invalidate the virtual computed-packument cache; \
             got {after_tag:?}"
        );
    }

    /// REST artifact delete (`DELETE /api/v1/repositories/{key}/artifacts/..`)
    /// must invalidate the computed-packument cache like the format-native
    /// write paths do: after deleting the member's only version, the virtual
    /// repo must stop serving the cached packument immediately.
    #[tokio::test]
    async fn test_rest_artifact_delete_invalidates_packument_cache() {
        use axum::extract::{Path, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::Extension;

        let Some(fx) = tdh::Fixture::setup("virtual", "npm").await else {
            return;
        };
        let (member_id, member_key, member_dir) = attach_local_member(&fx).await;
        // Admin: the REST delete path refuses non-admin deletes of released
        // (immutable) versions; this test targets cache invalidation, not the
        // immutability gate.
        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = true;

        let published = super::publish_package(
            &fx.state,
            Some(auth.clone()),
            &member_key,
            "delpkg",
            &HeaderMap::new(),
            publish_body("delpkg", "1.0.0"),
        )
        .await;
        assert!(published.is_ok(), "publish must succeed");

        // Warm the virtual repo's cache.
        let (status, warm) = fetch_packument_json(&fx.state, &fx.repo_key, "delpkg").await;
        assert_eq!(status, StatusCode::OK);
        assert!(warm["versions"]["1.0.0"].is_object(), "got {warm:?}");

        // Delete the only version through the REST handler.
        let deleted = crate::api::handlers::repositories::delete_artifact(
            State(fx.state.clone()),
            Extension(Some(auth)),
            Path((
                member_key.clone(),
                "delpkg/1.0.0/delpkg-1.0.0.tgz".to_string(),
            )),
            HeaderMap::new(),
        )
        .await;
        assert!(
            deleted.is_ok(),
            "REST artifact delete must succeed: {deleted:?}"
        );

        // Without invalidation the virtual repo would keep serving the cached
        // packument for the whole fresh window; with it, the recompute finds
        // no versions and the package is gone.
        let (status_after, after) = fetch_packument_json(&fx.state, &fx.repo_key, "delpkg").await;

        cleanup_member(&fx, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            status_after,
            StatusCode::NOT_FOUND,
            "REST delete must invalidate the computed-packument cache; got {after:?}"
        );
    }

    /// Build a state like [`tdh::build_state`] but with a proxy service and a
    /// custom fresh TTL for the packument cache, so staleness is reachable
    /// without sleeping.
    fn build_state_with_fresh_ttl(
        fx: &tdh::Fixture,
        fresh_ttl_secs: u64,
    ) -> crate::api::SharedState {
        let mut config = crate::config::Config::test_config();
        config.storage_path = fx.storage_dir.to_string_lossy().into_owned();
        config.npm_packument_cache_fresh_ttl_secs = fresh_ttl_secs;
        let storage: std::sync::Arc<dyn crate::storage::StorageBackend> = std::sync::Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(&config.storage_path),
        );
        let registry = std::sync::Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let mut state = crate::api::AppState::new(config, fx.pool.clone(), storage, registry);
        state.set_proxy_service(tdh::build_proxy_service_with_fs(
            fx.pool.clone(),
            fx.storage_dir.to_str().unwrap(),
        ));
        std::sync::Arc::new(state)
    }

    /// Upstream packument body for the wiremock server.
    fn upstream_packument(package: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": package,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": package,
                    "version": version,
                    "dist": {
                        "tarball": format!(
                            "https://registry.example.test/{package}/-/{package}-{version}.tgz"
                        )
                    }
                }
            }
        })
    }

    /// Point the fixture's remote repo at `upstream` and drop the proxy's raw
    /// metadata cache, so the next fetch really consults the (new) upstream.
    async fn repoint_upstream_and_wipe_proxy_cache(fx: &tdh::Fixture, upstream: &str) {
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream)
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");
        std::fs::remove_dir_all(&fx.storage_dir).expect("wipe proxy cache");
        std::fs::create_dir_all(&fx.storage_dir).expect("recreate storage dir");
    }

    /// End-to-end #2162 stale-while-revalidate on a remote repo: with a zero
    /// fresh window every warm hit classifies as stale, so the handler must
    /// serve the cached body immediately (no inline upstream fetch) and
    /// refresh in the background — observable because the upstream flips from
    /// v1 to v2 and the stale hit still serves v1 before the refresh lands v2.
    #[tokio::test]
    async fn test_stale_packument_serves_immediately_and_refreshes_in_background() {
        use axum::http::StatusCode;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/swrpkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(upstream_packument("swrpkg", "1.0.0")),
            )
            .mount(&mock_server)
            .await;
        repoint_upstream_and_wipe_proxy_cache(&fx, &mock_server.uri()).await;
        let state = build_state_with_fresh_ttl(&fx, 0);

        // Miss: computes v1 and stores it.
        let (status, first) = fetch_packument_json(&state, &fx.repo_key, "swrpkg").await;
        assert_eq!(status, StatusCode::OK);
        assert!(first["versions"]["1.0.0"].is_object(), "got {first:?}");

        // Upstream moves to v2; the raw proxy cache is wiped so the refresh
        // really refetches.
        mock_server.reset().await;
        Mock::given(method("GET"))
            .and(path("/swrpkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(upstream_packument("swrpkg", "2.0.0")),
            )
            .mount(&mock_server)
            .await;
        repoint_upstream_and_wipe_proxy_cache(&fx, &mock_server.uri()).await;

        // Stale hit: the OLD body is served immediately while the refresh
        // runs in the background.
        let (status, stale) = fetch_packument_json(&state, &fx.repo_key, "swrpkg").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            stale["versions"]["1.0.0"].is_object() && stale["versions"]["2.0.0"].is_null(),
            "a stale hit must serve the cached body without an inline upstream fetch; \
             got {stale:?}"
        );

        // The background refresh eventually stores the recomputed entry.
        let mut refreshed = stale;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let (_, current) = fetch_packument_json(&state, &fx.repo_key, "swrpkg").await;
            refreshed = current;
            if refreshed["versions"]["2.0.0"].is_object() {
                break;
            }
        }

        fx.teardown().await;

        assert!(
            refreshed["versions"]["2.0.0"].is_object(),
            "the background refresh must replace the stale entry; got {refreshed:?}"
        );
    }

    /// Definitive-miss eviction (#2162): when the upstream starts answering
    /// 404 for a cached packument, the background refresh must EVICT the
    /// entry — not keep serving the ghost until the stale window ends — so
    /// unpublishes and takedowns propagate promptly. Transient failures keep
    /// serving stale (that is the point of SWR); only 404/410 evict.
    #[tokio::test]
    async fn test_stale_entry_evicted_when_upstream_returns_404() {
        use axum::http::StatusCode;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ghostpkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(upstream_packument("ghostpkg", "1.0.0")),
            )
            .mount(&mock_server)
            .await;
        repoint_upstream_and_wipe_proxy_cache(&fx, &mock_server.uri()).await;
        let state = build_state_with_fresh_ttl(&fx, 0);

        // Warm the cache with the live packument.
        let (status, first) = fetch_packument_json(&state, &fx.repo_key, "ghostpkg").await;
        assert_eq!(status, StatusCode::OK);
        assert!(first["versions"]["1.0.0"].is_object(), "got {first:?}");

        // The package is unpublished upstream: every request now 404s (a
        // reset wiremock answers 404 to everything). Wipe the raw proxy
        // cache so the refresh consults the upstream for real.
        mock_server.reset().await;
        repoint_upstream_and_wipe_proxy_cache(&fx, &mock_server.uri()).await;

        // The first request may still serve the stale entry (SWR), but the
        // refresh it triggers observes the authoritative 404 and evicts, so
        // requests must converge on 404 rather than the ghost packument.
        let mut final_status = StatusCode::OK;
        for _ in 0..50 {
            let (status, _) = fetch_packument_json(&state, &fx.repo_key, "ghostpkg").await;
            final_status = status;
            if final_status == StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        fx.teardown().await;

        assert_eq!(
            final_status,
            StatusCode::NOT_FOUND,
            "an authoritative upstream 404 must evict the cached packument"
        );
    }

    /// A gzip-accepting client gets the pre-encoded gzip variant back from
    /// the cache: `Content-Encoding: gzip` set by the handler (so the
    /// compression layer passes it through), `Vary` declaring both request
    /// dimensions, and a body that gunzips to the same packument an identity
    /// client sees.
    #[tokio::test]
    async fn test_gzip_variant_served_pre_encoded() {
        use axum::http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, VARY};
        use axum::http::{HeaderMap, StatusCode};
        use flate2::read::GzDecoder;
        use std::io::Read;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "npm").await else {
            return;
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gzpkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(upstream_packument("gzpkg", "1.0.0")),
            )
            .mount(&mock_server)
            .await;
        repoint_upstream_and_wipe_proxy_cache(&fx, &mock_server.uri()).await;
        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip".parse().unwrap());
        // Twice: the first request stores both variants, the second is a
        // warm gzip hit.
        for pass in ["cold", "warm"] {
            let response = super::get_package_metadata_cached(
                &state,
                &fx.repo_key,
                "gzpkg",
                "http://localhost",
                &headers,
            )
            .await
            .unwrap_or_else(|error_response| error_response);
            assert_eq!(response.status(), StatusCode::OK, "{pass} request failed");
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "{pass}: gzip-accepting clients must get the pre-encoded variant"
            );
            assert_eq!(
                response.headers().get(VARY).and_then(|v| v.to_str().ok()),
                Some("Accept, Accept-Encoding"),
                "{pass}: pre-encoded responses must declare Vary themselves"
            );
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read body");
            let mut decoded = Vec::new();
            GzDecoder::new(&body[..])
                .read_to_end(&mut decoded)
                .expect("gunzip cached body");
            let json: serde_json::Value =
                serde_json::from_slice(&decoded).expect("parse gunzipped packument");
            assert!(
                json["versions"]["1.0.0"].is_object(),
                "{pass}: gunzipped body must be the packument, got {json:?}"
            );
        }

        fx.teardown().await;
    }
}
