//! Cargo sparse registry protocol handlers.
//!
//! Implements the endpoints required for `cargo publish` and `cargo install`
//! via the sparse registry protocol (RFC 2789).
//!
//! Routes are mounted at `/cargo/{repo_key}/...`:
//!   GET  /cargo/{repo_key}/config.json                              - Registry config
//!   GET  /cargo/{repo_key}/api/v1/crates                           - Search crates
//!   PUT  /cargo/{repo_key}/api/v1/crates/new                       - Publish crate
//!   GET  /cargo/{repo_key}/api/v1/crates/{name}/{version}/download - Download crate
//!   GET  /cargo/{repo_key}/index/*path                             - Sparse index lookup

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::{require_auth_with_bearer_fallback, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::api::{CachedRepo, IndexCache, RepoCache, REPO_CACHE_TTL_SECS};
use crate::error::AppError;
use crate::models::repository::{RepositoryFormat, RepositoryType};

// ---------------------------------------------------------------------------
// In-process caches
// ---------------------------------------------------------------------------

const INDEX_CACHE_TTL_SECS: u64 = 300;

/// TTL for cached upstream `config.json` data (the `dl` download URL).
/// Upstream registries change their config.json very rarely, so 1 hour
/// is a reasonable balance between freshness and upstream request volume.
const CONFIG_CACHE_TTL_SECS: u64 = 3600;

/// Thread-safe cache for upstream registry `config.json` download URL (`dl` field).
/// Key: upstream base URL. Value: resolved `dl` URL + insertion time.
type ConfigCache = std::sync::Arc<tokio::sync::RwLock<HashMap<String, (String, Instant)>>>;

/// Module-level cache for upstream `config.json` download URLs.
static UPSTREAM_CONFIG_CACHE: once_cell::sync::Lazy<ConfigCache> =
    once_cell::sync::Lazy::new(|| std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())));

async fn index_cache_get(cache: &IndexCache, key: &str) -> Option<Bytes> {
    let c = cache.read().await;
    let (bytes, at) = c.get(key)?;
    if at.elapsed().as_secs() < INDEX_CACHE_TTL_SECS {
        Some(bytes.clone())
    } else {
        None
    }
}

async fn index_cache_set(cache: &IndexCache, key: String, bytes: Bytes) {
    let mut c = cache.write().await;
    c.retain(|_, (_, at)| at.elapsed().as_secs() < INDEX_CACHE_TTL_SECS);
    c.insert(key, (bytes, Instant::now()));
}

async fn index_cache_invalidate(cache: &IndexCache, key: &str) {
    cache.write().await.remove(key);
}

// ---------------------------------------------------------------------------
// Upstream config.json resolution
// ---------------------------------------------------------------------------

/// Look up the cached `dl` URL for an upstream registry base URL.
async fn config_cache_get(base_url: &str) -> Option<String> {
    let c = UPSTREAM_CONFIG_CACHE.read().await;
    let (dl_url, at) = c.get(base_url)?;
    if at.elapsed().as_secs() < CONFIG_CACHE_TTL_SECS {
        Some(dl_url.clone())
    } else {
        None
    }
}

/// Store a resolved `dl` URL for an upstream base URL.
async fn config_cache_set(base_url: String, dl_url: String) {
    let mut c = UPSTREAM_CONFIG_CACHE.write().await;
    c.retain(|_, (_, at)| at.elapsed().as_secs() < CONFIG_CACHE_TTL_SECS);
    c.insert(base_url, (dl_url, Instant::now()));
}

/// Fetch the upstream registry's `config.json` and extract the `dl` field.
///
/// Cargo registries serve a `config.json` at their root that contains a `dl`
/// field indicating the download URL template. For registries like crates.io,
/// the index (`https://index.crates.io`) and the download host
/// (`https://crates.io`) are on different domains, so the `dl` field is the
/// authoritative source for where to fetch .crate files.
///
/// Returns `Some(dl_url)` on success, `None` if the config could not be fetched
/// or parsed. Results are cached for `CONFIG_CACHE_TTL_SECS`.
async fn resolve_upstream_dl_url(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
) -> Option<String> {
    // Determine which base URL to fetch config.json from. Prefer the index URL
    // because that is where Cargo registries serve their config.json.
    let base_url = repo
        .index_upstream_url
        .as_deref()
        .or(repo.upstream_url.as_deref())?;

    // Check the cache first.
    if let Some(cached) = config_cache_get(base_url).await {
        return Some(cached);
    }

    // Fetch config.json from upstream.
    let proxy = state.proxy_service.as_ref()?;
    let config_bytes = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        repo_key,
        base_url,
        "config.json",
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    .ok()?;

    let config: serde_json::Value = serde_json::from_slice(&config_bytes.0).ok()?;
    let dl_url = config.get("dl")?.as_str()?.to_string();

    // Cache the resolved dl URL.
    config_cache_set(base_url.to_string(), dl_url.clone()).await;

    Some(dl_url)
}

/// Extract the `cksum` recorded for `version` from a sparse-index document
/// (#2929).
///
/// The sparse index is NDJSON: one JSON object per line, each carrying `vers`
/// and `cksum`. `cksum` is the SHA-256 of the `.crate` file — it is exactly
/// what cargo itself verifies the download against, and on a split-host
/// registry (crates.io serves the index from `index.crates.io` and the
/// `.crate` from a separate download host) it is sourced independently of the
/// host that serves the bytes.
///
/// Returns `None` when the document is unparseable, the version is absent, or
/// the recorded value is not a bare lowercase SHA-256 — all of which mean "no
/// enforceable digest", so the caller falls back to an unverified fetch rather
/// than failing the download.
fn cksum_for_version(index_ndjson: &[u8], version: &str) -> Option<String> {
    let text = std::str::from_utf8(index_ndjson).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            // A single malformed line must not hide a later good one.
            continue;
        };
        if entry.get("vers").and_then(|v| v.as_str()) != Some(version) {
            continue;
        }
        return entry
            .get("cksum")
            .and_then(|v| v.as_str())
            .and_then(proxy_helpers::normalize_expected_sha256);
    }
    None
}

/// Resolve the sparse-index `cksum` for `{name}/{version}` from the upstream
/// registry so the streamed `.crate` download can be digest-gated (#2929).
///
/// Best-effort by construction: any failure (no proxy, index fetch error,
/// missing version, non-canonical digest) returns `None` and the download
/// proceeds unverified, exactly as it did before. The index fetch uses the
/// same proxy-cached, capped metadata helper the sparse-index handler uses, so
/// a cargo client — which always reads the index immediately before
/// downloading — finds it warm.
async fn resolve_index_cksum(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    name_lower: &str,
    version: &str,
) -> Option<String> {
    let proxy = state.proxy_service.as_ref()?;
    let base_url = repo
        .index_upstream_url
        .as_deref()
        .or(repo.upstream_url.as_deref())?;
    let index_path = cargo_sparse_index_path_upstream(name_lower);
    let (content, _content_type) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        repo_key,
        base_url,
        &index_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    .ok()?;
    cksum_for_version(&content, version)
}

/// Build the full download URL for a crate, using the upstream `dl` template
/// when available. Falls back to `{upstream_url}/api/v1/crates/{name}/{version}/download`.
///
/// The `dl` field from `config.json` can be either a plain base URL
/// (e.g. `https://crates.io/api/v1/crates`) to which `/{name}/{version}/download`
/// is appended, or a template with `{crate}` / `{version}` markers. This
/// function handles both forms.
fn build_download_url(dl_url: &str, name: &str, version: &str) -> String {
    if dl_url.contains("{crate}") || dl_url.contains("{version}") {
        dl_url
            .replace("{crate}", name)
            .replace("{version}", version)
    } else {
        let base = dl_url.trim_end_matches('/');
        format!("{}/{}/{}/download", base, name, version)
    }
}

/// Split a fully-qualified URL into `(origin, path)`.
///
/// Given `https://crates.io/api/v1/crates/serde/1.0.0/download`, returns
/// `("https://crates.io", "api/v1/crates/serde/1.0.0/download")`.
///
/// Returns `None` when the URL has no scheme or no path component after the host.
fn split_url(url: &str) -> Option<(String, String)> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let slash = after_scheme.find('/')?;
    let origin = &url[..scheme_end + 3 + slash];
    let path = &url[scheme_end + 3 + slash + 1..];
    Some((origin.to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// Age-gate sparse-index filtering (#3480, Phase 1 — pure, no IO)
// ---------------------------------------------------------------------------
//
// These helpers extract `(version, publish_time)` pairs from a sparse-index
// NDJSON document for `AgeGateService::evaluate_versions_batch`
// (`crate::services::age_gate_service`, `pub(crate)`), and rebuild a
// filtered document once the caller knows which versions are blocked — the
// same split as the Go `@v/list` filter (`parse_version_list` /
// `filter_version_list` in `goproxy.rs`). Not yet wired into `serve_index`,
// `try_remote_index`, or `try_virtual_index`: that DB-backed enforcement,
// the content-coding-aware `_encoded` fetch variant, and the `resolve_index_
// cksum` fail-open-to-fail-closed inversion are Phase 2. `#[allow(dead_code)]`
// mirrors `package_name_from_crate_filename` in `formats::cargo` — a pure
// primitive kept ready for a call site that lands in a later phase.

/// Minimal fields extracted from one Cargo sparse-index NDJSON line for
/// age-gate evaluation: the version being described and its optional
/// registry-published `pubtime`. Deliberately narrower than
/// [`crate::formats::cargo::IndexEntry`] (which requires `name`/`cksum` and
/// models the full entry shape): serde ignores JSON keys it doesn't
/// recognise, so this stays forward-compatible with index fields this
/// server does not otherwise model, and a line missing `cksum` (which the
/// full `IndexEntry` requires) still parses far enough to be age-gate
/// evaluated.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CargoAgeGateLineFields {
    vers: String,
    #[serde(default)]
    pubtime: Option<String>,
}

/// Parse a Cargo sparse-index `pubtime` value under the registry-index
/// spec's **strict** grammar: exactly `yyyy-mm-ddThh:mm:ssZ` — zero-padded,
/// `Z`-suffixed UTC, no fractional seconds, no numeric offset, no other
/// RFC 3339 variant.
///
/// This is deliberately narrower than Cargo itself. Cargo stabilized
/// parsing `pubtime` by deserializing it into a `jiff::Timestamp`, which
/// accepts the full RFC 3339 grammar (fractional seconds, `+00:00`-style
/// numeric offsets). A conforming third-party sparse registry could
/// therefore emit a `pubtime` Cargo parses successfully but this function
/// rejects. That divergence is a conscious, spec-strict, fail-closed choice
/// for the initial slice — raised as an open question upstream
/// (artifact-keeper#3480, unanswered as of this writing): a `pubtime` this
/// function cannot parse becomes `None`, which the `upstream_publish_time`
/// policy treats as missing evidence and blocks + queues for review, rather
/// than silently trusting a lenient parse.
///
/// Isolated as a single function — with its own tests below, including the
/// forms it deliberately rejects — so switching to Cargo's own leniency
/// later, if that is the maintainers' answer, is a one-function change.
#[allow(dead_code)] // not yet wired into a handler; see the module comment above.
fn parse_cargo_pubtime(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDate, NaiveTime, TimeZone, Utc};

    // "yyyy-mm-ddThh:mm:ssZ" is exactly 20 ASCII bytes. Checking length and
    // ASCII-ness up front means every byte index used below is also a valid
    // char boundary, so the slices cannot panic.
    if raw.len() != 20 || !raw.is_ascii() {
        return None;
    }
    let b = raw.as_bytes();
    let literals_match = b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z';
    let digits_match = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
        .iter()
        .all(|&i| b[i].is_ascii_digit());
    if !literals_match || !digits_match {
        return None;
    }

    let year: i32 = raw[0..4].parse().ok()?;
    let month: u32 = raw[5..7].parse().ok()?;
    let day: u32 = raw[8..10].parse().ok()?;
    let hour: u32 = raw[11..13].parse().ok()?;
    let minute: u32 = raw[14..16].parse().ok()?;
    let second: u32 = raw[17..19].parse().ok()?;

    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let time = NaiveTime::from_hms_opt(hour, minute, second)?;
    Some(Utc.from_utc_datetime(&date.and_time(time)))
}

/// Extract `(version, publish_time)` pairs from a decoded Cargo sparse-index
/// NDJSON document, for [`AgeGateService::evaluate_versions_batch`]
/// (`crate::services::age_gate_service`).
///
/// Pure and IO-free: `content` must already be decoded bytes (identity
/// coding) — stripping an upstream `Content-Encoding` before parsing is the
/// caller's job, following `decode_go_metadata_body`'s template in
/// `goproxy.rs` (#3280). Splits on raw bytes (not `str::from_utf8` on the
/// whole document) so one invalid-UTF-8 line cannot hide every other line's
/// evaluation. Blank/whitespace-only lines are skipped, matching
/// [`crate::formats::cargo::CargoHandler::parse_index_file`]'s existing
/// upstream-document shape.
///
/// A line that is not valid UTF-8, not valid JSON, or has no `vers` field is
/// a malformed upstream entry: it is logged and OMITTED — not surfaced as an
/// error — so one bad line cannot hide the rest of a crate's otherwise-valid
/// version history from evaluation. A missing or unparseable `pubtime`
/// (see [`parse_cargo_pubtime`]) becomes `None` on an otherwise-valid line;
/// the `upstream_publish_time` policy is what turns that into a block.
///
/// Because omission here means a version never reaches
/// `evaluate_versions_batch`, [`filter_cargo_index_lines`] independently
/// omits any line this function could not parse too — an enabled gate must
/// never pass a line whose version/time it never evaluated.
#[allow(dead_code)] // not yet wired into a handler; see the module comment above.
fn collect_cargo_index_versions(
    content: &[u8],
) -> Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> {
    let mut out = Vec::new();
    for raw_line in content.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(raw_line) else {
            tracing::warn!(
                "cargo sparse-index line is not valid UTF-8; omitting from age-gate evaluation"
            );
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<CargoAgeGateLineFields>(trimmed) {
            Ok(fields) => {
                let pubtime = fields.pubtime.as_deref().and_then(parse_cargo_pubtime);
                out.push((fields.vers, pubtime));
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "cargo sparse-index line failed to parse; omitting from age-gate evaluation"
                );
            }
        }
    }
    out
}

/// Rebuild a Cargo sparse-index NDJSON document with every `blocked` version
/// removed, preserving each surviving line byte-for-byte (no
/// re-serialization) and in original order.
///
/// This is the enabled-gate contract: it is deliberately more aggressive
/// than [`collect_cargo_index_versions`] on malformed input. That function
/// only SKIPS a line it cannot parse, so one bad release does not hide the
/// rest of the document from evaluation; this function OMITS such a line
/// too, for a different reason — an enabled gate must never pass a line
/// whose version/publish-time was never evaluated (fail closed on malformed
/// NDJSON, per the plan). Blank lines are dropped, matching
/// [`collect_cargo_index_versions`] and the Go `@v/list` filter's shape.
///
/// The caller (Phase 2's handler-level wiring — not yet added) is expected
/// to invoke this only when the age gate is enabled and enforceable; an
/// ungated repository keeps today's verbatim proxy fast path untouched.
/// `content` must already be decoded bytes for the same reason as
/// [`collect_cargo_index_versions`].
#[allow(dead_code)] // not yet wired into a handler; see the module comment above.
fn filter_cargo_index_lines(content: &[u8], blocked: &HashSet<String>) -> Bytes {
    let mut out: Vec<u8> = Vec::with_capacity(content.len());
    let mut wrote_any = false;
    for raw_line in content.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(raw_line) else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(fields) = serde_json::from_str::<CargoAgeGateLineFields>(trimmed) else {
            continue;
        };
        if blocked.contains(&fields.vers) {
            continue;
        }
        if wrote_any {
            out.push(b'\n');
        }
        out.extend_from_slice(raw_line);
        wrote_any = true;
    }
    Bytes::from(out)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Registry config
        .route("/:repo_key/config.json", get(config_json))
        // Search
        .route("/:repo_key/api/v1/crates", get(search_crates))
        // Publish
        .route("/:repo_key/api/v1/crates/new", put(publish))
        // Download
        .route(
            "/:repo_key/api/v1/crates/:name/:version/download",
            get(download),
        )
        // Sparse index — index/ prefixed paths (legacy / internal)
        .route("/:repo_key/index/1/:name", get(sparse_index_1))
        .route("/:repo_key/index/2/:name", get(sparse_index_2))
        .route("/:repo_key/index/3/:prefix/:name", get(sparse_index_3))
        .route(
            "/:repo_key/index/:prefix1/:prefix2/:name",
            get(sparse_index_4plus),
        )
        // Sparse index — root-level paths (Cargo sparse registry protocol)
        // Cargo clients expect index files at the registry root, not under index/.
        // Axum prioritises static segments first so api/v1/crates etc. still win.
        .route("/:repo_key/1/:name", get(sparse_index_1))
        .route("/:repo_key/2/:name", get(sparse_index_2))
        .route("/:repo_key/3/:prefix/:name", get(sparse_index_3))
        .route(
            "/:repo_key/:prefix1/:prefix2/:name",
            get(sparse_index_4plus),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
    storage_backend: String,
    repo_type: String,
    upstream_url: Option<String>,
    /// Separate index host for registries like crates.io that split index
    /// (`https://index.crates.io`) and download (`https://crates.io`) across
    /// two hosts. Loaded from the `repository_config` table on the key
    /// `index_upstream_url`. Falls back to `upstream_url` when absent.
    index_upstream_url: Option<String>,
}

impl RepoInfo {
    fn storage_location(&self) -> crate::storage::StorageLocation {
        crate::storage::StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

async fn resolve_cargo_repo(
    db: &PgPool,
    repo_key: &str,
    repo_cache: &RepoCache,
) -> Result<RepoInfo, Response> {
    // Check the shared repo cache first.  The repo_visibility_middleware
    // populates this cache before handlers run, so on most requests this
    // returns immediately with 0 DB queries.
    {
        let cache = repo_cache.read().await;
        if let Some((entry, at)) = cache.get(repo_key) {
            if at.elapsed().as_secs() < REPO_CACHE_TTL_SECS {
                let fmt = entry.format.to_lowercase();
                if fmt != "cargo" {
                    return Err(AppError::Validation(format!(
                        "Repository '{}' is not a Cargo repository (format: {})",
                        repo_key, fmt
                    ))
                    .into_response());
                }
                return Ok(RepoInfo {
                    id: entry.id,
                    storage_path: entry.storage_path.clone(),
                    storage_backend: entry.storage_backend.clone(),
                    repo_type: entry.repo_type.clone(),
                    upstream_url: entry.upstream_url.clone(),
                    index_upstream_url: entry.index_upstream_url.clone(),
                });
            }
        }
    }

    // Cache miss (e.g. direct access bypassing the middleware): fall back to
    // a DB lookup and populate the cache for next time.  Uses sqlx::query()
    // (not the macro) so no offline-cache update is needed.
    use sqlx::Row;
    let repo = sqlx::query(
        "SELECT id, storage_backend, storage_path, format::text as format, repo_type::text as repo_type, \
         upstream_url, is_public, \
         (SELECT value FROM repository_config \
          WHERE repository_id = repositories.id \
          AND key = 'index_upstream_url') AS index_upstream_url \
         FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(map_db_err)?
    .ok_or_else(|| AppError::NotFound("Repository not found".to_string()).into_response())?;

    let fmt: String = repo.get("format");
    let fmt = fmt.to_lowercase();
    if fmt != "cargo" {
        return Err(AppError::Validation(format!(
            "Repository '{}' is not a Cargo repository (format: {})",
            repo_key, fmt
        ))
        .into_response());
    }

    let id: uuid::Uuid = repo.get("id");
    let storage_backend: String = repo.get("storage_backend");
    let storage_path: String = repo.get("storage_path");
    let repo_type: String = repo.get("repo_type");
    let upstream_url: Option<String> = repo.get("upstream_url");
    let is_public: bool = repo.get("is_public");
    let index_upstream_url: Option<String> = repo.get("index_upstream_url");

    // Populate cache so subsequent requests from this handler path are fast.
    {
        let mut cache = repo_cache.write().await;
        cache.retain(|_, (_, at)| at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
        cache.insert(
            repo_key.to_string(),
            (
                CachedRepo {
                    id,
                    format: fmt.clone(),
                    repo_type: repo_type.clone(),
                    upstream_url: upstream_url.clone(),
                    storage_path: storage_path.clone(),
                    storage_backend: storage_backend.clone(),
                    is_public,
                    index_upstream_url: index_upstream_url.clone(),
                },
                Instant::now(),
            ),
        );
    }

    Ok(RepoInfo {
        id,
        storage_path,
        storage_backend,
        repo_type,
        upstream_url,
        index_upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/config.json — Registry configuration
// ---------------------------------------------------------------------------

async fn config_json(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let _repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;

    // Check repo visibility from the cache (populated by resolve_cargo_repo).
    let is_private = {
        let cache = state.repo_cache.read().await;
        !cache
            .get(&repo_key)
            .map(|(r, _)| r.is_public)
            .unwrap_or(true)
    };

    // Determine the base URL from reverse-proxy / Host headers.
    let config = serde_json::json!({
        "dl": format!("{}/cargo/{}/api/v1/crates", base_url.as_str(), repo_key),
        "api": format!("{}/cargo/{}", base_url.as_str(), repo_key),
        // For private repos, tell cargo to send credentials on all requests
        // (index fetches included).  Without this flag cargo only sends auth
        // after a 401 challenge, but it does not retry 401s on index entries.
        // Public repos must NOT set this, otherwise anonymous users need a
        // credential provider configured even though the server allows access.
        "auth-required": is_private,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "max-age=300")
        .body(Body::from(serde_json::to_string_pretty(&config).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/api/v1/crates — Search crates
// ---------------------------------------------------------------------------

async fn search_crates(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;

    let query = params.get("q").cloned().unwrap_or_default();
    let per_page: i64 = params
        .get("per_page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .min(100);

    // Total number of distinct crates matching the query. This must be counted
    // independently of the paginated (LIMIT-truncated) result set, otherwise
    // `meta.total` reports the page size rather than the real match count and
    // cargo's search pagination breaks.
    let total_matches: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT a.name)
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND ($2 = '' OR a.name ILIKE '%' || $2 || '%')
        "#,
        repo.id,
        query,
    )
    .fetch_one(&state.db)
    .await
    .map_err(map_db_err)?
    .unwrap_or(0);

    // Search for crates matching the query
    let crates = sqlx::query!(
        r#"
        SELECT DISTINCT a.name,
               MAX(a.version) as "max_version?",
               MAX(am.metadata::text) as "metadata_text?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND ($2 = '' OR a.name ILIKE '%' || $2 || '%')
        GROUP BY a.name
        ORDER BY a.name
        LIMIT $3
        "#,
        repo.id,
        query,
        per_page,
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

    let crate_list: Vec<serde_json::Value> = crates
        .iter()
        .map(|c| {
            let description = c
                .metadata_text
                .as_ref()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .and_then(|m| {
                    m.get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_default();

            serde_json::json!({
                "name": c.name,
                "max_version": c.max_version,
                "description": description,
            })
        })
        .collect();

    let response = build_search_response(crate_list, total_matches);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

/// Build the cargo search-endpoint JSON body.
///
/// `meta.total` is the **total** number of distinct crates matching the query
/// across all pages — not the length of the (LIMIT-truncated) `crate_list`
/// for the current page. Cargo relies on `meta.total` for pagination, so it
/// must be derived from a separate COUNT(*) and not from the page slice.
fn build_search_response(
    crate_list: Vec<serde_json::Value>,
    total_matches: i64,
) -> serde_json::Value {
    serde_json::json!({
        "crates": crate_list,
        "meta": {
            "total": total_matches,
        }
    })
}

// ---------------------------------------------------------------------------
// PUT /cargo/{repo_key}/api/v1/crates/new — Publish crate
// ---------------------------------------------------------------------------

/// Result of parsing the Cargo publish binary protocol payload.
struct ParsedPublishPayload {
    metadata: serde_json::Value,
    crate_name: String,
    crate_version: String,
    crate_bytes: Bytes,
}

/// Parse the Cargo publish binary protocol:
///   - 4 bytes: JSON metadata length (LE u32)
///   - N bytes: JSON metadata
///   - 4 bytes: .crate file length (LE u32)
///   - Remaining: .crate file bytes (gzipped tar)
#[allow(clippy::result_large_err)]
fn parse_publish_payload(body: &Bytes) -> Result<ParsedPublishPayload, Response> {
    if body.len() < 4 {
        return Err(AppError::Validation("Payload too short".to_string()).into_response());
    }

    let json_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + json_len + 4 {
        return Err(AppError::Validation(
            "Payload too short for metadata + crate length".to_string(),
        )
        .into_response());
    }

    let json_bytes = &body[4..4 + json_len];
    let metadata: serde_json::Value = serde_json::from_slice(json_bytes).map_err(|e| {
        AppError::Validation(format!("Invalid JSON metadata: {}", e)).into_response()
    })?;

    let crate_name = metadata["name"]
        .as_str()
        .ok_or_else(|| {
            AppError::Validation("Missing 'name' in metadata".to_string()).into_response()
        })?
        .to_string();

    let crate_version = metadata["vers"]
        .as_str()
        .ok_or_else(|| {
            AppError::Validation("Missing 'vers' in metadata".to_string()).into_response()
        })?
        .to_string();

    let crate_len_offset = 4 + json_len;
    let crate_len = u32::from_le_bytes([
        body[crate_len_offset],
        body[crate_len_offset + 1],
        body[crate_len_offset + 2],
        body[crate_len_offset + 3],
    ]) as usize;

    let crate_data_offset = crate_len_offset + 4;
    if body.len() < crate_data_offset + crate_len {
        return Err(
            AppError::Validation("Payload too short for .crate data".to_string()).into_response(),
        );
    }

    let crate_bytes =
        Bytes::copy_from_slice(&body[crate_data_offset..crate_data_offset + crate_len]);

    Ok(ParsedPublishPayload {
        metadata,
        crate_name,
        crate_version,
        crate_bytes,
    })
}

/// Build the cargo metadata JSON from the publish request metadata, suitable
/// for storing in the artifact_metadata table.
fn build_cargo_metadata(
    metadata: &serde_json::Value,
    name_lower: &str,
    crate_version: &str,
    checksum: &str,
) -> serde_json::Value {
    let get_or = |key: &str, default: serde_json::Value| -> serde_json::Value {
        metadata.get(key).cloned().unwrap_or(default)
    };

    serde_json::json!({
        "name": name_lower,
        "vers": crate_version,
        "deps": get_or("deps", serde_json::json!([])),
        "features": get_or("features", serde_json::json!({})),
        "description": metadata.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "license": metadata.get("license").and_then(|v| v.as_str()).unwrap_or(""),
        "keywords": get_or("keywords", serde_json::json!([])),
        "categories": get_or("categories", serde_json::json!([])),
        "links": metadata.get("links").cloned(),
        "rust_version": metadata.get("rust_version").and_then(|v| v.as_str()),
        "cksum": checksum,
    })
}

/// Check whether a crate version already exists and return a CONFLICT error if so.
async fn check_duplicate_crate(
    db: &PgPool,
    repo_id: uuid::Uuid,
    name: &str,
    version: &str,
) -> Result<(), Response> {
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo_id,
        name,
        version,
    )
    .fetch_optional(db)
    .await
    .map_err(map_db_err)?;

    if existing.is_some() {
        return Err(Response::builder()
            .status(StatusCode::CONFLICT)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({"errors": [{"detail": format!(
                    "crate version `{}@{}` already exists",
                    name, version
                )}]})
                .to_string(),
            ))
            .unwrap());
    }

    Ok(())
}

/// Store the .crate file and insert artifact + metadata records into the database.
#[allow(clippy::too_many_arguments)]
async fn store_crate_artifact(
    state: &SharedState,
    repo: &RepoInfo,
    name_lower: &str,
    crate_version: &str,
    crate_bytes: Bytes,
    checksum: &str,
    cargo_metadata: serde_json::Value,
    user_id: uuid::Uuid,
) -> Result<(), Response> {
    let filename = format!("{}-{}.crate", name_lower, crate_version);
    let storage_key = format!("cargo/{}/{}/{}", name_lower, crate_version, filename);
    proxy_helpers::guard_cross_repo_write(state, repo.id, &repo.storage_backend, &storage_key)
        .await?;
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, crate_bytes.clone())
        .await
        .map_err(map_storage_err)?;

    let artifact_path = format!("{}/{}/{}", name_lower, crate_version, filename);
    let size_bytes = crate_bytes.len() as i64;

    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Cargo,
        repo.id,
        &artifact_path,
        checksum,
    )
    .await
    .map_err(|e| e.into_response())?;

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
        name_lower,
        crate_version,
        size_bytes,
        checksum,
        "application/x-tar",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(map_db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'cargo', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        cargo_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(())
}

async fn publish(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: a read-scoped service-account token must not be
    // accepted for `cargo publish`. Enforce the write scope on the token
    // before falling back to the Bearer-as-base64 credential path.
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write:artifacts")?;
    let user_id =
        require_auth_with_bearer_fallback(auth, &headers, &state.db, &state.config, "cargo")
            .await?;
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Reject direct uploads to promotion-only repositories. Such repos accept
    // artifacts only via the promotion path, not direct `cargo publish`. The
    // cargo handler owns its own repo struct/cache, so query the flag directly
    // at this commit choke point (stale-proof, no admin exemption).
    let promotion_only = sqlx::query_scalar!(
        "SELECT promotion_only FROM repositories WHERE id = $1",
        repo.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| proxy_helpers::internal_error("Database", e))?
    .unwrap_or(false);
    proxy_helpers::reject_direct_upload_if_promotion_only(promotion_only, false)?;

    let parsed = parse_publish_payload(&body)?;
    let name_lower = parsed.crate_name.to_lowercase();

    check_duplicate_crate(&state.db, repo.id, &name_lower, &parsed.crate_version).await?;

    // Compute SHA256 of the .crate file
    let mut hasher = Sha256::new();
    hasher.update(&parsed.crate_bytes);
    let checksum = format!("{:x}", hasher.finalize());

    let cargo_metadata = build_cargo_metadata(
        &parsed.metadata,
        &name_lower,
        &parsed.crate_version,
        &checksum,
    );

    let size_bytes = parsed.crate_bytes.len() as i64;

    store_crate_artifact(
        &state,
        &repo,
        &name_lower,
        &parsed.crate_version,
        parsed.crate_bytes,
        &checksum,
        cargo_metadata,
        user_id,
    )
    .await?;

    // Invalidate the index cache for this crate so the next fetch sees the new version.
    index_cache_invalidate(&state.index_cache, &format!("{}:{}", repo_key, name_lower)).await;

    // Also invalidate any virtual repos that include this hosted repo.
    let virtual_keys: Vec<String> = sqlx::query_scalar(
        "SELECT r.key FROM repositories r \
         INNER JOIN virtual_repo_members vrm ON r.id = vrm.virtual_repo_id \
         WHERE vrm.member_repo_id = $1",
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for vkey in &virtual_keys {
        index_cache_invalidate(&state.index_cache, &format!("{}:{}", vkey, name_lower)).await;
    }

    info!(
        "Cargo publish: {} {} ({} bytes) to repo {}",
        name_lower, parsed.crate_version, size_bytes, repo_key
    );

    // Cargo expects a JSON response with warnings
    let response = serde_json::json!({
        "warnings": {
            "invalid_categories": [],
            "invalid_badges": [],
            "other": []
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/api/v1/crates/{name}/{version}/download — Download
// ---------------------------------------------------------------------------

async fn download(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;
    let name_lower = name.to_lowercase();

    // Curation enforcement (#2930): block a curated crate before it is resolved
    // locally or proxied from upstream. The cargo handler's private `RepoInfo`
    // does not carry the curation columns, so use the by-id lookup variant
    // (no-op / no query for hosted repos and when curation is off).
    proxy_helpers::enforce_curation_lookup(
        &state.db,
        repo.id,
        &repo_key,
        &repo.repo_type,
        &name_lower,
        Some(&version),
    )
    .await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        name_lower,
        version,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    // If crate not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Resolve the download base URL from the upstream config.json.
                    // This handles split-host registries like crates.io where
                    // the index lives at index.crates.io but downloads come
                    // from crates.io/api/v1/crates.
                    let fallback_path =
                        format!("api/v1/crates/{}/{}/download", name_lower, version);
                    let (dl_base, dl_path) = match resolve_upstream_dl_url(&state, &repo, &repo_key)
                        .await
                    {
                        Some(dl_url) => {
                            let full = build_download_url(&dl_url, &name_lower, &version);
                            // Validate the resolved download URL against SSRF.
                            // A malicious upstream config.json could set `dl` to
                            // a cloud metadata endpoint or internal service URL.
                            validate_outbound_url(&full, "Cargo upstream download URL")
                                .map_err(|e| e.into_response())?;
                            split_url(&full)
                                .unwrap_or_else(|| (upstream_url.clone(), fallback_path.clone()))
                        }
                        None => (upstream_url.clone(), fallback_path.clone()),
                    };

                    // Use the canonical local cache path regardless of which
                    // upstream URL was resolved so that subsequent requests hit
                    // the proxy cache even after a config.json TTL change.
                    let cache_path = format!("api/v1/crates/{}/{}/download", name_lower, version);

                    // Stream the crate rather than buffering it (#895 / #2192,
                    // the cargo instance of that class). This used to be a
                    // `proxy_fetch_capped_with_cache_key` at
                    // `DEFAULT_METADATA_MAX_BYTES`, which is an 8 MiB *metadata*
                    // ceiling applied to an artifact binary:
                    // `read_upstream_response_capped` does not truncate, it
                    // returns `BadGateway` the moment the accumulated body would
                    // exceed the cap — and it does so BEFORE the cache write, so
                    // nothing is persisted and every retry fails identically.
                    // There was no warm-cache escape: a crate over the cap could
                    // never become a cache hit through this path. crates.io's
                    // default publish limit is 10 MiB, so ordinary crates in the
                    // 8-10 MiB band failed outright, as did every crate holding a
                    // raised limit (vendored C/C++ sources, large generated
                    // bindings).
                    //
                    // `dl_base` / `dl_path` / `cache_path` are unchanged, so the
                    // canonical `api/v1/crates/{name}/{version}/download` cache
                    // key is preserved and already-warm entries are not orphaned.
                    // The *metadata* fetches on this handler (config.json, sparse
                    // index) stay capped and buffered — an 8 MiB ceiling is
                    // correct for those.
                    // #2929: gate the proxy-cache commit on the sparse index's
                    // recorded `cksum` for this exact `{name}/{version}`. The
                    // index entry this same handler serves already carries the
                    // digest cargo verifies the download against, but the
                    // download arm reached the streaming helper that hardcodes
                    // `expected_checksum: None`, so the digest was decorative:
                    // a `.crate` whose bytes disagreed with it was committed to
                    // the cache and served warm from then on.
                    //
                    // This cannot catch a wholly compromised registry — index
                    // and bytes could both be forged — but on a split-host
                    // registry (crates.io: `index.crates.io` vs the download
                    // host) it catches a misbehaving or compromised download
                    // host while the index is intact, and it catches ordinary
                    // corruption or a clean-EOF truncation on either. A body
                    // that fails the gate is still streamed to the client
                    // (which verifies it independently and errors); it is only
                    // kept out of the cache.
                    let expected_cksum =
                        resolve_index_cksum(&state, &repo, &repo_key, &name_lower, &version).await;
                    let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
                        proxy,
                        repo.id,
                        &repo_key,
                        &dl_base,
                        &dl_path,
                        &cache_path,
                        expected_cksum,
                        RepositoryFormat::Cargo,
                    )
                    .await?;

                    let filename = format!("{}-{}.crate", name_lower, version);

                    // Headers match what the buffered arm sent, so only the
                    // transfer mechanism changes. In particular the content type
                    // stays pinned to `application/x-tar` rather than forwarding
                    // upstream's (crates.io serves `application/gzip`), keeping
                    // this arm byte-identical to the local-hit arm; and
                    // `Content-Length` is emitted only when upstream advertised
                    // one, otherwise the response is chunked.
                    let mut builder = Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/x-tar")
                        .header(
                            "Content-Disposition",
                            format!("attachment; filename=\"{}\"", filename),
                        )
                        .header("cache-control", "public, max-age=31536000, immutable");
                    if let Some(size) = result.content_length {
                        builder = builder.header(CONTENT_LENGTH, size.to_string());
                    }
                    // The proxy no longer decodes upstream bodies (see
                    // `http_client::base_client_builder`), so a content-coded body
                    // must be declared as such or cargo silently writes compressed
                    // bytes to disk and fails the checksum. `content_length` above
                    // is the coded length, which is what the client reads.
                    if let Some(ref encoding) = result.content_encoding {
                        builder = builder.header(CONTENT_ENCODING, encoding);
                    }
                    // #3446: count the proxied crate. This arm returns the
                    // upstream stream directly, so it never reached the
                    // `record_download` call ~15 lines below on the hosted
                    // path — and `record_download` would not have helped
                    // anyway: it is keyed on an `artifacts.id`, and a
                    // proxy-cached crate has no `artifacts` row. The proxy
                    // recorder is keyed on (repo, path) instead, and the path
                    // is `cache_path` — the same canonical key the streaming
                    // tee commits the catalog row under, so the count and the
                    // listing row line up.
                    proxy_helpers::record_proxy_download(
                        &state,
                        repo.id,
                        &repo_key,
                        &cache_path,
                        &ctx,
                    )
                    .await;
                    return Ok(builder.body(Body::from_stream(result.body)).unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let vname = name_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!("api/v1/crates/{}/{}/download", name_lower, version);

                // Supply-chain shadowing guard (#1217 follow-up, ak-hv3s).
                // If a non-Remote member of this Virtual repo owns the
                // crate name, block Remote members from satisfying the
                // download. The guard runs on the case-folded crate name
                // (`name_lower` is already lowercase). When the guard
                // fires we pass `None` to `resolve_virtual_download` so
                // Remote members fall to `VirtualMemberFetchStrategy::Skip`.
                // The `None` argument is load-bearing: see the comment
                // on `serve_virtual_tarball_local_only` in hex.rs for
                // why any future refactor that threads a real proxy
                // service through this branch would re-open the
                // shadowing attack.
                //
                // Fail-closed: if the requested name does not parse as a
                // valid crate name, do not run the guard. Bad names
                // cannot reach `artifacts.name` (the publish path also
                // rejects them) so the guard would always return false
                // anyway, and skipping it spares the DB an existence
                // check on every malformed request.
                let local_owns = if crate::formats::cargo::is_valid_cargo_name(&name_lower) {
                    proxy_helpers::virtual_non_remote_owns_name(&state.db, repo.id, &name_lower)
                        .await?
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
                    auth.as_ref(),
                    proxy_for_virtual,
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

                let filename = format!("{}-{}.crate", name_lower, version);

                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        result
                            .content_type
                            .unwrap_or_else(|| "application/x-tar".to_string()),
                    )
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    )
                    .header("cache-control", "public, max-age=31536000, immutable");
                if let Some(size) = result.content_length {
                    builder = builder.header(CONTENT_LENGTH, size.to_string());
                }
                // Same reason as the Remote arm above: an undeclared content
                // coding reaches cargo as compressed bytes it will not inflate.
                if let Some(ref encoding) = result.content_encoding {
                    builder = builder.header(CONTENT_ENCODING, encoding);
                }
                return Ok(builder.body(Body::from_stream(result.body)).unwrap());
            }
            return Err(AppError::NotFound("Crate not found".to_string()).into_response());
        }
    };

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let filename = format!("{}-{}.crate", name_lower, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-tar")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        // .crate files are content-addressed and immutable: same name+version
        // always has the same bytes.  Cargo can cache them indefinitely.
        .header("cache-control", "public, max-age=31536000, immutable")
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/index/... — Sparse index endpoints
// ---------------------------------------------------------------------------

/// Index for 1-character crate names: /index/1/{name}
async fn sparse_index_1(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, auth.as_ref(), &repo_key, &name).await
}

/// Index for 2-character crate names: /index/2/{name}
async fn sparse_index_2(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, auth.as_ref(), &repo_key, &name).await
}

/// Index for 3-character crate names: /index/3/{first_char}/{name}
async fn sparse_index_3(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, _prefix, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, auth.as_ref(), &repo_key, &name).await
}

/// Index for 4+ character crate names: /index/{first2}/{next2}/{name}
async fn sparse_index_4plus(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, _prefix1, _prefix2, name)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, auth.as_ref(), &repo_key, &name).await
}

/// Build a single sparse-index JSON entry from crate metadata.
fn build_index_entry(
    crate_name: &str,
    version: &str,
    checksum: &str,
    metadata: Option<&serde_json::Value>,
) -> String {
    let (deps, features, links, rust_version) = extract_index_fields(metadata);

    let mut entry = serde_json::json!({
        "name": crate_name,
        "vers": version,
        "deps": deps,
        "cksum": checksum,
        "features": features,
        "yanked": false,
    });

    if !links.is_null() {
        entry["links"] = links;
    }
    if !rust_version.is_null() {
        entry["rust-version"] = rust_version;
    }

    serde_json::to_string(&entry).unwrap()
}

/// Extract deps, features, links, and rust_version from stored metadata,
/// returning defaults when metadata is absent.
fn extract_index_fields(
    metadata: Option<&serde_json::Value>,
) -> (
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
) {
    let Some(meta) = metadata else {
        return (
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
    };

    // Cargo publish API sends "version_req" but the sparse index format
    // requires "req".  Rename on the fly so clients can parse the index.
    // See https://doc.rust-lang.org/cargo/reference/registry-index.html
    let deps = match meta.get("deps").cloned().unwrap_or(serde_json::json!([])) {
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(|mut dep| {
                    if let serde_json::Value::Object(ref mut map) = dep {
                        if let Some(vr) = map.remove("version_req") {
                            map.entry("req").or_insert(vr);
                        }
                    }
                    dep
                })
                .collect(),
        ),
        other => other,
    };

    (
        deps,
        meta.get("features")
            .cloned()
            .unwrap_or(serde_json::json!({})),
        meta.get("links")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        meta.get("rust_version")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
}

/// Build a JSON response with cache-control for index responses.
///
/// For server-built index bodies (local rows, virtual aggregation, and the
/// in-process cache fast path), which are always uncoded.
fn index_response(content: impl Into<Body>, content_type: Option<String>) -> Response {
    index_response_coded(content, content_type, None)
}

/// [`index_response`] for the one arm that re-serves UPSTREAM bytes verbatim:
/// the Remote sparse-index proxy.
///
/// #3149: the proxy pins `Accept-Encoding: identity` and does not decode
/// upstream bodies, so a sparse index fetched from a coding intermediary
/// arrives still coded. Cargo reads the index as JSON, so an undeclared coding
/// makes it fail to parse the index rather than silently corrupt a `.crate` —
/// it degrades rather than producing a bad artifact, which is why this is the
/// lower-severity half of #3149. `Content-Length` is derived by axum from the
/// bytes actually in the body, so it describes the same coded bytes.
fn index_response_coded(
    content: impl Into<Body>,
    content_type: Option<String>,
    content_encoding: Option<String>,
) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| "application/json".to_string()),
        )
        .header("cache-control", "max-age=300");
    if let Some(ref encoding) = content_encoding {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    builder.body(content.into()).unwrap()
}

/// Try to resolve a crate index from a remote upstream proxy.
async fn try_remote_index(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    name_lower: &str,
    index_cache: &IndexCache,
    cache_key: &str,
) -> Option<Result<Response, Response>> {
    if repo.repo_type != "remote" {
        return None;
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return None,
    };

    let base_url = repo.index_upstream_url.as_deref().unwrap_or(upstream_url);
    let index_path = cargo_sparse_index_path_upstream(name_lower);
    // #3149: the encoding-preserving 3-tuple variant. `proxy_fetch_capped`
    // structurally discards the upstream `Content-Encoding`, so the coded
    // bytes were re-served (and cached) advertised as plain JSON.
    let result = proxy_helpers::proxy_fetch_capped_with_cache_key_and_accept_encoded(
        proxy,
        repo.id,
        repo_key,
        base_url,
        &index_path,
        &index_path,
        None,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await;

    Some(match result {
        Ok((content, content_type, content_encoding)) => {
            // Only memoize UNCODED bytes. The in-process `index_cache` stores
            // bare bytes with no room for a coding, and its fast path serves
            // them as `application/json`, so pinning a coded body here would
            // hand every later hit an undeclared coded index. Coded responses
            // simply skip this cache; the ProxyService's own cache (whose
            // sidecar does carry the coding) still serves them warm through
            // this same arm, which re-declares it.
            if content_encoding.is_none() {
                index_cache_set(index_cache, cache_key.to_string(), content.clone()).await;
            }
            Ok(index_response_coded(
                content,
                content_type,
                content_encoding,
            ))
        }
        Err(e) => Err(e),
    })
}

/// Try to resolve a crate index from a virtual repo's member repositories.
///
/// Iterates members in priority order. Dispatch by member type:
///
/// * **Remote** — always go through [`ProxyService`] (via `proxy_fetch`) so
///   that `__cache_meta__.json` governs freshness (default 24 h, per-repo
///   configurable). This returns the raw upstream sparse-index JSON and
///   therefore stays in sync with yanks, new releases, and dep changes
///   whenever the cache expires. Uses each member's `index_upstream_url`
///   config override when present, falling back to `upstream_url`.
///
/// * **Local / Staging** — the `artifacts` table is authoritative for
///   repos that host crates directly; rebuild the sparse-index lines from
///   DB rows.
///
/// * **Virtual** (nested) — skipped defensively to avoid recursion; not
///   a supported configuration.
///
/// NOTE: This does not use `resolve_virtual_metadata` because cargo index
/// resolution honours `index_upstream_url` config overrides for the proxy
/// URL, which the shared helper does not know about.
///
/// Aggregation semantics (matches helm/conda/cran/rubygems and #1143):
///
/// * Visit every member in priority order rather than stopping at the first
///   member that has data. A virtual cargo repo with both a Local fork and a
///   Remote upstream must surface versions from both, not just the first.
/// * Within a single response, dedupe NDJSON entries by `(name, vers)`. When
///   the same `(name, vers)` appears in more than one member, the entry from
///   the higher-priority member (earlier in the iteration order) wins, which
///   matches the artifact-listing precedence used elsewhere.
#[allow(clippy::result_large_err)]
async fn try_virtual_index(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name_lower: &str,
    index_cache: &IndexCache,
    cache_key: &str,
    cache_shareable: bool,
) -> Option<Result<Response, Response>> {
    use sqlx::Row;

    if repo.repo_type != "virtual" {
        return None;
    }

    // Caller-authorized member walk (#3323): the aggregated sparse index is
    // content — crate names, versions, checksums, dependency lists and yank
    // state — so a member this caller may not read directly must not
    // contribute entries to it.
    let members = match proxy_helpers::authorized_virtual_members(&state.db, auth, repo.id).await {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };

    if members.is_empty() {
        return Some(Err(AppError::NotFound(
            "Virtual repository has no members".to_string(),
        )
        .into_response()));
    }

    // Batch-fetch index_upstream_url overrides for all members in one query.
    let member_ids: Vec<uuid::Uuid> = members.iter().map(|m| m.id).collect();
    let index_url_overrides: HashMap<uuid::Uuid, String> =
        sqlx::query_as::<_, (uuid::Uuid, String)>(
            "SELECT repository_id, value FROM repository_config \
             WHERE repository_id = ANY($1) AND key = 'index_upstream_url' AND value IS NOT NULL",
        )
        .bind(&member_ids)
        .fetch_all(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch index_upstream_url overrides: {}", e);
            Vec::new()
        })
        .into_iter()
        .collect();

    let index_path = cargo_sparse_index_path_upstream(name_lower);

    // Accumulate NDJSON entries across all members. Use a LinkedHashMap-style
    // ordered set keyed by version so that:
    //   * iteration order = first-seen order = priority order;
    //   * a `(name, vers)` already inserted by a higher-priority member is
    //     not overwritten by a lower-priority member's entry.
    //
    // Visit every member in priority order. For each member, pick the lookup
    // strategy that matches its type:
    //
    // * Remote members go straight through the proxy (ProxyService consults
    //   __cache_meta__.json and re-fetches from upstream when the cache has
    //   expired). We deliberately skip the DB-rebuild path for Remote members,
    //   because proxy-cached .crate downloads leave rows in the artifacts
    //   table; rebuilding the sparse index from those rows would serve a
    //   stale snapshot that ignores upstream yanks / new releases and never
    //   re-validates with crates.io. See the PR introducing this change for
    //   details on the prior bypass.
    //
    // * Local and Staging members have no proxy cache; the artifacts table is
    //   the authoritative source for the crates they host. We build the index
    //   from their rows exactly as we do for the top-level hosted case.
    let mut aggregated: Vec<String> = Vec::new();
    let mut seen_versions: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Visit non-Remote (Local/Staging) members before Remote members so a
    // locally-published crate version cannot be shadowed by an upstream
    // entry of the same `(name, vers)`. This mirrors the supply-chain
    // protection applied to Hex package_info in this same PR (#973) and
    // closes the gap where a Remote member configured at higher priority
    // could pre-empt a Local member's authoritative entry.
    let ordered_members = order_members_local_first(&members);

    for member in ordered_members {
        match member.repo_type {
            RepositoryType::Remote => {
                let (Some(proxy), Some(upstream_url)) =
                    (&state.proxy_service, &member.upstream_url)
                else {
                    continue;
                };

                let base_url =
                    resolve_remote_index_base_url(&index_url_overrides, member.id, upstream_url);

                if let Ok((content, _content_type)) = proxy_helpers::proxy_fetch_capped(
                    proxy,
                    member.id,
                    &member.key,
                    &base_url,
                    &index_path,
                    proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
                )
                .await
                {
                    merge_index_lines(&content, &mut aggregated, &mut seen_versions);
                }
            }
            RepositoryType::Local | RepositoryType::Staging => {
                let rows = sqlx::query(
                    r#"
                    SELECT a.name, a.version, a.checksum_sha256,
                           am.metadata
                    FROM artifacts a
                    LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
                    WHERE a.repository_id = $1
                      AND a.name = $2
                      AND a.version IS NOT NULL
                      AND a.is_deleted = false
                    ORDER BY a.created_at ASC
                    "#,
                )
                .bind(member.id)
                .bind(name_lower)
                .fetch_all(&state.db)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("Failed to query artifacts for member {}: {}", member.id, e);
                    Vec::new()
                });

                for row in &rows {
                    let vers: Option<String> = row.get("version");
                    let Some(vers) = vers else { continue };
                    if !seen_versions.insert(vers.clone()) {
                        continue;
                    }
                    let cksum: String = row.get("checksum_sha256");
                    let meta: Option<serde_json::Value> = row.get("metadata");
                    aggregated.push(build_index_entry(name_lower, &vers, &cksum, meta.as_ref()));
                }
            }
            RepositoryType::Virtual => {
                // Nested virtuals are not supported and would cause recursion.
                // Skip defensively rather than attempting a lookup.
                continue;
            }
        }
    }

    match finalize_virtual_index_aggregation(aggregated) {
        Some(Ok(body)) => {
            // Only memoize a document that is the SAME for every caller
            // (#3323). The index cache is keyed by `repo_key:crate`, not by
            // caller, so storing a caller-narrowed aggregation would serve one
            // caller's view to the next — including an anonymous one.
            if cache_shareable {
                index_cache_set(index_cache, cache_key.to_string(), body.clone()).await;
            }
            Some(Ok(index_response(
                body,
                Some("application/json".to_string()),
            )))
        }
        Some(Err(resp)) => Some(Err(resp)),
        None => None,
    }
}

/// Order virtual repo members so non-Remote members come before Remote
/// members, preserving the original priority ordering within each group.
///
/// Pure function so the supply-chain-shadowing rule can be unit-tested
/// without standing up a real virtual-repo configuration. Non-Remote-first
/// ordering prevents an upstream from shadowing a locally-published crate
/// version even when the admin configures the Remote member at a higher
/// raw priority than the Local member (#1143).
///
/// Matches the equivalent helper in `hex.rs` so the two formats apply the
/// same supply-chain protection. Keeping a local copy (rather than sharing
/// via `proxy_helpers`) avoids cross-module churn for a 6-line function;
/// the followup to consolidate is tracked in the review notes.
fn order_members_local_first(
    members: &[crate::models::repository::Repository],
) -> Vec<&crate::models::repository::Repository> {
    let mut ordered: Vec<&crate::models::repository::Repository> =
        Vec::with_capacity(members.len());
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

/// Pick the upstream base URL to use when fetching a virtual member's
/// sparse-index NDJSON. An entry in `repository_config.index_upstream_url`
/// overrides the member's primary `upstream_url`, so an admin can point
/// e.g. a github.com Cargo registry at a separate index host without
/// editing the artifact upstream. Pure to keep tested without DB.
fn resolve_remote_index_base_url(
    overrides: &HashMap<uuid::Uuid, String>,
    member_id: uuid::Uuid,
    fallback_upstream_url: &str,
) -> String {
    overrides
        .get(&member_id)
        .cloned()
        .unwrap_or_else(|| fallback_upstream_url.to_string())
}

/// Decide what `try_virtual_index` should return given the aggregated
/// NDJSON lines collected from every member. Returns `Some(Ok(body))`
/// when there are entries to serve, `Some(Err(404 response))` when no
/// member contributed anything. Returning `None` is reserved for the
/// "skip the virtual path entirely" pre-check before aggregation; this
/// helper does not produce it.
#[allow(clippy::result_large_err)]
fn finalize_virtual_index_aggregation(aggregated: Vec<String>) -> Option<Result<Bytes, Response>> {
    if aggregated.is_empty() {
        return Some(Err(AppError::NotFound(
            "Artifact not found in any member repository".to_string(),
        )
        .into_response()));
    }
    Some(Ok(Bytes::from(aggregated.join("\n"))))
}

/// Merge sparse-index NDJSON lines from one member into the running
/// aggregate, skipping any line whose `vers` field has already been
/// contributed by a higher-priority member. Lines that fail to parse as
/// JSON or are missing `vers` are preserved at the cost of dedup so the
/// client still sees them, matching the helm/conda merge behaviour for
/// malformed upstream data.
fn merge_index_lines(
    content: &[u8],
    aggregated: &mut Vec<String>,
    seen_versions: &mut std::collections::HashSet<String>,
) {
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return,
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("vers").and_then(|x| x.as_str()).map(String::from))
        {
            Some(vers) => {
                if seen_versions.insert(vers) {
                    aggregated.push(line.to_string());
                }
            }
            None => {
                // Unparseable line: keep it so we don't silently drop data,
                // but don't track it in the dedup set.
                aggregated.push(line.to_string());
            }
        }
    }
}

/// Serve the sparse index file for a crate (one JSON object per version, per line).
async fn serve_index(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo_key: &str,
    crate_name: &str,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, repo_key, &state.repo_cache).await?;
    let name_lower = crate_name.to_lowercase();

    let cache_key = format!("{}:{}", repo_key, name_lower);

    // Whether the in-process index cache — keyed by `repo_key:crate`, not by
    // caller — may be read or written for this repository (#3323). A virtual
    // repo aggregates its members' entries, and that aggregation is now
    // narrowed to the members THIS caller may read, so it is only shareable
    // when every member is public.
    let cache_shareable = proxy_helpers::virtual_aggregate_cacheable(
        &state.db,
        repo.id,
        repo.repo_type == RepositoryType::Virtual,
    )
    .await;

    // Fast path: serve from in-process index cache (no storage I/O, no SHA-256).
    if cache_shareable {
        if let Some(cached) = index_cache_get(&state.index_cache, &cache_key).await {
            return Ok(index_response(cached, Some("application/json".to_string())));
        }
    }

    // Remote and virtual repos never have directly-published artifacts — publishes
    // are rejected by reject_write_if_not_hosted.  Skip the artifacts DB query and
    // go straight to the appropriate upstream/member lookup.
    if repo.repo_type == "remote" {
        return match try_remote_index(
            state,
            &repo,
            repo_key,
            &name_lower,
            &state.index_cache,
            &cache_key,
        )
        .await
        {
            Some(result) => result,
            None => Err(AppError::NotFound("Crate not found in index".to_string()).into_response()),
        };
    }
    if repo.repo_type == "virtual" {
        return match try_virtual_index(
            state,
            auth,
            &repo,
            &name_lower,
            &state.index_cache,
            &cache_key,
            cache_shareable,
        )
        .await
        {
            Some(result) => result,
            None => Err(AppError::NotFound("Crate not found in index".to_string()).into_response()),
        };
    }

    // Fetch all versions of this crate with their metadata
    let versions = sqlx::query!(
        r#"
        SELECT a.name, a.version as "version?", a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.is_deleted = false
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        name_lower,
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

    if versions.is_empty() {
        if let Some(result) = try_remote_index(
            state,
            &repo,
            repo_key,
            &name_lower,
            &state.index_cache,
            &cache_key,
        )
        .await
        {
            return result;
        }
        if let Some(result) = try_virtual_index(
            state,
            auth,
            &repo,
            &name_lower,
            &state.index_cache,
            &cache_key,
            cache_shareable,
        )
        .await
        {
            return result;
        }
        return Err(AppError::NotFound("Crate not found in index".to_string()).into_response());
    }

    // Build index file: one JSON object per line
    let lines: Vec<String> = versions
        .iter()
        .map(|v| {
            let vers = v.version.as_deref().unwrap_or("0.0.0");
            build_index_entry(&name_lower, vers, &v.checksum_sha256, v.metadata.as_ref())
        })
        .collect();

    let body = bytes::Bytes::from(lines.join("\n"));
    index_cache_set(&state.index_cache, cache_key, body.clone()).await;
    Ok(index_response(body, Some("application/json".to_string())))
}

/// Build the sparse index path for a crate name following the Cargo registry layout.
/// Includes the `index/` prefix used by artifact-keeper's own routing.
#[cfg_attr(not(test), allow(dead_code))]
fn cargo_sparse_index_path(name: &str) -> String {
    format!("index/{}", cargo_sparse_index_path_upstream(name))
}

/// Build the upstream sparse index path for proxying to an external registry.
///
/// The Cargo sparse registry protocol stores index files at the path root
/// (e.g. `https://index.crates.io/se/rd/serde`), so no `index/` prefix is
/// used when constructing the proxy request path.
fn cargo_sparse_index_path_upstream(name: &str) -> String {
    match name.len() {
        1 => format!("1/{}", name),
        2 => format!("2/{}", name),
        3 => format!("3/{}/{}", &name[..1], name),
        _ => format!("{}/{}/{}", &name[..2], &name[2..4], name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    // ── #2929: the sparse-index cksum must gate the .crate cache commit ──

    const CKSUM_A: &str = "abc1230000000000000000000000000000000000000000000000000000000def";

    #[test]
    fn test_cksum_for_version_picks_the_matching_version() {
        let ndjson = format!(
            "{{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"{}\"}}\n\
             {{\"name\":\"serde\",\"vers\":\"1.0.1\",\"cksum\":\"{}\"}}",
            CKSUM_A,
            "2".repeat(64)
        );
        assert_eq!(
            super::cksum_for_version(ndjson.as_bytes(), "1.0.0").as_deref(),
            Some(CKSUM_A),
            "the digest must be the one recorded for the requested version"
        );
        assert_eq!(
            super::cksum_for_version(ndjson.as_bytes(), "1.0.1").as_deref(),
            Some("2".repeat(64).as_str())
        );
        assert_ne!(
            CKSUM_A,
            CKSUM_A.to_uppercase(),
            "the fixture must contain hex letters or the case test below is vacuous"
        );
        assert_eq!(
            super::cksum_for_version(ndjson.as_bytes(), "9.9.9"),
            None,
            "an absent version means no enforceable digest, not a wrong one"
        );
    }

    #[test]
    fn test_cksum_for_version_degrades_on_unusable_input() {
        // A non-canonical cksum must read as "no digest available" rather than
        // being enforced: it could never equal the streamed lowercase-hex
        // SHA-256, so enforcing it would reject the crate on every fetch and
        // re-pull upstream forever.
        let prefixed = format!("{{\"vers\":\"1.0.0\",\"cksum\":\"sha256:{CKSUM_A}\"}}");
        assert_eq!(super::cksum_for_version(prefixed.as_bytes(), "1.0.0"), None);

        let upper = format!(
            "{{\"vers\":\"1.0.0\",\"cksum\":\"{}\"}}",
            CKSUM_A.to_uppercase()
        );
        assert_eq!(super::cksum_for_version(upper.as_bytes(), "1.0.0"), None);

        assert_eq!(super::cksum_for_version(b"not json at all", "1.0.0"), None);
        assert_eq!(super::cksum_for_version(b"", "1.0.0"), None);
        assert_eq!(
            super::cksum_for_version(b"{\"vers\":\"1.0.0\"}", "1.0.0"),
            None,
            "an entry with no cksum is not a digest"
        );
    }

    /// A malformed line must not hide a good entry further down: the sparse
    /// index is NDJSON produced by a third party, and a single bad line
    /// silently disabling the digest gate for the whole crate would make the
    /// guard trivially bypassable by a hostile index.
    #[test]
    fn test_cksum_for_version_skips_a_malformed_line() {
        let ndjson = format!("this-is-not-json\n{{\"vers\":\"1.0.0\",\"cksum\":\"{CKSUM_A}\"}}");
        assert_eq!(
            super::cksum_for_version(ndjson.as_bytes(), "1.0.0").as_deref(),
            Some(CKSUM_A)
        );
    }

    // ── #3480 Phase 1: age-gate sparse-index filtering (pure helpers) ──

    // ---- parse_cargo_pubtime ----

    #[test]
    fn test_parse_cargo_pubtime_valid_strict_format() {
        use chrono::TimeZone;
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15T09:30:00Z"),
            Some(chrono::Utc.with_ymd_and_hms(2024, 3, 15, 9, 30, 0).unwrap())
        );
    }

    #[test]
    fn test_parse_cargo_pubtime_old_timestamp() {
        use chrono::TimeZone;
        // "old" — well outside any plausible min-age window.
        assert_eq!(
            super::parse_cargo_pubtime("1970-01-01T00:00:00Z"),
            Some(chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
        );
    }

    #[test]
    fn test_parse_cargo_pubtime_young_timestamp() {
        use chrono::TimeZone;
        // "young" — the incident's actual publish instant (arrayref 0.3.10).
        assert_eq!(
            super::parse_cargo_pubtime("2026-08-20T07:15:00Z"),
            Some(chrono::Utc.with_ymd_and_hms(2026, 8, 20, 7, 15, 0).unwrap())
        );
    }

    #[test]
    fn test_parse_cargo_pubtime_boundary_leap_day_valid() {
        use chrono::TimeZone;
        // 2024 is a leap year: Feb 29 is a valid calendar date.
        assert_eq!(
            super::parse_cargo_pubtime("2024-02-29T23:59:59Z"),
            Some(
                chrono::Utc
                    .with_ymd_and_hms(2024, 2, 29, 23, 59, 59)
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_parse_cargo_pubtime_boundary_non_leap_year_rejected() {
        // 2023 is not a leap year: Feb 29 does not exist.
        assert_eq!(super::parse_cargo_pubtime("2023-02-29T00:00:00Z"), None);
    }

    #[test]
    fn test_parse_cargo_pubtime_boundary_out_of_range_components_rejected() {
        assert_eq!(
            super::parse_cargo_pubtime("2024-13-01T00:00:00Z"),
            None,
            "month 13 is out of range"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-01-32T00:00:00Z"),
            None,
            "day 32 is out of range"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-01-01T24:00:00Z"),
            None,
            "hour 24 is out of range"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-01-01T00:60:00Z"),
            None,
            "minute 60 is out of range"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-01-01T00:00:60Z"),
            None,
            "a leap second is outside the spec-strict grammar"
        );
    }

    #[test]
    fn test_parse_cargo_pubtime_missing_and_malformed() {
        assert_eq!(super::parse_cargo_pubtime(""), None);
        assert_eq!(super::parse_cargo_pubtime("not a timestamp"), None);
        assert_eq!(
            super::parse_cargo_pubtime("2024-01-01"),
            None,
            "a bare date has no time component"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024/01/01T00:00:00Z"),
            None,
            "slashes instead of hyphens"
        );
    }

    /// Deliberate spec-strict divergence from Cargo's own (jiff-based) RFC
    /// 3339 leniency — see the doc comment on `parse_cargo_pubtime`. These
    /// forms are exactly what upstream `pubtime`-carrying registries could
    /// legally emit under full RFC 3339 but this parser rejects.
    #[test]
    fn test_parse_cargo_pubtime_strict_divergence_from_cargo_leniency() {
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15T09:30:00.123Z"),
            None,
            "fractional seconds are accepted by jiff but not the registry-index spec"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15T09:30:00.000000001Z"),
            None,
            "nanosecond-precision fractional seconds"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15T09:30:00+00:00"),
            None,
            "a numeric UTC offset is accepted by jiff but not the registry-index spec"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15T09:30:00-05:00"),
            None,
            "a non-UTC numeric offset"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15t09:30:00z"),
            None,
            "lowercase T/Z are outside the spec-strict grammar"
        );
        assert_eq!(
            super::parse_cargo_pubtime("2024-03-15 09:30:00Z"),
            None,
            "a space separator instead of T is valid RFC 3339 but not this grammar"
        );
    }

    // ---- collect_cargo_index_versions ----

    #[test]
    fn test_collect_cargo_index_versions_extracts_vers_and_pubtime_in_order() {
        let ndjson = concat!(
            "{\"name\":\"arrayref\",\"vers\":\"0.3.9\",\"cksum\":\"aa\",\"pubtime\":\"2020-01-01T00:00:00Z\"}\n",
            "{\"name\":\"arrayref\",\"vers\":\"0.3.10\",\"cksum\":\"bb\",\"pubtime\":\"2026-08-20T07:15:00Z\"}\n",
        );
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].0, "0.3.9");
        assert_eq!(
            versions[0].1,
            super::parse_cargo_pubtime("2020-01-01T00:00:00Z")
        );
        assert_eq!(versions[1].0, "0.3.10");
        assert_eq!(
            versions[1].1,
            super::parse_cargo_pubtime("2026-08-20T07:15:00Z")
        );
    }

    #[test]
    fn test_collect_cargo_index_versions_missing_pubtime_is_none() {
        let ndjson = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(versions, vec![("1.0.0".to_string(), None)]);
    }

    #[test]
    fn test_collect_cargo_index_versions_malformed_pubtime_is_none_not_an_error() {
        let ndjson =
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"pubtime\":\"not-a-timestamp\"}";
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(versions, vec![("1.0.0".to_string(), None)]);
    }

    #[test]
    fn test_collect_cargo_index_versions_omits_malformed_json_line_but_keeps_others() {
        let ndjson = concat!(
            "this-is-not-json\n",
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}\n",
        );
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(
            versions,
            vec![("1.0.0".to_string(), None)],
            "a malformed line must not hide a later good one, and must not itself surface"
        );
    }

    #[test]
    fn test_collect_cargo_index_versions_line_missing_vers_field_omitted() {
        let ndjson = concat!(
            "{\"name\":\"x\",\"cksum\":\"aa\"}\n",
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}\n",
        );
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(versions, vec![("1.0.0".to_string(), None)]);
    }

    #[test]
    fn test_collect_cargo_index_versions_blank_lines_skipped() {
        let ndjson = concat!(
            "\n",
            "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}\n",
            "\n\n",
            "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\"}\n",
            "\n",
        );
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(
            versions,
            vec![("1.0.0".to_string(), None), ("1.0.1".to_string(), None)]
        );
    }

    #[test]
    fn test_collect_cargo_index_versions_invalid_utf8_line_omitted_others_kept() {
        let mut ndjson: Vec<u8> = Vec::new();
        ndjson.extend_from_slice(b"{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}\n");
        ndjson.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // not valid UTF-8
        ndjson.push(b'\n');
        ndjson.extend_from_slice(b"{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\"}");
        let versions = super::collect_cargo_index_versions(&ndjson);
        assert_eq!(
            versions,
            vec![("1.0.0".to_string(), None), ("1.0.1".to_string(), None)],
            "the invalid-UTF-8 line must be omitted without corrupting neighboring lines"
        );
    }

    #[test]
    fn test_collect_cargo_index_versions_yanked_entry_still_extracted() {
        // `yanked` is not part of the age-gate contract; a yanked-but-young
        // entry is still evaluated (and, once wired, still blockable) like
        // any other.
        let ndjson = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"yanked\":true,\"pubtime\":\"2026-08-20T07:15:00Z\"}";
        let versions = super::collect_cargo_index_versions(ndjson.as_bytes());
        assert_eq!(
            versions,
            vec![(
                "1.0.0".to_string(),
                super::parse_cargo_pubtime("2026-08-20T07:15:00Z")
            )]
        );
    }

    #[test]
    fn test_collect_cargo_index_versions_empty_document() {
        assert!(super::collect_cargo_index_versions(b"").is_empty());
    }

    // ---- filter_cargo_index_lines ----

    #[test]
    fn test_filter_cargo_index_lines_preserves_allowed_lines_byte_for_byte_and_in_order() {
        let line_a = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"deps\":[]}";
        let line_b = "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\",\"deps\":[]}";
        let ndjson = format!("{line_a}\n{line_b}");
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(filtered.as_ref(), format!("{line_a}\n{line_b}").as_bytes());
    }

    #[test]
    fn test_filter_cargo_index_lines_drops_blocked_versions_entirely() {
        let line_a = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let line_b = "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\"}";
        let line_c = "{\"name\":\"x\",\"vers\":\"1.0.2\",\"cksum\":\"cc\"}";
        let ndjson = format!("{line_a}\n{line_b}\n{line_c}");
        let mut blocked = HashSet::new();
        blocked.insert("1.0.1".to_string());
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(
            filtered.as_ref(),
            format!("{line_a}\n{line_c}").as_bytes(),
            "the blocked version's line must be dropped entirely, survivors stay in order"
        );
    }

    #[test]
    fn test_filter_cargo_index_lines_drops_malformed_line_even_when_gate_enabled() {
        // Fail-closed contract: an unparseable line is omitted regardless of
        // the blocked set, because its version/time was never evaluated.
        let good = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let ndjson = format!("this-is-not-json\n{good}");
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(filtered.as_ref(), good.as_bytes());
    }

    #[test]
    fn test_filter_cargo_index_lines_drops_line_missing_vers_field() {
        let good = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let ndjson = format!("{{\"name\":\"x\",\"cksum\":\"aa\"}}\n{good}");
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(filtered.as_ref(), good.as_bytes());
    }

    #[test]
    fn test_filter_cargo_index_lines_blank_lines_dropped() {
        let line_a = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let line_b = "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\"}";
        let ndjson = format!("\n{line_a}\n\n\n{line_b}\n\n");
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(filtered.as_ref(), format!("{line_a}\n{line_b}").as_bytes());
    }

    #[test]
    fn test_filter_cargo_index_lines_invalid_utf8_line_dropped() {
        let good = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let mut ndjson: Vec<u8> = Vec::new();
        ndjson.extend_from_slice(&[0xFF, 0xFE]);
        ndjson.push(b'\n');
        ndjson.extend_from_slice(good.as_bytes());
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(&ndjson, &blocked);
        assert_eq!(filtered.as_ref(), good.as_bytes());
    }

    #[test]
    fn test_filter_cargo_index_lines_yanked_entry_follows_the_same_blocked_set() {
        // yanked:true must not exempt a version from the age gate, and must
        // not itself trigger the malformed-line fail-closed path.
        let yanked_allowed = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"yanked\":true}";
        let yanked_blocked = "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\",\"yanked\":true}";
        let ndjson = format!("{yanked_allowed}\n{yanked_blocked}");
        let mut blocked = HashSet::new();
        blocked.insert("1.0.1".to_string());
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert_eq!(
            filtered.as_ref(),
            yanked_allowed.as_bytes(),
            "yanked is orthogonal to the age-gate block decision"
        );
    }

    #[test]
    fn test_filter_cargo_index_lines_all_blocked_yields_empty_document() {
        let ndjson = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\"}";
        let mut blocked = HashSet::new();
        blocked.insert("1.0.0".to_string());
        let filtered = super::filter_cargo_index_lines(ndjson.as_bytes(), &blocked);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_cargo_index_lines_empty_document() {
        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(b"", &blocked);
        assert!(filtered.is_empty());
    }

    /// Decoded-body (identity content-coding) coverage at this pure layer:
    /// bytes that already represent the identity-coded document round-trip
    /// through both helpers with no surprises. Stripping an actual upstream
    /// content-coding (gzip/deflate/zstd) before calling either helper is
    /// Phase 2's job (`strip_content_coding`, per the module comment above);
    /// these helpers only ever see decoded bytes.
    #[test]
    fn test_identity_decoded_body_round_trips_through_collect_and_filter() {
        let line_a = "{\"name\":\"x\",\"vers\":\"1.0.0\",\"cksum\":\"aa\",\"pubtime\":\"2020-01-01T00:00:00Z\"}";
        let line_b = "{\"name\":\"x\",\"vers\":\"1.0.1\",\"cksum\":\"bb\",\"pubtime\":\"2026-08-20T07:15:00Z\"}";
        let ndjson = format!("{line_a}\n{line_b}");
        let decoded: Bytes = Bytes::from(ndjson.clone().into_bytes());

        let versions = super::collect_cargo_index_versions(&decoded);
        assert_eq!(versions.len(), 2);

        let blocked = HashSet::new();
        let filtered = super::filter_cargo_index_lines(&decoded, &blocked);
        assert_eq!(filtered.as_ref(), ndjson.as_bytes());
    }

    /// Fixture shared by the two #2929 cache-gate tests below.
    ///
    /// Serves a sparse-index document recording `index_cksum` for
    /// `{name}/{version}` and a download host serving `body`, then issues two
    /// cold requests through the real router. The upstream download mock is
    /// pinned to `expected_download_hits`, which is what actually distinguishes
    /// the two cases: a committed cache entry makes the second request a hit
    /// (1 upstream fetch), a refused commit makes it another miss (2).
    ///
    /// Returns the served bodies plus the proxy cache dir so the caller can
    /// assert on what was persisted.
    async fn run_cargo_download_with_index_cksum(
        name: &str,
        version: &str,
        body: Vec<u8>,
        index_cksum: &str,
        expected_download_hits: u64,
    ) -> Option<(Vec<u8>, Vec<u8>, tempfile::TempDir)> {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method as wm_method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let fx = tdh::Fixture::setup("remote", "cargo").await?;

        let server = MockServer::start().await;

        // The sparse index this same handler proxies. `cksum` is the digest the
        // download is gated on.
        let index_doc = format!(
            "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"cksum\":\"{index_cksum}\",\"deps\":[],\"features\":{{}},\"yanked\":false}}\n"
        );
        Mock::given(wm_method("GET"))
            .and(wm_path(format!(
                "/{}",
                cargo_sparse_index_path_upstream(name)
            )))
            .respond_with(ResponseTemplate::new(200).set_body_string(index_doc))
            .mount(&server)
            .await;

        Mock::given(wm_method("GET"))
            .and(wm_path(format!("/api/v1/crates/{name}/{version}/download")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .expect(expected_download_hits)
            .mount(&server)
            .await;

        let (state, dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let request_path = format!(
            "/cargo/{}/api/v1/crates/{}/{}/download",
            fx.repo_key, name, version
        );

        let (cold_status, cold_body) = tdh::send(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(request_path.clone()),
        )
        .await;
        assert_eq!(
            cold_status,
            StatusCode::OK,
            "cold download must succeed; body was {}",
            String::from_utf8_lossy(&cold_body)
        );

        // Give the asynchronous tee its chance to commit either way. The
        // matching case must commit (and does so well inside this budget); the
        // mismatching case must still not have committed when the budget
        // expires, which is what makes the negative assertion meaningful rather
        // than a race the test happens to win.
        for _ in 0..400 {
            if tdh::committed_cache_entry_exists(dir.path(), body.len() as u64) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let (warm_status, warm_body) = tdh::send(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(request_path),
        )
        .await;
        assert_eq!(warm_status, StatusCode::OK, "second download must succeed");

        fx.teardown().await;
        // Dropping the MockServer verifies `.expect(...)`.
        drop(server);

        Some((cold_body.to_vec(), warm_body.to_vec(), dir))
    }

    /// #2929: a `.crate` whose bytes match the sparse index's recorded `cksum`
    /// is committed to the proxy cache and served warm from then on.
    ///
    /// The companion to the mismatch test below — without this one, "never
    /// commits anything" would also pass.
    #[tokio::test]
    async fn test_remote_crate_download_commits_cache_on_matching_index_cksum_2929() {
        let name = "gated-crate";
        let version = "2.0.0";
        let body = b"a plausible .crate tarball payload".repeat(32);
        let good = crate::services::storage_service::StorageService::calculate_hash(&body);

        // One upstream download: the second request is served from the cache.
        let Some((cold, warm, dir)) =
            run_cargo_download_with_index_cksum(name, version, body.clone(), &good, 1).await
        else {
            return;
        };

        assert_eq!(&cold[..], &body[..], "cold read must serve upstream bytes");
        assert_eq!(&warm[..], &body[..], "warm read must serve identical bytes");
        assert!(
            crate::api::handlers::test_db_helpers::committed_cache_entry_exists(
                dir.path(),
                body.len() as u64
            ),
            "a digest-matching body must be committed to the proxy cache (#2929)"
        );
    }

    /// #2929: a `.crate` whose bytes DISAGREE with the sparse index's recorded
    /// `cksum` must never be committed to the proxy cache.
    ///
    /// This is the regression that the source-grep test it replaces could only
    /// approximate. It fails if the download arm is reverted to the unverified
    /// streaming helper, if the resolved digest is passed as `None`, or if the
    /// gate is moved after the cache write — none of which a text assertion on
    /// this file can distinguish from a working gate.
    ///
    /// The body is still streamed to the client: cargo verifies the download
    /// against this same `cksum` itself and will reject it, and truncating the
    /// response would only turn a detected corruption into an ambiguous one.
    /// What must not happen is the bad body becoming a warm cache entry served
    /// to everyone afterwards.
    #[tokio::test]
    async fn test_remote_crate_download_refuses_cache_commit_on_cksum_mismatch_2929() {
        let name = "forged-crate";
        let version = "3.1.4";
        let body = b"bytes that do not match the recorded cksum".repeat(32);
        // Well-formed (bare lowercase 64-hex) so it passes
        // `normalize_expected_sha256` and is actually enforced, rather than
        // being discarded as "no digest available".
        let wrong = "9".repeat(64);
        assert_ne!(
            wrong,
            crate::services::storage_service::StorageService::calculate_hash(&body),
            "fixture digest must actually differ or the test proves nothing"
        );

        // Two upstream downloads: nothing was cached, so the second request is
        // another cold miss.
        let Some((cold, warm, dir)) =
            run_cargo_download_with_index_cksum(name, version, body.clone(), &wrong, 2).await
        else {
            return;
        };

        assert_eq!(
            &cold[..],
            &body[..],
            "the client is still served the full body; cargo verifies it independently"
        );
        assert_eq!(&warm[..], &body[..], "the refetch serves the full body too");
        assert!(
            !crate::api::handlers::test_db_helpers::committed_cache_entry_exists(
                dir.path(),
                body.len() as u64
            ),
            "a body failing the index cksum must NOT be committed to the proxy cache (#2929)"
        );
    }

    /// #3446: a PROXIED crate download must increment the Downloads counter.
    ///
    /// The Remote arm returns the upstream stream directly, so it never reached
    /// the hosted `record_download` further down the function — and that call
    /// could not have helped anyway, because it resolves an `artifacts.id` and
    /// a proxy-cached crate has no `artifacts` row. The failure was silent: the
    /// crate was served correctly and the counter simply never moved.
    ///
    /// Asserted through `download_counts_by_paths`, the same lookup the
    /// artifact listing uses (#3388), so this pins the number an operator
    /// actually sees rather than just the fact that a row was written. Two
    /// requests are made — a cold miss and a warm cache hit — because the two
    /// take different paths through the handler and BOTH must count.
    #[tokio::test]
    async fn test_proxied_crate_download_is_counted_3446() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method as wm_method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };

        let name = "counted-crate";
        let version = "0.4.2";
        let body = b"a small but real crate body".repeat(8);

        let server = MockServer::start().await;
        Mock::given(wm_method("GET"))
            .and(wm_path(format!("/api/v1/crates/{name}/{version}/download")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let (state, _dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let request_path = format!(
            "/cargo/{}/api/v1/crates/{}/{}/download",
            fx.repo_key, name, version
        );

        // The canonical proxy-cache key the handler records under, which is
        // also the `proxy_cache_artifacts.path` the listing renders.
        let cache_path = format!("api/v1/crates/{name}/{version}/download");
        let counted = |pool: sqlx::PgPool, repo_id: uuid::Uuid, path: String| async move {
            crate::services::proxy_catalog::download_counts_by_paths(
                &pool,
                repo_id,
                std::slice::from_ref(&path),
            )
            .await
            .expect("count proxy downloads")
            .get(&path)
            .copied()
            .unwrap_or(0)
        };

        assert_eq!(
            counted(fx.pool.clone(), fx.repo_id, cache_path.clone()).await,
            0,
            "negative control: nothing is counted before the first download"
        );

        for expected in 1..=2i64 {
            let (status, served) = tdh::send(
                tdh::router_anon(mounted_router(), state.clone()),
                tdh::get(request_path.clone()),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "proxied crate download must succeed"
            );
            assert_eq!(&served[..], &body[..], "the full crate body is served");
            assert_eq!(
                counted(fx.pool.clone(), fx.repo_id, cache_path.clone()).await,
                expected,
                "#3446: proxied crate download {expected} must be counted (cold miss \
                 then warm cache hit); a 0 here is the original bug"
            );
        }
    }

    /// Regression test for the cargo instance of the buffered-download class
    /// (#895 / #2192).
    ///
    /// The Remote arm used to fetch the `.crate` through
    /// `proxy_fetch_capped_with_cache_key` at `DEFAULT_METADATA_MAX_BYTES`, an
    /// 8 MiB *metadata* ceiling applied to an artifact binary. The capped reader
    /// does not truncate — it returns `BadGateway` as soon as the accumulated
    /// body would exceed the cap, and it does so before the cache write, so the
    /// failure was permanent: nothing was persisted and every retry failed
    /// identically. crates.io's default publish limit is 10 MiB, so ordinary
    /// crates in the 8-10 MiB band could never be downloaded through a Remote
    /// cargo repository.
    ///
    /// The body is deliberately non-uniform and position-dependent so a
    /// truncate-or-pad regression cannot satisfy the byte-equality assertion.
    /// Both a cold and a warm request are checked, with the upstream mock
    /// expecting exactly one hit, so this also proves the streamed body is tee'd
    /// into the proxy cache rather than refetched.
    #[tokio::test]
    async fn test_remote_crate_download_streams_body_over_metadata_cap() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method as wm_method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };

        let name = "big-crate";
        let version = "1.2.3";
        let body: Vec<u8> = (0..(9 * 1024 * 1024u32))
            .map(|i| ((i.wrapping_mul(31)) ^ (i >> 11)) as u8)
            .collect();
        assert!(
            body.len() > proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            "fixture must exceed the metadata cap or the test proves nothing",
        );

        let server = MockServer::start().await;
        let upstream_path = format!("/api/v1/crates/{name}/{version}/download");
        Mock::given(wm_method("GET"))
            .and(wm_path(upstream_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let (state, dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let request_path = format!(
            "/cargo/{}/api/v1/crates/{}/{}/download",
            fx.repo_key, name, version
        );

        let (cold_status, cold_body) = tdh::send(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(request_path.clone()),
        )
        .await;

        assert_eq!(
            cold_status,
            StatusCode::OK,
            "a .crate larger than the 8 MiB buffered cap must stream, not 502; body was {}",
            String::from_utf8_lossy(&cold_body)
        );
        assert_eq!(cold_body.len(), body.len(), "full body must be served");
        assert_eq!(
            &cold_body[..],
            &body[..],
            "served bytes must match upstream"
        );

        // The streaming tee commits asynchronously, so wait for the cached body
        // to land before asserting the warm read is served from it — otherwise the
        // second request races the writer and refetches upstream.
        tdh::wait_for_cache_commit(dir.path(), body.len() as u64).await;

        // Second request must be served from the proxy cache; the mock's
        // `.expect(1)` fails on drop if the tee did not commit.
        let (warm_status, warm_body) = tdh::send(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(request_path),
        )
        .await;

        fx.teardown().await;

        assert_eq!(warm_status, StatusCode::OK, "warm read must also succeed");
        assert_eq!(
            &warm_body[..],
            &body[..],
            "warm read must serve the identical bytes"
        );
    }

    /// #2920: a content-coded upstream `.crate` must arrive declared.
    ///
    /// The Remote arm builds its response by hand rather than through
    /// `build_streaming_response_with_disposition`, deliberately, so the content
    /// type stays pinned to `application/x-tar` instead of taking upstream's
    /// `application/gzip`. The hand-rolled builder read `content_length` off
    /// `StreamingFetchResult` and dropped `content_encoding` one line later.
    ///
    /// Since #2915 the proxy no longer decodes upstream bodies, so an undeclared
    /// coding reaches cargo as compressed bytes it will not inflate: the client
    /// writes them to disk and fails the index `cksum`. This needs an
    /// intermediary that applies a transfer coding (a corporate proxy, nginx
    /// with gzip on, a mirror); crates.io itself does not trigger it.
    ///
    /// The body is asserted to arrive still compressed and byte-identical, so a
    /// regression that re-enables transparent decoding fails here too.
    #[tokio::test]
    async fn test_remote_crate_download_forwards_upstream_content_encoding() {
        use crate::api::handlers::test_db_helpers as tdh;
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use wiremock::matchers::{method as wm_method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };

        let name = "coded-crate";
        let version = "0.4.1";
        let plain = b"\x1f\x8b fake .crate tarball payload, repeated. ".repeat(64);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plain).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");
        assert_ne!(
            compressed, plain,
            "fixture must actually be coded or the test proves nothing"
        );

        let server = MockServer::start().await;
        Mock::given(wm_method("GET"))
            .and(wm_path(format!("/api/v1/crates/{name}/{version}/download")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(compressed.clone()),
            )
            .mount(&server)
            .await;

        let (state, _dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        // `tdh::send` drops the headers, which are the subject of this test.
        let (status, body, headers) = tdh::send_with_headers(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(format!(
                "/cargo/{}/api/v1/crates/{}/{}/download",
                fx.repo_key, name, version
            )),
        )
        .await;

        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "upstream Content-Encoding must be forwarded, or cargo writes \
             undecodable bytes to disk and fails the checksum",
        );
        assert_eq!(
            &body[..],
            &compressed[..],
            "the coded bytes must be passed through untouched",
        );
        // The pinned content type is the reason this arm hand-rolls its
        // response; guard it here so a future move to the shared helper cannot
        // silently start forwarding upstream's `application/gzip`.
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-tar"),
        );
    }

    /// Sibling of the Remote-arm test above, for the VIRTUAL arm.
    ///
    /// #2920 names both download arms, and both hand-roll their response, so
    /// both dropped `content_encoding`. The fix touched both but shipped a test
    /// for only one -- leaving the virtual arm free to regress silently. This
    /// closes that: it fails on the pre-fix code exactly as the Remote-arm test
    /// does.
    #[tokio::test]
    async fn test_virtual_crate_download_forwards_upstream_content_encoding() {
        use crate::api::handlers::test_db_helpers as tdh;
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use wiremock::matchers::{method as wm_method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Remote member that actually proxies, plus the virtual repo in front.
        let Some(member) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };
        let Some(virt) = tdh::Fixture::setup("virtual", "cargo").await else {
            member.teardown().await;
            return;
        };

        let name = "virt-coded-crate";
        let version = "1.2.3";
        let plain = b"\x1f\x8b fake .crate tarball payload, repeated. ".repeat(64);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plain).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");
        assert_ne!(
            compressed, plain,
            "fixture must actually be coded or the test proves nothing"
        );

        let server = MockServer::start().await;
        Mock::given(wm_method("GET"))
            .and(wm_path(format!("/api/v1/crates/{name}/{version}/download")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(compressed.clone()),
            )
            .mount(&server)
            .await;

        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virt.repo_id)
        .bind(member.repo_id)
        .execute(&virt.pool)
        .await
        .expect("link remote member into the virtual repo");

        // #3178: the virtual byte path filters members by CALLER, and this
        // request is ANONYMOUS. The subject here is Content-Encoding
        // forwarding, not authorization, so publish both repositories --
        // `require_visible` early-returns on a public repo. Before #3178 an
        // anonymous caller was served a PRIVATE member's bytes, which is
        // exactly the bug; that behaviour is now asserted (inverted) in
        // `repositories::virtual_member_authz_tests`.
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = ANY($1)")
            .bind(vec![virt.repo_id, member.repo_id])
            .execute(&virt.pool)
            .await
            .expect("publish the virtual repo and its member");

        let (state, _dir) = tdh::rewire_remote_proxy(&member, &server.uri()).await;
        let (status, body, headers) = tdh::send_with_headers(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(format!(
                "/cargo/{}/api/v1/crates/{}/{}/download",
                virt.repo_key, name, version
            )),
        )
        .await;

        virt.teardown().await;
        member.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "the virtual arm must forward upstream Content-Encoding too, or \
             cargo writes undecodable bytes and fails the checksum",
        );
        assert_eq!(
            &body[..],
            &compressed[..],
            "the coded bytes must be passed through untouched",
        );
    }

    fn make_publish_payload(metadata: &serde_json::Value, crate_data: &[u8]) -> Bytes {
        let json_bytes = serde_json::to_vec(metadata).unwrap();
        let json_len = json_bytes.len() as u32;
        let crate_len = crate_data.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);
        Bytes::from(payload)
    }

    fn sample_metadata() -> serde_json::Value {
        serde_json::json!({
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [{"name": "serde", "req": "^1.0", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"default": ["serde"]},
            "description": "A test crate",
            "license": "MIT",
            "keywords": ["test", "example"],
            "categories": ["development-tools"],
            "links": null,
            "rust_version": "1.70.0"
        })
    }

    /// #2022: a direct `cargo publish` (PUT /api/v1/crates/new) to a
    /// `promotion_only` repository must be rejected with 409 CONFLICT; the same
    /// publish to a normal repository must still succeed. Cargo owns its own
    /// repo struct/cache, so the gate is a direct scalar query at the publish
    /// choke point. Skips when no test database is configured.
    #[tokio::test]
    async fn test_publish_blocked_on_promotion_only_repo() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "cargo").await else {
            return;
        };

        let crate_data = b"fake-crate-tarball-bytes";
        let payload = make_publish_payload(&sample_metadata(), crate_data);
        let uri = format!("/{}/api/v1/crates/new", fx.repo_key);

        // Flag the repo promotion_only -> direct publish is rejected with 409.
        fx.set_promotion_only(true).await;
        let app = tdh::router_with_auth(
            super::router(),
            fx.state.clone(),
            tdh::make_auth(fx.user_id, &fx.username),
        );
        let req = tdh::put(uri.clone(), payload.clone());
        let (blocked_status, _) = tdh::send(app, req).await;

        // Clear the flag -> the same publish succeeds.
        fx.set_promotion_only(false).await;
        let app = tdh::router_with_auth(
            super::router(),
            fx.state.clone(),
            tdh::make_auth(fx.user_id, &fx.username),
        );
        let req = tdh::put(uri, payload);
        let (allowed_status, allowed_body) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            blocked_status,
            StatusCode::CONFLICT,
            "promotion_only direct publish must return 409"
        );
        assert_eq!(
            allowed_status,
            StatusCode::OK,
            "publish to a normal repo must still succeed; body: {}",
            String::from_utf8_lossy(&allowed_body)
        );
    }

    // -----------------------------------------------------------------------
    // build_search_response — meta.total must reflect the total match count
    // across all pages, not the (LIMIT-truncated) current page length (#1777)
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_meta_total_reflects_total_not_page_len() {
        // One crate on the current page, but 3 total matches across all pages.
        let page: Vec<serde_json::Value> = vec![serde_json::json!({
            "name": "alpha-crate",
            "max_version": "0.1.0",
            "description": "",
        })];
        let resp = build_search_response(page, 3);
        assert_eq!(resp["crates"].as_array().unwrap().len(), 1);
        // Regression: previously this used crate_list.len() (== 1) and broke
        // cargo search pagination. It must be the real total (3).
        assert_eq!(resp["meta"]["total"], serde_json::json!(3));
    }

    #[test]
    fn test_search_meta_total_zero_when_no_matches() {
        let resp = build_search_response(Vec::new(), 0);
        assert_eq!(resp["crates"].as_array().unwrap().len(), 0);
        assert_eq!(resp["meta"]["total"], serde_json::json!(0));
    }

    // -----------------------------------------------------------------------
    // merge_index_lines (virtual repo NDJSON aggregation, #1143)
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_index_lines_first_member_wins_on_collision() {
        // Local member already contributed serde 1.0.0; the upstream's
        // serde 1.0.0 line must not overwrite it. Higher-priority
        // member's `cksum` is preserved.
        let mut aggregated: Vec<String> =
            vec![r#"{"name":"serde","vers":"1.0.0","cksum":"LOCAL"}"#.to_string()];
        let mut seen: std::collections::HashSet<String> =
            ["1.0.0".to_string()].into_iter().collect();
        let upstream = b"{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"UPSTREAM\"}\n{\"name\":\"serde\",\"vers\":\"1.0.1\",\"cksum\":\"UPSTREAM\"}";
        merge_index_lines(upstream, &mut aggregated, &mut seen);
        // 1.0.0 stays as LOCAL, 1.0.1 added from upstream.
        assert_eq!(aggregated.len(), 2);
        assert!(aggregated[0].contains("LOCAL"));
        assert!(aggregated[1].contains("1.0.1"));
        assert!(seen.contains("1.0.0"));
        assert!(seen.contains("1.0.1"));
    }

    #[test]
    fn test_merge_index_lines_skips_blank_lines() {
        let mut aggregated: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let upstream = b"\n\n{\"name\":\"foo\",\"vers\":\"0.1.0\"}\n\n";
        merge_index_lines(upstream, &mut aggregated, &mut seen);
        assert_eq!(aggregated.len(), 1);
    }

    #[test]
    fn test_merge_index_lines_keeps_unparseable_lines() {
        // A malformed NDJSON line (not JSON, no `vers`) is preserved
        // verbatim so we don't silently drop upstream data.
        let mut aggregated: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let upstream = b"not-json\n{\"name\":\"foo\",\"vers\":\"0.1.0\"}";
        merge_index_lines(upstream, &mut aggregated, &mut seen);
        assert_eq!(aggregated.len(), 2);
        assert_eq!(aggregated[0], "not-json");
    }

    #[test]
    fn test_merge_index_lines_handles_invalid_utf8() {
        // A non-UTF-8 body is a no-op rather than a panic.
        let mut aggregated: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let bytes: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x80];
        merge_index_lines(&bytes, &mut aggregated, &mut seen);
        assert!(aggregated.is_empty());
        assert!(seen.is_empty());
    }

    // -----------------------------------------------------------------------
    // resolve_remote_index_base_url (#1143)
    //
    // Pure helper for the virtual-index Remote-member path: picks the
    // `repository_config.index_upstream_url` override when present, else
    // falls back to the member's primary `upstream_url`. Exercising it
    // directly avoids spinning up a DB just to verify the precedence
    // table.
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_remote_index_base_url_uses_override_when_present() {
        let id = uuid::Uuid::new_v4();
        let mut overrides: HashMap<uuid::Uuid, String> = HashMap::new();
        overrides.insert(id, "https://override.example/index".to_string());
        let base = resolve_remote_index_base_url(&overrides, id, "https://upstream.example");
        assert_eq!(base, "https://override.example/index");
    }

    #[test]
    fn test_resolve_remote_index_base_url_falls_back_to_upstream_when_no_override() {
        let id = uuid::Uuid::new_v4();
        let overrides: HashMap<uuid::Uuid, String> = HashMap::new();
        let base = resolve_remote_index_base_url(&overrides, id, "https://upstream.example");
        assert_eq!(base, "https://upstream.example");
    }

    #[test]
    fn test_resolve_remote_index_base_url_override_only_applies_to_matching_member() {
        // Override is registered for *another* member's id; the current
        // member should still get its primary upstream URL.
        let target_id = uuid::Uuid::new_v4();
        let other_id = uuid::Uuid::new_v4();
        let mut overrides: HashMap<uuid::Uuid, String> = HashMap::new();
        overrides.insert(other_id, "https://override.example/index".to_string());
        let base = resolve_remote_index_base_url(&overrides, target_id, "https://upstream.example");
        assert_eq!(base, "https://upstream.example");
    }

    // -----------------------------------------------------------------------
    // finalize_virtual_index_aggregation (#1143)
    //
    // Decides between an aggregated NDJSON body and a 404 when no member
    // contributed any line. The pre-cache step happens in the caller so
    // this helper is purely a body-or-not-found decision.
    // -----------------------------------------------------------------------

    #[test]
    fn test_finalize_virtual_index_aggregation_returns_body_when_lines_present() {
        let lines = vec![
            r#"{"name":"foo","vers":"1.0.0"}"#.to_string(),
            r#"{"name":"foo","vers":"1.0.1"}"#.to_string(),
        ];
        let out = finalize_virtual_index_aggregation(lines)
            .expect("Some(_) when called from aggregation path");
        let body = out.expect("Ok(body) when lines were aggregated");
        // Lines are joined with `\n` (no trailing newline added).
        let text = std::str::from_utf8(&body).expect("utf-8 NDJSON");
        assert!(text.contains("1.0.0"));
        assert!(text.contains("1.0.1"));
        assert!(text.contains('\n'));
    }

    #[test]
    fn test_finalize_virtual_index_aggregation_returns_404_when_empty() {
        let out = finalize_virtual_index_aggregation(Vec::new()).expect("Some(_)");
        let resp = out.expect_err("empty aggregation must surface as 404");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // order_members_local_first (cargo virtual-index shadowing guard, #1143)
    //
    // Mirrors the equivalent hex.rs tests: Local/Staging members must
    // precede Remote members in the iteration so a Remote-hosted crate
    // version cannot pre-empt a locally-published `(name, vers)`.
    // -----------------------------------------------------------------------

    fn make_cargo_member(
        repo_type: RepositoryType,
        key: &str,
    ) -> crate::models::repository::Repository {
        use crate::models::repository::{ReplicationPriority, Repository, RepositoryFormat};
        Repository {
            versioning_enabled: false,
            id: uuid::Uuid::new_v4(),
            key: key.to_string(),
            name: key.to_string(),
            description: None,
            format: RepositoryFormat::Cargo,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: String::new(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 0,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            project_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_order_members_local_first_cargo_puts_local_before_remote() {
        // Admin configured Remote at higher raw priority. The helper must
        // still surface Local first so an upstream `serde 1.0.0` cannot
        // shadow a locally-published `serde 1.0.0`.
        let m1 = make_cargo_member(RepositoryType::Remote, "crates-io");
        let m2 = make_cargo_member(RepositoryType::Local, "internal-fork");
        let members = vec![m1, m2];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered[0].key, "internal-fork");
        assert_eq!(ordered[1].key, "crates-io");
    }

    #[test]
    fn test_order_members_local_first_cargo_preserves_within_group_order() {
        // Within each group, original input order is preserved so
        // configured priority still matters when there is no shadowing
        // conflict to resolve.
        let m1 = make_cargo_member(RepositoryType::Staging, "stage");
        let m2 = make_cargo_member(RepositoryType::Remote, "crates-io");
        let m3 = make_cargo_member(RepositoryType::Local, "fork");
        let m4 = make_cargo_member(RepositoryType::Remote, "mirror");
        let members = vec![m1, m2, m3, m4];
        let ordered = order_members_local_first(&members);
        assert_eq!(ordered[0].key, "stage");
        assert_eq!(ordered[1].key, "fork");
        assert_eq!(ordered[2].key, "crates-io");
        assert_eq!(ordered[3].key, "mirror");
    }

    #[test]
    fn test_order_members_local_first_cargo_empty_input() {
        let members: Vec<crate::models::repository::Repository> = Vec::new();
        let ordered = order_members_local_first(&members);
        assert!(ordered.is_empty());
    }

    // -----------------------------------------------------------------------
    // cargo_sparse_index_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_cargo_sparse_index_path_1_char() {
        assert_eq!(cargo_sparse_index_path("a"), "index/1/a");
    }

    #[test]
    fn test_cargo_sparse_index_path_2_char() {
        assert_eq!(cargo_sparse_index_path("ab"), "index/2/ab");
    }

    #[test]
    fn test_cargo_sparse_index_path_3_char() {
        assert_eq!(cargo_sparse_index_path("abc"), "index/3/a/abc");
    }

    #[test]
    fn test_cargo_sparse_index_path_4_char() {
        assert_eq!(cargo_sparse_index_path("abcd"), "index/ab/cd/abcd");
    }

    #[test]
    fn test_cargo_sparse_index_path_long_name() {
        assert_eq!(
            cargo_sparse_index_path("serde_json"),
            "index/se/rd/serde_json"
        );
    }

    #[test]
    fn test_cargo_sparse_index_path_5_char() {
        assert_eq!(cargo_sparse_index_path("tokio"), "index/to/ki/tokio");
    }

    #[test]
    fn test_cargo_sparse_index_path_exact_4() {
        assert_eq!(cargo_sparse_index_path("rand"), "index/ra/nd/rand");
    }

    #[test]
    fn test_cargo_sparse_index_path_hyphenated() {
        assert_eq!(cargo_sparse_index_path("my-crate"), "index/my/-c/my-crate");
    }

    #[test]
    fn test_cargo_sparse_index_path_underscore() {
        assert_eq!(
            cargo_sparse_index_path("tokio_util"),
            "index/to/ki/tokio_util"
        );
    }

    // -----------------------------------------------------------------------
    // cargo_sparse_index_path_upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_cargo_sparse_index_path_upstream_1char() {
        assert_eq!(cargo_sparse_index_path_upstream("a"), "1/a");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_2char() {
        assert_eq!(cargo_sparse_index_path_upstream("ab"), "2/ab");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_3char() {
        assert_eq!(cargo_sparse_index_path_upstream("abc"), "3/a/abc");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_serde() {
        assert_eq!(cargo_sparse_index_path_upstream("serde"), "se/rd/serde");
    }

    // -----------------------------------------------------------------------
    // Root-level sparse index route path construction
    // -----------------------------------------------------------------------

    /// Verify that the root-level route path for a 4+ char crate matches what
    /// a standard Cargo client would request: `/{repo}/se/rd/serde` (no index/ prefix).
    #[test]
    fn test_sparse_index_root_route_4plus() {
        let path = cargo_sparse_index_path_upstream("serde");
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "se");
        assert_eq!(parts[1], "rd");
        assert_eq!(parts[2], "serde");
    }

    // -----------------------------------------------------------------------
    // parse_publish_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_publish_payload_too_short() {
        let body = Bytes::from_static(&[0, 0, 0]);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_exactly_4_bytes_no_json() {
        let body = Bytes::from_static(&[10, 0, 0, 0]);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_json_but_no_crate_length() {
        let metadata = serde_json::json!({"name": "x", "vers": "1.0.0"});
        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let json_len = json_bytes.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        // Missing 4-byte crate length
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_invalid_json() {
        let bad_json = b"not json{{{";
        let json_len = bad_json.len() as u32;
        let crate_data = b"data";
        let crate_len = crate_data.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(bad_json);
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_missing_name() {
        let metadata = serde_json::json!({"vers": "1.0.0"});
        let body = make_publish_payload(&metadata, b"crate-bytes");
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_missing_vers() {
        let metadata = serde_json::json!({"name": "my-crate"});
        let body = make_publish_payload(&metadata, b"crate-bytes");
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_crate_data_truncated() {
        let metadata = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let json_len = json_bytes.len() as u32;
        let declared_crate_len: u32 = 100;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&declared_crate_len.to_le_bytes());
        payload.extend_from_slice(b"short"); // only 5 bytes, declared 100
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_valid_minimal() {
        let metadata = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let crate_data = b"fake-tarball-data";
        let body = make_publish_payload(&metadata, crate_data);

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "my-crate");
        assert_eq!(parsed.crate_version, "1.0.0");
        assert_eq!(parsed.crate_bytes.as_ref(), crate_data);
        assert_eq!(parsed.metadata["name"], "my-crate");
        assert_eq!(parsed.metadata["vers"], "1.0.0");
    }

    #[test]
    fn test_parse_publish_payload_valid_full_metadata() {
        let metadata = sample_metadata();
        let crate_data = b"compressed-tarball-bytes-here";
        let body = make_publish_payload(&metadata, crate_data);

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "my-crate");
        assert_eq!(parsed.crate_version, "0.1.0");
        assert_eq!(parsed.crate_bytes.len(), crate_data.len());
        assert_eq!(parsed.metadata["description"], "A test crate");
        assert_eq!(parsed.metadata["license"], "MIT");
    }

    #[test]
    fn test_parse_publish_payload_empty_crate_data() {
        let metadata = serde_json::json!({"name": "empty", "vers": "0.0.1"});
        let body = make_publish_payload(&metadata, b"");

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "empty");
        assert_eq!(parsed.crate_version, "0.0.1");
        assert!(parsed.crate_bytes.is_empty());
    }

    #[test]
    fn test_parse_publish_payload_preserves_all_metadata_fields() {
        let metadata = serde_json::json!({
            "name": "full-crate",
            "vers": "2.0.0",
            "deps": [{"name": "tokio", "req": "^1"}],
            "features": {"async": ["tokio"]},
            "description": "Full featured crate",
            "license": "Apache-2.0",
            "keywords": ["async", "runtime"],
            "categories": ["asynchronous"],
            "links": "native-lib",
            "rust_version": "1.75.0"
        });
        let body = make_publish_payload(&metadata, b"data");

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.metadata["deps"][0]["name"], "tokio");
        assert_eq!(parsed.metadata["features"]["async"][0], "tokio");
        assert_eq!(parsed.metadata["keywords"][0], "async");
        assert_eq!(parsed.metadata["links"], "native-lib");
        assert_eq!(parsed.metadata["rust_version"], "1.75.0");
    }

    // -----------------------------------------------------------------------
    // build_cargo_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cargo_metadata_minimal() {
        let input = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let result = build_cargo_metadata(&input, "my-crate", "1.0.0", "abc123");

        assert_eq!(result["name"], "my-crate");
        assert_eq!(result["vers"], "1.0.0");
        assert_eq!(result["cksum"], "abc123");
        assert_eq!(result["deps"], serde_json::json!([]));
        assert_eq!(result["features"], serde_json::json!({}));
        assert_eq!(result["description"], "");
        assert_eq!(result["license"], "");
        assert_eq!(result["keywords"], serde_json::json!([]));
        assert_eq!(result["categories"], serde_json::json!([]));
    }

    #[test]
    fn test_build_cargo_metadata_full() {
        let input = sample_metadata();
        let result = build_cargo_metadata(&input, "my-crate", "0.1.0", "deadbeef");

        assert_eq!(result["name"], "my-crate");
        assert_eq!(result["vers"], "0.1.0");
        assert_eq!(result["cksum"], "deadbeef");
        assert_eq!(result["description"], "A test crate");
        assert_eq!(result["license"], "MIT");
        assert_eq!(result["rust_version"], "1.70.0");
        assert_eq!(result["keywords"], serde_json::json!(["test", "example"]));
        assert_eq!(
            result["categories"],
            serde_json::json!(["development-tools"])
        );
        assert!(result["links"].is_null());

        let deps = result["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0]["name"], "serde");
    }

    #[test]
    fn test_build_cargo_metadata_uses_name_lower_not_original() {
        let input = serde_json::json!({"name": "My-Crate", "vers": "1.0.0"});
        let result = build_cargo_metadata(&input, "my-crate", "1.0.0", "checksum");
        assert_eq!(result["name"], "my-crate");
    }

    #[test]
    fn test_build_cargo_metadata_with_links() {
        let input = serde_json::json!({
            "name": "openssl-sys",
            "vers": "0.9.0",
            "links": "openssl"
        });
        let result = build_cargo_metadata(&input, "openssl-sys", "0.9.0", "sum");
        assert_eq!(result["links"], "openssl");
    }

    #[test]
    fn test_build_cargo_metadata_deps_preserved() {
        let deps = serde_json::json!([
            {"name": "serde", "req": "^1.0", "features": ["derive"], "optional": false, "default_features": true, "target": null, "kind": "normal"},
            {"name": "tokio", "req": "^1", "features": ["full"], "optional": false, "default_features": true, "target": null, "kind": "normal"}
        ]);
        let input = serde_json::json!({"name": "x", "vers": "1.0.0", "deps": deps});
        let result = build_cargo_metadata(&input, "x", "1.0.0", "sum");
        assert_eq!(result["deps"].as_array().unwrap().len(), 2);
        assert_eq!(result["deps"][1]["name"], "tokio");
    }

    #[test]
    fn test_build_cargo_metadata_features_preserved() {
        let input = serde_json::json!({
            "name": "x",
            "vers": "1.0.0",
            "features": {
                "default": ["std"],
                "std": [],
                "serde": ["dep:serde"]
            }
        });
        let result = build_cargo_metadata(&input, "x", "1.0.0", "sum");
        let features = result["features"].as_object().unwrap();
        assert_eq!(features.len(), 3);
        assert_eq!(features["default"], serde_json::json!(["std"]));
        assert_eq!(features["serde"], serde_json::json!(["dep:serde"]));
    }

    // -----------------------------------------------------------------------
    // extract_index_fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_index_fields_none() {
        let (deps, features, links, rust_version) = extract_index_fields(None);
        assert_eq!(deps, serde_json::json!([]));
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert!(rust_version.is_null());
    }

    #[test]
    fn test_extract_index_fields_empty_object() {
        let meta = serde_json::json!({});
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps, serde_json::json!([]));
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert!(rust_version.is_null());
    }

    #[test]
    fn test_extract_index_fields_with_all_fields() {
        let meta = serde_json::json!({
            "deps": [{"name": "serde", "req": "^1"}],
            "features": {"default": ["std"]},
            "links": "native-lib",
            "rust_version": "1.70.0"
        });
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps, serde_json::json!([{"name": "serde", "req": "^1"}]));
        assert_eq!(features, serde_json::json!({"default": ["std"]}));
        assert_eq!(links, "native-lib");
        assert_eq!(rust_version, "1.70.0");
    }

    #[test]
    fn test_extract_index_fields_partial() {
        let meta = serde_json::json!({
            "deps": [{"name": "log"}],
            "rust_version": "1.56.0"
        });
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps.as_array().unwrap().len(), 1);
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert_eq!(rust_version, "1.56.0");
    }

    // -----------------------------------------------------------------------
    // build_index_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_index_entry_no_metadata() {
        let entry_str = build_index_entry("my-crate", "1.0.0", "abcdef1234", None);
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert_eq!(entry["name"], "my-crate");
        assert_eq!(entry["vers"], "1.0.0");
        assert_eq!(entry["cksum"], "abcdef1234");
        assert_eq!(entry["deps"], serde_json::json!([]));
        assert_eq!(entry["features"], serde_json::json!({}));
        assert_eq!(entry["yanked"], false);
        assert!(entry.get("links").is_none());
        assert!(entry.get("rust-version").is_none());
    }

    #[test]
    fn test_build_index_entry_with_metadata() {
        let meta = serde_json::json!({
            "deps": [{"name": "serde", "req": "^1.0", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"derive": ["serde/derive"]},
            "links": "openssl",
            "rust_version": "1.75.0"
        });
        let entry_str = build_index_entry("openssl-sys", "0.9.102", "deadbeef", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert_eq!(entry["name"], "openssl-sys");
        assert_eq!(entry["vers"], "0.9.102");
        assert_eq!(entry["cksum"], "deadbeef");
        assert_eq!(entry["yanked"], false);
        assert_eq!(entry["deps"][0]["name"], "serde");
        assert_eq!(entry["features"]["derive"][0], "serde/derive");
        assert_eq!(entry["links"], "openssl");
        assert_eq!(entry["rust-version"], "1.75.0");
    }

    #[test]
    fn test_build_index_entry_without_links_or_rust_version() {
        let meta = serde_json::json!({
            "deps": [],
            "features": {}
        });
        let entry_str = build_index_entry("simple", "0.1.0", "aaa", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert!(entry.get("links").is_none());
        assert!(entry.get("rust-version").is_none());
    }

    #[test]
    fn test_build_index_entry_is_valid_json() {
        let entry_str = build_index_entry("test", "0.0.1", "checksum", None);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&entry_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_build_index_entry_yanked_is_always_false() {
        let meta = serde_json::json!({"deps": [], "features": {}});
        let entry_str = build_index_entry("crate", "1.0.0", "cksum", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();
        assert_eq!(entry["yanked"], false);
    }

    #[test]
    fn test_build_index_entry_normalises_dep_version_req_field() {
        // Cargo publish sends "version_req" but the sparse index requires "req".
        // If metadata already uses "req" (e.g. proxied index), it passes through.
        // See https://doc.rust-lang.org/cargo/reference/registry-index.html
        let cases: &[(&str, &str)] = &[("version_req", "^1.0"), ("req", "^0.4")];
        for &(field, ver) in cases {
            let meta = serde_json::json!({
                "deps": [{ "name": "dep", field: ver, "kind": "normal" }],
                "features": {}
            });
            let entry_str = build_index_entry("test-crate", "0.1.0", "aaa", Some(&meta));
            let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();
            let dep = &entry["deps"][0];
            assert_eq!(dep["req"], ver, "field '{field}' should produce req={ver}");
            assert!(
                dep.get("version_req").is_none(),
                "version_req must be absent for '{field}'"
            );
        }
    }

    // -----------------------------------------------------------------------
    // index_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_response_default_content_type() {
        let resp = index_response("test body", None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "max-age=300");
    }

    #[test]
    fn test_index_response_custom_content_type() {
        let resp = index_response("body", Some("text/plain".to_string()));
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
    }

    #[test]
    fn test_index_response_status_is_ok() {
        let resp = index_response("", None);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_index_response_cache_control() {
        let resp = index_response("data", None);
        let cache = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "max-age=300");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (same logic used in publish)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation_deterministic() {
        let data = b"test crate data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);

        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let checksum2 = format!("{:x}", hasher2.finalize());
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_sha256_different_data() {
        let mut h1 = Sha256::new();
        h1.update(b"data1");
        let c1 = format!("{:x}", h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(b"data2");
        let c2 = format!("{:x}", h2.finalize());

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_sha256_empty_input() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_known_value() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(
            checksum,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    // -----------------------------------------------------------------------
    // Storage path and key construction (patterns from store_crate_artifact)
    // -----------------------------------------------------------------------

    fn build_crate_filename(name: &str, version: &str) -> String {
        format!("{}-{}.crate", name, version)
    }

    fn build_crate_storage_key(name: &str, version: &str, filename: &str) -> String {
        format!("cargo/{}/{}/{}", name, version, filename)
    }

    fn build_crate_artifact_path(name: &str, version: &str, filename: &str) -> String {
        format!("{}/{}/{}", name, version, filename)
    }

    #[test]
    fn test_crate_filename() {
        assert_eq!(build_crate_filename("serde", "1.0.0"), "serde-1.0.0.crate");
        assert_eq!(
            build_crate_filename("my-crate", "0.1.0"),
            "my-crate-0.1.0.crate"
        );
        assert_eq!(
            build_crate_filename("tokio", "1.35.1"),
            "tokio-1.35.1.crate"
        );
    }

    #[test]
    fn test_crate_storage_key() {
        let filename = build_crate_filename("serde", "1.0.0");
        let key = build_crate_storage_key("serde", "1.0.0", &filename);
        assert_eq!(key, "cargo/serde/1.0.0/serde-1.0.0.crate");
    }

    #[test]
    fn test_crate_artifact_path() {
        let filename = build_crate_filename("tokio", "1.35.1");
        let path = build_crate_artifact_path("tokio", "1.35.1", &filename);
        assert_eq!(path, "tokio/1.35.1/tokio-1.35.1.crate");
    }

    #[test]
    fn test_crate_storage_key_hyphenated_name() {
        let filename = build_crate_filename("my-cool-crate", "2.0.0-rc.1");
        let key = build_crate_storage_key("my-cool-crate", "2.0.0-rc.1", &filename);
        assert_eq!(
            key,
            "cargo/my-cool-crate/2.0.0-rc.1/my-cool-crate-2.0.0-rc.1.crate"
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-remote".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://crates.io".to_string()),
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "remote");
        assert_eq!(info.upstream_url.as_deref(), Some("https://crates.io"));
    }

    #[test]
    fn test_repo_info_remote_with_index_upstream_url() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-remote".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://crates.io".to_string()),
            index_upstream_url: Some("https://index.crates.io".to_string()),
        };
        assert_eq!(info.upstream_url.as_deref(), Some("https://crates.io"));
        assert_eq!(
            info.index_upstream_url.as_deref(),
            Some("https://index.crates.io")
        );
    }

    #[test]
    fn test_repo_info_virtual() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-virtual".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "virtual".to_string(),
            upstream_url: None,
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "virtual");
    }

    // -----------------------------------------------------------------------
    // Config JSON URL construction
    // -----------------------------------------------------------------------

    fn build_config_json(base_url: &str, repo_key: &str) -> serde_json::Value {
        serde_json::json!({
            "dl": format!("{}/cargo/{}/api/v1/crates", base_url, repo_key),
            "api": format!("{}/cargo/{}", base_url, repo_key),
        })
    }

    #[test]
    fn test_config_json_url_construction() {
        let config = build_config_json("http://localhost:8080", "cargo-hosted");
        assert_eq!(
            config["dl"],
            "http://localhost:8080/cargo/cargo-hosted/api/v1/crates"
        );
        assert_eq!(config["api"], "http://localhost:8080/cargo/cargo-hosted");
    }

    #[test]
    fn test_config_json_url_https() {
        let config = build_config_json("https://registry.example.com", "main");
        assert_eq!(
            config["dl"],
            "https://registry.example.com/cargo/main/api/v1/crates"
        );
        assert_eq!(config["api"], "https://registry.example.com/cargo/main");
    }

    #[test]
    fn test_config_json_base_url_construction() {
        let scheme = "https";
        let host = "my.registry.com";
        let base_url = format!("{}://{}", scheme, host);
        assert_eq!(base_url, "https://my.registry.com");
    }

    #[test]
    fn test_config_json_base_url_with_port() {
        let scheme = "http";
        let host = "localhost:8080";
        let base_url = format!("{}://{}", scheme, host);
        assert_eq!(base_url, "http://localhost:8080");
    }

    // -----------------------------------------------------------------------
    // Publish response format
    // -----------------------------------------------------------------------

    #[test]
    fn test_publish_response_format() {
        let response = serde_json::json!({
            "warnings": {
                "invalid_categories": [],
                "invalid_badges": [],
                "other": []
            }
        });
        assert!(response["warnings"]["invalid_categories"].is_array());
        assert!(response["warnings"]["invalid_badges"].is_array());
        assert!(response["warnings"]["other"].is_array());
        assert_eq!(
            response["warnings"]["invalid_categories"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    // -----------------------------------------------------------------------
    // Download content-disposition header format
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_content_disposition() {
        let name_lower = "serde_json";
        let version = "1.0.120";
        let filename = format!("{}-{}.crate", name_lower, version);
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(header, "attachment; filename=\"serde_json-1.0.120.crate\"");
    }

    #[test]
    fn test_download_content_disposition_hyphenated() {
        let filename = format!("{}-{}.crate", "my-cool-crate", "0.1.0-alpha.1");
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(
            header,
            "attachment; filename=\"my-cool-crate-0.1.0-alpha.1.crate\""
        );
    }

    // -----------------------------------------------------------------------
    // Search response construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_response_structure() {
        let crate_list: Vec<serde_json::Value> = vec![
            serde_json::json!({"name": "serde", "max_version": "1.0.0", "description": "Serialization"}),
            serde_json::json!({"name": "serde_json", "max_version": "1.0.120", "description": "JSON"}),
        ];
        let response = serde_json::json!({
            "crates": crate_list,
            "meta": {
                "total": crate_list.len(),
            }
        });
        assert_eq!(response["crates"].as_array().unwrap().len(), 2);
        assert_eq!(response["meta"]["total"], 2);
        assert_eq!(response["crates"][0]["name"], "serde");
    }

    #[test]
    fn test_search_response_empty() {
        let crate_list: Vec<serde_json::Value> = vec![];
        let response = serde_json::json!({
            "crates": crate_list,
            "meta": {
                "total": crate_list.len(),
            }
        });
        assert_eq!(response["crates"].as_array().unwrap().len(), 0);
        assert_eq!(response["meta"]["total"], 0);
    }

    #[test]
    fn test_search_description_extraction_from_metadata() {
        let metadata_text = r#"{"description": "A fast JSON library", "license": "MIT"}"#;
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "A fast JSON library");
    }

    #[test]
    fn test_search_description_extraction_missing() {
        let metadata_text = r#"{"license": "MIT"}"#;
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "");
    }

    #[test]
    fn test_search_description_extraction_invalid_json() {
        let metadata_text = "not json at all";
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "");
    }

    // -----------------------------------------------------------------------
    // per_page clamping (same logic as search_crates)
    // -----------------------------------------------------------------------

    #[test]
    fn test_per_page_default() {
        let params: HashMap<String, String> = HashMap::new();
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 10);
    }

    #[test]
    fn test_per_page_custom_value() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "50".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 50);
    }

    #[test]
    fn test_per_page_clamped_to_100() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "500".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_per_page_invalid_string() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "not_a_number".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 10);
    }

    // -----------------------------------------------------------------------
    // Sparse index multiline output (one JSON per line)
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_multiline_output() {
        let lines: Vec<String> = vec![
            build_index_entry("mycrate", "0.1.0", "aaa", None),
            build_index_entry("mycrate", "0.2.0", "bbb", None),
            build_index_entry("mycrate", "1.0.0", "ccc", None),
        ];
        let body = lines.join("\n");

        let parsed_lines: Vec<&str> = body.split('\n').collect();
        assert_eq!(parsed_lines.len(), 3);

        for line in &parsed_lines {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(entry["name"], "mycrate");
            assert_eq!(entry["yanked"], false);
        }

        let first: serde_json::Value = serde_json::from_str(parsed_lines[0]).unwrap();
        assert_eq!(first["vers"], "0.1.0");
        assert_eq!(first["cksum"], "aaa");

        let last: serde_json::Value = serde_json::from_str(parsed_lines[2]).unwrap();
        assert_eq!(last["vers"], "1.0.0");
        assert_eq!(last["cksum"], "ccc");
    }

    #[test]
    fn test_index_single_version() {
        let lines: Vec<String> = vec![build_index_entry("single", "1.0.0", "checksum", None)];
        let body = lines.join("\n");
        assert!(!body.contains('\n'));

        let entry: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(entry["name"], "single");
    }

    // -----------------------------------------------------------------------
    // Name lowercasing (used throughout handlers)
    // -----------------------------------------------------------------------

    #[test]
    fn test_crate_name_lowercasing() {
        assert_eq!("My-Crate".to_lowercase(), "my-crate");
        assert_eq!("SERDE".to_lowercase(), "serde");
        assert_eq!("already-lower".to_lowercase(), "already-lower");
        assert_eq!("Tokio_Util".to_lowercase(), "tokio_util");
    }

    // -----------------------------------------------------------------------
    // Conflict error JSON format
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_error_json_format() {
        let name = "my-crate";
        let version = "1.0.0";
        let error_json = serde_json::json!({"errors": [{"detail": format!(
            "crate version `{}@{}` already exists",
            name, version
        )}]});
        assert_eq!(
            error_json["errors"][0]["detail"],
            "crate version `my-crate@1.0.0` already exists"
        );
    }

    // -----------------------------------------------------------------------
    // Auth error JSON format
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_required_error_json() {
        let error = serde_json::json!({"errors": [{"detail": "Authentication required"}]});
        assert_eq!(error["errors"][0]["detail"], "Authentication required");
    }

    #[test]
    fn test_invalid_credentials_error_json() {
        let error = serde_json::json!({"errors": [{"detail": "Invalid credentials"}]});
        assert_eq!(error["errors"][0]["detail"], "Invalid credentials");
    }

    // -----------------------------------------------------------------------
    // index_cache_get / index_cache_set / index_cache_invalidate
    // -----------------------------------------------------------------------

    fn make_index_cache() -> IndexCache {
        use std::sync::Arc;
        use tokio::sync::RwLock;
        Arc::new(RwLock::new(HashMap::new()))
    }

    #[tokio::test]
    async fn test_index_cache_get_empty_cache_returns_none() {
        let cache = make_index_cache();
        assert!(index_cache_get(&cache, "myrepo:serde").await.is_none());
    }

    #[tokio::test]
    async fn test_index_cache_get_unknown_key_returns_none() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"some index data");
        index_cache_set(&cache, "myrepo:tokio".to_string(), data).await;
        assert!(index_cache_get(&cache, "myrepo:serde").await.is_none());
    }

    #[tokio::test]
    async fn test_index_cache_set_and_get_roundtrip() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}");
        index_cache_set(&cache, "myrepo:serde".to_string(), data.clone()).await;
        let result = index_cache_get(&cache, "myrepo:serde")
            .await
            .expect("should be in cache");
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_index_cache_set_overwrites_existing_entry() {
        let cache = make_index_cache();
        let v1 = Bytes::from_static(b"version 1 data");
        let v2 = Bytes::from_static(b"version 2 data");
        index_cache_set(&cache, "repo:crate".to_string(), v1).await;
        index_cache_set(&cache, "repo:crate".to_string(), v2.clone()).await;
        let result = index_cache_get(&cache, "repo:crate")
            .await
            .expect("should be in cache");
        assert_eq!(result, v2);
    }

    #[tokio::test]
    async fn test_index_cache_invalidate_removes_key() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"data");
        index_cache_set(&cache, "repo:serde".to_string(), data).await;
        assert!(index_cache_get(&cache, "repo:serde").await.is_some());
        index_cache_invalidate(&cache, "repo:serde").await;
        assert!(index_cache_get(&cache, "repo:serde").await.is_none());
    }

    #[tokio::test]
    async fn test_index_cache_invalidate_missing_key_is_noop() {
        let cache = make_index_cache();
        // Should not panic on a cache miss.
        index_cache_invalidate(&cache, "repo:nonexistent").await;
        assert!(index_cache_get(&cache, "repo:nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_index_cache_invalidate_leaves_other_keys_intact() {
        let cache = make_index_cache();
        index_cache_set(
            &cache,
            "repo:serde".to_string(),
            Bytes::from_static(b"serde"),
        )
        .await;
        index_cache_set(
            &cache,
            "repo:tokio".to_string(),
            Bytes::from_static(b"tokio"),
        )
        .await;
        index_cache_invalidate(&cache, "repo:serde").await;
        assert!(index_cache_get(&cache, "repo:serde").await.is_none());
        assert!(index_cache_get(&cache, "repo:tokio").await.is_some());
    }

    #[test]
    fn test_index_cache_key_format() {
        // The key is "{repo_key}:{crate_name_lowercase}".
        let repo_key = "cargo-proxy";
        let crate_name = "serde_json";
        let key = format!("{}:{}", repo_key, crate_name.to_lowercase());
        assert_eq!(key, "cargo-proxy:serde_json");
    }

    #[tokio::test]
    async fn test_index_cache_key_uses_lowercase_crate_name() {
        // Verify that upper-case input is folded before building the key,
        // matching what serve_index does with `crate_name.to_lowercase()`.
        let cache = make_index_cache();
        let data = Bytes::from_static(b"data");
        let lower_key = "repo:serde".to_string();
        index_cache_set(&cache, lower_key, data.clone()).await;
        // A lookup with the pre-lowercased key must hit.
        assert!(index_cache_get(&cache, "repo:serde").await.is_some());
        // A lookup with a mixed-case key does NOT hit (the caller is responsible
        // for lowercasing before building the key).
        assert!(index_cache_get(&cache, "repo:Serde").await.is_none());
    }

    #[tokio::test]
    async fn test_index_cache_set_lazy_eviction_preserves_fresh_entries() {
        // After a set+get cycle the entry must still be retrievable: the
        // lazy eviction in index_cache_set only removes *expired* entries,
        // never fresh ones.
        let cache = make_index_cache();
        let data = Bytes::from_static(b"fresh");
        index_cache_set(&cache, "repo:crate-a".to_string(), data.clone()).await;
        // Trigger eviction pass by setting another entry.
        index_cache_set(&cache, "repo:crate-b".to_string(), Bytes::from_static(b"b")).await;
        // The first entry must still be present.
        assert_eq!(
            index_cache_get(&cache, "repo:crate-a")
                .await
                .expect("should still be cached"),
            data
        );
    }

    #[tokio::test]
    async fn test_index_cache_multiple_repos_isolated() {
        // Entries for different repo keys must not collide.
        let cache = make_index_cache();
        let data_a = Bytes::from_static(b"repo-a data");
        let data_b = Bytes::from_static(b"repo-b data");
        index_cache_set(&cache, "repo-a:serde".to_string(), data_a.clone()).await;
        index_cache_set(&cache, "repo-b:serde".to_string(), data_b.clone()).await;
        assert_eq!(
            index_cache_get(&cache, "repo-a:serde").await.unwrap(),
            data_a
        );
        assert_eq!(
            index_cache_get(&cache, "repo-b:serde").await.unwrap(),
            data_b
        );
        index_cache_invalidate(&cache, "repo-a:serde").await;
        assert!(index_cache_get(&cache, "repo-a:serde").await.is_none());
        assert!(index_cache_get(&cache, "repo-b:serde").await.is_some());
    }

    #[test]
    fn test_index_cache_ttl_matches_http_max_age() {
        // INDEX_CACHE_TTL_SECS must equal the numeric value in the HTTP
        // Cache-Control header that index_response() sets.  If someone changes
        // one without the other, cargo clients will either hold stale data
        // longer than the in-process cache, or re-request before the in-process
        // cache has expired.
        assert_eq!(INDEX_CACHE_TTL_SECS, 300);
        let resp = index_response("", None);
        let cache_control = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, &format!("max-age={}", INDEX_CACHE_TTL_SECS));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_index_cache_concurrent_access() {
        // Arc<tokio::sync::RwLock<HashMap>> must allow concurrent reads and
        // writes from multiple tasks without panicking, losing data, or
        // blocking the runtime worker threads (ak-2q98).
        let cache = make_index_cache();
        let mut handles = Vec::new();
        for i in 0..16 {
            let c = cache.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("repo:crate-{}", i);
                let data = Bytes::from(format!("data-{}", i).into_bytes());
                index_cache_set(&c, key.clone(), data.clone()).await;
                let result = index_cache_get(&c, &key).await;
                assert!(result.is_some());
                assert_eq!(result.unwrap(), data);
            }));
        }
        for h in handles {
            h.await.expect("task panicked");
        }
        let guard = cache.read().await;
        assert_eq!(guard.len(), 16);
    }

    #[tokio::test]
    async fn test_virtual_repo_invalidation_pattern() {
        // Simulates the multi-key invalidation that publish performs:
        // invalidate the hosted repo's entry AND each virtual repo that
        // aggregates it.
        let cache = make_index_cache();
        let crate_name = "serde";
        let hosted_key = "hosted-repo";
        let virtual_keys = ["virtual-a", "virtual-b"];

        // Populate all keys (as if serve_index has warmed them).
        index_cache_set(
            &cache,
            format!("{}:{}", hosted_key, crate_name),
            Bytes::from_static(b"hosted-index"),
        )
        .await;
        for vk in &virtual_keys {
            index_cache_set(
                &cache,
                format!("{}:{}", vk, crate_name),
                Bytes::from_static(b"virtual-index"),
            )
            .await;
        }

        // Invalidate (mirrors the publish handler).
        index_cache_invalidate(&cache, &format!("{}:{}", hosted_key, crate_name)).await;
        for vk in &virtual_keys {
            index_cache_invalidate(&cache, &format!("{}:{}", vk, crate_name)).await;
        }

        // All three entries must be gone.
        assert!(
            index_cache_get(&cache, &format!("{}:{}", hosted_key, crate_name))
                .await
                .is_none()
        );
        for vk in &virtual_keys {
            assert!(index_cache_get(&cache, &format!("{}:{}", vk, crate_name))
                .await
                .is_none());
        }
    }

    #[tokio::test]
    async fn test_index_cache_binary_content_round_trip() {
        // The cache stores raw Bytes; arbitrary byte sequences (not just UTF-8
        // JSON) must be returned unchanged.
        let cache = make_index_cache();
        let binary_data = Bytes::from(vec![0u8, 1, 2, 127, 128, 255, b'"', b'\n']);
        index_cache_set(&cache, "repo:binary-crate".to_string(), binary_data.clone()).await;
        let result = index_cache_get(&cache, "repo:binary-crate").await.unwrap();
        assert_eq!(result, binary_data);
    }

    // -----------------------------------------------------------------------
    // build_download_url (upstream config.json dl field)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_download_url_plain_base() {
        // Standard crates.io style: dl is a plain URL, we append /{name}/{version}/download.
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "serde", "1.0.200");
        assert_eq!(
            url,
            "https://crates.io/api/v1/crates/serde/1.0.200/download"
        );
    }

    #[test]
    fn test_build_download_url_plain_base_trailing_slash() {
        let dl = "https://crates.io/api/v1/crates/";
        let url = build_download_url(dl, "tokio", "1.38.0");
        assert_eq!(url, "https://crates.io/api/v1/crates/tokio/1.38.0/download");
    }

    #[test]
    fn test_build_download_url_template_with_markers() {
        // Some registries use template markers in the dl field.
        let dl = "https://dl.example.com/crates/{crate}/{version}/download";
        let url = build_download_url(dl, "rand", "0.8.5");
        assert_eq!(url, "https://dl.example.com/crates/rand/0.8.5/download");
    }

    #[test]
    fn test_build_download_url_template_only_crate_marker() {
        let dl = "https://cdn.example.com/{crate}/files/{version}.tgz";
        let url = build_download_url(dl, "regex", "1.10.0");
        assert_eq!(url, "https://cdn.example.com/regex/files/1.10.0.tgz");
    }

    #[test]
    fn test_build_download_url_prerelease_version() {
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "my-crate", "0.1.0-alpha.1");
        assert_eq!(
            url,
            "https://crates.io/api/v1/crates/my-crate/0.1.0-alpha.1/download"
        );
    }

    #[test]
    fn test_build_download_url_single_char_crate() {
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "a", "0.0.1");
        assert_eq!(url, "https://crates.io/api/v1/crates/a/0.0.1/download");
    }

    // -----------------------------------------------------------------------
    // split_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_url_standard() {
        let (origin, path) =
            split_url("https://crates.io/api/v1/crates/serde/1.0.0/download").unwrap();
        assert_eq!(origin, "https://crates.io");
        assert_eq!(path, "api/v1/crates/serde/1.0.0/download");
    }

    #[test]
    fn test_split_url_with_port() {
        let (origin, path) =
            split_url("http://localhost:8080/api/v1/crates/tokio/1.0.0/download").unwrap();
        assert_eq!(origin, "http://localhost:8080");
        assert_eq!(path, "api/v1/crates/tokio/1.0.0/download");
    }

    #[test]
    fn test_split_url_no_path() {
        // A URL with no path after the host returns None.
        assert!(split_url("https://crates.io").is_none());
    }

    #[test]
    fn test_split_url_no_scheme() {
        assert!(split_url("crates.io/api/v1/crates").is_none());
    }

    #[test]
    fn test_split_url_root_path() {
        let (origin, path) = split_url("https://example.com/download").unwrap();
        assert_eq!(origin, "https://example.com");
        assert_eq!(path, "download");
    }

    #[test]
    fn test_split_url_deep_path() {
        let (origin, path) = split_url("https://cdn.example.com/a/b/c/d/e").unwrap();
        assert_eq!(origin, "https://cdn.example.com");
        assert_eq!(path, "a/b/c/d/e");
    }

    // -----------------------------------------------------------------------
    // config_cache_get / config_cache_set
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_config_cache_miss_returns_none() {
        assert!(config_cache_get("https://nonexistent.example.com")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_config_cache_set_and_get_roundtrip() {
        let base = format!(
            "https://test-roundtrip-{}.example.com",
            uuid::Uuid::new_v4()
        );
        let dl = "https://dl.example.com/api/v1/crates".to_string();
        config_cache_set(base.clone(), dl.clone()).await;
        let result = config_cache_get(&base).await.expect("should be in cache");
        assert_eq!(result, dl);
    }

    #[tokio::test]
    async fn test_config_cache_overwrites_previous_value() {
        let base = format!(
            "https://test-overwrite-{}.example.com",
            uuid::Uuid::new_v4()
        );
        config_cache_set(base.clone(), "https://old.example.com/dl".to_string()).await;
        config_cache_set(base.clone(), "https://new.example.com/dl".to_string()).await;
        let result = config_cache_get(&base).await.unwrap();
        assert_eq!(result, "https://new.example.com/dl");
    }

    // -----------------------------------------------------------------------
    // End-to-end download URL resolution scenario tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_crates_io_dl_url_produces_correct_download() {
        // Simulates the crates.io scenario:
        // config.json at index.crates.io has dl = "https://crates.io/api/v1/crates"
        let dl = "https://crates.io/api/v1/crates";
        let full_url = build_download_url(dl, "serde_json", "1.0.120");
        assert_eq!(
            full_url,
            "https://crates.io/api/v1/crates/serde_json/1.0.120/download"
        );

        // The split must yield the correct origin for proxy_fetch.
        let (origin, path) = split_url(&full_url).unwrap();
        assert_eq!(origin, "https://crates.io");
        assert_eq!(path, "api/v1/crates/serde_json/1.0.120/download");
    }

    #[test]
    fn test_self_hosted_registry_same_host_dl() {
        // A self-hosted registry where index and downloads share the same host.
        // config.json has dl = "https://registry.company.com/api/v1/crates"
        let dl = "https://registry.company.com/api/v1/crates";
        let full_url = build_download_url(dl, "internal-lib", "2.0.0");
        let (origin, path) = split_url(&full_url).unwrap();
        assert_eq!(origin, "https://registry.company.com");
        assert_eq!(path, "api/v1/crates/internal-lib/2.0.0/download");
    }

    #[test]
    fn test_fallback_when_no_dl_url() {
        // When resolve_upstream_dl_url returns None, the download handler
        // falls back to upstream_url + the standard path.
        let upstream_url = "https://index.crates.io";
        let name = "serde";
        let version = "1.0.0";
        let fallback_path = format!("api/v1/crates/{}/{}/download", name, version);
        assert_eq!(fallback_path, "api/v1/crates/serde/1.0.0/download");

        // This would produce the wrong URL for crates.io (index.crates.io
        // does not serve downloads), but it is the correct fallback for
        // registries where index and downloads share the same host.
        let full_fallback = format!("{}/{}", upstream_url, fallback_path);
        assert_eq!(
            full_fallback,
            "https://index.crates.io/api/v1/crates/serde/1.0.0/download"
        );
    }

    #[test]
    fn test_build_download_url_rejects_internal_addresses() {
        use crate::api::validation::validate_outbound_url;

        // Cloud metadata endpoint (AWS IMDSv1)
        let dl = "http://169.254.169.254/latest/meta-data/";
        let url = build_download_url(dl, "evil", "1.0.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "cloud metadata URL should be rejected"
        );

        // Localhost
        let dl = "http://localhost:8080/evil";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "localhost URL should be rejected"
        );

        // Private network (10.x)
        let dl = "http://10.0.0.1/packages";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "private network URL should be rejected"
        );

        // Docker-internal service name
        let dl = "http://backend:8080/internal";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "Docker-internal service URL should be rejected"
        );

        // Legitimate external URL should pass
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "serde", "1.0.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_ok(),
            "legitimate external URL should be accepted"
        );
    }

    /// Smoke test that the cargo `dl` field flows through
    /// `validate_outbound_url`. The detailed coverage of each bypass
    /// class lives in `api::validation::tests`; this test pins the
    /// integration: a malicious upstream `config.json` returning a
    /// crafted `dl` cannot reach AWS IMDS via the cargo download path.
    /// One realistic case is sufficient — duplicating the full bypass
    /// matrix here would shadow the validator's own tests.
    #[test]
    fn test_build_download_url_rejects_ipv6_ssrf_bypass() {
        use crate::api::validation::validate_outbound_url;
        let dl = "http://[::ffff:169.254.169.254]";
        let url = build_download_url(dl, "evil", "1.0.0");
        let err = validate_outbound_url(&url, "Cargo upstream download URL")
            .expect_err("IPv4-mapped AWS IMDS via dl must be rejected");
        assert!(
            err.to_string().contains("private/internal network"),
            "expected SSRF rejection reason in error message, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Advertised-location conformance (#2657 class)
    //
    // The `dl` template a cargo client reads from `config.json` is what it
    // appends `{name}/{version}/download` to. The unit tests above prove the
    // builder emits a string; only routing the resulting URL against the REAL
    // router (mounted where `api::routes` nests it) proves a `cargo` client can
    // actually fetch the published `.crate`.
    // -----------------------------------------------------------------------

    /// The cargo routes mounted exactly where `api::routes` nests them. The
    /// `dl` URL in `config.json` is absolute and carries the `/cargo` prefix.
    fn mounted_router() -> Router<SharedState> {
        Router::new().nest("/cargo", super::router())
    }

    /// Resolve an advertised URL against the document that carried it and return
    /// the path+query to request (dropping any fragment).
    fn resolve_advertised(document_url: &str, advertised: &str) -> String {
        let base = reqwest::Url::parse(document_url).expect("document url");
        let joined = base.join(advertised).expect("advertised url must resolve");
        joined[url::Position::BeforePath..url::Position::AfterQuery].to_string()
    }

    /// The download URL a cargo client builds from the advertised `dl` template
    /// must resolve against the real router and serve the published `.crate`.
    #[tokio::test]
    async fn test_advertised_dl_download_url_resolves_against_real_router() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "cargo").await else {
            return;
        };

        let name = "my-crate";
        let version = "0.1.0";
        let crate_data: &[u8] = b"fake-crate-tarball-bytes-for-advertised-url";

        // Publish through the real publish handler.
        let publish_status = {
            let app = tdh::router_with_auth(
                mounted_router(),
                fx.state.clone(),
                tdh::make_auth(fx.user_id, &fx.username),
            );
            let (status, _) = tdh::send(
                app,
                tdh::put(
                    format!("/cargo/{}/api/v1/crates/new", fx.repo_key),
                    make_publish_payload(&sample_metadata(), crate_data),
                ),
            )
            .await;
            status
        };

        // Read the advertised `dl` template from config.json.
        let config_path = format!("/cargo/{}/config.json", fx.repo_key);
        let config_doc_url = format!("http://ak.test{config_path}");
        let (config_status, config_body) = tdh::send(
            tdh::router_anon(mounted_router(), fx.state.clone()),
            tdh::get(config_path.clone()),
        )
        .await;
        let config: serde_json::Value = serde_json::from_slice(&config_body).unwrap_or_default();
        let dl = config["dl"].as_str().unwrap_or_default().to_string();

        // Build the download URL exactly as cargo does: `{dl}/{name}/{version}/download`.
        let advertised = format!("{dl}/{name}/{version}/download");
        let (dl_status, dl_body) = if dl.is_empty() {
            (StatusCode::NOT_FOUND, Bytes::new())
        } else {
            let path = resolve_advertised(&config_doc_url, &advertised);
            tdh::send(
                tdh::router_anon(mounted_router(), fx.state.clone()),
                tdh::get(path),
            )
            .await
        };

        fx.teardown().await;

        assert_eq!(publish_status, StatusCode::OK, "publish must succeed");
        assert_eq!(config_status, StatusCode::OK, "config.json");
        assert!(!dl.is_empty(), "config.json must advertise a `dl` template");
        assert_eq!(
            dl_status,
            StatusCode::OK,
            "the download URL built from the advertised `dl` ({advertised}) must resolve, not 404"
        );
        assert_eq!(
            &dl_body[..],
            crate_data,
            "the advertised download URL must serve the published .crate bytes"
        );
    }
}

/// #3149 — upstream `Content-Encoding` forwarding on the cargo SPARSE INDEX.
///
/// A different mechanism from the `.crate` download arms fixed in #2922:
/// `try_remote_index` fetched through `proxy_fetch_capped`, whose 2-tuple
/// return type STRUCTURALLY discards the coding, and `index_response` set only
/// a content type and cache-control. Coded index bytes were therefore re-served
/// as plain JSON — and pinned into the in-process `index_cache`, which stores
/// bare bytes and has no room for a coding, so every later hit repeated it.
///
/// Cargo parses the index server-side rather than writing it to disk, so this
/// degrades (a failed parse) instead of silently corrupting an artifact, which
/// is why it is the lower-severity half of the issue.
#[cfg(test)]
mod index_content_encoding_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use wiremock::matchers::{method as wm_method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mounted_router() -> Router<SharedState> {
        Router::new().nest("/cargo", super::router())
    }

    /// #3000: the documented cargo setup points the sparse registry index at
    /// `sparse+{base}/api/cargo/{repo}/`, so cargo resolves `config.json`
    /// (and the sparse index files) under the `/api` prefix. The `/api/cargo`
    /// alias in `routes.rs` mounts this same router there; a newly created
    /// cargo repo must answer `config.json` through it instead of 404ing
    /// with cargo's "config.json not found".
    #[tokio::test]
    async fn test_config_json_served_under_api_cargo_alias() {
        let Some(fx) = tdh::Fixture::setup("local", "cargo").await else {
            return;
        };
        let app = fx.router_anon(Router::new().nest("/api/cargo", super::router()));
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/api/cargo/{}/config.json", fx.repo_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "config.json must resolve under the /api/cargo alias; got body {:?}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("config.json body");
        let dl = json["dl"].as_str().expect("dl field");
        assert!(
            dl.ends_with(&format!("/cargo/{}/api/v1/crates", fx.repo_key)),
            "dl must point at the canonical /cargo download endpoint, got {dl}"
        );
        fx.teardown().await;
    }

    /// Builder guard: the coded index builder declares the coding.
    #[test]
    fn test_index_response_coded_forwards_content_encoding() {
        let resp = index_response_coded(
            "{}",
            Some("application/json".to_string()),
            Some("gzip".to_string()),
        );
        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_ENCODING).as_deref(),
            Some("gzip"),
        );
    }

    /// Negative control: server-built index bodies are uncoded, and
    /// `index_response` must never manufacture a coding for them.
    #[test]
    fn test_index_response_omits_content_encoding_for_server_built_bodies() {
        let resp = index_response("{}", Some("application/json".to_string()));
        assert!(
            resp.headers().get(CONTENT_ENCODING).is_none(),
            "server-built index bodies are uncoded",
        );
    }

    /// A coded upstream sparse index must be served declared -- on the FIRST
    /// request and on every later one. The second request is the real point:
    /// the pre-fix code pinned the coded bytes into `index_cache`, so even a
    /// fix that only touched the fresh-fetch path would keep serving
    /// undeclared coded bytes from memory afterwards.
    #[tokio::test]
    async fn test_remote_sparse_index_forwards_upstream_content_encoding() {
        let Some(fx) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };
        let (_plain, coded) =
            tdh::coded_fixture("deflate", b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n");

        let server = MockServer::start().await;
        Mock::given(wm_method("GET"))
            .and(wm_path("/se/rd/serde"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "deflate")
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(coded.clone()),
            )
            .mount(&server)
            .await;

        let (state, _dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;

        let mut seen = Vec::new();
        for _ in 0..2 {
            let (status, body, headers) = tdh::send_with_headers(
                tdh::router_anon(mounted_router(), state.clone()),
                tdh::get(format!("/cargo/{}/se/rd/serde", fx.repo_key)),
            )
            .await;
            seen.push((
                status,
                tdh::header_str(&headers, CONTENT_ENCODING),
                body.to_vec(),
            ));
        }
        fx.teardown().await;

        for (i, (status, encoding, body)) in seen.iter().enumerate() {
            assert_eq!(*status, StatusCode::OK, "request {i} must succeed");
            assert_eq!(
                encoding.as_deref(),
                Some("deflate"),
                "request {i}: the coded sparse index must be declared -- \
                 request 1 is the fresh fetch, request 2 proves the coded body \
                 was not memoized undeclared (#3149)",
            );
            assert_eq!(&body[..], &coded[..], "request {i}: bytes pass through");
        }
    }

    /// Control for the SAME change: skipping the in-process cache must apply
    /// ONLY to coded bodies. An ordinary uncoded index must still be memoized,
    /// so upstream is hit exactly once across two requests and no coding is
    /// manufactured. Without this, "never cache" would satisfy the test above
    /// while quietly removing the index cache for everyone.
    #[tokio::test]
    async fn test_uncoded_sparse_index_is_still_memoized_and_declares_no_coding() {
        let Some(fx) = tdh::Fixture::setup("remote", "cargo").await else {
            return;
        };
        let plain = b"{\"name\":\"tokio\",\"vers\":\"1.0.0\"}\n".to_vec();

        let server = MockServer::start().await;
        Mock::given(wm_method("GET"))
            .and(wm_path("/to/ki/tokio"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(plain.clone()),
            )
            // The in-process index cache must absorb the second request.
            .expect(1)
            .mount(&server)
            .await;

        let (state, _dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;

        let mut seen = Vec::new();
        for _ in 0..2 {
            let (status, body, headers) = tdh::send_with_headers(
                tdh::router_anon(mounted_router(), state.clone()),
                tdh::get(format!("/cargo/{}/to/ki/tokio", fx.repo_key)),
            )
            .await;
            seen.push((
                status,
                tdh::header_str(&headers, CONTENT_ENCODING),
                body.to_vec(),
            ));
        }
        // Drop the server to assert the `.expect(1)` upstream-hit count.
        drop(server);
        fx.teardown().await;

        for (i, (status, encoding, body)) in seen.iter().enumerate() {
            assert_eq!(*status, StatusCode::OK, "request {i} must succeed");
            assert!(
                encoding.is_none(),
                "request {i}: an uncoded index must not gain a coding",
            );
            assert_eq!(&body[..], &plain[..], "request {i}: bytes unchanged");
        }
    }
}
