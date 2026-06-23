//! PyPI Simple Repository API (PEP 503) handlers.
//!
//! Implements the endpoints required for `pip install` and `twine upload`
//! per PEP 503, PEP 658, and PEP 691.
//!
//! Routes are mounted at `/pypi/{repo_key}/...`:
//!   GET  /pypi/{repo_key}/simple/                     - Root index
//!   GET  /pypi/{repo_key}/simple/{project}/           - Package index
//!   GET  /pypi/{repo_key}/simple/{project}/{filename} - Download file
//!   GET  /pypi/{repo_key}/simple/{project}/{filename}.metadata - PEP 658 metadata
//!   POST /pypi/{repo_key}/                            - Twine upload

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use sqlx::PgPool;
use std::future::Future;
use tracing::{debug, info, warn};

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::error::AppError;
use crate::formats::pypi::PypiHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Twine upload
        .route("/:repo_key/", post(upload))
        // Simple index root
        .route("/:repo_key/simple/", get(simple_root))
        .route("/:repo_key/simple", get(simple_root))
        // Package index
        .route("/:repo_key/simple/:project/", get(simple_project))
        .route("/:repo_key/simple/:project", get(simple_project))
        // Download & metadata
        .route(
            "/:repo_key/simple/:project/:filename",
            get(download_or_metadata),
        )
}

// ---------------------------------------------------------------------------
// PEP 503 name normalization
// ---------------------------------------------------------------------------

/// Normalize a package name per PEP 503: lowercase, and replace any run of
/// `[-_.]` characters with a single hyphen.
///
/// PEP 503 restricts canonical project names to the alphabet
/// `[A-Za-z0-9._-]`. Any character outside that set is *malformed* and must
/// be **dropped** rather than preserved. Preserving arbitrary characters
/// (the previous behaviour) created a stored-XSS sink when this function
/// was fed names parsed out of upstream HTML: an upstream serving an
/// `<a>` element containing `<script>alert(1)</script>` would round-trip
/// through `decode_html_entities_minimal` and land in our own simple-index
/// HTML response (#1377 review, defense-in-depth layer 1). See also the
/// HTML-escape applied at render time in `build_simple_root_response`.
pub(crate) fn normalize_pep503(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut last_was_sep = true;

    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            result.push(c.to_ascii_lowercase());
            last_was_sep = false;
        } else if (c == '-' || c == '_' || c == '.') && !last_was_sep {
            result.push('-');
            last_was_sep = true;
        }
        // All other characters are NOT valid in a PEP 503 canonical name
        // and are silently dropped. This is the security boundary that
        // prevents `<`, `>`, `"`, `&`, control chars, etc. from ever
        // appearing in a normalized package name.
    }

    if result.ends_with('-') {
        result.pop();
    }

    result
}

// ---------------------------------------------------------------------------
// Upstream URL normalization for the PEP 503 simple index
// ---------------------------------------------------------------------------

/// Build the upstream path for a PyPI Simple-API request without duplicating
/// the `simple/` segment when the configured upstream URL already ends in
/// `/simple` or `/simple/` (issue #1130).
///
/// The PyPI Simple API canonically lives at `https://pypi.org/simple/`. Users
/// reasonably copy that URL verbatim into the remote-repo "upstream URL"
/// field. The handler also conventionally prefixes `simple/{project}/` onto
/// the proxied path, producing requests like
/// `https://pypi.org/simple/simple/{project}/` which return 404. Detect the
/// suffix and emit `{project}/` (or `{project}/{filename}`) instead.
///
/// `tail` is the relative portion below the `simple/` segment (e.g.
/// `flask/`, `flask/Flask-3.0.0-py3-none-any.whl`). Callers must NOT include
/// the leading `simple/` themselves.
///
/// `index_path` controls how the prefix is built (issue #1546):
/// - `"simple"` (default) — standard PEP 503 layout: prepends `simple/` to `tail`.
/// - `""` (empty) — flat CDN layout (e.g. PyTorch wheel CDN): emits `tail` with
///   no prefix, so `torch/` maps directly to `{upstream}/torch/`.
/// - any other non-empty value — custom prefix: emits `{index_path}/{tail}`.
///
/// The `/simple`-dedup logic (#1130) is only applied when `index_path` is
/// `"simple"` — for flat or custom indexes the upstream URL is used verbatim.
///
/// Returns `(adjusted_upstream_url, upstream_path)`. The URL has any trailing
/// `/simple` or `/simple/` stripped so [`crate::services::proxy_service::ProxyService::build_upstream_url`]
/// (which trims one trailing slash on the base and joins with `/`) produces
/// a single `simple/` segment in the final outbound URL.
fn pypi_upstream_url_and_path(
    upstream_url: &str,
    tail: &str,
    index_path: &str,
) -> (String, String) {
    let trimmed_url = upstream_url.trim_end_matches('/');
    let tail = tail.trim_start_matches('/');
    if index_path == "simple" {
        if let Some(base) = trimmed_url.strip_suffix("/simple") {
            let normalized = if base.is_empty() {
                "/".to_string()
            } else {
                base.to_string()
            };
            return (normalized, format!("simple/{}", tail));
        }
    }
    if index_path.is_empty() {
        (upstream_url.to_string(), tail.to_string())
    } else {
        (upstream_url.to_string(), format!("{}/{}", index_path, tail))
    }
}

/// Fetch the `pypi_upstream_index_path` config value for a repository.
///
/// Returns `"simple"` (the PEP 503 default) when no override is configured.
/// An empty string signals a flat CDN layout (no `simple/` prefix); any other
/// non-empty string is used as-is as the index path prefix.
async fn fetch_pypi_upstream_index_path(db: &PgPool, repo_id: uuid::Uuid) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind("pypi_upstream_index_path")
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "simple".to_string())
}

// ---------------------------------------------------------------------------
// Internal struct used to decouple DB query results from response rendering.
// ---------------------------------------------------------------------------

struct SimpleProjectArtifact {
    path: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
    /// Upload timestamp, surfaced as PEP 700 `upload-time` (RFC 3339) in the
    /// PEP 691 JSON response and `data-upload-time` in the HTML response.
    upload_time: Option<chrono::DateTime<chrono::Utc>>,
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_pypi_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["pypi", "poetry", "conda"], "a PyPI").await
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/ — PEP 503 root index
// ---------------------------------------------------------------------------

async fn simple_root(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // Get all distinct package names in this repository, then normalize
    // them in Rust per PEP 503 (the SQL REPLACE chain is only approximate).
    let raw_names: Vec<String> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

    let mut merged: std::collections::BTreeSet<String> =
        raw_names.iter().map(|n| normalize_pep503(n)).collect();

    // Remote repos: proxy the upstream /simple/ root and merge its package
    // list into the response. Without this, a fresh Remote-only repo
    // (proxy-cached artifacts no longer land in `artifacts`; see #1278/#1280)
    // returns an empty root index even when the upstream advertises hundreds
    // of packages. The fetched index is also cached via the proxy_service
    // cache so subsequent requests hit the cache. (#1377)
    if repo.repo_type == RepositoryType::Remote {
        if let Some(names) =
            fetch_remote_simple_root(&state, &repo.key, repo.id, &repo.upstream_url).await
        {
            merged.extend(names);
        }
        // Some upstreams don't serve a browsable root index (or it is too
        // large to parse), so `fetch_remote_simple_root` returns nothing.
        // Recover the projects the proxy has already served from the proxy
        // cache so the root index lists them instead of coming back with
        // zero anchors (B8 / #1377). Proxy-cached artifacts are not recorded
        // in `artifacts` (#1278), making the cache the only local record of
        // which projects exist for a Remote repo.
        if let Some(proxy) = state.proxy_service.as_ref() {
            merged.extend(
                proxy
                    .list_cached_pypi_packages(&repo.key)
                    .await
                    .into_iter()
                    .map(|n| normalize_pep503(&n)),
            );
        }
    }

    // Virtual repos have no artifacts of their own. Aggregate package names
    // from all member repos so that the root index lists every package
    // available through the virtual endpoint.
    if merged.is_empty() && repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

        for member in &members {
            if member.repo_type == RepositoryType::Local
                || member.repo_type == RepositoryType::Staging
            {
                let member_raw: Vec<String> = sqlx::query_scalar!(
                    r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false
        "#,
                    member.id
                )
                .fetch_all(&state.db)
                .await
                .map_err(map_db_err)?;

                merged.extend(member_raw.iter().map(|n| normalize_pep503(n)));
            } else if member.repo_type == RepositoryType::Remote {
                if let Some(names) =
                    fetch_remote_simple_root(&state, &member.key, member.id, &member.upstream_url)
                        .await
                {
                    merged.extend(names);
                }
                if let Some(proxy) = state.proxy_service.as_ref() {
                    merged.extend(
                        proxy
                            .list_cached_pypi_packages(&member.key)
                            .await
                            .into_iter()
                            .map(|n| normalize_pep503(&n)),
                    );
                }
            }
        }
    }

    let packages: Vec<String> = merged.into_iter().collect();
    build_simple_root_response(&headers, &repo_key, &packages)
}

/// Maximum size of an upstream PEP 503 root simple-index body we will parse.
///
/// PyPI's own root index is ~30 MB compressed but our typical Remote repos
/// front a private/curated mirror with at most a few thousand packages
/// (well under 1 MB). A 10 MB ceiling keeps us comfortably above any
/// legitimate index while preventing a hostile or misconfigured upstream
/// from feeding us a multi-hundred-megabyte HTML blob that would block the
/// request handler synchronously inside the regex engine (#1377 review).
const MAX_SIMPLE_ROOT_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Fetch the PEP 503 root index from a Remote repo's upstream URL and parse
/// out the project names. Returns `None` when the proxy service is not
/// configured, the upstream URL is missing, the fetch fails, the response
/// exceeds [`MAX_SIMPLE_ROOT_BODY_BYTES`], or the response is not HTML the
/// parser recognises.
///
/// The fetched bytes are cached by the proxy_service under cache_path
/// `simple/`. Subsequent calls within the cache TTL return the cached body
/// without re-hitting upstream, which keeps the root index responsive even
/// when the upstream registry is slow or transiently down (#1377).
async fn fetch_remote_simple_root(
    state: &SharedState,
    repo_key: &str,
    repo_id: uuid::Uuid,
    upstream_url: &Option<String>,
) -> Option<Vec<String>> {
    let upstream = upstream_url.as_ref()?;
    let proxy = state.proxy_service.as_ref()?;

    let index_path = fetch_pypi_upstream_index_path(&state.db, repo_id).await;
    let (effective_upstream, upstream_path) = pypi_upstream_url_and_path(upstream, "", &index_path);
    let (content, _content_type) = match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        &effective_upstream,
        &upstream_path,
        proxy_helpers::LARGE_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok(pair) => pair,
        Err(_) => return None,
    };

    if content.len() > MAX_SIMPLE_ROOT_BODY_BYTES {
        warn!(
            repo_key = %repo_key,
            upstream = %effective_upstream,
            body_bytes = content.len(),
            cap_bytes = MAX_SIMPLE_ROOT_BODY_BYTES,
            "upstream PEP 503 root index exceeds size cap; skipping parse. \
             A future release will allow operators to opt into a higher cap \
             for full-mirror Remote repos that front pypi.org directly."
        );
        return None;
    }

    // The regex pass over up to ~10 MiB of HTML is CPU-bound and blocks
    // the async runtime worker. Offload to a blocking thread so the
    // request handler does not stall other tasks on a slow parse
    // (#1377 review).
    let parsed = tokio::task::spawn_blocking(move || {
        let html = String::from_utf8_lossy(&content);
        parse_simple_root_projects(&html)
    })
    .await
    .ok()?;
    Some(parsed)
}

/// Decode the minimal set of HTML entities that legally appear inside an
/// `<a>` text or `href` value in a PEP 503 simple-index page: `&amp;`,
/// `&lt;`, `&gt;`, `&quot;`, `&apos;`, and the numeric `&#39;` apostrophe.
///
/// PEP 503 project names are restricted to `[A-Za-z0-9._-]` after
/// normalisation, so a real project name will not contain entities; but a
/// raw upstream index served by Warehouse/Nexus/Artifactory may HTML-escape
/// ampersands in non-conforming legacy names (e.g. `foo&amp;bar`) or in
/// hrefs that include query strings. Decoding here ensures the value fed
/// into [`normalize_pep503`] is the real character, not the literal
/// entity reference.
fn decode_html_entities_minimal(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    // Single-pass scan so chained `.replace()` cannot double-decode.
    // Naive `.replace("&amp;", "&").replace("&lt;", "<")` would convert
    // `&amp;lt;` into `<`, which can re-introduce script-like sequences
    // from a malicious upstream. A single left-to-right scan only
    // recognises an entity at its original position and copies the
    // resulting character verbatim, so further entity sequences are not
    // re-evaluated (#1377 review).
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            // Longest-match-first on the supported entities. The list is
            // intentionally fixed and small; arbitrary `&xyz;` references
            // are left untouched (and ultimately get dropped by
            // `normalize_pep503`).
            let rest = &input[i..];
            if rest.starts_with("&amp;") {
                out.push('&');
                i += "&amp;".len();
                continue;
            }
            if rest.starts_with("&lt;") {
                out.push('<');
                i += "&lt;".len();
                continue;
            }
            if rest.starts_with("&gt;") {
                out.push('>');
                i += "&gt;".len();
                continue;
            }
            if rest.starts_with("&quot;") {
                out.push('"');
                i += "&quot;".len();
                continue;
            }
            if rest.starts_with("&apos;") {
                out.push('\'');
                i += "&apos;".len();
                continue;
            }
            if rest.starts_with("&#39;") {
                out.push('\'');
                i += "&#39;".len();
                continue;
            }
        }
        // Push one UTF-8 codepoint and advance past it.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Extract project names from an upstream PEP 503 root simple index.
///
/// The root index is a flat HTML list of `<a href="...">project-name</a>`
/// entries. We prefer the link text (canonical project name) but fall back
/// to the last non-empty segment of the href when the text is empty. All
/// names are PEP 503 normalised so duplicates collapse before merging into
/// the response.
///
/// The regex accepts both double- and single-quoted href attributes (both
/// are legal HTML) and the captured text/href is HTML-entity-decoded for a
/// small set of common entities before normalisation, so a project like
/// `foo&amp;bar` in upstream HTML normalises through the same path as
/// `foo&bar` would.
///
/// Callers are expected to bound the input size before invoking this
/// helper; see [`MAX_SIMPLE_ROOT_BODY_BYTES`]. This regex-based parser is
/// intentionally narrow: a full HTML5 parser (e.g. the `scraper` crate)
/// is tracked as a v1.2.1 follow-up.
fn parse_simple_root_projects(html: &str) -> Vec<String> {
    // Match `<a ... href="..." ...>text</a>` or `<a ... href='...' ...>text</a>`.
    // Two alternations so the two captured pairs always live in fixed group
    // indices: 1+2 (double-quote) or 3+4 (single-quote). Whichever pair the
    // alternation matched, the other is `None`.
    static A_TAG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)<a\s+[^>]*?(?:href="([^"]*)"[^>]*>([^<]*)|href='([^']*)'[^>]*>([^<]*))</a>"#,
        )
        .unwrap()
    });

    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for caps in A_TAG_RE.captures_iter(html) {
        let (href_raw, text_raw) = match (caps.get(1), caps.get(2), caps.get(3), caps.get(4)) {
            (Some(h), Some(t), _, _) => (h.as_str(), t.as_str()),
            (_, _, Some(h), Some(t)) => (h.as_str(), t.as_str()),
            _ => continue,
        };
        let href = decode_html_entities_minimal(href_raw);
        let text = decode_html_entities_minimal(text_raw.trim());
        let name = if !text.is_empty() {
            text
        } else {
            // Fallback: take the last non-empty path segment from the href.
            href.trim_end_matches('/')
                .rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string()
        };
        let normalized = normalize_pep503(&name);
        if !normalized.is_empty() {
            out.insert(normalized);
        }
    }
    out.into_iter().collect()
}

/// Render the simple root index (list of all packages) as either HTML (PEP 503)
/// or JSON (PEP 691) based on the Accept header.
#[allow(clippy::result_large_err)]
fn build_simple_root_response(
    headers: &HeaderMap,
    repo_key: &str,
    packages: &[String],
) -> Result<Response, Response> {
    // Content negotiation is driven solely by the Accept header (#1773),
    // matching `build_simple_project_response`. Previously this also consulted
    // the request Content-Type, which is the media type of the request *body*,
    // not a negotiation signal — a client sending `Content-Type: ...+json`
    // with `Accept: text/html` would wrongly receive JSON.
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/vnd.pypi.simple.v1+json") {
        let json = serde_json::json!({
            "meta": { "api-version": "1.2" },
            "projects": packages.iter().map(|p| {
                serde_json::json!({ "name": p })
            }).collect::<Vec<_>>()
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap());
    }

    // HTML response (default).
    //
    // Defense-in-depth against stored XSS (#1377 review): even though
    // `normalize_pep503` drops every character outside `[a-z0-9.-]`, the
    // shared renderer HTML-escapes both the `repo_key` (URL-route input) and
    // each `package` name (DB- or upstream-derived) before interpolation. The
    // restrictive CSP header below denies inline script execution even if a
    // future regression somehow lets a `<` through both layers. The body
    // construction lives in `PypiHandler::render_simple_root_html` so the
    // anchor-rendering rules have pure unit coverage (B8).
    let html = PypiHandler::render_simple_root_html(repo_key, packages);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        // pip/uv only consume the link list; deny everything else so a
        // hypothetical injection cannot exfiltrate cookies or load images.
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'",
        )
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(html))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/{project}/ — PEP 503 package index
// ---------------------------------------------------------------------------

/// Fetch the PEP 708 `tracks` URLs declared for `normalized` on any of the
/// project-owning `repo_ids`. Best-effort: a DB error yields an empty list,
/// since this metadata is non-essential and must never fail a listing (#1600).
async fn pypi_project_tracks_for(
    db: &sqlx::PgPool,
    repo_ids: &[uuid::Uuid],
    normalized: &str,
) -> Vec<String> {
    if repo_ids.is_empty() {
        return Vec::new();
    }
    sqlx::query_scalar::<_, String>(
        "SELECT tracks_url FROM pypi_project_tracks \
         WHERE repository_id = ANY($1) AND normalized_name = $2 ORDER BY tracks_url",
    )
    .bind(repo_ids)
    .bind(normalized)
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

async fn simple_project(
    State(state): State<SharedState>,
    Path((repo_key, project)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;
    let normalized = normalize_pep503(&project);

    // PEP 691 content negotiation also governs the proxy path: a JSON client
    // must get the upstream's JSON representation (which carries PEP 700
    // `upload-time`), not its HTML index (which never does).
    let wants_json = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains(PEP691_JSON_CONTENT_TYPE);

    // Find all artifacts that belong to this package.
    // We normalize the name for matching: replace [_.-]+ with - then lowercase.
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.created_at,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(REPLACE(REPLACE(REPLACE(a.name, '_', '-'), '.', '-'), '--', '-')) = $2
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        normalized
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

    let simple_artifacts: Vec<SimpleProjectArtifact> = artifacts
        .into_iter()
        .map(|a| SimpleProjectArtifact {
            path: a.path,
            version: a.version,
            size_bytes: a.size_bytes,
            checksum_sha256: a.checksum_sha256,
            metadata: a.metadata,
            upload_time: Some(a.created_at),
        })
        .collect();

    if simple_artifacts.is_empty() {
        // For remote repos, proxy the simple index from upstream
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let index_path = fetch_pypi_upstream_index_path(&state.db, repo.id).await;
                let (effective_upstream, upstream_path) = pypi_upstream_url_and_path(
                    upstream_url,
                    &format!("{}/", normalized),
                    &index_path,
                );

                let (content, content_type) = if wants_json {
                    // Request the PEP 691 JSON form from upstream, cached under a
                    // format-qualified key so it never collides with the HTML index.
                    proxy_helpers::proxy_fetch_capped_with_cache_key_and_accept(
                        proxy,
                        repo.id,
                        &repo_key,
                        &effective_upstream,
                        &upstream_path,
                        &format!("{}index.v1+json", upstream_path),
                        Some(PEP691_JSON_CONTENT_TYPE),
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await?
                } else {
                    proxy_helpers::proxy_fetch_capped(
                        proxy,
                        repo.id,
                        &repo_key,
                        &effective_upstream,
                        &upstream_path,
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await?
                };

                let ct = content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string());

                // When the client asked for JSON and upstream honoured it, rewrite
                // the JSON download URLs and serve PEP 691 — preserving PEP 700
                // `upload-time`. Upstreams that ignore the Accept header return
                // HTML and fall through to the HTML rewrite below.
                if wants_json && ct.contains("json") {
                    if let Some(json) =
                        rewrite_upstream_simple_json(&content, &repo_key, &normalized)
                    {
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, PEP691_JSON_CONTENT_TYPE)
                            .body(Body::from(json))
                            .unwrap());
                    }
                }

                // Rewrite absolute download URLs to route through our proxy
                let body = if ct.contains("text/html") {
                    let html = String::from_utf8_lossy(&content);
                    let rewritten = rewrite_upstream_urls(&html, &repo_key, &project);
                    Body::from(rewritten)
                } else {
                    Body::from(content)
                };

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .body(body)
                    .unwrap());
            }
        }
        // For virtual repos, iterate through ALL members and union their
        // entries — both local DB rows and remote proxy responses — so a
        // package that exists partially in a local member doesn't shadow
        // the rest of upstream. See #1230.
        if repo.repo_type == RepositoryType::Virtual {
            let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

            if members.is_empty() {
                return Err(
                    AppError::NotFound("Virtual repository has no members".to_string())
                        .into_response(),
                );
            }

            // PEP 708 (#1600): when a local member owns this name and no
            // operator `tracks` declaration permits merging, isolate the name to
            // its local owner. We then skip every Remote member below, so the
            // index lists only the local distributions (and the download path
            // makes the same decision, keeping index and download consistent).
            let isolate =
                proxy_helpers::pypi_virtual_isolates_name(&state.db, repo.id, &normalized).await?;

            let mut local_artifacts: Vec<SimpleProjectArtifact> = Vec::new();
            let mut remote_response: Option<(Bytes, Option<String>)> = None;

            // First pass: collect distributions from every local (hosted /
            // staging) member. We must know whether a local member owns the
            // name BEFORE deciding to fetch any remote index, because members
            // are iterated in priority order and a remote can precede a local.
            for member in &members {
                if member.repo_type != RepositoryType::Local
                    && member.repo_type != RepositoryType::Staging
                {
                    continue;
                }
                let member_rows = sqlx::query!(
                    r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.created_at,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(REPLACE(REPLACE(REPLACE(a.name, '_', '-'), '.', '-'), '--', '-')) = $2
        ORDER BY a.created_at DESC
        "#,
                    member.id,
                    normalized
                )
                .fetch_all(&state.db)
                .await
                .map_err(map_db_err)?;

                local_artifacts.extend(member_rows.into_iter().map(|a| SimpleProjectArtifact {
                    path: a.path,
                    version: a.version,
                    size_bytes: a.size_bytes,
                    checksum_sha256: a.checksum_sha256,
                    metadata: a.metadata,
                    upload_time: Some(a.created_at),
                }));
            }

            // Ownership / dependency-confusion guard (#1600), superseding the
            // name-only suppression from #1738. When a local member owns this
            // PEP 503 name and no operator `tracks` declaration permits merging,
            // `isolate` is true and the virtual serves ONLY that member's
            // distributions for the name — in both the simple index and the
            // download — rather than unioning the remote's versions for it.
            // Unioning an unrelated public package that merely shares the name
            // is a supply-chain hole (`pip` prefers the higher public version)
            // AND makes the index inconsistent with the download path, which is
            // also tracks-aware and 404s for any version only the remote has.
            // Local precedence is the PEP 708-aligned default for a locally-
            // owned name; a `tracks` declaration re-enables the union (#1582).
            // Second pass: fetch a remote index only when the name is not
            // isolated.
            for member in &members {
                if isolate {
                    break;
                }
                if member.repo_type != RepositoryType::Remote {
                    continue;
                }
                // Only take the first remote response; multiple remote
                // members in one virtual is rare, and merging two upstream
                // /simple/<pkg>/ listings deterministically is out of scope
                // for this fix.
                if remote_response.is_some() {
                    continue;
                }
                let Some(ref upstream_url) = member.upstream_url else {
                    continue;
                };
                let Some(ref proxy) = state.proxy_service else {
                    continue;
                };

                let member_index_path = fetch_pypi_upstream_index_path(&state.db, member.id).await;
                let (effective_upstream, upstream_path) = pypi_upstream_url_and_path(
                    upstream_url,
                    &format!("{}/", normalized),
                    &member_index_path,
                );
                let result = if wants_json {
                    proxy_helpers::proxy_fetch_capped_with_cache_key_and_accept(
                        proxy,
                        member.id,
                        &member.key,
                        &effective_upstream,
                        &upstream_path,
                        &format!("{}index.v1+json", upstream_path),
                        Some(PEP691_JSON_CONTENT_TYPE),
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await
                } else {
                    proxy_helpers::proxy_fetch_capped(
                        proxy,
                        member.id,
                        &member.key,
                        &effective_upstream,
                        &upstream_path,
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await
                };

                match result {
                    Ok((content, content_type)) => {
                        remote_response = Some((content, content_type));
                    }
                    Err(_e) => {
                        debug!(
                            member_key = %member.key,
                            "simple index proxy fetch missed for virtual member"
                        );
                    }
                }
            }

            // PEP 708 `tracks` declared by this virtual's local owners for the
            // project, for metadata emission (#1600). Empty in the isolate case.
            let local_member_ids: Vec<uuid::Uuid> = members
                .iter()
                .filter(|m| matches!(m.repo_type, RepositoryType::Local | RepositoryType::Staging))
                .map(|m| m.id)
                .collect();
            let tracks = pypi_project_tracks_for(&state.db, &local_member_ids, &normalized).await;

            // Render the union.
            match (local_artifacts.is_empty(), remote_response) {
                (true, None) => {
                    return Err(AppError::NotFound(
                        "Package not found in any member repository".to_string(),
                    )
                    .into_response());
                }
                (false, None) => {
                    return build_simple_project_response(
                        &headers,
                        &repo_key,
                        &normalized,
                        &local_artifacts,
                        &tracks,
                    );
                }
                (_, Some((content, content_type))) => {
                    let ct = content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string());

                    // JSON client + JSON upstream: rewrite the upstream download
                    // URLs and splice in local entries, preserving PEP 700
                    // `upload-time` on both. Upstreams that returned HTML despite
                    // the JSON request fall through to the HTML merge below.
                    if wants_json && ct.contains("json") {
                        if let Some(json) = merge_local_into_remote_simple_json(
                            &content,
                            &repo_key,
                            &normalized,
                            &local_artifacts,
                            &tracks,
                        ) {
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, PEP691_JSON_CONTENT_TYPE)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let body = if ct.contains("text/html") {
                        let html = String::from_utf8_lossy(&content);
                        let rewritten = rewrite_upstream_urls(&html, &repo_key, &project);
                        let merged = merge_local_into_remote_simple_html(
                            &rewritten,
                            &repo_key,
                            &normalized,
                            &local_artifacts,
                            &tracks,
                        );
                        Body::from(merged)
                    } else {
                        Body::from(content)
                    };

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .body(body)
                        .unwrap());
                }
            }
        }

        return Err(AppError::NotFound("Package not found".to_string()).into_response());
    }

    let tracks = pypi_project_tracks_for(&state.db, &[repo.id], &normalized).await;
    build_simple_project_response(&headers, &repo_key, &normalized, &simple_artifacts, &tracks)
}

// ---------------------------------------------------------------------------
// Shared response builder for simple project listings (HTML + PEP 691 JSON)
// ---------------------------------------------------------------------------

/// Render the simple project index for a given set of artifacts, using either
/// HTML (PEP 503) or JSON (PEP 691) based on the Accept header.
/// URLs in the response always point through `repo_key` (the virtual or
/// direct repo the client originally requested).
#[allow(clippy::result_large_err)]
fn build_simple_project_response(
    headers: &HeaderMap,
    repo_key: &str,
    normalized: &str,
    artifacts: &[SimpleProjectArtifact],
    tracks: &[String],
) -> Result<Response, Response> {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/vnd.pypi.simple.v1+json") {
        // PEP 691 JSON response
        let files: Vec<serde_json::Value> = artifacts
            .iter()
            .map(|a| {
                let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
                let requires_python = a
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("pkg_info"))
                    .and_then(|pi| pi.get("requires_python"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let mut file = serde_json::json!({
                    "filename": filename,
                    "url": format!("/pypi/{}/simple/{}/{}", repo_key, normalized, filename),
                    "hashes": { "sha256": &a.checksum_sha256 },
                    "size": a.size_bytes,
                });
                if let Some(rp) = requires_python {
                    file["requires-python"] = serde_json::Value::String(rp);
                }
                // PEP 700: surface the distribution's upload timestamp as an
                // RFC 3339 / ISO 8601 `upload-time` field (#1773).
                if let Some(ut) = a.upload_time {
                    file["upload-time"] =
                        serde_json::Value::String(ut.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                }
                file
            })
            .collect();

        let versions: Vec<String> = artifacts
            .iter()
            .filter_map(|a| a.version.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        // PEP 708 / Simple API v1.2: advertise v1.2 and, when the project has
        // operator `tracks` declarations, emit them under meta.tracks so
        // PEP-708-aware installers can validate the server-side merge (#1600).
        let mut meta = serde_json::json!({ "api-version": "1.2" });
        if !tracks.is_empty() {
            meta["tracks"] = serde_json::Value::Array(
                tracks
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            );
        }
        let json = serde_json::json!({
            "meta": meta,
            "name": normalized,
            "versions": versions,
            "files": files,
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap());
    }

    // HTML response
    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str("<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n");
    // PEP 708: surface operator `tracks` declarations on the project page (#1600).
    for t in tracks {
        html.push_str(&format!(
            "<meta name=\"pypi:tracks\" content=\"{}\"/>\n",
            html_escape(t)
        ));
    }
    html.push_str(&format!("<title>Links for {}</title>\n", normalized));
    html.push_str("</head>\n<body>\n");
    html.push_str(&format!("<h1>Links for {}</h1>\n", normalized));

    for a in artifacts {
        let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        let url = format!(
            "/pypi/{}/simple/{}/{}#sha256={}",
            repo_key, normalized, filename, a.checksum_sha256
        );

        let requires_python = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("pkg_info"))
            .and_then(|pi| pi.get("requires_python"))
            .and_then(|v| v.as_str());

        let rp_attr = requires_python
            .map(|rp| format!(" data-requires-python=\"{}\"", html_escape(rp)))
            .unwrap_or_default();

        // PEP 700: expose the upload timestamp as a `data-upload-time` anchor
        // attribute (RFC 3339) so HTML clients can read it too (#1773).
        let ut_attr = a
            .upload_time
            .map(|ut| format!(" data-upload-time=\"{}\"", ut.format("%Y-%m-%dT%H:%M:%SZ")))
            .unwrap_or_default();

        html.push_str(&format!(
            "<a href=\"{}\"{}{}>{}</a><br/>\n",
            url, rp_attr, ut_attr, filename
        ));
    }

    html.push_str("</body>\n</html>\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap())
}

/// Splice local-member entries into a remote-member PEP 503 HTML response so
/// the union is visible through the virtual repo. Entries already present in
/// the remote response (matched by filename, the anchor's inner text per
/// PEP 503) are skipped to preserve idempotence when the same file exists in
/// both members.
fn merge_local_into_remote_simple_html(
    remote_html: &str,
    repo_key: &str,
    normalized: &str,
    local: &[SimpleProjectArtifact],
    tracks: &[String],
) -> String {
    if local.is_empty() && tracks.is_empty() {
        return remote_html.to_string();
    }

    static ANCHOR_FILENAME: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?s)<a\s[^>]*>([^<]+)</a>").unwrap());
    let existing: std::collections::HashSet<&str> = ANCHOR_FILENAME
        .captures_iter(remote_html)
        .map(|c| c.get(1).unwrap().as_str().trim())
        .collect();

    let mut local_lines = String::new();
    for a in local {
        let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        if existing.contains(filename) {
            continue;
        }
        let url = format!(
            "/pypi/{}/simple/{}/{}#sha256={}",
            repo_key, normalized, filename, a.checksum_sha256
        );
        let requires_python = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("pkg_info"))
            .and_then(|pi| pi.get("requires_python"))
            .and_then(|v| v.as_str());
        let rp_attr = requires_python
            .map(|rp| format!(" data-requires-python=\"{}\"", html_escape(rp)))
            .unwrap_or_default();
        // PEP 700: include the upload timestamp for spliced local entries (#1773).
        let ut_attr = a
            .upload_time
            .map(|ut| format!(" data-upload-time=\"{}\"", ut.format("%Y-%m-%dT%H:%M:%SZ")))
            .unwrap_or_default();
        local_lines.push_str(&format!(
            "<a href=\"{}\"{}{}>{}</a><br/>\n",
            url, rp_attr, ut_attr, filename
        ));
    }

    if local_lines.is_empty() && tracks.is_empty() {
        return remote_html.to_string();
    }

    let mut out = remote_html.to_string();

    // PEP 708: inject operator `tracks` declarations into the project page head
    // so the union the virtual performs is validatable downstream (#1600).
    if !tracks.is_empty() {
        let metas: String = tracks
            .iter()
            .map(|t| {
                format!(
                    "<meta name=\"pypi:tracks\" content=\"{}\"/>\n",
                    html_escape(t)
                )
            })
            .collect();
        if let Some(h) = out.find("</head>") {
            out.insert_str(h, &metas);
        } else {
            out = format!("{}{}", metas, out);
        }
    }

    if !local_lines.is_empty() {
        if let Some(idx) = out.rfind("</body>") {
            out.insert_str(idx, &local_lines);
        } else {
            out.push_str(&local_lines);
        }
    }

    out
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/{project}/{filename} — Download or metadata
// ---------------------------------------------------------------------------

async fn download_or_metadata(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, project, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // PEP 658: if filename ends with .metadata, serve extracted METADATA
    if filename.ends_with(".metadata") {
        let real_filename = filename.trim_end_matches(".metadata");
        return serve_metadata(
            &state,
            &state.db,
            repo.id,
            &repo.storage_location(),
            real_filename,
        )
        .await;
    }

    // Regular file download
    serve_file(&state, &repo, &repo_key, &project, &filename, auth.as_ref()).await
}

async fn serve_file(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    project: &str,
    filename: &str,
    auth: Option<&AuthExtension>,
) -> Result<Response, Response> {
    // Find artifact by filename (last path segment matches)
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, content_type, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE '%/' || $2 ESCAPE '\'
        LIMIT 1
        "#,
        repo.id,
        super::escape_filename_for_like(filename)
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Try the proxy cache first using a predictable local
                    // path. This avoids fetching the simple index from upstream
                    // just to rediscover the download URL when the file is
                    // already cached from a previous request. Streamed straight
                    // from storage (#895): buffering cached multi-hundred-MiB
                    // wheels per request OOM-killed memory-constrained pods.
                    let normalized = PypiHandler::normalize_name(project);
                    let local_cache_path = format!("simple/{}/{}", normalized, filename);

                    // #1555: redirect to a presigned URL on a fresh cache hit
                    // before falling back to streaming.
                    if let Some(redirect) =
                        pypi_proxy_cache_redirect(state, proxy, repo_key, &local_cache_path).await
                    {
                        return Ok(redirect);
                    }

                    if let Some(result) = proxy_helpers::proxy_check_cache_streaming(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        &local_cache_path,
                    )
                    .await
                    {
                        return Ok(build_streaming_file_response(filename, result));
                    }

                    // Cache miss: use PyPI-specific fetch logic, streaming the
                    // package file from upstream while teeing it into the cache.
                    let index_path = fetch_pypi_upstream_index_path(&state.db, repo.id).await;
                    let result = fetch_from_pypi_remote_streaming(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        project,
                        filename,
                        &index_path,
                    )
                    .await?;

                    return Ok(build_streaming_file_response(filename, result));
                }
            }
            // Virtual repo: try each member in priority order.
            // Unlike generic formats, PyPI requires format-specific fetch
            // logic for remote members because external registries (e.g.
            // pypi.org) host files on a different domain than the simple
            // index. We iterate members manually and delegate to
            // fetch_from_pypi_remote_streaming for each remote member.
            if repo.repo_type == RepositoryType::Virtual {
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

                if members.is_empty() {
                    return Err(AppError::NotFound(
                        "Virtual repository has no members".to_string(),
                    )
                    .into_response());
                }

                // #2073 (sibling of #1804, fixed for Maven by #1816): authorize
                // each member against the caller BEFORE any of its bytes can be
                // served. A public virtual repo must not become a confused
                // deputy that streams its PRIVATE members' artifacts to
                // anonymous / unprivileged callers. Members the caller could not
                // read directly are dropped, so a denied member behaves exactly
                // as if it did not contain the artifact (404) and its existence
                // is never leaked. Routes through the SAME helper the Maven
                // download path uses.
                let members = proxy_helpers::authorize_virtual_members(
                    &state.permission_service,
                    auth,
                    members,
                )
                .await;

                // PEP 708 dependency-confusion guard (#1600), superseding the
                // version-aware shadowing guard (#1217, #1582) and the
                // name-only local-precedence suppression (#1738). Isolate to the
                // local owner when a local member owns the name and no operator
                // `tracks` declaration permits merging with upstream. When
                // isolated, every Remote member is skipped so an unrelated
                // public package of the same name is never served through the
                // virtual; the download then 404s for a version the local owner
                // lacks, which matches what the simple index lists (consistent).
                // When a `tracks` declaration exists (same project, split version
                // ranges, #1582) this returns false and the proxy fallthrough
                // below applies.
                let normalized_project = normalize_pep503(project);
                let suppress_remote_members = proxy_helpers::pypi_virtual_isolates_name(
                    &state.db,
                    repo.id,
                    &normalized_project,
                )
                .await?;

                for member in &members {
                    // Try local storage first (works for hosted repos and
                    // cached remote artifacts). #1555: redirect to S3 presigned
                    // URL instead of streaming when enabled.
                    match proxy_helpers::local_fetch_or_redirect_by_suffix(
                        &state.db,
                        state,
                        member.id,
                        &member.storage_location(),
                        filename,
                    )
                    .await
                    {
                        Ok(response) => {
                            return Ok(response);
                        }
                        Err(e) => {
                            debug!(
                                member_key = %member.key,
                                error = %e.status(),
                                "local fetch failed for virtual member"
                            );
                        }
                    }

                    // If member is a remote PyPI repo, use the same logic as
                    // the direct Remote path: check the proxy cache first using
                    // a stable key, then fall back to the format-specific fetch
                    // that resolves the real download URL via the simple index.
                    //
                    // Shadowing guard (#1217 follow-up, ak-hv3s): when
                    // `suppress_remote_members` is set, skip every Remote
                    // member so an upstream cannot serve a project whose
                    // normalized PEP 503 name a local member already
                    // owns. Pair with `order_members_local_first`-style
                    // ordering at the top of this loop: locals run
                    // first so they win even when the guard doesn't fire.
                    if member.repo_type == RepositoryType::Remote && !suppress_remote_members {
                        if let (Some(ref upstream_url), Some(ref proxy)) =
                            (&member.upstream_url, &state.proxy_service)
                        {
                            // Check proxy cache first (same optimization as the
                            // direct Remote path). This avoids re-fetching the
                            // simple index from upstream when the file is already
                            // cached from a previous request through this member.
                            let normalized = PypiHandler::normalize_name(project);
                            let local_cache_path = format!("simple/{}/{}", normalized, filename);

                            // #1555: redirect to a presigned URL on a fresh
                            // cache hit before falling back to streaming.
                            if let Some(redirect) = pypi_proxy_cache_redirect(
                                state,
                                proxy,
                                &member.key,
                                &local_cache_path,
                            )
                            .await
                            {
                                return Ok(redirect);
                            }

                            if let Some(result) = proxy_helpers::proxy_check_cache_streaming(
                                proxy,
                                member.id,
                                &member.key,
                                upstream_url,
                                &local_cache_path,
                            )
                            .await
                            {
                                return Ok(build_streaming_file_response(filename, result));
                            }

                            let member_index_path =
                                fetch_pypi_upstream_index_path(&state.db, member.id).await;
                            match fetch_from_pypi_remote_streaming(
                                proxy,
                                member.id,
                                &member.key,
                                upstream_url,
                                project,
                                filename,
                                &member_index_path,
                            )
                            .await
                            {
                                Ok(result) => {
                                    return Ok(build_streaming_file_response(filename, result));
                                }
                                Err(e) => {
                                    debug!(
                                        member_key = %member.key,
                                        error = %e.status(),
                                        "remote PyPI fetch failed for virtual member"
                                    );
                                }
                            }
                        }
                    }
                }

                return Err(AppError::NotFound(
                    "Artifact not found in any member repository".to_string(),
                )
                .into_response());
            }
            return Err(AppError::NotFound("File not found".to_string()).into_response());
        }
    };

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let stream = if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let index_path = fetch_pypi_upstream_index_path(&state.db, repo.id).await;
            get_remote_cached_or_refetch_stream(
                storage.clone(),
                &artifact.storage_key,
                || async move {
                    fetch_from_pypi_remote_streaming(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        project,
                        filename,
                        &index_path,
                    )
                    .await
                },
            )
            .await?
        } else {
            storage
                .get_stream(&artifact.storage_key)
                .await
                .map_err(map_storage_err)?
                .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
                .boxed()
        }
    } else {
        storage
            .get_stream(&artifact.storage_key)
            .await
            .map_err(map_storage_err)?
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
            .boxed()
    };

    // Record download statistics for locally-stored artifacts only.
    // Proxied and virtual-repo fetches go through
    // build_streaming_file_response() which intentionally skips stats since
    // the artifact is not ours.
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, pypi_content_type(filename))
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-PyPI-File-SHA256", &artifact.checksum_sha256)
        .body(Body::from_stream(stream))
        .unwrap())
}

/// Streaming variant of the PyPI proxy cache read. Streams a cache hit
/// straight from storage; on a miss it re-fetches the wheel from upstream and
/// STREAMS it to the caller while teeing it back into storage so the next
/// request is served warm.
///
/// #2192 / #1608 Phase 4c: the previous recovery path buffered the refetch
/// (capped at 16 MiB by #2181) and 502'd a wheel larger than the cap even
/// though the primary download path streams. The refetch now yields a
/// [`StreamingFetchResult`] (via `fetch_from_pypi_remote_streaming`) and the
/// body is teed into `storage_key` as it flows to the client — preserving the
/// thundering-herd write-back (PR #1283) without ever buffering the whole wheel.
async fn get_remote_cached_or_refetch_stream<F, Fut>(
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
    storage_key: &str,
    refetch: F,
) -> Result<BoxStream<'static, Result<Bytes, std::io::Error>>, Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<crate::services::proxy_service::StreamingFetchResult, Response>>,
{
    match storage.get_stream(storage_key).await {
        Ok(stream) => Ok(stream
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
            .boxed()),
        Err(AppError::NotFound(_)) => {
            tracing::warn!(
                storage_key = %storage_key,
                "remote PyPI proxy cache entry is missing on disk; re-fetching from upstream (streaming)"
            );
            let result = refetch().await?;
            Ok(tee_refetch_to_storage(
                storage,
                storage_key.to_string(),
                result.content_length,
                result.body,
            ))
        }
        Err(e) => Err(map_storage_err(e)),
    }
}

/// Tee a streaming refetch body into repo storage at `storage_key` while
/// forwarding it to the caller (#2192 / #1608 Phase 4c).
///
/// Replaces the buffered `storage.put(storage_key, bytes)` write-back the
/// recovery path used to perform, without buffering the whole payload:
///
/// * The body is forwarded to the client verbatim.
/// * A clone of each chunk is streamed, in order and with backpressure, to a
///   background `put_stream` so the cached blob is byte-exact.
/// * The client stream awaits the write-back at EOF, so a subsequent request
///   deterministically observes the warmed entry.
/// * Best-effort: a write failure is logged but never fails the in-flight
///   download. A truncated write-back (client disconnect, short read, or upstream
///   error mid-stream) is detected against `expected_len` and the partial cache
///   entry is deleted so no corrupt blob is ever served warm.
fn tee_refetch_to_storage(
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
    storage_key: String,
    expected_len: Option<u64>,
    upstream: BoxStream<'static, crate::error::Result<Bytes>>,
) -> BoxStream<'static, Result<Bytes, std::io::Error>> {
    // Bounded channel: a slow backend applies backpressure to the upstream read
    // instead of letting chunks pile up in memory. Order is preserved and no
    // chunk is dropped, so the written-back blob matches the served bytes.
    let (tx, rx) = tokio::sync::mpsc::channel::<crate::error::Result<Bytes>>(16);
    let writer_key = storage_key.clone();
    let writer = tokio::spawn(async move {
        let rx_stream =
            futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|i| (i, rx)) });
        match storage.put_stream(&writer_key, Box::pin(rx_stream)).await {
            Ok(w) => {
                // Compensate for a partial write (the default put_stream commits
                // whatever it received when the channel closes cleanly): if the
                // written length does not match the advertised length, delete the
                // truncated entry so it is never served as a warm hit.
                if let Some(expected) = expected_len {
                    if w.bytes_written != expected {
                        tracing::warn!(
                            storage_key = %writer_key,
                            expected,
                            written = w.bytes_written,
                            "streaming write-back of refetched PyPI payload was truncated; \
                             deleting partial cache entry"
                        );
                        let _ = storage.delete(&writer_key).await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    storage_key = %writer_key,
                    error = %e,
                    "streaming write-back of refetched PyPI payload failed; \
                     subsequent requests will re-fetch from upstream"
                );
            }
        }
    });

    futures::stream::unfold(
        (upstream, Some(tx), Some(writer)),
        |(mut upstream, mut tx, mut writer)| async move {
            match upstream.next().await {
                Some(Ok(bytes)) => {
                    if let Some(sender) = tx.as_ref() {
                        // Backpressure on the writer; drop the tee (not the
                        // client stream) if the writer has gone away.
                        if sender.send(Ok(bytes.clone())).await.is_err() {
                            tx = None;
                        }
                    }
                    Some((Ok(bytes), (upstream, tx, writer)))
                }
                Some(Err(e)) => {
                    // Propagate the error to the writer so the default put_stream
                    // aborts (no partial commit), then stop teeing.
                    if let Some(sender) = tx.as_ref() {
                        let _ = sender
                            .send(Err(crate::error::AppError::Internal(e.to_string())))
                            .await;
                    }
                    let io_err = std::io::Error::other(e.to_string());
                    Some((Err(io_err), (upstream, None, writer)))
                }
                None => {
                    // EOF: closing the channel lets put_stream commit; await it so
                    // a subsequent request observes the warmed entry.
                    drop(tx);
                    if let Some(handle) = writer.take() {
                        let _ = handle.await;
                    }
                    None
                }
            }
        },
    )
    .boxed()
}

/// Resolved upstream download target for a PyPI remote file, produced by
/// [`resolve_pypi_remote_fetch_target`] and consumed by both the buffered
/// and the streaming fetch variants.
struct PypiRemoteFetchTarget {
    /// Upstream base URL for the file download (may be a different host
    /// than the simple index, e.g. files.pythonhosted.org).
    fetch_base: String,
    /// Path relative to `fetch_base`.
    fetch_path: String,
    /// Stable proxy-cache key (`simple/{project}/{filename}`), independent
    /// of the actual upstream URL layout.
    cache_path: String,
}

/// Resolve the real download URL for a file hosted by a remote PyPI
/// upstream. External PyPI registries (e.g. pypi.org) host files on a
/// different domain (files.pythonhosted.org), so we cannot just append the
/// filename to the upstream URL. Instead, we fetch the simple index page,
/// parse it to discover the real download URL for the file, and validate it
/// against SSRF before returning.
///
/// The index fetch stays buffered by design: simple-index pages are small
/// HTML documents that must be parsed in-process. Only the package file
/// itself (potentially hundreds of MiB) needs the streaming path.
async fn resolve_pypi_remote_fetch_target(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &str,
    filename: &str,
    index_path: &str,
) -> Result<PypiRemoteFetchTarget, Response> {
    let normalized = PypiHandler::normalize_name(project);

    // Build the upstream index URL using the configured index_path.
    // When `index_path` is "simple" (the default), the existing /simple-dedup
    // logic from #1130 applies. When empty, the CDN flat-index layout is used
    // (no prefix). Any other non-empty value is used verbatim as the prefix.
    let (effective_upstream, upstream_index_path) =
        pypi_upstream_url_and_path(upstream_url, &format!("{}/", normalized), index_path);
    let (index_bytes, _ct, effective_url) = proxy_helpers::proxy_fetch_uncached(
        proxy,
        repo_id,
        repo_key,
        &effective_upstream,
        &upstream_index_path,
    )
    .await?;

    let index_html = String::from_utf8_lossy(&index_bytes);

    // Use the effective URL (after redirects) as the base for resolving
    // relative hrefs. Some registries (Nexus, Artifactory) redirect the
    // index request, and the relative paths in the HTML are relative to
    // the final serving URL, not the originally requested URL.
    let full_index_url = effective_url;
    let file_url = find_upstream_url_for_file(&index_html, filename, Some(&full_index_url));

    let fallback = || {
        let (base, path) = pypi_upstream_url_and_path(
            upstream_url,
            &format!("{}/{}", normalized, filename),
            index_path,
        );
        (base, path)
    };

    // Validate resolved URL against SSRF before making the outbound request.
    // A malicious upstream index could contain hrefs pointing to internal
    // addresses (169.254.169.254, localhost, Docker service names, etc.).
    if let Some(ref url) = file_url {
        if let Err(e) = validate_outbound_url(url, "PyPI upstream file URL") {
            tracing::warn!(
                "SSRF check rejected resolved file URL '{}' from upstream index: {}",
                url,
                e
            );
            // Fall through to the fallback path instead of fetching the
            // potentially malicious URL.
            return Err(AppError::Validation(format!(
                "Upstream index contains a disallowed URL: {}",
                e
            ))
            .into_response());
        }
    }

    // Use a stable cache key (simple/{project}/{filename}) regardless of the
    // actual upstream URL. Nexus/devpi resolve to paths like
    // packages/requests/2.31.0/requests-2.31.0.tar.gz which differ from the
    // simple/ convention. A stable cache key ensures the cache-check
    // optimization in serve_file works for all upstream registry types.
    let cache_path = format!("simple/{}/{}", normalized, filename);

    let (fetch_base, fetch_path) = match file_url.as_deref().and_then(split_url_base_and_path) {
        Some(pair) => pair,
        None => fallback(),
    };

    Ok(PypiRemoteFetchTarget {
        fetch_base,
        fetch_path,
        cache_path,
    })
}

/// #1555: presigned-redirect fast path for a fresh proxy-cache hit on a remote
/// PyPI member. Returns `Some(307 redirect)` only when presigned downloads are
/// enabled and the cache is fresh, signing the cache key through the proxy's own
/// no-prefix backend (proxy-cache content lives at the storage root). Returns
/// `None` on a miss/disabled so the caller falls back to the streaming path,
/// which resolves the real upstream URL via the simple index — never via a
/// presumed download URL.
async fn pypi_proxy_cache_redirect(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_key: &str,
    cache_path: &str,
) -> Option<Response> {
    if !state.config.presigned_downloads_enabled {
        return None;
    }
    // #1555: resolve the no-prefix presign handle and confirm redirect support
    // BEFORE the `is_cache_fresh` probe — the probe loads the cache-meta
    // sidecar, so we avoid a wasted S3 GET when we can't redirect anyway (the
    // streaming fallback re-reads the same sidecar).
    let storage = proxy.cache_storage_backend();
    if !storage.supports_redirect() {
        return None;
    }
    if !proxy.is_cache_fresh(repo_key, cache_path).await {
        return None;
    }
    let cache_key =
        crate::services::proxy_service::ProxyService::cache_storage_key(repo_key, cache_path)
            .ok()?;
    let expiry = std::time::Duration::from_secs(state.config.presigned_download_expiry_secs);
    proxy_helpers::try_proxy_cache_redirect(
        storage.as_ref(),
        &cache_key,
        /* presigned_enabled = */ true,
        expiry,
        /* cache_is_fresh = */ true,
    )
    .await
}

/// Fetch a PyPI package file from a remote upstream as a stream (#895 OOM
/// relief).
///
/// Resolves the real download URL via the simple index (buffered, in-process),
/// then streams the package file from upstream — teed into the proxy cache —
/// instead of buffering it in memory. This is the single fetch path for remote
/// PyPI downloads, including the cache-recovery write-back in
/// [`get_remote_cached_or_refetch_stream`]. Large wheels
/// (CUDA / ML packages routinely exceed 400 MiB) previously OOM-killed
/// memory-constrained pods when several `pip install` runs downloaded
/// concurrently through the buffered path.
async fn fetch_from_pypi_remote_streaming(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &str,
    filename: &str,
    index_path: &str,
) -> Result<crate::services::proxy_service::StreamingFetchResult, Response> {
    let target = resolve_pypi_remote_fetch_target(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        project,
        filename,
        index_path,
    )
    .await?;

    proxy_helpers::proxy_fetch_streaming_with_cache_key(
        proxy,
        repo_id,
        repo_key,
        &target.fetch_base,
        &target.fetch_path,
        &target.cache_path,
    )
    .await
}

/// Build the HTTP response for serving a PyPI file download from a
/// [`StreamingFetchResult`] (proxied and virtual-repo fetches, #895).
///
/// Sets the format-specific `Content-Type` and an attachment
/// `Content-Disposition`; the body is driven from the stream without
/// buffering. `Content-Length` is set only when the result advertises one;
/// otherwise the response uses chunked transfer encoding. Download
/// statistics are not recorded here because the artifact is not stored
/// locally; stats are only tracked for artifacts served from our own
/// storage (see `serve_file`).
fn build_streaming_file_response(
    filename: &str,
    result: crate::services::proxy_service::StreamingFetchResult,
) -> Response {
    let content_type = pypi_content_type(filename);

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        );
    if let Some(len) = result.content_length {
        builder = builder.header(CONTENT_LENGTH, len.to_string());
    }
    builder
        .body(Body::from_stream(
            result
                .body
                .map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
        ))
        .unwrap()
}

async fn serve_metadata(
    state: &SharedState,
    db: &PgPool,
    repo_id: uuid::Uuid,
    location: &crate::storage::StorageLocation,
    filename: &str,
) -> Result<Response, Response> {
    // Find the artifact
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.storage_key
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE '%/' || $2 ESCAPE '\'
        LIMIT 1
        "#,
        repo_id,
        super::escape_filename_for_like(filename)
    )
    .fetch_optional(db)
    .await
    .map_err(map_db_err)?
    .ok_or_else(|| AppError::NotFound("File not found".to_string()).into_response())?;

    // Try to extract METADATA from the package file
    let storage = state.storage_for_repo_or_500(location)?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    let metadata_text = if filename.ends_with(".whl") {
        extract_metadata_from_wheel(&content)
    } else if filename.ends_with(".tar.gz") {
        extract_metadata_from_sdist(&content)
    } else {
        None
    };

    match metadata_text {
        Some(text) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(text))
            .unwrap()),
        None => Err(AppError::NotFound("Metadata not available".to_string()).into_response()),
    }
}

fn extract_metadata_from_wheel(content: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(content);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).ok()?;
        if file.name().contains(".dist-info/") && file.name().ends_with("METADATA") {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut file, &mut text).ok()?;
            return Some(text);
        }
    }
    None
}

fn extract_metadata_from_sdist(content: &[u8]) -> Option<String> {
    use flate2::read::GzDecoder;
    let gz = GzDecoder::new(content);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_path_buf();
        if path.ends_with("PKG-INFO") {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut entry, &mut text).ok()?;
            return Some(text);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// POST /pypi/{repo_key}/ — Twine upload
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (assignment expr); the exempt call is marked inline below (#1608)
async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    // Authenticate
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "pypi", "write")?.user_id;
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Parse multipart form data
    let mut action: Option<String> = None;
    let mut pkg_name: Option<String> = None;
    let mut pkg_version: Option<String> = None;
    let mut staged_content: Option<proxy_helpers::StagedUpload> = None;
    let mut content_digests: Option<crate::services::artifact_service::ContentDigests> = None;
    let mut file_name: Option<String> = None;
    let mut sha256_digest: Option<String> = None;
    let mut _md5_digest: Option<String> = None;
    let mut requires_python: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut metadata_fields: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Invalid multipart: {}", e)).into_response())?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            ":action" => {
                action = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "name" => {
                pkg_name = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "version" => {
                pkg_version = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "sha256_digest" => {
                sha256_digest = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "md5_digest" => {
                _md5_digest = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "requires_python" => {
                requires_python = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "summary" => {
                summary = Some(field.text().await.map_err(|e| {
                    AppError::Validation(format!("Invalid field: {}", e)).into_response()
                })?);
            }
            "content" => {
                file_name = field.file_name().map(|s| s.to_string());
                // Spool the wheel straight to a bounded scratch file while
                // computing SHA-256/SHA-1/MD5 incrementally — never buffered.
                let (s, d) =
                    proxy_helpers::stage_upload_field_content_addressed(&state, field).await?;
                staged_content = Some(s);
                content_digests = Some(d);
            }
            // Capture other metadata fields
            _ => {
                if let Ok(text) = field.text().await {
                    // Handle repeated fields (classifiers, etc.)
                    if let Some(existing) = metadata_fields.get(&name) {
                        if let Some(arr) = existing.as_array() {
                            let mut arr = arr.clone();
                            arr.push(serde_json::Value::String(text));
                            metadata_fields.insert(name, serde_json::Value::Array(arr));
                        } else {
                            metadata_fields.insert(
                                name,
                                serde_json::Value::Array(vec![
                                    existing.clone(),
                                    serde_json::Value::String(text),
                                ]),
                            );
                        }
                    } else {
                        metadata_fields.insert(name, serde_json::Value::String(text));
                    }
                }
            }
        }
    }

    // Validate required fields
    let action = action.unwrap_or_default();
    if action != "file_upload" {
        return Err(
            AppError::Validation(format!("Unsupported action: {}", action)).into_response(),
        );
    }

    let pkg_name = pkg_name
        .ok_or_else(|| AppError::Validation("Missing 'name' field".to_string()).into_response())?;
    let pkg_version = pkg_version.ok_or_else(|| {
        AppError::Validation("Missing 'version' field".to_string()).into_response()
    })?;
    let staged_content = staged_content.ok_or_else(|| {
        AppError::Validation("Missing 'content' field".to_string()).into_response()
    })?;
    let digests = content_digests.ok_or_else(|| {
        AppError::Validation("Missing 'content' field".to_string()).into_response()
    })?;
    let filename = file_name.ok_or_else(|| {
        AppError::Validation("Missing filename in content field".to_string()).into_response()
    })?;

    let normalized = PypiHandler::normalize_name(&pkg_name);

    // SHA-256 was computed incrementally while the body was spooled to disk.
    let computed_sha256 = digests.sha256.clone();

    // Verify digest if provided
    if let Some(ref expected) = sha256_digest {
        if !expected.is_empty() && expected != &computed_sha256 {
            return Err(AppError::Validation(format!(
                "SHA256 mismatch: expected {} got {}",
                expected, computed_sha256
            ))
            .into_response());
        }
    }

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        format!("{}/{}/{}", normalized, pkg_version, filename)
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    if existing.is_some() {
        return Err(AppError::Conflict("File already exists".to_string()).into_response());
    }

    // Build metadata JSON
    let mut pkg_metadata = serde_json::json!({
        "name": &pkg_name,
        "normalized_name": &normalized,
        "version": &pkg_version,
        "filename": &filename,
    });
    if let Some(rp) = &requires_python {
        pkg_metadata["pkg_info"] = serde_json::json!({
            "requires_python": rp,
        });
    }
    if let Some(s) = &summary {
        if !pkg_metadata["pkg_info"].is_object() {
            pkg_metadata["pkg_info"] = serde_json::json!({});
        }
        if let Some(pkg_info) = pkg_metadata["pkg_info"].as_object_mut() {
            pkg_info.insert("summary".to_string(), serde_json::Value::String(s.clone()));
        }
    }
    if !metadata_fields.is_empty() {
        pkg_metadata["upload_metadata"] = serde_json::Value::Object(metadata_fields);
    }

    let content_type = pypi_content_type(&filename);

    let artifact_path = format!("{}/{}/{}", normalized, pkg_version, filename);
    let size_bytes = staged_content.size_bytes();

    // No pre-cleanup here: this path persists through
    // `artifact_service::upload_with_sync_options`, whose release-immutability
    // backstop must see the soft-deleted tombstone (purging it first would hide
    // a release-immutability swap). The service's `ON CONFLICT DO UPDATE`
    // resurrects the soft-deleted row in the allowed (identical-bytes / mutable)
    // cases, so the UNIQUE(repository_id, path) constraint is still satisfied.

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let artifact_service = state.create_artifact_service(storage);
    // Re-read the staged scratch file as a `'static` stream; the service does the
    // dedup `exists()` check first and only streams into storage on a miss.
    let content_stream = proxy_helpers::open_staged_upload_stream(&staged_content).await?;
    let artifact = artifact_service
        .upload_stream_with_sync_options(
            repo.id,
            &artifact_path,
            &normalized,
            Some(&pkg_version),
            content_type,
            content_stream,
            digests,
            size_bytes,
            Some(user_id),
            should_enqueue_pypi_sync_tasks(&headers),
        )
        .await
        .map_err(|e| e.into_response())?;
    // Scratch file no longer needed once the service has consumed the stream.
    drop(staged_content);

    artifact_service
        .set_metadata(artifact.id, "pypi", pkg_metadata, serde_json::json!({}))
        .await
        .map_err(|e| e.into_response())?;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    // Populate packages / package_versions tables (best-effort)
    {
        let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
        pkg_svc
            .try_create_or_update_from_artifact(
                repo.id,
                &normalized,
                &pkg_version,
                size_bytes,
                &artifact.checksum_sha256,
                summary.as_deref(),
                Some(build_pypi_package_catalog_metadata(
                    &filename,
                    requires_python.as_deref(),
                )),
            )
            .await;
    }

    info!(
        "PyPI upload: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("OK"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn should_enqueue_pypi_sync_tasks(headers: &HeaderMap) -> bool {
    !super::is_replication_request(headers)
}

fn build_pypi_package_catalog_metadata(
    filename: &str,
    requires_python: Option<&str>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "format": "pypi",
        "filename": filename,
    });
    if let Some(rp) = requires_python.filter(|value| !value.trim().is_empty()) {
        metadata["requires_python"] = serde_json::Value::String(rp.to_string());
    }
    metadata
}

/// Determine the Content-Type for a PyPI filename based on its extension.
fn pypi_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".whl") || filename.ends_with(".zip") {
        "application/zip"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else if filename.ends_with(".tar.bz2") {
        "application/x-bzip2"
    } else {
        "application/octet-stream"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        // Escape the apostrophe so the helper is safe in single-quoted
        // attribute contexts too, matching html_escape_pep503 in formats/pypi.rs.
        .replace('\'', "&#39;")
}

// ---------------------------------------------------------------------------
// Static regexes (compiled once, reused across requests)
// ---------------------------------------------------------------------------

static HREF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r##"<a\s+[^>]*?href="([^"#]+)"##).unwrap());

static REWRITE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<a\s+([^>]*?)href="([^"]+)"([^>]*)>"#).unwrap());

static METADATA_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\s*data-(?:dist-info-metadata|core-metadata)="[^"]*""#).unwrap());

/// Split a URL into its base (scheme + host) and path components.
///
/// For example, `https://files.pythonhosted.org/packages/ab/cd/file.whl` splits
/// into `("https://files.pythonhosted.org", "packages/ab/cd/file.whl")`.
/// Returns `None` if the URL has no `://` scheme separator or no path after the
/// host.
fn split_url_base_and_path(url_str: &str) -> Option<(String, String)> {
    let parsed = url::Url::parse(url_str).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let base = format!("{}://{}", parsed.scheme(), parsed.authority());
    let path = parsed.path().strip_prefix('/').unwrap_or(parsed.path());
    if path.is_empty() {
        return None;
    }
    Some((base, path.to_string()))
}

/// Look up the original download URL for a given filename in upstream simple
/// index HTML. Returns the full absolute URL (e.g.,
/// `https://files.pythonhosted.org/packages/.../six-1.16.0.whl`) or `None` if
/// no matching link is found. Hash fragments are stripped from the returned URL.
///
/// Supports both absolute URLs (`https://...`) and relative paths
/// (`../../packages/file.tar.gz` or `packages/file.tar.gz`). Relative paths
/// are resolved against `index_url`, which is the full URL of the simple index
/// page that was fetched (e.g.,
/// `https://nexus.example.com/repository/pypi/simple/requests/`).
///
/// Registries like Sonatype Nexus, Artifactory, and devpi commonly use relative
/// hrefs in their simple index HTML instead of absolute URLs.
fn find_upstream_url_for_file(
    index_html: &str,
    filename: &str,
    index_url: Option<&str>,
) -> Option<String> {
    for caps in HREF_RE.captures_iter(index_html) {
        let href = &caps[1];
        let href_filename = href.rsplit('/').next().unwrap_or("");
        if href_filename != filename {
            continue;
        }

        // Already an absolute URL, return as-is.
        if href.starts_with("http://") || href.starts_with("https://") {
            return Some(href.to_string());
        }

        // Relative or root-relative path: resolve against the index page URL.
        // Only return HTTP/HTTPS results to prevent javascript:, data:, file://
        // and other non-HTTP schemes from being promoted to fetch targets.
        if let Some(base) = index_url {
            if let Ok(base_url) = url::Url::parse(base) {
                if let Ok(resolved) = base_url.join(href) {
                    if resolved.scheme() == "http" || resolved.scheme() == "https" {
                        return Some(resolved.as_str().to_string());
                    }
                    continue;
                }
            }
        }
    }
    None
}

/// Rewrite download URLs in upstream PyPI simple index HTML to route through
/// Artifact Keeper's proxy endpoint.
///
/// Upstream sources return links that would bypass the cache:
///   - External PyPI: `<a href="https://files.pythonhosted.org/packages/...">`
///   - Local AK repos: `<a href="/pypi/upstream-key/simple/pkg/file#hash">`
///
/// This function rewrites both forms to paths under the current (remote) repo:
/// `/pypi/{repo_key}/simple/{project}/{filename}#sha256=...` so downloads go
/// through Artifact Keeper and get cached.
///
/// Absolute URLs (`http://`, `https://`) and root-relative paths starting with
/// `/pypi/` are rewritten. Plain relative URLs and anchors are left unchanged.
///
/// PEP 658 metadata attributes (`data-dist-info-metadata` and
/// `data-core-metadata`) are stripped from rewritten links because the proxy
/// cannot serve `.metadata` files for packages it has not stored locally.
/// Keeping these attributes would cause pip to request a `.metadata` URL that
/// returns 404, which pip treats as a hard error since the index promised the
/// metadata was available.
fn rewrite_upstream_urls(html: &str, repo_key: &str, project: &str) -> String {
    let normalized = PypiHandler::normalize_name(project);

    REWRITE_RE
        .replace_all(html, |caps: &regex::Captures| {
            let before_href = &caps[1];
            let full_url = &caps[2];
            let after_href = &caps[3];

            // Split off the fragment (#sha256=...) if present
            let (url_path, fragment) = match full_url.find('#') {
                Some(pos) => (&full_url[..pos], &full_url[pos..]),
                None => (full_url, ""),
            };

            // Extract the filename from the URL path
            let filename = url_path.rsplit('/').next().unwrap_or(url_path);

            if filename.is_empty() {
                // Not a file URL, leave unchanged
                return caps[0].to_string();
            }

            let rewritten = format!(
                "/pypi/{}/simple/{}/{}{}",
                repo_key, normalized, filename, fragment
            );

            // Strip PEP 658 metadata attributes. The proxy does not cache or
            // serve .metadata files, so advertising them causes pip to fail
            // with a 404 when it tries to fetch the promised metadata.
            let before_cleaned = METADATA_ATTR_RE.replace_all(before_href, "");
            let after_cleaned = METADATA_ATTR_RE.replace_all(after_href, "");

            format!(
                "<a {}href=\"{}\"{}>",
                before_cleaned, rewritten, after_cleaned
            )
        })
        .into_owned()
}

/// PEP 691 JSON simple-index media type.
const PEP691_JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";

/// Rewrite the `files[].url` of a parsed PEP 691 JSON simple index to route
/// downloads through Artifact Keeper's proxy, mirroring `rewrite_upstream_urls`
/// for the HTML form, and strip the PEP 658/714 metadata signals the proxy
/// cannot serve (`core-metadata`, `data-dist-info-metadata`). PEP 700
/// `upload-time` and every other field are preserved untouched.
fn rewrite_simple_json_files(doc: &mut serde_json::Value, repo_key: &str, normalized: &str) {
    let Some(files) = doc.get_mut("files").and_then(|f| f.as_array_mut()) else {
        return;
    };
    for file in files.iter_mut() {
        let Some(filename) = file
            .get("filename")
            .and_then(|f| f.as_str())
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(obj) = file.as_object_mut() else {
            continue;
        };
        obj.insert(
            "url".to_owned(),
            serde_json::Value::String(format!(
                "/pypi/{}/simple/{}/{}",
                repo_key, normalized, filename
            )),
        );
        // The proxy cannot serve `.metadata` for distributions it has not
        // cached, so drop the PEP 658/714 metadata signals — the JSON analogue
        // of the `data-*-metadata` stripping in `rewrite_upstream_urls`.
        obj.remove("core-metadata");
        obj.remove("data-dist-info-metadata");
    }
}

/// Rewrite a proxied upstream PEP 691 JSON simple-index response so download
/// URLs route through the proxy endpoint. Returns `None` when the body is not
/// valid PEP 691 JSON, so the caller can fall back to treating the upstream
/// response as HTML.
fn rewrite_upstream_simple_json(json: &[u8], repo_key: &str, normalized: &str) -> Option<String> {
    let mut doc: serde_json::Value = serde_json::from_slice(json).ok()?;
    if !doc.get("files").map(|f| f.is_array()).unwrap_or(false) {
        return None;
    }
    rewrite_simple_json_files(&mut doc, repo_key, normalized);
    serde_json::to_string(&doc).ok()
}

/// Splice local-member distributions into a proxied upstream PEP 691 JSON
/// simple index so the union is visible through a virtual repo, mirroring
/// `merge_local_into_remote_simple_html`. Upstream `files[].url`s are rewritten
/// through the proxy; local entries already present upstream (matched by
/// filename) are skipped. Local `versions` are unioned and operator `tracks`
/// are surfaced under `meta.tracks`. Returns `None` when the upstream body is
/// not valid PEP 691 JSON.
fn merge_local_into_remote_simple_json(
    json: &[u8],
    repo_key: &str,
    normalized: &str,
    local: &[SimpleProjectArtifact],
    tracks: &[String],
) -> Option<String> {
    let mut doc: serde_json::Value = serde_json::from_slice(json).ok()?;
    if !doc.get("files").map(|f| f.is_array()).unwrap_or(false) {
        return None;
    }
    rewrite_simple_json_files(&mut doc, repo_key, normalized);

    // Filenames already present upstream — skip locals that duplicate them, so
    // the union is idempotent when the same file exists in both members.
    let existing: std::collections::HashSet<String> = doc
        .get("files")
        .and_then(|f| f.as_array())
        .map(|files| {
            files
                .iter()
                .filter_map(|f| {
                    f.get("filename")
                        .and_then(|n| n.as_str())
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();

    let mut local_versions: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut appended: Vec<serde_json::Value> = Vec::new();
    for a in local {
        let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        if existing.contains(filename) {
            continue;
        }
        if let Some(v) = &a.version {
            local_versions.insert(v.clone());
        }
        let mut file = serde_json::json!({
            "filename": filename,
            "url": format!("/pypi/{}/simple/{}/{}", repo_key, normalized, filename),
            "hashes": { "sha256": &a.checksum_sha256 },
            "size": a.size_bytes,
        });
        if let Some(rp) = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("pkg_info"))
            .and_then(|pi| pi.get("requires_python"))
            .and_then(|v| v.as_str())
        {
            file["requires-python"] = serde_json::Value::String(rp.to_owned());
        }
        if let Some(ut) = a.upload_time {
            file["upload-time"] =
                serde_json::Value::String(ut.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        }
        appended.push(file);
    }

    if let Some(files) = doc.get_mut("files").and_then(|f| f.as_array_mut()) {
        files.extend(appended);
    }

    // Union the local distributions' versions into the advertised list.
    if !local_versions.is_empty() {
        let mut versions: std::collections::BTreeSet<String> = doc
            .get("versions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        versions.extend(local_versions);
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "versions".to_owned(),
                serde_json::Value::Array(
                    versions
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    // PEP 708: surface operator `tracks` under `meta.tracks`, mirroring the
    // local emission and the HTML merge.
    if !tracks.is_empty() {
        if let Some(meta) = doc.get_mut("meta").and_then(|m| m.as_object_mut()) {
            meta.insert(
                "tracks".to_owned(),
                serde_json::Value::Array(
                    tracks
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    serde_json::to_string(&doc).ok()
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn headers_with_replication(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    fn pypi_upload_multipart(
        project: &str,
        version: &str,
        filename: &str,
        content: &[u8],
        summary: &str,
        requires_python: &str,
    ) -> (String, Bytes) {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256 = format!("{:x}", hasher.finalize());
        let boundary = format!("ak-pypi-test-{}", project.replace('-', "_"));
        let fields = [
            (":action", "file_upload"),
            ("protocol_version", "1"),
            ("metadata_version", "2.1"),
            ("name", project),
            ("version", version),
            ("summary", summary),
            ("sha256_digest", sha256.as_str()),
            ("filetype", "bdist_wheel"),
            ("pyversion", "py3"),
            ("requires_python", requires_python),
        ];
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (
            format!("multipart/form-data; boundary={boundary}"),
            Bytes::from(body),
        )
    }

    // -----------------------------------------------------------------------
    // pypi_upstream_url_and_path (#1130)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pypi_upstream_strips_trailing_simple() {
        let (url, path) =
            pypi_upstream_url_and_path("https://pypi.org/simple/", "flask/", "simple");
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_strips_trailing_simple_no_slash() {
        let (url, path) = pypi_upstream_url_and_path("https://pypi.org/simple", "flask/", "simple");
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_keeps_non_simple_url() {
        let (url, path) = pypi_upstream_url_and_path("https://pypi.org", "flask/", "simple");
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_keeps_devpi_path() {
        let (url, path) =
            pypi_upstream_url_and_path("https://devpi.example.com/root/pypi", "numpy/", "simple");
        assert_eq!(url, "https://devpi.example.com/root/pypi");
        assert_eq!(path, "simple/numpy/");
    }

    #[test]
    fn test_pypi_upstream_trailing_simple_with_file() {
        let (url, path) = pypi_upstream_url_and_path(
            "https://pypi.org/simple/",
            "flask/Flask-3.0.0.tar.gz",
            "simple",
        );
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/Flask-3.0.0.tar.gz");
    }

    #[test]
    fn test_pypi_upstream_bare_simple_collapses_to_root() {
        // Edge case: configured upstream is literally "/simple" — strip the
        // suffix and substitute "/" so build_upstream_url has a non-empty
        // base to operate on. Exercises the `if base.is_empty()` branch.
        let (url, path) = pypi_upstream_url_and_path("/simple", "flask/", "simple");
        assert_eq!(url, "/");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_bare_simple_with_trailing_slash_collapses_to_root() {
        let (url, path) = pypi_upstream_url_and_path("/simple/", "flask/", "simple");
        assert_eq!(url, "/");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_should_enqueue_pypi_sync_tasks_for_direct_upload() {
        assert!(should_enqueue_pypi_sync_tasks(&HeaderMap::new()));
    }

    #[test]
    fn test_should_enqueue_pypi_sync_tasks_skips_peer_replication() {
        assert!(!should_enqueue_pypi_sync_tasks(&headers_with_replication(
            "true"
        )));
    }

    #[test]
    fn test_pypi_upstream_strips_leading_slash_from_tail() {
        // Tail with a stray leading slash should not produce `simple//flask/`.
        let (url, path) = pypi_upstream_url_and_path("https://pypi.org", "/flask/", "simple");
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_simple_substring_not_stripped() {
        // `simple-index` ends with `simple` substring but NOT the `/simple`
        // path segment, so it must not be stripped.
        let (url, path) = pypi_upstream_url_and_path(
            "https://mirror.example.com/pypi-simple-index",
            "flask/",
            "simple",
        );
        assert_eq!(url, "https://mirror.example.com/pypi-simple-index");
        assert_eq!(path, "simple/flask/");
    }

    #[test]
    fn test_pypi_upstream_multiple_trailing_slashes_handled() {
        // trim_end_matches('/') strips all trailing slashes; the resulting
        // URL must still strip the `/simple` segment correctly.
        let (url, path) =
            pypi_upstream_url_and_path("https://pypi.org/simple///", "flask/", "simple");
        assert_eq!(url, "https://pypi.org");
        assert_eq!(path, "simple/flask/");
    }

    // -----------------------------------------------------------------------
    // pypi_upstream_url_and_path — flat CDN index (#1546)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pypi_upstream_flat_index_pytorch_cdn() {
        // PyTorch CDN: packages live directly under the upstream root.
        // index_path="" means no prefix: torch/ → {upstream}/torch/
        let (url, path) =
            pypi_upstream_url_and_path("https://download.pytorch.org/whl/cpu", "torch/", "");
        assert_eq!(url, "https://download.pytorch.org/whl/cpu");
        assert_eq!(path, "torch/");
    }

    #[test]
    fn test_pypi_upstream_flat_index_strips_leading_slash_from_tail() {
        // Stray leading slash on tail must not produce `//torch/` on flat layout.
        let (url, path) =
            pypi_upstream_url_and_path("https://download.pytorch.org/whl/cpu", "/torch/", "");
        assert_eq!(url, "https://download.pytorch.org/whl/cpu");
        assert_eq!(path, "torch/");
    }

    #[test]
    fn test_pypi_upstream_flat_index_with_filename() {
        // File download on flat layout: tail includes the filename.
        let (url, path) = pypi_upstream_url_and_path(
            "https://download.pytorch.org/whl/cpu",
            "torch/torch-2.2.0+cpu-cp311-cp311-linux_x86_64.whl",
            "",
        );
        assert_eq!(url, "https://download.pytorch.org/whl/cpu");
        assert_eq!(path, "torch/torch-2.2.0+cpu-cp311-cp311-linux_x86_64.whl");
    }

    #[test]
    fn test_pypi_upstream_flat_index_url_ending_in_simple_not_stripped() {
        // When index_path is empty the /simple de-dup logic is intentionally
        // skipped. A URL that happens to end in `/simple` is used verbatim.
        let (url, path) =
            pypi_upstream_url_and_path("https://cdn.example.com/simple", "numpy/", "");
        assert_eq!(url, "https://cdn.example.com/simple");
        assert_eq!(path, "numpy/");
    }

    #[test]
    fn test_pypi_upstream_custom_index_path() {
        // Custom prefix other than "simple" (e.g. a private mirror's layout).
        let (url, path) =
            pypi_upstream_url_and_path("https://mirror.corp/pypi", "requests/", "packages");
        assert_eq!(url, "https://mirror.corp/pypi");
        assert_eq!(path, "packages/requests/");
    }

    #[test]
    fn test_pypi_upstream_custom_index_no_dedup_for_non_simple_prefix() {
        // Even if the upstream URL ends in "/simple", the de-dup logic is
        // skipped when index_path != "simple". The URL is used as-is.
        let (url, path) =
            pypi_upstream_url_and_path("https://mirror.corp/simple", "numpy/", "packages");
        assert_eq!(url, "https://mirror.corp/simple");
        assert_eq!(path, "packages/numpy/");
    }

    // -----------------------------------------------------------------------
    // normalize_pep503
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_pep503_lowercase() {
        assert_eq!(normalize_pep503("MyPackage"), "mypackage");
    }

    #[test]
    fn test_normalize_pep503_underscores_to_hyphen() {
        assert_eq!(normalize_pep503("my_package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_dots_to_hyphen() {
        assert_eq!(normalize_pep503("my.package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_mixed_separators() {
        assert_eq!(normalize_pep503("My_Package.Name"), "my-package-name");
    }

    #[test]
    fn test_normalize_pep503_consecutive_separators() {
        assert_eq!(normalize_pep503("my__package"), "my-package");
        assert_eq!(normalize_pep503("my_._package"), "my-package");
        assert_eq!(normalize_pep503("my--package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_already_normalized() {
        assert_eq!(normalize_pep503("my-package"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_trailing_separator() {
        assert_eq!(normalize_pep503("my-package_"), "my-package");
    }

    #[test]
    fn test_normalize_pep503_leading_separator() {
        // Leading separators are collapsed and skipped
        assert_eq!(normalize_pep503("_mypackage"), "mypackage");
    }

    #[test]
    fn test_normalize_pep503_real_world_names() {
        assert_eq!(normalize_pep503("Jinja2"), "jinja2");
        assert_eq!(normalize_pep503("zope.interface"), "zope-interface");
        assert_eq!(normalize_pep503("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(
            normalize_pep503("backports.ssl_match_hostname"),
            "backports-ssl-match-hostname"
        );
    }

    // -----------------------------------------------------------------------
    // html_escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_html_escape_no_special_chars() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn test_html_escape_ampersand() {
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn test_html_escape_less_than() {
        assert_eq!(html_escape("a < b"), "a &lt; b");
    }

    #[test]
    fn test_html_escape_greater_than() {
        assert_eq!(html_escape("a > b"), "a &gt; b");
    }

    #[test]
    fn test_html_escape_quotes() {
        assert_eq!(html_escape("a \"b\" c"), "a &quot;b&quot; c");
    }

    #[test]
    fn test_html_escape_apostrophe() {
        assert_eq!(html_escape("O'Reilly"), "O&#39;Reilly");
        assert_eq!(
            html_escape("' onload='alert(1)"),
            "&#39; onload=&#39;alert(1)"
        );
    }

    #[test]
    fn test_html_escape_all_special() {
        assert_eq!(
            html_escape("<script>alert(\"x&y\")</script>"),
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_html_escape_requires_python_version() {
        assert_eq!(html_escape(">=3.7"), "&gt;=3.7");
        assert_eq!(html_escape(">=3.7,<4.0"), "&gt;=3.7,&lt;4.0");
    }

    // -----------------------------------------------------------------------
    // rewrite_upstream_urls
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_absolute_url_with_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/ab/cd/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_absolute_url_without_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_rewrites_relative_urls() {
        // Relative URLs should now be rewritten to local proxy paths
        // (previously these were left unchanged, which broke Nexus/devpi remotes)
        let html = r#"<a href="numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert!(result
            .contains(r#"href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123""#));
    }

    #[test]
    fn test_rewrite_multiple_links() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=aaa">numpy-1.3.0.tar.gz</a><br/>"#,
            "\n",
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl#sha256=bbb">numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl</a><br/>"#,
        );
        let result = rewrite_upstream_urls(html, "my-pypi", "numpy");
        assert!(
            result.contains(r#"href="/pypi/my-pypi/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa""#)
        );
        assert!(result.contains(
            r#"href="/pypi/my-pypi/simple/numpy/numpy-1.4.0-cp39-cp39-manylinux1_x86_64.whl#sha256=bbb""#
        ));
    }

    #[test]
    fn test_rewrite_normalizes_project_name() {
        let html = r#"<a href="https://example.com/My_Package-1.0.tar.gz#sha256=abc">My_Package-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "My_Package");
        assert!(result.contains(
            r#"href="/pypi/pypi-remote/simple/my-package/My_Package-1.0.tar.gz#sha256=abc""#
        ));
    }

    #[test]
    fn test_rewrite_http_url() {
        let html = r#"<a href="http://example.com/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(
            result,
            r#"<a href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_preserves_data_attributes() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=abc" data-requires-python="&gt;=3.7">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert!(result
            .contains(r#"href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc""#));
        assert!(result.contains(r#"data-requires-python="&gt;=3.7""#));
    }

    #[test]
    fn test_rewrite_no_links() {
        let html = "<html><body><h1>No links here</h1></body></html>";
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(result, html);
    }

    #[test]
    fn test_rewrite_empty_string() {
        let result = rewrite_upstream_urls("", "repo", "pkg");
        assert_eq!(result, "");
    }

    #[test]
    fn test_rewrite_full_simple_index_page() {
        let html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.0"/><title>Links for numpy</title></head>
<body>
<h1>Links for numpy</h1>
<a href="https://files.pythonhosted.org/packages/3e/ee/numpy-1.3.0.tar.gz#sha256=aaa111" >numpy-1.3.0.tar.gz</a><br/>
<a href="https://files.pythonhosted.org/packages/c5/63/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=bbb222" data-requires-python="&gt;=3.9">numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl</a><br/>
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "pypi-public", "numpy");

        // Absolute URLs should be rewritten
        assert!(!result.contains("files.pythonhosted.org"));
        assert!(result
            .contains(r#"href="/pypi/pypi-public/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa111""#));
        assert!(result.contains(
            r#"href="/pypi/pypi-public/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=bbb222""#
        ));

        // data-requires-python should be preserved
        assert!(result.contains("data-requires-python"));

        // Non-link content should be preserved
        assert!(result.contains("<h1>Links for numpy</h1>"));
        assert!(result.contains("pypi:repository-version"));
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_relative() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/pkg-1.0.tar.gz#sha256=aaa">pkg-1.0.tar.gz</a>"#,
            "\n",
            r#"<a href="pkg-2.0.tar.gz#sha256=bbb">pkg-2.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        // Absolute URL is rewritten
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#sha256=aaa""#));
        // Relative URL is now also rewritten (needed for Nexus/devpi remotes)
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-2.0.tar.gz#sha256=bbb""#));
    }

    #[test]
    fn test_rewrite_url_with_deep_path() {
        // URLs from real PyPI have deep paths like /packages/3e/ee/ab/...
        let html = r#"<a href="https://files.pythonhosted.org/packages/3e/ee/ab/cd/ef/numpy-1.3.0.tar.gz#sha256=abc">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "numpy");
        assert!(result.contains(r#"href="/pypi/repo/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc""#));
    }

    #[test]
    fn test_rewrite_preserves_md5_fragment() {
        let html =
            r#"<a href="https://example.com/pkg-1.0.tar.gz#md5=deadbeef">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#md5=deadbeef""#));
    }

    #[test]
    fn test_rewrite_local_upstream_root_relative_url() {
        // When a remote repo proxies a local AK repo, the simple index contains
        // root-relative paths like /pypi/upstream-key/simple/pkg/file#hash
        let html = r#"<a href="/pypi/upstream-local/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#
        );
    }

    #[test]
    fn test_rewrite_local_upstream_without_hash() {
        let html = r#"<a href="/pypi/upstream-local/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "remote-repo", "pkg");
        assert_eq!(
            result,
            r#"<a href="/pypi/remote-repo/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a>"#
        );
    }

    #[test]
    fn test_rewrite_local_upstream_with_data_attr() {
        let html = r#"<a href="/pypi/upstream/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl#sha256=bbb" data-requires-python="&gt;=3.9">numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl</a>"#;
        let result = rewrite_upstream_urls(html, "my-remote", "numpy");
        assert!(result.contains(
            r#"href="/pypi/my-remote/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl#sha256=bbb""#
        ));
        assert!(result.contains(r#"data-requires-python="&gt;=3.9""#));
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_local_relative() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz#sha256=aaa">numpy-1.3.0.tar.gz</a>"#,
            "\n",
            r#"<a href="/pypi/local-repo/simple/numpy/numpy-2.0.0.tar.gz#sha256=bbb">numpy-2.0.0.tar.gz</a>"#,
            "\n",
            r#"<a href="numpy-3.0.0.tar.gz#sha256=ccc">numpy-3.0.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "remote", "numpy");
        // Absolute URL is rewritten
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=aaa""#)
        );
        // Root-relative /pypi/ URL is rewritten
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-2.0.0.tar.gz#sha256=bbb""#)
        );
        // Plain relative URL is now also rewritten (needed for Nexus/devpi)
        assert!(
            result.contains(r#"href="/pypi/remote/simple/numpy/numpy-3.0.0.tar.gz#sha256=ccc""#)
        );
    }

    #[test]
    fn test_rewrite_full_local_upstream_index() {
        // Simulates the full HTML generated by a local AK PyPI repo
        let html = r#"<!DOCTYPE html>
<html>
<head>
<meta name="pypi:repository-version" content="1.0"/>
<title>Links for mypackage</title>
</head>
<body>
<h1>Links for mypackage</h1>
<a href="/pypi/local-pypi/simple/mypackage/mypackage-1.0.0.tar.gz#sha256=aaa111">mypackage-1.0.0.tar.gz</a><br/>
<a href="/pypi/local-pypi/simple/mypackage/mypackage-1.0.0-py3-none-any.whl#sha256=bbb222" data-requires-python="&gt;=3.8">mypackage-1.0.0-py3-none-any.whl</a><br/>
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "remote-pypi", "mypackage");

        // Local upstream URLs should be rewritten to use the remote repo key
        assert!(!result.contains("local-pypi"));
        assert!(result.contains(
            r#"href="/pypi/remote-pypi/simple/mypackage/mypackage-1.0.0.tar.gz#sha256=aaa111""#
        ));
        assert!(result.contains(
            r#"href="/pypi/remote-pypi/simple/mypackage/mypackage-1.0.0-py3-none-any.whl#sha256=bbb222""#
        ));

        // data-requires-python and other structure should be preserved
        assert!(result.contains("data-requires-python"));
        assert!(result.contains("<h1>Links for mypackage</h1>"));
    }

    #[test]
    fn test_rewrite_strips_data_dist_info_metadata() {
        // Real PyPI HTML includes data-dist-info-metadata on .whl links.
        // The proxy cannot serve .metadata files, so these attributes must
        // be stripped to prevent pip from requesting them and getting 404.
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=8abb" data-requires-python="&gt;=2.7" data-dist-info-metadata="sha256=5507" data-core-metadata="sha256=5507">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-proxy", "six");
        assert!(result.contains(
            r#"href="/pypi/pypi-proxy/simple/six/six-1.16.0-py2.py3-none-any.whl#sha256=8abb""#
        ));
        // data-requires-python should be preserved
        assert!(result.contains(r#"data-requires-python="&gt;=2.7""#));
        // PEP 658 metadata attributes must be stripped
        assert!(!result.contains("data-dist-info-metadata"));
        assert!(!result.contains("data-core-metadata"));
    }

    #[test]
    fn test_rewrite_strips_metadata_attrs_from_real_pypi_html() {
        // Simulates the actual HTML returned by pypi.org for the `six` package
        let html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.4"><title>Links for six</title></head>
<body>
<h1>Links for six</h1>
<a href="https://files.pythonhosted.org/packages/b7/ce/six-1.17.0-py2.py3-none-any.whl#sha256=4721" data-requires-python="!=3.0.*,!=3.1.*,!=3.2.*,&gt;=2.7" data-dist-info-metadata="sha256=5620" data-core-metadata="sha256=5620">six-1.17.0-py2.py3-none-any.whl</a><br />
<a href="https://files.pythonhosted.org/packages/94/e7/six-1.17.0.tar.gz#sha256=ff70" data-requires-python="!=3.0.*,!=3.1.*,!=3.2.*,&gt;=2.7" >six-1.17.0.tar.gz</a><br />
</body>
</html>
"#;
        let result = rewrite_upstream_urls(html, "pypi-proxy", "six");

        // URLs should be rewritten
        assert!(!result.contains("files.pythonhosted.org"));
        assert!(result.contains(
            r#"href="/pypi/pypi-proxy/simple/six/six-1.17.0-py2.py3-none-any.whl#sha256=4721""#
        ));
        assert!(
            result.contains(r#"href="/pypi/pypi-proxy/simple/six/six-1.17.0.tar.gz#sha256=ff70""#)
        );

        // data-requires-python should be preserved on both links
        assert!(result.contains("data-requires-python"));

        // PEP 658 metadata attributes must be stripped from the .whl link
        assert!(!result.contains("data-dist-info-metadata"));
        assert!(!result.contains("data-core-metadata"));

        // Structure should be preserved
        assert!(result.contains("<h1>Links for six</h1>"));
    }

    // -----------------------------------------------------------------------
    // PEP 691 JSON proxy: upstream URL rewriting + upload-time preservation
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_upstream_simple_json_rewrites_urls_preserves_upload_time_strips_metadata() {
        // Shape mirrors a real pypi.org PEP 691 JSON file object.
        let upstream = r#"{
            "meta": {"api-version": "1.1"},
            "name": "requests",
            "versions": ["2.31.0"],
            "files": [
                {
                    "filename": "requests-2.31.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.31.0-py3-none-any.whl",
                    "hashes": {"sha256": "deadbeef"},
                    "requires-python": ">=3.7",
                    "size": 62574,
                    "upload-time": "2023-05-22T15:12:42.313790Z",
                    "core-metadata": {"sha256": "abc"},
                    "data-dist-info-metadata": {"sha256": "abc"}
                }
            ]
        }"#;
        let out =
            rewrite_upstream_simple_json(upstream.as_bytes(), "pypi-proxy", "requests").unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let file = &json["files"][0];

        // Download URL routes through the proxy, not the upstream CDN.
        assert_eq!(
            file["url"],
            "/pypi/pypi-proxy/simple/requests/requests-2.31.0-py3-none-any.whl"
        );
        assert!(!out.contains("files.pythonhosted.org"));

        // PEP 700 upload-time (the whole point) plus size/hashes/requires-python preserved.
        assert_eq!(file["upload-time"], "2023-05-22T15:12:42.313790Z");
        assert_eq!(file["size"], 62574);
        assert_eq!(file["hashes"]["sha256"], "deadbeef");
        assert_eq!(file["requires-python"], ">=3.7");

        // PEP 658/714 metadata signals stripped — the proxy can't serve `.metadata`.
        assert!(file.get("core-metadata").is_none());
        assert!(file.get("data-dist-info-metadata").is_none());
    }

    #[test]
    fn test_rewrite_upstream_simple_json_returns_none_for_non_json() {
        assert!(rewrite_upstream_simple_json(b"<!DOCTYPE html><html></html>", "r", "p").is_none());
    }

    #[test]
    fn test_merge_local_into_remote_simple_json_appends_local_and_unions_versions() {
        let upstream = r#"{
            "meta": {"api-version": "1.1"},
            "name": "mypkg",
            "versions": ["1.0.0"],
            "files": [
                {"filename": "mypkg-1.0.0-py3-none-any.whl",
                 "url": "https://files.pythonhosted.org/packages/aa/mypkg-1.0.0-py3-none-any.whl",
                 "hashes": {"sha256": "remotehash"}, "size": 100}
            ]
        }"#;
        let upload_time = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let local = vec![SimpleProjectArtifact {
            path: "packages/mypkg-2.0.0-py3-none-any.whl".to_string(),
            version: Some("2.0.0".to_string()),
            size_bytes: 222,
            checksum_sha256: "localhash".to_string(),
            metadata: None,
            upload_time: Some(upload_time),
        }];

        let out = merge_local_into_remote_simple_json(
            upstream.as_bytes(),
            "pypi-proxy",
            "mypkg",
            &local,
            &[],
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();

        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 2, "remote rewritten + local appended");

        // Upstream entry rewritten through the proxy.
        let remote_file = files
            .iter()
            .find(|f| f["filename"] == "mypkg-1.0.0-py3-none-any.whl")
            .unwrap();
        assert_eq!(
            remote_file["url"],
            "/pypi/pypi-proxy/simple/mypkg/mypkg-1.0.0-py3-none-any.whl"
        );

        // Local entry appended with upload-time + size + hash.
        let local_file = files
            .iter()
            .find(|f| f["filename"] == "mypkg-2.0.0-py3-none-any.whl")
            .unwrap();
        assert_eq!(
            local_file["url"],
            "/pypi/pypi-proxy/simple/mypkg/mypkg-2.0.0-py3-none-any.whl"
        );
        assert_eq!(local_file["hashes"]["sha256"], "localhash");
        assert_eq!(local_file["size"], 222);
        assert_eq!(local_file["upload-time"], "2026-01-02T03:04:05Z");

        // Versions unioned across members.
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(versions.contains(&"1.0.0"));
        assert!(versions.contains(&"2.0.0"));
    }

    #[test]
    fn test_merge_local_into_remote_simple_json_skips_filename_already_upstream() {
        let upstream = r#"{"meta":{"api-version":"1.1"},"name":"p","versions":["1.0.0"],
            "files":[{"filename":"p-1.0.0.tar.gz","url":"https://x/p-1.0.0.tar.gz","hashes":{"sha256":"r"}}]}"#;
        let local = vec![SimpleProjectArtifact {
            path: "p-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 1,
            checksum_sha256: "l".to_string(),
            metadata: None,
            upload_time: None,
        }];
        let out = merge_local_into_remote_simple_json(upstream.as_bytes(), "v", "p", &local, &[])
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            json["files"].as_array().unwrap().len(),
            1,
            "filename already upstream must not be duplicated"
        );
    }

    #[test]
    fn test_merge_local_into_remote_simple_json_includes_requires_python_and_tracks() {
        let upstream = r#"{"meta":{"api-version":"1.1"},"name":"pkg","versions":[],"files":[]}"#;
        let metadata = serde_json::json!({"pkg_info": {"requires_python": ">=3.9"}});
        let local = vec![SimpleProjectArtifact {
            path: "pkg-1.2.3-py3-none-any.whl".to_string(),
            version: Some("1.2.3".to_string()),
            size_bytes: 9,
            checksum_sha256: "h".to_string(),
            metadata: Some(metadata),
            upload_time: None,
        }];
        let tracks = vec!["https://pypi.org/simple/pkg/".to_string()];

        let out =
            merge_local_into_remote_simple_json(upstream.as_bytes(), "v", "pkg", &local, &tracks)
                .unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();

        // requires-python carried over from pkg_info metadata; no upload-time emitted.
        assert_eq!(json["files"][0]["requires-python"], ">=3.9");
        assert!(json["files"][0].get("upload-time").is_none());

        // PEP 708 tracks surfaced under meta.tracks.
        let meta_tracks: Vec<&str> = json["meta"]["tracks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(meta_tracks, vec!["https://pypi.org/simple/pkg/"]);
    }

    #[test]
    fn test_rewrite_strips_metadata_attr_before_href() {
        // Edge case: metadata attribute appears before href
        let html = r#"<a data-dist-info-metadata="sha256=abc" href="https://example.com/pkg-1.0.whl#sha256=def">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=def""#));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_preserves_non_metadata_attrs() {
        // Only PEP 658 attrs should be stripped; other data-* attrs remain
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=abc" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=def" data-gpg-sig="true">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains("data-requires-python"));
        assert!(result.contains("data-gpg-sig"));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_relative_dotdot_href() {
        // Nexus-style relative href should be rewritten to local proxy path
        let html = r#"<a href="../../packages/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "requests");
        assert!(result.contains(
            r#"href="/pypi/pypi-remote/simple/requests/requests-2.31.0.tar.gz#sha256=abc""#
        ));
    }

    #[test]
    fn test_rewrite_root_relative_href() {
        // Root-relative href (/packages/...) should also be rewritten
        let html =
            r#"<a href="/packages/ab/cd/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "six");
        assert!(result.contains(r#"href="/pypi/repo/simple/six/six-1.16.0.tar.gz#sha256=abc""#));
    }

    #[test]
    fn test_rewrite_plain_relative_href() {
        // Plain relative href (packages/file.tar.gz) from devpi
        let html = r#"<a href="packages/pkg-1.0.tar.gz#sha256=abc">pkg-1.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "devpi-remote", "pkg");
        assert!(
            result.contains(r#"href="/pypi/devpi-remote/simple/pkg/pkg-1.0.tar.gz#sha256=abc""#)
        );
    }

    #[test]
    fn test_rewrite_mixed_absolute_and_relative_hrefs() {
        let html = concat!(
            r#"<a href="https://files.example.com/pkg-1.0.whl#sha256=aaa">pkg-1.0.whl</a>"#,
            "\n",
            r#"<a href="../../packages/pkg-1.0.tar.gz#sha256=bbb">pkg-1.0.tar.gz</a>"#,
        );
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        // Both should be rewritten to local proxy paths
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=aaa""#));
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz#sha256=bbb""#));
    }

    // -----------------------------------------------------------------------
    // find_upstream_url_for_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_upstream_url_basic() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=abc">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_no_match() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.15.0.tar.gz", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_relative_ignored_without_index_url() {
        // Relative URLs cannot be resolved without an index URL
        let html = r#"<a href="/pypi/local/simple/six/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_multiple_files() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/a/six-1.15.0.tar.gz#sha256=aaa">six-1.15.0.tar.gz</a>"#,
            "\n",
            r#"<a href="https://files.pythonhosted.org/packages/b/six-1.16.0-py2.py3-none-any.whl#sha256=bbb">six-1.16.0-py2.py3-none-any.whl</a>"#,
        );
        let result = find_upstream_url_for_file(html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/b/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_with_data_attrs() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-2.0.0.whl#sha256=abc" data-requires-python="&gt;=3.9">numpy-2.0.0.whl</a>"#;
        let result = find_upstream_url_for_file(html, "numpy-2.0.0.whl", None);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/numpy-2.0.0.whl".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_raw_index_has_absolute_urls() {
        // Simulates a real upstream simple index from pypi.org.
        // find_upstream_url_for_file must find the correct absolute URL
        // when given the raw (un-rewritten) upstream HTML.
        let raw_upstream_html = r#"<!DOCTYPE html>
<html>
<head><meta name="pypi:repository-version" content="1.0"/><title>Links for six</title></head>
<body>
<h1>Links for six</h1>
<a href="https://files.pythonhosted.org/packages/71/39/six-1.16.0-py2.py3-none-any.whl#sha256=8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254">six-1.16.0-py2.py3-none-any.whl</a><br/>
<a href="https://files.pythonhosted.org/packages/94/e7/six-1.16.0.tar.gz#sha256=1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926">six-1.16.0.tar.gz</a><br/>
</body>
</html>
"#;
        let result =
            find_upstream_url_for_file(raw_upstream_html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/71/39/six-1.16.0-py2.py3-none-any.whl"
                    .to_string()
            )
        );

        let result = find_upstream_url_for_file(raw_upstream_html, "six-1.16.0.tar.gz", None);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/94/e7/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_fails_on_rewritten_html() {
        // After rewrite_upstream_urls(), all absolute URLs become local
        // /pypi/... paths. Without an index_url, these cannot be resolved.
        let rewritten_html = r#"<!DOCTYPE html>
<html>
<head><title>Links for six</title></head>
<body>
<a href="/pypi/pypi-proxy/simple/six/six-1.16.0-py2.py3-none-any.whl#sha256=8abb">six-1.16.0-py2.py3-none-any.whl</a><br/>
<a href="/pypi/pypi-proxy/simple/six/six-1.16.0.tar.gz#sha256=1e61">six-1.16.0.tar.gz</a><br/>
</body>
</html>
"#;
        let result =
            find_upstream_url_for_file(rewritten_html, "six-1.16.0-py2.py3-none-any.whl", None);
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // find_upstream_url_for_file - relative URL resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_upstream_url_relative_dotdot_path() {
        // Nexus-style relative href with ../../ prefix.
        // Base: /repository/pypi/simple/requests/
        //   ../ => /repository/pypi/simple/
        //   ../ => /repository/pypi/
        //   packages/... => /repository/pypi/packages/requests-2.31.0.tar.gz
        let html = r#"<a href="../../packages/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/requests/";
        let result = find_upstream_url_for_file(html, "requests-2.31.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://nexus.example.com/repository/pypi/packages/requests-2.31.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_plain_path() {
        // Simple relative path without ../ prefix
        let html = r#"<a href="packages/pkg-1.0.tar.gz#sha256=abc">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://devpi.local/root/pypi/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://devpi.local/root/pypi/simple/pkg/packages/pkg-1.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_root_relative_path() {
        // Root-relative path starting with /
        let html =
            r#"<a href="/packages/ab/cd/six-1.16.0.tar.gz#sha256=abc">six-1.16.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/six/";
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://nexus.example.com/packages/ab/cd/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_relative_multiple_dotdot() {
        // Multiple levels of ../ traversal (Artifactory-style deep paths).
        // Base: /api/pypi/pypi-remote/simple/numpy/
        //   ../  => /api/pypi/pypi-remote/simple/
        //   ../  => /api/pypi/pypi-remote/
        //   ../  => /api/pypi/
        //   packages/... => /api/pypi/packages/numpy/1.24.0/numpy-1.24.0.tar.gz
        let html = r#"<a href="../../../packages/numpy/1.24.0/numpy-1.24.0.tar.gz#sha256=abc">numpy-1.24.0.tar.gz</a>"#;
        let index_url = "https://artifactory.corp.com/api/pypi/pypi-remote/simple/numpy/";
        let result = find_upstream_url_for_file(html, "numpy-1.24.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://artifactory.corp.com/api/pypi/packages/numpy/1.24.0/numpy-1.24.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_prefers_absolute_first() {
        // When both absolute and relative URLs exist, the first match wins.
        // Absolute URLs are found and returned without needing resolution.
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/six-1.16.0.tar.gz#sha256=aaa">six-1.16.0.tar.gz</a>"#,
            "\n",
            r#"<a href="../../packages/six-1.16.0.tar.gz#sha256=bbb">six-1.16.0.tar.gz</a>"#,
        );
        let index_url = "https://nexus.example.com/repository/pypi/simple/six/";
        let result = find_upstream_url_for_file(html, "six-1.16.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/six-1.16.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_upstream_url_nexus_full_index() {
        // Simulates a real Nexus simple index page with relative hrefs.
        // ../../ from /repository/pypi/simple/requests/ resolves to
        // /repository/pypi/ so the final path is
        // /repository/pypi/packages/requests/2.31.0/requests-2.31.0.tar.gz
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Links for requests</title></head>
<body>
<h1>Links for requests</h1>
<a href="../../packages/requests/2.31.0/requests-2.31.0-py3-none-any.whl#sha256=aaa">requests-2.31.0-py3-none-any.whl</a><br/>
<a href="../../packages/requests/2.31.0/requests-2.31.0.tar.gz#sha256=bbb">requests-2.31.0.tar.gz</a><br/>
<a href="../../packages/requests/2.32.0/requests-2.32.0-py3-none-any.whl#sha256=ccc">requests-2.32.0-py3-none-any.whl</a><br/>
</body>
</html>
"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/requests/";
        let result = find_upstream_url_for_file(html, "requests-2.31.0.tar.gz", Some(index_url));
        assert_eq!(
            result,
            Some(
                "https://nexus.example.com/repository/pypi/packages/requests/2.31.0/requests-2.31.0.tar.gz"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_upstream_url_relative_no_match() {
        // Relative URLs present but no filename match
        let html = r#"<a href="../../packages/other-1.0.tar.gz#sha256=abc">other-1.0.tar.gz</a>"#;
        let index_url = "https://nexus.example.com/repository/pypi/simple/other/";
        let result = find_upstream_url_for_file(html, "nonexistent-1.0.tar.gz", Some(index_url));
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_rejects_javascript_scheme() {
        let html = r#"<a href="javascript:fetch('http://internal/secret')/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://registry.example.com/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        // javascript: hrefs must not produce a fetchable URL
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_upstream_url_rejects_data_scheme() {
        let html = r#"<a href="data:application/octet-stream;base64,abc/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a>"#;
        let index_url = "https://registry.example.com/simple/pkg/";
        let result = find_upstream_url_for_file(html, "pkg-1.0.tar.gz", Some(index_url));
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // extract_metadata_from_wheel
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_metadata_from_wheel_with_valid_wheel() {
        // Create a minimal valid zip with a METADATA file inside .dist-info
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("mypackage-1.0.dist-info/METADATA", options)
            .unwrap();
        std::io::Write::write_all(
            &mut writer,
            b"Metadata-Version: 2.1\nName: mypackage\nVersion: 1.0\n",
        )
        .unwrap();
        let cursor = writer.finish().unwrap();
        let content = cursor.into_inner();

        let result = extract_metadata_from_wheel(&content);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Metadata-Version: 2.1"));
        assert!(text.contains("Name: mypackage"));
    }

    #[test]
    fn test_extract_metadata_from_wheel_no_metadata_file() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("some-other-file.txt", options).unwrap();
        std::io::Write::write_all(&mut writer, b"no metadata here").unwrap();
        let cursor = writer.finish().unwrap();
        let content = cursor.into_inner();

        let result = extract_metadata_from_wheel(&content);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_metadata_from_wheel_invalid_zip() {
        let content = b"not a zip file at all";
        let result = extract_metadata_from_wheel(content);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_metadata_from_sdist
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_metadata_from_sdist_with_pkg_info() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        // Build a tar.gz with a PKG-INFO file
        let mut tar_builder = tar::Builder::new(Vec::new());
        let pkg_info = b"Metadata-Version: 1.0\nName: mypackage\nVersion: 1.0\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("mypackage-1.0/PKG-INFO").unwrap();
        header.set_size(pkg_info.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &pkg_info[..]).unwrap();
        let tar_data = tar_builder.into_inner().unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let gz_data = gz.finish().unwrap();

        let result = extract_metadata_from_sdist(&gz_data);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Name: mypackage"));
    }

    #[test]
    fn test_extract_metadata_from_sdist_no_pkg_info() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut tar_builder = tar::Builder::new(Vec::new());
        let data = b"some other file content";
        let mut header = tar::Header::new_gnu();
        header.set_path("mypackage-1.0/setup.py").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &data[..]).unwrap();
        let tar_data = tar_builder.into_inner().unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let gz_data = gz.finish().unwrap();

        let result = extract_metadata_from_sdist(&gz_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_metadata_from_sdist_invalid_data() {
        let result = extract_metadata_from_sdist(b"not a tar.gz");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // build_streaming_file_response
    // -----------------------------------------------------------------------

    /// Wrap static bytes in a one-shot [`StreamingFetchResult`] for header
    /// tests, with `content_length` advertised only when `len` is `Some`.
    fn streaming_result_with(
        content: &'static [u8],
        len: Option<u64>,
    ) -> crate::services::proxy_service::StreamingFetchResult {
        crate::services::proxy_service::StreamingFetchResult {
            body: futures::stream::once(async move { Ok(Bytes::from_static(content)) }).boxed(),
            content_type: None,
            content_length: len,
        }
    }

    #[test]
    fn test_build_streaming_file_response_wheel_content_type() {
        let resp = build_streaming_file_response(
            "numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl",
            streaming_result_with(b"fake wheel data", Some(15)),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/zip");
        assert_eq!(resp.headers().get(CONTENT_LENGTH).unwrap(), "15");
        assert_eq!(
            resp.headers().get("Content-Disposition").unwrap(),
            "attachment; filename=\"numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl\""
        );
    }

    #[test]
    fn test_build_streaming_file_response_sdist_content_type() {
        let resp = build_streaming_file_response(
            "six-1.16.0.tar.gz",
            streaming_result_with(b"fake sdist data", Some(15)),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
    }

    #[test]
    fn test_build_streaming_file_response_zip_extension() {
        let resp = build_streaming_file_response(
            "package-1.0.zip",
            streaming_result_with(b"some data", Some(9)),
        );
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "application/zip");
    }

    #[test]
    fn test_build_streaming_file_response_unknown_extension() {
        let resp = build_streaming_file_response(
            "package-1.0.egg",
            streaming_result_with(b"some data", Some(9)),
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_build_streaming_file_response_unknown_length_omits_content_length() {
        // No advertised length -> no Content-Length header; axum falls back
        // to chunked transfer encoding for the streamed body.
        let resp = build_streaming_file_response(
            "package-1.0.whl",
            streaming_result_with(b"some data", None),
        );
        assert!(resp.headers().get(CONTENT_LENGTH).is_none());
    }

    #[test]
    fn test_build_streaming_file_response_content_disposition() {
        let resp = build_streaming_file_response(
            "requests-2.31.0.tar.gz",
            streaming_result_with(b"data", Some(4)),
        );
        assert_eq!(
            resp.headers().get("Content-Disposition").unwrap(),
            "attachment; filename=\"requests-2.31.0.tar.gz\""
        );
    }

    #[test]
    fn test_build_streaming_file_response_content_length() {
        let data = b"hello world data here";
        let resp = build_streaming_file_response(
            "pkg-1.0.tar.gz",
            streaming_result_with(data, Some(data.len() as u64)),
        );
        assert_eq!(
            resp.headers().get(CONTENT_LENGTH).unwrap(),
            &data.len().to_string()
        );
    }

    // -----------------------------------------------------------------------
    // get_remote_cached_or_refetch
    // -----------------------------------------------------------------------

    /// Drain a `get_remote_cached_or_refetch_stream` body into a single `Bytes`
    /// so the existing buffered-semantics assertions still hold against the
    /// streaming implementation.
    async fn collect_stream(stream: BoxStream<'static, Result<Bytes, std::io::Error>>) -> Bytes {
        let mut s = stream;
        let mut buf = Vec::new();
        while let Some(chunk) = s.next().await {
            buf.extend_from_slice(&chunk.expect("stream chunk"));
        }
        Bytes::from(buf)
    }

    /// Wrap static bytes as a one-shot [`StreamingFetchResult`] so the recovery
    /// tests can drive the streaming refetch closure (#2192).
    fn one_shot_result(
        content: &'static [u8],
    ) -> crate::services::proxy_service::StreamingFetchResult {
        crate::services::proxy_service::StreamingFetchResult {
            body: futures::stream::once(async move { Ok(Bytes::from_static(content)) }).boxed(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(content.len() as u64),
        }
    }

    /// Storage double that reports the entry as missing on every `get`, and
    /// records every `put` so tests can assert the write-back path persists
    /// refetched payloads (PR #1283 follow-up: thundering-herd fix).
    struct MissingStorage {
        puts: std::sync::Mutex<Vec<(String, Bytes)>>,
    }

    impl MissingStorage {
        fn new() -> Self {
            Self {
                puts: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for MissingStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.puts
                .lock()
                .expect("puts mutex")
                .push((key.to_string(), content));
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Err(AppError::NotFound("missing cache entry".to_string()))
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// Returns the configured bytes for any `get` call, simulating a healthy
    /// proxy-cache hit on disk.
    struct PresentStorage {
        bytes: Bytes,
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for PresentStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(self.bytes.clone())
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// Returns a non-`NotFound` storage error for every `get`, simulating an
    /// underlying backend failure (permissions, I/O, etc.) that should NOT be
    /// silently swallowed as a stale-cache miss.
    struct BrokenStorage;

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for BrokenStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Err(AppError::Storage("permission denied".to_string()))
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_refetches_on_missing_storage() {
        // Streaming refetch path is DB-free (storage doubles only), so this runs
        // in Tier-1 `cargo test --lib` without a live Postgres.
        let storage = std::sync::Arc::new(MissingStorage::new());
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let storage_key =
            "proxy-cache/pypi-remote/simple/fastapi/fastapi-0.136.1-py3-none-any.whl/__content__";
        let stream =
            super::get_remote_cached_or_refetch_stream(storage.clone(), storage_key, move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"refetched-bytes"))
                }
            })
            .await
            .expect("refetch should succeed");
        let content = collect_stream(stream).await;

        assert_eq!(content, Bytes::from_static(b"refetched-bytes"));
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "missing proxy-cache entry should trigger exactly one upstream refetch"
        );

        // PR #1283 thundering-herd fix: the refetched payload MUST be written
        // back to storage under the same key, so the next caller hits the
        // cache instead of re-traversing the simple index and re-downloading
        // from upstream.
        let puts = storage.puts.lock().expect("puts mutex");
        assert_eq!(
            puts.len(),
            1,
            "refetched payload must be persisted exactly once for the next request"
        );
        assert_eq!(puts[0].0, storage_key);
        assert_eq!(puts[0].1, Bytes::from_static(b"refetched-bytes"));
    }

    /// Storage double whose `put` always fails. The handler must still
    /// successfully serve the refetched bytes to the current caller; a
    /// broken write-back is observability noise, not a fatal error for
    /// this request.
    struct WriteFailingStorage;

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for WriteFailingStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Err(AppError::Storage("disk full".to_string()))
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Err(AppError::NotFound("missing cache entry".to_string()))
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_serves_payload_even_if_writeback_fails() {
        // A best-effort write-back must NOT fail the current request. If the
        // disk is full or read-only the user still gets their wheel; the
        // next request will simply re-fetch from upstream until the backend
        // recovers.
        let storage = std::sync::Arc::new(WriteFailingStorage);
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/urllib3/urllib3-2.2.0-py3-none-any.whl/__content__",
            move || async move { Ok(one_shot_result(b"refetched-when-disk-full")) },
        )
        .await
        .expect("write-back failures must not fail the current request");
        let content = collect_stream(stream).await;

        assert_eq!(content, Bytes::from_static(b"refetched-when-disk-full"));
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_returns_cached_without_refetch() {
        // Happy path: cache hits should return the stored bytes verbatim and
        // must NEVER invoke the upstream refetch closure.
        let storage = std::sync::Arc::new(PresentStorage {
            bytes: Bytes::from_static(b"cached-wheel-bytes"),
        });
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/numpy/numpy-2.0.0-cp312-cp312-manylinux.whl/__content__",
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"should-not-be-used"))
                }
            },
        )
        .await
        .expect("cached read should succeed");
        let content = collect_stream(stream).await;

        assert_eq!(content, Bytes::from_static(b"cached-wheel-bytes"));
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a healthy cache hit must not trigger an upstream refetch"
        );
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_propagates_non_notfound_storage_error() {
        // A storage backend error that is NOT `NotFound` (e.g. permission
        // denied, I/O error) must be surfaced as a 500 instead of silently
        // re-fetching, otherwise we mask infra issues from operators.
        let storage = std::sync::Arc::new(BrokenStorage);
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let result = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/six/six-1.16.0.tar.gz/__content__",
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"never-reached"))
                }
            },
        )
        .await;

        // The Ok arm carries a BoxStream (not Debug), so match instead of
        // `expect_err` to extract the error Response.
        let response = match result {
            Ok(_) => panic!("non-NotFound storage errors must propagate"),
            Err(resp) => resp,
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "non-NotFound storage errors must not trigger a refetch"
        );
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_surfaces_refetch_failure() {
        // When the cache is stale AND the upstream refetch also fails, the
        // upstream error response must reach the caller untouched so the
        // client sees the correct upstream status (e.g. 502).
        let storage = std::sync::Arc::new(MissingStorage::new());
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let result = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/requests/requests-2.32.0-py3-none-any.whl/__content__",
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(AppError::BadGateway("upstream timed out".to_string()).into_response())
                }
            },
        )
        .await;

        // The Ok arm carries a BoxStream (not Debug), so match instead of
        // `expect_err` to extract the error Response.
        let response = match result {
            Ok(_) => panic!("refetch failures must propagate to caller"),
            Err(resp) => resp,
        };
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "stale-cache miss must attempt exactly one refetch even if it fails"
        );
    }

    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_preserves_empty_cached_payload() {
        // Edge case: a legitimately empty cached payload (zero bytes) is
        // still a cache hit and must be returned without triggering a
        // refetch. This guards against accidentally treating empty bodies
        // as "missing".
        let storage = std::sync::Arc::new(PresentStorage {
            bytes: Bytes::new(),
        });
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/empty/empty-0.0.0.tar.gz/__content__",
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"unexpected"))
                }
            },
        )
        .await
        .expect("empty cached payload should still be a hit");
        let content = collect_stream(stream).await;

        assert!(content.is_empty());
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "empty cached payload is a cache hit, not a stale miss"
        );
    }

    /// Storage double that reports missing on `get` but records both `put`
    /// (write-back) and `delete` (truncation compensation).
    struct RecordingStorage {
        puts: std::sync::Mutex<Vec<(String, Bytes)>>,
        deletes: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingStorage {
        fn new() -> Self {
            Self {
                puts: std::sync::Mutex::new(Vec::new()),
                deletes: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for RecordingStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.puts
                .lock()
                .expect("puts mutex")
                .push((key.to_string(), content));
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Err(AppError::NotFound("missing cache entry".to_string()))
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.deletes
                .lock()
                .expect("deletes mutex")
                .push(key.to_string());
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn multi_chunk_result(
        chunks: Vec<&'static [u8]>,
        content_length: Option<u64>,
    ) -> crate::services::proxy_service::StreamingFetchResult {
        crate::services::proxy_service::StreamingFetchResult {
            body: futures::stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from_static(c))))
                .boxed(),
            content_type: Some("application/octet-stream".to_string()),
            content_length,
        }
    }

    /// #2192: a multi-chunk streaming refetch must serve every chunk to the
    /// caller AND write the full, byte-exact payload back for the next request.
    #[tokio::test]
    async fn test_streaming_refetch_tees_multi_chunk_body_to_cache() {
        let storage = std::sync::Arc::new(RecordingStorage::new());
        let key = "proxy-cache/pypi-remote/simple/big/big-9.9.9-py3-none-any.whl/__content__";
        let stream =
            super::get_remote_cached_or_refetch_stream(storage.clone(), key, move || async move {
                Ok(multi_chunk_result(vec![b"aaaa", b"bbbb", b"cc"], Some(10)))
            })
            .await
            .expect("streaming refetch should succeed");
        let content = collect_stream(stream).await;

        assert_eq!(content, Bytes::from_static(b"aaaabbbbcc"));
        let puts = storage.puts.lock().expect("puts mutex");
        assert_eq!(puts.len(), 1, "full body must be written back exactly once");
        assert_eq!(puts[0].0, key);
        assert_eq!(puts[0].1, Bytes::from_static(b"aaaabbbbcc"));
        assert!(
            storage.deletes.lock().expect("deletes mutex").is_empty(),
            "a complete write-back must not be deleted"
        );
    }

    /// #2192: if the written-back length does not match the advertised
    /// `content_length` (truncation / short read), the partial cache entry must
    /// be deleted so it is never served as a corrupt warm hit.
    #[tokio::test]
    async fn test_streaming_refetch_deletes_truncated_writeback() {
        let storage = std::sync::Arc::new(RecordingStorage::new());
        let key = "proxy-cache/pypi-remote/simple/trunc/trunc-1.0.0-py3-none-any.whl/__content__";
        // Advertise 100 bytes but only deliver 4: the guard must delete.
        let stream =
            super::get_remote_cached_or_refetch_stream(storage.clone(), key, move || async move {
                Ok(multi_chunk_result(vec![b"abcd"], Some(100)))
            })
            .await
            .expect("streaming refetch should succeed even when truncated");
        let content = collect_stream(stream).await;

        // The caller still receives whatever bytes arrived.
        assert_eq!(content, Bytes::from_static(b"abcd"));
        let deletes = storage.deletes.lock().expect("deletes mutex");
        assert_eq!(
            deletes.as_slice(),
            &[key.to_string()],
            "a truncated write-back must be deleted, not served warm"
        );
    }

    // -----------------------------------------------------------------------
    // serve_file Remote-arm wiring (PR #1283: stale-cache refetch)
    //
    // The unit tests above exercise `get_remote_cached_or_refetch` in
    // isolation. This DB-backed test pins the wiring at lines ~796-810 of
    // serve_file: when the artifact row's `repo_type` is Remote and a
    // proxy service is present, the handler must route the storage read
    // through `get_remote_cached_or_refetch` (not a bare `storage.get`).
    //
    // We cover the cache-hit branch end-to-end: artifact row + on-disk
    // payload both present. The refetch closure must not run; the bytes
    // returned must come from storage; the response must be a well-formed
    // PyPI download (correct content-type, content-disposition, length).
    // The stale-cache branch is covered by the four `get_remote_cached_or_refetch`
    // unit tests above (including writeback assertions); it cannot be
    // driven end-to-end here because the SSRF guard at line 928 hard-blocks
    // loopback as a resolved upstream file URL.
    //
    // Skips cleanly when DATABASE_URL is unset.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_serve_file_remote_arm_routes_through_cached_or_refetch_helper() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        let wheel_bytes: &[u8] = b"PK\x03\x04 cached-wheel-from-disk";
        let filename = "wired-1.2.3-py3-none-any.whl";
        let project = "wired";

        // The wiring branch under test requires (a) a remote repo with an
        // upstream_url AND (b) a proxy service on the state. We do NOT
        // exercise upstream I/O in this test, so the upstream URL only
        // needs to parse and pass SSRF (any public host works because
        // nothing dials it).
        let upstream = "https://upstream.example.test".to_string();
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);

        // Seed an artifact row + matching payload on disk. With the file
        // present, `get_remote_cached_or_refetch` must short-circuit on
        // the cache hit and return the bytes without invoking the refetch
        // closure (the unit tests above pin that contract).
        let storage_key = format!(
            "proxy-cache/{}/simple/{}/{}",
            fx.repo_key, project, filename
        );
        let artifact_path = format!("simple/{}/{}", project, filename);
        let repo_info = fx.repo_info("remote", Some(&upstream));
        crate::api::handlers::proxy_helpers::put_artifact_bytes(
            &state,
            &repo_info,
            &storage_key,
            Bytes::from_static(wheel_bytes),
        )
        .await
        .expect("seed payload on disk");
        let _artifact_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING id",
        )
        .bind(fx.repo_id)
        .bind(&artifact_path)
        .bind(project)
        .bind("1.2.3")
        .bind(wheel_bytes.len() as i64)
        .bind("test-wired")
        .bind("application/zip")
        .bind(&storage_key)
        .bind(fx.user_id)
        .fetch_one(&fx.pool)
        .await
        .expect("seed cached artifact row");

        // Invoke serve_file directly. The Remote arm at lines ~796-810
        // must construct a `get_remote_cached_or_refetch` call against
        // the storage backend; the helper hits the cache and returns the
        // wheel bytes; the handler wraps them in a PyPI download response.
        let result =
            super::serve_file(&state, &repo_info, &fx.repo_key, project, filename, None).await;

        // Clean up BEFORE asserting so a panic still leaves the DB clean.
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
                panic!("serve_file Remote arm must serve cached payload, got {status}");
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
            "application/zip",
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .expect("Content-Length")
                .to_str()
                .unwrap(),
            wheel_bytes.len().to_string(),
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        assert_eq!(
            &body_bytes[..],
            wheel_bytes,
            "wired Remote arm must serve the bytes returned by get_remote_cached_or_refetch"
        );

        cleanup().await;
    }

    #[tokio::test]
    async fn pypi_upload_queues_sync_tasks_and_preserves_replication_metadata() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::peer_instance_service::{
            PeerInstanceService, RegisterPeerInstanceRequest, ReplicationMode,
        };

        async fn sync_task_count(pool: &sqlx::PgPool, repo_id: uuid::Uuid, path: &str) -> i64 {
            sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COUNT(*)
                FROM sync_tasks st
                JOIN artifacts a ON a.id = st.artifact_id
                WHERE a.repository_id = $1
                  AND a.path = $2
                "#,
            )
            .bind(repo_id)
            .bind(path)
            .fetch_one(pool)
            .await
            .expect("count sync tasks")
        }

        async fn wait_for_sync_task_count(
            pool: &sqlx::PgPool,
            repo_id: uuid::Uuid,
            path: &str,
            expected: i64,
        ) -> i64 {
            for _ in 0..40 {
                let count = sync_task_count(pool, repo_id, path).await;
                if count == expected {
                    return count;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            sync_task_count(pool, repo_id, path).await
        }

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let peer_service = PeerInstanceService::new(fx.pool.clone());
        let peer = peer_service
            .register(RegisterPeerInstanceRequest {
                name: format!("pypi-repl-peer-{}", fx.repo_id),
                endpoint_url: "https://peer.example.test".to_string(),
                region: None,
                cache_size_bytes: 1024 * 1024,
                sync_filter: None,
                api_key: "peer-key".to_string(),
            })
            .await
            .expect("register test peer");
        peer_service
            .assign_repository(
                peer.id,
                fx.repo_id,
                true,
                Some(ReplicationMode::Mirror),
                None,
                None,
            )
            .await
            .expect("assign repo to peer");

        let project = "ak-pypi-replication-smoke";
        let version = "0.1.0";
        let filename = "ak_pypi_replication_smoke-0.1.0-py3-none-any.whl";
        let artifact_path = format!("{project}/{version}/{filename}");
        let payload = b"fake-wheel-bytes-for-replication";
        let (content_type, body) = pypi_upload_multipart(
            project,
            version,
            filename,
            payload,
            "PyPI peer replication smoke package",
            ">=3.8",
        );
        let app = fx.router_with_auth(super::router());
        let req = tdh::post(format!("/{}/", fx.repo_key), &content_type, body);
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "PyPI upload must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );

        assert_eq!(
            wait_for_sync_task_count(&fx.pool, fx.repo_id, &artifact_path, 1).await,
            1,
            "direct PyPI upload must queue exactly one peer sync task"
        );

        let metadata: (String, serde_json::Value) = sqlx::query_as(
            r#"
            SELECT am.format, am.metadata
            FROM artifact_metadata am
            JOIN artifacts a ON a.id = am.artifact_id
            WHERE a.repository_id = $1
              AND a.path = $2
            "#,
        )
        .bind(fx.repo_id)
        .bind(&artifact_path)
        .fetch_one(&fx.pool)
        .await
        .expect("query PyPI artifact metadata");
        assert_eq!(metadata.0, "pypi");
        assert_eq!(metadata.1["filename"], filename);
        assert_eq!(metadata.1["pkg_info"]["requires_python"], ">=3.8");
        assert_eq!(
            metadata.1["pkg_info"]["summary"],
            "PyPI peer replication smoke package"
        );
        assert_eq!(metadata.1["upload_metadata"]["metadata_version"], "2.1");

        let package: (Option<String>, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT description, metadata FROM packages WHERE repository_id = $1 AND name = $2",
        )
        .bind(fx.repo_id)
        .bind(project)
        .fetch_one(&fx.pool)
        .await
        .expect("query package catalog row");
        assert_eq!(
            package.0.as_deref(),
            Some("PyPI peer replication smoke package")
        );
        let package_metadata = package.1.expect("package metadata");
        assert_eq!(package_metadata["format"], "pypi");
        assert_eq!(package_metadata["filename"], filename);
        assert_eq!(package_metadata["requires_python"], ">=3.8");

        let version_rows: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.repository_id = $1
              AND p.name = $2
              AND pv.version = $3
            "#,
        )
        .bind(fx.repo_id)
        .bind(project)
        .bind(version)
        .fetch_one(&fx.pool)
        .await
        .expect("query package version row");
        assert_eq!(version_rows, 1);

        let replicated_project = "ak-pypi-replication-incoming";
        let replicated_version = "0.2.0";
        let replicated_filename = "ak_pypi_replication_incoming-0.2.0-py3-none-any.whl";
        let replicated_path =
            format!("{replicated_project}/{replicated_version}/{replicated_filename}");
        let (content_type, body) = pypi_upload_multipart(
            replicated_project,
            replicated_version,
            replicated_filename,
            b"incoming-replication-wheel",
            "Incoming replicated PyPI package",
            ">=3.9",
        );
        let app = fx.router_with_auth(super::router());
        let mut req = tdh::post(format!("/{}/", fx.repo_key), &content_type, body);
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "replication-marked PyPI upload must persist; body: {}",
            String::from_utf8_lossy(&body)
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            sync_task_count(&fx.pool, fx.repo_id, &replicated_path).await,
            0,
            "incoming peer replication writes must not requeue back to peers"
        );

        let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// #2022: a direct `twine upload` to a `promotion_only` repository must be
    /// rejected with 409 CONFLICT; the same upload to a normal repository must
    /// still succeed. Skips when no test database is configured.
    #[tokio::test]
    async fn test_upload_blocked_on_promotion_only_repo() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let project = "ak-pypi-promotion-gate";
        let version = "0.1.0";
        let filename = "ak_pypi_promotion_gate-0.1.0-py3-none-any.whl";

        // Flag the repo promotion_only -> direct upload is rejected with 409.
        fx.set_promotion_only(true).await;
        let (content_type, body) = pypi_upload_multipart(
            project,
            version,
            filename,
            b"fake-wheel-bytes",
            "promotion gate test",
            ">=3.8",
        );
        let app = fx.router_with_auth(super::router());
        let req = tdh::post(format!("/{}/", fx.repo_key), &content_type, body);
        let (blocked_status, _) = tdh::send(app, req).await;

        // Clear the flag -> the same upload succeeds.
        fx.set_promotion_only(false).await;
        let (content_type, body) = pypi_upload_multipart(
            project,
            version,
            filename,
            b"fake-wheel-bytes",
            "promotion gate test",
            ">=3.8",
        );
        let app = fx.router_with_auth(super::router());
        let req = tdh::post(format!("/{}/", fx.repo_key), &content_type, body);
        let (allowed_status, allowed_body) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            blocked_status,
            StatusCode::CONFLICT,
            "promotion_only direct upload must return 409"
        );
        assert_eq!(
            allowed_status,
            StatusCode::OK,
            "upload to a normal repo must still succeed; body: {}",
            String::from_utf8_lossy(&allowed_body)
        );
    }

    // -----------------------------------------------------------------------
    // pypi_content_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_pypi_content_type_whl() {
        assert_eq!(
            pypi_content_type("numpy-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
            "application/zip"
        );
    }

    #[test]
    fn test_pypi_content_type_tar_gz() {
        assert_eq!(pypi_content_type("six-1.16.0.tar.gz"), "application/gzip");
    }

    #[test]
    fn test_pypi_content_type_tar_bz2() {
        assert_eq!(
            pypi_content_type("package-1.0.tar.bz2"),
            "application/x-bzip2"
        );
    }

    #[test]
    fn test_pypi_content_type_zip() {
        assert_eq!(pypi_content_type("package-1.0.zip"), "application/zip");
    }

    #[test]
    fn test_pypi_content_type_unknown() {
        assert_eq!(
            pypi_content_type("package-1.0.egg"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // split_url_base_and_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_url_normal() {
        let result =
            split_url_base_and_path("https://files.pythonhosted.org/packages/ab/cd/file.whl");
        assert_eq!(
            result,
            Some((
                "https://files.pythonhosted.org".to_string(),
                "packages/ab/cd/file.whl".to_string()
            ))
        );
    }

    #[test]
    fn test_split_url_with_port() {
        let result = split_url_base_and_path("http://localhost:8080/api/v1/packages");
        assert_eq!(
            result,
            Some((
                "http://localhost:8080".to_string(),
                "api/v1/packages".to_string()
            ))
        );
    }

    #[test]
    fn test_split_url_without_path() {
        // URL with host only and no trailing slash has no path component
        let result = split_url_base_and_path("https://example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_split_url_with_single_path_segment() {
        let result = split_url_base_and_path("https://example.com/file.whl");
        assert_eq!(
            result,
            Some(("https://example.com".to_string(), "file.whl".to_string()))
        );
    }

    #[test]
    fn test_split_url_no_scheme() {
        let result = split_url_base_and_path("not-a-url");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // build_simple_project_response — HTML (PEP 503)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_project_response_html_single_artifact() {
        let artifacts = vec![SimpleProjectArtifact {
            path: "my-package/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 12345,
            checksum_sha256: "abc123def456".to_string(),
            metadata: None,
            upload_time: None,
        }];

        let headers = HeaderMap::new();
        let result =
            build_simple_project_response(&headers, "my-virtual", "my-package", &artifacts, &[]);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/html; charset=utf-8");
    }

    #[test]
    fn test_build_simple_project_response_html_uses_virtual_repo_key() {
        // Reproducer for #643: when a local repo is part of a virtual repo,
        // the simple index URLs must use the virtual repo key, not the member's.
        let artifacts = vec![SimpleProjectArtifact {
            path: "packages/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 5000,
            checksum_sha256: "aaa111bbb222".to_string(),
            metadata: None,
            upload_time: None,
        }];

        let headers = HeaderMap::new();
        let result =
            build_simple_project_response(&headers, "pypi-virtual", "my-package", &artifacts, &[]);
        let response = result.unwrap();

        // Read the body to verify URLs point through the virtual repo
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("/pypi/pypi-virtual/simple/my-package/my_package-1.0.0.tar.gz"),
            "URL should use the virtual repo key, got: {}",
            html
        );
        assert!(
            html.contains("sha256=aaa111bbb222"),
            "URL should include sha256 hash"
        );
        assert!(
            html.contains("<h1>Links for my-package</h1>"),
            "HTML should include package heading"
        );
    }

    #[test]
    fn test_build_simple_project_response_html_with_requires_python() {
        let metadata = serde_json::json!({
            "pkg_info": {
                "requires_python": ">=3.8"
            }
        });

        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0-py3-none-any.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 4000,
            checksum_sha256: "deadbeef".to_string(),
            metadata: Some(metadata),
            upload_time: None,
        }];

        let headers = HeaderMap::new();
        let result = build_simple_project_response(&headers, "virt", "pkg", &artifacts, &[]);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("data-requires-python=\"&gt;=3.8\""),
            "HTML should include escaped requires-python attribute"
        );
    }

    #[test]
    fn test_build_simple_project_response_html_multiple_artifacts() {
        let artifacts = vec![
            SimpleProjectArtifact {
                path: "pkg-1.0.0.tar.gz".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 1000,
                checksum_sha256: "aaa".to_string(),
                metadata: None,
                upload_time: None,
            },
            SimpleProjectArtifact {
                path: "pkg-2.0.0.tar.gz".to_string(),
                version: Some("2.0.0".to_string()),
                size_bytes: 2000,
                checksum_sha256: "bbb".to_string(),
                metadata: None,
                upload_time: None,
            },
        ];

        let headers = HeaderMap::new();
        let result = build_simple_project_response(&headers, "vrepo", "pkg", &artifacts, &[]);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("/pypi/vrepo/simple/pkg/pkg-1.0.0.tar.gz#sha256=aaa"));
        assert!(html.contains("/pypi/vrepo/simple/pkg/pkg-2.0.0.tar.gz#sha256=bbb"));
    }

    // -----------------------------------------------------------------------
    // build_simple_project_response — JSON (PEP 691)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_project_response_json_uses_virtual_repo_key() {
        // PEP 691 variant of the #643 reproducer: JSON response should also
        // route URLs through the virtual repo.
        let artifacts = vec![SimpleProjectArtifact {
            path: "packages/my_package-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 5000,
            checksum_sha256: "abc123".to_string(),
            metadata: None,
            upload_time: None,
        }];

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result =
            build_simple_project_response(&headers, "pypi-virtual", "my-package", &artifacts, &[]);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "my-package");
        assert_eq!(json["meta"]["api-version"], "1.2");

        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "my_package-1.0.0.tar.gz");
        assert!(
            files[0]["url"]
                .as_str()
                .unwrap()
                .contains("/pypi/pypi-virtual/simple/my-package/"),
            "JSON URL should use virtual repo key"
        );
        assert_eq!(files[0]["hashes"]["sha256"], "abc123");
        assert_eq!(files[0]["size"], 5000);

        let versions = json["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0], "1.0.0");
    }

    #[test]
    fn test_build_simple_project_response_json_with_requires_python() {
        let metadata = serde_json::json!({
            "pkg_info": {
                "requires_python": ">=3.9,<4.0"
            }
        });

        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0-py3-none-any.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 3000,
            checksum_sha256: "cafe".to_string(),
            metadata: Some(metadata),
            upload_time: None,
        }];

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result = build_simple_project_response(&headers, "repo", "pkg", &artifacts, &[]);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let files = json["files"].as_array().unwrap();
        assert_eq!(files[0]["requires-python"], ">=3.9,<4.0");
    }

    // -----------------------------------------------------------------------
    // PEP 700 upload-time (#1773)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_project_response_json_emits_upload_time() {
        // Regression for #1773: the PEP 691 JSON file object must carry the
        // PEP 700 `upload-time` field, formatted as RFC 3339 (UTC, `Z`).
        let upload_time = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0-py3-none-any.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 3000,
            checksum_sha256: "cafe".to_string(),
            metadata: None,
            upload_time: Some(upload_time),
        }];

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result = build_simple_project_response(&headers, "repo", "pkg", &artifacts, &[]);
        let response = result.unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let files = json["files"].as_array().unwrap();
        assert_eq!(files[0]["upload-time"], "2026-01-02T03:04:05Z");
    }

    #[test]
    fn test_build_simple_project_response_json_omits_upload_time_when_absent() {
        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 10,
            checksum_sha256: "abc".to_string(),
            metadata: None,
            upload_time: None,
        }];
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );
        let response =
            build_simple_project_response(&headers, "repo", "pkg", &artifacts, &[]).unwrap();
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["files"][0].get("upload-time").is_none());
    }

    #[test]
    fn test_build_simple_project_response_html_emits_upload_time() {
        // Regression for #1773: HTML anchors must carry a `data-upload-time`
        // attribute when the upload timestamp is known.
        let upload_time = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let artifacts = vec![SimpleProjectArtifact {
            path: "pkg-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 10,
            checksum_sha256: "abc".to_string(),
            metadata: None,
            upload_time: Some(upload_time),
        }];
        let response =
            build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &artifacts, &[])
                .unwrap();
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("data-upload-time=\"2026-01-02T03:04:05Z\""),
            "HTML should include data-upload-time, got: {}",
            html
        );
    }

    // -----------------------------------------------------------------------
    // build_simple_root_response (PEP 503 / PEP 691 root index)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_simple_root_response_html() {
        let packages = vec![
            "flask".to_string(),
            "numpy".to_string(),
            "requests".to_string(),
        ];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/html; charset=utf-8");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("<h1>Simple Index</h1>"));
        assert!(html.contains("/pypi/pypi-virtual/simple/flask/"));
        assert!(html.contains("/pypi/pypi-virtual/simple/numpy/"));
        assert!(html.contains("/pypi/pypi-virtual/simple/requests/"));
    }

    #[test]
    fn test_build_simple_root_response_json() {
        let packages = vec!["flask".to_string(), "numpy".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["meta"]["api-version"], "1.2");
        let projects = json["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0]["name"], "flask");
        assert_eq!(projects[1]["name"], "numpy");
    }

    #[test]
    fn test_build_simple_root_response_ignores_content_type_for_negotiation() {
        // Regression for #1773: content negotiation must use ONLY the Accept
        // header. A request Content-Type of the JSON media type with an
        // HTML Accept must still yield HTML (the request Content-Type
        // describes the request body, not the desired response format).
        let packages = vec!["flask".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );
        headers.insert("accept", "text/html".parse().unwrap());

        let response = build_simple_root_response(&headers, "pypi-virtual", &packages).unwrap();
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "text/html; charset=utf-8",
            "Content-Type must not drive response negotiation"
        );
    }

    #[test]
    fn test_build_simple_root_response_empty_packages() {
        let packages: Vec<String> = vec![];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-local", &packages);
        let response = result.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("<h1>Simple Index</h1>"));
        // No package links should appear
        assert!(!html.contains("<a href="));
    }

    #[test]
    fn test_build_simple_root_response_deduplicates_via_btreeset() {
        // Verify that duplicate package names (which would come from
        // multiple member repos in a virtual) are already deduplicated
        // by the BTreeSet in simple_root before reaching the response
        // builder. The response builder itself renders whatever it gets.
        let packages = vec!["flask".to_string(), "flask".to_string()];
        let headers = HeaderMap::new();

        let result = build_simple_root_response(&headers, "pypi-virtual", &packages);
        let response = result.unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Two entries appear because deduplication is the caller's job
        // (simple_root uses BTreeSet). This test documents the contract.
        let count = html.matches("/pypi/pypi-virtual/simple/flask/").count();
        assert_eq!(count, 2);
    }

    // -----------------------------------------------------------------------
    // Stored-XSS regression tests (#1377 review)
    //
    // These tests pin the defense-in-depth contract for the proxied
    // PEP 503 root index:
    //   1. `normalize_pep503` MUST drop every char outside `[a-z0-9.-]`.
    //   2. `build_simple_root_response` MUST HTML-escape everything it
    //      interpolates.
    //   3. The response MUST emit a restrictive Content-Security-Policy
    //      so a hypothetical future regression cannot execute script.
    //   4. `decode_html_entities_minimal` MUST NOT double-decode (so
    //      `&amp;lt;` survives as the literal string `&lt;`, not `<`).
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_pep503_drops_script_chars() {
        // Layer 1: the security boundary at the name-normalisation step.
        // A name parsed out of malicious upstream HTML must lose every
        // character that could break out of an HTML attribute or text
        // node before it ever reaches the response builder.
        assert_eq!(
            normalize_pep503("<script>alert(1)</script>"),
            "scriptalert1script"
        );
        assert_eq!(
            normalize_pep503("foo\"onerror=alert(1)"),
            "fooonerroralert1"
        );
        assert_eq!(normalize_pep503("foo&bar"), "foobar");
        assert_eq!(normalize_pep503("foo>bar"), "foobar");
        assert_eq!(normalize_pep503("foo'bar"), "foobar");
        // Backslash, tab, newline — all dropped.
        assert_eq!(normalize_pep503("a\\b\tc\nd"), "abcd");
        // Real-world: a valid name surrounded by junk loses only the junk.
        assert_eq!(normalize_pep503("<a>flask</a>"), "aflaska");
    }

    #[test]
    fn test_build_simple_root_response_escapes_html_in_package_name() {
        // Layer 2: even if a malformed name with HTML metacharacters did
        // somehow reach the response builder (e.g. a future code path
        // that bypasses `normalize_pep503`), the rendered HTML must
        // never interpret it as markup.
        let packages = vec![
            "<script>alert('xss')</script>".to_string(),
            "foo\"onerror=alert(1)\"".to_string(),
            "ampersand&here".to_string(),
        ];
        let headers = HeaderMap::new();

        let response = build_simple_root_response(&headers, "pypi-virtual", &packages).unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Raw `<script>` must NEVER appear in the body. The literal
        // string `alert` is fine to appear escaped, but the surrounding
        // tag must be entity-encoded.
        assert!(
            !html.contains("<script>"),
            "raw <script> tag MUST NOT appear in rendered HTML: {}",
            html
        );
        assert!(
            !html.contains("</script>"),
            "raw </script> tag MUST NOT appear in rendered HTML: {}",
            html
        );
        // The escaped form must be present, proving the escape ran.
        assert!(html.contains("&lt;script&gt;"));
        // Quote-injection inside the href attribute is neutralised.
        assert!(!html.contains("\"onerror="));
        assert!(html.contains("&quot;onerror"));
        // Ampersand becomes &amp; (so the entity itself is safely encoded).
        assert!(html.contains("ampersand&amp;here"));
    }

    #[test]
    fn test_build_simple_root_response_escapes_html_in_repo_key() {
        // The repo_key arrives from the URL router and should already
        // be safe in practice, but the response builder treats it as
        // untrusted on principle.
        let packages = vec!["flask".to_string()];
        let headers = HeaderMap::new();

        let response =
            build_simple_root_response(&headers, "repo\"><script>x</script>", &packages).unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_build_simple_root_response_sets_csp_header() {
        // Layer 3: even if both upstream layers somehow regress, the
        // browser refuses to execute inline script under this policy.
        let packages = vec!["flask".to_string()];
        let headers = HeaderMap::new();

        let response = build_simple_root_response(&headers, "pypi-virtual", &packages).unwrap();
        let csp = response
            .headers()
            .get("Content-Security-Policy")
            .expect("CSP header MUST be present on simple-index responses")
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
        // X-Content-Type-Options nosniff also pins the content-type.
        let xcto = response
            .headers()
            .get("X-Content-Type-Options")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(xcto, "nosniff");
    }

    #[test]
    fn test_decode_html_entities_minimal_does_not_double_decode() {
        // Naive chained `.replace()` would convert `&amp;lt;` -> `&lt;`
        // -> `<`. A correct single-pass decoder yields `&lt;`.
        assert_eq!(decode_html_entities_minimal("&amp;lt;"), "&lt;");
        assert_eq!(decode_html_entities_minimal("&amp;gt;"), "&gt;");
        assert_eq!(
            decode_html_entities_minimal("&amp;amp;"),
            "&amp;",
            "double-encoded ampersand must decode once, not twice"
        );
        assert_eq!(decode_html_entities_minimal("&amp;quot;"), "&quot;");
        // Single-encoded entities still decode normally.
        assert_eq!(decode_html_entities_minimal("&lt;"), "<");
        assert_eq!(decode_html_entities_minimal("&amp;"), "&");
        assert_eq!(decode_html_entities_minimal("&quot;"), "\"");
        // Mixed content.
        assert_eq!(
            decode_html_entities_minimal("foo &amp; &lt;bar&gt;"),
            "foo & <bar>"
        );
        // Strings without `&` short-circuit and round-trip.
        assert_eq!(decode_html_entities_minimal("hello world"), "hello world");
        // Unknown entity references are passed through verbatim.
        assert_eq!(decode_html_entities_minimal("&unknown;"), "&unknown;");
    }

    #[test]
    fn test_malicious_upstream_simple_index_is_sanitized_end_to_end() {
        // End-to-end pin: simulate a malicious upstream serving a
        // `<script>`-bearing project name. After parsing + normalising,
        // the rendered response must contain NO executable script
        // markup (the package is effectively dropped because the only
        // chars surviving normalisation are alphanumerics inside the
        // `<script>` text, but the test focuses on the safety property
        // rather than the exact surviving string).
        let malicious_upstream = r#"
            <!DOCTYPE html>
            <html><body>
              <a href="/simple/&lt;script&gt;alert(1)&lt;/script&gt;/">&lt;script&gt;alert(1)&lt;/script&gt;</a>
              <a href="/simple/flask/">flask</a>
              <a href="/simple/foo&amp;bar/">foo&amp;bar</a>
            </body></html>
        "#;

        let names = parse_simple_root_projects(malicious_upstream);

        // No surviving name may contain any HTML special character.
        for name in &names {
            assert!(!name.contains('<'), "parsed name leaked `<`: {:?}", name);
            assert!(!name.contains('>'), "parsed name leaked `>`: {:?}", name);
            assert!(!name.contains('&'), "parsed name leaked `&`: {:?}", name);
            assert!(!name.contains('"'), "parsed name leaked `\"`: {:?}", name);
            assert!(!name.contains('\''), "parsed name leaked `'`: {:?}", name);
        }
        // The benign names still come through.
        assert!(names.iter().any(|n| n == "flask"));
        assert!(names.iter().any(|n| n == "foobar"));

        // Now render and verify the response body is XSS-safe.
        let response =
            build_simple_root_response(&HeaderMap::new(), "pypi-remote", &names).unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<script>"));
        assert!(!html.contains("</script>"));
        assert!(!html.contains("onerror="));
    }

    // -----------------------------------------------------------------------
    // merge_local_into_remote_simple_html — #1230 virtual union behavior
    // -----------------------------------------------------------------------

    fn remote_html_with(entries: &[(&str, Option<&str>)]) -> String {
        let mut s = String::from(
            "<!DOCTYPE html>\n<html>\n<head>\n\
             <meta name=\"pypi:repository-version\" content=\"1.0\"/>\n\
             <title>Links for pkg</title>\n</head>\n<body>\n\
             <h1>Links for pkg</h1>\n",
        );
        for (filename, rp) in entries {
            let rp_attr = rp
                .map(|v| format!(" data-requires-python=\"{}\"", v))
                .unwrap_or_default();
            s.push_str(&format!(
                "<a href=\"/pypi/v/simple/pkg/{}\"{}>{}</a><br/>\n",
                filename, rp_attr, filename
            ));
        }
        s.push_str("</body>\n</html>\n");
        s
    }

    #[test]
    fn test_merge_local_appends_entries_absent_from_remote() {
        // Reproducer for #1230: local member has versions upstream does not
        // (or in our prod case, upstream has versions the local subset
        // shadows — symmetric situation, same fix). The merged response
        // must contain entries from both sides.
        let remote = remote_html_with(&[("pkg-1.0.0.tar.gz", Some("&gt;=3.8"))]);
        let local = vec![SimpleProjectArtifact {
            path: "pkg/pkg-2.0.0-py3-none-any.whl".to_string(),
            version: Some("2.0.0".to_string()),
            size_bytes: 4096,
            checksum_sha256: "ffeeddccbbaa99887766554433221100".to_string(),
            metadata: None,
            upload_time: None,
        }];

        let merged = merge_local_into_remote_simple_html(&remote, "virt", "pkg", &local, &[]);

        assert!(
            merged.contains("pkg-1.0.0.tar.gz"),
            "remote entry preserved"
        );
        assert!(
            merged.contains("pkg-2.0.0-py3-none-any.whl"),
            "local entry spliced in"
        );
        assert!(
            merged.contains("/pypi/virt/simple/pkg/pkg-2.0.0-py3-none-any.whl#sha256=ffeeddccbbaa99887766554433221100"),
            "local URL uses the virtual repo key and carries the sha256 fragment"
        );
        // Spliced before </body> so the document is still well-formed.
        let body_idx = merged.find("</body>").expect("</body> still present");
        let local_idx = merged.find("pkg-2.0.0-py3-none-any.whl").unwrap();
        assert!(local_idx < body_idx, "local entries must precede </body>");
    }

    #[test]
    fn test_merge_local_skips_filenames_already_in_remote() {
        // If a file with the same filename exists in both members, the
        // remote entry wins (idempotence — no duplicate <a> emitted).
        let remote = remote_html_with(&[("pkg-1.0.0.tar.gz", None)]);
        let local = vec![SimpleProjectArtifact {
            path: "pkg/pkg-1.0.0.tar.gz".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            metadata: None,
            upload_time: None,
        }];

        let merged = merge_local_into_remote_simple_html(&remote, "virt", "pkg", &local, &[]);
        let count = merged.matches("pkg-1.0.0.tar.gz</a>").count();
        assert_eq!(count, 1, "filename present exactly once after dedupe");
        // The local sha256 must NOT appear — the remote entry is canonical.
        assert!(
            !merged.contains(
                "sha256=0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "local sha256 not spliced in when filename dedupes against remote"
        );
    }

    #[test]
    fn test_merge_empty_local_returns_remote_unchanged() {
        let remote = remote_html_with(&[("pkg-1.0.0.tar.gz", None)]);
        let merged = merge_local_into_remote_simple_html(&remote, "virt", "pkg", &[], &[]);
        assert_eq!(merged, remote);
    }

    #[test]
    fn test_merge_emits_data_requires_python_attribute() {
        let remote = remote_html_with(&[]);
        let metadata = serde_json::json!({
            "pkg_info": { "requires_python": ">=3.10,<3.14" }
        });
        let local = vec![SimpleProjectArtifact {
            path: "pkg/pkg-3.0.0.tar.gz".to_string(),
            version: Some("3.0.0".to_string()),
            size_bytes: 256,
            checksum_sha256: "deadbeef".to_string(),
            metadata: Some(metadata),
            upload_time: None,
        }];

        let merged = merge_local_into_remote_simple_html(&remote, "virt", "pkg", &local, &[]);
        assert!(
            merged.contains("data-requires-python=\"&gt;=3.10,&lt;3.14\""),
            "requires_python is HTML-escaped: {}",
            merged
        );
    }

    #[test]
    fn test_merge_handles_remote_html_without_body_close() {
        // Defensive: if upstream omits </body> (malformed but seen in the
        // wild on some private indexes) the helper appends rather than
        // dropping local entries.
        let remote = String::from(
            "<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n\
             <a href=\"/pypi/v/simple/pkg/pkg-1.0.0.tar.gz\">pkg-1.0.0.tar.gz</a><br/>\n",
        );
        let local = vec![SimpleProjectArtifact {
            path: "pkg/pkg-2.0.0-py3-none-any.whl".to_string(),
            version: Some("2.0.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "cafebabe".to_string(),
            metadata: None,
            upload_time: None,
        }];

        let merged = merge_local_into_remote_simple_html(&remote, "virt", "pkg", &local, &[]);
        assert!(merged.contains("pkg-1.0.0.tar.gz"));
        assert!(merged.contains("pkg-2.0.0-py3-none-any.whl"));
    }

    // -----------------------------------------------------------------------
    // Regression tests for #1377 — Remote PyPI root simple-index proxy + cache.
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_simple_root_projects_extracts_from_pep503_html() {
        // Canonical PEP 503 root index shape: <a href="<project>/"><project></a>
        let html = "<!DOCTYPE html><html><body>\
                    <a href=\"flask/\">Flask</a>\
                    <a href=\"requests/\">requests</a>\
                    <a href=\"my_pkg/\">My_Pkg</a>\
                    </body></html>";
        let projects = super::parse_simple_root_projects(html);
        // PEP 503 normalisation: lowercase + `_`/`.` collapsed to `-`.
        assert_eq!(projects, vec!["flask", "my-pkg", "requests"]);
    }

    #[test]
    fn test_parse_simple_root_projects_falls_back_to_href_when_text_missing() {
        // Some indexes emit the link without text content (Nexus). The
        // parser must fall back to the trailing href segment so we do not
        // silently drop entries.
        let html = "<html><body><a href=\"numpy/\"></a></body></html>";
        let projects = super::parse_simple_root_projects(html);
        assert_eq!(projects, vec!["numpy"]);
    }

    #[test]
    fn test_parse_simple_root_projects_empty_when_no_anchors() {
        let projects = super::parse_simple_root_projects("<html><body>no links</body></html>");
        assert!(projects.is_empty());
    }

    /// Regression: single-quoted href attributes are legal HTML and at
    /// least one upstream (older Devpi releases) emits them. Before the
    /// review hardening the regex only matched `href="..."`, silently
    /// dropping single-quoted entries from the parsed project list.
    #[test]
    fn test_parse_simple_root_projects_accepts_single_quoted_hrefs() {
        let html = "<html><body>\
                    <a href='flask/'>Flask</a>\
                    <a href='requests/'>requests</a>\
                    </body></html>";
        let projects = super::parse_simple_root_projects(html);
        assert_eq!(projects, vec!["flask", "requests"]);
    }

    /// Mixed single + double quote anchors in the same document must both
    /// be picked up. Real-world index pages occasionally mix quoting styles
    /// when concatenated from multiple templates.
    #[test]
    fn test_parse_simple_root_projects_mixed_quote_styles() {
        let html = "<html><body>\
                    <a href=\"flask/\">Flask</a>\
                    <a href='requests/'>requests</a>\
                    </body></html>";
        let projects = super::parse_simple_root_projects(html);
        assert_eq!(projects, vec!["flask", "requests"]);
    }

    /// Regression: HTML entities inside the anchor text must be decoded
    /// BEFORE PEP 503 normalisation, otherwise a name escaped as
    /// `foo&amp;bar` would carry the literal entity reference (`&amp;`)
    /// into the normalised output. After the #1377 review hardening,
    /// `normalize_pep503` also DROPS any character outside `[a-z0-9.-]`
    /// — so the decoded `&`, `<`, `>`, `"`, `'` characters are stripped
    /// at the normalisation step rather than carried through. The
    /// assertion here is that (a) the literal entity reference tokens
    /// do not leak through (decoder ran), AND (b) the dangerous
    /// characters themselves do not leak through (normalisation
    /// stripped them).
    #[test]
    fn test_parse_simple_root_projects_decodes_html_entities_in_text() {
        let html = "<html><body>\
                    <a href=\"odd/\">foo&amp;bar</a>\
                    <a href=\"q/\">a&lt;b</a>\
                    <a href=\"r/\">a&gt;b</a>\
                    <a href=\"s/\">a&quot;b</a>\
                    <a href=\"t/\">a&apos;b</a>\
                    </body></html>";
        let projects = super::parse_simple_root_projects(html);
        for p in &projects {
            // No entity reference TOKEN should survive into the output.
            for token in ["amp;", "&lt", "&gt", "&quot", "&apos", "&#"] {
                assert!(
                    !p.contains(token),
                    "entity reference token {token:?} leaked through into {p:?}"
                );
            }
            // Nor the dangerous decoded characters themselves.
            for ch in ['&', '<', '>', '"', '\''] {
                assert!(
                    !p.contains(ch),
                    "dangerous character {ch:?} leaked through into {p:?}"
                );
            }
        }
        // The benign letters survive normalisation: `foo&amp;bar`
        // decodes to `foo&bar`, the `&` is stripped, and the result is
        // `foobar`.
        assert!(
            projects.iter().any(|p| p == "foobar"),
            "expected `foobar` (from `foo&amp;bar` after decode + strip) in {projects:?}"
        );
    }

    /// HTML entities in the href fallback path (when anchor text is
    /// empty) must also be decoded before the trailing-segment
    /// extraction. After #1377 review hardening, the apostrophe
    /// produced by the decode is then dropped by `normalize_pep503` so
    /// the resulting project name contains only `[a-z0-9.-]`.
    #[test]
    fn test_parse_simple_root_projects_decodes_html_entities_in_href_fallback() {
        let html = "<html><body><a href=\"my&#39;pkg/\"></a></body></html>";
        let projects = super::parse_simple_root_projects(html);
        // The `&#39;` decodes to `'` (decoder ran), then the `'` is
        // dropped at normalisation. The literal entity must not
        // survive, and neither must the apostrophe.
        assert_eq!(projects, vec!["mypkg"]);
    }

    // The body-size cap constant must be high enough to comfortably
    // accommodate any legitimate private-mirror index but low enough to
    // stop a hostile upstream from forcing a multi-hundred-megabyte
    // allocation + regex sweep on a single request. We assert this at
    // compile time rather than runtime so the test is free.
    const _MIN_CAP: usize = 1024 * 1024; // 1 MiB
    const _MAX_CAP: usize = 64 * 1024 * 1024; // 64 MiB
    const _: () = assert!(super::MAX_SIMPLE_ROOT_BODY_BYTES >= _MIN_CAP);
    const _: () = assert!(super::MAX_SIMPLE_ROOT_BODY_BYTES <= _MAX_CAP);

    /// Regression: a Remote PyPI repo with NO local artifacts must proxy
    /// upstream `/simple/` and return the upstream's package list. Before
    /// #1377 this returned an empty index because `simple_root` only ever
    /// queried the local `artifacts` table, and proxy-cached items no
    /// longer create rows there (#1278 / #1280).
    ///
    /// Also covers the cache-roundtrip path: a second invocation must
    /// reuse the proxy_service cache and produce the same package list
    /// without re-hitting upstream.
    #[tokio::test]
    async fn test_simple_root_remote_proxies_and_caches_upstream_index() {
        use crate::api::handlers::test_db_helpers as tdh;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let upstream_index = "<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"/></head><body>\
                              <a href=\"reltest-pkg/\">reltest-pkg</a>\
                              <a href=\"flask/\">Flask</a>\
                              </body></html>";

        // Both /simple/ and /simple (without trailing slash) should be
        // covered: the proxy fetch always lands on /simple/.
        let hits_for_mock = hits.clone();
        Mock::given(method("GET"))
            .and(path("/simple/"))
            .respond_with(move |_req: &wiremock::Request| {
                hits_for_mock.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .set_body_string(upstream_index)
            })
            .mount(&mock_server)
            .await;

        // Re-point repo at the mock upstream.
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
        let do_cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        // 1st call: HTML body must contain BOTH upstream packages and route
        // their hrefs to the local repo (not the upstream URL).
        let result = super::simple_root(
            axum::extract::State(state.clone()),
            axum::extract::Path(fx.repo_key.clone()),
            HeaderMap::new(),
        )
        .await;
        let response = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                do_cleanup().await;
                panic!("simple_root must succeed for Remote repo, got {status}");
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let body_str = std::str::from_utf8(&body_bytes).expect("utf8");
        assert!(
            body_str.contains(">reltest-pkg<"),
            "root simple index must list 'reltest-pkg' from upstream (#1377): {body_str}"
        );
        assert!(
            body_str.contains(">flask<"),
            "root simple index must list 'flask' (normalised) from upstream: {body_str}"
        );
        assert!(
            body_str.contains(&format!("/pypi/{}/simple/", fx.repo_key)),
            "root simple index must point hrefs at the local repo, not the upstream: {body_str}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "upstream hit exactly once on first call"
        );

        // 2nd call: proxy cache must satisfy this request without a fresh
        // upstream HEAD/GET. Package list must still be the same.
        let result2 = super::simple_root(
            axum::extract::State(state.clone()),
            axum::extract::Path(fx.repo_key.clone()),
            HeaderMap::new(),
        )
        .await;
        let response2 = match result2 {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                do_cleanup().await;
                panic!("simple_root cache roundtrip must succeed, got {status}");
            }
        };
        let body_bytes2 = axum::body::to_bytes(response2.into_body(), 1024 * 1024)
            .await
            .expect("body2");
        let body_str2 = std::str::from_utf8(&body_bytes2).expect("utf82");
        assert!(
            body_str2.contains(">reltest-pkg<"),
            "cached root simple index must still list 'reltest-pkg' (#1377): {body_str2}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "upstream must NOT be hit again on a cache-roundtrip read"
        );

        do_cleanup().await;
    }

    // -----------------------------------------------------------------------
    // resolve_pypi_remote_fetch_target / fetch_from_pypi_remote_streaming
    // -----------------------------------------------------------------------
    //
    // DB-free helpers (MissingSvcStorage / build_proxy_service_no_db) are used
    // for tests that only probe the cache layer (e.g. cache-miss probes).
    // Tests that exercise the upstream fetch path require a real PgPool so that
    // load_upstream_auth succeeds; they use tdh::try_pool() and skip when
    // DATABASE_URL is unset.

    /// Storage backend that implements `storage_service::StorageBackend` (the
    /// richer trait used by `StorageService` / `ProxyService`). Reports every
    /// `get` as a miss (NotFound) so tests hit the upstream fetch path.
    struct MissingSvcStorage;

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for MissingSvcStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            Err(AppError::NotFound(key.to_string()))
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> crate::error::Result<Vec<String>> {
            Ok(vec![])
        }
        async fn copy(&self, _src: &str, _dst: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> crate::error::Result<u64> {
            Ok(0)
        }
    }

    fn build_proxy_service_no_db() -> crate::services::proxy_service::ProxyService {
        use crate::services::storage_service::StorageService;
        let storage = std::sync::Arc::new(MissingSvcStorage);
        let storage_svc = std::sync::Arc::new(StorageService::new(storage));
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy");
        crate::services::proxy_service::ProxyService::new(pool, storage_svc)
    }

    /// End-to-end test for the streaming download path via the fallback route.
    ///
    /// The simple index page has no matching href, so `resolve_pypi_remote_fetch_target`
    /// falls through to the stable `simple/{project}/{filename}` fallback path.
    /// This avoids the SSRF check (which hard-blocks loopback) while still
    /// exercising `fetch_from_pypi_remote_streaming` and `proxy_fetch_streaming_with_cache_key`.
    ///
    /// Skipped when `DATABASE_URL` is unset (CI always sets it).
    #[tokio::test]
    async fn test_fetch_from_pypi_remote_streaming_fallback_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let wheel_body = b"fake-wheel-bytes";

        // Empty simple-index page → find_upstream_url_for_file returns None →
        // resolve_pypi_remote_fetch_target falls back to simple/{project}/{filename}.
        Mock::given(method("GET"))
            .and(path("/simple/numpy/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<!DOCTYPE html><html><body></body></html>"),
            )
            .mount(&server)
            .await;

        // The fallback fetch path is simple/{normalized}/{filename}.
        Mock::given(method("GET"))
            .and(path("/simple/numpy/numpy-2.0.0-py3-none-any.whl"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/zip")
                    .set_body_bytes(wheel_body.as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("pypi-stream-e2e-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp dir");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_id = uuid::Uuid::new_v4();

        let result = fetch_from_pypi_remote_streaming(
            &proxy,
            repo_id,
            "pypi-remote",
            &server.uri(),
            "numpy",
            "numpy-2.0.0-py3-none-any.whl",
            "simple",
        )
        .await
        .expect("streaming fetch via fallback path must succeed");

        let mut body_bytes = Vec::new();
        let mut body = result.body;
        while let Some(chunk) = body.next().await {
            body_bytes.extend_from_slice(&chunk.expect("stream chunk must be Ok"));
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(body_bytes, wheel_body);
    }

    #[test]
    fn test_serve_file_presign_redirect_precedes_streaming_1555() {
        // #1555: on a fresh proxy-cache hit, the PyPI remote download path must
        // attempt a presigned redirect (via the proxy's no-prefix handle)
        // BEFORE falling back to `proxy_check_cache_streaming` / streaming, so
        // large wheels are not streamed through the backend. The streaming
        // fallback (#1215 OOM relief) must still be present for cache misses.
        let src = include_str!("pypi.rs");
        let fn_start = src
            .find("async fn serve_file(")
            .expect("serve_file must exist");
        let next = src[fn_start + 1..]
            .find("\nasync fn ")
            .map(|p| fn_start + 1 + p)
            .unwrap_or(src.len());
        let body = &src[fn_start..next];

        let redirect_pos = body
            .find("pypi_proxy_cache_redirect(")
            .expect("serve_file MUST attempt pypi_proxy_cache_redirect (#1555)");
        let stream_pos = body
            .find("proxy_check_cache_streaming(")
            .expect("serve_file MUST retain the streaming fallback (#1215)");
        assert!(
            redirect_pos < stream_pos,
            "the presigned redirect attempt (#1555) MUST come BEFORE the \
             streaming cache check (#1215).",
        );
        assert!(
            body.contains("fetch_from_pypi_remote_streaming("),
            "serve_file MUST resolve the real upstream URL via \
             fetch_from_pypi_remote_streaming on a miss, never via a presumed \
             download URL (#1555).",
        );
    }

    #[test]
    fn test_pypi_virtual_blocks_private_member_2073() {
        // Verified-bug regression for #2073: a public PyPI virtual repo must not
        // serve a PRIVATE member's artifact to an anonymous / zero-grant caller.
        // Sibling bug #1804 (fixed by #1816) added the per-member authorization
        // helpers and wired them into the Maven download path, but the PyPI
        // handler was never updated, so the confused-deputy leak persisted for
        // PyPI. The fix routes serve_file's virtual branch through the SAME
        // `authorize_virtual_members` filter Maven uses, dropping members the
        // caller could not read directly BEFORE any of their bytes are fetched.
        //
        // This guards the wiring structurally (DB-free, runs in the offline lib
        // suite): the virtual branch of serve_file MUST authorize the member
        // list returned by fetch_virtual_members before iterating members, so a
        // private member behaves exactly as a 404 for a caller who could not
        // read it directly (its existence is never leaked).
        let src = include_str!("pypi.rs");
        let fn_start = src
            .find("async fn serve_file(")
            .expect("serve_file must exist");
        let next = src[fn_start + 1..]
            .find("\nasync fn ")
            .map(|p| fn_start + 1 + p)
            .unwrap_or(src.len());
        let body = &src[fn_start..next];

        let fetch_pos = body
            .find("fetch_virtual_members(")
            .expect("serve_file virtual branch must fetch members");
        let authz_pos = body.find("authorize_virtual_members(").expect(
            "serve_file MUST authorize virtual members per-caller before serving \
             any member's bytes (#2073)",
        );
        let loop_pos = body
            .find("for member in &members")
            .expect("serve_file must iterate virtual members");

        assert!(
            fetch_pos < authz_pos,
            "members must be authorized AFTER they are fetched (#2073)"
        );
        assert!(
            authz_pos < loop_pos,
            "members must be authorized BEFORE the per-member fetch loop so a \
             private member is dropped and never serves bytes to an \
             unauthorized caller (#2073)"
        );
    }

    #[test]
    fn test_pypi_proxy_cache_redirect_uses_no_prefix_handle_1555() {
        // The presign helper must sign through the proxy's no-prefix backend.
        let src = include_str!("pypi.rs");
        let fn_start = src
            .find("async fn pypi_proxy_cache_redirect(")
            .expect("pypi_proxy_cache_redirect must exist");
        let window_end = (fn_start + 1500).min(src.len());
        let window = &src[fn_start..window_end];
        assert!(
            window.contains("cache_storage_backend("),
            "pypi_proxy_cache_redirect MUST sign via cache_storage_backend() \
             (no-prefix handle), not a prefixed repo handle (#1555).",
        );
        assert!(
            window.contains("is_cache_fresh("),
            "pypi_proxy_cache_redirect MUST gate on is_cache_fresh (#1555).",
        );
    }

    // Behavioral coverage for `pypi_proxy_cache_redirect` (#1555). The two
    // short-circuit guards both return BEFORE any DB access, so these run
    // DB-free on a lazy pool: (1) presigned disabled, and (2) a filesystem
    // proxy backend that does not support redirects — both must yield None so
    // `serve_file` falls through to the streaming path on the rig / non-S3.
    #[tokio::test]
    async fn test_pypi_proxy_cache_redirect_none_when_presigned_disabled() {
        use crate::api::handlers::test_db_helpers as tdh;
        let pool = tdh::lazy_pool();
        let storage_path = std::env::temp_dir()
            .join(format!("pypi-presign-off-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &storage_path);
        // Default config: presigned_downloads_enabled = false.
        let state = tdh::build_state_with_proxy(pool.clone(), &storage_path, proxy.clone());

        let result = super::pypi_proxy_cache_redirect(
            &state,
            proxy.as_ref(),
            "pypi-remote",
            "simple/foo/foo-1.0-py3-none-any.whl",
        )
        .await;
        assert!(
            result.is_none(),
            "presigned disabled must short-circuit before any redirect"
        );
    }

    #[tokio::test]
    async fn test_pypi_proxy_cache_redirect_none_when_backend_no_redirect_support() {
        use crate::api::handlers::test_db_helpers as tdh;
        let pool = tdh::lazy_pool();
        let storage_path = std::env::temp_dir()
            .join(format!("pypi-presign-fs-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &storage_path);
        // Presigned ENABLED, but the filesystem proxy backend reports
        // supports_redirect() == false, so the helper must still return None
        // without touching the DB (the is_cache_fresh probe is never reached).
        let state =
            tdh::build_state_with_proxy_presigned(pool.clone(), &storage_path, proxy.clone());

        let result = super::pypi_proxy_cache_redirect(
            &state,
            proxy.as_ref(),
            "pypi-remote",
            "simple/foo/foo-1.0-py3-none-any.whl",
        )
        .await;
        assert!(
            result.is_none(),
            "filesystem (non-redirect) backend must yield None → stream fallback (#1555)"
        );
    }

    #[tokio::test]
    async fn test_build_streaming_file_response_headers() {
        use futures::stream;

        let wheel_data = Bytes::from_static(b"wheel-content");
        let data_len = wheel_data.len() as u64;
        let stream = stream::once(async move { Ok::<Bytes, crate::error::AppError>(wheel_data) });
        let result = crate::services::proxy_service::StreamingFetchResult {
            body: Box::pin(stream),
            content_type: Some("application/zip".to_string()),
            content_length: Some(data_len),
        };

        let response = build_streaming_file_response("numpy-1.0-py3-none-any.whl", result);

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/zip"),
            "content-type must be application/zip, got: {ct}"
        );
        let cd = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            cd.contains("numpy-1.0-py3-none-any.whl"),
            "content-disposition must contain filename, got: {cd}"
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(data_len.to_string().as_str()),
            "content-length must match"
        );
    }

    #[tokio::test]
    async fn test_proxy_check_cache_streaming_returns_none_on_miss() {
        // Empty MissingStorage → streaming probe returns None without errors.
        let proxy = build_proxy_service_no_db();
        let repo_id = uuid::Uuid::new_v4();

        let result = super::proxy_helpers::proxy_check_cache_streaming(
            &proxy,
            repo_id,
            "pypi-remote",
            "https://pypi.org/simple",
            "simple/numpy/numpy-2.0.0-py3-none-any.whl",
        )
        .await;

        assert!(
            result.is_none(),
            "cache miss must yield None, not Some(result)"
        );
    }
}
