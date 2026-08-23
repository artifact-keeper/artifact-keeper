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
use axum::http::header::{
    CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY,
};
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

use crate::api::handlers::cache_headers::{
    check_conditional_request_with, compute_etag, negotiated_cache_control,
    negotiated_cacheable_response, VARY_ACCEPT,
};
use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::error::AppError;
use crate::formats::pypi::PypiHandler;
use crate::formats::pypi_name::{NormalizedProjectName, PEP508_NAME_PATTERN};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::age_gate_service::AgeGateService;
use crate::services::upstream_metadata::metadata_http_client;
use chrono::Utc;

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
// PEP 508 project-name validation (the routed edge)
// ---------------------------------------------------------------------------

/// Validate a `:project` path segment against PEP 508 and return it in PEP 503
/// canonical form, or a 404.
///
/// This is the ONLY way a routed project segment enters the PyPI handlers, and
/// it runs before any curation gate, any DB lookup and any upstream fetch.
///
/// # Why validate rather than coerce
///
/// PEP 503 defines normalization as exactly `re.sub(r"[-_.]+", "-",
/// name).lower()` and says nothing about any other character, because it
/// presupposes a name that is already valid. PEP 508 supplies that
/// precondition: a name matches `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`
/// (case-insensitive). `acme sdk` is therefore not a project name and has no
/// correct normalization — which is precisely why our two coercions could
/// disagree about it ([`normalize_pep503`] drops the space to `acmesdk`,
/// [`PypiHandler::normalize_name`] turns it into `acme-sdk`), letting a client
/// clear a gate under one name and be served another package's bytes (#3077,
/// #3179, #3183). See [`crate::formats::pypi_name`].
///
/// # Why 404
///
/// Measured against the reference implementation, not inferred: pypi.org
/// returns `404` for `/simple/acme%20sdk/`, `/simple/acme!sdk/`,
/// `/simple/_leading/` and `/simple/trailing-/`, and `301`s a *valid* but
/// non-canonical name (`/simple/Django/`, `/simple/zope.interface/`) to its
/// canonical URL. A name that cannot exist has no route, so 404 — not 400 — is
/// the behaviour clients already handle.
///
/// # Why the body is "Invalid project name" and does not echo the segment
///
/// Two reasons, and both are load-bearing.
///
/// *It does not repeat the input.* Reflecting an unvalidated segment would hand
/// back the very characters [`normalize_pep503`] exists to strip, and a 404 that
/// repeats its input is a reflection sink. The rejected name is only logged.
///
/// *It is not "Package not found".* An absent-but-valid project already 404s
/// with that message, so reusing it would make a validation rejection and an
/// ordinary lookup miss indistinguishable -- to an operator debugging a broken
/// `pip install`, and to the tests that have to prove this change does not
/// over-reject. Distinct wording is what lets a test assert *which* 404 it got.
#[allow(clippy::result_large_err)]
fn parse_project_segment(project: &str) -> Result<NormalizedProjectName, Response> {
    NormalizedProjectName::parse(project).ok_or_else(|| {
        debug!(
            "rejecting PyPI project segment that is not a PEP 508 name (len {})",
            project.len()
        );
        AppError::NotFound("Invalid project name".to_string()).into_response()
    })
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

/// Best-effort extraction of a distribution version from a PyPI filename.
///
/// Wheels are `{name}-{version}(-{build})?-{py}-{abi}-{platform}.whl`, so the
/// version is the second `-`-separated field. Source distributions are
/// `{name}-{version}{ext}`, so the version is what remains after stripping the
/// extension and the trailing `-`-delimited segment boundary.
///
/// Returns `None` when the shape is not recognized. Callers must treat that as
/// "version unknown" and pass it through as `None` rather than substituting a
/// placeholder: a placeholder is compared as a literal version and silently
/// inverts version-constrained rules (#2912).
pub(crate) fn version_from_pypi_filename(filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let _name = parts.next()?;
        let version = parts.next()?;
        return (!version.is_empty()).then(|| version.to_string());
    }

    const SDIST_EXTS: [&str; 6] = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"];
    for ext in SDIST_EXTS {
        if let Some(stem) = filename.strip_suffix(ext) {
            // The project name may itself contain `-`, and a PEP 440 version does
            // not, so the version is the final `-`-delimited segment.
            let (_, version) = stem.rsplit_once('-')?;
            return (!version.is_empty()).then(|| version.to_string());
        }
    }

    None
}

/// The distribution a request ultimately refers to, with any PEP 658
/// `.metadata` suffix removed.
///
/// ALL trailing `.metadata` suffixes are stripped, not just one. The serve path
/// resolves a metadata request back to a distribution the same way, and the
/// curation gate must evaluate the distribution that will actually be served:
/// when the two disagree, a request naming the same wheel through a different
/// suffix shape (`…-1.0-py3-none-any.whl.metadata.metadata`) is version-parsed
/// as `None` — which skips version-constrained rules — while still resolving to
/// the blocked wheel, serving a blocked version's metadata. Both callers in
/// `download_or_metadata` share one call to this function so they cannot drift
/// apart again.
fn pypi_distribution_filename(filename: &str) -> &str {
    filename.trim_end_matches(".metadata")
}

/// Curation gate for PyPI proxy requests (#2912). Returns
/// `Err(403 response)` when a block rule matches.
///
/// Name matching is PEP 503-insensitive on both sides — the request name is
/// normalized and the rule pattern is folded the same way — so a rule written the
/// way PyPI displays the project (`PyYAML`, `my_package`) matches. `version` is
/// `None` on the index path, which identifies only a project; the download path
/// passes the version parsed from the distribution filename so exact-version
/// rules apply there. A `None` version skips version-constrained rules rather
/// than mis-evaluating them.
///
/// No-op when curation is disabled for the repository, and no-op for hosted
/// (`local` / `staging`) repositories: curation rules describe what may be pulled
/// from upstream, so applying them to a hosted repo would 403 that repository's
/// own published packages. On a rule evaluation error, fails open (logging the
/// repository and package so the unenforced request is greppable) rather than
/// taking the proxy down.
async fn enforce_pypi_curation(
    state: &SharedState,
    repo: &RepoInfo,
    project: &str,
    version: Option<&str>,
) -> Result<(), Response> {
    // Delegate to the shared, format-agnostic curation seam (#2930). PyPI was
    // the original (and once only) enforced format; the seam now lives in
    // `proxy_helpers` so every proxy format shares one implementation.
    proxy_helpers::enforce_curation(&state.db, repo, project, version).await
}

// ---------------------------------------------------------------------------
// GET /pypi/{repo_key}/simple/ — PEP 503 root index
// ---------------------------------------------------------------------------

async fn simple_root(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
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
        // Caller-authorized member walk (#3323): the root index is content, so
        // a member this caller may not read directly must not contribute its
        // project names to it.
        let members =
            proxy_helpers::authorized_virtual_members(&state.db, auth.as_ref(), repo.id).await?;

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
    let (content, _content_type, _budget_permit) = match proxy_helpers::proxy_fetch_capped_budgeted(
        proxy,
        repo_id,
        repo_key,
        &effective_upstream,
        &upstream_path,
        proxy_helpers::LARGE_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok(triple) => triple,
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
        // HTTP caching (#2773): serve the JSON root index through the shared
        // cacheable_response helper so it carries an ETag + Cache-Control and
        // honors If-None-Match (-> 304), matching conda/maven.
        return Ok(negotiated_cacheable_response(
            serde_json::to_vec(&json).unwrap(),
            "application/vnd.pypi.simple.v1+json",
            headers,
        ));
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

    // HTTP caching (#2773): compute a strong ETag over the rendered body and
    // honor If-None-Match here (rather than via the shared cacheable_response)
    // so the PEP 503 security headers below are preserved on the 200 path.
    //
    // #3406: this arm is the HTML half of an `Accept`-negotiated pair, so it
    // carries the same `Vary`/`Cache-Control` the shared helper emits for the
    // JSON half above. Open-coding the response must not open-code a weaker
    // cache contract.
    let cache_control = negotiated_cache_control(headers);
    let body = html.into_bytes();
    let etag = compute_etag(&body);
    if let Some(not_modified) =
        check_conditional_request_with(headers, &etag, cache_control, Some(VARY_ACCEPT))
    {
        return Ok(not_modified);
    }

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
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, cache_control)
        .header(VARY, VARY_ACCEPT)
        .body(Body::from(body))
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, project)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;
    // PEP 508 validation FIRST (#3186), before the curation gate, the local
    // lookup and any upstream fetch. An invalid segment is not a project name,
    // so there is nothing to gate and nothing to fetch.
    let normalized = parse_project_segment(&project)?;

    // Curation gate (#2912): block a curation-ruled package
    // before doing any local lookup or upstream fetch for it. The index request
    // names only a project, so version-constrained rules do not apply here — they
    // are enforced on the download path, which knows the version.
    enforce_pypi_curation(&state, &repo, normalized.as_str(), None).await?;

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
        normalized.as_str()
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

                let (content, content_type, _budget_permit) = if wants_json {
                    // Request the PEP 691 JSON form from upstream, cached under a
                    // format-qualified key so it never collides with the HTML index.
                    proxy_helpers::proxy_fetch_capped_with_cache_key_and_accept_budgeted(
                        proxy,
                        repo.id,
                        &repo_key,
                        &effective_upstream,
                        &upstream_path,
                        &format!("{}{}", upstream_path, PEP691_JSON_CACHE_SUFFIX),
                        Some(PEP691_JSON_CONTENT_TYPE),
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await?
                } else {
                    proxy_helpers::proxy_fetch_capped_budgeted(
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
                        rewrite_upstream_simple_json(&content, &repo_key, normalized.as_str())
                    {
                        let json = filter_pypi_simple_json_response(
                            &state,
                            &repo,
                            &effective_upstream,
                            normalized.as_str(),
                            json,
                        )
                        .await;
                        // HTTP caching (#2773): ETag + Cache-Control + 304.
                        return Ok(negotiated_cacheable_response(
                            json.into_bytes(),
                            PEP691_JSON_CONTENT_TYPE,
                            &headers,
                        ));
                    }
                }

                // Rewrite absolute download URLs to route through our proxy.
                if ct.contains("text/html") {
                    let html = String::from_utf8_lossy(&content);
                    let rewritten = rewrite_upstream_urls(&html, &repo_key, normalized.as_str());
                    let rewritten = filter_pypi_simple_html_response(
                        &state,
                        &repo,
                        &effective_upstream,
                        normalized.as_str(),
                        rewritten,
                    )
                    .await;
                    // HTTP caching (#2773): ETag + Cache-Control + 304.
                    return Ok(negotiated_cacheable_response(
                        rewritten.into_bytes(),
                        &ct,
                        &headers,
                    ));
                }

                // #2801: the upstream Content-Type is neither JSON (handled
                // above) nor `text/html` — a corporate proxy / quirky mirror
                // may have mislabeled the body (e.g. `application/octet-stream`).
                // Sniff the body instead of trusting the label and run it
                // through the SAME rewrite path; never serve the raw upstream
                // bytes, which carry un-rewritten offsite download URLs.
                return match sniff_simple_index(&content) {
                    SniffedSimpleIndex::Json => {
                        match rewrite_upstream_simple_json(&content, &repo_key, normalized.as_str())
                        {
                            Some(json) => {
                                let json = filter_pypi_simple_json_response(
                                    &state,
                                    &repo,
                                    &effective_upstream,
                                    normalized.as_str(),
                                    json,
                                )
                                .await;
                                Ok(negotiated_cacheable_response(
                                    json.into_bytes(),
                                    PEP691_JSON_CONTENT_TYPE,
                                    &headers,
                                ))
                            }
                            None => Ok(bad_upstream_simple_index()),
                        }
                    }
                    SniffedSimpleIndex::Html => {
                        let html = String::from_utf8_lossy(&content);
                        let rewritten =
                            rewrite_upstream_urls(&html, &repo_key, normalized.as_str());
                        let rewritten = filter_pypi_simple_html_response(
                            &state,
                            &repo,
                            &effective_upstream,
                            normalized.as_str(),
                            rewritten,
                        )
                        .await;
                        Ok(negotiated_cacheable_response(
                            rewritten.into_bytes(),
                            "text/html; charset=utf-8",
                            &headers,
                        ))
                    }
                    SniffedSimpleIndex::Binary => Ok(bad_upstream_simple_index()),
                };
            }
        }
        // For virtual repos, iterate through ALL members and union their
        // entries — both local DB rows and remote proxy responses — so a
        // package that exists partially in a local member doesn't shadow
        // the rest of upstream. See #1230.
        if repo.repo_type == RepositoryType::Virtual {
            // Caller-authorized member walk (#3323). Only the CONTENT walk is
            // narrowed: the PEP 708 isolation decision below
            // (`pypi_virtual_isolates_name`) and the priority map that feeds it
            // deliberately keep looking at every member, because narrowing an
            // isolation/shadowing decision by caller visibility would drop the
            // isolation a member the caller cannot see asserts and re-expose
            // the upstream name — dependency confusion.
            let members =
                proxy_helpers::authorized_virtual_members(&state.db, auth.as_ref(), repo.id)
                    .await?;

            if members.is_empty() {
                return Err(proxy_helpers::no_accessible_members_response());
            }

            // PEP 708 (#1600, priority-aware per #2311): when a local member
            // owns this name and no operator `tracks` declaration permits
            // merging, isolate the name to its local owner — but only against
            // Remote members the owning local outranks. A Remote member the
            // operator configured at equal or higher priority than the owning
            // local still surfaces below, so a lower-priority local owner
            // cannot hide a higher-priority upstream's versions from pip.
            // The download path makes the same per-member decision, keeping
            // index and download consistent.
            let owning_local_min_priority =
                proxy_helpers::pypi_virtual_isolates_name(&state.db, repo.id, normalized.as_str())
                    .await?;
            let member_priorities = if owning_local_min_priority.is_some() {
                proxy_helpers::fetch_virtual_member_priorities(&state.db, repo.id).await?
            } else {
                Default::default()
            };

            let mut local_artifacts: Vec<SimpleProjectArtifact> = Vec::new();
            let mut remote_response: Option<(Bytes, Option<String>)> = None;
            // #2967 R4: true when the surfaced remote_response came from a
            // SUPPRESSED member and has already been reduced to its
            // ownership-filtered form by `case_a_filter_remote_body`. Such a body
            // must never be re-run through `rewrite_upstream_urls` (which applies
            // no ownership filter); the render path below splices locals straight
            // into the filtered document instead.
            let mut remote_case_a = false;

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
                    normalized.as_str()
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
            // the virtual isolates the name to that member — rather than
            // unioning the remote's versions for it. Unioning an unrelated
            // public package that merely shares the name is a supply-chain hole
            // (`pip` prefers the higher public version). Local precedence is
            // the PEP 708-aligned default for a locally-owned name; a `tracks`
            // declaration re-enables the union (#1582).
            //
            // #2311: the guard is applied PER REMOTE MEMBER relative to member
            // priority. It only suppresses a Remote member the owning local
            // outranks (owning priority value strictly lower). A Remote member
            // at equal or higher priority than the owning local was explicitly
            // ranked above the internal package by the operator, so its
            // versions still surface.
            //
            // #2937: the suppression is distribution-granular, not name-coarse.
            // For a suppressed Remote member the virtual still UNIONS Case-A
            // distributions — platform/ABI-distinct wheels of a version the
            // owning local already provides (local ships linux 2.0, remote ships
            // windows 2.0) — while continuing to suppress Case-B distributions
            // (a version only the remote has, or a same-platform rebuild). The
            // profile is derived from the local owner's filenames collected in
            // the first pass, so the download path (which rebuilds the same
            // profile) admits the identical set and the two stay symmetric.
            let owned_profile = if owning_local_min_priority.is_some() {
                OwnedWheelProfile::from_filenames(
                    local_artifacts
                        .iter()
                        .map(|a| a.path.rsplit('/').next().unwrap_or(a.path.as_str())),
                )
            } else {
                OwnedWheelProfile::default()
            };

            // Second pass: fetch a remote index from every remote member, but
            // narrow a suppressed member's contribution to its Case-A unions.
            for member in &members {
                if member.repo_type != RepositoryType::Remote {
                    continue;
                }
                // Suppressed (owning local outranks this remote): keep only its
                // Case-A distributions rather than dropping it whole (#2937). A
                // member missing from the priority map cannot outrank the owning
                // local: treat it as lowest priority (fail closed → suppressed).
                let case_a_only = match owning_local_min_priority {
                    Some(local_min) => {
                        let member_priority = member_priorities
                            .get(&member.id)
                            .copied()
                            .unwrap_or(i32::MAX);
                        local_min < member_priority
                    }
                    None => false,
                };
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

                // #2912: apply THIS member's curation rules before its index is
                // fetched, mirroring the per-member age gate below (#2066). The
                // entry gate above only saw the virtual repository's own flags, so
                // without this a virtual repository fronting a curated remote —
                // the normal curated-mirror topology — served blocked packages. A
                // block suppresses this member's contribution rather than failing
                // the whole listing, exactly as the age gate filters it.
                let member_info = proxy_helpers::repo_info_from_member(member);
                if enforce_pypi_curation(&state, &member_info, normalized.as_str(), None)
                    .await
                    .is_err()
                {
                    continue;
                }

                let member_index_path = fetch_pypi_upstream_index_path(&state.db, member.id).await;
                let (effective_upstream, upstream_path) = pypi_upstream_url_and_path(
                    upstream_url,
                    &format!("{}/", normalized),
                    &member_index_path,
                );
                let result = if wants_json {
                    proxy_helpers::proxy_fetch_capped_with_cache_key_and_accept_budgeted(
                        proxy,
                        member.id,
                        &member.key,
                        &effective_upstream,
                        &upstream_path,
                        &format!("{}{}", upstream_path, PEP691_JSON_CACHE_SUFFIX),
                        Some(PEP691_JSON_CONTENT_TYPE),
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await
                } else {
                    proxy_helpers::proxy_fetch_capped_budgeted(
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
                    Ok((content, content_type, _budget_permit)) => {
                        // #2066: apply THIS gated remote member's age gate to its
                        // own contribution before it is merged with local members
                        // below. Locals stay unfiltered (they are not gated);
                        // filtering the remote member here mirrors the direct
                        // simple-index path so a young version of a gated member
                        // is not leaked through the virtual listing.
                        let ct = content_type.clone().unwrap_or_default();
                        let content = if wants_json && ct.contains("json") {
                            let filtered = filter_pypi_simple_json_response(
                                &state,
                                &member_info,
                                &effective_upstream,
                                normalized.as_str(),
                                String::from_utf8_lossy(&content).into_owned(),
                            )
                            .await;
                            Bytes::from(filtered)
                        } else if ct.contains("text/html") {
                            let filtered = filter_pypi_simple_html_response(
                                &state,
                                &member_info,
                                &effective_upstream,
                                normalized.as_str(),
                                String::from_utf8_lossy(&content).into_owned(),
                            )
                            .await;
                            Bytes::from(filtered)
                        } else {
                            content
                        };
                        // #2937: a suppressed Remote member contributes only its
                        // Case-A distributions (platform/ABI-distinct wheels of a
                        // version the owning local already provides); Case-B
                        // entries (remote-only versions, same-platform rebuilds)
                        // are dropped here, mirroring the download gate below.
                        let content = if case_a_only {
                            remote_case_a = true;
                            case_a_filter_remote_body(
                                &content,
                                &owned_profile,
                                &repo_key,
                                normalized.as_str(),
                            )
                        } else {
                            content
                        };
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
            let tracks =
                pypi_project_tracks_for(&state.db, &local_member_ids, normalized.as_str()).await;

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
                        normalized.as_str(),
                        &local_artifacts,
                        &tracks,
                    );
                }
                (_, Some((content, content_type))) => {
                    let ct = content_type.unwrap_or_else(|| "text/html; charset=utf-8".to_string());

                    // #2967 R4: a SUPPRESSED member's body has already been reduced
                    // to its ownership-filtered form — a rebuilt AK-pathed PEP 503
                    // index or a fail-closed PEP 691 listing — by
                    // `case_a_filter_remote_body`. It must NEVER reach the in-place
                    // `rewrite_upstream_urls` rewriter (no ownership filter; its
                    // `[^>]*?` can't cross a `>`, so an anchor whose `href` follows a
                    // `>` inside an attribute would be left off-site → dependency
                    // confusion). Classify by the FILTERED body's own bytes (never the
                    // upstream's possibly-mislabeled Content-Type) and splice locals
                    // straight in.
                    if remote_case_a {
                        return match sniff_simple_index(&content) {
                            SniffedSimpleIndex::Json => {
                                let merged = merge_local_into_remote_simple_json(
                                    &content,
                                    &repo_key,
                                    normalized.as_str(),
                                    &local_artifacts,
                                    &tracks,
                                )
                                .unwrap_or_else(|| empty_pep691_listing(normalized.as_str()));
                                Ok(negotiated_cacheable_response(
                                    merged.into_bytes(),
                                    PEP691_JSON_CONTENT_TYPE,
                                    &headers,
                                ))
                            }
                            SniffedSimpleIndex::Html => {
                                // The rebuild is already AK-pathed; splice locals
                                // WITHOUT rewrite_upstream_urls.
                                let merged = merge_local_into_remote_simple_html(
                                    &String::from_utf8_lossy(&content),
                                    &repo_key,
                                    normalized.as_str(),
                                    &local_artifacts,
                                    &tracks,
                                );
                                Ok(negotiated_cacheable_response(
                                    merged.into_bytes(),
                                    "text/html; charset=utf-8",
                                    &headers,
                                ))
                            }
                            // Fail closed: filter emitted nothing usable → empty
                            // listing, never raw upstream bytes.
                            SniffedSimpleIndex::Binary => {
                                let merged = merge_local_into_remote_simple_json(
                                    empty_pep691_listing(normalized.as_str()).as_bytes(),
                                    &repo_key,
                                    normalized.as_str(),
                                    &local_artifacts,
                                    &tracks,
                                )
                                .unwrap_or_else(|| empty_pep691_listing(normalized.as_str()));
                                Ok(negotiated_cacheable_response(
                                    merged.into_bytes(),
                                    PEP691_JSON_CONTENT_TYPE,
                                    &headers,
                                ))
                            }
                        };
                    }

                    // JSON client + JSON upstream: rewrite the upstream download
                    // URLs and splice in local entries, preserving PEP 700
                    // `upload-time` on both. Upstreams that returned HTML despite
                    // the JSON request fall through to the HTML merge below.
                    if wants_json && ct.contains("json") {
                        if let Some(json) = merge_local_into_remote_simple_json(
                            &content,
                            &repo_key,
                            normalized.as_str(),
                            &local_artifacts,
                            &tracks,
                        ) {
                            // HTTP caching (#2773): ETag + Cache-Control + 304.
                            return Ok(negotiated_cacheable_response(
                                json.into_bytes(),
                                PEP691_JSON_CONTENT_TYPE,
                                &headers,
                            ));
                        }
                    }

                    if ct.contains("text/html") {
                        let html = String::from_utf8_lossy(&content);
                        let rewritten =
                            rewrite_upstream_urls(&html, &repo_key, normalized.as_str());
                        let merged = merge_local_into_remote_simple_html(
                            &rewritten,
                            &repo_key,
                            normalized.as_str(),
                            &local_artifacts,
                            &tracks,
                        );
                        // HTTP caching (#2773): ETag + Cache-Control + 304.
                        return Ok(negotiated_cacheable_response(
                            merged.into_bytes(),
                            &ct,
                            &headers,
                        ));
                    }

                    // #2801: the upstream Content-Type is neither JSON (handled
                    // above) nor `text/html` — a proxy / quirky mirror may have
                    // mislabeled the body (e.g. `application/octet-stream`).
                    // Sniff the body and run it through the SAME merge path
                    // (splicing local members) instead of serving raw upstream
                    // bytes with un-rewritten offsite download URLs.
                    return match sniff_simple_index(&content) {
                        SniffedSimpleIndex::Json => {
                            match merge_local_into_remote_simple_json(
                                &content,
                                &repo_key,
                                normalized.as_str(),
                                &local_artifacts,
                                &tracks,
                            ) {
                                Some(json) => Ok(negotiated_cacheable_response(
                                    json.into_bytes(),
                                    PEP691_JSON_CONTENT_TYPE,
                                    &headers,
                                )),
                                None => Ok(bad_upstream_simple_index()),
                            }
                        }
                        SniffedSimpleIndex::Html => {
                            let html = String::from_utf8_lossy(&content);
                            let rewritten =
                                rewrite_upstream_urls(&html, &repo_key, normalized.as_str());
                            let merged = merge_local_into_remote_simple_html(
                                &rewritten,
                                &repo_key,
                                normalized.as_str(),
                                &local_artifacts,
                                &tracks,
                            );
                            Ok(negotiated_cacheable_response(
                                merged.into_bytes(),
                                "text/html; charset=utf-8",
                                &headers,
                            ))
                        }
                        SniffedSimpleIndex::Binary => Ok(bad_upstream_simple_index()),
                    };
                }
            }
        }

        return Err(AppError::NotFound("Package not found".to_string()).into_response());
    }

    let tracks = pypi_project_tracks_for(&state.db, &[repo.id], normalized.as_str()).await;
    build_simple_project_response(
        &headers,
        &repo_key,
        normalized.as_str(),
        &simple_artifacts,
        &tracks,
    )
}

// ---------------------------------------------------------------------------
// Shared response builder for simple project listings (HTML + PEP 691 JSON)
// ---------------------------------------------------------------------------

/// Render the simple project index for a given set of artifacts, using either
/// HTML (PEP 503) or JSON (PEP 691) based on the Accept header.
/// URLs in the response always point through `repo_key` (the virtual or
/// direct repo the client originally requested).
/// Render ONE local-member distribution as a PEP 691 `files[]` entry.
///
/// The single source of truth for what a locally-stored artifact looks like in
/// JSON, shared by the direct emitter ([`build_simple_project_response`]) and
/// the virtual union ([`merge_local_into_remote_simple_json`]) (#2748).
///
/// They used to be separate copies, and they had drifted: only the direct copy
/// advertised the PEP 658/714 `core-metadata` flag. Because the virtual repo
/// picks its emitter at request time — [`build_simple_project_response`] when no
/// remote member answered, this one when one did, and a remote fetch miss is a
/// silent `debug!` — the *same* URL advertised `core-metadata` or not depending
/// on whether an upstream happened to respond. Installers that use the flag
/// (pip, uv) therefore lost the metadata fast path through a virtual repository
/// and had to download whole wheels to read `Requires-Dist`.
fn local_simple_file_json(
    a: &SimpleProjectArtifact,
    repo_key: &str,
    normalized: &str,
) -> serde_json::Value {
    let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
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
    // PEP 658/714: a wheel ships its METADATA and AK already serves it at
    // `<file>.metadata`, so advertise `core-metadata` here so installers
    // (pip/uv) can fetch metadata without downloading the whole wheel. sdists
    // carry no such metadata, so they must not advertise it. Surfaced by the
    // conformance corpus (pip harvest).
    if filename.ends_with(".whl") {
        file["core-metadata"] = serde_json::Value::Bool(true);
    }
    // PEP 700: surface the distribution's upload timestamp as an RFC 3339 /
    // ISO 8601 `upload-time` field (#1773).
    if let Some(ut) = a.upload_time {
        file["upload-time"] =
            serde_json::Value::String(ut.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    file
}

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
            .map(|a| local_simple_file_json(a, repo_key, normalized))
            .collect();

        // PEP 691 `versions`: dedupe, then order by PEP 440 (#3106).
        let versions = sorted_pep440_versions(artifacts.iter().filter_map(|a| a.version.clone()));

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

        // HTTP caching (#2773): ETag + Cache-Control + 304, via the shared
        // helper used by conda/maven.
        return Ok(negotiated_cacheable_response(
            serde_json::to_vec(&json).unwrap(),
            "application/vnd.pypi.simple.v1+json",
            headers,
        ));
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
        let raw_filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        // Security: the filename is publisher-controlled, so it must be
        // HTML-escaped before it is spliced into this Simple-index page —
        // otherwise a filename like `x"><script>...</script>.whl` is stored XSS
        // that runs for anyone (incl. admins) viewing the index.
        let filename = html_escape(raw_filename);
        let url = format!(
            "/pypi/{}/simple/{}/{}#sha256={}",
            repo_key,
            normalized,
            filename,
            html_escape(&a.checksum_sha256)
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

        // PEP 658/714: advertise the wheel's METADATA (HTML parity with the JSON
        // branch), since AK serves `<file>.metadata`.
        let cm_attr = if raw_filename.ends_with(".whl") {
            " data-core-metadata=\"true\""
        } else {
            ""
        };

        html.push_str(&format!(
            "<a href=\"{}\"{}{}{}>{}</a><br/>\n",
            url, rp_attr, ut_attr, cm_attr, filename
        ));
    }

    html.push_str("</body>\n</html>\n");

    // HTTP caching (#2773): ETag + Cache-Control + 304. This HTML variant
    // carries no extra security headers, so the shared helper suffices.
    Ok(negotiated_cacheable_response(
        html.into_bytes(),
        "text/html; charset=utf-8",
        headers,
    ))
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
        let raw_filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        if existing.contains(raw_filename) {
            continue;
        }
        // Security: escape the publisher-controlled filename before splicing it
        // into the merged HTML index (stored-XSS otherwise; see the sibling
        // build_simple_project_response HTML branch).
        let filename = html_escape(raw_filename);
        let url = format!(
            "/pypi/{}/simple/{}/{}#sha256={}",
            repo_key,
            normalized,
            filename,
            html_escape(&a.checksum_sha256)
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
        // PEP 658/714: advertise wheel METADATA (HTML parity with the JSON path).
        let cm_attr = if raw_filename.ends_with(".whl") {
            " data-core-metadata=\"true\""
        } else {
            ""
        };
        local_lines.push_str(&format!(
            "<a href=\"{}\"{}{}{}>{}</a><br/>\n",
            url, rp_attr, ut_attr, cm_attr, filename
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
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_pypi_repo(&state.db, &repo_key).await?;

    // Curation gate (#2912): a blocked package must never serve any version,
    // whether via PEP 658 metadata or a regular file download, so this runs before
    // either branch below. The version is parsed from the distribution filename so
    // exact- and range-constrained rules apply on this path; an unrecognized
    // filename shape yields `None`, which matches on name only.
    //
    // `distribution` is resolved ONCE and reused by the metadata branch below:
    // the gate must evaluate exactly the distribution the serve path resolves,
    // or a suffix shape that parses to a different (or no) version slips past a
    // version-constrained rule and is then served anyway.
    // PEP 508 validation FIRST (#3186). This covers BOTH branches below --
    // the PEP 658 `.metadata` resource and the regular distribution download --
    // because both are reached through this one route.
    let normalized = parse_project_segment(&project)?;
    let distribution = pypi_distribution_filename(&filename);
    let requested_version = version_from_pypi_filename(distribution);
    enforce_pypi_curation(
        &state,
        &repo,
        normalized.as_str(),
        requested_version.as_deref(),
    )
    .await?;

    // PEP 658: serve metadata from the remote upstream when possible. If the
    // upstream advertises metadata but returns 404, fall back to extracting it
    // from the wheel so clients do not see the hard failure that motivated
    // stripping these attributes in the first place.
    if filename.ends_with(".metadata") {
        // PEP 658 names exactly one metadata resource per distribution,
        // `<distribution>.metadata`; a stacked suffix names none. Refusing the
        // shape outright keeps a request that is not a metadata request from
        // resolving back to a distribution at all — defence in depth behind the
        // shared `distribution` above, which is what actually gates curation.
        if filename
            .strip_suffix(".metadata")
            .is_some_and(|rest| rest.ends_with(".metadata"))
        {
            return Err(AppError::NotFound(format!("File not found: {}", filename)).into_response());
        }
        let real_filename = distribution;
        if repo.repo_type == RepositoryType::Virtual {
            return serve_virtual_metadata(
                &state,
                auth.as_ref(),
                &repo,
                &normalized,
                requested_version.as_deref(),
                real_filename,
            )
            .await;
        }
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(upstream_url), Some(proxy)) = (&repo.upstream_url, &state.proxy_service) {
                return serve_remote_metadata(
                    &state,
                    proxy,
                    repo.id,
                    &repo.key,
                    upstream_url,
                    // NORMALIZED, exactly as the virtual arm above. This
                    // branch was left on the raw segment when the virtual one
                    // was fixed, so a curation block on a direct Remote repo
                    // was still evadable by spelling: the gate saw "acmesdk"
                    // and the fetch resolved "acme-sdk".
                    // The VALIDATED, normalized name -- not the raw segment.
                    // This is #3179's fix, now enforced by the type system:
                    // `serve_remote_metadata` no longer accepts a `&str`.
                    &normalized,
                    real_filename,
                )
                .await;
            }
        }
        return serve_metadata(&state, &state.db, &repo, real_filename).await;
    }

    // Regular file download.
    //
    // The NORMALIZED name, not the raw path segment (#3183). The curation gate
    // above and every gate inside `serve_file` key on `normalize_pep503`, but
    // the upstream fetch re-normalizes with `PypiHandler::normalize_name`, and
    // the two disagree: `normalize_pep503` silently DROPS any character outside
    // [A-Za-z0-9._-] without marking a separator, while `normalize_name` maps
    // every non-alphanumeric to '-'. So "acme sdk" cleared the gates as
    // "acmesdk" -- owned by nobody, blocked by nobody -- and then fetched
    // "acme-sdk", which is precisely the private package the dependency-
    // confusion gate exists to protect. That served the attacker's WHEEL BYTES.
    //
    // `normalize_name` is idempotent on `normalize_pep503` output (see
    // `test_normalize_name_is_idempotent_on_pep503_output`), so upstream URLs
    // and proxy-cache keys are byte-identical for every well-formed name.
    // The VALIDATED, normalized name -- not the raw segment. This is #3183's
    // fix, now enforced by the type system: `serve_file` no longer accepts a
    // `&str`, so the gates it runs and the upstream fetch it performs cannot
    // key on different strings.
    let response = serve_file(
        &state,
        &repo,
        &repo_key,
        &normalized,
        &filename,
        auth.as_ref(),
        &ctx,
    )
    .await?;

    // #2955 on-demand curation ingestion: when a proxy serves a real pypi
    // distribution, enqueue a pending curation row (name+version+filename) for
    // any staging repo curating this proxy. Best-effort and spawned so the
    // download latency is untouched; the scheduler enriches it from the upstream
    // (PEP 740 provenance) and runs attestation verification off this hot path.
    //
    // Deliberately placed AFTER `serve_file` returns success. `download_or_metadata`
    // does no authorization of its own — `resolve_pypi_repo` is a bare key lookup
    // and `enforce_pypi_curation` is a content gate, not an access gate; the
    // repository access check lives inside `serve_file`. Enqueuing before that
    // call let an unauthenticated caller write a row for a package that does not
    // exist (the name and version are parsed straight out of the request path
    // and never contacted upstream), for a staging repo belonging to another
    // tenant, with no cap — unbounded catalog inflation plus a poisoned review
    // queue. Gating on a served 2xx/3xx means the distribution provably resolved
    // and the caller was allowed to have it. npm's seam is already shaped this
    // way: it enqueues only after a version document resolves out of a real
    // packument.
    //
    // The predicate itself lives in `proxy_helpers` so the relocation is covered
    // by a test (#3233): `response_admits_ondemand_ingest` documents why 3xx
    // counts (#1555 presigned redirects) and pins that 401/403/404 do not.
    let served =
        crate::api::handlers::proxy_helpers::response_admits_ondemand_ingest(response.status());
    if served && repo.repo_type == RepositoryType::Remote && !filename.ends_with(".metadata") {
        if let Some(version) = requested_version.clone() {
            // `normalized.as_str()` (#3186): the catalog row must key on the same
            // validated, PEP 503-canonical name every gate above and `serve_file`
            // used. Taking the raw `project` segment here would reintroduce the
            // gate-on-one-string / record-another divergence the newtype exists to
            // make unrepresentable — and the curation catalog is a gate input, so
            // it is exactly the kind of fourth code path #3186 was written for.
            let catalog_name = normalized.as_str().to_string();
            let entry = crate::services::curation_sync::CurationPackageEntry {
                format: "pypi".to_string(),
                package_name: catalog_name.clone(),
                version: version.clone(),
                release: None,
                architecture: None,
                checksum_sha256: None,
                upstream_path: distribution.to_string(),
                metadata: serde_json::json!({
                    "name": catalog_name,
                    "version": version,
                    "_ak_dist": { "filename": distribution },
                }),
                primary_metadata: None,
            };
            let db = state.db.clone();
            let proxy_id = repo.id;
            tokio::spawn(async move {
                crate::api::handlers::proxy_helpers::enqueue_curation_on_demand(
                    &db, proxy_id, "remote", entry,
                )
                .await;
            });
        }
    }

    Ok(response)
}

/// Resolve a PEP 658 metadata request through a virtual repository's members.
///
/// Virtual repositories do not own artifacts, so metadata cannot be served
/// against the virtual repository ID. Resolve members in priority order,
/// applying the member authorization filter, the per-member curation gate, and
/// the PEP 708 dependency-confusion isolation the download path uses.
///
/// It is NOT full parity with the download path, and the difference is worth
/// stating rather than implying: `serve_file` additionally enforces the
/// download age gate, the inline scan-and-block gate, and the quarantine check
/// (`serve_metadata`'s query selects no quarantine columns). So a quarantined
/// or age-withheld distribution returns 403/451 on download while its METADATA
/// -- name, version, full `Requires-Dist` -- is served here. That is a
/// disclosure gap, not an install bypass, and it is tracked separately.
///
/// A missing distribution falls through to the next member. Other failures are
/// recorded and returned only if NO member serves, so one misconfigured
/// upstream cannot deny metadata for a package another member owns.
/// Takes ONLY the normalized project name. The raw path segment is
/// deliberately not a parameter: every gate here keys on the PEP 503 form, and
/// an earlier revision passed the raw segment to the upstream fetch, which
/// re-normalizes with a DIFFERENT function. Not having the raw name in scope
/// is what stops that from being reintroduced.
async fn serve_virtual_metadata(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo: &RepoInfo,
    normalized_project: &NormalizedProjectName,
    requested_version: Option<&str>,
    filename: &str,
) -> Result<Response, Response> {
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo.id).await?;
    if members.is_empty() {
        return Err(proxy_helpers::no_accessible_members_response());
    }

    let members =
        proxy_helpers::authorize_virtual_members(&state.db, auth, virtual_repo.id, members).await;
    // #3452: a fully-filtered member set must answer the SAME body the
    // genuinely-empty set above answers, or the pair is an existence oracle
    // over the private members this virtual aggregates.
    if members.is_empty() {
        return Err(proxy_helpers::no_accessible_members_response());
    }

    // Keep PEP 658 metadata resolution symmetric with the simple-index and
    // distribution-download paths. A higher-priority local owner suppresses a
    // lower-priority Remote member unless the requested distribution is an
    // admitted Case-A platform wheel. Without this gate, a direct or stale
    // `.metadata` URL could expose a remote-only Case-B version that neither
    // the index advertises nor the download route serves.
    let guard = PypiOwnershipGuard::resolve(
        &state.db,
        virtual_repo.id,
        &members,
        normalized_project.as_str(),
    )
    .await?;

    let mut first_member_error: Option<Response> = None;
    for member in members {
        // #3404 (sibling of the `serve_file` fix): apply the guard BEFORE the
        // local-first `serve_metadata` call below, not after it.
        //
        // The check used to live inside the Remote branch further down, so a
        // suppressed member's locally-cached `artifacts` row was read — and its
        // METADATA returned — by the local-first lookup that runs for every
        // member. Fixing only the wheel path would have left the sidecar
        // exposing exactly the suppressed distribution the wheel now 404s for.
        if guard.suppresses(member.id, &member.repo_type, filename) {
            debug!(
                member_key = %member.key,
                %filename,
                "virtual pypi member suppressed by ownership guard; skipping metadata"
            );
            continue;
        }

        let member_info = proxy_helpers::repo_info_from_member(&member);
        if enforce_pypi_curation(
            state,
            &member_info,
            normalized_project.as_str(),
            requested_version,
        )
        .await
        .is_err()
        {
            continue;
        }

        // Local-first for EVERY member, including Remote ones -- mirroring
        // `serve_file`, which calls `local_fetch_or_redirect_by_suffix` before
        // its own Remote branch precisely because Remote-typed repos do carry
        // `artifacts` rows (direct upload, replication, promotion).
        //
        // Dispatching on `repo_type` alone made metadata and the wheel resolve
        // from different places: the download served a Remote member's stored
        // bytes while `.metadata` skipped the row and fetched the upstream's.
        // PEP 658 metadata is not hash-tied to the distribution, so pip would
        // resolve against one package's dependencies and install another's,
        // with nothing anywhere to detect it.

        // Set when this member owns the name but its bytes are temporarily
        // unavailable; confines the fallback to this member (#3372).
        let mut owns_unavailable_bytes = false;
        match serve_metadata(state, &state.db, &member_info, filename).await {
            Ok(response) => return Ok(response),
            Err(response) if response.status() == StatusCode::NOT_FOUND => {}
            // 507: this member HAS an `artifacts` row for the file, but
            // storage could not produce the bytes. For a hosted row that is
            // after the coordinated re-read; for a proxy-cache-backed row
            // `serve_metadata` answers immediately, because no local writer
            // owns that key and the re-read cannot succeed -- the recovery
            // that works is the upstream re-fetch just below, which is exactly
            // why it hands us the 507 straight away (#3463). Either way this
            // is NOT "this member does not have it" -- the
            // member owns the name, so falling through to a lower-priority
            // member would serve THAT member's upstream METADATA for a
            // distribution this one owns. We still try this member's OWN
            // upstream (same provenance the wheel would resolve to), but the
            // flag below stops resolution at this member either way (#3372).
            Err(response) if response.status() == StatusCode::INSUFFICIENT_STORAGE => {
                owns_unavailable_bytes = true;
                if first_member_error.is_none() {
                    first_member_error = Some(response);
                }
            }
            // A non-404 here is a storage or DB fault, or a 503 from the
            // decode-permit fast-fail -- not "this member does not have it".
            // Swallowing it would fall through to a lower-priority REMOTE
            // member and serve the upstream's metadata for a distribution this
            // member holds locally, which is exactly the bytes-mismatch the
            // local-first ordering exists to prevent, reappearing under load.
            Err(response) => {
                if first_member_error.is_none() {
                    first_member_error = Some(response);
                }
                continue;
            }
        }

        let result = if member.repo_type == RepositoryType::Remote {
            // Suppression already applied at the top of the loop (#3404).
            match (&member.upstream_url, state.proxy_service.as_ref()) {
                (Some(upstream_url), Some(proxy)) => {
                    serve_remote_metadata(
                        state,
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        // The NORMALIZED name, not the raw path segment.
                        //
                        // Every gate above keys on `normalized_project`
                        // (`normalize_pep503`), but the upstream fetch
                        // re-normalizes with `PypiHandler::normalize_name`,
                        // and the two disagree: `normalize_pep503` silently
                        // DROPS any character outside [A-Za-z0-9._-] without
                        // marking a separator, while `normalize_name` maps
                        // every non-alphanumeric to '-'. So "acme sdk" clears
                        // the gate as "acmesdk" -- owned by nobody -- and then
                        // fetches "acme-sdk", which is precisely the private
                        // package the gate exists to protect.
                        //
                        // `normalize_name` is idempotent on PEP 503 output, so
                        // passing the normalized name keeps the policy string
                        // and the fetch string identical.
                        normalized_project,
                        filename,
                    )
                    .await
                }
                _ => continue,
            }
        } else {
            // Local storage was already tried for this member above.
            //
            // A Local/Staging member that owns the name but could not produce
            // its bytes must not fall through either. `pypi_virtual_isolates_name`
            // does suppress lower-priority Remotes for a Local-owned name, so
            // this is belt-and-braces — but the substitution guard should not
            // depend on a second mechanism agreeing with it (#3372).
            if owns_unavailable_bytes {
                return Err(first_member_error.take().unwrap_or_else(|| {
                    (
                        StatusCode::INSUFFICIENT_STORAGE,
                        "artifact metadata unavailable; retry later",
                    )
                        .into_response()
                }));
            }
            continue;
        };

        // M2: record and continue, do NOT abort the whole resolution.
        //
        // `serve_file`'s virtual loop logs and continues on a member error;
        // this returned immediately on any non-404. Upstream 401/403/5xx map
        // to BadGateway and an SSRF-blocked href maps to 400, so one Remote
        // member with expired credentials at priority 0 made EVERY
        // locally-owned package's metadata 502 -- while the sibling wheel
        // download succeeded from the local member. That is the exact topology
        // this function exists to serve.
        //
        // The first non-404 is kept and returned only if nothing serves, so a
        // genuine upstream failure is still visible rather than masked as a
        // 404.
        match result {
            Ok(response) => return Ok(response),
            Err(response) => {
                if response.status() != StatusCode::NOT_FOUND && first_member_error.is_none() {
                    first_member_error = Some(response);
                }
                // This member owns the name (it holds an `artifacts` row for
                // the file) and neither its storage nor its own upstream could
                // serve it. Stop here rather than letting a lower-priority
                // member answer for a name it does not own -- that is the
                // metadata/wheel mismatch the local-first ordering exists to
                // prevent (#3372).
                if owns_unavailable_bytes {
                    return Err(first_member_error.take().unwrap_or_else(|| {
                        (
                            StatusCode::INSUFFICIENT_STORAGE,
                            "artifact metadata unavailable; retry later",
                        )
                            .into_response()
                    }));
                }
                continue;
            }
        }
    }

    if let Some(error) = first_member_error {
        return Err(error);
    }

    Err(
        AppError::NotFound("Metadata not found in any member repository".to_string())
            .into_response(),
    )
}
/// Serve a PEP 658 `.metadata` resource from a remote upstream.
///
/// `project` is a [`NormalizedProjectName`] (#3186), so the string this fetches
/// with is by construction the same string the curation gate in
/// `download_or_metadata` evaluated.
async fn serve_remote_metadata(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &NormalizedProjectName,
    filename: &str,
) -> Result<Response, Response> {
    let metadata_filename = format!("{}.metadata", filename);
    let cache_path = build_pypi_proxy_cache_path(project, &metadata_filename);

    // The probe must stay ahead of target resolution (#3300): resolving reads
    // the upstream simple index through `proxy_fetch_uncached`, so a probe
    // behind it pays an upstream round-trip even on a hit. Keyed on the
    // sidecar's own cache path — the key the fetch below writes.
    //
    // A probe error counts as a miss, so a cache fault degrades to a refetch
    // rather than failing the request.
    if let Ok(Some((content, _content_type, content_encoding))) = proxy
        .cached_metadata_if_servable(
            &proxy_helpers::build_remote_repo_with_format(
                repo_id,
                repo_key,
                upstream_url,
                RepositoryFormat::Pypi,
            ),
            &cache_path,
        )
        .await
    {
        return Ok(pep658_metadata_response(
            content,
            content_encoding.as_deref(),
        ));
    }

    let index_path = fetch_pypi_upstream_index_path(&state.db, repo_id).await;
    let target = resolve_pypi_remote_fetch_target(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        project,
        &metadata_filename,
        &index_path,
    )
    .await?;

    let remote_repo = proxy_helpers::build_remote_repo_with_format(
        repo_id,
        repo_key,
        &target.fetch_base,
        RepositoryFormat::Pypi,
    );

    // Fetching through the cache is what lets the probe above ever hit: the
    // `fetch_upstream_direct_*` family bypasses the cache in both directions.
    // This stores the body and its upstream `Content-Encoding` under
    // `target.cache_path` (`simple/{project}/{dist}.metadata`), which is
    // distinct from the distribution's own key.
    match proxy
        .fetch_artifact_with_cache_path_capped(
            &remote_repo,
            &target.fetch_path,
            &target.cache_path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await
    {
        Ok((content, _content_type, content_encoding)) => Ok(pep658_metadata_response(
            content,
            content_encoding.as_deref(),
        )),
        Err(AppError::NotFound(_)) => {
            let wheel_target = resolve_pypi_remote_fetch_target(
                proxy,
                repo_id,
                repo_key,
                upstream_url,
                project,
                filename,
                &index_path,
            )
            .await?;
            let wheel_repo = proxy_helpers::build_remote_repo_with_format(
                repo_id,
                repo_key,
                &wheel_target.fetch_base,
                RepositoryFormat::Pypi,
            );
            // Unlike the arm above, this one PARSES the upstream bytes: it
            // opens the wheel as a zip to read `*.dist-info/METADATA`. A coded
            // wheel is not a parseable zip, so before #3193 a perfectly valid
            // wheel behind a gzipping intermediary answered "Metadata not
            // available" — forwarding a header would not have helped, the bytes
            // have to be DECODED before the parser sees them.
            //
            // `_capped` at `DEFAULT_METADATA_MAX_BYTES` is the same ceiling the
            // uncapped `fetch_artifact_with_cache_path` already delegates with,
            // so the byte budget is unchanged; the capped form is used because
            // it is the variant that reports the coding (#3184).
            let (wheel, _content_type, wheel_encoding) = proxy
                .fetch_artifact_with_cache_path_capped(
                    &wheel_repo,
                    &wheel_target.fetch_path,
                    &wheel_target.cache_path,
                    proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
                )
                .await
                .map_err(|e| e.into_response())?;
            // Decode and parse under ONE extraction permit: both halves are
            // CPU work on upstream-controlled bytes, so they are admission-
            // controlled together, and the decode is bounded by the same
            // decompression-bomb budget the zip walk uses.
            let metadata = crate::util::bounded_archive::with_ingest_extraction(|| {
                match crate::util::content_coding::strip_content_coding(
                    &wheel,
                    wheel_encoding.as_deref(),
                ) {
                    Ok(crate::util::content_coding::Decoded::Bytes(bytes)) => {
                        Ok(extract_metadata_from_wheel(&bytes))
                    }
                    // A coding this build cannot strip (`br`) degrades to the
                    // pre-existing "not available" answer rather than a hard
                    // upstream error: pip recovers from that by downloading the
                    // wheel itself, which succeeds because the download path
                    // forwards the coding for the client to strip (#3176).
                    Ok(crate::util::content_coding::Decoded::Unsupported) => Ok(None),
                    // A supported coding that will not decode is a corrupt or
                    // bomb stream; surface it rather than reporting it as a
                    // missing resource.
                    Err(e) => Err(e),
                }
            })
            .map_err(|e| e.into_response())?
            .map_err(|e| e.into_response())?
            .ok_or_else(|| {
                AppError::NotFound("Metadata not available".to_string()).into_response()
            })?;
            // Extracted here, so the bytes are plain: no coding to declare.
            Ok(pep658_metadata_response(Bytes::from(metadata), None))
        }
        Err(error) => Err(error.into_response()),
    }
}

/// Build the response for a PEP 658 `.metadata` resource.
///
/// The content-type is pinned rather than relayed: a PEP 658 resource is always
/// the plain-text METADATA file, so an upstream labelling it `text/html` must
/// not get that type echoed back under this origin.
///
/// The coding is the opposite case (#3193). The shared HTTP client hands over
/// undecoded upstream bodies, so bytes forwarded verbatim may still be coded
/// and must say so, or pip parses a compressed body as METADATA. `None` leaves
/// the header absent — the common, uncoded case.
///
/// Shared by every arm that produces a sidecar (cache hit, upstream fetch,
/// wheel extraction) so one resource carries identical headers whichever
/// served it.
fn pep658_metadata_response(content: Bytes, content_encoding: Option<&str>) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(enc) = content_encoding {
        builder = builder.header(CONTENT_ENCODING, enc);
    }
    builder.body(Body::from(content)).unwrap()
}

fn pypi_lkg_filename_from_artifact_path(artifact_path: &str) -> String {
    artifact_path
        .rsplit('/')
        .next()
        .unwrap_or(artifact_path)
        .to_string()
}

/// Build the stable proxy-cache key for a proxied PyPI distribution.
///
/// Takes a [`NormalizedProjectName`], not a `&str` (#3186): the cache key is a
/// *name-keyed* store, so if this could be called with a raw segment then two
/// spellings of one request could address two different cache entries -- or,
/// worse, one spelling could address the entry another package's bytes were
/// written under. The newtype makes that unrepresentable.
fn build_pypi_proxy_cache_path(project: &NormalizedProjectName, filename: &str) -> String {
    format!("simple/{}/{}", project.as_str(), filename)
}

/// Apply the age-gate listing filter to a rewritten PEP 691 JSON simple
/// index (#1944). The JSON and HTML representations of one index must
/// withhold the same young versions, or a JSON-negotiating client (modern
/// pip) sees everything the HTML filter hides. Mirrors the HTML hook in
/// `simple_project`: an evaluation/filter failure serves the unfiltered
/// listing rather than failing the request, while an authoritative policy
/// resolution failure returns a structurally valid empty listing. The
/// download path re-checks every version independently and fails closed, so
/// enforcement never rests on this listing-side filter.
async fn filter_pypi_simple_json_response(
    state: &SharedState,
    repo: &RepoInfo,
    effective_upstream: &str,
    project: &str,
    json: String,
) -> String {
    let Some(svc) = state.age_gate_service.as_ref() else {
        return json;
    };
    // Quick struct-derived check, then DB-resolve the authoritative policy
    // (mode + upstream identity) — a virtual member's RepoInfo carries a
    // defaulted mode (#2264). A resolve failure suppresses the listing with a
    // valid PEP 691 empty response; the download path re-checks fail-closed.
    if !AgeGateService::is_applicable(&proxy_helpers::age_gate_params(repo)) {
        return json;
    }
    let params = match crate::services::age_gate_service::resolve_repo_params(&state.db, repo.id)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, repo_key = %repo.key, "Failed to resolve age-gate params for PyPI simple JSON response; suppressing listing");
            return empty_pep691_listing(project);
        }
    };
    let Ok(mut index) = serde_json::from_str::<serde_json::Value>(&json) else {
        // `rewrite_upstream_simple_json` only returns JSON it serialized
        // itself, so this branch is unreachable in practice.
        return json;
    };
    if svc
        .filter_pypi_simple_json(&params, project, effective_upstream, &mut index)
        .await
        .is_ok()
    {
        if let Ok(filtered) = serde_json::to_string(&index) {
            return filtered;
        }
    }
    json
}

/// Age-gate a PyPI simple-index **HTML** body (PEP 503) for a single repo,
/// dropping the download links of upstream versions younger than the repo's
/// threshold. Sibling of [`filter_pypi_simple_json_response`] for the HTML
/// form; extracted from the direct-Remote branch so the virtual-resolution
/// loop can apply the SAME per-member filter (#2066). Returns the input
/// unchanged when the gate is not applicable or the publish times cannot be
/// resolved (same data-dependent behavior as the original inline block).
async fn filter_pypi_simple_html_response(
    state: &SharedState,
    repo: &RepoInfo,
    effective_upstream: &str,
    project: &str,
    html: String,
) -> String {
    let Some(svc) = state.age_gate_service.as_ref() else {
        return html;
    };
    // Quick struct-derived check, then DB-resolve the authoritative policy —
    // same rationale as the JSON twin above (#2264).
    if !AgeGateService::is_applicable(&proxy_helpers::age_gate_params(repo)) {
        return html;
    }
    let params = match crate::services::age_gate_service::resolve_repo_params(&state.db, repo.id)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, repo_key = %repo.key, "Failed to resolve age-gate params for PyPI simple HTML response; suppressing listing");
            return "<html><body></body></html>".to_string();
        }
    };
    // Publish times are only the basis in `upstream_publish_time` mode;
    // `first_seen` substitutes this server's own observations inside the
    // filter, so the fetch is skipped (and a fetch failure must not skip
    // filtering there).
    let times = if params.age_gate_mode
        == crate::services::age_gate_service::AgeGateMode::UpstreamPublishTime
    {
        let Ok(client) = metadata_http_client() else {
            return html;
        };
        let Ok(times) = svc
            .metadata_cache()
            .fetch_pypi_publish_times(&client, repo.id, effective_upstream, project)
            .await
        else {
            return html;
        };
        times
    } else {
        std::collections::HashMap::new()
    };
    match svc
        .filter_pypi_simple_index(&params, project, &times, &html)
        .await
    {
        Ok(filtered) => filtered,
        Err(_) => html,
    }
}

async fn apply_pypi_download_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    project: &str,
    filename: &str,
) -> Result<Option<String>, Response> {
    // Cheap struct-derived pre-check, then DB-resolve the authoritative
    // policy (mode + upstream identity) by id — struct-derived params can
    // carry a stale or defaulted mode (e.g. a virtual member's RepoInfo),
    // and gate policy is enforcement input (#2264).
    if !AgeGateService::is_applicable(&proxy_helpers::age_gate_params(repo)) {
        return Ok(None);
    }
    let params = crate::services::age_gate_service::resolve_repo_params(&state.db, repo.id)
        .await
        .map_err(|e| e.into_response())?;

    let info = PypiHandler::parse_filename(filename)
        .map_err(|e| AppError::Validation(e.to_string()).into_response())?;
    let version = info.version.ok_or_else(|| {
        AppError::Validation("Missing version in filename".to_string()).into_response()
    })?;

    let svc = state.age_gate_service.as_deref();
    // Publish-time evidence from the project's upstream JSON metadata; under
    // `first_seen` the time itself is ignored, but presence in the document
    // is the existence evidence that may start the observation clock.
    let published_at = if let (Some(svc), Some(upstream_url), Ok(client)) =
        (svc, &repo.upstream_url, metadata_http_client())
    {
        svc.metadata_cache()
            .fetch_pypi_publish_times(&client, repo.id, upstream_url, project)
            .await
            .ok()
            .and_then(|times| times.get(&version).copied())
    } else {
        None
    };
    let basis = match svc {
        Some(svc) => svc
            .download_basis(
                &params,
                project,
                &version,
                published_at,
                published_at.is_some(),
            )
            .await
            .map_err(|e| e.into_response())?,
        None => published_at,
    };

    // The shared seam (#2264) owns the decision and the terminal 451; only
    // the LKG wheel-filename substitution below is pypi-specific.
    let lkg = proxy_helpers::enforce_age_gate(svc, &params, project, &version, basis).await?;
    Ok(lkg.map(|blocked| {
        pypi_lkg_filename_from_artifact_path(&blocked.last_known_good.artifact_path)
    }))
}

/// Run the remote-PyPI download age gate and, when the requested version is
/// withheld, resolve the response the caller should return: the last-known-good
/// wheel served via the proxy cache (presigned redirect / cache stream /
/// upstream refetch), or the 451 block propagated as an `Err`.
///
/// Returns `Ok(Some(response))` when the gate handled the request and
/// `Ok(None)` when the version is allowed and the caller should keep serving
/// normally. Shared by both the cache-miss and the local-`artifacts`-hit
/// branches of `serve_file` so a young version is never streamed just because a
/// local row exists (parity with npm's unconditional `serve_tarball` gate).
async fn enforce_pypi_download_age_gate(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    project: &NormalizedProjectName,
    filename: &str,
) -> Result<Option<Response>, Response> {
    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok(None),
    };

    let lkg_filename =
        match apply_pypi_download_age_gate(state, repo, project.as_str(), filename).await? {
            Some(lkg) => lkg,
            None => return Ok(None),
        };

    // The gate above and this cache key are now the SAME string by
    // construction (#3186); they used to be `project` and
    // `PypiHandler::normalize_name(project)` respectively.
    let lkg_cache_path = build_pypi_proxy_cache_path(project, &lkg_filename);
    // #1555 ordering holds on the LKG fallback too: presigned redirect on a
    // fresh cache hit BEFORE the streaming cache check, so a cached LKG wheel is
    // not streamed through the backend.
    if let Some(redirect) = pypi_proxy_cache_redirect(state, proxy, repo_key, &lkg_cache_path).await
    {
        return Ok(Some(redirect));
    }
    if let Some(result) = proxy_helpers::proxy_check_cache_streaming(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        &lkg_cache_path,
        RepositoryFormat::Pypi,
    )
    .await
    {
        return Ok(Some(build_streaming_file_response(&lkg_filename, result)));
    }
    let index_path = fetch_pypi_upstream_index_path(&state.db, repo.id).await;
    let result = fetch_from_pypi_remote_streaming(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        project,
        &lkg_filename,
        &index_path,
        RepositoryFormat::Pypi,
    )
    .await?;
    Ok(Some(build_streaming_file_response(&lkg_filename, result)))
}

/// Serve a PyPI distribution download.
///
/// Takes ONLY the PEP 503 normalized project name. The raw path segment is
/// deliberately not a parameter (#3183, same shape as the #3179 metadata fix):
/// every gate on this path -- the PEP 708 dependency-confusion isolation, the
/// per-member curation gate, the download age gate, and the inline scan gate --
/// keys on the `normalize_pep503` form, while the upstream fetch re-normalizes
/// with `PypiHandler::normalize_name`. Those two functions disagree on any
/// character outside `[A-Za-z0-9._-]`: the gate DROPS it, the fetch turns it
/// into a '-'. Passing the raw segment therefore let a client check one name
/// and download another. Not having the raw name in scope is what stops that
/// from being reintroduced.
/// `project` is a [`NormalizedProjectName`] (#3186). Every gate on this path --
/// the PEP 708 dependency-confusion isolation, the per-member curation gate,
/// the download age gate and the inline scan gate -- keys on the PEP 503 form,
/// while the upstream fetch and the proxy-cache key are built from the same
/// value. Because the parameter is not a `&str`, "gate one name, fetch another"
/// is no longer expressible here.
async fn serve_file(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    project: &NormalizedProjectName,
    filename: &str,
    auth: Option<&AuthExtension>,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
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
                    // Enforce the download age gate before any proxy fetch, and
                    // serve the last-known-good wheel if the requested version is
                    // withheld. Shared with the local-`artifacts`-hit branch below.
                    if let Some(resp) =
                        enforce_pypi_download_age_gate(state, repo, repo_key, project, filename)
                            .await?
                    {
                        return Ok(resp);
                    }

                    // #2954: when scan-on-proxy is enabled, route through the
                    // inline scan-and-block path (buffered fetch + digest-keyed
                    // verdict gate). It handles the cache internally, so we take
                    // it INSTEAD of the streaming/redirect cache paths below,
                    // which serve bytes without consulting a scan verdict. Repos
                    // that have not enabled scan-on-proxy skip this entirely and
                    // keep today's untouched streaming behavior (no regression).
                    if crate::services::scan_config_service::ScanConfigService::new(
                        state.db.clone(),
                    )
                    .is_proxy_scan_enabled(repo.id)
                    .await
                    .unwrap_or(false)
                    {
                        let (action, severity_gate) =
                            proxy_helpers::direct_scan_policy(&state.db, repo.id).await;
                        return serve_scanned_pypi_file(
                            state,
                            proxy,
                            repo.id,
                            repo_key,
                            upstream_url,
                            project,
                            filename,
                            action,
                            severity_gate,
                            ctx,
                        )
                        .await;
                    }

                    // Try the proxy cache first using a predictable local
                    // path. This avoids fetching the simple index from upstream
                    // just to rediscover the download URL when the file is
                    // already cached from a previous request. Streamed straight
                    // from storage (#895): buffering cached multi-hundred-MiB
                    // wheels per request OOM-killed memory-constrained pods.
                    // `project` is already canonical, so this is the same
                    // cache key it always was for a well-formed name -- but it
                    // can no longer be a DIFFERENT one for a malformed name.
                    let local_cache_path = build_pypi_proxy_cache_path(project, filename);

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
                        RepositoryFormat::Pypi,
                    )
                    .await
                    {
                        // #2270/#2260: proxy-cache serve now counts into the
                        // sibling proxy_download_statistics table via the
                        // catalog id (HEAD-guarded + best-effort inside).
                        proxy_helpers::record_proxy_download(
                            state,
                            repo.id,
                            repo_key,
                            &local_cache_path,
                            ctx,
                        )
                        .await;
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
                        RepositoryFormat::Pypi,
                    )
                    .await?;

                    // #2270/#2260 + #2537: count the proxy serve. The streaming
                    // tee commits the authoritative catalog row only after the
                    // client drains the body, so the recorder ensures the
                    // (repo, cache_path) row exists to make this FIRST serve
                    // count; the tee later refines that same row in place.
                    proxy_helpers::record_proxy_download(
                        state,
                        repo.id,
                        repo_key,
                        &local_cache_path,
                        ctx,
                    )
                    .await;
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
                    return Err(proxy_helpers::no_accessible_members_response());
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
                let members =
                    proxy_helpers::authorize_virtual_members(&state.db, auth, repo.id, members)
                        .await;
                // #3452: a fully-filtered member set must answer the SAME body
                // the genuinely-empty set above answers, or the pair is an
                // existence oracle over the private members this virtual
                // aggregates.
                if members.is_empty() {
                    return Err(proxy_helpers::no_accessible_members_response());
                }

                // PEP 708 dependency-confusion guard (#1600), superseding the
                // version-aware shadowing guard (#1217, #1582) and the
                // name-only local-precedence suppression (#1738). Isolate to the
                // local owner when a local member owns the name and no operator
                // `tracks` declaration permits merging with upstream. A
                // suppressed Remote member is skipped so an unrelated public
                // package of the same name is never served through the virtual;
                // the download then 404s for a version the local owner lacks,
                // which matches what the simple index lists (consistent). When
                // a `tracks` declaration exists (same project, split version
                // ranges, #1582) this returns None and the proxy fallthrough
                // below applies.
                //
                // #2311: the guard is priority-aware and applied PER REMOTE
                // MEMBER — it only suppresses a Remote member the owning local
                // outranks (owning priority value strictly lower). A Remote
                // member at equal or higher priority than the owning local
                // still serves, mirroring the simple-index decision above so
                // every version the index lists is downloadable.
                // #2937: the guard also carries the owning local's per-version
                // wheel-tag profile, so a suppressed Remote member can still
                // serve a Case-A distribution (a platform/ABI-distinct wheel of
                // a version the owner already provides) while a Case-B one (a
                // remote-only version, or a same-platform rebuild) stays
                // suppressed. Built from the same local-owner query the simple
                // index uses, keeping the two paths symmetric: every
                // distribution the index lists is downloadable and every one it
                // hides 404s here.
                let guard =
                    PypiOwnershipGuard::resolve(&state.db, repo.id, &members, project.as_str())
                        .await?;

                for member in &members {
                    // #3404: apply the ownership guard BEFORE this member is
                    // consulted at all — not just before its upstream fetch.
                    //
                    // The local-first lookup below runs for EVERY member,
                    // Remote included, because Remote-typed repos legitimately
                    // carry `artifacts` rows (direct upload, replication,
                    // promotion). The suppression decision used to be computed
                    // ~50 lines further down and consulted only by the upstream
                    // branch, so a suppressed member's *cached* row was served
                    // straight out of the local branch. Any request that
                    // legitimately resolved the distribution once — before a
                    // local member claimed the name, while the remote was
                    // ranked equal-or-higher, or under a since-removed PEP 708
                    // `tracks` declaration — leaves such a row behind and
                    // bypassed the guard for that exact file permanently.
                    //
                    // That broke the invariant #2937 states it maintains: the
                    // index and download paths make the identical decision, so
                    // a distribution the index hides 404s here too. A stale
                    // `uv.lock` / hashed `requirements.txt` pins exact
                    // filenames, so a resolution made while the remote was
                    // permitted otherwise kept succeeding long after the
                    // operator re-ranked the members to stop it.
                    //
                    // Skipping the whole member (rather than only its local
                    // branch) is deliberate: a member the guard suppresses gets
                    // no say in the response, so its per-member age gate must
                    // not answer either. The #3220 fail-closed block below is
                    // unaffected — it can only fire for a member that is still
                    // allowed to supply the file.
                    if guard.suppresses(member.id, &member.repo_type, filename) {
                        debug!(
                            member_key = %member.key,
                            %filename,
                            "virtual pypi member suppressed by ownership guard; skipping"
                        );
                        continue;
                    }

                    // #2066: enforce THIS member's download age gate before any
                    // of its bytes can be served — including from a local
                    // `artifacts` cache row below (parity with the direct
                    // artifacts-hit fix). For local / ungated members the helper
                    // early-returns `Ok(None)` (no upstream_url / not applicable)
                    // so normal resolution proceeds; an aged version also returns
                    // `Ok(None)`. A withheld young version returns the
                    // last-known-good wheel (`Ok(Some(resp))`) or 451 (`Err`).
                    let member_info = proxy_helpers::repo_info_from_member(member);

                    // #2912: enforce THIS member's curation rules before any of its
                    // bytes are served, including from its local cache row —
                    // parity with the per-member age gate immediately below. Skips
                    // the blocked member so a sibling that does not block the
                    // package still resolves, rather than failing the whole
                    // virtual request.
                    if enforce_pypi_curation(
                        state,
                        &member_info,
                        project.as_str(),
                        version_from_pypi_filename(filename).as_deref(),
                    )
                    .await
                    .is_err()
                    {
                        continue;
                    }

                    if let Some(resp) = enforce_pypi_download_age_gate(
                        state,
                        &member_info,
                        &member.key,
                        project,
                        filename,
                    )
                    .await?
                    {
                        return Ok(resp);
                    }

                    // Try local storage first (works for hosted repos and
                    // cached remote artifacts). #1555: redirect to S3 presigned
                    // URL instead of streaming when enabled.
                    match proxy_helpers::local_fetch_or_redirect_by_suffix(
                        &state.db,
                        state,
                        member.id,
                        &member.storage_location(),
                        filename,
                        ctx,
                    )
                    .await
                    {
                        Ok(response) => {
                            return Ok(response);
                        }
                        // #3220: this member HAS the distribution and its
                        // download gate (quarantine hold / scan policy) refuses
                        // to serve it. Fail closed — falling through would try
                        // the member's own upstream, or the next member, and
                        // serve the blocked file with a 200, which is how the
                        // direct hosted route's 403 was bypassable through any
                        // virtual listing that repo. Note this deliberately
                        // differs from the per-member curation skip above: a
                        // curation rule says "this member must not supply this
                        // package" (a sibling still may), whereas the download
                        // gate says "these bytes must not be served".
                        Err(e) if proxy_helpers::is_member_policy_block_response(&e) => {
                            return Err(e);
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
                    // Shadowing guard (#1217 follow-up, ak-hv3s; priority-aware
                    // per #2311, distribution-granular per #2937): already
                    // applied at the top of the loop by `guard.suppresses`,
                    // which skips a suppressed Remote member outright — so
                    // reaching here means this member is permitted to serve.
                    if member.repo_type == RepositoryType::Remote {
                        if let (Some(ref upstream_url), Some(ref proxy)) =
                            (&member.upstream_url, &state.proxy_service)
                        {
                            // #3023: gate this remote member's serve through the
                            // inline scan-and-block path when the stricter-of-two
                            // policy (virtual OR member) enables it, mirroring the
                            // direct-Remote pypi path. A vulnerable digest is
                            // blocked (403) / an inconclusive fail-closed is 423;
                            // a not-found or other error falls through to the next
                            // member. A member with scanning disabled keeps the
                            // untouched streaming cache path below (no regression).
                            let (scan_enabled, action, severity_gate) =
                                proxy_helpers::effective_virtual_scan_policy(
                                    &state.db, repo.id, member.id,
                                )
                                .await;
                            if scan_enabled {
                                match serve_scanned_pypi_file(
                                    state,
                                    proxy,
                                    member.id,
                                    &member.key,
                                    upstream_url,
                                    project,
                                    filename,
                                    action,
                                    severity_gate,
                                    ctx,
                                )
                                .await
                                {
                                    Ok(resp) => return Ok(resp),
                                    Err(resp) => {
                                        let status = resp.status();
                                        if status == StatusCode::FORBIDDEN
                                            || status == StatusCode::LOCKED
                                        {
                                            return Err(resp);
                                        }
                                        debug!(
                                            member_key = %member.key,
                                            status = %status,
                                            "scanned pypi virtual member did not serve; trying next member"
                                        );
                                        continue;
                                    }
                                }
                            }

                            // Check proxy cache first (same optimization as the
                            // direct Remote path). This avoids re-fetching the
                            // simple index from upstream when the file is already
                            // cached from a previous request through this member.
                            // Already canonical; see the direct-remote arm.
                            let local_cache_path = build_pypi_proxy_cache_path(project, filename);

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
                                member.format.clone(),
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
                                member.format.clone(),
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

    // Enforce the download age gate even when a local `artifacts` row exists for
    // a Remote repo (a locally-published, hydrated/replicated, or pre-#1278
    // cached wheel). Without this, the cache-hit branch above streams a young
    // version UNGATED while the cache-miss branch blocks it — a fail-open
    // asymmetry versus npm's serve_tarball, which gates unconditionally. A
    // withheld version returns 451 (or the last-known-good wheel) instead of the
    // young local artifact.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(resp) =
            enforce_pypi_download_age_gate(state, repo, repo_key, project, filename).await?
        {
            return Ok(resp);
        }
    }

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
            // #3147: this arm used to stream `artifacts.storage_key` straight
            // out of storage with no sidecar, digest or freshness check of any
            // kind. For a Remote PyPI repo that key IS proxy-cache content
            // (`proxy-cache/<repo>/simple/<project>/<file>/__content__`), so
            // the `__cache_meta__.json` sidecar beside it is the record of what
            // this server actually committed there. Consult it before serving.
            let verdict = proxy_cache_object_verdict(proxy, &artifact.storage_key).await;
            if verdict == CachedObjectVerdict::Held {
                // Package Age Policy (#1770 / #2075) parity: every other read
                // path 409s on a held entry rather than serving it.
                return Err(AppError::Conflict(
                    "Artifact is quarantined and pending security review".to_string(),
                )
                .into_response());
            }
            get_remote_cached_or_refetch_stream(
                storage.clone(),
                &artifact.storage_key,
                verdict.may_serve_stored_object(),
                || async move {
                    // Fetched lazily inside the closure: this path serves
                    // cache hits straight from storage, and the index_path is
                    // only needed on a cache miss when we re-fetch upstream.
                    let index_path = fetch_pypi_upstream_index_path(&state.db, repo.id).await;
                    fetch_from_pypi_remote_streaming(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        project,
                        filename,
                        &index_path,
                        RepositoryFormat::Pypi,
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
    crate::services::artifact_service::record_download(&state.db, artifact.id, ctx).await;

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
    may_serve_stored_object: bool,
    refetch: F,
) -> Result<BoxStream<'static, Result<Bytes, std::io::Error>>, Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<crate::services::proxy_service::StreamingFetchResult, Response>>,
{
    // #3147: when nothing vouches for the stored object, treat it exactly as if
    // it were absent — refuse it and re-fetch upstream. That is the same
    // self-healing move the `NotFound` arm below already makes, and the refetch
    // runs through the proxy service's normal streaming cache path, which
    // rewrites BOTH the object and its sidecar. So an entry rejected here is
    // repaired by the very next request rather than refetching forever.
    if !may_serve_stored_object {
        tracing::warn!(
            storage_key = %storage_key,
            "remote PyPI proxy-cache object has no valid metadata sidecar vouching for it; \
             refusing to serve it and re-fetching from upstream (#3147)"
        );
        let result = refetch().await?;
        return Ok(write_back_refetch(storage, storage_key, result));
    }

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
            Ok(write_back_refetch(storage, storage_key, result))
        }
        Err(e) => Err(map_storage_err(e)),
    }
}

/// Forward a refetched body to the client, teeing it back into storage only
/// when this handle is the one that owns the key.
///
/// `refetch` runs through the proxy service's normal streaming cache path,
/// which commits the body **and** its `__cache_meta__.json` sidecar under the
/// `CachePersister` contract (#1618 S9): #1365 zero-byte guard, #1051 ETag
/// pin, body-before-sidecar ordering, and the `proxy_cache_artifacts` catalog
/// upsert. For a `proxy-cache/` key that write has therefore already happened,
/// to the same key, by the owner of the key.
///
/// Teeing a second copy through the ARTIFACT handle would write the body with
/// none of that: no sidecar update, no zero-byte guard, no ETag re-pin, no
/// catalog row, no quota accounting — and it races the proxy's own writer for
/// the same object. It is not merely redundant, it is unsafe: `is_fresh` falls
/// back to comparing `size(cache_key)` against the sidecar's `size_bytes` when
/// the pinned ETag is multipart-shaped, so a same-length body written out of
/// band keeps the entry "fresh" and the redirect path hands out a presigned
/// URL to bytes the sidecar never vouched for — the hole #3147 exists to
/// close. The truncation compensator in [`tee_refetch_to_storage`] would also
/// issue a `delete()` against the live cache object.
///
/// Before #3368 this was masked rather than absent: on a prefixed S3
/// deployment the tee landed on `<S3_PREFIX>/proxy-cache/...`, a shadow path
/// nothing read. On every unprefixed deployment the two writers have always
/// collided. Restricting the tee to keys this handle actually owns fixes both.
fn write_back_refetch(
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
    storage_key: &str,
    result: crate::services::proxy_service::StreamingFetchResult,
) -> BoxStream<'static, Result<Bytes, std::io::Error>> {
    if crate::services::proxy_service::ProxyService::is_proxy_cache_key(storage_key) {
        tracing::debug!(
            storage_key = %storage_key,
            "refetched proxy-cache content is written back by the proxy cache itself; \
             not teeing a second unguarded copy through the artifact handle (#3368)"
        );
        return result
            .body
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
            .boxed();
    }
    tee_refetch_to_storage(
        storage,
        storage_key.to_string(),
        result.content_length,
        result.body,
    )
}

/// Whether the object stored at an `artifacts.storage_key` may be streamed
/// straight out of storage, per the proxy-cache sidecar beside it (#3147).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedObjectVerdict {
    /// The key is not proxy-cache content, so no sidecar can exist and the
    /// `artifacts` row is the metadata of record. Serve it as before — this is
    /// an ordinary local artifact read (a locally-published wheel in a Remote
    /// repo), not the proxy-cache path #3147 is about.
    NotProxyCache,
    /// A positive sidecar vouches for the object.
    Vouched,
    /// Proxy-cache content with no usable sidecar: absent, unreadable, or a
    /// negative-cache marker (#1611) that vouches for no body at all.
    Unvouched,
    /// A Package Age Policy hold (#1770) is still active on the entry.
    Held,
}

impl CachedObjectVerdict {
    fn may_serve_stored_object(self) -> bool {
        matches!(self, Self::NotProxyCache | Self::Vouched)
    }
}

/// Map a proxy-cache CONTENT key to its metadata sidecar key.
///
/// Returns `None` when `storage_key` is not proxy-cache content, which is the
/// signal that no sidecar can exist for it. Kept pure so the key algebra is
/// unit-testable without storage.
fn proxy_cache_metadata_key_for(storage_key: &str) -> Option<String> {
    if !storage_key.starts_with("proxy-cache/") {
        return None;
    }
    let stem = storage_key.strip_suffix("__content__")?;
    Some(format!("{stem}__cache_meta__.json"))
}

/// Resolve the sidecar verdict for an `artifacts.storage_key`.
///
/// Absent and unreadable sidecars both resolve to [`CachedObjectVerdict::Unvouched`]:
/// `load_cache_metadata_pub` collapses them, and they warrant the same answer
/// anyway — neither tells us anything about the object, so neither is grounds
/// to serve it.
async fn proxy_cache_object_verdict(
    proxy: &crate::services::proxy_service::ProxyService,
    storage_key: &str,
) -> CachedObjectVerdict {
    let Some(metadata_key) = proxy_cache_metadata_key_for(storage_key) else {
        return CachedObjectVerdict::NotProxyCache;
    };
    match proxy.load_cache_metadata_pub(&metadata_key).await {
        None => CachedObjectVerdict::Unvouched,
        Some(metadata) if metadata.negative_cached_until.is_some() => {
            CachedObjectVerdict::Unvouched
        }
        Some(metadata) => match metadata.quarantine_until {
            Some(until) if until > chrono::Utc::now() => CachedObjectVerdict::Held,
            _ => CachedObjectVerdict::Vouched,
        },
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
    /// SHA-256 the upstream simple index pinned for this file in its
    /// `#sha256=` fragment (GHSA-qxv7-p3mq-88fv). `Some` gates the
    /// streaming proxy-cache commit: a body whose digest disagrees with the
    /// index is streamed to the client (which verifies it independently)
    /// but never persisted. `None` — no usable fragment, e.g. a PEP 658
    /// `.metadata` resolution — fetches unverified, as before.
    expected_sha256: Option<String>,
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
///
/// `project` is a [`NormalizedProjectName`], not a `&str` (#3186). This is the
/// single place a route-derived project name becomes an OUTBOUND upstream URL,
/// so it is the exact boundary the newtype exists to guard: the gates upstream
/// of here key on the PEP 503 form, and a raw segment reaching this function
/// re-normalized differently is what produced #3077, #3179 and #3183. A `&str`
/// no longer compiles here, so a fourth path cannot reintroduce it.
async fn resolve_pypi_remote_fetch_target(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &NormalizedProjectName,
    filename: &str,
    index_path: &str,
) -> Result<PypiRemoteFetchTarget, Response> {
    // `PypiHandler::normalize_name` is the identity on canonical input (see
    // `pypi_name::tests::legacy_fetch_normalizer_is_identity_on_canonical_form`),
    // so this is retained only to keep the produced URLs byte-identical to what
    // they were before, and can be dropped once nothing else calls it.
    let normalized = PypiHandler::normalize_name(project.as_str());

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
    let file_url = find_upstream_url_for_file(&index_html, filename, Some(&full_index_url))
        .or_else(|| find_upstream_metadata_url(&index_html, filename, Some(&full_index_url)));

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

    // GHSA-qxv7-p3mq-88fv: the same index page that vouched for the download
    // URL also pins the file's SHA-256 in the anchor fragment — the digest
    // pip verifies the download against. Lift it so the streamed fetch gates
    // the proxy-cache commit on it; before this, the fragment was forwarded
    // to clients but never checked server-side, so a body that disagreed
    // with the index was cached and served warm from then on.
    let expected_sha256 = find_upstream_sha256_for_file(&index_html, filename);

    Ok(PypiRemoteFetchTarget {
        fetch_base,
        fetch_path,
        cache_path,
        expected_sha256,
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
#[allow(clippy::too_many_arguments)]
async fn fetch_from_pypi_remote_streaming(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &NormalizedProjectName,
    filename: &str,
    index_path: &str,
    format: RepositoryFormat,
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

    // GHSA-qxv7-p3mq-88fv: gate the proxy-cache commit on the index-pinned
    // SHA-256 when the upstream simple page carried one — serve-but-don't-cache
    // on a mismatch, the same posture as Cargo's #2929 `cksum` gate.
    proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
        proxy,
        repo_id,
        repo_key,
        &target.fetch_base,
        &target.fetch_path,
        &target.cache_path,
        target.expected_sha256,
        format,
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
    // #3149: the proxy pins `Accept-Encoding: identity` and no longer decodes
    // upstream bodies (see `http_client::base_client_builder`), so a
    // content-coded body must be declared or pip writes compressed bytes to
    // disk and fails the hash check. `content_length` above is the CODED
    // length; forwarding it without the coding is a protocol defect, so both
    // come off the same `StreamingFetchResult`.
    if let Some(ref encoding) = result.content_encoding {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    builder
        .body(Body::from_stream(
            result
                .body
                .map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
        ))
        .unwrap()
}

// ---------------------------------------------------------------------------
// #2954: inline scan-and-block on proxy download (PyPI Phase 1).
//
// The format-agnostic pieces — digesting, the verdict state machine, the
// block/lock response shapes, and the scan-and-record orchestration — were
// lifted into `proxy_helpers` (#3003) so npm (and later OCI) share ONE
// implementation of the #2954 fail-closed gate and the #2976 freshness gate.
// This module keeps only the PyPI-specific glue: index-target resolution, the
// synthetic-artifact shape, and the PyPI response builders.
// ---------------------------------------------------------------------------

use super::proxy_helpers::{is_over_cap_error, scan_pending_locked_response, sha256_hex};

/// Build the synthetic in-memory [`Artifact`](crate::models::artifact::Artifact)
/// that [`ScannerService::scan_content`] runs the leaf scanners over. There is
/// NO `artifacts` row: proxy-cached bytes are deliberately not persisted as
/// artifacts (#1278/#1280). The filename drives per-scanner applicability +
/// workspace naming exactly as for a hosted wheel.
fn pypi_synthetic_artifact(
    repo_id: uuid::Uuid,
    filename: &str,
    digest: &str,
    size: i64,
) -> crate::models::artifact::Artifact {
    let now = Utc::now();
    crate::models::artifact::Artifact {
        id: uuid::Uuid::new_v4(),
        repository_id: repo_id,
        path: filename.to_string(),
        name: filename.to_string(),
        version: version_from_pypi_filename(filename),
        size_bytes: size,
        checksum_sha256: digest.to_string(),
        checksum_md5: None,
        checksum_sha1: None,
        content_type: pypi_content_type(filename).to_string(),
        storage_key: String::new(),
        is_deleted: false,
        uploaded_by: None,
        quarantine_status: None,
        quarantine_until: None,
        created_at: now,
        updated_at: now,
    }
}

/// Build a buffered 200 response for scanned bytes. `pending` adds the loud
/// `X-AK-Scan: pending` header for the fail-open serve-before-verdict path so a
/// served-unscanned byte is observable (kills the #1274 silent gap).
///
/// `content_encoding` is the coding the UPSTREAM declared on these exact bytes,
/// forwarded verbatim (#3184). The proxy no longer lets reqwest decode upstream
/// bodies, so a coded wheel arrives here still coded and `bytes.len()` — which
/// feeds `Content-Length` — is the CODED length. Serving that without declaring
/// the coding is #3149: pip receives compressed data labelled as identity and
/// fails to unpack it. Pass `None` when the upstream sent no coding; the header
/// must then be ABSENT rather than manufactured, or every uncoded serve is
/// mislabelled instead.
fn build_scanned_file_response(
    filename: &str,
    bytes: Bytes,
    content_type: Option<String>,
    content_encoding: Option<&str>,
    digest: Option<&str>,
    pending: bool,
) -> Response {
    let ct = content_type.unwrap_or_else(|| pypi_content_type(filename).to_string());
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, bytes.len().to_string())
        .header("X-AK-Scan", if pending { "pending" } else { "clean" });
    if let Some(enc) = content_encoding {
        builder = builder.header(CONTENT_ENCODING, enc);
    }
    if let Some(d) = digest {
        builder = builder.header("X-PyPI-File-SHA256", d);
    }
    builder.body(Body::from(bytes)).unwrap()
}

/// Inline scan-and-block for a PyPI proxy file download (#2954).
///
/// Runs ONLY when scan-on-proxy is enabled for the repo; the caller falls back
/// to the untouched streaming path otherwise, so repos that have not opted in
/// see NO change. Flow: buffered capped fetch (cache-first, so a repeat pull is
/// served from cache with no upstream hit) → content digest → verdict lookup →
/// serve / block / scan-inline per the fail-open/closed action.
#[allow(clippy::too_many_arguments)]
async fn serve_scanned_pypi_file(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    project: &NormalizedProjectName,
    filename: &str,
    action: crate::services::proxy_scan_service::ProxyScanAction,
    severity_gate: crate::services::proxy_scan_service::ProxySeverityGate,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let index_path = fetch_pypi_upstream_index_path(&state.db, repo_id).await;
    let target = resolve_pypi_remote_fetch_target(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        project,
        filename,
        &index_path,
    )
    .await?;

    // Buffered capped fetch (cache-first). The proxy caches the bytes under
    // cache_path, so a repeat pull returns from cache with NO upstream fetch.
    let repo = proxy_helpers::build_remote_repo_with_format(
        repo_id,
        repo_key,
        &target.fetch_base,
        RepositoryFormat::Pypi,
    );
    // `content_encoding` is the coding these exact bytes arrived under. It has
    // to travel with them to `build_scanned_file_response` below: this arm
    // forwards the buffered body VERBATIM, so dropping the coding here is the
    // #3149 bug (#3184).
    let (bytes, content_type, content_encoding) = match proxy
        .fetch_artifact_with_cache_path_capped(
            &repo,
            &target.fetch_path,
            &target.cache_path,
            crate::services::scanner_service::PROXY_SCAN_MAX_BYTES,
        )
        .await
    {
        Ok(triple) => triple,
        Err(e) if is_over_cap_error(&e) => {
            // Over the byte cap: never buffer unbounded (#895 OOM).
            return match crate::services::proxy_scan_service::decide_inconclusive(action) {
                crate::services::proxy_scan_service::InconclusiveOutcome::Locked => {
                    warn!(
                        repo_id = %repo_id, file = %filename,
                        "proxy object exceeds scan byte cap; fail-closed -> 423"
                    );
                    Err(scan_pending_locked_response(filename))
                }
                crate::services::proxy_scan_service::InconclusiveOutcome::ServePending => {
                    // Fail-open oversized: serve via the untouched streaming path
                    // (loud: X-AK-Scan pending header carried on the stream).
                    warn!(
                        repo_id = %repo_id, file = %filename,
                        "proxy object exceeds scan byte cap; fail-open -> serving UNSCANNED (streaming)"
                    );
                    let result = fetch_from_pypi_remote_streaming(
                        proxy,
                        repo_id,
                        repo_key,
                        upstream_url,
                        project,
                        filename,
                        &index_path,
                        RepositoryFormat::Pypi,
                    )
                    .await?;
                    proxy_helpers::record_proxy_download(
                        state,
                        repo_id,
                        repo_key,
                        &target.cache_path,
                        ctx,
                    )
                    .await;
                    let mut resp = build_streaming_file_response(filename, result);
                    resp.headers_mut()
                        .insert("X-AK-Scan", axum::http::HeaderValue::from_static("pending"));
                    Ok(resp)
                }
            };
        }
        Err(e) => return Err(e.into_response()),
    };

    let digest = sha256_hex(&bytes);

    // #3003: the identity these bytes are being served as. `project` is the
    // requested distribution and the version comes from the filename, so the
    // coordinate is request-derived, never upstream-controlled.
    //
    // This is what finally grades an SDIST. syft/grype catalog a wheel from its
    // `.dist-info/METADATA`, but an sdist ships only a ROOT `PKG-INFO`, which
    // syft does not catalog — so a vulnerable sdist scanned with zero cataloged
    // components, reported zero findings, and served 200 "clean" while the same
    // release's wheel was correctly blocked. Pinning the coordinate gives the
    // CVE engine the component to grade, and the shared assessment gate refuses
    // to call the result clean unless it actually graded it.
    //
    // Filenames we cannot parse a version from keep the prior behavior (no
    // pin, no assessment gate) rather than newly withholding an odd-but-legit
    // artifact.
    let identity = match version_from_pypi_filename(filename) {
        Some(version) => proxy_helpers::ProxyScanIdentity::Established(
            crate::services::scanner_service::ExpectedComponent::new(
                crate::services::scanner_service::ComponentEcosystem::Python,
                // The canonical name. The scan gate grades a component by
                // name+version, so before #3186 it could grade `acme sdk`
                // while the fetch resolved `acme-sdk` -- the same divergence,
                // in the component identity the verdict is keyed on.
                project.as_str(),
                &version,
            ),
        ),
        // An unparseable filename keeps the pre-#3003 behavior rather than
        // newly withholding an odd-but-legitimate artifact.
        None => proxy_helpers::ProxyScanIdentity::NotApplicable,
    };

    // Digest-keyed verdict gate, shared with every proxy format (#3003):
    // lookup → `decide_serve` (freshness incl. the #2976 unknown-live-version
    // fail-closed tightening) → inline scan / async scan per the action, with
    // the #2954 fail-closed contract enforced inside the shared scanner loop.
    let synthetic = pypi_synthetic_artifact(repo_id, filename, &digest, bytes.len() as i64);
    match proxy_helpers::gate_proxy_scan_serve(
        state,
        repo_id,
        filename,
        &digest,
        synthetic,
        &bytes,
        action,
        severity_gate,
        identity,
        proxy_helpers::ProxyScanMode::File,
    )
    .await
    {
        proxy_helpers::ProxyScanServeOutcome::Deny(resp) => Err(resp),
        proxy_helpers::ProxyScanServeOutcome::Serve { pending } => {
            proxy_helpers::record_proxy_download(state, repo_id, repo_key, &target.cache_path, ctx)
                .await;
            Ok(build_scanned_file_response(
                filename,
                bytes,
                content_type,
                content_encoding.as_deref(),
                Some(&digest),
                pending,
            ))
        }
    }
}

/// What to do when the storage read behind a PEP 658 `.metadata` request
/// misses — the "row present, object absent" state.
///
/// Pure decision, split out from [`serve_metadata`] so the routing rule is
/// unit-testable without storage, a database or an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataMissRepair {
    /// The local missing-file repair path: take the cluster-wide hydration
    /// lease, re-read, and answer 507 if the object is still absent.
    ///
    /// Correct for a row whose bytes a local writer owns — a hosted artifact
    /// on any repository type, where another replica really may be mid-write.
    CoordinatedRetry,
    /// Answer 507 immediately; the caller owns recovery.
    ///
    /// Chosen for a proxy-cache-backed row. Nothing local writes a
    /// `proxy-cache/` key except the proxy cache itself, so re-reading the
    /// same key under a hydration lease cannot produce the bytes — the
    /// reported deployment logged the miss and the 507 at a 1:1 ratio, 32,681
    /// times in 24h, without one coordinated re-read ever succeeding (#3463).
    /// Running it costs a Postgres advisory lock, a second storage round trip
    /// and an ERROR-level log line per request, and buys nothing.
    ///
    /// The recovery that DOES work is a re-fetch from this repository's own
    /// upstream, and `serve_virtual_metadata` — the only caller that reaches
    /// this state — already performs exactly that: a 507 sets
    /// `owns_unavailable_bytes` and falls into the member's own
    /// `serve_remote_metadata`. Answering 507 straight away hands it that
    /// signal one round trip sooner. It must stay 507 and never 404: 404 is
    /// the member loop's "this member does not have it", which would let
    /// resolution fall through to a DIFFERENT member (#3372).
    CallerRecoversFromUpstream,
}

/// Route a `.metadata` storage miss to the repair that can actually succeed.
///
/// Keyed on the storage key alone, because the key is what determines who can
/// write those bytes: `coordinated_retry_get` is documented as the repair path
/// for a **locally stored** artifact, and a `proxy-cache/` key is never
/// written by a local publish, replication or promotion — only by the proxy
/// cache, whose own writer is not waiting on this lease.
///
/// Note what does NOT reach this function: a non-`NotFound` storage error.
/// A real backend fault (auth, timeout, genuine insufficient storage) is still
/// mapped by `map_storage_err` and surfaced, never reinterpreted as a missing
/// cache entry.
fn metadata_miss_repair(storage_key: &str) -> MetadataMissRepair {
    if crate::services::proxy_service::ProxyService::is_proxy_cache_key(storage_key) {
        MetadataMissRepair::CallerRecoversFromUpstream
    } else {
        MetadataMissRepair::CoordinatedRetry
    }
}

/// The single 507 answer for "this repository owns the name but its bytes are
/// unavailable", worded identically to the one `serve_virtual_metadata`
/// synthesises so a client sees one message whichever layer produced it.
#[allow(clippy::result_large_err)]
fn insufficient_storage_metadata_response() -> Response {
    (
        StatusCode::INSUFFICIENT_STORAGE,
        "artifact metadata unavailable; retry later",
    )
        .into_response()
}

async fn serve_metadata(
    state: &SharedState,
    db: &PgPool,
    repo: &RepoInfo,
    filename: &str,
) -> Result<Response, Response> {
    let repo_id = repo.id;
    let location = &repo.storage_location();
    // Find the artifact through the SAME resolver the distribution download
    // uses (#3405).
    //
    // This used to open-code `path LIKE '%/' || $2`, which requires a `/`
    // before the filename and therefore cannot match an artifact stored at its
    // bare path (generic uploads, imports/migrations that synthesise no
    // `{name}/{version}/` prefix, and replicas of those). The download path
    // resolves those through `resolve_local_artifact_by_suffix`'s exact-path
    // fallback, so such a distribution downloaded fine while its PEP 658
    // sidecar 404'd — a hard `pip`/`uv` failure, since the index advertises
    // `core-metadata: true` for every `.whl`. One resolver, one rule, no drift.
    let artifact = crate::api::handlers::proxy_helpers::resolve_local_artifact_by_suffix(
        db, repo_id, filename,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("File not found".to_string()).into_response())?;

    // Try to extract METADATA from the package file
    let storage = state.storage_for_repo_or_500(location)?;
    let content = match storage.get(&artifact.storage_key).await {
        Ok(bytes) => bytes,
        // A storage NotFound on a row we just read is the "row present,
        // object absent" state — and in this codebase that state is TRANSIENT
        // until proven otherwise. `coordinated_retry_get` is the download
        // path's handling of exactly it (#1609/#3147): take the cluster-wide
        // hydration lease, re-read, and only if the object is *still* absent
        // answer 507 "retry later".
        //
        // Do NOT map this to 404. #3366 did, and 404 is the virtual member
        // loop's "this member does not have it" signal — the one status that
        // lets resolution fall through to a LOWER-PRIORITY member. A Remote
        // member carrying `artifacts` rows (direct upload, replication,
        // promotion — see the local-first comment in `serve_virtual_metadata`)
        // owns the name, but `pypi_virtual_isolates_name` counts only
        // Local/Staging members, so nothing suppresses the lower-priority
        // Remote. The result was pip resolving `Requires-Dist` from a public
        // package while the wheel path — which DOES coordinate and retry —
        // served the private bytes, with nothing anywhere to detect it.
        //
        // 507 keeps metadata and the wheel failing together, which is the
        // invariant that matters. The caller's loop treats it as "owns the
        // name, bytes unavailable" and confines the fallback to this member.
        //
        // #3463: that reasoning holds for a LOCALLY stored row. It does not
        // hold for a proxy-cache-backed row, where "the bytes are not in the
        // cache" is the ordinary state and no local writer will ever produce
        // them — re-reading the same key under the hydration lease 507s
        // forever, which is what the reporter measured 1:1 with the miss.
        //
        // Answer 507 without the dead repair. The caller
        // (`serve_virtual_metadata`) treats 507 as "owns the name, bytes
        // unavailable" and re-fetches from this member's OWN upstream, which
        // is the recovery that works and the same provenance the wheel
        // download resolves to. Deliberately NOT re-fetching here as well:
        // that would duplicate the upstream resolution the caller is about to
        // perform, doubling upstream load on exactly the hot failing key this
        // issue is about.
        Err(AppError::NotFound(_)) => match metadata_miss_repair(&artifact.storage_key) {
            MetadataMissRepair::CallerRecoversFromUpstream => {
                tracing::debug!(
                    artifact_id = %artifact.id,
                    storage_key = %artifact.storage_key,
                    repo_key = %repo.key,
                    "proxy-cache-backed metadata row is not in the cache; no local repair \
                     is possible, deferring to the caller's upstream re-fetch (#3463)"
                );
                return Err(insufficient_storage_metadata_response());
            }
            MetadataMissRepair::CoordinatedRetry => {
                crate::api::handlers::proxy_helpers::coordinated_retry_get(
                    db,
                    artifact.id,
                    &artifact.storage_key,
                    storage.as_ref(),
                )
                .await?
            }
        },
        Err(other) => return Err(map_storage_err(other)),
    };

    // #2561: permit-scoped decode on the serve path, fast-fail 503 on
    // saturation. Only taken for the branches that actually decode an archive.
    let metadata_text = if filename.ends_with(".whl") {
        crate::util::bounded_archive::with_ingest_extraction(|| {
            extract_metadata_from_wheel(&content)
        })
        .map_err(|e| e.into_response())?
    } else if filename.ends_with(".tar.gz") {
        crate::util::bounded_archive::with_ingest_extraction(|| {
            extract_metadata_from_sdist(&content)
        })
        .map_err(|e| e.into_response())?
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
    // Bound the zip decompression (#2556): a crafted wheel served via PEP 658
    // `.metadata` cannot inflate the METADATA entry unbounded. On a cap breach
    // this returns None -> a bounded "Metadata not available" response instead
    // of an unbounded inflate.
    let cursor = std::io::Cursor::new(content);
    let bytes = crate::util::bounded_archive::read_metadata_from_zip(cursor, |name| {
        name.contains(".dist-info/") && name.ends_with("METADATA")
    })
    .ok()??;
    String::from_utf8(bytes).ok()
}

fn extract_metadata_from_sdist(content: &[u8]) -> Option<String> {
    // Bound the gzip/tar decompression (#2556) for the served sdist PKG-INFO.
    let bytes = crate::util::bounded_archive::read_metadata_from_tar_gz(content, |path| {
        path.ends_with("PKG-INFO")
    })
    .ok()??;
    String::from_utf8(bytes).ok()
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
    let user_id = require_auth_basic_scope(auth, "pypi", "write:artifacts")?.user_id;
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
    // Security (#3107): the filename becomes a segment of the artifact storage
    // path, so reject anything that could escape it before it is used below.
    if !is_safe_upload_filename(&filename) {
        return Err(
            AppError::Validation(format!("Invalid upload filename: {filename:?}")).into_response(),
        );
    }

    // PEP 508 validation on the upload channel (#3198).
    //
    // #3196 validated every routed `:project` segment, but twine takes the
    // project name from a multipart form field, so it never reaches
    // `parse_project_segment`. What flowed in here instead was
    // `PypiHandler::normalize_name`, which coerces rather than validates: it
    // maps every non-ASCII-alphanumeric character to `-`, skips leading
    // separators and pops one trailing hyphen. So `acme sdk`, `acme!sdk` and
    // `acme<U+212A>sdk` all published into the namespace of `acme-sdk` -- a
    // real, valid, possibly someone else's project -- and `---` published under
    // the EMPTY name, which is stored and charged to quota but reachable at no
    // URL, because `/simple//` is not a route.
    //
    // Deliberately the same constructor as the read paths, not a second
    // validator: two implementations that must agree about names is the exact
    // shape of #3186 / #3077 / #3179 / #3183.
    //
    // This is NOT a rename for well-formed names. For every PEP 508-valid name
    // the canonical form and `PypiHandler::normalize_name` agree byte for byte
    // -- a valid name draws only on `[A-Za-z0-9._-]`, so nothing is dropped,
    // and it begins and ends alphanumeric, so neither the leading-separator
    // skip nor the trailing-hyphen pop fires. That equivalence is asserted in
    // `formats::pypi_name::tests::all_three_normalizers_agree_on_every_valid_name`,
    // which is what makes this substitution storage-compatible: no existing
    // artifact path, cache key or index entry changes.
    //
    // 400, not the 404 the read paths give: a path segment that is not a
    // project name names no resource, but an upload that declares one is a
    // malformed request, and the publisher is the party who can fix it. The
    // message therefore carries the pattern -- but never the rejected name,
    // which would make the error a reflection sink for exactly the characters
    // `normalize_pep503` exists to strip (#1377).
    let normalized_project = NormalizedProjectName::parse(&pkg_name).ok_or_else(|| {
        debug!(
            "rejecting PyPI upload whose 'name' field is not a PEP 508 name (len {})",
            pkg_name.len()
        );
        AppError::Validation(format!(
            "Invalid project name: a PyPI project name must match the PEP 508 pattern {}",
            PEP508_NAME_PATTERN
        ))
        .into_response()
    })?;
    let normalized = normalized_project.as_str().to_string();

    // Distribution/metadata consistency (#3107).
    //
    // `PypiHandler::validate` held name/version-vs-metadata checks but had no
    // call site, so a wheel/sdist whose embedded METADATA/PKG-INFO named a
    // DIFFERENT project (or version) than the twine `name`/`version` fields was
    // published into the declared project's namespace unchecked — the bytes and
    // the identity they resolve under could disagree. Bind them here.
    //
    // The body was streamed to a bounded scratch file (up to
    // `max_upload_size_bytes`, 10 GiB by default); re-open that file and read
    // only the metadata entry rather than buffering the whole distribution.
    // ZIP/tar parsing is blocking, so it runs on the blocking pool.
    {
        let staged_path = staged_content.path().to_path_buf();
        let expected_name = normalized.clone();
        let expected_version = pkg_version.clone();
        let dist_filename = filename.clone();
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&staged_path).map_err(|e| {
                AppError::Internal(format!("re-open staged upload for validation: {e}"))
            })?;
            PypiHandler::validate_upload_file(
                &expected_name,
                &expected_version,
                &dist_filename,
                file,
            )
        })
        .await
        .map_err(|e| {
            AppError::Internal(format!("upload validation task failed: {e}")).into_response()
        })?
        .map_err(|e| e.into_response())?;
    }

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

/// Reject an uploaded PyPI filename that is unsafe as a path segment or when
/// rendered. Physical storage is content-addressed (keyed by SHA-256), so this
/// is not the sole defense — the Simple-index render sites HTML-escape the
/// filename — but it is defense-in-depth at the ingest choke-point: reject path
/// separators, parent references, control characters, and HTML metacharacters
/// (`< > "`). Legitimate wheel/sdist filenames never contain any of these. (#3107)
fn is_safe_upload_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains('<')
        && !name.contains('>')
        && !name.contains('"')
        && !name.chars().any(|c| c.is_control())
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

// #2967: quote-agnostic + case-insensitive so a single-quoted / uppercase
// `HREF` upstream anchor cannot slip an un-rewritten off-site href past the
// proxy render (defense-in-depth behind the Case-A HTML REBUILD). The URL lands
// in group 1 (double-quoted), 2 (single-quoted), or 3 (unquoted).
static HREF_RE: Lazy<Regex> = Lazy::new(|| {
    // Like the historical pattern, the URL is captured up to the first `#` (the
    // fragment is dropped) and the closing quote is NOT required — a `#sha256=`
    // fragment sits between the URL and the closing quote. The value lands in
    // group 1 (double-quoted), 2 (single-quoted), or 3 (unquoted).
    Regex::new(r##"(?is)<a\s+[^>]*?\bhref\s*=\s*(?:"([^"#]*)|'([^'#]*)|([^\s>#]+))"##).unwrap()
});

/// Anchor START-tag matcher for the simple-index REBUILD paths
/// (`rewrite_upstream_urls`, GHSA-4cw7-mgqj-hgmg, and the #2967 R3
/// ownership rebuild `filter_remote_case_a_html`). Matches `<a ...>` with NO
/// required `</a>`, so an unclosed/malformed upstream anchor is still parsed
/// rather than passing through unexamined.
static SIMPLE_ANCHOR_START_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<a\b[^>]*>").unwrap());

/// Quote-agnostic, case-insensitive `href` extractor applied to a single
/// anchor start-tag. The value lands in group 1 (double-quoted), 2
/// (single-quoted), or 3 (unquoted).
static SIMPLE_HREF_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).unwrap());

/// `data-*` attribute extractor applied to a single anchor start-tag, for
/// the simple-index rebuild: group 1 is the attribute name (emitted
/// lowercased), groups 2/3/4 its double-quoted / single-quoted / unquoted
/// value. A bare attribute (PEP 714 permits `data-core-metadata` with no
/// value) captures the name only. This is how `data-requires-python`,
/// `data-dist-info-metadata` / `data-core-metadata`, `data-gpg-sig`, etc.
/// survive the rebuild without any other upstream markup surviving with
/// them (GHSA-4cw7-mgqj-hgmg).
static SIMPLE_DATA_ATTR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\b(data-[a-z0-9-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#).unwrap()
});

/// The file identity carried by one upstream simple-index anchor: its
/// distribution filename and the `#fragment` (normally `#sha256=...`) that must
/// survive the rebuild so `pip`/`uv` can verify the bytes AK proxies.
struct SimpleAnchorTarget {
    filename: String,
    fragment: String,
}

/// Extract the download target of one anchor START-tag, quote-agnostically and
/// case-insensitively, deriving the identity from the href's URL basename —
/// never from the anchor text.
///
/// Shared by [`rewrite_upstream_urls`] and [`filter_remote_case_a_html`] (#2748)
/// so the two rebuilds cannot disagree about what an anchor means. They used to
/// carry independent copies, and the copies drifted: the ownership filter's had
/// no metacharacter check, so it would emit an anchor the proxy rebuild rejects.
///
/// Returns `None` when the anchor is not a file link (navigation, `../`, a bare
/// host), or when the "filename" contains HTML metacharacters, whitespace or
/// control characters — that is no filename at all, it is an attribute-breakout
/// payload riding the href (GHSA-4cw7-mgqj-hgmg), and the anchor is dropped
/// rather than escaped-and-emitted (the same posture `is_safe_upload_filename`
/// takes at the ingest choke-point, #3107).
fn simple_anchor_target(tag: &str) -> Option<SimpleAnchorTarget> {
    let href_caps = SIMPLE_HREF_ATTR_RE.captures(tag)?;
    let href_raw = href_caps
        .get(1)
        .or_else(|| href_caps.get(2))
        .or_else(|| href_caps.get(3))
        .map(|m| m.as_str())
        .unwrap_or("");
    // Minimal entity-decode BEFORE deriving the file identity from the href;
    // everything re-emitted by the callers is escaped again.
    let href = decode_html_entities_minimal(href_raw);
    let fragment = match href.find('#') {
        Some(pos) => href[pos..].to_owned(),
        None => String::new(),
    };
    let url_part = href.split('#').next().unwrap_or(&href);
    let url_no_query = url_part.split('?').next().unwrap_or(url_part);
    let filename = url_no_query.rsplit('/').next().unwrap_or("").trim();
    if filename.is_empty()
        || filename
            .chars()
            .any(|c| matches!(c, '<' | '>' | '"' | '\'') || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    Some(SimpleAnchorTarget {
        filename: filename.to_owned(),
        fragment,
    })
}

/// Preserve ONLY an anchor's `data-*` attributes, each re-emitted escaped into a
/// double-quoted value (or bare, as PEP 714 permits).
///
/// This is what carries `data-requires-python` (PEP 503), `data-yanked` (PEP
/// 592) and `data-core-metadata` / `data-dist-info-metadata` (PEP 658/714)
/// through a rebuild. Dropping them is not cosmetic: without
/// `data-requires-python` an installer is offered a wheel its interpreter cannot
/// run, and without `data-yanked` a withdrawn release becomes an ordinary
/// resolution candidate.
///
/// Shared by [`rewrite_upstream_urls`] and [`filter_remote_case_a_html`] (#2748)
/// — the ownership filter previously emitted a bare `<a href>` and silently lost
/// all of them, so the same distribution advertised through a virtual repo
/// looked installable-anywhere and un-yanked, while the direct repo said
/// otherwise.
fn simple_anchor_data_attrs(tag: &str) -> String {
    let mut data_attrs = String::new();
    for attr in SIMPLE_DATA_ATTR_RE.captures_iter(tag) {
        let name = attr[1].to_ascii_lowercase();
        let value = attr
            .get(2)
            .or_else(|| attr.get(3))
            .or_else(|| attr.get(4))
            .map(|m| m.as_str());
        match value {
            Some(v) => data_attrs.push_str(&format!(
                " {}=\"{}\"",
                name,
                html_escape(&decode_html_entities_minimal(v))
            )),
            None => data_attrs.push_str(&format!(" {}", name)),
        }
    }
    data_attrs
}

/// Emit one rebuilt PEP 503 anchor on an Artifact Keeper path.
///
/// No upstream host, scheme, query or non-`data-*` attribute survives; the
/// filename and fragment are escaped so neither can break out of the attribute.
fn emit_simple_anchor(
    repo_key: &str,
    normalized: &str,
    target: &SimpleAnchorTarget,
    data_attrs: &str,
) -> String {
    format!(
        "<a href=\"/pypi/{}/simple/{}/{}{}\"{}>{}</a><br/>\n",
        repo_key,
        normalized,
        html_escape(&target.filename),
        html_escape(&target.fragment),
        data_attrs,
        html_escape(&target.filename),
    )
}

/// Order PEP 691 `versions` by PEP 440 rather than lexicographically, so `1.9`
/// precedes `1.10` (#3106).
///
/// Anything that does not parse as PEP 440 has no defined position, so it sorts
/// after every parseable version (by string, for stability) rather than
/// interleaving with them. Shared by the direct emitter and the virtual merge /
/// ownership-filter emitters (#2748) — the virtual paths built a
/// `BTreeSet<String>` and emitted it raw, so the *same repository* ordered its
/// versions differently depending on whether a remote member answered.
fn sorted_pep440_versions<I: IntoIterator<Item = String>>(versions: I) -> Vec<String> {
    let mut versions: Vec<String> = versions
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    versions.sort_by(|a, b| {
        match (
            PypiHandler::pep440_sort_key(a),
            PypiHandler::pep440_sort_key(b),
        ) {
            (Some(ka), Some(kb)) => ka.cmp(&kb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.cmp(b),
        }
    });
    versions
}

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
        let href = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|m| m.as_str())
            .unwrap_or("");
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

/// Extract the `#sha256=` fragment the upstream simple index advertises for
/// `filename`, normalized to the bare lowercase hex the proxy-cache commit
/// gate compares against (GHSA-qxv7-p3mq-88fv). This is the same digest the
/// rewritten index hands to pip as a URL fragment — the client verifies it,
/// and the download path now gates the cache commit on it too. Returns
/// `None` when no anchor names the file or its fragment is absent or not a
/// canonical SHA-256 — the caller then fetches unverified, exactly as it did
/// before the gate existed.
fn find_upstream_sha256_for_file(index_html: &str, filename: &str) -> Option<String> {
    for tag in SIMPLE_ANCHOR_START_RE.find_iter(index_html) {
        let Some(href_caps) = SIMPLE_HREF_ATTR_RE.captures(tag.as_str()) else {
            continue;
        };
        let href_raw = href_caps
            .get(1)
            .or_else(|| href_caps.get(2))
            .or_else(|| href_caps.get(3))
            .map(|m| m.as_str())
            .unwrap_or("");
        let href = decode_html_entities_minimal(href_raw);
        let Some((url_part, fragment)) = href.split_once('#') else {
            continue;
        };
        let url_no_query = url_part.split('?').next().unwrap_or(url_part);
        if url_no_query.rsplit('/').next().unwrap_or("") != filename {
            continue;
        }
        let Some(digest) = fragment.strip_prefix("sha256=") else {
            continue;
        };
        if let Some(normalized) = proxy_helpers::normalize_expected_sha256(digest) {
            return Some(normalized);
        }
    }
    None
}

/// Resolve a PEP 658 metadata filename from the corresponding wheel URL.
/// PyPI advertises the metadata hash on the wheel anchor but usually does not
/// include a separate `.whl.metadata` anchor in the Simple API page.
fn find_upstream_metadata_url(
    index_html: &str,
    filename: &str,
    index_url: Option<&str>,
) -> Option<String> {
    let wheel_filename = filename.strip_suffix(".metadata")?;
    if !wheel_filename.ends_with(".whl") {
        return None;
    }

    let wheel_url = find_upstream_url_for_file(index_html, wheel_filename, index_url)?;
    let mut url = url::Url::parse(&wheel_url).ok()?;
    url.set_path(&format!("{}.metadata", url.path()));
    Some(url.into())
}

/// Classification of a proxied PyPI simple-index body sniffed from its
/// content, used when the upstream `Content-Type` is neither PEP 691 JSON nor
/// PEP 503 HTML. See #2801: corporate outbound proxies / quirky mirrors
/// sometimes rewrite the simple-index Content-Type (e.g. to
/// `application/octet-stream`). Trusting that label made the handler serve the
/// raw upstream body — leaking un-rewritten offsite `files.pythonhosted.*`
/// download URLs (fatal in air-gapped / NO_PROXY installs) and tripping uv's
/// `Unsupported Content-Type` check. We sniff the body instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniffedSimpleIndex {
    /// Body looks like PEP 691 JSON (first non-whitespace byte is `{` or `[`).
    Json,
    /// Body looks like PEP 503 HTML (`<a `, `<!doctype`, or `<html`).
    Html,
    /// Unrecognizable / binary — must NOT be served raw.
    Binary,
}

/// Sniff a proxied simple-index body by content. Only invoked from the render
/// fallthrough, i.e. when the upstream `Content-Type` was neither JSON nor
/// `text/html`, so the conformant happy path is never reclassified. PEP 691
/// JSON is detected by a leading `{`/`[`; PEP 503 HTML by an anchor tag or an
/// HTML doctype/root element within a bounded prefix. Anything else is
/// [`SniffedSimpleIndex::Binary`] and the caller returns 502 rather than serve
/// raw upstream bytes (#2801).
fn sniff_simple_index(body: &[u8]) -> SniffedSimpleIndex {
    // Skip a UTF-8 BOM and any leading ASCII whitespace.
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let start = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(body.len());
    let trimmed = &body[start..];
    match trimmed.first() {
        Some(b'{') | Some(b'[') => SniffedSimpleIndex::Json,
        _ => {
            // Inspect only a bounded prefix for HTML markers.
            let head_len = trimmed.len().min(4096);
            let head = String::from_utf8_lossy(&trimmed[..head_len]).to_ascii_lowercase();
            if head.contains("<a ") || head.contains("<!doctype") || head.contains("<html") {
                SniffedSimpleIndex::Html
            } else {
                SniffedSimpleIndex::Binary
            }
        }
    }
}

/// 502 for a proxied simple index whose upstream body cannot be rendered as a
/// PEP 503/691 document. Shared by the direct-remote and virtual render
/// fallthroughs so neither ever serves raw upstream bytes / offsite download
/// URLs to the client (#2801).
fn bad_upstream_simple_index() -> Response {
    AppError::BadGateway("upstream returned a non-simple-index response".to_string())
        .into_response()
}

/// Rewrite download URLs in upstream PyPI simple index HTML to route through
/// Artifact Keeper's proxy endpoint — by REBUILDING a fresh minimal PEP 503
/// page from the parsed anchors, never by editing the upstream markup in
/// place (GHSA-4cw7-mgqj-hgmg). Mirrors the #2967 R3 ownership rebuild
/// (`filter_remote_case_a_html`).
///
/// SECURITY. The previous in-place rewriter passed every upstream byte
/// through except `<base>` tags and the href values it recognized. A proxied
/// index is served from THIS registry's origin, so any surviving upstream
/// markup — a `<script>`, an `onerror=` handler, a `<form>` — is stored XSS
/// against anyone (admins included) browsing the index; and a filename or
/// `#fragment` containing the upstream's own href quote character broke out
/// of the rewritten attribute into arbitrary attacker-controlled markup. The
/// rebuild emits only what it can vouch for:
///
///   * one `<a>` per upstream anchor whose href yields a non-empty filename,
///     the href rebuilt as `/pypi/{repo_key}/simple/{project}/{filename}
///     {#fragment}` — the same local download path the in-place rewriter
///     produced, so absolute, root-relative and plain-relative upstream hrefs
///     (pypi.org, Nexus, Artifactory, devpi, another AK repo) all keep
///     routing through the proxy, and no upstream host/path/query survives;
///   * the anchor's `data-*` attributes (`data-requires-python`, the PEP
///     658/714 `data-dist-info-metadata` / `data-core-metadata`, …), each
///     entity-decoded then re-escaped into a fresh double-quoted value, so a
///     single-quoted upstream value cannot break out of its attribute;
///   * the filename, HTML-escaped, as the link text (PEP 503).
///
/// Everything else — `<base>`, `<script>`, event handlers, non-`data-*`
/// attributes, wrapper markup — is dropped with the rest of the upstream
/// page. The emitted skeleton keeps the `<head>`/`<body>` markers (and the
/// `pypi:repository-version` meta) that `merge_local_into_remote_simple_html`
/// splices local entries and operator `tracks` into.
fn rewrite_upstream_urls(html: &str, repo_key: &str, project: &str) -> String {
    let normalized = PypiHandler::normalize_name(project);

    let mut anchors = String::new();
    for tag in SIMPLE_ANCHOR_START_RE.find_iter(html) {
        let tag = tag.as_str();
        let Some(target) = simple_anchor_target(tag) else {
            continue;
        };
        let data_attrs = simple_anchor_data_attrs(tag);
        anchors.push_str(&emit_simple_anchor(
            repo_key,
            &normalized,
            &target,
            &data_attrs,
        ));
    }

    // Fresh minimal PEP 503 document containing ONLY Artifact-Keeper-pathed
    // anchors — the same skeleton `filter_remote_case_a_html` emits.
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n</head>\n<body>\n{anchors}</body>\n</html>\n"
    )
}

/// PEP 691 JSON simple-index media type.
const PEP691_JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";

/// Cache-path suffix under which the PEP 691 JSON representation of a Simple
/// project index is stored, appended to the HTML representation's cache path
/// (see `simple_project`'s `{upstream_path}index.v1+json` cache key).
const PEP691_JSON_CACHE_SUFFIX: &str = "index.v1+json";

/// The sibling content-negotiated cache path of a PyPI Simple project index
/// (#3290), or `None` when `path` is not a Simple-index cache path.
///
/// A Remote PyPI project index is cached once per negotiated representation:
/// the PEP 503 HTML under the index path itself (`.../<project>/`) and the
/// PEP 691 JSON under `.../<project>/index.v1+json`. The two entries expire
/// independently, so evicting one representation without the other leaves
/// them describing different upstream snapshots — `uv` (which prefers JSON)
/// then reports versions missing that the HTML index already lists. Callers
/// that explicitly invalidate either representation use this to evict the
/// sibling in the same operation.
pub(crate) fn pep691_sibling_cache_path(path: &str) -> Option<String> {
    if let Some(base) = path.strip_suffix(PEP691_JSON_CACHE_SUFFIX) {
        // JSON variant -> its HTML sibling, which is always a directory-shaped
        // index path. A non-directory base means `path` merely *ends* in the
        // suffix (e.g. an artifact literally named `index.v1+json`).
        return base.ends_with('/').then(|| base.to_string());
    }
    // Directory-shaped index path (HTML variant) -> its JSON sibling.
    path.ends_with('/')
        .then(|| format!("{path}{PEP691_JSON_CACHE_SUFFIX}"))
}

/// Rewrite the `files[].url` of a parsed PEP 691 JSON simple index to route
/// downloads through Artifact Keeper's proxy, mirroring `rewrite_upstream_urls`
/// for the HTML form. PEP 658/714 metadata signals (`core-metadata`,
/// `data-dist-info-metadata`) are preserved so installers can request the
/// corresponding `.metadata` file through the proxy. PEP 700 `upload-time`
/// and every other field are preserved untouched.
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
        // Shared with the direct emitter (#2748) so a local wheel advertises the
        // same fields — `core-metadata` above all — whether or not a remote
        // member happened to answer for this project.
        appended.push(local_simple_file_json(a, repo_key, normalized));
    }

    if let Some(files) = doc.get_mut("files").and_then(|f| f.as_array_mut()) {
        files.extend(appended);
    }

    // Union the local distributions' versions into the advertised list, ordered
    // by PEP 440 exactly as the direct emitter orders it (#2748/#3106) — a
    // plain `BTreeSet` put `1.10` before `1.9`, so the same repository ordered
    // its versions differently depending on whether a remote member answered.
    if !local_versions.is_empty() {
        let upstream_versions: Vec<String> = doc
            .get("versions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let versions = sorted_pep440_versions(upstream_versions.into_iter().chain(local_versions));
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

// ---------------------------------------------------------------------------
// #2937: distribution-granular ownership union for virtual PyPI
// ---------------------------------------------------------------------------
//
// The #1600 dependency-confusion guard suppresses a Remote member for a name a
// higher-priority local member owns, so a public `fastapi==0.119.1` can never
// shadow an internal `fastapi`. That suppression was name-level coarse and broke
// two legitimate topologies (#2748):
//
//   * Case A (safe to union): the remote holds a platform/ABI-distinct wheel of a
//     version the local ALREADY owns (local ships the linux `pydantic_core==2.0`
//     wheel, remote ships the windows wheel of the SAME 2.0). Same trusted
//     package, different build target — no confusion, so union it.
//   * Case B (must stay gated): a version present ONLY in the remote for a
//     locally-owned name (local owns `fastapi==0.119.0`, remote has `0.118.0`).
//     That is the confusion vector — keep it suppressed unless a `tracks`/opt-in
//     declaration re-enables the union (handled upstream via
//     `pypi_virtual_isolates_name` returning `None`).
//
// Security invariant (do NOT regress #1600): a Case-A union is admitted ONLY when
// it is a wheel of a version the local owner already provides AND its
// compatibility tag is one the owner does not already ship. It can therefore only
// ADD a build target the owner lacks (windows when the owner only has linux); it
// can never introduce a version the owner lacks, nor a competing same-platform
// rebuild of an owned version. The index and download paths make the identical
// decision so a distribution advertised in the index is downloadable and a
// suppressed one 404s on both.

/// Per-version record of the wheel compatibility tags a virtual's local owner
/// already provides for a PEP 503 name, used to admit Case-A remote unions
/// (#2937).
#[derive(Debug, Default)]
struct OwnedWheelProfile {
    /// owned version -> set of local wheel compat tags (`{py}-{abi}-{platform}`)
    /// for that version. A version present with an empty tag set is owned only
    /// via a source distribution, so any remote wheel tag for it is distinct.
    per_version: std::collections::HashMap<String, std::collections::HashSet<String>>,
}

impl OwnedWheelProfile {
    /// Build the profile from the owning local member(s)' distribution
    /// filenames. Every recognized version is registered as owned (wheels and
    /// sdists alike); only wheels contribute a compat tag.
    fn from_filenames<'a>(filenames: impl IntoIterator<Item = &'a str>) -> Self {
        let mut per_version: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for filename in filenames {
            let Some(version) = version_from_pypi_filename(filename) else {
                continue;
            };
            let entry = per_version.entry(version).or_default();
            if let Some(tag) = wheel_compat_tag(filename) {
                entry.insert(tag);
            }
        }
        Self { per_version }
    }

    /// Case-A test for one remote distribution filename: it must be a
    /// PLATFORM-SPECIFIC wheel, of a version the owner already provides, whose
    /// (case-normalized) compat tag the owner does NOT already ship. Rejected as
    /// Case B (stay suppressed): sdists, universal `*-none-any` wheels
    /// (installable everywhere — not a distinct build target, and a vector for a
    /// lower-priority remote to inject arbitrary code), unowned versions, and
    /// same-platform rebuilds (including a case-variant of a tag the local
    /// already ships). Fails closed (rejects) when the shape is unrecognized.
    fn admits(&self, filename: &str) -> bool {
        let Some(tag) = wheel_compat_tag(filename) else {
            return false;
        };
        // Exclude universal (pure-python) wheels: platform tag `any`. Case A
        // only adds a genuinely platform-specific target the owner lacks.
        if tag.rsplit('-').next() == Some("any") {
            return false;
        }
        let Some(version) = version_from_pypi_filename(filename) else {
            return false;
        };
        match self.per_version.get(&version) {
            // `tag` and the stored tags are both lowercased by `wheel_compat_tag`,
            // so a case-variant of the local's own tag compares equal (Case B).
            Some(local_tags) => !local_tags.contains(&tag),
            None => false,
        }
    }
}

/// Parse the `{python}-{abi}-{platform}` compatibility tag of a wheel filename
/// per the binary-distribution spec
/// (`{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`): the
/// last three `-`-separated fields of the stem, LOWERCASED so the Case-A
/// comparison is case-insensitive (wheel tags are case-insensitive; a
/// case-variant must not read as a distinct platform). Returns `None` for
/// non-wheels (an sdist has no platform tag) or malformed names.
fn wheel_compat_tag(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    // name, version, [build], python, abi, platform => at least five fields.
    if parts.len() < 5 {
        return None;
    }
    Some(parts[parts.len() - 3..].join("-").to_ascii_lowercase())
}

/// Narrow a suppressed Remote member's contribution to Case-A distributions
/// (#2937): return a body containing only the entries `owned.admits` accepts.
///
/// SECURITY (#2967 R4). The routing decision is made on the SNIFFED body, never
/// the upstream `Content-Type`. A hostile / quirky upstream can label an HTML
/// body `application/json` (or vice-versa); trusting the header let a mislabeled
/// HTML index skip the ownership filter and fall through to the in-place
/// `rewrite_upstream_urls` rewriter, delivering a raw off-site href to `pip`
/// (dependency confusion for a locally-owned name). Sniffing the actual bytes
/// picks the correct filter regardless of the header. Any body that is neither
/// recognizable PEP 691 JSON nor PEP 503 HTML fails closed to an EMPTY PEP 691
/// listing — never the raw upstream bytes.
fn case_a_filter_remote_body(
    content: &[u8],
    owned: &OwnedWheelProfile,
    repo_key: &str,
    normalized: &str,
) -> Bytes {
    let body = String::from_utf8_lossy(content);
    let filtered = match sniff_simple_index(content) {
        SniffedSimpleIndex::Json => filter_remote_case_a_json(&body, owned, normalized),
        SniffedSimpleIndex::Html => filter_remote_case_a_html(&body, owned, repo_key, normalized),
        SniffedSimpleIndex::Binary => empty_pep691_listing(normalized),
    };
    Bytes::from(filtered)
}

/// A structurally valid empty PEP 691 simple-index listing for `normalized`.
/// Used whenever a listing must fail closed without breaking JSON-simple
/// clients: for a locally-owned name whose suppressed Remote member returned a
/// body that could not be ownership-filtered (#2967 R4), and for an age-gate
/// policy-resolution failure. Mirrors the shape the merge path expects
/// (`meta`/`name`/`versions`/`files`) and guarantees no raw upstream byte is
/// surfaced.
fn empty_pep691_listing(normalized: &str) -> String {
    serde_json::json!({
        "meta": {"api-version": "1.0"},
        "name": normalized,
        "versions": [],
        "files": [],
    })
    .to_string()
}

/// Drop every file from a Remote member's PEP 691 JSON simple index that is not
/// a Case-A union candidate, and re-advertise `versions` from the survivors so
/// the listing never names a version no surviving file backs (#2937).
///
/// SECURITY (#2967 R4): FAILS CLOSED. A body that is not valid PEP 691 JSON (or
/// carries no `files` array) yields an EMPTY listing — NEVER the verbatim input.
/// Returning the raw body here was the bypass: an HTML index mislabeled
/// `application/json` was echoed back unfiltered and then rewritten in place,
/// leaking an off-site href for a locally-owned name.
fn filter_remote_case_a_json(json: &str, owned: &OwnedWheelProfile, normalized: &str) -> String {
    let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return empty_pep691_listing(normalized);
    };
    let Some(files) = doc.get_mut("files").and_then(|f| f.as_array_mut()) else {
        return empty_pep691_listing(normalized);
    };
    files.retain(|f| {
        f.get("filename")
            .and_then(|n| n.as_str())
            .map(|n| owned.admits(n))
            .unwrap_or(false)
    });
    // Rebuild `versions` from the surviving files so the index cannot advertise
    // a version only the remote has for a locally-owned name. PEP 440-ordered
    // for parity with every other emitter (#2748/#3106).
    let versions = sorted_pep440_versions(
        doc.get("files")
            .and_then(|f| f.as_array())
            .map(|files| {
                files
                    .iter()
                    .filter_map(|f| f.get("filename").and_then(|n| n.as_str()))
                    .filter_map(version_from_pypi_filename)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );
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
    serde_json::to_string(&doc).unwrap_or_else(|_| empty_pep691_listing(normalized))
}

/// HTML sibling of [`filter_remote_case_a_json`] (#2937): reduce a suppressed
/// Remote member's PEP 503 HTML simple index to its Case-A union candidates by
/// REBUILDING a fresh index from parsed anchors — never by editing the raw
/// upstream in place.
///
/// SECURITY. A span-replacing filter is fundamentally leaky: an UNCLOSED or
/// malformed anchor (no `</a>`, `</a >`, `</ a>`, …) is not a matched span, so
/// it passes through untouched, and combined with a quote/case gap in any later
/// URL rewriter it delivers a raw off-site href to the client (#2967 R3, the
/// #1600 class). This function instead scans anchor START-tags only (`<a ...>`
/// with NO required `</a>`, so unclosed/malformed anchors are covered); extracts
/// the `href` quote-agnostically and case-insensitively (double, single, or
/// unquoted; minimal-entity-decoded; query/fragment stripped) and derives the
/// file identity from its URL basename — never the anchor text; admits Case-A
/// wheels of that basename; and emits a FRESH minimal PEP 503 document
/// containing ONLY Artifact-Keeper-pathed anchors for the survivors.
///
/// No raw upstream anchor (closed or not, any quote style or letter case) ever
/// reaches the client, and every emitted href is an AK path the download gate
/// keys on — so the index stays symmetric with the download route.
fn filter_remote_case_a_html(
    html: &str,
    owned: &OwnedWheelProfile,
    repo_key: &str,
    normalized: &str,
) -> String {
    let mut survivors = String::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for tag in SIMPLE_ANCHOR_START_RE.find_iter(html) {
        let tag = tag.as_str();
        let Some(target) = simple_anchor_target(tag) else {
            continue;
        };
        if !owned.admits(&target.filename) {
            continue;
        }
        if !seen.insert(target.filename.clone()) {
            continue;
        }
        // AK path ONLY — no upstream host survives — but the anchor's `data-*`
        // attributes DO (#2748). A Case-A wheel is a real, installable
        // distribution of a version the local owner already ships; emitting it
        // stripped of `data-requires-python` offers an incompatible build to
        // every interpreter, and stripped of `data-yanked` (PEP 592) presents a
        // withdrawn release as an ordinary candidate. The JSON sibling
        // (`filter_remote_case_a_json`) only `retain`s entries and so always
        // kept these fields; the two representations of the same virtual index
        // disagreed about installability until this shared the emitter.
        let data_attrs = simple_anchor_data_attrs(tag);
        survivors.push_str(&emit_simple_anchor(
            repo_key,
            normalized,
            &target,
            &data_attrs,
        ));
    }

    // Fresh minimal PEP 503 document: only AK-pathed survivor anchors. The local
    // splice (`merge_local_into_remote_simple_html`) inserts before `</body>`
    // and `tracks` metas before `</head>`, so both markers are present.
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n</head>\n<body>\n{survivors}</body>\n</html>\n"
    )
}

/// Build the owning local member(s)' [`OwnedWheelProfile`] for a normalized PEP
/// 503 name by querying every local/staging member of the virtual repo for the
/// distribution filenames it holds (#2937). Shares the source of truth with the
/// simple-index first pass so the index and download paths admit the identical
/// set of Case-A unions. Fails closed to an empty profile (suppress everything)
/// on DB error.
async fn pypi_owned_wheel_profile(
    db: &PgPool,
    members: &[crate::models::repository::Repository],
    normalized: &str,
) -> OwnedWheelProfile {
    let local_ids: Vec<uuid::Uuid> = members
        .iter()
        .filter(|m| matches!(m.repo_type, RepositoryType::Local | RepositoryType::Staging))
        .map(|m| m.id)
        .collect();
    if local_ids.is_empty() {
        return OwnedWheelProfile::default();
    }
    let rows = sqlx::query!(
        r#"
        SELECT a.path
        FROM artifacts a
        WHERE a.repository_id = ANY($1)
          AND a.is_deleted = false
          AND LOWER(REPLACE(REPLACE(REPLACE(a.name, '_', '-'), '.', '-'), '--', '-')) = $2
        "#,
        &local_ids,
        normalized
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    OwnedWheelProfile::from_filenames(
        rows.iter()
            .map(|r| r.path.rsplit('/').next().unwrap_or(r.path.as_str())),
    )
}

/// The virtual-PyPI ownership (dependency-confusion) decision, resolved once
/// per request and then applied per member (#1600 / #2311 / #2937).
///
/// Bundles the three inputs the decision needs — which local member owns the
/// name and at what priority, the member priority map, and the owner's
/// per-version wheel-tag profile — so the *download* (`serve_file`) and *PEP
/// 658 metadata* (`serve_virtual_metadata`) paths cannot compute it
/// differently. They previously carried separate open-coded copies, which is
/// how the ordering bug in #3404 stayed invisible in one of them.
#[derive(Debug, Default)]
struct PypiOwnershipGuard {
    owning_local_min_priority: Option<i32>,
    member_priorities: std::collections::HashMap<uuid::Uuid, i32>,
    owned_profile: OwnedWheelProfile,
}

impl PypiOwnershipGuard {
    /// Resolve the guard for `normalized` within `virtual_repo_id`.
    ///
    /// `members` is used only to build the owning local's wheel profile. Note
    /// the isolation decision and priority map deliberately consult EVERY
    /// member (not just the caller-authorized ones, #3323/#3399): narrowing an
    /// isolation decision by caller visibility would drop the isolation a
    /// member the caller cannot see asserts, and re-expose the upstream name.
    /// Passing the authorized member list for the profile only ever *shrinks*
    /// the admitted Case-A set, which fails closed.
    async fn resolve(
        db: &PgPool,
        virtual_repo_id: uuid::Uuid,
        members: &[crate::models::repository::Repository],
        normalized: &str,
    ) -> Result<Self, Response> {
        let owning_local_min_priority =
            proxy_helpers::pypi_virtual_isolates_name(db, virtual_repo_id, normalized).await?;
        let (member_priorities, owned_profile) = if owning_local_min_priority.is_some() {
            (
                proxy_helpers::fetch_virtual_member_priorities(db, virtual_repo_id).await?,
                pypi_owned_wheel_profile(db, members, normalized).await,
            )
        } else {
            Default::default()
        };
        Ok(Self {
            owning_local_min_priority,
            member_priorities,
            owned_profile,
        })
    }

    /// Whether this member must not supply `filename` at all.
    ///
    /// True only for a Remote member that an owning local member strictly
    /// outranks and whose requested distribution is not an admitted Case-A
    /// platform wheel. A member missing from the priority map cannot outrank
    /// the owning local — it is treated as lowest priority, i.e. suppressed
    /// (fail closed). Local/Staging members are never the suppressed side.
    ///
    /// Pure given the resolved inputs, so the decision table is unit-testable
    /// without a database.
    fn suppresses(
        &self,
        member_id: uuid::Uuid,
        repo_type: &RepositoryType,
        filename: &str,
    ) -> bool {
        if *repo_type != RepositoryType::Remote {
            return false;
        }
        let Some(local_min) = self.owning_local_min_priority else {
            return false;
        };
        let member_priority = self
            .member_priorities
            .get(&member_id)
            .copied()
            .unwrap_or(i32::MAX);
        // #2937 Case-A carve-out: a platform/ABI-distinct wheel of a version
        // the owner already provides is what the simple index still lists for
        // a suppressed member, so it must remain downloadable here.
        local_min < member_priority && !self.owned_profile.admits(filename)
    }
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::cache_headers::{DEFAULT_CACHE_CONTROL, PRIVATE_CACHE_CONTROL};
    use crate::api::handlers::proxy_helpers::scan_blocked_response;
    use sha2::{Digest, Sha256};

    /// #3290: the sibling mapping between the two content-negotiated cache
    /// paths of a Simple project index, in both directions — and `None` for
    /// paths that are not Simple-index cache paths (a package file, or an
    /// artifact whose name merely ends in the JSON suffix).
    #[test]
    fn test_pep691_sibling_cache_path_maps_both_directions_3290() {
        assert_eq!(
            pep691_sibling_cache_path("simple/requests/").as_deref(),
            Some("simple/requests/index.v1+json"),
            "HTML index path must map to its PEP 691 sibling"
        );
        assert_eq!(
            pep691_sibling_cache_path("simple/requests/index.v1+json").as_deref(),
            Some("simple/requests/"),
            "PEP 691 path must map back to its HTML sibling"
        );
        // Flat (no `simple/` prefix) upstream layouts keep the same shape.
        assert_eq!(
            pep691_sibling_cache_path("requests/").as_deref(),
            Some("requests/index.v1+json")
        );
        // Not Simple-index cache paths: no sibling.
        assert_eq!(
            pep691_sibling_cache_path("simple/requests/requests-2.0.0-py3-none-any.whl"),
            None,
            "a package file has no negotiated sibling"
        );
        assert_eq!(
            pep691_sibling_cache_path("simple/proj/weird-index.v1+json"),
            None,
            "a non-directory base merely ends in the JSON suffix"
        );
    }

    /// Build a [`NormalizedProjectName`] for a test fixture (#3186).
    ///
    /// Panics on an invalid name on purpose: a fixture that cannot produce one
    /// is not exercising a real request, because `download_or_metadata` and
    /// `simple_project` reject such a segment with 404 before they ever reach
    /// the function under test. The rejection itself is covered end-to-end by
    /// the route-level tests, not here.
    fn proj(name: &str) -> NormalizedProjectName {
        NormalizedProjectName::parse(name)
            .unwrap_or_else(|| panic!("test fixture project name is not PEP 508-valid: {name:?}"))
    }

    #[test]
    fn metadata_filename_uses_distribution_version_for_curation() {
        let wheel = "demo-1.2.3-py3-none-any.whl";
        let metadata = format!("{wheel}.metadata");
        assert_eq!(
            version_from_pypi_filename(wheel),
            version_from_pypi_filename(pypi_distribution_filename(&metadata))
        );
        assert_eq!(version_from_pypi_filename(wheel).as_deref(), Some("1.2.3"));
    }

    /// A stacked `.metadata` suffix names the same distribution, so the
    /// curation gate must parse the same version from it. Stripping only one
    /// suffix yields `…whl.metadata`, whose version parses as `None` — and a
    /// `None` version skips version-constrained rules, which is exactly the
    /// bypass this resolver has to foreclose.
    #[test]
    fn stacked_metadata_suffix_resolves_to_the_same_distribution() {
        let wheel = "demo-1.0-py3-none-any.whl";
        for suffix in [
            "",
            ".metadata",
            ".metadata.metadata",
            ".metadata.metadata.metadata",
        ] {
            let requested = format!("{wheel}{suffix}");
            assert_eq!(
                pypi_distribution_filename(&requested),
                wheel,
                "'{requested}' must resolve to the distribution the serve path fetches"
            );
            assert_eq!(
                version_from_pypi_filename(pypi_distribution_filename(&requested)).as_deref(),
                Some("1.0"),
                "'{requested}' must version-parse as 1.0 so `==1.0` rules apply"
            );
        }
    }

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
        // The boundary must not be derived verbatim from `project`: RFC 2046
        // §5.1.1 restricts boundary characters, so a project name carrying a
        // space, a `/` or a non-ASCII character produced a body the multipart
        // parser rejected outright. That mattered once #3198 started feeding
        // this helper deliberately-invalid names -- every such case failed with
        // "Invalid `boundary` for `multipart/form-data` request" before the
        // handler ever saw the name, which is a 400 for the wrong reason.
        // Mapping to `_` keeps the boundary byte-identical for the plain
        // `a-b` names the older tests pass.
        let boundary = format!(
            "ak-pypi-test-{}",
            project
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>()
        );
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
    fn pypi_lkg_filename_from_artifact_path_takes_basename() {
        assert_eq!(
            pypi_lkg_filename_from_artifact_path("pkg/1.0.0/wheel.whl"),
            "wheel.whl"
        );
    }

    #[test]
    fn build_pypi_proxy_cache_path_format() {
        assert_eq!(
            build_pypi_proxy_cache_path(&proj("requests"), "requests-2.31.0.tar.gz"),
            "simple/requests/requests-2.31.0.tar.gz"
        );
    }

    // -----------------------------------------------------------------------
    // #3186 -- PEP 508 project-name validation at the routed edge
    // -----------------------------------------------------------------------

    /// The exact body `parse_project_segment` produces on rejection. Asserted
    /// literally so a route test cannot confuse a validation 404 with an
    /// ordinary "Package not found" / "File not found" 404 -- which is the
    /// failure mode that would let an over-rejecting fix look like it passes.
    const PROJECT_REJECTED_MESSAGE: &str = "Invalid project name";

    /// The PEP 508 *Names* pattern, as it must appear in the body of a rejected
    /// upload (#3198).
    ///
    /// A literal here rather than a reference to the production constant, on
    /// purpose and for the same reason as [`PROJECT_REJECTED_MESSAGE`] above:
    /// the test must still COMPILE against a tree with the fix reverted, so
    /// that reverting proves the assertion fails rather than that the crate
    /// stops building. It also makes the message a contract — the pattern is
    /// what tells a publisher how to spell the name, so silently dropping it
    /// from the message fails a test.
    const UPLOAD_NAME_REJECTED_MESSAGE: &str =
        r"^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$";

    /// PEP 508-valid names, weighted towards the unusual-but-legal.
    ///
    /// Over-rejection here does not break one request, it takes the entire
    /// PyPI surface offline, so this list matters more than the rejection list.
    fn valid_route_names() -> Vec<&'static str> {
        vec![
            "a",
            "A",
            "z",
            "0",
            "9",
            "123",
            "2024",
            "ab",
            "a1",
            "1a",
            "a-b",
            "a_b",
            "a.b",
            "a.b-c_d",
            "a__b",
            "a--b",
            "a._-b",
            "MyPackage",
            "Django",
            "PyYAML",
            "Jinja2",
            "zope.interface",
            "ruamel.yaml",
            "backports.ssl_match_hostname",
            "acme-sdk",
            "requests",
        ]
    }

    /// Names that fail `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`, paired with
    /// their percent-encoded URI form so they can be sent over a real route.
    fn invalid_route_names() -> Vec<(&'static str, &'static str)> {
        vec![
            // The motivating case (#3077 / #3179 / #3183): a space is where
            // `normalize_pep503` ("acmesdk") and `PypiHandler::normalize_name`
            // ("acme-sdk") disagree, so the gate and the fetch saw different
            // packages.
            ("acme sdk", "acme%20sdk"),
            ("acme+sdk", "acme%2Bsdk"),
            ("acme!sdk", "acme%21sdk"),
            ("acme@sdk", "acme%40sdk"),
            ("acme:sdk", "acme%3Asdk"),
            ("acme#sdk", "acme%23sdk"),
            // Leading / trailing separators: PEP 508 requires an alphanumeric
            // at both ends.
            ("_leading", "_leading"),
            ("-leading", "-leading"),
            (".leading", ".leading"),
            ("trailing_", "trailing_"),
            ("trailing-", "trailing-"),
            ("trailing.", "trailing."),
            ("-", "-"),
            ("---", "---"),
            // Non-ASCII, including the Kelvin sign that a `(?i)[A-Z]` class
            // would have accepted under Unicode case folding.
            ("acmeésdk", "acme%C3%A9sdk"),
            ("acme\u{212A}sdk", "acme%E2%84%AAsdk"),
            // A newline: Rust's `$` matches before a trailing newline, which is
            // why the pattern is anchored with `\z`.
            ("acme-sdk\n", "acme-sdk%0A"),
            ("acme\tsdk", "acme%09sdk"),
            // The stored-XSS payload `normalize_pep503`'s character dropping
            // exists to neutralize. Rejecting it outright is strictly stronger
            // than sanitizing it -- and the sanitizer is left untouched.
            ("<script>", "%3Cscript%3E"),
        ]
    }

    /// Pure, exhaustive over-rejection guard.
    ///
    /// Runs without a database so it can never be skipped, and covers far more
    /// names than the route tests below can afford to.
    #[test]
    fn parse_project_segment_accepts_valid_and_rejects_invalid() {
        for name in valid_route_names() {
            let parsed = parse_project_segment(name);
            assert!(
                parsed.is_ok(),
                "PEP 508-valid name must be accepted, got a rejection: {name:?}"
            );
        }

        for (raw, _encoded) in invalid_route_names() {
            match parse_project_segment(raw) {
                Ok(accepted) => panic!(
                    "PEP 508-invalid name {raw:?} was accepted and normalized to {accepted:?}"
                ),
                Err(response) => assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "rejection must be 404 (pypi.org has no route for an invalid name): {raw:?}"
                ),
            }
        }
    }

    /// Validation must not change the answer for any name that HAS one: on the
    /// PEP 508-valid domain the accepted form equals `normalize_pep503`, which
    /// is what every existing gate keys on.
    #[test]
    fn accepted_names_normalize_exactly_as_the_gate_does() {
        for name in valid_route_names() {
            let accepted = parse_project_segment(name).expect("valid");
            assert_eq!(
                accepted.as_str(),
                normalize_pep503(name),
                "validation changed the canonical form of {name:?}"
            );
        }
    }

    /// Every PyPI route that takes a `:project` segment must reject a name that
    /// is not a PEP 508 name, with 404, on all three shapes: the simple index,
    /// the distribution download, and the PEP 658 `.metadata` resource.
    #[tokio::test]
    async fn pep508_invalid_project_segment_is_404_on_every_pypi_route() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let wheel = "pkg-1.0.0-py3-none-any.whl";
        let mut failures: Vec<String> = Vec::new();

        for (raw, encoded) in invalid_route_names() {
            for (route, uri) in [
                (
                    "simple index",
                    format!("/{}/simple/{encoded}/", fx.repo_key),
                ),
                (
                    "download",
                    format!("/{}/simple/{encoded}/{wheel}", fx.repo_key),
                ),
                (
                    "PEP 658 metadata",
                    format!("/{}/simple/{encoded}/{wheel}.metadata", fx.repo_key),
                ),
            ] {
                let app = fx.router_with_auth(super::router());
                let (status, body) = tdh::send(app, tdh::get(uri.clone())).await;
                let body = String::from_utf8_lossy(&body).into_owned();

                if status != StatusCode::NOT_FOUND {
                    failures.push(format!(
                        "{route} {uri} (name {raw:?}): expected 404, got {status}; body {body}"
                    ));
                } else if !body.contains(PROJECT_REJECTED_MESSAGE) {
                    // A 404 alone is not proof: an unknown-but-valid package
                    // also 404s on these routes. The rejection message is what
                    // shows validation -- not a lookup miss -- produced it.
                    failures.push(format!(
                        "{route} {uri} (name {raw:?}): 404 but not from validation; body {body}"
                    ));
                }
            }
        }

        fx.teardown().await;

        assert!(
            failures.is_empty(),
            "PEP 508-invalid project segments were not rejected:\n{}",
            failures.join("\n")
        );
    }

    /// Groups of PEP 508-valid spellings that PEP 503 says name the SAME
    /// project, keyed by their canonical form.
    ///
    /// One upload per group, then a read back under every spelling in it. That
    /// covers acceptance (no spelling is rejected) and correctness (every
    /// spelling resolves to the one project) in a single pass, and it makes the
    /// case-folding and separator-collapsing rules of PEP 503 executable rather
    /// than asserted only against a helper.
    fn valid_name_groups() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            // Single character: the first branch of the PEP 508 alternation,
            // and the shape an off-by-one in the pattern breaks first.
            ("a", vec!["a", "A"]),
            ("z", vec!["z", "Z"]),
            // Digits only.
            ("0", vec!["0"]),
            ("123", vec!["123"]),
            ("2024", vec!["2024"]),
            // Two characters: the second branch with an empty middle.
            ("ab", vec!["ab", "AB", "Ab"]),
            ("a1", vec!["a1"]),
            ("1a", vec!["1a"]),
            // Every separator, and every run of separators, collapses to one
            // '-' per PEP 503's `re.sub(r"[-_.]+", "-", name)`.
            (
                "a-b",
                vec!["a-b", "a_b", "a.b", "a__b", "a--b", "a._-b", "A-B"],
            ),
            ("a-b-c-d", vec!["a.b-c_d", "a-b-c-d", "A.B-C_D"]),
            // Mixed case lowercases.
            ("mypackage", vec!["MyPackage", "mypackage", "MYPACKAGE"]),
            ("django", vec!["Django"]),
            ("pyyaml", vec!["PyYAML"]),
            ("jinja2", vec!["Jinja2"]),
            // Real-world dotted names.
            ("zope-interface", vec!["zope.interface", "zope-interface"]),
            ("ruamel-yaml", vec!["ruamel.yaml"]),
            (
                "backports-ssl-match-hostname",
                vec!["backports.ssl_match_hostname"],
            ),
            ("acme-sdk", vec!["acme-sdk", "acme_sdk", "ACME-SDK"]),
            ("requests", vec!["requests"]),
        ]
    }

    /// The positive control, and the one that matters more than the rejection
    /// tests: a name that IS a PEP 508 name must still work end to end.
    ///
    /// This deliberately does NOT settle for "did not return the validation
    /// 404". It uploads a real distribution under each name and reads it back
    /// from the simple index, so the assertion is a 200 that LISTS THE WHEEL --
    /// something an over-rejecting validator cannot produce, and something a
    /// wrongly-normalizing one cannot produce either.
    ///
    /// An earlier revision asserted "an unknown valid project returns 200 with
    /// an empty index". That was simply false -- a local repo 404s "Package not
    /// found" for an absent project -- and the test caught it. Recorded because
    /// the false version would have passed while proving nothing.
    #[tokio::test]
    async fn valid_project_names_round_trip_upload_to_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let mut failures: Vec<String> = Vec::new();

        for (canonical, spellings) in valid_name_groups() {
            let upload_name = spellings[0];
            // Wheel filenames use '_' where the project name uses a separator.
            let filename = format!(
                "{}-1.0.0-py3-none-any.whl",
                upload_name.replace(['.', '-'], "_")
            );
            let (content_type, body) = pypi_upload_multipart(
                upload_name,
                "1.0.0",
                &filename,
                b"fake-wheel-bytes",
                "pep508 positive control",
                ">=3.8",
            );
            let app = fx.router_with_auth(super::router());
            let (upload_status, upload_body) = tdh::send(
                app,
                tdh::post(format!("/{}/", fx.repo_key), &content_type, body),
            )
            .await;
            if upload_status != StatusCode::OK {
                failures.push(format!(
                    "upload of valid name {upload_name:?} failed with {upload_status}; body {}",
                    String::from_utf8_lossy(&upload_body)
                ));
                continue;
            }

            for spelling in &spellings {
                let uri = format!("/{}/simple/{spelling}/", fx.repo_key);
                let app = fx.router_with_auth(super::router());
                let (status, body) = tdh::send(app, tdh::get(uri.clone())).await;
                let body = String::from_utf8_lossy(&body).into_owned();
                if status != StatusCode::OK {
                    failures.push(format!(
                        "index {uri}: spelling {spelling:?} of canonical {canonical:?} \
                         must serve 200, got {status}; body {body}"
                    ));
                } else if !body.contains(&filename) {
                    failures.push(format!(
                        "index {uri}: spelling {spelling:?} served 200 but did not list \
                         {filename} -- it resolved to the wrong project; body {body}"
                    ));
                }
            }
        }

        fx.teardown().await;

        assert!(
            failures.is_empty(),
            "PEP 508-valid project names did not work -- over-rejection here breaks \
             all real pip traffic:\n{}",
            failures.join("\n")
        );
    }

    /// The download and PEP 658 metadata routes 404 for an absent file whether
    /// or not validation ran, so they get their own targeted assertion: a valid
    /// name must never produce the *validation* 404 on either of them.
    #[tokio::test]
    async fn valid_names_are_not_rejected_on_download_or_metadata_routes() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let wheel = "pkg-1.0.0-py3-none-any.whl";
        let mut failures: Vec<String> = Vec::new();

        for (_canonical, spellings) in valid_name_groups() {
            for name in spellings {
                for (route, uri) in [
                    (
                        "download",
                        format!("/{}/simple/{name}/{wheel}", fx.repo_key),
                    ),
                    (
                        "PEP 658 metadata",
                        format!("/{}/simple/{name}/{wheel}.metadata", fx.repo_key),
                    ),
                ] {
                    let app = fx.router_with_auth(super::router());
                    let (_status, body) = tdh::send(app, tdh::get(uri.clone())).await;
                    let body = String::from_utf8_lossy(&body).into_owned();
                    if body.contains(PROJECT_REJECTED_MESSAGE) {
                        failures.push(format!(
                            "{route} {uri}: valid name {name:?} was rejected by name validation"
                        ));
                    }
                }
            }
        }

        fx.teardown().await;

        assert!(
            failures.is_empty(),
            "PEP 508-valid names were rejected on a serve route:\n{}",
            failures.join("\n")
        );
    }

    /// Rejection must happen BEFORE any upstream fetch, not merely before the
    /// response is written.
    ///
    /// Differential, so it cannot pass vacuously: the same mock upstream is hit
    /// with a valid name and an invalid one. The valid name must reach it (which
    /// proves the proxy wiring is live) and the invalid name must not (which
    /// proves validation short-circuits ahead of the fetch). Without the
    /// control, "upstream saw nothing" would also be satisfied by a broken
    /// fixture.
    #[tokio::test]
    async fn invalid_project_segment_never_reaches_the_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::any;
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("point the fixture repo at the mock upstream");

        let proxy = tdh::build_proxy_service_with_fs(
            fx.pool.clone(),
            fx.storage_dir.to_str().expect("storage dir"),
        );
        let state = tdh::build_state_with_proxy(
            fx.pool.clone(),
            fx.storage_dir.to_str().expect("storage dir"),
            proxy,
        );

        let wheel = "pkg-1.0.0-py3-none-any.whl";

        // Invalid name first, so the count below cannot be polluted by the
        // control request.
        let app = tdh::router_anon(super::router(), state.clone());
        let (invalid_status, invalid_body) = tdh::send(
            app,
            tdh::get(format!("/{}/simple/acme%20sdk/{wheel}", fx.repo_key)),
        )
        .await;
        let after_invalid = upstream
            .received_requests()
            .await
            .expect("mock upstream records requests")
            .len();

        // Control: a valid name on the same repo MUST reach the upstream.
        let app = tdh::router_anon(super::router(), state.clone());
        let (_control_status, _control_body) = tdh::send(
            app,
            tdh::get(format!("/{}/simple/acme-sdk/{wheel}", fx.repo_key)),
        )
        .await;
        let after_control = upstream
            .received_requests()
            .await
            .expect("mock upstream records requests")
            .len();

        fx.teardown().await;

        assert_eq!(
            invalid_status,
            StatusCode::NOT_FOUND,
            "invalid name must 404; body: {}",
            String::from_utf8_lossy(&invalid_body)
        );
        assert!(
            String::from_utf8_lossy(&invalid_body).contains(PROJECT_REJECTED_MESSAGE),
            "the 404 must come from name validation; body: {}",
            String::from_utf8_lossy(&invalid_body)
        );
        assert_eq!(
            after_invalid, 0,
            "an invalid project name made {after_invalid} upstream request(s); \
             validation must short-circuit before ANY fetch"
        );
        assert!(
            after_control > 0,
            "control failed: a VALID name made no upstream request either, so the \
             zero-request assertion above proves nothing"
        );
    }

    // -----------------------------------------------------------------------
    // #3198 — the upload channel
    // -----------------------------------------------------------------------

    /// PEP 508-invalid names, as they arrive on the *upload* channel.
    ///
    /// Deliberately a separate list from [`invalid_route_names`], for two
    /// reasons. Nothing here is percent-encoded — a twine upload carries the
    /// project name in a multipart form field, not a path segment, so there is
    /// no URL layer to encode for. And every entry is a raw field value that a
    /// `multipart/form-data` body can actually carry, which rules out the CR/LF
    /// cases: a bare newline in a field value is a *multipart framing* problem,
    /// so a rejection would prove the parser works rather than that name
    /// validation does.
    ///
    /// Each entry carries the name `PypiHandler::normalize_name` coerces it to,
    /// which is what the unvalidated upload path stored it under. That column
    /// is the point of the issue: the coercion is silent, and it is not the
    /// name the publisher asked for.
    fn invalid_upload_names() -> Vec<(&'static str, &'static str)> {
        vec![
            // The motivating case. `acme sdk` is not a project name, but the
            // upload path coerced it into the namespace of `acme-sdk`, which
            // IS one — so the publisher silently squats a different project.
            ("acme sdk", "acme-sdk"),
            ("acme!sdk", "acme-sdk"),
            ("acme@sdk", "acme-sdk"),
            ("acme/sdk", "acme-sdk"),
            // Non-ASCII. `normalize_name` keys on `is_ascii_alphanumeric`, so
            // the `é` is coerced to a separator and swallows the `-` after it:
            // `acmé-sdk` lands under `acm-sdk`, a third distinct project.
            ("acmé-sdk", "acm-sdk"),
            ("acme\u{212A}sdk", "acme-sdk"),
            // PEP 508 requires an alphanumeric at both ends. `normalize_name`
            // skips leading separators and pops one trailing hyphen, so these
            // are silently renamed rather than refused.
            ("_leading", "leading"),
            ("-leading", "leading"),
            (".leading", "leading"),
            ("trailing_", "trailing"),
            ("trailing-", "trailing"),
            // Names made only of separators coerce to the EMPTY string. This is
            // the shape the issue titles: stored at path `/<version>/<file>`,
            // counted against quota, and unreachable at any URL, because
            // `/simple//` is not a route.
            ("---", ""),
            ("...", ""),
            ("", ""),
            // The stored-XSS payload `normalize_pep503` drops characters for.
            ("<script>", "script"),
        ]
    }

    /// The canonical, PEP 508-valid name every case in this test is measured
    /// against. It carries a separator on purpose: on a separator-free fixture
    /// such as `demo` the two legacy coercions cannot diverge, so the squatting
    /// assertion below would pass on the unfixed tree and report a false all-clear.
    const UPLOAD_CONTROL_PROJECT: &str = "acme-sdk";
    const UPLOAD_CONTROL_WHEEL: &str = "acme_sdk-1.0.0-py3-none-any.whl";

    /// The upload path must reject a project name that is not a PEP 508 name,
    /// with 400 — and a valid one must still publish and resolve.
    ///
    /// Three claims in one fixture, because separately each is satisfiable by
    /// the bug:
    ///
    /// 1. **400 on upload.** PEP 508 (*Names*) gives the pattern; an upload
    ///    naming something outside it is a malformed request, not a missing
    ///    resource, so it is 400 here and not the 404 the read routes give a
    ///    path segment (#3196).
    /// 2. **No squatting.** Rejecting is only half the fix: what made this worth
    ///    closing is *where the bytes went*. `PypiHandler::normalize_name` maps
    ///    every non-alphanumeric to `-`, so `acme sdk` was stored under
    ///    `acme-sdk` — a real, valid, possibly-someone-else's project. The
    ///    canonical index must not list a distribution uploaded under any of
    ///    these names.
    /// 3. **The positive control, in the same fixture and the same response.**
    ///    `acme-sdk` itself must upload with 200 and be listed by its own simple
    ///    index. Without it, claim 2 would be satisfied by a repo that serves
    ///    nothing at all — the failure mode that made an earlier security test
    ///    on #3179 green while the vulnerability was live.
    #[tokio::test]
    async fn pep508_invalid_upload_name_is_rejected_and_cannot_squat_a_valid_project() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let mut failures: Vec<String> = Vec::new();

        // Positive control first: publish the canonical project for real.
        let (content_type, body) = pypi_upload_multipart(
            UPLOAD_CONTROL_PROJECT,
            "1.0.0",
            UPLOAD_CONTROL_WHEEL,
            b"fake-wheel-bytes-control",
            "pep508 upload control",
            ">=3.8",
        );
        let app = fx.router_with_auth(super::router());
        let (control_status, control_body) = tdh::send(
            app,
            tdh::post(format!("/{}/", fx.repo_key), &content_type, body),
        )
        .await;
        if control_status != StatusCode::OK {
            failures.push(format!(
                "control upload of {UPLOAD_CONTROL_PROJECT:?} must succeed, got {control_status}; \
                 body: {}",
                String::from_utf8_lossy(&control_body)
            ));
        }

        // Every PEP 508-invalid name must be refused with 400, and the refusal
        // must name the pattern so the publisher can act on it.
        for (index, (raw, coerced_to)) in invalid_upload_names().into_iter().enumerate() {
            let filename = format!("squatted_{index}-9.9.9-py3-none-any.whl");
            let (content_type, body) = pypi_upload_multipart(
                raw,
                "9.9.9",
                &filename,
                b"fake-wheel-bytes-squat",
                "pep508 upload rejection",
                ">=3.8",
            );
            let app = fx.router_with_auth(super::router());
            let (status, body) = tdh::send(
                app,
                tdh::post(format!("/{}/", fx.repo_key), &content_type, body),
            )
            .await;
            let body = String::from_utf8_lossy(&body).into_owned();

            if status != StatusCode::BAD_REQUEST {
                failures.push(format!(
                    "upload named {raw:?} (coerces to {coerced_to:?}): expected 400, got {status}; \
                     body: {body}"
                ));
            } else if !body.contains(UPLOAD_NAME_REJECTED_MESSAGE) {
                // A 400 alone is not proof — a malformed body, a missing field
                // or a digest mismatch all produce one. The pattern in the
                // message is what shows name validation produced it.
                failures.push(format!(
                    "upload named {raw:?}: 400 but not from PEP 508 validation; body: {body}"
                ));
            }
        }

        // The canonical index must list its own wheel and nothing that was
        // uploaded under an invalid name.
        let app = fx.router_with_auth(super::router());
        let (index_status, index_body) = tdh::send(
            app,
            tdh::get(format!("/{}/simple/{UPLOAD_CONTROL_PROJECT}/", fx.repo_key)),
        )
        .await;
        let index_body = String::from_utf8_lossy(&index_body).into_owned();

        fx.teardown().await;

        if index_status != StatusCode::OK {
            failures.push(format!(
                "control index /simple/{UPLOAD_CONTROL_PROJECT}/ must be 200, got {index_status}; \
                 body: {index_body}"
            ));
        }
        if !index_body.contains(UPLOAD_CONTROL_WHEEL) {
            failures.push(format!(
                "control index does not list {UPLOAD_CONTROL_WHEEL}, so the \
                 'no squatted distribution' assertion below proves nothing; body: {index_body}"
            ));
        }
        if index_body.contains("squatted_") {
            failures.push(format!(
                "a distribution uploaded under a PEP 508-invalid name is listed in the \
                 index of {UPLOAD_CONTROL_PROJECT}; body: {index_body}"
            ));
        }

        assert!(
            failures.is_empty(),
            "PyPI upload name validation (#3198) failed:\n{}",
            failures.join("\n")
        );
    }

    // -----------------------------------------------------------------------
    // #3107 -- distribution/metadata consistency on the upload channel
    // -----------------------------------------------------------------------

    /// Build a minimal but *real* wheel (a ZIP carrying `.dist-info/METADATA`)
    /// whose declared `Name`/`Version` are `meta_name`/`meta_version`. Used to
    /// drive the #3107 consistency check, which reads the archive's real
    /// metadata rather than trusting the multipart form fields.
    fn build_test_wheel(meta_name: &str, meta_version: &str) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file(
                format!("{meta_name}-{meta_version}.dist-info/METADATA"),
                options,
            )
            .expect("start METADATA");
            write!(
                zip,
                "Metadata-Version: 2.1\nName: {meta_name}\nVersion: {meta_version}\n"
            )
            .expect("write METADATA");
            zip.finish().expect("finish wheel zip");
        }
        cursor.into_inner()
    }

    /// Build a minimal but *real* sdist (a gzip'd tar carrying `PKG-INFO`) whose
    /// declared `Name`/`Version` are `meta_name`/`meta_version`.
    fn build_test_sdist(meta_name: &str, meta_version: &str) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let pkg_info =
            format!("Metadata-Version: 2.1\nName: {meta_name}\nVersion: {meta_version}\n");
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header
            .set_path(format!("{meta_name}-{meta_version}/PKG-INFO"))
            .expect("set PKG-INFO path");
        header.set_size(pkg_info.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append(&header, pkg_info.as_bytes())
            .expect("append PKG-INFO");
        let tar_bytes = tar_builder.into_inner().expect("finish tar");

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    /// `PypiHandler::validate` (formats/pypi.rs) held name/version-vs-metadata
    /// checks but had no call site, so a distribution whose embedded metadata
    /// named a *different* project or version than the twine `name`/`version`
    /// fields published unchecked into the declared namespace (#3107). Wiring
    /// the check must:
    ///
    /// 1. **Positive control, same fixture.** A wheel and an sdist whose
    ///    metadata matches the declared identity upload with 200 and are listed
    ///    by their own simple index — without this a validator that rejects
    ///    everything would satisfy every negative assertion below (the #3179
    ///    failure mode).
    /// 2. **Reject name confusion.** A wheel/sdist whose `METADATA`/`PKG-INFO`
    ///    `Name` disagrees with the declared project is 400 and never lands in
    ///    that project's index.
    /// 3. **Reject version confusion.** A wheel whose `METADATA` `Version`
    ///    disagrees with the declared version is 400.
    /// 4. **PEP 440 equivalence is not a mismatch.** Declaring `1.0` for a wheel
    ///    whose metadata says `1.0.0` still succeeds — the guard must not
    ///    over-reject versions PEP 440 considers equal.
    ///
    /// The 400s must carry the word `mismatch`: a 400 alone proves nothing
    /// (a malformed body, a missing field or a digest error all produce one).
    #[tokio::test]
    async fn pypi_upload_rejects_distribution_metadata_mismatch_but_allows_consistent_ones() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        let mut failures: Vec<String> = Vec::new();

        // Helper: POST an upload, return (status, body).
        async fn upload(
            fx: &tdh::Fixture,
            project: &str,
            version: &str,
            filename: &str,
            content: &[u8],
        ) -> (StatusCode, String) {
            use crate::api::handlers::test_db_helpers as tdh;
            let (content_type, body) = pypi_upload_multipart(
                project,
                version,
                filename,
                content,
                "#3107 consistency",
                ">=3.8",
            );
            let app = fx.router_with_auth(super::router());
            let (status, body) = tdh::send(
                app,
                tdh::post(format!("/{}/", fx.repo_key), &content_type, body),
            )
            .await;
            (status, String::from_utf8_lossy(&body).into_owned())
        }

        // Helper: GET a project's simple index, return (status, body).
        async fn simple_index(fx: &tdh::Fixture, project: &str) -> (StatusCode, String) {
            use crate::api::handlers::test_db_helpers as tdh;
            let app = fx.router_with_auth(super::router());
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{}/simple/{project}/", fx.repo_key))).await;
            (status, String::from_utf8_lossy(&body).into_owned())
        }

        // (1) Positive control: a consistent wheel publishes and resolves.
        let good_wheel = "goodpkg-1.0.0-py3-none-any.whl";
        let (st, body) = upload(
            &fx,
            "goodpkg",
            "1.0.0",
            good_wheel,
            &build_test_wheel("goodpkg", "1.0.0"),
        )
        .await;
        if st != StatusCode::OK {
            failures.push(format!(
                "consistent wheel must upload (200), got {st}; body: {body}"
            ));
        }
        let (st, body) = simple_index(&fx, "goodpkg").await;
        if st != StatusCode::OK || !body.contains(good_wheel) {
            failures.push(format!(
                "consistent wheel must be listed at /simple/goodpkg/ (200 + lists {good_wheel}); \
                 got {st}; body: {body}"
            ));
        }

        // (1) Positive control: a consistent sdist publishes and resolves.
        let good_sdist = "goodsdist-2.0.0.tar.gz";
        let (st, body) = upload(
            &fx,
            "goodsdist",
            "2.0.0",
            good_sdist,
            &build_test_sdist("goodsdist", "2.0.0"),
        )
        .await;
        if st != StatusCode::OK {
            failures.push(format!(
                "consistent sdist must upload (200), got {st}; body: {body}"
            ));
        }
        let (st, body) = simple_index(&fx, "goodsdist").await;
        if st != StatusCode::OK || !body.contains(good_sdist) {
            failures.push(format!(
                "consistent sdist must be listed at /simple/goodsdist/; got {st}; body: {body}"
            ));
        }

        // (4) PEP 440 equivalence: declared `1.0` vs metadata `1.0.0` -> 200.
        let canon_wheel = "canonpkg-1.0-py3-none-any.whl";
        let (st, body) = upload(
            &fx,
            "canonpkg",
            "1.0",
            canon_wheel,
            &build_test_wheel("canonpkg", "1.0.0"),
        )
        .await;
        if st != StatusCode::OK {
            failures.push(format!(
                "PEP 440-equivalent version (declared 1.0, metadata 1.0.0) must NOT be rejected; \
                 got {st}; body: {body}"
            ));
        }

        // (2) Name confusion in a wheel -> 400 mismatch, and nothing squats.
        let (st, body) = upload(
            &fx,
            "realclaim",
            "1.0.0",
            "realclaim-1.0.0-py3-none-any.whl",
            &build_test_wheel("evilpkg", "1.0.0"),
        )
        .await;
        if st != StatusCode::BAD_REQUEST || !body.to_lowercase().contains("mismatch") {
            failures.push(format!(
                "wheel whose metadata names a different project must be 400 with 'mismatch'; \
                 got {st}; body: {body}"
            ));
        }
        let (_st, body) = simple_index(&fx, "realclaim").await;
        if body.contains("realclaim-1.0.0-py3-none-any.whl") {
            failures.push(format!(
                "a name-mismatched wheel must not land in /simple/realclaim/; body: {body}"
            ));
        }

        // (3) Version confusion in a wheel -> 400 mismatch.
        let (st, body) = upload(
            &fx,
            "verpkg",
            "1.0.0",
            "verpkg-1.0.0-py3-none-any.whl",
            &build_test_wheel("verpkg", "9.9.9"),
        )
        .await;
        if st != StatusCode::BAD_REQUEST || !body.to_lowercase().contains("mismatch") {
            failures.push(format!(
                "wheel whose metadata version disagrees must be 400 with 'mismatch'; \
                 got {st}; body: {body}"
            ));
        }

        // (2) Name confusion in an sdist -> 400 mismatch.
        let (st, body) = upload(
            &fx,
            "sdistclaim",
            "1.0.0",
            "sdistclaim-1.0.0.tar.gz",
            &build_test_sdist("othersdist", "1.0.0"),
        )
        .await;
        if st != StatusCode::BAD_REQUEST || !body.to_lowercase().contains("mismatch") {
            failures.push(format!(
                "sdist whose metadata names a different project must be 400 with 'mismatch'; \
                 got {st}; body: {body}"
            ));
        }

        fx.teardown().await;

        assert!(
            failures.is_empty(),
            "PyPI upload metadata-consistency (#3107) failed:\n{}",
            failures.join("\n")
        );
    }

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

    /// Expected shape of a REGENERATED simple-index page (GHSA-4cw7-mgqj-hgmg):
    /// `rewrite_upstream_urls` no longer edits the upstream page in place — it
    /// emits a fresh minimal PEP 503 document containing ONLY the rebuilt
    /// anchors. The skeleton carries the `</head>` / `</body>` markers
    /// `merge_local_into_remote_simple_html` splices into.
    fn rebuilt_simple_page(anchors: &str) -> String {
        format!(
            "<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n</head>\n<body>\n{anchors}</body>\n</html>\n"
        )
    }

    #[test]
    fn test_rewrite_absolute_url_with_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/ab/cd/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            rebuilt_simple_page(
                r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a><br/>
"#
            )
        );
    }

    #[test]
    fn test_rewrite_absolute_url_without_hash() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-remote", "numpy");
        assert_eq!(
            result,
            rebuilt_simple_page(
                r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz">numpy-1.3.0.tar.gz</a><br/>
"#
            )
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
            rebuilt_simple_page(
                r#"<a href="/pypi/repo/simple/pkg/pkg-1.0.tar.gz">pkg-1.0.tar.gz</a><br/>
"#
            )
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
        // GHSA-4cw7-mgqj-hgmg: a page with no file anchors regenerates as an
        // EMPTY listing — the upstream `<h1>` (and any other markup) no longer
        // passes through.
        let html = "<html><body><h1>No links here</h1></body></html>";
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(result, rebuilt_simple_page(""));
        assert!(
            !result.contains("<h1>"),
            "upstream markup survived: {result}"
        );
    }

    #[test]
    fn test_rewrite_empty_string() {
        let result = rewrite_upstream_urls("", "repo", "pkg");
        assert_eq!(result, rebuilt_simple_page(""));
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

        // GHSA-4cw7-mgqj-hgmg: non-link upstream content does NOT survive —
        // the page is regenerated from parsed anchors, so the upstream's
        // `<h1>`/`<title>` are gone. The repository-version meta that remains
        // is OUR OWN skeleton's, not the upstream's.
        assert!(!result.contains("<h1>Links for numpy</h1>"));
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
            rebuilt_simple_page(
                r#"<a href="/pypi/pypi-remote/simple/numpy/numpy-1.3.0.tar.gz#sha256=abc123">numpy-1.3.0.tar.gz</a><br/>
"#
            )
        );
    }

    #[test]
    fn test_rewrite_local_upstream_without_hash() {
        let html = r#"<a href="/pypi/upstream-local/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "remote-repo", "pkg");
        assert_eq!(
            result,
            rebuilt_simple_page(
                r#"<a href="/pypi/remote-repo/simple/pkg/pkg-2.0.whl">pkg-2.0.whl</a><br/>
"#
            )
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

        // data-requires-python is preserved; the upstream page structure is
        // NOT (GHSA-4cw7-mgqj-hgmg — the page is regenerated).
        assert!(result.contains("data-requires-python"));
        assert!(!result.contains("<h1>Links for mypackage</h1>"));
    }

    #[test]
    fn test_rewrite_preserves_data_dist_info_metadata() {
        // Real PyPI HTML includes data-dist-info-metadata on .whl links.
        // The metadata URL is proxied through the same upstream Simple API,
        // so its hash must remain attached to the rewritten wheel link.
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=8abb" data-requires-python="&gt;=2.7" data-dist-info-metadata="sha256=5507" data-core-metadata="sha256=5507">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result = rewrite_upstream_urls(html, "pypi-proxy", "six");
        assert!(result.contains(
            r#"href="/pypi/pypi-proxy/simple/six/six-1.16.0-py2.py3-none-any.whl#sha256=8abb""#
        ));
        // data-requires-python should be preserved
        assert!(result.contains(r#"data-requires-python="&gt;=2.7""#));
        assert!(result.contains(r#"data-dist-info-metadata="sha256=5507""#));
        assert!(result.contains(r#"data-core-metadata="sha256=5507""#));
    }

    #[test]
    fn test_rewrite_preserves_metadata_attrs_from_real_pypi_html() {
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

        // PEP 658 metadata hashes must be preserved on the .whl link
        assert!(result.contains(r#"data-dist-info-metadata="sha256=5620""#));
        assert!(result.contains(r#"data-core-metadata="sha256=5620""#));

        // Upstream page structure does NOT survive the regeneration
        // (GHSA-4cw7-mgqj-hgmg).
        assert!(!result.contains("<h1>Links for six</h1>"));
    }

    // -----------------------------------------------------------------------
    // PEP 691 JSON proxy: upstream URL rewriting + upload-time preservation
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_upstream_simple_json_rewrites_urls_preserves_metadata() {
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

        assert_eq!(file["core-metadata"]["sha256"], "abc");
        assert_eq!(file["data-dist-info-metadata"]["sha256"], "abc");
    }

    #[test]
    fn test_rewrite_upstream_simple_json_returns_none_for_non_json() {
        assert!(rewrite_upstream_simple_json(b"<!DOCTYPE html><html></html>", "r", "p").is_none());
    }

    #[test]
    fn test_empty_pep691_listing_preserves_required_project_shape() {
        let doc: serde_json::Value =
            serde_json::from_str(&empty_pep691_listing("my-package")).unwrap();

        assert_eq!(doc["meta"]["api-version"], "1.0");
        assert_eq!(doc["name"], "my-package");
        assert_eq!(doc["versions"], serde_json::json!([]));
        assert_eq!(doc["files"], serde_json::json!([]));
    }

    // -----------------------------------------------------------------------
    // #2801: content-sniffing hardening for the simple-index proxy. When an
    // upstream / corporate proxy mislabels the simple-index Content-Type (e.g.
    // `application/octet-stream`), the render fallthrough must sniff the body
    // and rewrite it through the proxy, never serve raw offsite URLs, and 502
    // on a genuinely unrecognizable body.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sniff_simple_index_classifies_json_html_and_binary() {
        // Leading `{` / `[` (with leading whitespace + BOM) => JSON.
        assert_eq!(
            sniff_simple_index(b"  \n  {\"meta\":{}}"),
            SniffedSimpleIndex::Json
        );
        assert_eq!(sniff_simple_index(b"[1,2,3]"), SniffedSimpleIndex::Json);
        assert_eq!(
            sniff_simple_index(b"\xEF\xBB\xBF{\"files\":[]}"),
            SniffedSimpleIndex::Json
        );

        // PEP 503 markers => HTML.
        assert_eq!(
            sniff_simple_index(b"<!DOCTYPE html><html><body></body></html>"),
            SniffedSimpleIndex::Html
        );
        assert_eq!(
            sniff_simple_index(b"<a href=\"x-1.0.tar.gz\">x-1.0.tar.gz</a>"),
            SniffedSimpleIndex::Html
        );

        // Anything else => Binary.
        assert_eq!(
            sniff_simple_index(&[0x00, 0x01, 0x02, 0xff, 0xfe]),
            SniffedSimpleIndex::Binary
        );
        assert_eq!(sniff_simple_index(b""), SniffedSimpleIndex::Binary);
        assert_eq!(
            sniff_simple_index(b"just some plain text, not an index"),
            SniffedSimpleIndex::Binary
        );
    }

    #[test]
    fn test_sniff_then_rewrite_json_body_mislabeled_octet_stream() {
        // (a) A PEP 691 JSON body that upstream labeled `application/octet-stream`.
        // The fix sniffs it as JSON, then rewrites files[].url through the repo
        // and serves the JSON simple-index media type — no offsite URL survives.
        let upstream = r#"{
            "meta": {"api-version": "1.1"},
            "name": "jsonpkg",
            "versions": ["1.0.0"],
            "files": [
                {
                    "filename": "jsonpkg-1.0.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/aa/bb/jsonpkg-1.0.0-py3-none-any.whl",
                    "hashes": {"sha256": "deadbeef"}
                }
            ]
        }"#;

        assert_eq!(
            sniff_simple_index(upstream.as_bytes()),
            SniffedSimpleIndex::Json
        );

        let out =
            rewrite_upstream_simple_json(upstream.as_bytes(), "bgd-htmlv", "jsonpkg").unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            json["files"][0]["url"],
            "/pypi/bgd-htmlv/simple/jsonpkg/jsonpkg-1.0.0-py3-none-any.whl"
        );
        // No offsite download URL leaks into the rendered body.
        assert!(!out.contains("files.pythonhosted"));
    }

    #[test]
    fn test_sniff_then_rewrite_html_body_mislabeled_octet_stream() {
        // (b) A PEP 503 HTML body labeled `application/octet-stream`. Sniffed as
        // HTML, then the anchor href is rewritten through the repo.
        let upstream = r#"<!DOCTYPE html><html><body>
<a href="https://files.pythonhosted.org/packages/ab/cd/htmlpkg-2.0.0.tar.gz#sha256=abc123">htmlpkg-2.0.0.tar.gz</a>
</body></html>"#;

        assert_eq!(
            sniff_simple_index(upstream.as_bytes()),
            SniffedSimpleIndex::Html
        );

        let out = rewrite_upstream_urls(upstream, "bgd-htmlv", "htmlpkg");
        assert!(out.contains(
            "href=\"/pypi/bgd-htmlv/simple/htmlpkg/htmlpkg-2.0.0.tar.gz#sha256=abc123\""
        ));
        // No offsite download URL leaks into the rendered body.
        assert!(!out.contains("files.pythonhosted"));
    }

    #[test]
    fn test_binary_body_yields_502_and_no_offsite_urls() {
        // (c) Unrecognizable / binary upstream body => 502 Bad Gateway, and we
        // never render the raw bytes. The classifier refuses it up front.
        let garbage: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(sniff_simple_index(garbage), SniffedSimpleIndex::Binary);

        let resp = bad_upstream_simple_index();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
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

    // -----------------------------------------------------------------------
    // #2748: the virtual union must describe a distribution the SAME way the
    // direct repository does. Each of these fails on main.
    // -----------------------------------------------------------------------

    /// The reporter's topology in miniature: a local member owns the name, a
    /// remote member answers, so the virtual renders through the merge emitter.
    /// The local wheel must still advertise the PEP 658/714 `core-metadata`
    /// flag it advertises on the direct path — otherwise the same URL gains or
    /// loses the metadata fast path depending on whether an upstream happened to
    /// respond (a remote fetch miss is a silent `debug!`).
    #[test]
    fn test_merge_local_into_remote_simple_json_advertises_core_metadata_for_local_wheels() {
        let upstream = r#"{"meta":{"api-version":"1.1"},"name":"pkg","versions":[],"files":[]}"#;
        let local = vec![
            SimpleProjectArtifact {
                path: "pkg/1.0.0/pkg-1.0.0-cp39-cp39-manylinux_2_17_x86_64.whl".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 9,
                checksum_sha256: "h".to_string(),
                metadata: None,
                upload_time: None,
            },
            SimpleProjectArtifact {
                path: "pkg/1.0.0/pkg-1.0.0.tar.gz".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 5,
                checksum_sha256: "s".to_string(),
                metadata: None,
                upload_time: None,
            },
        ];

        let out = merge_local_into_remote_simple_json(upstream.as_bytes(), "v", "pkg", &local, &[])
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let files = json["files"].as_array().unwrap();

        let wheel = files
            .iter()
            .find(|f| f["filename"] == "pkg-1.0.0-cp39-cp39-manylinux_2_17_x86_64.whl")
            .expect("local wheel spliced in");
        assert_eq!(
            wheel["core-metadata"], true,
            "a local wheel must advertise PEP 658 core-metadata through the virtual union, \
             exactly as it does through the direct repository"
        );

        // An sdist ships no METADATA sidecar, so it must NOT advertise one —
        // advertising it would make both pip and uv hard-fail on the 404.
        let sdist = files
            .iter()
            .find(|f| f["filename"] == "pkg-1.0.0.tar.gz")
            .expect("local sdist spliced in");
        assert!(sdist.get("core-metadata").is_none());
    }

    /// The direct emitter and the virtual merge emitter must produce
    /// byte-identical `files[]` entries for the same local artifact. Pinning the
    /// equality (rather than one field) is what stops the next field added to
    /// one emitter from silently missing on the other.
    #[test]
    fn test_local_file_json_is_identical_on_the_direct_and_virtual_paths() {
        let upload_time = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let artifact = SimpleProjectArtifact {
            path: "pkg/1.2.3/pkg-1.2.3-py3-none-any.whl".to_string(),
            version: Some("1.2.3".to_string()),
            size_bytes: 42,
            checksum_sha256: "abc".to_string(),
            metadata: Some(serde_json::json!({"pkg_info": {"requires_python": ">=3.9"}})),
            upload_time: Some(upload_time),
        };

        let direct = local_simple_file_json(&artifact, "v", "pkg");

        let upstream = r#"{"meta":{"api-version":"1.1"},"name":"pkg","versions":[],"files":[]}"#;
        let merged = merge_local_into_remote_simple_json(
            upstream.as_bytes(),
            "v",
            "pkg",
            std::slice::from_ref(&artifact),
            &[],
        )
        .unwrap();
        let merged: serde_json::Value = serde_json::from_str(&merged).unwrap();

        assert_eq!(merged["files"][0], direct);
    }

    /// A suppressed Remote member's Case-A wheel is a real, installable
    /// distribution. Rebuilding its anchor without `data-requires-python` offers
    /// an incompatible build to every interpreter, and without `data-yanked`
    /// (PEP 592) presents a withdrawn release as an ordinary candidate. The JSON
    /// sibling always kept both, so the two representations of one virtual index
    /// disagreed about installability.
    #[test]
    fn test_filter_remote_case_a_html_preserves_data_attributes() {
        let owned = linux_owner_profile();
        let upstream = concat!(
            "<!DOCTYPE html><html><body>\n",
            "<a href=\"https://files.pythonhosted.org/p/pydantic_core-2.0-cp39-cp39-win_amd64.whl#sha256=aa\"",
            " data-requires-python=\"&gt;=3.12\"",
            " data-core-metadata=\"sha256=bb\"",
            " data-yanked=\"CVE-2026-0001\">pydantic_core-2.0-cp39-cp39-win_amd64.whl</a><br/>\n",
            "</body></html>\n",
        );

        let out = filter_remote_case_a_html(upstream, &owned, "virt", "pydantic-core");

        assert!(
            out.contains("data-requires-python=\"&gt;=3.12\""),
            "PEP 503 requires-python must survive the ownership rebuild: {out}"
        );
        assert!(
            out.contains("data-yanked=\"CVE-2026-0001\""),
            "PEP 592 yanked must survive the ownership rebuild: {out}"
        );
        assert!(
            out.contains("data-core-metadata=\"sha256=bb\""),
            "PEP 658 core-metadata must survive the ownership rebuild: {out}"
        );
        // Unchanged invariants: AK-pathed href, fragment kept, no upstream host.
        assert!(out.contains(
            "href=\"/pypi/virt/simple/pydantic-core/pydantic_core-2.0-cp39-cp39-win_amd64.whl#sha256=aa\""
        ));
        assert!(!out.contains("files.pythonhosted"));
    }

    /// Sharing the anchor rebuilder also gives the ownership filter the proxy
    /// rebuild's filename-metacharacter check, which it previously lacked.
    #[test]
    fn test_filter_remote_case_a_html_drops_attribute_breakout_filenames() {
        let owned = linux_owner_profile();
        let upstream = "<a href='https://x/p/\"><script>alert(1)</script>.whl'>x</a>";
        let out = filter_remote_case_a_html(upstream, &owned, "virt", "pydantic-core");
        assert!(!out.contains("script"), "{out}");
    }

    /// `versions` must be PEP 440-ordered on every emitter (#3106), not just the
    /// direct one — a `BTreeSet<String>` puts `1.10` before `1.9`.
    #[test]
    fn test_merge_local_into_remote_simple_json_orders_versions_by_pep440() {
        let upstream =
            r#"{"meta":{"api-version":"1.1"},"name":"pkg","versions":["1.9","1.10"],"files":[]}"#;
        let local = vec![SimpleProjectArtifact {
            path: "pkg-1.2-py3-none-any.whl".to_string(),
            version: Some("1.2".to_string()),
            size_bytes: 1,
            checksum_sha256: "h".to_string(),
            metadata: None,
            upload_time: None,
        }];
        let out = merge_local_into_remote_simple_json(upstream.as_bytes(), "v", "pkg", &local, &[])
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(versions, vec!["1.2", "1.9", "1.10"]);
    }

    #[test]
    fn test_sorted_pep440_versions_dedupes_and_parks_unparseable_last() {
        let out = sorted_pep440_versions(
            ["1.10", "1.9", "1.9", "not-a-version", "2.0"]
                .into_iter()
                .map(str::to_owned),
        );
        assert_eq!(out, vec!["1.9", "1.10", "2.0", "not-a-version"]);
    }

    // -----------------------------------------------------------------------
    // #2937: distribution-granular ownership union (Case A) vs suppression
    // (Case B) for a locally-owned virtual PyPI name.
    // -----------------------------------------------------------------------

    #[test]
    fn test_wheel_compat_tag_parses_platform_triple() {
        assert_eq!(
            wheel_compat_tag("pydantic_core-2.0-cp39-cp39-manylinux_2_17_x86_64.whl").as_deref(),
            Some("cp39-cp39-manylinux_2_17_x86_64")
        );
        assert_eq!(
            wheel_compat_tag("pydantic_core-2.0-cp39-cp39-win_amd64.whl").as_deref(),
            Some("cp39-cp39-win_amd64")
        );
        // Optional build tag is tolerated: the last three fields are the tag.
        assert_eq!(
            wheel_compat_tag("pkg-1.0-1-py3-none-any.whl").as_deref(),
            Some("py3-none-any")
        );
        // Sdists and malformed names have no platform tag.
        assert_eq!(wheel_compat_tag("pydantic_core-2.0.tar.gz"), None);
        assert_eq!(wheel_compat_tag("weird.whl"), None);
    }

    fn linux_owner_profile() -> OwnedWheelProfile {
        // Local owner ships only the linux wheel of 2.0 (Case-A backdrop).
        OwnedWheelProfile::from_filenames(["pydantic_core-2.0-cp39-cp39-manylinux_2_17_x86_64.whl"])
    }

    #[test]
    fn test_owned_profile_admits_case_a_rejects_case_b() {
        let owned = linux_owner_profile();
        // Case A: windows wheel of the version the local ALREADY owns -> union.
        assert!(owned.admits("pydantic_core-2.0-cp39-cp39-win_amd64.whl"));
        // Case B: a version only the remote has -> stay suppressed.
        assert!(!owned.admits("pydantic_core-1.9-cp39-cp39-win_amd64.whl"));
        // Same-platform rebuild of an owned version -> confusion vector, reject.
        assert!(!owned.admits("pydantic_core-2.0-cp39-cp39-manylinux_2_17_x86_64.whl"));
        // An sdist of an owned version is NOT platform-distinct -> reject.
        assert!(!owned.admits("pydantic_core-2.0.tar.gz"));
    }

    // -----------------------------------------------------------------------
    // #3404: the per-member ownership decision, as a pure table. The download
    // and PEP 658 metadata paths both route through `suppresses`, so this is
    // the single place the decision is specified.
    // -----------------------------------------------------------------------

    /// Guard for a virtual whose local owner sits at priority `local_min` and
    /// whose one Remote member `remote_id` sits at `remote_priority`.
    fn guard_with(
        local_min: Option<i32>,
        remote_id: uuid::Uuid,
        remote_priority: Option<i32>,
    ) -> PypiOwnershipGuard {
        let mut member_priorities = std::collections::HashMap::new();
        if let Some(p) = remote_priority {
            member_priorities.insert(remote_id, p);
        }
        PypiOwnershipGuard {
            owning_local_min_priority: local_min,
            member_priorities,
            owned_profile: linux_owner_profile(),
        }
    }

    const CASE_B_WHEEL: &str = "pydantic_core-9.9.9-cp39-cp39-win_amd64.whl";
    const CASE_A_WHEEL: &str = "pydantic_core-2.0-cp39-cp39-win_amd64.whl";

    #[test]
    fn test_guard_suppresses_outranked_remote_for_case_b() {
        let remote = uuid::Uuid::new_v4();
        let guard = guard_with(Some(0), remote, Some(10));
        assert!(
            guard.suppresses(remote, &RepositoryType::Remote, CASE_B_WHEEL),
            "a remote-only version of a locally-owned name is the dependency-confusion \
             vector the guard exists to stop"
        );
    }

    /// The #2937 carve-out survives the reordering: a Case-A platform wheel is
    /// still listed by the index for a suppressed member, so it must still
    /// download (and its `.metadata` must still resolve).
    #[test]
    fn test_guard_admits_case_a_wheel_from_suppressed_remote() {
        let remote = uuid::Uuid::new_v4();
        let guard = guard_with(Some(0), remote, Some(10));
        assert!(!guard.suppresses(remote, &RepositoryType::Remote, CASE_A_WHEEL));
    }

    /// #2311: a Remote the operator ranked equal-or-higher than the owning
    /// local was deliberately put there, and still serves.
    #[test]
    fn test_guard_does_not_suppress_equal_or_higher_priority_remote() {
        let remote = uuid::Uuid::new_v4();
        assert!(!guard_with(Some(0), remote, Some(0)).suppresses(
            remote,
            &RepositoryType::Remote,
            CASE_B_WHEEL
        ));
        assert!(!guard_with(Some(5), remote, Some(1)).suppresses(
            remote,
            &RepositoryType::Remote,
            CASE_B_WHEEL
        ));
    }

    /// No local member owns the name (or a `tracks` declaration permits the
    /// merge) -> nothing is suppressed.
    #[test]
    fn test_guard_does_not_suppress_without_local_owner() {
        let remote = uuid::Uuid::new_v4();
        assert!(!guard_with(None, remote, Some(10)).suppresses(
            remote,
            &RepositoryType::Remote,
            CASE_B_WHEEL
        ));
    }

    /// Local/Staging members are never the suppressed side — they are the
    /// owning side. This is what keeps the reordered check from 404ing the
    /// owner's own distributions.
    #[test]
    fn test_guard_never_suppresses_local_or_staging_member() {
        let member = uuid::Uuid::new_v4();
        let guard = guard_with(Some(0), member, Some(10));
        for repo_type in [RepositoryType::Local, RepositoryType::Staging] {
            assert!(
                !guard.suppresses(member, &repo_type, CASE_B_WHEEL),
                "{repo_type:?} member must never be suppressed"
            );
        }
    }

    /// Fail closed: a member absent from the priority map cannot outrank the
    /// owning local, so it is treated as lowest priority and suppressed.
    #[test]
    fn test_guard_suppresses_member_missing_from_priority_map() {
        let remote = uuid::Uuid::new_v4();
        assert!(guard_with(Some(0), remote, None).suppresses(
            remote,
            &RepositoryType::Remote,
            CASE_B_WHEEL
        ));
    }

    #[test]
    fn test_owned_profile_sdist_only_owner_admits_any_platform_wheel() {
        // Owner holds only an sdist of 2.0 (no compat tags): any remote wheel of
        // 2.0 is platform-distinct, but a remote-only version stays suppressed.
        let owned = OwnedWheelProfile::from_filenames(["pydantic_core-2.0.tar.gz"]);
        assert!(owned.admits("pydantic_core-2.0-cp39-cp39-win_amd64.whl"));
        assert!(!owned.admits("pydantic_core-3.0-cp39-cp39-win_amd64.whl"));
    }

    #[test]
    fn test_filter_remote_case_a_json_keeps_owned_platform_wheel_drops_other_version() {
        let owned = linux_owner_profile();
        // Remote advertises: a windows wheel of the owned 2.0 (Case A, keep) and
        // a whole other version 1.9 (Case B, drop).
        let remote = r#"{
            "meta": {"api-version": "1.1"},
            "name": "pydantic-core",
            "versions": ["1.9", "2.0"],
            "files": [
                {"filename": "pydantic_core-2.0-cp39-cp39-win_amd64.whl",
                 "url": "https://files/pydantic_core-2.0-cp39-cp39-win_amd64.whl",
                 "hashes": {"sha256": "w"}},
                {"filename": "pydantic_core-1.9-cp39-cp39-win_amd64.whl",
                 "url": "https://files/pydantic_core-1.9-cp39-cp39-win_amd64.whl",
                 "hashes": {"sha256": "o"}}
            ]
        }"#;
        let out = filter_remote_case_a_json(remote, &owned, "pydantic-core");
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        let files = doc["files"].as_array().unwrap();
        assert_eq!(files.len(), 1, "only the Case-A windows wheel survives");
        assert_eq!(
            files[0]["filename"],
            "pydantic_core-2.0-cp39-cp39-win_amd64.whl"
        );
        // versions[] is rebuilt from survivors: the remote-only 1.9 is gone.
        let versions: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            versions,
            vec!["2.0"],
            "remote-only version must not surface"
        );
    }

    #[test]
    fn test_filter_remote_case_a_html_keeps_owned_platform_wheel_drops_other_version() {
        let owned = linux_owner_profile();
        let remote = concat!(
            "<!DOCTYPE html><html><head></head><body>\n",
            "<a href=\"https://files/pydantic_core-2.0-cp39-cp39-win_amd64.whl#sha256=aa\">pydantic_core-2.0-cp39-cp39-win_amd64.whl</a><br/>\n",
            "<a href=\"https://files/pydantic_core-1.9-cp39-cp39-win_amd64.whl\">pydantic_core-1.9-cp39-cp39-win_amd64.whl</a><br/>\n",
            "</body></html>\n"
        );
        let out = filter_remote_case_a_html(remote, &owned, "virt", "pydantic-core");
        // Case-A survivor is re-emitted as an AK path (no offsite host), fragment preserved.
        assert!(
            out.contains(
                "/pypi/virt/simple/pydantic-core/pydantic_core-2.0-cp39-cp39-win_amd64.whl#sha256=aa"
            ),
            "Case-A wheel re-emitted as an AK path: {out}"
        );
        assert!(
            !out.contains("https://files"),
            "no offsite href survives: {out}"
        );
        assert!(
            !out.contains("pydantic_core-1.9-cp39-cp39-win_amd64.whl"),
            "Case-B remote-only version dropped: {out}"
        );
    }

    // HIGH regression (#2967 red-team): a hostile upstream whose anchor TEXT is
    // an admitted owned-version wheel but whose HREF (single-quoted / uppercase /
    // text != href) points off-site at a remote-only version must NOT leak that
    // off-site URL nor surface the remote-only version. Membership is decided on
    // the href basename and every survivor is re-emitted as an AK path.
    #[test]
    fn test_filter_remote_case_a_html_href_based_defeats_text_spoof() {
        let owned = linux_owner_profile();
        let remote = concat!(
            "<body>\n",
            // text = admitted owned wheel, href (single-quoted) = remote-only 1.9 off-site.
            "<a href='http://evil/files/pydantic_core-1.9-cp39-cp39-win_amd64.whl#sha256=bad'>pydantic_core-2.0-cp99-cp99-win_amd64.whl</a><br/>\n",
            // uppercase HREF, double-quoted, also a remote-only version off-site.
            "<A HREF=\"http://evil/files/pydantic_core-7.7-cp39-cp39-win_amd64.whl\">pydantic_core-2.0-cp39-cp39-win_amd64.whl</A><br/>\n",
            // a genuine Case-A anchor (href basename is the owned-version windows wheel).
            "<a href=\"http://mirror/pydantic_core-2.0-cp39-cp39-win_amd64.whl\">whatever</a><br/>\n",
            "</body>\n"
        );
        let out = filter_remote_case_a_html(remote, &owned, "virt", "pydantic-core");
        // No off-site host, in any form.
        assert!(
            !out.contains("evil"),
            "off-site href must not survive: {out}"
        );
        assert!(
            !out.contains("mirror"),
            "off-site href must not survive: {out}"
        );
        assert!(!out.contains("http://"), "no absolute URL survives: {out}");
        // Remote-only versions (from the spoofed hrefs) must not surface at all.
        assert!(
            !out.contains("1.9"),
            "remote-only 1.9 must not surface: {out}"
        );
        assert!(
            !out.contains("7.7"),
            "remote-only 7.7 must not surface: {out}"
        );
        // The genuine Case-A wheel (decided on its href basename) IS re-emitted as an AK path.
        assert!(
            out.contains(
                "/pypi/virt/simple/pydantic-core/pydantic_core-2.0-cp39-cp39-win_amd64.whl"
            ),
            "genuine Case-A wheel re-emitted as AK path: {out}"
        );
    }

    // HIGH regression R3 (#2967 round 3): a span-replace filter left UNCLOSED and
    // MALFORMED anchors untouched. The REBUILD covers every anchor shape —
    // unclosed (no `</a>`), `</a >` / `</ a>`, uppercase, single/double-quoted,
    // and UNQUOTED — all pointing off-site at remote-only versions must be
    // dropped, and only genuine Case-A wheels survive as AK paths.
    #[test]
    fn test_filter_remote_case_a_html_rebuild_covers_unclosed_and_all_quote_shapes() {
        let owned = linux_owner_profile();
        let remote = concat!(
            "<body>\n",
            // 1) UNCLOSED single-quoted anchor, off-site remote-only 1.9.
            "<a href='http://evil/pydantic_core-1.9-cp39-cp39-win_amd64.whl'>\n",
            // 2) UNCLOSED uppercase double-quoted anchor, off-site remote-only 9.9.
            "<A HREF=\"http://evil/pydantic_core-9.9-cp39-cp39-win_amd64.whl\">\n",
            // 3) malformed close `</a >`, off-site remote-only 8.8.
            "<a href=\"http://evil/pydantic_core-8.8-cp39-cp39-win_amd64.whl\">x</a >\n",
            // 4) malformed close `</ a>`, off-site remote-only 6.6.
            "<a href=\"http://evil/pydantic_core-6.6-cp39-cp39-win_amd64.whl\">y</ a>\n",
            // 5) UNQUOTED off-site remote-only 5.5.
            "<a href=http://evil/pydantic_core-5.5-cp39-cp39-win_amd64.whl>z</a>\n",
            // 6) genuine Case-A: unquoted href basename is the owned windows wheel.
            "<a href=http://mirror/pydantic_core-2.0-cp39-cp39-win_amd64.whl>ok</a>\n",
            "</body>\n"
        );
        let out = filter_remote_case_a_html(remote, &owned, "virt", "pydantic-core");
        assert!(!out.contains("http://"), "no absolute URL survives: {out}");
        assert!(!out.contains("evil"), "no off-site host survives: {out}");
        assert!(!out.contains("mirror"), "no off-site host survives: {out}");
        for v in ["1.9", "9.9", "8.8", "6.6", "5.5"] {
            assert!(!out.contains(v), "remote-only {v} must not surface: {out}");
        }
        // Only the genuine Case-A wheel survives, as an AK path.
        assert!(
            out.contains(
                "/pypi/virt/simple/pydantic-core/pydantic_core-2.0-cp39-cp39-win_amd64.whl"
            ),
            "genuine Case-A wheel re-emitted as AK path: {out}"
        );
    }

    // Defense-in-depth (#2967): rewrite_upstream_urls now rewrites single-quoted
    // and uppercase-`HREF` upstream anchors too, so no off-site href survives the
    // proxy render even outside the suppressed-member rebuild path.
    #[test]
    fn test_rewrite_upstream_urls_handles_single_quote_and_uppercase() {
        let html = concat!(
            "<a href='https://files.pythonhosted.org/x/pkg-1.0.whl#sha256=aa'>pkg-1.0.whl</a>\n",
            "<A HREF=\"https://files.pythonhosted.org/y/pkg-2.0.whl\">pkg-2.0.whl</A>\n",
            "<a href=https://files.pythonhosted.org/z/pkg-3.0.whl>pkg-3.0.whl</a>\n"
        );
        let out = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(
            !out.contains("files.pythonhosted.org"),
            "offsite host rewritten: {out}"
        );
        assert!(
            out.contains("/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=aa"),
            "{out}"
        );
        assert!(out.contains("/pypi/repo/simple/pkg/pkg-2.0.whl"), "{out}");
        assert!(out.contains("/pypi/repo/simple/pkg/pkg-3.0.whl"), "{out}");
    }

    // -----------------------------------------------------------------------
    // GHSA-4cw7-mgqj-hgmg: proxied simple-index stored XSS
    //
    // The proxied page is served from THIS registry's origin, so any upstream
    // markup that survives the render runs with the registry's privileges.
    // The rewriter now REGENERATES the page from parsed anchors instead of
    // editing the upstream markup in place. These tests pin that contract.
    // -----------------------------------------------------------------------

    // The advisory's breakout: a single-quoted upstream href carries a double
    // quote, so the old in-place rewriter's `href="..."` re-emission let the
    // value escape its attribute into attacker markup. The "filename" of such
    // an href is no plausible filename, so the anchor is dropped wholesale.
    #[test]
    fn test_rewrite_regeneration_blocks_single_quote_href_breakout() {
        let html = concat!(
            "<a href='pkg-1.0.whl\"><img src=x onerror=alert(1)>'>pkg-1.0.whl</a>\n",
            "<script>alert(2)</script>",
        );
        let out = rewrite_upstream_urls(html, "repo", "pkg");
        assert_eq!(
            out,
            rebuilt_simple_page(""),
            "a breakout-payload href must yield NO anchor: {out}"
        );
        assert!(
            !out.contains("<img"),
            "event-handler markup survived: {out}"
        );
        assert!(!out.contains("onerror"), "event handler survived: {out}");
        assert!(!out.contains("<script"), "script tag survived: {out}");
        assert!(
            !out.contains("alert("),
            "attacker payload survived in any form: {out}"
        );
    }

    // An event handler riding a legitimate anchor's attribute list: only
    // `data-*` attributes are carried into the rebuilt page, so the handler
    // is dropped with the rest of the upstream markup.
    #[test]
    fn test_rewrite_regeneration_drops_anchor_event_handlers() {
        let html = r#"<a href="https://files.example.com/pkg-1.0.whl#sha256=aa" onmouseover="alert(1)" data-requires-python="&gt;=3.8">pkg-1.0.whl</a>"#;
        let out = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(
            !out.contains("onmouseover"),
            "event handler survived: {out}"
        );
        assert!(
            !out.contains("files.example.com"),
            "offsite host survived: {out}"
        );
        assert!(
            out.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=aa""#),
            "rebuilt href missing: {out}"
        );
        // data-* attributes DO survive (escaped).
        assert!(
            out.contains(r#"data-requires-python="&gt;=3.8""#),
            "data-requires-python lost: {out}"
        );
    }

    // A single-quoted `data-requires-python` value containing a double quote
    // must not break out of the double-quoted attribute it is re-emitted
    // into: the raw quote is escaped, so the `" onmouseover="` breakout
    // sequence never appears.
    #[test]
    fn test_rewrite_regeneration_escapes_data_attr_breakout() {
        let html = "<a href='pkg-1.0.whl' data-requires-python='&gt;=3.8\" onmouseover=\"alert(1)'>pkg-1.0.whl</a>";
        let out = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(
            !out.contains("\" onmouseover"),
            "attribute breakout survived: {out}"
        );
        assert!(
            !out.contains("onmouseover=\""),
            "live event-handler attribute survived: {out}"
        );
        assert!(
            out.contains("data-requires-python=\"&gt;=3.8&quot;"),
            "the (escaped) value must be re-emitted quoted: {out}"
        );
    }

    // The regenerated page must keep the skeleton markers downstream code
    // splices into: `</head>` / `</body>` for the virtual-repo local merge,
    // and the PEP 503 doctype.
    #[test]
    fn test_rewrite_regeneration_keeps_pep503_skeleton_markers() {
        let out = rewrite_upstream_urls("", "repo", "pkg");
        assert!(out.starts_with("<!DOCTYPE html>"), "{out}");
        assert!(
            out.contains("</head>"),
            "merge splice marker missing: {out}"
        );
        assert!(
            out.contains("</body>"),
            "merge splice marker missing: {out}"
        );
        assert!(
            out.contains("pypi:repository-version"),
            "repository-version meta missing: {out}"
        );
    }

    #[test]
    fn test_case_a_filter_remote_body_dispatch_sniffs_and_fails_closed() {
        let owned = linux_owner_profile();
        let json = r#"{"meta":{"api-version":"1.1"},"name":"p","versions":["2.0"],
            "files":[{"filename":"pydantic_core-2.0-cp39-cp39-win_amd64.whl","url":"u","hashes":{"sha256":"w"}}]}"#;
        // Genuine PEP 691 JSON is sniffed to JSON and filtered.
        let out = case_a_filter_remote_body(json.as_bytes(), &owned, "virt", "p");
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(doc["files"].as_array().unwrap().len(), 1);
        // Unparseable body -> empty PEP 691 listing (fail closed, never leak raw
        // remote bytes).
        let out = case_a_filter_remote_body(b"\x00\x01binary", &owned, "virt", "p");
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(doc["files"].as_array().unwrap().is_empty());
        assert_eq!(doc["name"], "p");
    }

    // #2967 R4 (CRITICAL bypass): an HTML index MISLABELED
    // `Content-Type: application/json`. The old code trusted `ct.contains("json")`
    // and echoed the HTML body verbatim (`return json.to_string()`), which the
    // render fallthrough then sniffed as HTML and served through the in-place
    // `rewrite_upstream_urls` rewriter with NO ownership filter — leaking an
    // off-site href for a locally-owned name. The dispatch now SNIFFS the body,
    // routes the HTML through the ownership rebuild, and emits ONLY AK paths.
    #[test]
    fn test_case_a_filter_remote_body_mislabeled_json_html_body_is_ownership_filtered() {
        let owned = linux_owner_profile(); // owns pydantic_core 2.0 linux
        let html_labeled_json = concat!(
            "<!DOCTYPE html><html><body>\n",
            // Genuine Case-A: owned version 2.0, distinct win platform, href back to
            // the mirror. Must UNION as an AK path.
            "<a href=\"http://mirror/files/pydantic_core-2.0-cp39-cp39-win_amd64.whl#sha256=aa\">pydantic_core-2.0-cp39-cp39-win_amd64.whl</a><br/>\n",
            // Off-site, remote-only Case-B (9.9) with a `>` INSIDE a prior `title`
            // attribute — the exact anchor the in-place rewriter leaked verbatim
            // (its `[^>]*?` stops before `href`). Must be dropped entirely.
            "<a title=\"x>y\" href=\"https://evil.example/pydantic_core-9.9-cp39-cp39-win_amd64.whl#sha256=cc\">pydantic_core-9.9-cp39-cp39-win_amd64.whl</a><br/>\n",
            "</body></html>\n"
        );
        let out = case_a_filter_remote_body(
            html_labeled_json.as_bytes(),
            &owned,
            "virt",
            "pydantic-core",
        );
        let out = String::from_utf8_lossy(&out);
        // No off-site host survives, in any form.
        assert!(!out.contains("evil.example"), "off-site href leaked: {out}");
        assert!(!out.contains("mirror"), "off-site href leaked: {out}");
        assert!(!out.contains("http://"), "absolute URL survived: {out}");
        assert!(!out.contains("https://"), "absolute URL survived: {out}");
        // Case-B remote-only version must not surface.
        assert!(
            !out.contains("9.9"),
            "remote-only Case-B version leaked: {out}"
        );
        // The genuine Case-A wheel IS re-emitted as an AK path.
        assert!(
            out.contains(
                "/pypi/virt/simple/pydantic-core/pydantic_core-2.0-cp39-cp39-win_amd64.whl"
            ),
            "Case-A wheel not re-emitted as AK path: {out}"
        );
    }

    // MEDIUM regression (#2967 red-team): admits() must reject a universal
    // `*-none-any` wheel (installable everywhere, not a distinct build target)
    // and a case-variant of a tag the local already ships (same platform).
    #[test]
    fn test_owned_profile_admits_tightened_universal_and_case_variant() {
        let owned = linux_owner_profile(); // local ships cp39-cp39-manylinux_2_17_x86_64
                                           // Universal pure-python wheel of the owned version -> NOT a platform build.
        assert!(!owned.admits("pydantic_core-2.0-py3-none-any.whl"));
        assert!(!owned.admits("pydantic_core-2.0-py2.py3-none-any.whl"));
        // Case-variant of the local's own tag -> same platform, Case B.
        assert!(!owned.admits("pydantic_core-2.0-cp39-cp39-MANYLINUX_2_17_X86_64.whl"));
        // A genuinely new platform-specific target of the owned version is still Case A.
        assert!(owned.admits("pydantic_core-2.0-cp39-cp39-win_amd64.whl"));
    }

    #[test]
    fn test_rewrite_preserves_metadata_attr_before_href() {
        // Edge case: metadata attribute appears before href
        let html = r#"<a data-dist-info-metadata="sha256=abc" href="https://example.com/pkg-1.0.whl#sha256=def">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains(r#"href="/pypi/repo/simple/pkg/pkg-1.0.whl#sha256=def""#));
        assert!(result.contains(r#"data-dist-info-metadata="sha256=abc""#));
    }

    #[test]
    fn test_rewrite_preserves_non_metadata_attrs() {
        // PEP 658 and other data-* attrs should remain intact
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=abc" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=def" data-gpg-sig="true">pkg-1.0.whl</a>"#;
        let result = rewrite_upstream_urls(html, "repo", "pkg");
        assert!(result.contains("data-requires-python"));
        assert!(result.contains("data-gpg-sig"));
        assert!(result.contains(r#"data-dist-info-metadata="sha256=def""#));
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
    fn test_find_upstream_metadata_url_derives_from_wheel_url() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl#sha256=abc" data-dist-info-metadata="sha256=metadata">six-1.16.0-py2.py3-none-any.whl</a>"#;
        let result =
            find_upstream_metadata_url(html, "six-1.16.0-py2.py3-none-any.whl.metadata", None);
        assert_eq!(
            result,
            Some(
                "https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl.metadata"
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

    // -----------------------------------------------------------------------
    // find_upstream_sha256_for_file (GHSA-qxv7-p3mq-88fv)
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_upstream_sha256_extracts_fragment_for_filename() {
        let sha = "a".repeat(64);
        let html = format!(
            r#"<a href="https://files.example.com/packages/ab/six-1.0.tar.gz#sha256={sha}">six-1.0.tar.gz</a>"#
        );
        assert_eq!(
            find_upstream_sha256_for_file(&html, "six-1.0.tar.gz"),
            Some(sha)
        );
        // A different file on the same page is not matched.
        assert_eq!(find_upstream_sha256_for_file(&html, "six-2.0.tar.gz"), None);
    }

    #[test]
    fn test_find_upstream_sha256_rejects_non_canonical_or_absent() {
        // No fragment -> None (the download proceeds unverified, as before).
        let html = r#"<a href="https://files.example.com/six-1.0.tar.gz">six-1.0.tar.gz</a>"#;
        assert_eq!(find_upstream_sha256_for_file(html, "six-1.0.tar.gz"), None);
        // Uppercase digests are not the canonical form the gate compares.
        let upper = "A".repeat(64);
        let html = format!(
            r#"<a href="https://files.example.com/six-1.0.tar.gz#sha256={upper}">six-1.0.tar.gz</a>"#
        );
        assert_eq!(find_upstream_sha256_for_file(&html, "six-1.0.tar.gz"), None);
        // Truncated digests are not SHA-256.
        let html = r#"<a href="https://files.example.com/six-1.0.tar.gz#sha256=abc123">six-1.0.tar.gz</a>"#;
        assert_eq!(find_upstream_sha256_for_file(html, "six-1.0.tar.gz"), None);
        // An md5 fragment is not a SHA-256 pin.
        let html =
            r#"<a href="https://files.example.com/six-1.0.tar.gz#md5=deadbeef">six-1.0.tar.gz</a>"#;
        assert_eq!(find_upstream_sha256_for_file(html, "six-1.0.tar.gz"), None);
    }

    #[test]
    fn test_find_upstream_sha256_handles_relative_and_single_quoted_hrefs() {
        let sha = "b".repeat(64);
        let html =
            format!("<a href='../../packages/six-1.0.tar.gz#sha256={sha}'>six-1.0.tar.gz</a>");
        assert_eq!(
            find_upstream_sha256_for_file(&html, "six-1.0.tar.gz"),
            Some(sha)
        );
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
            commit_sha: None,
            content_encoding: None,
            body: futures::stream::once(async move { Ok(Bytes::from_static(content)) }).boxed(),
            content_type: None,
            content_length: len,
            artifact_id: None,
            etag: None,
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
            commit_sha: None,
            content_encoding: None,
            body: futures::stream::once(async move { Ok(Bytes::from_static(content)) }).boxed(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(content.len() as u64),
            artifact_id: None,
            etag: None,
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

        // A hosted `artifacts` row on a Remote repository (locally published,
        // replicated or promoted) — `verdict == NotProxyCache`, so this handle
        // OWNS the key and the #1283 write-back below is its job.
        //
        // Deliberately NOT a `proxy-cache/` key (#3368): for those the refetch
        // itself commits body + sidecar through `CachePersister`, and a second
        // write through the artifact handle would be an unguarded overwrite of
        // the live cache object. `test_streaming_refetch_does_not_double_write_proxy_cache_3368`
        // below pins that.
        let storage_key = "pypi/fastapi/0.136.1/fastapi-0.136.1-py3-none-any.whl";
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            storage_key,
            true,
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"refetched-bytes"))
                }
            },
        )
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
            true,
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
            true,
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
            true,
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
            true,
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

    /// #3147: this test used to be called
    /// `..._preserves_empty_cached_payload` and asserted that "a legitimately
    /// empty cached payload (zero bytes) is still a cache hit and must be
    /// returned". There is no such thing as a legitimately empty PyPI
    /// distribution: a zero-byte object on a cache content key is exactly what
    /// a rejected or truncated write leaves behind, which is why #1365 and
    /// #1912 exist. The assertion was codifying the leak.
    ///
    /// What it was actually reaching for — that the reader must not confuse
    /// "storage returned an empty body" with "storage returned NotFound" — is
    /// a real invariant and is what this test keeps. The zero-byte object is
    /// still not treated as a miss by the STORAGE layer; whether it may be
    /// served at all is now decided by the sidecar gate, which the companion
    /// test below exercises.
    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_does_not_confuse_empty_with_missing() {
        let storage = std::sync::Arc::new(PresentStorage {
            bytes: Bytes::new(),
        });
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/empty/empty-0.0.0.tar.gz/__content__",
            true,
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"unexpected"))
                }
            },
        )
        .await
        .expect("an empty read is not a NotFound");
        let content = collect_stream(stream).await;

        assert!(content.is_empty());
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an empty body from storage is not the same signal as NotFound; the \
             decision about whether it may be SERVED belongs to the sidecar gate \
             (#3147), not to a length heuristic buried in the storage read"
        );
    }

    // -----------------------------------------------------------------------
    // #3147 -- the PyPI Remote arm's sidecar gate.
    //
    // For a Remote PyPI repo, `artifacts.storage_key` IS proxy-cache content
    // (`proxy-cache/<repo>/simple/<project>/<file>/__content__`, as every
    // fixture in this module shows). The reader streamed it straight out of
    // storage with no sidecar, digest or freshness check, so an object that no
    // sidecar vouched for was served under the `artifacts` row's
    // `Content-Length` and `X-PyPI-File-SHA256` headers -- headers that assert
    // a size and a digest nothing in the path had verified.
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_cache_metadata_key_for_maps_content_to_sidecar() {
        assert_eq!(
            super::proxy_cache_metadata_key_for(
                "proxy-cache/pypi-remote/simple/flask/flask-3.0.0-py3-none-any.whl/__content__"
            )
            .as_deref(),
            Some(
                "proxy-cache/pypi-remote/simple/flask/flask-3.0.0-py3-none-any.whl/__cache_meta__.json"
            )
        );
    }

    #[test]
    fn test_proxy_cache_metadata_key_for_rejects_non_cache_keys() {
        // A locally-published wheel in a Remote repo: an ordinary artifact key
        // with no sidecar anywhere. It must NOT be gated, or every local
        // upload into a Remote repo becomes unservable.
        assert_eq!(
            super::proxy_cache_metadata_key_for("pypi/flask/3.0.0/flask-3.0.0-py3-none-any.whl"),
            None
        );
        // Proxy-cache-prefixed but not a content key.
        assert_eq!(
            super::proxy_cache_metadata_key_for(
                "proxy-cache/pypi-remote/simple/flask/__cache_meta__.json"
            ),
            None
        );
    }

    #[test]
    fn test_cached_object_verdict_serve_matrix() {
        use super::CachedObjectVerdict::*;
        assert!(NotProxyCache.may_serve_stored_object());
        assert!(Vouched.may_serve_stored_object());
        assert!(!Unvouched.may_serve_stored_object());
        assert!(!Held.may_serve_stored_object());
    }

    /// The reproduction: an object present on a proxy-cache content key that
    /// no sidecar vouches for must NOT be streamed to the client. It is
    /// refused and re-fetched from upstream instead.
    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_refuses_an_unvouched_object() {
        let storage = std::sync::Arc::new(PresentStorage {
            bytes: Bytes::from_static(b"UNVALIDATED-WHEEL-BYTES"),
        });
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/jinja2/jinja2-3.1.0-py3-none-any.whl/__content__",
            // No sidecar vouches for the stored object.
            false,
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"refetched-from-upstream"))
                }
            },
        )
        .await
        .expect("the refetch must succeed");
        let content = collect_stream(stream).await;

        assert_ne!(
            content,
            Bytes::from_static(b"UNVALIDATED-WHEEL-BYTES"),
            "an object no sidecar vouches for must never reach the client (#3147)"
        );
        assert_eq!(content, Bytes::from_static(b"refetched-from-upstream"));
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unvouched object must be treated exactly like an absent one: \
             refuse and refetch"
        );
    }

    /// POSITIVE CONTROL for the guard above. A vouched-for cache entry must
    /// still be served straight from storage, with no upstream traffic at all.
    /// Without this, hard-wiring the gate to `false` — which would refetch every
    /// wheel on every request and quietly destroy the proxy cache — would pass.
    #[tokio::test]
    async fn test_get_remote_cached_or_refetch_serves_a_vouched_object_without_upstream() {
        let storage = std::sync::Arc::new(PresentStorage {
            bytes: Bytes::from_static(b"cached-wheel-bytes"),
        });
        let refetch_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refetch_calls_clone = refetch_calls.clone();

        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            "proxy-cache/pypi-remote/simple/jinja2/jinja2-3.1.0-py3-none-any.whl/__content__",
            true,
            move || {
                let refetch_calls_clone = refetch_calls_clone.clone();
                async move {
                    refetch_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(one_shot_result(b"should-not-be-used"))
                }
            },
        )
        .await
        .expect("a vouched cache hit must serve");
        let content = collect_stream(stream).await;

        assert_eq!(content, Bytes::from_static(b"cached-wheel-bytes"));
        assert_eq!(
            refetch_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a vouched cache hit must not touch upstream: the gate is a gate, \
             not a cache bypass"
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
            commit_sha: None,
            content_encoding: None,
            body: futures::stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from_static(c))))
                .boxed(),
            content_type: Some("application/octet-stream".to_string()),
            content_length,
            artifact_id: None,
            etag: None,
        }
    }

    /// #2192: a multi-chunk streaming refetch must serve every chunk to the
    /// caller AND write the full, byte-exact payload back for the next request.
    #[tokio::test]
    async fn test_streaming_refetch_tees_multi_chunk_body_to_cache() {
        let storage = std::sync::Arc::new(RecordingStorage::new());
        // Hosted-row key: the handle that owns it, so the tee applies (#3368).
        let key = "pypi/big/9.9.9/big-9.9.9-py3-none-any.whl";
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            key,
            true,
            move || async move { Ok(multi_chunk_result(vec![b"aaaa", b"bbbb", b"cc"], Some(10))) },
        )
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
        // Hosted-row key: the handle that owns it, so the tee applies (#3368).
        let key = "pypi/trunc/1.0.0/trunc-1.0.0-py3-none-any.whl";
        // Advertise 100 bytes but only deliver 4: the guard must delete.
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            key,
            true,
            move || async move { Ok(multi_chunk_result(vec![b"abcd"], Some(100))) },
        )
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

    /// #3368/#3147: a refetch for a `proxy-cache/` key must NOT be teed back
    /// through the ARTIFACT handle.
    ///
    /// The refetch runs through the proxy service's streaming cache path,
    /// which commits the body *and* its `__cache_meta__.json` sidecar under
    /// the `CachePersister` contract (#1618 S9). A second write here would put
    /// the body with none of it — no sidecar, no #1365 zero-byte guard, no
    /// #1051 ETag re-pin, no catalog row — while racing the proxy's own writer
    /// for the same object. `is_fresh` falls back to comparing
    /// `size(cache_key)` against the sidecar's `size_bytes` when the pinned
    /// ETag is multipart-shaped, so a same-length out-of-band body keeps the
    /// entry "fresh" and the redirect path signs a URL for bytes the sidecar
    /// never vouched for.
    ///
    /// The truncation compensator makes it worse: it would `delete()` the live
    /// cache object.
    ///
    /// Before #3368 this was masked on prefixed S3 (the write landed on a
    /// shadow path nothing read) and live everywhere else. Anchoring the key
    /// layout would have made it live everywhere, so the two must land
    /// together.
    ///
    /// FAILS ON MAIN: the write-back is unconditional.
    #[tokio::test]
    async fn test_streaming_refetch_does_not_double_write_proxy_cache_3368() {
        let storage = std::sync::Arc::new(RecordingStorage::new());
        let key = "proxy-cache/pypi-remote/simple/big/big-9.9.9-py3-none-any.whl/__content__";
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            key,
            true,
            move || async move { Ok(multi_chunk_result(vec![b"aaaa", b"bbbb", b"cc"], Some(10))) },
        )
        .await
        .expect("streaming refetch should succeed");
        let content = collect_stream(stream).await;

        // The caller is still served every byte: only the redundant, unguarded
        // second write is gone.
        assert_eq!(content, Bytes::from_static(b"aaaabbbbcc"));
        assert!(
            storage.puts.lock().expect("puts mutex").is_empty(),
            "proxy-cache content must not be written through the artifact handle; the \
             refetch already committed it, with its sidecar, through CachePersister"
        );
        assert!(
            storage.deletes.lock().expect("deletes mutex").is_empty(),
            "and the truncation compensator must never delete the live cache object"
        );
    }

    /// The property the #3368 tee removal RESTS ON: the refetch writes the
    /// same key the tee would have written.
    ///
    /// Dropping the write-back is only safe because `refetch` already commits
    /// that object — through `fetch_from_pypi_remote_streaming`, which caches
    /// under `target.cache_path` = `build_pypi_proxy_cache_path(project,
    /// filename)`, which `CacheKeys::derive` turns into
    /// `proxy-cache/<repo_key>/simple/<project>/<file>/__content__`. If that
    /// algebra ever drifts from the `artifacts.storage_key` shape the read
    /// path resolves, the refetch would warm one key while the row names
    /// another, and the entry would be permanently cold with nothing to say
    /// so. The sibling tests above prove the tee does NOT write; this one
    /// proves the cache DOES.
    #[test]
    fn test_refetch_cache_key_matches_the_row_key_the_tee_no_longer_writes_3368() {
        let project = proj("six");
        let filename = "six-1.17.0-py2.py3-none-any.whl";
        let cache_path = build_pypi_proxy_cache_path(&project, filename);

        let derived = crate::services::proxy_service::ProxyService::cache_storage_key(
            "pypi-remote",
            &cache_path,
        )
        .expect("derive cache key");

        assert_eq!(
            derived,
            "proxy-cache/pypi-remote/simple/six/six-1.17.0-py2.py3-none-any.whl/__content__",
            "the key the refetch warms must be exactly the `artifacts.storage_key` shape the \
             read path resolves, or removing the tee leaves the entry permanently cold"
        );
        assert!(
            crate::services::proxy_service::ProxyService::is_proxy_cache_key(&derived),
            "and it must be classified as proxy-cache content, which is what routes the \
             read to the shared root and suppresses the tee"
        );
        // The sidecar the verdict is read from sits beside it, so a warmed
        // entry is immediately servable rather than Unvouched.
        assert_eq!(
            proxy_cache_metadata_key_for(&derived).as_deref(),
            Some("proxy-cache/pypi-remote/simple/six/six-1.17.0-py2.py3-none-any.whl/__cache_meta__.json"),
            "the refetch commits body AND sidecar; without the sidecar the next read would \
             be Unvouched and re-fetch forever"
        );
    }

    /// Same for the unvouched arm (#3147): refusing a sidecar-less entry
    /// re-fetches, and that re-fetch must not be written back here either —
    /// otherwise the arm that exists BECAUSE the sidecar is missing would
    /// itself write a body with no sidecar, permanently.
    #[tokio::test]
    async fn test_unvouched_refetch_does_not_double_write_proxy_cache_3368() {
        let storage = std::sync::Arc::new(RecordingStorage::new());
        let key = "proxy-cache/pypi-remote/simple/unv/unv-1.0.0-py3-none-any.whl/__content__";
        let stream = super::get_remote_cached_or_refetch_stream(
            storage.clone(),
            key,
            /* may_serve_stored_object = */ false,
            move || async move { Ok(multi_chunk_result(vec![b"zz"], Some(2))) },
        )
        .await
        .expect("unvouched refetch should succeed");
        assert_eq!(collect_stream(stream).await, Bytes::from_static(b"zz"));
        assert!(
            storage.puts.lock().expect("puts mutex").is_empty(),
            "the unvouched arm must not write a sidecar-less body through the artifact handle"
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
        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

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

    // -----------------------------------------------------------------------
    // Age-gate fail-open regression: a local `artifacts` row must NOT bypass
    // the download age gate on a Remote repo.
    //
    // `serve_file` looks up the local `artifacts` table first. Before this
    // fix the gate ran ONLY on the cache-MISS branch, so a version with an
    // `artifacts` row (locally-published / hydrated / pre-#1278 cached wheel)
    // streamed UNGATED even when it was too young — an asymmetry versus npm's
    // `serve_tarball`, which gates unconditionally. This test seeds exactly
    // such a row for a gate-enabled Remote repo whose upstream reports a
    // just-now `upload_time` (so the version is younger than the threshold)
    // and asserts the request is blocked with HTTP 451 rather than streamed.
    //
    // Skips cleanly when DATABASE_URL is unset.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_serve_file_age_gate_blocks_young_version_on_artifacts_hit() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        let wheel_bytes: &[u8] = b"PK\x03\x04 young-wheel-should-be-gated";
        let project = "gated";
        let version = "1.2.3";
        let filename = "gated-1.2.3-py3-none-any.whl";

        // Upstream reports the version as published *just now* so it is younger
        // than the (very large) threshold and must be withheld.
        let upstream = MockServer::start().await;
        let now_iso = Utc::now().to_rfc3339();
        Mock::given(method("GET"))
            .and(path(format!("/pypi/{project}/json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": { version: [ { "upload_time_iso_8601": now_iso } ] }
            })))
            .mount(&upstream)
            .await;

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state =
            tdh::build_state_with_proxy_and_age_gate(fx.pool.clone(), storage_path.as_str(), proxy);

        // Remote repo with the age gate ENABLED and an absurd threshold so any
        // recent release is "young".
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();
        repo_info.age_gate_enabled = true;
        repo_info.age_gate_min_age_days = 3650; // 10 years
                                                // The gate re-resolves policy from the repositories row (the struct
                                                // only pre-screens), so the DB must agree with the struct above.
        sqlx::query(
            "UPDATE repositories SET age_gate_enabled = true, age_gate_min_age_days = 3650 \
             WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("enable age gate on repo row");

        // Seed the local `artifacts` row + payload that would otherwise be
        // served straight from storage on the cache-hit branch.
        let storage_key = format!(
            "proxy-cache/{}/simple/{}/{}",
            fx.repo_key, project, filename
        );
        let artifact_path = format!("simple/{}/{}", project, filename);
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
        .bind(version)
        .bind(wheel_bytes.len() as i64)
        .bind("test-gated")
        .bind("application/zip")
        .bind(&storage_key)
        .bind(fx.user_id)
        .fetch_one(&fx.pool)
        .await
        .expect("seed cached artifact row");

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        // Clean up BEFORE asserting so a panic still leaves the DB clean. The
        // age_gate_reviews row inserted by `check` cascades on repo delete.
        let cleanup_pool = fx.pool.clone();
        let cleanup_repo = fx.repo_id;
        let cleanup_user = fx.user_id;
        let cleanup_dir = fx.storage_dir.clone();
        let cleanup = || async move {
            tdh::cleanup(&cleanup_pool, cleanup_repo, cleanup_user).await;
            let _ = std::fs::remove_dir_all(&cleanup_dir);
        };

        match result {
            Ok(r) => {
                let status = r.status();
                cleanup().await;
                panic!(
                    "young version with an artifacts-row hit must be gated, got {status} \
                     (expected 451 age_gate_blocked)"
                );
            }
            Err(resp) => {
                let status = resp.status();
                cleanup().await;
                assert_eq!(
                    status,
                    StatusCode::from_u16(451).unwrap(),
                    "artifacts-hit young version must return 451, got {status}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // #2066: age-gate enforcement on VIRTUAL-repo resolution (download + index)
    // -----------------------------------------------------------------------

    /// Attach a fresh Remote pypi member (upstream = `upstream_uri`) to the
    /// virtual fixture, with the age gate enabled/disabled and a 30-day
    /// threshold. The member is public so an anonymous virtual read authorizes
    /// it. Returns the member id/key/dir plus a proxy+age-gate SharedState.
    async fn setup_virtual_pypi_member(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        age_gate_enabled: bool,
        upstream_uri: &str,
    ) -> (
        uuid::Uuid,
        String,
        std::path::PathBuf,
        crate::api::SharedState,
    ) {
        use crate::api::handlers::test_db_helpers as tdh;
        let (member_id, member_key, member_dir) =
            tdh::create_repo(&fx.pool, "remote", "pypi").await;
        sqlx::query(
            "UPDATE repositories SET upstream_url = $1, is_public = true, \
             age_gate_enabled = $2, age_gate_min_age_days = 30 WHERE id = $3",
        )
        .bind(upstream_uri)
        .bind(age_gate_enabled)
        .bind(member_id)
        .execute(&fx.pool)
        .await
        .expect("configure member");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(fx.repo_id)
        .bind(member_id)
        .execute(&fx.pool)
        .await
        .expect("attach member");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state =
            tdh::build_state_with_proxy_and_age_gate(fx.pool.clone(), storage_path.as_str(), proxy);
        (member_id, member_key, member_dir, state)
    }

    /// Seed a cached wheel (`artifacts` row + payload) on a virtual member so
    /// the virtual `serve_file` loop can serve it locally when the gate allows.
    #[allow(clippy::too_many_arguments)]
    async fn seed_member_wheel(
        state: &crate::api::SharedState,
        pool: &sqlx::PgPool,
        user_id: uuid::Uuid,
        member_id: uuid::Uuid,
        member_key: &str,
        member_dir: &std::path::Path,
        upstream_uri: &str,
        project: &str,
        version: &str,
        filename: &str,
    ) {
        use crate::api::handlers::test_db_helpers as tdh;
        let wheel: &[u8] = b"PK\x03\x04 virtual-member-wheel";
        let member_info = tdh::make_repo_info(
            member_id,
            member_key,
            member_dir,
            "remote",
            Some(upstream_uri),
        );
        let storage_key = format!("proxy-cache/{}/simple/{}/{}", member_key, project, filename);
        let artifact_path = format!("simple/{}/{}", project, filename);
        crate::api::handlers::proxy_helpers::put_artifact_bytes(
            state,
            &member_info,
            &storage_key,
            Bytes::from_static(wheel),
        )
        .await
        .expect("seed member payload");
        let _id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        )
        .bind(member_id)
        .bind(&artifact_path)
        .bind(project)
        .bind(version)
        .bind(wheel.len() as i64)
        .bind("test-member")
        .bind("application/zip")
        .bind(&storage_key)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("seed member artifact row");
    }

    /// Drop everything a virtual member created.
    async fn cleanup_virtual_member(
        pool: &sqlx::PgPool,
        member_id: uuid::Uuid,
        member_dir: &std::path::Path,
    ) {
        for sql in [
            "DELETE FROM virtual_repo_members WHERE member_repo_id = $1",
            "DELETE FROM age_gate_reviews WHERE repository_id = $1",
            "DELETE FROM role_assignments WHERE repository_id = $1",
            "DELETE FROM artifacts WHERE repository_id = $1",
            "DELETE FROM repository_config WHERE repository_id = $1",
            "DELETE FROM repositories WHERE id = $1",
        ] {
            let _ = sqlx::query(sql).bind(member_id).execute(pool).await;
        }
        let _ = std::fs::remove_dir_all(member_dir);
    }

    /// Mount the `/pypi/<project>/json` publish-times endpoint used by the
    /// per-version download gate, reporting `version` published at `iso`.
    async fn mount_pypi_publish_times(
        upstream: &wiremock::MockServer,
        project: &str,
        version: &str,
        iso: &str,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(format!("/pypi/{project}/json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": { version: [ { "upload_time_iso_8601": iso } ] }
            })))
            .mount(upstream)
            .await;
    }

    #[tokio::test]
    async fn test_serve_file_virtual_gated_member_blocks_young() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "gated";
        let version = "9.9.9";
        let filename = "gated-9.9.9-py3-none-any.whl";

        let upstream = MockServer::start().await;
        mount_pypi_publish_times(&upstream, project, version, &Utc::now().to_rfc3339()).await;

        let (member_id, member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, true, &upstream.uri()).await;
        // Seed a cached young wheel too, so this also proves the gate fires
        // BEFORE the local artifacts-hit can serve young bytes.
        seed_member_wheel(
            &state,
            &fx.pool,
            fx.user_id,
            member_id,
            &member_key,
            &member_dir,
            &upstream.uri(),
            project,
            version,
            filename,
        )
        .await;

        let virtual_info = fx.repo_info("virtual", None);
        let result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        match result {
            Ok(r) => panic!(
                "young version of a gated virtual member must be blocked, got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::from_u16(451).unwrap(),
                "young gated member must return 451 through the virtual"
            ),
        }
    }

    #[tokio::test]
    async fn test_serve_file_virtual_gated_member_allows_old() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "gated";
        let version = "1.0.0";
        let filename = "gated-1.0.0-py3-none-any.whl";

        let upstream = MockServer::start().await;
        let old = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        mount_pypi_publish_times(&upstream, project, version, &old).await;

        let (member_id, member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, true, &upstream.uri()).await;
        seed_member_wheel(
            &state,
            &fx.pool,
            fx.user_id,
            member_id,
            &member_key,
            &member_dir,
            &upstream.uri(),
            project,
            version,
            filename,
        )
        .await;

        let virtual_info = fx.repo_info("virtual", None);
        let result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        let status = result.map(|r| r.status()).unwrap_or_else(|e| e.status());
        assert_eq!(
            status,
            StatusCode::OK,
            "aged version of a gated virtual member must still resolve 200 (regression guard)"
        );
    }

    #[tokio::test]
    async fn test_virtual_ungated_member_unaffected() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "ungated";
        let version = "9.9.9";
        let filename = "ungated-9.9.9-py3-none-any.whl";

        // Age gate DISABLED on the member: a young version must NOT be blocked.
        // No upstream is contacted (the gate short-circuits on !is_applicable).
        let (member_id, member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, "http://127.0.0.1:1").await;
        seed_member_wheel(
            &state,
            &fx.pool,
            fx.user_id,
            member_id,
            &member_key,
            &member_dir,
            "http://127.0.0.1:1",
            project,
            version,
            filename,
        )
        .await;

        let virtual_info = fx.repo_info("virtual", None);
        let result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        let status = result.map(|r| r.status()).unwrap_or_else(|e| e.status());
        assert_eq!(
            status,
            StatusCode::OK,
            "an ungated virtual member must serve its (young) version normally"
        );
    }

    #[tokio::test]
    async fn test_virtual_simple_json_filters_young_member() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "gated";
        let now = Utc::now().to_rfc3339();
        let old = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        let index = serde_json::json!({
            "meta": {"api-version": "1.0"},
            "name": project,
            "files": [
                {"filename": "gated-1.0.0-py3-none-any.whl",
                 "url": "https://files.example.test/gated-1.0.0-py3-none-any.whl",
                 "hashes": {}, "upload-time": old},
                {"filename": "gated-9.9.9-py3-none-any.whl",
                 "url": "https://files.example.test/gated-9.9.9-py3-none-any.whl",
                 "hashes": {}, "upload-time": now},
            ]
        });
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", PEP691_JSON_CONTENT_TYPE)
                    .set_body_json(&index),
            )
            .mount(&upstream)
            .await;

        let (member_id, _member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, true, &upstream.uri()).await;

        let mut headers = HeaderMap::new();
        headers.insert("accept", PEP691_JSON_CONTENT_TYPE.parse().unwrap());
        let result = super::simple_project(
            axum::extract::State(state.clone()),
            axum::Extension(None),
            axum::extract::Path((fx.repo_key.clone(), project.to_string())),
            headers,
        )
        .await;

        let names: Vec<String> = match result {
            Ok(r) => {
                let bytes = axum::body::to_bytes(r.into_body(), 1024 * 1024)
                    .await
                    .expect("read body");
                let json: serde_json::Value =
                    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                json.get("files")
                    .and_then(|f| f.as_array())
                    .map(|files| {
                        files
                            .iter()
                            .filter_map(|f| {
                                f.get("filename").and_then(|n| n.as_str()).map(String::from)
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }
            Err(r) => {
                let status = r.status();
                tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
                cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
                let _ = std::fs::remove_dir_all(&fx.storage_dir);
                panic!("virtual simple JSON index must succeed, got {status}");
            }
        };

        tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        assert!(
            names.iter().any(|n| n.contains("1.0.0")),
            "aged 1.0.0 must remain in the virtual JSON index: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("9.9.9")),
            "young 9.9.9 of a gated member must be filtered from the virtual JSON index: {names:?}"
        );
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

    // Conformance corpus (pip/warehouse harvest): a wheel's METADATA is served
    // at `<file>.metadata`, so the PEP 691 JSON must advertise `core-metadata`
    // (PEP 658/714) for the installer fast path; sdists must not. RED before the
    // core-metadata emission, GREEN after.
    #[test]
    fn test_build_simple_project_response_json_advertises_core_metadata_for_wheels() {
        let artifacts = vec![
            SimpleProjectArtifact {
                path: "pkg-1.0.0-py3-none-any.whl".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 3000,
                checksum_sha256: "cafe".to_string(),
                metadata: None,
                upload_time: None,
            },
            SimpleProjectArtifact {
                path: "pkg-1.0.0.tar.gz".to_string(),
                version: Some("1.0.0".to_string()),
                size_bytes: 2000,
                checksum_sha256: "beef".to_string(),
                metadata: None,
                upload_time: None,
            },
        ];
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
        let files = json["files"].as_array().unwrap();
        let wheel = files
            .iter()
            .find(|f| f["filename"].as_str().unwrap().ends_with(".whl"))
            .unwrap();
        let sdist = files
            .iter()
            .find(|f| f["filename"].as_str().unwrap().ends_with(".tar.gz"))
            .unwrap();
        assert_eq!(
            wheel["core-metadata"],
            serde_json::Value::Bool(true),
            "wheel must advertise core-metadata: {json}"
        );
        assert!(
            sdist.get("core-metadata").is_none(),
            "sdist must not advertise core-metadata: {json}"
        );
    }

    // Conformance corpus (pypa/packaging ordering vectors): the PEP 691
    // `versions` array must be ordered by PEP 440, not lexicographically.
    // The old BTreeSet<String> put `1.10` before `1.9` and `10.0` before `9.0`,
    // which misleads any consumer treating the last entry as "latest".
    // RED before the pep440_sort_key ordering, GREEN after. (#3106)
    #[test]
    fn test_build_simple_project_response_json_versions_are_pep440_ordered() {
        let raw = ["1.9", "1.10", "10.0", "9.0", "1.0", "2.0rc1", "2.0"];
        let artifacts: Vec<SimpleProjectArtifact> = raw
            .iter()
            .map(|v| SimpleProjectArtifact {
                path: format!("pkg-{v}.tar.gz"),
                version: Some((*v).to_string()),
                size_bytes: 10,
                checksum_sha256: "abc".to_string(),
                metadata: None,
                upload_time: None,
            })
            .collect();
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
        let versions: Vec<&str> = json["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            versions,
            vec!["1.0", "1.9", "1.10", "2.0rc1", "2.0", "9.0", "10.0"],
            "versions must be PEP 440-ordered, not lexicographic: {json}"
        );
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
    // HTTP caching on the simple-index responses (#2773): ETag +
    // Cache-Control + If-None-Match -> 304, for both HTML and JSON variants,
    // with a changed package set invalidating the ETag.
    // -----------------------------------------------------------------------

    fn body_string(response: Response) -> String {
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(body_bytes)
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn project_artifact(filename: &str, sha: &str) -> SimpleProjectArtifact {
        SimpleProjectArtifact {
            path: format!("pkg/{}", filename),
            version: Some("1.0.0".to_string()),
            size_bytes: 100,
            checksum_sha256: sha.to_string(),
            metadata: None,
            upload_time: None,
        }
    }

    fn json_accept_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "accept",
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );
        h
    }

    #[test]
    fn test_project_html_carries_etag_and_cache_control() {
        let artifacts = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];
        let response =
            build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &artifacts, &[])
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(ETAG).is_some(), "ETag missing");
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn test_project_json_carries_etag_and_cache_control() {
        let artifacts = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];
        let response =
            build_simple_project_response(&json_accept_headers(), "repo", "pkg", &artifacts, &[])
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response.headers().get(CONTENT_TYPE).unwrap();
        assert_eq!(ct, "application/vnd.pypi.simple.v1+json");
        assert!(response.headers().get(ETAG).is_some(), "ETag missing");
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn test_root_html_carries_etag_and_preserves_security_headers() {
        let packages = vec!["flask".to_string(), "requests".to_string()];
        let response = build_simple_root_response(&HeaderMap::new(), "repo", &packages).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(ETAG).is_some(), "ETag missing");
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
        // The PEP 503 hardening headers must survive the caching change.
        assert!(response.headers().get("Content-Security-Policy").is_some());
        assert_eq!(
            response.headers().get("X-Content-Type-Options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn test_root_json_carries_etag_and_cache_control() {
        let packages = vec!["flask".to_string()];
        let response =
            build_simple_root_response(&json_accept_headers(), "repo", &packages).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(ETAG).is_some(), "ETag missing");
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn test_project_conditional_get_returns_304_no_body() {
        let artifacts = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];
        // First request: capture the served ETag.
        let first =
            build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &artifacts, &[])
                .unwrap();
        let etag = first
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Conditional request with the matching If-None-Match -> 304, empty body.
        let mut cond = HeaderMap::new();
        cond.insert(axum::http::header::IF_NONE_MATCH, etag.parse().unwrap());
        let response =
            build_simple_project_response(&cond, "repo", "pkg", &artifacts, &[]).unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response.headers().get(ETAG).unwrap().to_str().unwrap(),
            etag
        );
        assert!(body_string(response).is_empty(), "304 must have no body");
    }

    #[test]
    fn test_root_conditional_get_returns_304() {
        let packages = vec!["flask".to_string()];
        let first = build_simple_root_response(&HeaderMap::new(), "repo", &packages).unwrap();
        let etag = first
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut cond = HeaderMap::new();
        cond.insert(axum::http::header::IF_NONE_MATCH, etag.parse().unwrap());
        let response = build_simple_root_response(&cond, "repo", &packages).unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(body_string(response).is_empty(), "304 must have no body");
    }

    // -----------------------------------------------------------------------
    // #3406: the Simple index is negotiated on `Accept`, so every emitter must
    // declare `Vary: Accept` and must not hand a credentialed caller's body a
    // shared-cache directive.
    // -----------------------------------------------------------------------

    fn json_accept() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", PEP691_JSON_CONTENT_TYPE.parse().unwrap());
        h
    }

    /// Both halves of both negotiated emitters must declare the selecting
    /// header. The HTML root arm is the one that matters most here: it builds
    /// its response by hand (to keep the PEP 503 CSP headers) and so does not
    /// inherit the shared helper's contract automatically.
    #[test]
    fn test_negotiated_simple_index_declares_vary_accept() {
        let packages = vec!["flask".to_string()];
        let artifacts = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];

        let cases: Vec<(&str, Response)> = vec![
            (
                "root/html",
                build_simple_root_response(&HeaderMap::new(), "repo", &packages).unwrap(),
            ),
            (
                "root/json",
                build_simple_root_response(&json_accept(), "repo", &packages).unwrap(),
            ),
            (
                "project/html",
                build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &artifacts, &[])
                    .unwrap(),
            ),
            (
                "project/json",
                build_simple_project_response(&json_accept(), "repo", "pkg", &artifacts, &[])
                    .unwrap(),
            ),
        ];

        for (label, response) in cases {
            assert_eq!(
                response.headers().get(VARY).map(|v| v.to_str().unwrap()),
                Some("Accept"),
                "{label}: a body selected by Accept must declare Vary: Accept, or a shared \
                 cache may serve it to a client that asked for the other representation"
            );
            assert_eq!(
                response.headers().get(CACHE_CONTROL).unwrap(),
                DEFAULT_CACHE_CONTROL,
                "{label}: an anonymous read stays publicly cacheable"
            );
        }
    }

    /// The HTML root arm must keep its PEP 503 security headers while gaining
    /// the cache contract — the open-coded builder is easy to regress.
    #[test]
    fn test_root_html_keeps_security_headers_alongside_vary() {
        let packages = vec!["flask".to_string()];
        let r = build_simple_root_response(&HeaderMap::new(), "repo", &packages).unwrap();
        assert_eq!(r.headers().get(VARY).unwrap(), "Accept");
        assert!(r.headers().get("Content-Security-Policy").is_some());
        assert_eq!(
            r.headers().get("X-Content-Type-Options").unwrap(),
            "nosniff"
        );
    }

    /// A virtual repo's index is built from the members the CALLER may read
    /// (#2073 / #3323 / #3399) and a private repo's requires credentials at
    /// all, so a credentialed response must not be shared-cacheable. `Vary`
    /// stays regardless: the negotiation is orthogonal to the caller.
    #[test]
    fn test_credentialed_simple_index_is_private() {
        let packages = vec!["internal-lib".to_string()];
        let artifacts = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];

        let mut auth = json_accept();
        auth.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        let mut auth_html = HeaderMap::new();
        auth_html.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ak_token".parse().unwrap(),
        );

        for (label, response) in [
            (
                "root/json",
                build_simple_root_response(&auth, "repo", &packages).unwrap(),
            ),
            (
                "root/html",
                build_simple_root_response(&auth_html, "repo", &packages).unwrap(),
            ),
            (
                "project/json",
                build_simple_project_response(&auth, "repo", "pkg", &artifacts, &[]).unwrap(),
            ),
            (
                "project/html",
                build_simple_project_response(&auth_html, "repo", "pkg", &artifacts, &[]).unwrap(),
            ),
        ] {
            assert_eq!(
                response.headers().get(CACHE_CONTROL).unwrap(),
                PRIVATE_CACHE_CONTROL,
                "{label}: a credentialed caller's index must not be stored by a shared cache"
            );
            assert_eq!(response.headers().get(VARY).unwrap(), "Accept", "{label}");
        }
    }

    /// The 304 shortcut must carry the same cache-key metadata as the 200 it
    /// stands in for, on the open-coded HTML arm too.
    #[test]
    fn test_negotiated_304_carries_vary_accept() {
        let packages = vec!["flask".to_string()];
        for accept in [None, Some(PEP691_JSON_CONTENT_TYPE)] {
            let mut h = HeaderMap::new();
            if let Some(a) = accept {
                h.insert("accept", a.parse().unwrap());
            }
            let first = build_simple_root_response(&h, "repo", &packages).unwrap();
            let etag = first
                .headers()
                .get(ETAG)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            h.insert(axum::http::header::IF_NONE_MATCH, etag.parse().unwrap());
            let second = build_simple_root_response(&h, "repo", &packages).unwrap();
            assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(
                second.headers().get(VARY).unwrap(),
                "Accept",
                "accept={accept:?}: a 304 without Vary refreshes the wrong stored representation"
            );
        }
    }

    #[test]
    fn test_project_etag_changes_when_package_set_changes_and_stale_conditional_is_200() {
        let before = vec![project_artifact("pkg-1.0.0.tar.gz", "aaa")];
        let first =
            build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &before, &[]).unwrap();
        let etag_before = first
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // A new distribution is added to the project.
        let after = vec![
            project_artifact("pkg-1.0.0.tar.gz", "aaa"),
            project_artifact("pkg-2.0.0.tar.gz", "bbb"),
        ];
        let second =
            build_simple_project_response(&HeaderMap::new(), "repo", "pkg", &after, &[]).unwrap();
        let etag_after = second
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        assert_ne!(
            etag_before, etag_after,
            "a changed package set must invalidate the ETag"
        );

        // The client's stale If-None-Match must NOT short-circuit to 304 now.
        let mut stale = HeaderMap::new();
        stale.insert(
            axum::http::header::IF_NONE_MATCH,
            etag_before.parse().unwrap(),
        );
        let response = build_simple_project_response(&stale, "repo", "pkg", &after, &[]).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            body_string(response).contains("pkg-2.0.0.tar.gz"),
            "the fresh 200 must carry the new distribution"
        );
    }

    #[test]
    fn test_root_etag_changes_when_package_set_changes() {
        let before = vec!["flask".to_string()];
        let after = vec!["flask".to_string(), "requests".to_string()];
        let e_before = build_simple_root_response(&HeaderMap::new(), "repo", &before)
            .unwrap()
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let e_after = build_simple_root_response(&HeaderMap::new(), "repo", &after)
            .unwrap()
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_ne!(e_before, e_after, "root ETag must track the package set");
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
            axum::Extension(None),
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
            axum::Extension(None),
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

    // -----------------------------------------------------------------------
    // #3147 -- `proxy_cache_object_verdict` against a real sidecar.
    // -----------------------------------------------------------------------

    /// Serves one sidecar, at one key. Every other `get` is a miss, so a test
    /// that names the wrong key sees `Unvouched` rather than a false pass.
    struct OneSidecarStorage {
        key: String,
        sidecar: Bytes,
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for OneSidecarStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            if key == self.key {
                Ok(self.sidecar.clone())
            } else {
                Err(AppError::NotFound(key.to_string()))
            }
        }
        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(key == self.key)
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

    /// Build a proxy service whose only readable object is the sidecar for
    /// `content_key`.
    ///
    /// `load_cache_metadata` reads through a process-global LRU keyed by the
    /// metadata key, so every test here uses its own project name to avoid
    /// contaminating the others.
    fn proxy_with_sidecar(
        content_key: &str,
        metadata: &crate::services::proxy_service::CacheMetadata,
    ) -> crate::services::proxy_service::ProxyService {
        use crate::services::storage_service::StorageService;
        let storage = std::sync::Arc::new(OneSidecarStorage {
            key: super::proxy_cache_metadata_key_for(content_key).expect("cache-shaped key"),
            sidecar: Bytes::from(serde_json::to_vec(metadata).expect("serialize sidecar")),
        });
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy");
        crate::services::proxy_service::ProxyService::new(
            pool,
            std::sync::Arc::new(StorageService::new(storage)),
        )
    }

    fn positive_sidecar() -> crate::services::proxy_service::CacheMetadata {
        crate::services::proxy_service::CacheMetadata {
            cached_at: chrono::Utc::now(),
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            content_encoding: None,
            upstream_commit_sha: None,
            size_bytes: 18,
            checksum_sha256: "c".repeat(64),
        }
    }

    #[tokio::test]
    async fn test_verdict_is_vouched_when_a_positive_sidecar_exists() {
        let key = "proxy-cache/pypi-remote/simple/vouchedpkg/vouchedpkg-1.0.tar.gz/__content__";
        let proxy = proxy_with_sidecar(key, &positive_sidecar());

        assert_eq!(
            super::proxy_cache_object_verdict(&proxy, key).await,
            super::CachedObjectVerdict::Vouched
        );
    }

    #[tokio::test]
    async fn test_verdict_is_unvouched_when_no_sidecar_exists() {
        // The proxy's storage serves a sidecar for a DIFFERENT entry only.
        let present = "proxy-cache/pypi-remote/simple/otherpkg/otherpkg-1.0.tar.gz/__content__";
        let missing = "proxy-cache/pypi-remote/simple/nosidecar/nosidecar-1.0.tar.gz/__content__";
        let proxy = proxy_with_sidecar(present, &positive_sidecar());

        assert_eq!(
            super::proxy_cache_object_verdict(&proxy, missing).await,
            super::CachedObjectVerdict::Unvouched,
            "an object with no sidecar must not be served (#3147)"
        );
    }

    #[tokio::test]
    async fn test_verdict_is_unvouched_under_a_negative_cache_marker() {
        let key = "proxy-cache/pypi-remote/simple/negpkg/negpkg-1.0.tar.gz/__content__";
        let mut marker = positive_sidecar();
        marker.negative_cached_until = Some(chrono::Utc::now() + chrono::Duration::minutes(5));
        marker.size_bytes = 0;
        marker.checksum_sha256 = String::new();
        let proxy = proxy_with_sidecar(key, &marker);

        assert_eq!(
            super::proxy_cache_object_verdict(&proxy, key).await,
            super::CachedObjectVerdict::Unvouched,
            "a negative-cache marker vouches for no body at all (#1611)"
        );
    }

    #[tokio::test]
    async fn test_verdict_is_held_while_a_package_age_hold_is_active() {
        let key = "proxy-cache/pypi-remote/simple/heldpkg/heldpkg-1.0.tar.gz/__content__";
        let mut held = positive_sidecar();
        held.quarantine_until = Some(chrono::Utc::now() + chrono::Duration::hours(6));
        let proxy = proxy_with_sidecar(key, &held);

        assert_eq!(
            super::proxy_cache_object_verdict(&proxy, key).await,
            super::CachedObjectVerdict::Held,
            "an active Package Age Policy hold must 409, not serve (#1770/#2075)"
        );
    }

    /// An ELAPSED hold is not a hold. Without this, hard-wiring `Held` for any
    /// non-`None` `quarantine_until` would pass the test above.
    #[tokio::test]
    async fn test_verdict_is_vouched_once_a_package_age_hold_has_elapsed() {
        let key = "proxy-cache/pypi-remote/simple/elapsedpkg/elapsedpkg-1.0.tar.gz/__content__";
        let mut elapsed = positive_sidecar();
        elapsed.quarantine_until = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        let proxy = proxy_with_sidecar(key, &elapsed);

        assert_eq!(
            super::proxy_cache_object_verdict(&proxy, key).await,
            super::CachedObjectVerdict::Vouched
        );
    }

    /// POSITIVE CONTROL for the whole gate: a locally-published wheel in a
    /// Remote repo has an ordinary artifact key and no sidecar anywhere. It
    /// must resolve to `NotProxyCache` and stay servable — gating it would make
    /// every local upload into a Remote repo unreachable.
    #[tokio::test]
    async fn test_verdict_leaves_non_proxy_cache_keys_alone() {
        let key = "pypi/localpkg/1.0/localpkg-1.0-py3-none-any.whl";
        let proxy = build_proxy_service_no_db();

        let verdict = super::proxy_cache_object_verdict(&proxy, key).await;
        assert_eq!(verdict, super::CachedObjectVerdict::NotProxyCache);
        assert!(
            verdict.may_serve_stored_object(),
            "a locally-published wheel in a Remote repo must stay servable"
        );
    }

    /// End-to-end test for the streaming download path via the fallback route.
    ///
    /// The simple index page has no matching href, so `resolve_pypi_remote_fetch_target`
    /// falls through to the stable `simple/{project}/{filename}` fallback path.
    /// This avoids the SSRF check (which hard-blocks loopback) while still
    /// exercising `fetch_from_pypi_remote_streaming` and
    /// `proxy_fetch_streaming_with_cache_key_verified`.
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
            &proj("numpy"),
            "numpy-2.0.0-py3-none-any.whl",
            "simple",
            RepositoryFormat::Pypi,
        )
        .await
        .expect("streaming fetch via fallback path must succeed");

        let mut body_bytes = Vec::new();
        let mut body = result.body;
        while let Some(chunk) = body.next().await {
            body_bytes.extend_from_slice(&chunk.expect("stream chunk must be Ok"));
        }
        assert_eq!(body_bytes, wheel_body);

        tdh::wait_for_cache_commit(&tmp, wheel_body.len() as u64).await;
        let cache_path = "simple/numpy/numpy-2.0.0-py3-none-any.whl";
        let metadata_key = crate::services::proxy_service::ProxyService::cache_metadata_key(
            "pypi-remote",
            cache_path,
        )
        .expect("metadata key");
        let metadata = proxy
            .load_cache_metadata_pub(&metadata_key)
            .await
            .expect("streaming fetch must write cache metadata");
        let ttl_secs = (metadata.expires_at - metadata.cached_at).num_seconds();
        assert_eq!(
            ttl_secs,
            crate::services::cache_classifier::Mutability::Immutable.write_ttl_secs(),
            "PyPI wheel cache entries must use the immutable 10-year TTL"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -----------------------------------------------------------------------
    // PEP 658 remote `.metadata` serving (`serve_remote_metadata`). These live
    // in-crate (not `backend/tests/`) so the coverage `--lib` run exercises
    // the async handler body: upstream 200 → serve verbatim; upstream 404 →
    // extract METADATA from the wheel instead of surfacing a hard failure.
    // -----------------------------------------------------------------------

    /// Serializes the `.metadata` tests' `AK_SSRF_ALLOW_PRIVATE_CIDRS`
    /// mutation. Under nextest each test is its own process, but under plain
    /// `cargo test` parallel threads share the environment, so the guard's
    /// set/restore must not interleave.
    static SSRF_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct SsrfEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<String>,
    }

    impl SsrfEnvGuard {
        const KEY: &'static str = "AK_SSRF_ALLOW_PRIVATE_CIDRS";

        fn set(value: String) -> Self {
            let lock = SSRF_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var(Self::KEY).ok();
            std::env::set_var(Self::KEY, value);
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for SsrfEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(Self::KEY, value),
                None => std::env::remove_var(Self::KEY),
            }
        }
    }

    /// Start a wiremock upstream on a **non-loopback** local address and
    /// allowlist that address for SSRF. Required because the index-anchor URL
    /// resolved by `resolve_pypi_remote_fetch_target` is run through
    /// `validate_outbound_url`, which hard-blocks loopback (so a plain
    /// `MockServer::start()` upstream would be rejected before the fetch).
    async fn non_loopback_upstream() -> (wiremock::MockServer, SsrfEnvGuard) {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind probe socket");
        probe.connect("8.8.8.8:80").expect("route probe");
        let bind_ip = probe.local_addr().expect("probe local addr").ip();
        let guard = SsrfEnvGuard::set(format!(
            "{bind_ip}/{}",
            if bind_ip.is_ipv4() { 32 } else { 128 }
        ));
        let listener = std::net::TcpListener::bind((bind_ip, 0)).expect("bind mock listener");
        let upstream = wiremock::MockServer::builder()
            .listener(listener)
            .start()
            .await;
        (upstream, guard)
    }

    /// Simple-index HTML advertising PEP 658 metadata for `wheel`.
    fn pep658_index_html(wheel: &str) -> String {
        format!(
            "<html><body><a href=\"/packages/{wheel}\" \
             data-dist-info-metadata=\"sha256=deadbeef\">{wheel}</a></body></html>"
        )
    }

    /// Minimal wheel (stored zip) whose only entry is
    /// `{dist_info}.dist-info/METADATA`.
    fn wheel_with_metadata(dist_info: &str, metadata: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file(format!("{dist_info}.dist-info/METADATA"), options)
            .expect("start METADATA entry");
        zip.write_all(metadata).expect("write METADATA");
        zip.finish().expect("finish wheel zip");
        cursor.into_inner()
    }

    /// A remote index may advertise PEP 658 metadata even when the
    /// corresponding `.whl.metadata` resource is unavailable upstream. The
    /// proxy must not turn pip's metadata request into a hard 404: it falls
    /// back to fetching the wheel and extracting METADATA from it
    /// (the `Err(AppError::NotFound)` arm of `serve_remote_metadata`).
    #[tokio::test]
    async fn test_remote_pypi_metadata_404_falls_back_to_wheel_metadata() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;

        let project = "demo";
        let wheel = "demo-1.0-py3-none-any.whl";
        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(pep658_index_html(wheel)))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}.metadata")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(wheel_with_metadata("demo-1.0", metadata)),
            )
            .mount(&upstream)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &upstream.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "upstream 404 on .whl.metadata must fall back to wheel extraction; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            metadata,
            "served metadata must be the wheel's METADATA bytes"
        );
    }

    // -----------------------------------------------------------------------
    // #3193: `serve_remote_metadata` and content codings. Two independent bugs,
    // one per arm, needing opposite remediations:
    //
    //   arm 1 (upstream serves `.metadata`) forwards the bytes VERBATIM, so it
    //         must re-declare the upstream `Content-Encoding`;
    //   arm 2 (upstream 404s, extract METADATA from the wheel) PARSES the
    //         bytes, so it must DECODE them first — forwarding a header would
    //         do nothing for a zip reader handed a deflate stream.
    //
    // Every fixture below is `deflate`, never gzip. #3176 shipped fourteen
    // tests that all stayed green when the forwarded value was replaced with a
    // hardcoded `"gzip"`, because every fixture WAS gzip: they pinned "a coding
    // is declared", not "the UPSTREAM's coding is declared". `tdh::gzip_fixture`
    // is for the GET/HEAD parity arms and is deliberately not used here.
    //
    // These run the real router end to end, so they fail against the handler
    // itself rather than against a response-builder helper.
    // -----------------------------------------------------------------------

    /// Fixed coordinates for the `.metadata` end-to-end cases below.
    const CODING_PROJECT: &str = "demo";
    const CODING_WHEEL: &str = "demo-1.0-py3-none-any.whl";

    /// Drive one PEP 658 `.metadata` request end to end against a mock upstream
    /// that answers `<wheel>.metadata` with `metadata_response` and `<wheel>`
    /// with `wheel_response`.
    ///
    /// Returns `None` when no database is available (the suite's standing
    /// skip), otherwise the served status, body and headers. Shared by the
    /// three cases so the fixture/mock/rewire scaffolding is written once.
    async fn serve_remote_metadata_e2e(
        metadata_response: wiremock::ResponseTemplate,
        wheel_response: wiremock::ResponseTemplate,
    ) -> Option<(StatusCode, Bytes, axum::http::HeaderMap)> {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::Mock;

        let fx = tdh::Fixture::setup("remote", "pypi").await?;
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;

        Mock::given(method("GET"))
            .and(path(format!("/simple/{CODING_PROJECT}/")))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(pep658_index_html(CODING_WHEEL)),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{CODING_WHEEL}.metadata")))
            .respond_with(metadata_response)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{CODING_WHEEL}")))
            .respond_with(wheel_response)
            .mount(&upstream)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &upstream.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let served = tdh::send_with_headers(
            app,
            tdh::get(format!(
                "/{}/simple/{CODING_PROJECT}/{CODING_WHEEL}.metadata",
                fx.repo_key
            )),
        )
        .await;

        fx.teardown().await;
        Some(served)
    }

    /// Arm 1, positive. A `deflate`-coded upstream `.metadata` must be served
    /// with `Content-Encoding: deflate`, and the served bytes must decode under
    /// that declared coding.
    ///
    /// Before #3193 the handler pinned `text/plain; charset=utf-8` and declared
    /// no coding at all — `fetch_upstream_direct_with_link`'s third tuple slot
    /// was the `Link` header, not the coding — so pip received compressed bytes
    /// labelled as plain text.
    ///
    /// Fails if the coding is dropped (asserts the header is present), and
    /// fails if it is hardcoded to `"gzip"` (asserts `deflate`, and decodes the
    /// body with a deflate decoder).
    #[tokio::test]
    async fn test_remote_pypi_metadata_forwards_upstream_deflate_coding() {
        use crate::api::handlers::test_db_helpers as tdh;

        let (plain, coded) = tdh::coded_fixture("deflate", b"Metadata-Version: 2.1\n");
        let Some((status, body, headers)) = serve_remote_metadata_e2e(
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-encoding", "deflate")
                .set_body_bytes(coded.clone()),
            wiremock::ResponseTemplate::new(404),
        )
        .await
        else {
            return;
        };

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            tdh::header_str(&headers, CONTENT_ENCODING).as_deref(),
            Some("deflate"),
            "the served `.metadata` must declare the UPSTREAM's coding; \
             `gzip` means the value is hardcoded, `None` means #3193 is live"
        );
        // The proxy must not decode on pip's behalf: the wire bytes stay coded,
        // which is the whole reason the header has to be declared.
        assert_eq!(
            &body[..],
            coded.as_slice(),
            "coded upstream bytes must be forwarded verbatim"
        );
        assert_eq!(
            tdh::inflate_deflate(&body),
            plain,
            "the served body must decode under the coding the response declares"
        );
    }

    /// Arm 1, negative control. An UNCODED upstream `.metadata` must be served
    /// with NO `Content-Encoding`.
    ///
    /// This is the overwhelmingly common case — most indexes serve `.metadata`
    /// uncoded — so a header emitted unconditionally would break the default
    /// path, not an edge case: pip would try to inflate plain text. Fails if
    /// the header is set unconditionally.
    #[tokio::test]
    async fn test_remote_pypi_metadata_omits_coding_when_upstream_uncoded() {
        use crate::api::handlers::test_db_helpers as tdh;

        let plain: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";
        let Some((status, body, headers)) = serve_remote_metadata_e2e(
            wiremock::ResponseTemplate::new(200).set_body_bytes(plain),
            wiremock::ResponseTemplate::new(404),
        )
        .await
        else {
            return;
        };

        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], plain);
        assert_eq!(
            tdh::header_str(&headers, CONTENT_ENCODING),
            None,
            "an uncoded upstream must be served with NO Content-Encoding; \
             manufacturing one makes pip try to inflate plain text"
        );
    }

    /// Arm 2. When upstream 404s the `.metadata`, a `deflate`-coded WHEEL must
    /// still yield its METADATA.
    ///
    /// This arm needs decode-before-parse, not header forwarding:
    /// `extract_metadata_from_wheel` opens the bytes as a zip, and a coded wheel
    /// is not a parseable zip, so before #3193 a present and perfectly valid
    /// wheel answered 404 "Metadata not available". The served response carries
    /// no coding of its own — the extracted METADATA is freshly built plaintext,
    /// not the upstream bytes — so this also pins that the arm-1 header is not
    /// leaking across arms.
    #[tokio::test]
    async fn test_remote_pypi_metadata_extracts_from_deflate_coded_wheel() {
        use crate::api::handlers::test_db_helpers as tdh;

        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";
        let wheel = wheel_with_metadata("demo-1.0", metadata);
        let coded_wheel = tdh::code_bytes("deflate", &wheel);
        assert_ne!(
            coded_wheel, wheel,
            "the wheel fixture must actually be coded or the test proves nothing"
        );

        let Some((status, body, headers)) = serve_remote_metadata_e2e(
            wiremock::ResponseTemplate::new(404),
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-encoding", "deflate")
                .set_body_bytes(coded_wheel),
        )
        .await
        else {
            return;
        };

        assert_eq!(
            status,
            StatusCode::OK,
            "a deflate-coded wheel is still a valid wheel; its METADATA must be \
             extracted rather than 404'd as unavailable; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            metadata,
            "served metadata must be the coded wheel's METADATA bytes"
        );
        assert_eq!(
            tdh::header_str(&headers, CONTENT_ENCODING),
            None,
            "the extracted METADATA is freshly built plaintext, so the upstream \
             wheel's coding must NOT be echoed onto it"
        );
    }

    /// A virtual repository has no artifacts of its own. PEP 658 metadata must
    /// therefore resolve through its remote member, just as a wheel download
    /// does. This exercises the PR #3077 404-to-wheel fallback through the
    /// virtual route that previously passed the virtual repository ID to
    /// `serve_metadata` and returned 404.
    #[tokio::test]
    async fn test_virtual_pypi_metadata_resolves_remote_member() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "demo";
        let wheel = "demo-1.0-py3-none-any.whl";
        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(pep658_index_html(wheel)))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}.metadata")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(wheel_with_metadata("demo-1.0", metadata)),
            )
            .mount(&upstream)
            .await;

        let (member_id, _member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "virtual metadata request must resolve its member"
        );
        assert_eq!(
            &body[..],
            metadata,
            "virtual member must return wheel METADATA"
        );
    }

    /// A Remote member carrying an `artifacts` row whose `storage_key` object
    /// no longer exists must not turn the virtual `.metadata` route into a
    /// permanent 500 (#3366). The member loop's local-first check hits the row,
    /// storage answers NotFound, and pre-fix `map_storage_err` promoted that to
    /// a 500 — which the loop deliberately propagates (the #3179 transient-
    /// fault guard) instead of trying the SAME member's upstream fallback. With
    /// the NotFound carve-out, the local-first check 404s and the loop falls
    /// through to `serve_remote_metadata`, which serves the upstream's PEP 658
    /// metadata. There are no local bytes for that fallback to mismatch
    /// against, so this does not weaken the #3179 guard for real storage/DB
    /// faults.
    #[tokio::test]
    async fn test_virtual_pypi_metadata_missing_storage_object_falls_back_to_remote() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "demo";
        let wheel = "demo-1.0-py3-none-any.whl";
        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(pep658_index_html(wheel)))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}.metadata")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(metadata))
            .mount(&upstream)
            .await;

        let (member_id, _member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;

        // The poisoned state: an artifacts row on the REMOTE member whose
        // storage_key names an object that was never written (deleted cache
        // entry, lost object, stale backfill). Nothing is written to the
        // member's storage on purpose.
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)",
        )
        .bind(member_id)
        .bind(format!("simple/{project}/{wheel}"))
        .bind(project)
        .bind("1.0")
        .bind("test-orphaned-row")
        .bind("application/zip")
        .bind(format!("missing/{wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed orphaned artifacts row");

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "an orphaned artifacts row must fall through to the member's \
             upstream metadata, not pin the route to a 500: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            metadata,
            "the upstream's PEP 658 metadata must be served"
        );
    }

    /// A higher-priority local owner without a `tracks` declaration isolates
    /// its project from lower-priority remote-only versions. PEP 658 metadata
    /// must enforce the same Case-B suppression as the simple index and wheel
    /// download, including for direct or stale `.metadata` URLs.
    #[tokio::test]
    async fn test_virtual_pypi_metadata_suppresses_remote_only_version() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "demo";
        let local_wheel = "demo-1.0-cp39-cp39-manylinux_2_17_x86_64.whl";
        let remote_wheel = "demo-2.0-cp39-cp39-win_amd64.whl";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(pep658_index_html(remote_wheel)),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{remote_wheel}.metadata")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Metadata-Version: 2.1\nName: demo\nVersion: 2.0\n"),
            )
            .mount(&upstream)
            .await;

        let (remote_id, _remote_key, remote_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let (local_id, _local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("make local owner public");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach higher-priority local owner");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)",
        )
        .bind(local_id)
        .bind(format!("simple/{project}/{local_wheel}"))
        .bind(project)
        .bind("1.0")
        .bind("test-local-owner")
        .bind("application/zip")
        .bind(format!("local/{local_wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed local ownership artifact");

        // Write the local owner's wheel to its storage so the local branch can
        // actually resolve. Without this the local member is only ever a miss,
        // and the 404 below cannot distinguish "the guard suppressed the
        // remote" from "nothing resolved at all".
        let local_wheel_path = local_dir.join("local");
        std::fs::create_dir_all(&local_wheel_path).expect("local storage dir");
        std::fs::write(
            local_wheel_path.join(local_wheel),
            wheel_with_metadata(
                "demo-1.0",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            ),
        )
        .expect("seed local wheel bytes");

        let app = tdh::router_anon(super::router(), state.clone());
        let (status, _body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{remote_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        // POSITIVE CONTROL. The local owner's own wheel must resolve through
        // the virtual. This is the half that fails on `main`: pre-fix, a
        // virtual `.metadata` request falls through to
        // `serve_metadata(repo.id)` against a repo that owns no artifacts, so
        // EVERYTHING 404s -- which silently satisfies the negative assertion
        // above. Without this control the suppression test is green on `main`
        // and carries no information about whether the fix shipped.
        let app = tdh::router_anon(super::router(), state);
        let (local_status, local_body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{local_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        cleanup_virtual_member(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "remote-only metadata must stay hidden when the local owner outranks the remote"
        );
        assert_eq!(
            local_status,
            StatusCode::OK,
            "the local owner's own wheel must still resolve through the virtual"
        );
        assert!(
            String::from_utf8_lossy(&local_body).contains("Version: 1.0"),
            "the served metadata must come from the LOCAL member's wheel, not \
             the remote's -- got {:?}",
            String::from_utf8_lossy(&local_body)
        );
    }

    #[tokio::test]
    async fn test_virtual_pypi_metadata_does_not_leak_a_private_member_to_anon() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "demo";
        let local_wheel = "demo-1.0-cp39-cp39-manylinux_2_17_x86_64.whl";
        let remote_wheel = "demo-2.0-cp39-cp39-win_amd64.whl";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(pep658_index_html(remote_wheel)),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{remote_wheel}.metadata")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Metadata-Version: 2.1\nName: demo\nVersion: 2.0\n"),
            )
            .mount(&upstream)
            .await;

        let (remote_id, _remote_key, remote_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let (local_id, _local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        // PRIVATE, unlike the sibling fixture. An anonymous caller must not
        // be able to read this member's content through the virtual.
        sqlx::query("UPDATE repositories SET is_public = false WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("make local owner private");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach higher-priority local owner");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)",
        )
        .bind(local_id)
        .bind(format!("simple/{project}/{local_wheel}"))
        .bind(project)
        .bind("1.0")
        .bind("test-local-owner")
        .bind("application/zip")
        .bind(format!("local/{local_wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed local ownership artifact");

        // Write the local owner's wheel to its storage so the local branch can
        // actually resolve. Without this the local member is only ever a miss,
        // and the 404 below cannot distinguish "the guard suppressed the
        // remote" from "nothing resolved at all".
        let local_wheel_path = local_dir.join("local");
        std::fs::create_dir_all(&local_wheel_path).expect("local storage dir");
        std::fs::write(
            local_wheel_path.join(local_wheel),
            wheel_with_metadata(
                "demo-1.0",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            ),
        )
        .expect("seed local wheel bytes");

        let app = tdh::router_anon(super::router(), state.clone());
        let (status, _body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{remote_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        // POSITIVE CONTROL. The local owner's own wheel must resolve through
        // the virtual. This is the half that fails on `main`: pre-fix, a
        // virtual `.metadata` request falls through to
        // `serve_metadata(repo.id)` against a repo that owns no artifacts, so
        // EVERYTHING 404s -- which silently satisfies the negative assertion
        // above. Without this control the suppression test is green on `main`
        // and carries no information about whether the fix shipped.
        let app = tdh::router_anon(super::router(), state);
        let (local_status, local_body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{local_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        cleanup_virtual_member(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        let _ = status;
        // `serve_virtual_metadata` is a NEW way to read member content through
        // a virtual repo, so the member filter is load-bearing here rather
        // than inherited. Deleting `authorize_virtual_members` leaves every
        // other test in this module green.
        assert_ne!(
            local_status,
            StatusCode::OK,
            "an anonymous caller must not read a PRIVATE member's metadata \
             through the virtual: got body {:?}",
            String::from_utf8_lossy(&local_body)
        );
    }

    #[tokio::test]
    async fn test_virtual_pypi_metadata_survives_a_failing_higher_priority_member() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "demo";
        let local_wheel = "demo-1.0-cp39-cp39-manylinux_2_17_x86_64.whl";
        let remote_wheel = "demo-2.0-cp39-cp39-win_amd64.whl";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{remote_wheel}.metadata")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Metadata-Version: 2.1\nName: demo\nVersion: 2.0\n"),
            )
            .mount(&upstream)
            .await;

        let (remote_id, _remote_key, remote_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let (local_id, _local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("make local owner public");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 10)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach LOWER-priority local owner (remote outranks it)");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)",
        )
        .bind(local_id)
        .bind(format!("simple/{project}/{local_wheel}"))
        .bind(project)
        .bind("1.0")
        .bind("test-local-owner")
        .bind("application/zip")
        .bind(format!("local/{local_wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed local ownership artifact");

        // Write the local owner's wheel to its storage so the local branch can
        // actually resolve. Without this the local member is only ever a miss,
        // and the 404 below cannot distinguish "the guard suppressed the
        // remote" from "nothing resolved at all".
        let local_wheel_path = local_dir.join("local");
        std::fs::create_dir_all(&local_wheel_path).expect("local storage dir");
        std::fs::write(
            local_wheel_path.join(local_wheel),
            wheel_with_metadata(
                "demo-1.0",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            ),
        )
        .expect("seed local wheel bytes");

        let app = tdh::router_anon(super::router(), state.clone());
        let (status, _body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{remote_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        // POSITIVE CONTROL. The local owner's own wheel must resolve through
        // the virtual. This is the half that fails on `main`: pre-fix, a
        // virtual `.metadata` request falls through to
        // `serve_metadata(repo.id)` against a repo that owns no artifacts, so
        // EVERYTHING 404s -- which silently satisfies the negative assertion
        // above. Without this control the suppression test is green on `main`
        // and carries no information about whether the fix shipped.
        let app = tdh::router_anon(super::router(), state);
        let (local_status, local_body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/{project}/{local_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        cleanup_virtual_member(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        let _ = status;
        // `serve_virtual_metadata` is a NEW way to read member content through
        // a virtual repo, so the member filter is load-bearing here rather
        // than inherited. Deleting `authorize_virtual_members` leaves every
        // other test in this module green.
        // The remote outranks the local owner and returns 500. Previously any
        // non-404 aborted the whole loop, so a misconfigured or briefly-down
        // upstream made EVERY locally-owned package's metadata 502 -- while
        // the sibling wheel download succeeded, because `serve_file`'s loop
        // logs and continues. Resolution must reach the local member.
        assert_eq!(
            local_status,
            StatusCode::OK,
            "a failing higher-priority member must not deny metadata for a \
             package a lower-priority member owns: got body {:?}",
            String::from_utf8_lossy(&local_body)
        );
        assert!(
            String::from_utf8_lossy(&local_body).contains("Version: 1.0"),
            "and the body must be the local member's"
        );
    }

    #[tokio::test]
    async fn test_virtual_pypi_metadata_isolation_survives_a_divergent_project_spelling() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        let project = "acme-sdk";
        let local_wheel = "acme_sdk-1.0-cp39-cp39-manylinux_2_17_x86_64.whl";
        let remote_wheel = "acme_sdk-9.9.9-py3-none-any.whl";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(pep658_index_html(remote_wheel)),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{remote_wheel}.metadata")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Metadata-Version: 2.1\nName: acme-sdk\nVersion: 9.9.9\n"),
            )
            .mount(&upstream)
            .await;

        let (remote_id, _remote_key, remote_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let (local_id, _local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("make local owner public");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach higher-priority local owner");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)",
        )
        .bind(local_id)
        .bind(format!("simple/{project}/{local_wheel}"))
        .bind(project)
        .bind("1.0")
        .bind("test-local-owner")
        .bind("application/zip")
        .bind(format!("local/{local_wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed local ownership artifact");

        let app = tdh::router_anon(super::router(), state);
        let (status, _body) = tdh::send(
            app,
            // Same request, but the project segment is spelled with a
            // character that the two normalizers disagree about. axum
            // percent-decodes the segment, so the handler sees "demo x".
            //
            // `normalize_pep503` (the gate) DROPS any character outside
            // [A-Za-z0-9._-] without marking a separator, so it yields
            // "demox" and no local owner is found. `PypiHandler::normalize_name`
            // (the upstream fetch) maps every non-alphanumeric to '-', so it
            // yields "demo-x" and asks upstream for a different project than
            // the one the gate cleared.
            // "acme sdk" -- one space. axum percent-decodes it.
            //
            // `normalize_pep503` (the GATE) drops any character outside
            // [A-Za-z0-9._-] without marking a separator  -> "acmesdk",
            // which no local member owns, so nothing is suppressed.
            // `PypiHandler::normalize_name` (the upstream FETCH) maps every
            // non-alphanumeric to '-'                      -> "acme-sdk",
            // which is exactly the private package the gate was supposed to
            // protect. The upstream mock below answers on that spelling, the
            // way public PyPI would for an attacker-published shadow.
            tdh::get(format!(
                "/{}/simple/acme%20sdk/{remote_wheel}.metadata",
                fx.repo_key
            )),
        )
        .await;

        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        cleanup_virtual_member(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "isolation must not depend on how the client spells the project. If the \
             string used for the policy check differs from the string used to fetch, \
             one percent-encoded character turns the dependency-confusion gate off."
        );
    }

    /// The common real-world path: the upstream serves `.whl.metadata` with
    /// 200 and the proxy returns that body (the `Ok` arm of
    /// `serve_remote_metadata`). No wheel mock is mounted, so the test also
    /// proves the fallback does not fire spuriously.
    ///
    /// The upstream deliberately labels the metadata `text/html`: a PEP 658
    /// metadata resource is always the plain-text METADATA file, and relaying a
    /// hostile upstream's content-type would let it choose how this origin
    /// renders the response. The served type must be pinned to `text/plain`.
    #[tokio::test]
    async fn test_remote_pypi_metadata_200_served_directly() {
        use crate::api::handlers::test_db_helpers as tdh;
        use tower::ServiceExt;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;

        let project = "demo";
        let wheel = "demo-1.0-py3-none-any.whl";
        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(pep658_index_html(wheel)))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}.metadata")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_bytes(metadata),
            )
            .mount(&upstream)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &upstream.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let resp = app
            .oneshot(tdh::get(format!(
                "/{}/simple/{project}/{wheel}.metadata",
                fx.repo_key
            )))
            .await
            .expect("oneshot");
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("body");

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "upstream 200 on .whl.metadata must be served; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            metadata,
            "upstream metadata must be served verbatim"
        );
        assert_eq!(
            content_type, "text/plain; charset=utf-8",
            "the served content-type must be pinned to text/plain, not relayed \
             from the upstream (which answered text/html here)"
        );
    }

    /// A repeated `.whl.metadata` request is served from the proxy cache
    /// (#3300), reaching upstream zero times.
    ///
    /// Asserted on the upstream request COUNT, not the body: the sidecar's
    /// bytes are correct whether or not the cache is consulted, so only the
    /// count separates a cache hit from a silent refetch of the simple index
    /// and the sidecar.
    #[tokio::test]
    async fn test_remote_pypi_metadata_is_served_from_cache_on_repeat() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;

        let project = "demo";
        let wheel = "demo-1.0-py3-none-any.whl";
        let metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";

        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(pep658_index_html(wheel)))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{wheel}.metadata")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(metadata))
            .mount(&upstream)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &upstream.uri()).await;
        let uri = format!("/{}/simple/{project}/{wheel}.metadata", fx.repo_key);

        let (cold_status, cold_body, cold_headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(uri.clone()),
        )
        .await;
        let after_cold = upstream.received_requests().await.unwrap_or_default().len();

        let (warm_status, warm_body, warm_headers) =
            tdh::send_with_headers(tdh::router_anon(super::router(), state), tdh::get(uri)).await;
        let after_warm = upstream.received_requests().await.unwrap_or_default().len();

        fx.teardown().await;

        assert_eq!(
            cold_status,
            StatusCode::OK,
            "cold .metadata request must be served; body: {}",
            String::from_utf8_lossy(&cold_body)
        );
        assert_eq!(&cold_body[..], metadata);
        assert_eq!(
            after_cold, 2,
            "a cold sidecar costs one simple-index read plus one sidecar fetch"
        );

        assert_eq!(
            warm_status,
            StatusCode::OK,
            "warm .metadata request must be served; body: {}",
            String::from_utf8_lossy(&warm_body)
        );
        assert_eq!(
            after_warm, after_cold,
            "a repeated .metadata request must hit the proxy cache and reach \
             upstream zero times — neither the sidecar nor the simple index"
        );

        // What the cache replays must be indistinguishable from what filled it.
        assert_eq!(
            warm_body, cold_body,
            "cached sidecar bytes must be identical"
        );
        assert_eq!(
            warm_headers.get(CONTENT_TYPE),
            cold_headers.get(CONTENT_TYPE),
            "cached sidecar must carry the same Content-Type"
        );
        assert_eq!(
            warm_headers.get(CONTENT_ENCODING),
            cold_headers.get(CONTENT_ENCODING),
            "cached sidecar must carry the same Content-Encoding"
        );
    }

    /// Curation must gate every spelling of a metadata request, not just the
    /// canonical one. A version-constrained block rule is evaluated against the
    /// version parsed from the requested distribution, so a request that names
    /// the blocked wheel through a stacked `.metadata` suffix must resolve to
    /// the same distribution and be blocked identically — otherwise the version
    /// parses as `None`, the version-constrained rule is skipped, and the
    /// blocked version's metadata is served anyway.
    #[tokio::test]
    async fn test_curation_blocks_every_metadata_suffix_shape() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;

        let project = "demo";
        let blocked_wheel = "demo-1.0-py3-none-any.whl";
        let allowed_wheel = "demo-2.0-py3-none-any.whl";
        let blocked_metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n";
        let allowed_metadata: &[u8] = b"Metadata-Version: 2.1\nName: demo\nVersion: 2.0\n";

        // The upstream would happily serve both versions: only curation may
        // withhold 1.0, so a 403 here cannot come from an unreachable mock.
        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "{}{}",
                pep658_index_html(blocked_wheel),
                pep658_index_html(allowed_wheel)
            )))
            .mount(&upstream)
            .await;
        for (wheel, metadata) in [
            (blocked_wheel, blocked_metadata),
            (allowed_wheel, allowed_metadata),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/packages/{wheel}.metadata")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&upstream)
                .await;
            let dist_info = wheel.split('-').take(2).collect::<Vec<_>>().join("-");
            Mock::given(method("GET"))
                .and(path(format!("/packages/{wheel}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(wheel_with_metadata(&dist_info, metadata)),
                )
                .mount(&upstream)
                .await;
        }

        // `=1.0`, not `==1.0`: `version_matches` strips a single leading `=`,
        // so the PEP 440 spelling would leave the target as `=1.0` and match
        // nothing — which would make this test vacuously green.
        enable_curation_with_rule(&fx.pool, fx.repo_id, fx.user_id, "demo*", "=1.0").await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &upstream.uri()).await;

        let request = |suffix: &str| {
            let state = state.clone();
            let uri = format!("/{}/simple/{project}/{suffix}", fx.repo_key);
            async move { tdh::send(tdh::router_anon(super::router(), state), tdh::get(uri)).await }
        };

        let (canonical_status, canonical_body) =
            request(&format!("{blocked_wheel}.metadata")).await;
        let (stacked_status, stacked_body) =
            request(&format!("{blocked_wheel}.metadata.metadata")).await;
        let (allowed_status, allowed_body) = request(&format!("{allowed_wheel}.metadata")).await;

        fx.teardown().await;

        assert_eq!(
            canonical_status,
            StatusCode::FORBIDDEN,
            "the canonical metadata request for a blocked version must 403; body: {}",
            String::from_utf8_lossy(&canonical_body)
        );
        assert_eq!(
            stacked_status,
            StatusCode::FORBIDDEN,
            "a stacked .metadata suffix names the same blocked distribution and \
             must 403 identically; body: {}",
            String::from_utf8_lossy(&stacked_body)
        );
        // The strongest discriminator: pre-fix this response was a 200 whose
        // body was the blocked version's real METADATA.
        assert_ne!(
            &stacked_body[..],
            blocked_metadata,
            "a blocked version's metadata must never be served through any suffix shape"
        );
        assert_eq!(
            allowed_status,
            StatusCode::OK,
            "a version the rule does not constrain must still be served; body: {}",
            String::from_utf8_lossy(&allowed_body)
        );
        assert_eq!(
            &allowed_body[..],
            allowed_metadata,
            "the unblocked version must serve its own METADATA"
        );
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
            commit_sha: None,
            content_encoding: None,
            body: Box::pin(stream),
            content_type: Some("application/zip".to_string()),
            content_length: Some(data_len),
            artifact_id: None,
            etag: None,
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
            RepositoryFormat::Pypi,
        )
        .await;

        assert!(
            result.is_none(),
            "cache miss must yield None, not Some(result)"
        );
    }

    // -----------------------------------------------------------------------
    // Curation gating (#2912): a curation "block" rule must 403
    // requests through the PyPI proxy's simple index on a curation-enabled
    // repository, and must be a no-op on a repository with curation disabled.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_curation_block_rule_403s_simple_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        sqlx::query(
            "UPDATE repositories SET curation_enabled = true, curation_default_action = 'allow' \
             WHERE id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("enable curation on fixture repo");

        sqlx::query(
            "INSERT INTO curation_rules \
                 (staging_repo_id, package_pattern, version_constraint, architecture, \
                  action, priority, reason, enabled, created_by) \
             VALUES ($1, 'evilpkg*', '*', '*', 'block', 10, 'blocked by test rule', true, $2)",
        )
        .bind(fx.repo_id)
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("insert curation block rule");

        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!("/{}/simple/evilpkg/", fx.repo_key));
        let (blocked_status, blocked_body) = tdh::send(app, req).await;

        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!("/{}/simple/goodpkg/", fx.repo_key));
        let (allowed_status, _allowed_body) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            blocked_status,
            StatusCode::FORBIDDEN,
            "a curation block rule must 403 the simple index for a matching package"
        );
        assert!(
            String::from_utf8_lossy(&blocked_body).contains("blocked by test rule"),
            "403 body must surface the rule's reason: {}",
            String::from_utf8_lossy(&blocked_body)
        );
        // Asserted as the concrete expected status rather than `!= 403`: a
        // not-403 assertion passes on pre-enforcement code and for reasons that
        // have nothing to do with curation, so it is a guard, not a regression
        // test. 404 is what this handler returns once the request falls through to
        // the fixture's unreachable upstream.
        assert_eq!(
            allowed_status,
            StatusCode::NOT_FOUND,
            "a package not matched by any rule must fall through to the (unreachable) \
             upstream rather than being blocked by curation"
        );
    }

    /// Enable curation on a repository and insert one block rule.
    async fn enable_curation_with_rule(
        pool: &sqlx::PgPool,
        repo_id: uuid::Uuid,
        user_id: uuid::Uuid,
        pattern: &str,
        version_constraint: &str,
    ) {
        sqlx::query(
            "UPDATE repositories SET curation_enabled = true, curation_default_action = 'allow' \
             WHERE id = $1",
        )
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("enable curation");

        sqlx::query(
            "INSERT INTO curation_rules \
                 (staging_repo_id, package_pattern, version_constraint, architecture, \
                  action, priority, reason, enabled, created_by) \
             VALUES ($1, $2, $3, '*', 'block', 10, 'blocked by test rule', true, $4)",
        )
        .bind(repo_id)
        .bind(pattern)
        .bind(version_constraint)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert curation block rule");
    }

    /// The download path must be gated too, not just the index. Deleting the gate
    /// in `download_or_metadata` would otherwise leave the feature looking alive
    /// while the path that actually serves bytes was open (#2912).
    #[tokio::test]
    async fn test_curation_block_rule_403s_download() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        enable_curation_with_rule(&fx.pool, fx.repo_id, fx.user_id, "evilpkg*", "*").await;

        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!(
            "/{}/simple/evilpkg/evilpkg-1.0.tar.gz",
            fx.repo_key
        ));
        let (status, body) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a curation block rule must 403 the download path"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("blocked by test rule"),
            "403 body must surface the rule's reason: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// A rule written the way PyPI displays the project must match the normalized
    /// request name. `glob_match` is case-sensitive and the gate normalizes only the
    /// request, so before the fix a `PyYAML` rule silently enforced nothing on the
    /// proxy while the staging-sync path enforced it (#2912).
    #[tokio::test]
    async fn test_curation_rule_pattern_is_pep503_insensitive() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        // Display spelling: mixed case AND an underscore separator.
        enable_curation_with_rule(&fx.pool, fx.repo_id, fx.user_id, "Evil_Pkg", "*").await;

        let app = fx.router_with_auth(super::router());
        // PEP 503 request spelling for the same project.
        let req = tdh::get(format!("/{}/simple/evil-pkg/", fx.repo_key));
        let (status, body) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a rule spelled 'Evil_Pkg' must block a request for 'evil-pkg'"
        );
        assert!(String::from_utf8_lossy(&body).contains("blocked by test rule"));
    }

    /// A version-constrained rule must be decided against the real version, and
    /// skipped (not mis-evaluated) when the request carries none. Before the fix the
    /// gate passed the literal "*" as the *version*, which made `>=` rules match
    /// nothing and `<` rules match everything (#2912).
    #[tokio::test]
    async fn test_curation_version_constraint_applies_on_download_only() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        enable_curation_with_rule(&fx.pool, fx.repo_id, fx.user_id, "evilpkg", ">= 2.0").await;

        // Download of a version the rule covers: blocked.
        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!(
            "/{}/simple/evilpkg/evilpkg-2.5.tar.gz",
            fx.repo_key
        ));
        let (blocked_status, _) = tdh::send(app, req).await;

        // Download of a version below the constraint: not blocked.
        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!(
            "/{}/simple/evilpkg/evilpkg-1.0.tar.gz",
            fx.repo_key
        ));
        let (allowed_status, _) = tdh::send(app, req).await;

        // Index request carries no version, so the constrained rule is skipped
        // rather than being read as matching (or not matching) everything.
        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!("/{}/simple/evilpkg/", fx.repo_key));
        let (index_status, _) = tdh::send(app, req).await;

        fx.teardown().await;

        assert_eq!(
            blocked_status,
            StatusCode::FORBIDDEN,
            "'>= 2.0' must block version 2.5 on the download path"
        );
        assert_ne!(
            allowed_status,
            StatusCode::FORBIDDEN,
            "'>= 2.0' must not block version 1.0"
        );
        assert_ne!(
            index_status,
            StatusCode::FORBIDDEN,
            "a version-constrained rule must not block a versionless index request"
        );
    }

    /// A virtual repository fronting a curated remote must enforce that member's
    /// rules. Before the fix the gate only saw the virtual repository's own flags,
    /// so the normal curated-mirror topology served blocked packages — the same
    /// bypass class #2066 fixed for the age gate (#2912).
    #[tokio::test]
    async fn test_curation_enforced_through_virtual_member() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        enable_curation_with_rule(&fx.pool, fx.repo_id, fx.user_id, "evilpkg*", "*").await;

        // A virtual repository with the curated remote as its only member. The
        // virtual repo itself has curation disabled, which is the point: the
        // member's rules must still apply.
        let virtual_id = uuid::Uuid::new_v4();
        let virtual_key = format!("ph-test-virtual-{virtual_id}");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'virtual'::repository_type, 'pypi'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&*fx.storage_dir.to_string_lossy())
        .execute(&fx.pool)
        .await
        .expect("create virtual repo");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("attach member");

        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!("/{virtual_key}/simple/evilpkg/"));
        let (status, _body) = tdh::send(app, req).await;

        // Clean up the extra rows the fixture's own teardown does not know about.
        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&fx.pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(&fx.pool)
            .await
            .ok();
        fx.teardown().await;

        assert_ne!(
            status,
            StatusCode::OK,
            "a package blocked by a virtual member's curation rule must not be served \
             through the virtual repository"
        );
    }

    /// #3183: the PEP 708 dependency-confusion isolation must not depend on how
    /// the client spells the project segment.
    ///
    /// `serve_file`'s gates keyed on `normalize_pep503(project)` while the raw
    /// segment was passed downstream, where `PypiHandler::normalize_name`
    /// re-normalized it differently:
    ///
    /// ```text
    /// input        gate (normalize_pep503)   fetch (normalize_name)
    /// "acme-sdk"   acme-sdk                  acme-sdk      same
    /// "acme sdk"   acmesdk                   acme-sdk      DIVERGE
    /// ```
    ///
    /// So one space turned the gate off (nothing owns "acmesdk", so nothing was
    /// suppressed) and then resolved the private package's real name upstream —
    /// serving the attacker's WHEEL BYTES, not merely metadata.
    ///
    /// FIXTURE NOTE, and it is load-bearing: the private package name MUST
    /// contain a separator. With a separator-free name like `demo` the two
    /// normalizers cannot diverge in the exploitable direction ("demo x" ->
    /// "demox" vs "demo-x", neither of which is `demo`), and this test reports a
    /// FALSE PASS. That cost a full cycle on #3179.
    #[tokio::test]
    async fn test_virtual_pypi_download_isolation_survives_a_divergent_project_spelling() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (upstream, _ssrf_allowlist) = non_loopback_upstream().await;
        // A HYPHENATED private name -- see the fixture note above.
        let project = "acme-sdk";
        let local_wheel = "acme_sdk-1.0-py3-none-any.whl";
        let attacker_wheel = "acme_sdk-9.9.9-py3-none-any.whl";
        let attacker_bytes: &[u8] = b"PK\x03\x04 ATTACKER-SHADOW-WHEEL";
        let local_bytes: &[u8] = b"PK\x03\x04 private-acme-sdk-wheel";

        // The public shadow: the attacker has published `acme-sdk` upstream,
        // the classic dependency-confusion setup. The upstream answers ONLY on
        // the private package's real, hyphenated spelling -- exactly as
        // pypi.org would. It has no `acmesdk` project, so an unmatched request
        // 404s, which is what makes the assertion below meaningful.
        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(pep658_index_html(attacker_wheel)),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/packages/{attacker_wheel}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(attacker_bytes.to_vec()))
            .mount(&upstream)
            .await;

        // Remote member at priority 1 (the public upstream).
        let (remote_id, _remote_key, remote_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;

        // Local member at priority 0 owning the private `acme-sdk`.
        let (local_id, _local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("make local owner public");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach higher-priority local owner");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(local_id)
        .bind(format!("simple/{project}/{local_wheel}"))
        .bind(project)
        .bind("1.0")
        .bind(local_bytes.len() as i64)
        .bind("test-local-owner")
        .bind("application/zip")
        .bind(format!("local/{local_wheel}"))
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed local ownership artifact");

        // Write the owner's wheel bytes so the POSITIVE CONTROL below can
        // actually resolve. Without this the local member is only ever a miss,
        // and a 404 on the attack request could not be distinguished from "the
        // fixture never wired anything up at all".
        let local_storage = local_dir.join("local");
        std::fs::create_dir_all(&local_storage).expect("local storage dir");
        std::fs::write(local_storage.join(local_wheel), local_bytes).expect("seed local wheel");

        // THE ATTACK. Same wheel request, but the project segment is spelled
        // "acme sdk" -- one space. axum percent-decodes it, so the handler sees
        // the literal space.
        //
        // `normalize_pep503` (the GATE) drops any character outside
        // [A-Za-z0-9._-] WITHOUT marking a separator -> "acmesdk", which no
        // local member owns, so `owning_local_min_priority` is None and nothing
        // is suppressed. `PypiHandler::normalize_name` (the upstream FETCH)
        // maps every non-alphanumeric to '-' -> "acme-sdk", which is exactly
        // the private package the gate exists to protect.
        let app = tdh::router_anon(super::router(), state.clone());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{}/simple/acme%20sdk/{attacker_wheel}",
                fx.repo_key
            )),
        )
        .await;

        // POSITIVE CONTROL. The owner's own wheel must still resolve through
        // the virtual under the canonical spelling, proving both members are
        // wired and reachable and that the 404 above is the gate and the fetch
        // finally agreeing -- not a broken fixture.
        let app = tdh::router_anon(super::router(), state);
        let (control_status, control_body) = tdh::send(
            app,
            tdh::get(format!("/{}/simple/{project}/{local_wheel}", fx.repo_key)),
        )
        .await;

        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        cleanup_virtual_member(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        assert_ne!(
            &body[..],
            attacker_bytes,
            "the attacker's shadow wheel was SERVED. Isolation must not depend on \
             how the client spells the project: if the string used for the policy \
             check differs from the string used to fetch, one percent-encoded \
             character turns the dependency-confusion gate off and the upstream \
             resolves the private package's real name."
        );
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a divergent spelling must not resolve any distribution"
        );
        assert_eq!(
            control_status,
            StatusCode::OK,
            "positive control: the local owner's wheel must still serve"
        );
        assert_eq!(
            &control_body[..],
            local_bytes,
            "positive control: the local owner's OWN bytes must be served"
        );
    }

    /// The fix in `serve_file` / `download_or_metadata` passes the
    /// `normalize_pep503` output to helpers that re-normalize with
    /// `PypiHandler::normalize_name`. That is only behavior-preserving if the
    /// second function is the IDENTITY on the first one's output — otherwise
    /// every upstream URL and proxy-cache key would shift for well-formed
    /// names. Prove it rather than asserting it.
    ///
    /// `normalize_pep503` emits only `[a-z0-9]` and `-`, never leading,
    /// trailing, or consecutive `-`. `normalize_name` lowercases alphanumerics
    /// (already lowercase) and maps a non-alphanumeric to `-` unless the
    /// previous character was a separator — which, given no runs, is exactly a
    /// copy.
    #[test]
    fn test_normalize_name_is_idempotent_on_pep503_output() {
        let inputs = [
            "acme-sdk",
            "acme sdk",
            "acme_sdk",
            "acme.sdk",
            "Acme..SDK",
            "ACME__SDK",
            "zope.interface",
            "backports.ssl_match_hostname",
            "ruamel.yaml",
            "Jinja2",
            "requests",
            "a",
            "_leading",
            "trailing_",
            "my--package",
            "my_._package",
            "<script>alert(1)</script>",
            "foo&bar",
            "acme!sdk",
            "acmeésdk",
            "a\\b\tc\nd",
            "café-au-lait",
            "..--__..",
        ];

        for input in inputs {
            let pep503 = normalize_pep503(input);
            assert_eq!(
                PypiHandler::normalize_name(&pep503),
                pep503,
                "normalize_name must be the identity on normalize_pep503 output \
                 (input {input:?} normalized to {pep503:?}); if it is not, passing \
                 the normalized name downstream would change upstream URLs and \
                 proxy-cache keys"
            );
        }
    }

    /// The divergence this whole class of bug rests on, pinned so it cannot be
    /// silently "fixed" by making `normalize_pep503` permissive — the dropping
    /// behavior is a deliberate XSS boundary (see the function's docs and
    /// `test_normalize_pep503_drops_script_chars`). The point is that the FETCH
    /// must consume the gate's output, not that the two agree on raw input.
    #[test]
    fn test_the_two_pypi_normalizers_still_diverge_on_invalid_names() {
        assert_eq!(normalize_pep503("acme sdk"), "acmesdk");
        assert_eq!(PypiHandler::normalize_name("acme sdk"), "acme-sdk");
        assert_ne!(
            normalize_pep503("acme sdk"),
            PypiHandler::normalize_name("acme sdk"),
            "if these ever converge, the #3183 fix is still correct but this \
             test's premise changed; see #3186 for rejecting invalid names at \
             the edge instead"
        );
        // They agree on every WELL-FORMED (PEP 508) name, which is why passing
        // the normalized form downstream is behavior-preserving.
        for name in ["acme-sdk", "acme_sdk", "acme.sdk", "Acme-SDK", "requests"] {
            assert_eq!(
                normalize_pep503(name),
                PypiHandler::normalize_name(name),
                "the two normalizers must agree on the valid-name domain"
            );
        }
    }

    #[tokio::test]
    async fn test_curation_disabled_repo_unaffected() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        // curation_enabled defaults to false; the fixture repo is left as-is.
        // The same block rule that would 403 a curation-enabled repo must be
        // a no-op here.
        sqlx::query(
            "INSERT INTO curation_rules \
                 (staging_repo_id, package_pattern, version_constraint, architecture, \
                  action, priority, reason, enabled, created_by) \
             VALUES ($1, 'evilpkg*', '*', '*', 'block', 10, 'blocked by test rule', true, $2)",
        )
        .bind(fx.repo_id)
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("insert curation block rule");

        let app = fx.router_with_auth(super::router());
        let req = tdh::get(format!("/{}/simple/evilpkg/", fx.repo_key));
        let (status, _body) = tdh::send(app, req).await;

        fx.teardown().await;

        // Concrete expected status rather than `!= 403`, which passes trivially on
        // pre-enforcement code and for reasons unrelated to curation. 404 is the
        // fall-through once the request reaches the fixture's unreachable upstream.
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a curation-disabled repo must not be blocked by a matching rule"
        );
    }

    // -----------------------------------------------------------------------
    // #2954 inline proxy scan-and-block: pure helpers.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_hex_known_vectors() {
        // Empty input and the classic "abc" NIST vector: the verdict cache is
        // keyed on this digest, so it must be the plain lowercase-hex SHA-256
        // of the CONTENT (never an index-advertised digest).
        assert_eq!(
            sha256_hex(&Bytes::new()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(&Bytes::from_static(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_pypi_synthetic_artifact_shape() {
        let repo_id = uuid::Uuid::new_v4();
        let filename = "PyYAML-5.3.1-cp38-cp38-manylinux1_x86_64.whl";
        let digest = "deadbeef".repeat(8);
        let art = pypi_synthetic_artifact(repo_id, filename, &digest, 1234);

        // The synthetic artifact drives scanner applicability + workspace
        // naming exactly as a hosted wheel would.
        assert_eq!(art.repository_id, repo_id);
        assert_eq!(art.name, filename);
        assert_eq!(art.path, filename);
        assert_eq!(art.version.as_deref(), Some("5.3.1"));
        assert_eq!(art.size_bytes, 1234);
        assert_eq!(art.checksum_sha256, digest);
        assert_eq!(art.content_type, "application/zip");
        // No artifacts row backs this: storage key stays empty by design.
        assert!(art.storage_key.is_empty());
        assert!(!art.is_deleted);
        assert_eq!(art.quarantine_status, None);

        // sdist naming resolves version + gzip content type too.
        let sdist = pypi_synthetic_artifact(repo_id, "requests-2.31.0.tar.gz", &digest, 1);
        assert_eq!(sdist.version.as_deref(), Some("2.31.0"));
        assert_eq!(sdist.content_type, "application/gzip");
    }

    #[test]
    fn test_scan_blocked_response_is_403_neutral_json() {
        let resp = scan_blocked_response("evil-1.0.whl");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_scan_blocked_response_body_names_file_not_cves() {
        // The download route is anonymous-readable for public repos: the body
        // must name the file, never the specific CVEs.
        let resp = scan_blocked_response("evil-1.0.whl");
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "scan_blocked");
        assert_eq!(json["file"], "evil-1.0.whl");
        assert!(!body.windows(4).any(|w| w == b"CVE-"), "no CVE detail leak");
    }

    #[tokio::test]
    async fn test_scan_pending_locked_response_is_423() {
        // The fail-closed inconclusive branch must be 423 Locked, never a 200
        // of unscanned bytes.
        let resp = scan_pending_locked_response("big-1.0.whl");
        assert_eq!(resp.status(), StatusCode::LOCKED);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "scan_pending");
        assert_eq!(json["file"], "big-1.0.whl");
    }

    #[test]
    fn test_build_scanned_file_response_clean_and_pending_headers() {
        let bytes = Bytes::from_static(b"PK\x03\x04wheel-bytes");
        let digest = sha256_hex(&bytes);

        // Clean serve: explicit content type wins, digest header present.
        let resp = build_scanned_file_response(
            "pkg-1.0-py3-none-any.whl",
            bytes.clone(),
            Some("application/x-custom".to_string()),
            None,
            Some(&digest),
            false,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/x-custom"
        );
        assert_eq!(
            resp.headers().get("X-AK-Scan").unwrap().to_str().unwrap(),
            "clean"
        );
        assert_eq!(
            resp.headers()
                .get("X-PyPI-File-SHA256")
                .unwrap()
                .to_str()
                .unwrap(),
            digest
        );
        assert_eq!(
            resp.headers()
                .get(CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            bytes.len().to_string()
        );

        // Pending serve (fail-open before a verdict): loud header, and the
        // content type falls back to the filename-derived default.
        let resp = build_scanned_file_response("pkg-1.0.tar.gz", bytes, None, None, None, true);
        assert_eq!(
            resp.headers().get("X-AK-Scan").unwrap().to_str().unwrap(),
            "pending"
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/gzip"
        );
        assert!(resp.headers().get("X-PyPI-File-SHA256").is_none());
    }

    // -----------------------------------------------------------------------
    // #3184: the buffered scan-on-proxy serve path must forward the UPSTREAM's
    // Content-Encoding.
    //
    // Every fixture below is `deflate`, never gzip. #3176 shipped fourteen
    // tests that all stayed green when the forwarded value was replaced by a
    // hardcoded `"gzip"` literal, because every fixture WAS gzip -- they pinned
    // "a coding is declared", not "the upstream's coding is declared". A
    // gzip-only fixture cannot tell the two apart; deflate can.
    // -----------------------------------------------------------------------

    /// Positive: a deflate-coded upstream body is served with
    /// `Content-Encoding: deflate`, not with some other coding and not bare.
    ///
    /// Fails if the builder hardcodes `"gzip"` (asserts `deflate`), and fails
    /// if the builder drops the coding (asserts the header is present) -- the
    /// #3184 bug itself.
    #[test]
    fn test_build_scanned_file_response_forwards_upstream_deflate_coding() {
        use crate::api::handlers::test_db_helpers as tdh;
        let (_plain, coded) = tdh::coded_fixture("deflate", b"wheel-payload-");
        let bytes = Bytes::from(coded.clone());
        let digest = sha256_hex(&bytes);

        let resp = build_scanned_file_response(
            "pkg-1.0-py3-none-any.whl",
            bytes.clone(),
            None,
            Some("deflate"),
            Some(&digest),
            false,
        );

        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_ENCODING).as_deref(),
            Some("deflate"),
            "buffered scanned serve must declare the UPSTREAM's coding; \
             `gzip` here means the value is hardcoded, `None` means #3184 is live"
        );
        // Content-Length describes the CODED bytes, which is only correct
        // once the coding is declared alongside it.
        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_LENGTH).as_deref(),
            Some(coded.len().to_string().as_str())
        );
    }

    /// Negative control: an UNCODED upstream must not have a coding
    /// manufactured for it. Fails if the header is emitted unconditionally.
    #[test]
    fn test_build_scanned_file_response_omits_coding_when_upstream_uncoded() {
        use crate::api::handlers::test_db_helpers as tdh;
        let bytes = Bytes::from_static(b"PK\x03\x04plain-wheel-bytes");
        let digest = sha256_hex(&bytes);

        let resp = build_scanned_file_response(
            "pkg-1.0-py3-none-any.whl",
            bytes,
            None,
            None,
            Some(&digest),
            false,
        );

        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_ENCODING),
            None,
            "an uncoded upstream must be served with NO Content-Encoding; \
             manufacturing one mislabels every plain wheel"
        );
    }

    /// End-to-end on the bytes, not just the header: decode the served body
    /// with the coding the response declares and compare to the plaintext.
    ///
    /// This is the assertion a client actually makes. A response whose declared
    /// coding does not match its bytes fails here even if the header is
    /// non-empty, which is exactly what a hardcoded `"gzip"` produces.
    #[tokio::test]
    async fn test_build_scanned_file_response_body_decodes_under_declared_coding() {
        use crate::api::handlers::test_db_helpers as tdh;
        let (plain, coded) = tdh::coded_fixture("deflate", b"decodable-wheel-");
        let resp = build_scanned_file_response(
            "pkg-1.0-py3-none-any.whl",
            Bytes::from(coded.clone()),
            None,
            Some("deflate"),
            None,
            true,
        );

        let declared = tdh::header_str(resp.headers(), CONTENT_ENCODING);
        assert_eq!(declared.as_deref(), Some("deflate"));

        let (status, body, _headers) = tdh::collect_response(resp).await;
        assert_eq!(status, StatusCode::OK);
        // The proxy must not decode on the client's behalf either: the wire
        // bytes are the coded ones.
        assert_eq!(body.as_ref(), coded.as_slice());
        assert_eq!(
            tdh::inflate_deflate(&body),
            plain,
            "body must decode under the coding the response declares"
        );
    }

    #[test]
    fn test_is_over_cap_error_classification() {
        // The real over-cap shape emitted by the capped proxy fetch.
        let over_cap = AppError::BadGateway(
            "Upstream metadata response exceeded the 209715200-byte limit".to_string(),
        );
        assert!(is_over_cap_error(&over_cap));

        // Any other BadGateway (upstream 5xx etc.) must be propagated as-is,
        // not treated as the over-cap inconclusive branch.
        let other_bad_gateway = AppError::BadGateway("upstream returned 500".to_string());
        assert!(!is_over_cap_error(&other_bad_gateway));

        // Non-BadGateway errors (a 404 stays a 404).
        let not_found = AppError::NotFound("no such file".to_string());
        assert!(!is_over_cap_error(&not_found));
    }

    // -----------------------------------------------------------------------
    // #2954 inline proxy scan-and-block: DB-backed serve paths.
    //
    // These drive `serve_file` end-to-end into `serve_scanned_pypi_file` with
    // a wiremock upstream, a real proxy service, and a scan_configs row with
    // scan_on_proxy enabled. The state carries NO scanner service, so a
    // first-pull scan is inconclusive — exactly the branch whose fail-closed
    // handling (423, never a 200 of unscanned bytes) is the point of the fix.
    // Cached-verdict paths are seeded through ProxyScanService::record_verdict
    // so the digest-keyed block/serve fast path is covered against a real DB.
    //
    // Skip cleanly when DATABASE_URL is unset.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers::enable_proxy_scan;

    /// Mount a PEP 503 index page (with no matching href, so the fetch target
    /// falls back to the conventional simple/ path) plus the wheel bytes.
    async fn mount_scan_upstream(
        upstream: &wiremock::MockServer,
        project: &str,
        filename: &str,
        wheel: &'static [u8],
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html><body></body></html>")
                    .insert_header("Content-Type", "text/html"),
            )
            .mount(upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/simple/{project}/{filename}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(wheel)
                    .insert_header("Content-Type", "application/zip"),
            )
            .mount(upstream)
            .await;
    }

    // ── #3023: the inline scan gate on the VIRTUAL pypi serve path ─────────
    //
    // A wheel whose digest carries a vulnerable verdict must be blocked when
    // pulled through a Virtual repo that aggregates the Remote member, not just
    // through the direct Remote path.
    #[tokio::test]
    async fn test_virtual_serve_file_blocks_vulnerable_member_wheel() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "vulnpkg";
        let filename = "vulnpkg-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 vulnpkg-wheel-3023";
        let digest = sha256_hex(&Bytes::from_static(b"PK\x03\x04 vulnpkg-wheel-3023"));

        let upstream = MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;

        let (member_id, _member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        // Scanning enabled on the MEMBER; the verdict mimics a prior remote scan.
        enable_proxy_scan(&fx.pool, member_id, "fail_closed").await;
        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "vulnerable",
                2,
                1,
                1,
                0,
                0,
                Some("critical"),
                Some("grype-1.0.0-test"),
                Some(member_id),
            )
            .await
            .expect("seed vulnerable verdict");

        let virtual_info = fx.repo_info("virtual", None);
        let result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .ok();
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "a vulnerable wheel through a virtual repo must be blocked (#3023), got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "vulnerable-via-virtual pypi serve must be 403"
            ),
        }
    }

    /// Buffer a `serve_file` outcome (Ok or Err) into (status, body) for the
    /// #3220 gate assertions below.
    async fn collect_serve_3220(r: Result<Response, Response>) -> (StatusCode, Bytes) {
        let resp = match r {
            Ok(resp) => resp,
            Err(resp) => resp,
        };
        let (status, body, _) = crate::api::handlers::test_db_helpers::collect_response(resp).await;
        (status, body)
    }

    /// #3220: `serve_file`'s virtual-member loop must apply the resolving
    /// member's DOWNLOAD gate (quarantine + scan policy) to the bytes it serves
    /// from that member's local row, and must fail closed when it blocks.
    ///
    /// Two independent defects met on this path. `local_fetch_or_redirect_by_suffix`
    /// applied only the raw quarantine predicate, so `block_unscanned` /
    /// `block_on_fail` / `max_severity` were never consulted. And the loop's
    /// `Err(e) => debug!(...)` arm treated any failure as "this member does not
    /// have it", so even once the gate existed its 403 would have fallen through
    /// to the member's own upstream — which happily returns the wheel.
    ///
    /// The upstream mock therefore serves DIFFERENT bytes from the cached copy:
    /// a fall-through is observable as a 200 carrying the upstream bytes, not
    /// merely as "not a 403". The positive control (no policy -> 200 with the
    /// CACHED bytes) is in the same fixture, so a change that blocks everything,
    /// or that stops resolving the member at all, fails this test.
    #[tokio::test]
    async fn test_virtual_serve_file_applies_member_download_gate_3220() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "gatepkg";
        let version = "1.0.0";
        let filename = "gatepkg-1.0.0-py3-none-any.whl";
        // Distinct from `seed_member_wheel`'s cached payload on purpose.
        let upstream_wheel: &[u8] = b"PK\x03\x04 gatepkg-from-UPSTREAM-not-cache";
        let cached_wheel: &[u8] = b"PK\x03\x04 virtual-member-wheel";

        let upstream = MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, upstream_wheel).await;

        let (member_id, member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        seed_member_wheel(
            &state,
            &fx.pool,
            fx.user_id,
            member_id,
            &member_key,
            &member_dir,
            &upstream.uri(),
            project,
            version,
            filename,
        )
        .await;

        let virtual_info = fx.repo_info("virtual", None);
        let project_name = proj(project);
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let serve = || {
            super::serve_file(
                &state,
                &virtual_info,
                &fx.repo_key,
                &project_name,
                filename,
                None,
                &ctx,
            )
        };

        // POSITIVE CONTROL: no policy -> the cached member copy is served.
        let (before_status, before_body) = collect_serve_3220(serve().await).await;

        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("gate-3220-pypi-{member_id}"))
        .bind(member_id)
        .execute(&fx.pool)
        .await
        .expect("insert block_unscanned policy");

        let (blocked_status, blocked_body) = collect_serve_3220(serve().await).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(member_id)
            .execute(&fx.pool)
            .await;

        // NEGATIVE CONTROL: policy removed -> serving resumes.
        let (after_status, after_body) = collect_serve_3220(serve().await).await;

        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            before_status,
            StatusCode::OK,
            "positive control: with no scan policy the virtual member must serve"
        );
        assert_eq!(
            &before_body[..],
            cached_wheel,
            "positive control: the member's cached copy is what serves"
        );
        assert_eq!(
            blocked_status,
            StatusCode::FORBIDDEN,
            "#3220: an unscanned wheel under block_unscanned must be refused with 403 \
             through the virtual repo, got {blocked_status}"
        );
        assert_ne!(
            &blocked_body[..],
            cached_wheel,
            "#3220: the blocked wheel's bytes must not be served"
        );
        assert_ne!(
            &blocked_body[..],
            upstream_wheel,
            "#3220: the block must not fall through to the member's upstream — that is the \
             silent fallback that turns a policy block into a 200"
        );
        assert_eq!(
            after_status,
            StatusCode::OK,
            "negative control: removing the policy must restore the download"
        );
        assert_eq!(&after_body[..], cached_wheel);
    }

    // -----------------------------------------------------------------------
    // #3404: the ownership guard must gate a suppressed Remote member's LOCAL
    // `artifacts` row, not only its upstream fetch.
    // -----------------------------------------------------------------------

    /// Seed one distribution on `member_id`: the payload bytes into storage and
    /// a matching `artifacts` row.
    ///
    /// `dir_prefix` controls the row's `path`. `Some(p)` stores it under
    /// `{p}/{filename}`; `None` stores it at its BARE filename — the shape
    /// generic uploads and imports produce, and the one #3405's `.metadata`
    /// lookup could not resolve.
    #[allow(clippy::too_many_arguments)]
    async fn seed_distribution(
        state: &crate::api::SharedState,
        pool: &sqlx::PgPool,
        user_id: uuid::Uuid,
        member_info: &proxy_helpers::RepoInfo,
        project: &str,
        version: &str,
        filename: &str,
        dir_prefix: Option<&str>,
        bytes: &[u8],
    ) {
        let storage_key = format!("pypi/{}/{}/{}", project, version, filename);
        let artifact_path = match dir_prefix {
            Some(prefix) => format!("{prefix}/{filename}"),
            None => filename.to_string(),
        };
        proxy_helpers::put_artifact_bytes(
            state,
            member_info,
            &storage_key,
            Bytes::copy_from_slice(bytes),
        )
        .await
        .expect("seed payload");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(member_info.id)
        .bind(&artifact_path)
        .bind(project)
        .bind(version)
        .bind(bytes.len() as i64)
        .bind(format!("sha-{filename}"))
        .bind("application/zip")
        .bind(&storage_key)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed artifact row");
    }

    /// #3404: a SUPPRESSED Remote member's locally-cached `artifacts` row must
    /// not be served through the virtual repo.
    ///
    /// The virtual member loop tries local storage FIRST for every member,
    /// Remote included, because Remote-typed repos legitimately carry
    /// `artifacts` rows. The suppression decision was computed ~50 lines below
    /// that local-first serve and consulted only by the upstream branch, so a
    /// Case-B distribution the dependency-confusion guard hides from the simple
    /// index stayed downloadable from any member that had ever cached it — the
    /// exact shape a stale `uv.lock` or hashed `requirements.txt` keeps
    /// requesting long after the operator re-ranked the members.
    ///
    /// FAILS ON MAIN: the guarded request returns 200 with the cached bytes.
    ///
    /// The upstream mock serves nothing, so a 200 can ONLY have come from the
    /// cached row — this cannot pass by accidentally proxying. The positive
    /// control (before a local member owns the name) runs in the same fixture,
    /// so a change that 404s everything fails too. The PEP 658 sidecar is
    /// asserted alongside: fixing only the wheel would leave `.metadata`
    /// exposing precisely the suppressed distribution.
    #[tokio::test]
    async fn test_virtual_serve_file_gates_suppressed_member_cached_row_3404() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "confpkg";
        // Case B: a version ONLY the remote has for a locally-owned name.
        let remote_only = "confpkg-9.9.9-py3-none-any.whl";
        let remote_wheel = wheel_with_metadata(
            "confpkg-9.9.9",
            b"Metadata-Version: 2.1\nName: confpkg\nVersion: 9.9.9\n",
        );

        // No mounts: the upstream has nothing, so any 200 came from the row.
        let upstream = MockServer::start().await;
        let (member_id, member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        let member_info = tdh::make_repo_info(
            member_id,
            &member_key,
            &member_dir,
            "remote",
            Some(&upstream.uri()),
        );
        seed_distribution(
            &state,
            &fx.pool,
            fx.user_id,
            &member_info,
            project,
            "9.9.9",
            remote_only,
            Some("simple/confpkg"),
            &remote_wheel,
        )
        .await;

        let virtual_info = fx.repo_info("virtual", None);
        let project_name = proj(project);
        let ctx = crate::api::middleware::download_telemetry::DownloadContext::default();
        let serve = || {
            super::serve_file(
                &state,
                &virtual_info,
                &fx.repo_key,
                &project_name,
                remote_only,
                None,
                &ctx,
            )
        };
        let serve_meta = || {
            super::serve_virtual_metadata(
                &state,
                None,
                &virtual_info,
                &project_name,
                Some("9.9.9"),
                remote_only,
            )
        };

        // POSITIVE CONTROL: no local member owns the name yet, so nothing is
        // suppressed and the member's cached row serves.
        let (before_status, before_body) = collect_serve_3220(serve().await).await;
        let (before_meta_status, _) = collect_serve_3220(serve_meta().await).await;

        // Attach a PUBLIC Local member at priority 0 that OWNS `confpkg`, so it
        // strictly outranks the Remote member (priority 1) and the guard
        // engages for every distribution outside its Case-A profile.
        let (local_id, local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await
            .expect("publish local member");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(fx.repo_id)
        .bind(local_id)
        .execute(&fx.pool)
        .await
        .expect("attach local member");
        let local_info = tdh::make_repo_info(local_id, &local_key, &local_dir, "local", None);
        seed_distribution(
            &state,
            &fx.pool,
            fx.user_id,
            &local_info,
            project,
            "1.0.0",
            "confpkg-1.0.0-py3-none-any.whl",
            Some("simple/confpkg"),
            &wheel_with_metadata(
                "confpkg-1.0.0",
                b"Metadata-Version: 2.1\nName: confpkg\nVersion: 1.0.0\n",
            ),
        )
        .await;

        let (guarded_status, guarded_body) = collect_serve_3220(serve().await).await;
        let (guarded_meta_status, guarded_meta_body) = collect_serve_3220(serve_meta().await).await;

        // The owner's own distribution must still resolve — the reordered check
        // must not 404 the member that does the owning.
        let owned_result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &project_name,
            "confpkg-1.0.0-py3-none-any.whl",
            None,
            &ctx,
        )
        .await;
        let (owned_status, _) = collect_serve_3220(owned_result).await;

        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        cleanup_virtual_member(&fx.pool, local_id, &local_dir).await;
        fx.teardown().await;

        assert_eq!(
            before_status,
            StatusCode::OK,
            "positive control: with no local owner the cached member row must serve"
        );
        assert_eq!(
            &before_body[..],
            &remote_wheel[..],
            "positive control: the cached row's bytes are what serve"
        );
        assert_eq!(
            before_meta_status,
            StatusCode::OK,
            "positive control: the PEP 658 sidecar resolves from the same row"
        );

        assert_eq!(
            guarded_status,
            StatusCode::NOT_FOUND,
            "#3404: a Case-B distribution the simple index refuses to advertise must \
             404 on download too, even when the suppressed member has it cached; got \
             {guarded_status}"
        );
        assert_ne!(
            &guarded_body[..],
            &remote_wheel[..],
            "#3404: the suppressed member's cached bytes must not be served"
        );
        assert_eq!(
            guarded_meta_status,
            StatusCode::NOT_FOUND,
            "#3404: the PEP 658 sidecar must make the same decision as the wheel, or the \
             suppressed distribution is still described through the virtual repo"
        );
        assert!(
            !String::from_utf8_lossy(&guarded_meta_body).contains("9.9.9"),
            "#3404: the suppressed distribution's METADATA must not leak"
        );
        assert_eq!(
            owned_status,
            StatusCode::OK,
            "negative control: the owning local member's own distribution must still serve"
        );
    }

    /// #3405: the PEP 658 `.metadata` resource must resolve an artifact stored
    /// at its BARE path, exactly as the distribution download does.
    ///
    /// `serve_metadata` open-coded `path LIKE '%/' || $2`, which requires a `/`
    /// before the filename, while the download path resolves through
    /// `resolve_local_artifact_by_suffix` and falls back to an exact
    /// `path = $2`. A bare-path artifact therefore downloaded fine and 404'd on
    /// its sidecar — and since the simple index advertises `core-metadata:
    /// true` for every `.whl`, pip and uv treat that as a hard install failure
    /// rather than falling back to the wheel.
    ///
    /// FAILS ON MAIN on the bare-path case. The directory-path case is the
    /// control that proves the shared resolver did not regress the shape every
    /// existing fixture uses.
    #[tokio::test]
    async fn test_serve_metadata_resolves_bare_path_artifact_3405() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let repo_info = fx.repo_info("local", None);
        let location = repo_info.storage_location();

        // Same project, two storage shapes: one bare, one directory-prefixed.
        let bare = "barepkg-1.0.0-py3-none-any.whl";
        let nested = "barepkg-2.0.0-py3-none-any.whl";
        for (filename, version, prefix) in [
            (bare, "1.0.0", None),
            (nested, "2.0.0", Some("simple/barepkg")),
        ] {
            seed_distribution(
                &state,
                &fx.pool,
                fx.user_id,
                &repo_info,
                "barepkg",
                version,
                filename,
                prefix,
                &wheel_with_metadata(
                    &format!("barepkg-{version}"),
                    format!("Metadata-Version: 2.1\nName: barepkg\nVersion: {version}\n")
                        .as_bytes(),
                ),
            )
            .await;
        }

        let bare_meta = super::serve_metadata(&state, &fx.pool, &repo_info, bare).await;
        let nested_meta = super::serve_metadata(&state, &fx.pool, &repo_info, nested).await;
        // The wheel itself resolved fine before this fix; assert the pair stays
        // consistent rather than trusting that separately.
        let bare_wheel = proxy_helpers::local_fetch_or_redirect_by_suffix(
            &fx.pool,
            &state,
            fx.repo_id,
            &location,
            bare,
            &Default::default(),
        )
        .await;

        let (bare_status, bare_body) = collect_serve_3220(bare_meta).await;
        let (nested_status, nested_body) = collect_serve_3220(nested_meta).await;
        let (bare_wheel_status, _) = collect_serve_3220(bare_wheel).await;

        fx.teardown().await;

        assert_eq!(
            bare_wheel_status,
            StatusCode::OK,
            "premise: a bare-path artifact's DISTRIBUTION already downloads"
        );
        assert_eq!(
            bare_status,
            StatusCode::OK,
            "#3405: the index advertises core-metadata for this wheel and the wheel \
             downloads, so its .metadata must not 404; got {bare_status}"
        );
        assert!(
            String::from_utf8_lossy(&bare_body).contains("Version: 1.0.0"),
            "#3405: the sidecar must carry the bare-path distribution's own METADATA"
        );
        assert_eq!(
            nested_status,
            StatusCode::OK,
            "control: the directory-prefixed shape every existing fixture uses must \
             keep resolving"
        );
        assert!(String::from_utf8_lossy(&nested_body).contains("Version: 2.0.0"));
    }

    /// Verified-bug regression for the PyPI half of #3452, and the guard the
    /// rest of the PR's tests do NOT reach.
    ///
    /// `serve_file` and `serve_virtual_metadata` walk their members by hand
    /// rather than going through the `proxy_helpers` primitives, so the shared
    /// `no_accessible_members_response` collapse in those primitives does not
    /// apply to them. Both fetch members, filter with
    /// `authorize_virtual_members`, and — before this PR — carried on with an
    /// EMPTY set, ultimately answering a different body from the one the
    /// genuinely-empty virtual gets a few lines above. Measured on a build of
    /// the parent commit, one caller holding `read` on the virtual PARENT only:
    ///
    /// ```text
    /// /pypi/{virtual-with-private-member}/simple/demo/demo-1.0.tar.gz  404 "Artifact not found in any member repository"
    /// /pypi/{virtual-with-no-members}/simple/demo/demo-1.0.tar.gz      404 "Virtual repository has no members"
    /// ```
    ///
    /// — a live existence oracle over the private repositories a virtual
    /// aggregates, on the byte-serving route and on the PEP 658 metadata route.
    ///
    /// This test exists because reverting ONLY those two guards left all five
    /// of the PR's other tests green: `proxy_helpers`' test drives the shared
    /// primitives, which PyPI's two hand-rolled walks bypass, and coverage
    /// measures execution rather than assertion, so 94% new-code coverage did
    /// not contradict it either. Without this, a later refactor can delete the
    /// guards and re-open the oracle with CI green.
    ///
    /// Both routes are asserted, and both against the same principal, so a fix
    /// applied to one walk and not its sibling fails here.
    #[tokio::test]
    async fn test_3452_pypi_virtual_filtered_members_answer_the_empty_virtual_body() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // A virtual with a PRIVATE member, and a virtual with no members at
        // all. Both real rows: the member filter is evaluated in SQL.
        let (parent_id, parent_key, parent_dir) = tdh::create_repo(&pool, "virtual", "pypi").await;
        let (empty_id, empty_key, empty_dir) = tdh::create_repo(&pool, "virtual", "pypi").await;
        let (member_id, _mk, member_dir) = tdh::create_repo(&pool, "local", "pypi").await;
        tdh::link_virtual_member(&pool, parent_id, member_id, 1).await;

        // The reported principal: granted on the PARENT, nothing on the member.
        let (user_id, uname) = tdh::create_user(&pool).await;
        tdh::grant_repo_actions(&pool, parent_id, user_id, &["read"]).await;
        tdh::grant_repo_actions(&pool, empty_id, user_id, &["read"]).await;
        let auth = tdh::make_auth(user_id, &uname);

        let state = tdh::build_state(pool.clone(), &parent_dir.to_string_lossy());
        let parent = tdh::make_repo_info(parent_id, &parent_key, &parent_dir, "virtual", None);
        let empty = tdh::make_repo_info(empty_id, &empty_key, &empty_dir, "virtual", None);

        async fn describe(r: Result<Response, Response>) -> (StatusCode, Option<String>, String) {
            let resp = match r {
                Ok(resp) => resp,
                Err(resp) => resp,
            };
            let status = resp.status();
            let ct = resp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .expect("read body");
            (status, ct, String::from_utf8_lossy(&body).into_owned())
        }

        let project = proj("demo");
        let sdist = "demo-1.0.tar.gz";

        // Route 1: the byte-serving download walk.
        let filtered_file = describe(
            super::serve_file(
                &state,
                &parent,
                &parent_key,
                &project,
                sdist,
                Some(&auth),
                &Default::default(),
            )
            .await,
        )
        .await;
        let empty_file = describe(
            super::serve_file(
                &state,
                &empty,
                &empty_key,
                &project,
                sdist,
                Some(&auth),
                &Default::default(),
            )
            .await,
        )
        .await;

        // Route 2: the PEP 658 `.metadata` walk.
        let filtered_meta = describe(
            super::serve_virtual_metadata(&state, Some(&auth), &parent, &project, None, sdist)
                .await,
        )
        .await;
        let empty_meta = describe(
            super::serve_virtual_metadata(&state, Some(&auth), &empty, &project, None, sdist).await,
        )
        .await;

        // POSITIVE CONTROL, before cleanup: a caller who MAY read the member
        // must get PAST the member gate on both routes, so an implementation
        // that refused everyone cannot satisfy the equalities below.
        let (allowed_id, allowed_name) = tdh::create_user(&pool).await;
        tdh::grant_repo_actions(&pool, parent_id, allowed_id, &["read"]).await;
        tdh::grant_repo_actions(&pool, member_id, allowed_id, &["read"]).await;
        let allowed_auth = tdh::make_auth(allowed_id, &allowed_name);
        let walked_file = describe(
            super::serve_file(
                &state,
                &parent,
                &parent_key,
                &project,
                sdist,
                Some(&allowed_auth),
                &Default::default(),
            )
            .await,
        )
        .await;
        let walked_meta = describe(
            super::serve_virtual_metadata(
                &state,
                Some(&allowed_auth),
                &parent,
                &project,
                None,
                sdist,
            )
            .await,
        )
        .await;

        for (id, dir) in [
            (member_id, &member_dir),
            (parent_id, &parent_dir),
            (empty_id, &empty_dir),
        ] {
            tdh::cleanup_member_repo(&pool, id, dir).await;
        }
        for uid in [user_id, allowed_id] {
            tdh::cleanup_user(&pool, uid).await;
        }

        let expected = (
            StatusCode::NOT_FOUND,
            Some("application/json".to_string()),
            format!(
                "{{\"code\":\"NOT_FOUND\",\"message\":\"{}\"}}",
                proxy_helpers::NO_ACCESSIBLE_MEMBERS_MSG
            ),
        );
        assert_eq!(
            empty_file, expected,
            "a pypi virtual with no member rows must answer the shared \
             no-accessible-members body on the download route"
        );
        assert_eq!(
            filtered_file, empty_file,
            "#3452: `serve_file` walks its members by hand, so the collapse in the shared \
             proxy_helpers primitives does not cover it. A caller granted on the PARENT only \
             must not be able to tell that this virtual aggregates a member it may not see"
        );
        assert_eq!(
            empty_meta, expected,
            "the PEP 658 metadata route must answer the same body as the download route"
        );
        assert_eq!(
            filtered_meta, empty_meta,
            "#3452: `serve_virtual_metadata` is the sibling hand-rolled walk; fixing one route \
             and not the other leaves the oracle open on `.metadata` URLs"
        );
        assert_ne!(
            walked_file.2, empty_file.2,
            "POSITIVE CONTROL (download): a caller who MAY read the member must get PAST the \
             member gate. If this equals the refusal body the walk refuses everyone and every \
             equality above is vacuous"
        );
        assert_ne!(
            walked_meta.2, empty_meta.2,
            "POSITIVE CONTROL (metadata): as above, for the sibling route"
        );
    }

    /// Clean via virtual -> 200 (no over-block).
    #[tokio::test]
    async fn test_virtual_serve_file_serves_clean_member_wheel() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;
        use wiremock::MockServer;

        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let project = "cleanpkg";
        let filename = "cleanpkg-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 cleanpkg-wheel-3023";
        let digest = sha256_hex(&Bytes::from_static(b"PK\x03\x04 cleanpkg-wheel-3023"));

        let upstream = MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;

        let (member_id, _member_key, member_dir, state) =
            setup_virtual_pypi_member(&fx, false, &upstream.uri()).await;
        // fail_open: a fresh cached CLEAN verdict serves without a live scanner
        // (the #2976 unknown-live-version re-scan tightening is fail_closed-only).
        enable_proxy_scan(&fx.pool, member_id, "fail_open").await;
        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-1.0.0-test"),
                Some(member_id),
            )
            .await
            .expect("seed clean verdict");

        let virtual_info = fx.repo_info("virtual", None);
        let result = super::serve_file(
            &state,
            &virtual_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;
        let status = result
            .as_ref()
            .map(|r| r.status())
            .unwrap_or_else(|r| r.status());

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .ok();
        cleanup_virtual_member(&fx.pool, member_id, &member_dir).await;
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a clean wheel through a virtual repo must still serve 200 (no over-block)"
        );
    }

    #[tokio::test]
    async fn test_serve_file_proxy_scan_fail_closed_inconclusive_is_423() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "sealed";
        let filename = "sealed-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 sealed-wheel-2954-fail-closed";

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        // No scanner service on the state: the inline scan is inconclusive.
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "fail-closed + inconclusive scan must never serve bytes, got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::LOCKED,
                "fail-closed inconclusive must be 423 Locked"
            ),
        }
    }

    #[tokio::test]
    async fn test_serve_file_proxy_scan_fail_open_serves_pending() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "openpkg";
        let filename = "openpkg-2.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 open-wheel-2954-fail-open";

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        // Default action (fail_open): first pull serves LOUDLY with pending.
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_open").await;

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        let resp = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                fx.teardown().await;
                panic!("fail-open first pull must serve, got {status}");
            }
        };
        let status = resp.status();
        let scan_header = resp
            .headers()
            .get("X-AK-Scan")
            .map(|v| v.to_str().unwrap().to_string());
        let digest_header = resp
            .headers()
            .get("X-PyPI-File-SHA256")
            .map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("body");
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            scan_header.as_deref(),
            Some("pending"),
            "a served-before-verdict byte must be observable (X-AK-Scan: pending)"
        );
        assert_eq!(
            digest_header.as_deref(),
            Some(sha256_hex(&Bytes::from_static(b"PK\x03\x04 open-wheel-2954-fail-open")).as_str())
        );
        assert_eq!(&body[..], wheel, "served bytes must equal upstream bytes");
    }

    #[tokio::test]
    async fn test_serve_file_proxy_scan_blocks_cached_vulnerable_digest() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "poisoned";
        let filename = "poisoned-0.1.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 poisoned-wheel-2954-vulnerable";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 poisoned-wheel-2954-vulnerable",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        // Seed a fresh vulnerable verdict for this digest through the real
        // service so record_verdict + lookup_verdict are covered end-to-end.
        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "vulnerable",
                3,
                1,
                1,
                1,
                0,
                Some("critical"),
                Some("grype-0.99.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed vulnerable verdict");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        // proxy_scan_results outlives repo cleanup (repository_id is SET
        // NULL on delete): remove the digest row explicitly.
        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");
        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "a fresh cached vulnerable verdict must block the pull, got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "cached vulnerable digest must be a 403 scan_blocked (not 423: \
                 the verdict is conclusive)"
            ),
        }
    }

    /// The cached-`clean` fast path serves 200 `X-AK-Scan: clean` (#2954) —
    /// exercised here on a FAIL-OPEN repo with no scanner service, where the
    /// header is the discriminator: without the cached verdict this pull would
    /// still be a 200, but marked `pending`.
    ///
    /// This test used to assert the same 200 under FAIL-CLOSED. That passed
    /// only because a state with no scanner service reports an unknown live
    /// scanner version, which the freshness check treated as "not provably
    /// stale" and served — i.e. it encoded the #2976 fail-open hole: a node
    /// with no working CVE engine served cached-clean bytes through a
    /// fail-closed policy that 423s a fresh pull. The fail-closed side of that
    /// pair now lives in
    /// `test_serve_file_proxy_scan_unknown_live_version_rescans_under_fail_closed`.
    #[tokio::test]
    async fn test_serve_file_proxy_scan_serves_cached_clean_digest() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "verified";
        let filename = "verified-3.2.1-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 verified-wheel-2954-clean";
        let digest = sha256_hex(&Bytes::from_static(b"PK\x03\x04 verified-wheel-2954-clean"));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_open").await;

        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.99.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed clean verdict");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state = tdh::build_state_with_proxy(fx.pool.clone(), storage_path.as_str(), proxy);
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");

        let resp = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                fx.teardown().await;
                panic!("fresh clean verdict must serve from the cache, got {status}");
            }
        };
        let status = resp.status();
        let scan_header = resp
            .headers()
            .get("X-AK-Scan")
            .map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("body");
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            scan_header.as_deref(),
            Some("clean"),
            "a verdict-backed serve must be marked clean, not pending"
        );
        assert_eq!(&body[..], wheel);
    }

    // -----------------------------------------------------------------------
    // #2976: cached-verdict freshness vs the LIVE CVE-scanner version.
    //
    // These drive `serve_file` end-to-end with a scanner service on the state
    // whose CVE-authoritative mock reports an injected "live" version — the
    // `current_version` side of `verdict_is_fresh`. A cached verdict recorded
    // by an OLDER version must be treated stale and re-scanned; the SAME
    // version must keep using the cache (no needless re-scan).
    // -----------------------------------------------------------------------

    // The mock CVE engine (`VersionedCveScanner`/`MockCveRescan`) and the
    // state builder moved to shared test helpers so the npm inline-scan tests
    // (#3003) drive the identical mock through the identical wiring.
    use crate::services::scanner_service::test_helpers::{MockCveRescan, VersionedCveScanner};

    /// Build a state whose scanner service holds exactly the given mock CVE
    /// engine, wired over the fixture's storage + a real proxy service.
    fn scan_state_with_live_scanner(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        storage_path: &str,
        scanner: VersionedCveScanner,
    ) -> crate::api::SharedState {
        crate::api::handlers::test_db_helpers::build_scan_state_with_leaf_scanners(
            fx,
            storage_path,
            vec![std::sync::Arc::new(scanner)],
        )
    }

    /// #2976 discriminator: a cached `clean` verdict recorded by an OLDER
    /// scanner/CVE-DB version must NOT be reused once the live CVE engine
    /// reports a newer version. The serve path re-scans, and the re-scan
    /// (which now knows the new CVE) blocks with 403. Before the fix the call
    /// site passed `current_version=None`, so `verdict_is_fresh` never saw
    /// the bump and this pull served 200 stale-clean from cache for the full
    /// 30-day TTL.
    #[tokio::test]
    async fn test_serve_file_proxy_scan_rescans_when_scanner_version_advances() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "staleclean";
        let filename = "staleclean-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 staleclean-wheel-2976-bumped";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 staleclean-wheel-2976-bumped",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        // Cached CLEAN verdict recorded at stored version V...
        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.83.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed stale clean verdict");

        // ...while the LIVE engine is at V+1 and now flags the bytes.
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let state = scan_state_with_live_scanner(
            &fx,
            &storage_path,
            VersionedCveScanner {
                live_version: Some("grype-0.84.0-test"),
                rescan: MockCveRescan::Vulnerable,
            },
        );
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");
        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "clean verdict from an older scanner version must be re-scanned \
                 (and blocked), not served from cache; got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "re-scan against the bumped CVE-DB found the CVE -> 403"
            ),
        }
    }

    /// Same-version control: when the live CVE engine still reports the SAME
    /// version that produced the cached `clean` verdict, the cache is reused —
    /// the mock would 403 if a re-scan ran, so a 200 `X-AK-Scan: clean` proves
    /// there was no needless re-scan (no perf regression from #2976).
    #[tokio::test]
    async fn test_serve_file_proxy_scan_reuses_cached_verdict_same_version() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "sameversion";
        let filename = "sameversion-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 sameversion-wheel-2976-cached";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 sameversion-wheel-2976-cached",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.84.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed clean verdict");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let state = scan_state_with_live_scanner(
            &fx,
            &storage_path,
            VersionedCveScanner {
                live_version: Some("grype-0.84.0-test"),
                rescan: MockCveRescan::Vulnerable, // would 403 if re-scanned
            },
        );
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");

        let resp = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                fx.teardown().await;
                panic!("same-version clean verdict must serve from cache, got {status}");
            }
        };
        let status = resp.status();
        let scan_header = resp
            .headers()
            .get("X-AK-Scan")
            .map(|v| v.to_str().unwrap().to_string());
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            scan_header.as_deref(),
            Some("clean"),
            "cache hit must serve clean (a re-scan would have blocked)"
        );
    }

    /// Fail-closed alignment after a version bump: when the invalidating
    /// re-scan is INCONCLUSIVE (scanner error), the pull must 423, never a
    /// 200 of the stale-clean cache (#2976 + #2954 fail-closed contract).
    #[tokio::test]
    async fn test_serve_file_proxy_scan_version_bump_inconclusive_locks() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "bumplocked";
        let filename = "bumplocked-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 bumplocked-wheel-2976-locked";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 bumplocked-wheel-2976-locked",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.83.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed stale clean verdict");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let state = scan_state_with_live_scanner(
            &fx,
            &storage_path,
            VersionedCveScanner {
                live_version: Some("grype-0.84.0-test"),
                rescan: MockCveRescan::Error,
            },
        );
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");
        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "inconclusive re-scan after a version bump must 423 under \
                 fail-closed, not serve stale-clean; got {}",
                r.status()
            ),
            Err(resp) => assert_eq!(resp.status(), StatusCode::LOCKED),
        }
    }

    /// THE fail-open hole in the first cut of #2976: when the live version
    /// probe returns None (engine mid-upgrade / absent / probe timed out),
    /// `verdict_is_fresh`'s unknown-version arm returns true, so a cached
    /// `clean` verdict short-circuited the serve path — on a FAIL-CLOSED repo,
    /// serving bytes nothing on the node could vouch for, while a fresh pull
    /// on the same node would 423. The freshness fast path runs before the
    /// inline scan, so it must not fail open here: an unprovable clean verdict
    /// is stale, the pull re-scans, and the re-scan (vulnerable) blocks 403.
    #[tokio::test]
    async fn test_serve_file_proxy_scan_unknown_live_version_rescans_under_fail_closed() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "probenone";
        let filename = "probenone-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 probenone-wheel-2976-failclosed";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 probenone-wheel-2976-failclosed",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_closed").await;

        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.83.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed clean verdict");

        // Live engine present but its version probe FAILS (None).
        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let state = scan_state_with_live_scanner(
            &fx,
            &storage_path,
            VersionedCveScanner {
                live_version: None,
                rescan: MockCveRescan::Vulnerable,
            },
        );
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");
        fx.teardown().await;

        match result {
            Ok(r) => panic!(
                "an UNKNOWN live scanner version must not let a cached clean \
                 verdict short-circuit the fail-closed gate; got {} (expected a \
                 re-scan -> 403)",
                r.status()
            ),
            Err(resp) => assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "re-scan found the CVE -> 403 (a 200 here is the fail-open hole)"
            ),
        }
    }

    /// Availability control for the tightening above: `fail_open` keeps the
    /// TTL-only fallback on an unknown live version. A cached clean verdict
    /// still serves 200 there — the fail-open re-scan branch would serve
    /// anyway (X-AK-Scan: pending), so nothing is gained by re-scanning and
    /// the opt-in latency-first posture is preserved.
    #[tokio::test]
    async fn test_serve_file_proxy_scan_unknown_live_version_serves_under_fail_open() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::proxy_scan_service::ProxyScanService;

        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };
        let project = "probenoneopen";
        let filename = "probenoneopen-1.0.0-py3-none-any.whl";
        let wheel: &[u8] = b"PK\x03\x04 probenoneopen-wheel-2976-failopen";
        let digest = sha256_hex(&Bytes::from_static(
            b"PK\x03\x04 probenoneopen-wheel-2976-failopen",
        ));

        let upstream = wiremock::MockServer::start().await;
        mount_scan_upstream(&upstream, project, filename, wheel).await;
        enable_proxy_scan(&fx.pool, fx.repo_id, "fail_open").await;

        ProxyScanService::new(fx.pool.clone())
            .record_verdict(
                &digest,
                "grype",
                "clean",
                0,
                0,
                0,
                0,
                0,
                None,
                Some("grype-0.83.0-test"),
                Some(fx.repo_id),
            )
            .await
            .expect("seed clean verdict");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let state = scan_state_with_live_scanner(
            &fx,
            &storage_path,
            VersionedCveScanner {
                live_version: None,
                rescan: MockCveRescan::Vulnerable,
            },
        );
        let mut repo_info = fx.repo_info("remote", Some(&upstream.uri()));
        repo_info.format = "pypi".to_string();

        let result = super::serve_file(
            &state,
            &repo_info,
            &fx.repo_key,
            &proj(project),
            filename,
            None,
            &Default::default(),
        )
        .await;

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&fx.pool)
            .await
            .expect("cleanup proxy_scan_results");

        let resp = match result {
            Ok(r) => r,
            Err(r) => {
                let status = r.status();
                fx.teardown().await;
                panic!("fail-open must stay available on an unknown probe, got {status}");
            }
        };
        let status = resp.status();
        let scan_header = resp
            .headers()
            .get("X-AK-Scan")
            .map(|v| v.to_str().unwrap().to_string());
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            scan_header.as_deref(),
            Some("clean"),
            "fail-open keeps the cached-verdict fast path on an unknown probe"
        );
    }

    // Conformance corpus (pip harvest, MIT): a `<base href>` on an upstream
    // Simple index must be neutralized, or it re-anchors our root-relative
    // rewritten download URLs onto the upstream origin — a proxy bypass that
    // discloses the upstream host and breaks air-gapped installs. RED before
    // the BASE_TAG_RE strip, GREEN after; the GHSA-4cw7-mgqj-hgmg regeneration
    // made the strip moot (no upstream markup survives at all). Sibling of the
    // #2801 sniff fix.
    #[test]
    fn test_rewrite_upstream_urls_neutralizes_base_href() {
        let upstream = concat!(
            "<!DOCTYPE html><html><head>",
            "<base href=\"https://internal-mirror.example/simple/\">",
            "</head><body>",
            "<a href=\"foo-1.0.tar.gz#sha256=abc\">foo-1.0.tar.gz</a>",
            "</body></html>"
        );
        let out = super::rewrite_upstream_urls(upstream, "myrepo", "foo");
        assert!(
            !out.to_lowercase().contains("<base"),
            "<base> tag survived the rewrite: {out}"
        );
        assert!(
            !out.contains("internal-mirror.example"),
            "upstream host leaked through <base>: {out}"
        );
        assert!(
            out.contains("/pypi/myrepo/simple/foo/foo-1.0.tar.gz"),
            "anchor was not rewritten through the proxy: {out}"
        );
    }

    // Conformance corpus (#2801): sniff_simple_index must classify a proxied
    // body by content, never trusting a mislabeled upstream Content-Type. JSON
    // (leading {/[), HTML (anchor/doctype/root), else Binary -> 502.
    #[test]
    fn test_sniff_simple_index_classifies_by_content() {
        use super::{sniff_simple_index as sniff, SniffedSimpleIndex as S};
        assert_eq!(sniff(br#"{"meta":{"api-version":"1.1"}}"#), S::Json);
        assert_eq!(sniff(b"  \n\t[ ]"), S::Json, "leading whitespace then [");
        assert_eq!(sniff(b"\xEF\xBB\xBF{}"), S::Json, "UTF-8 BOM then {{");
        assert_eq!(sniff(b"<!DOCTYPE html><html></html>"), S::Html);
        assert_eq!(sniff(b"<html><body></body></html>"), S::Html);
        assert_eq!(sniff(b"<a href=\"x-1.0.whl\">x</a>"), S::Html);
        assert_eq!(sniff(b"PK\x03\x04 not an index",), S::Binary, "zip/binary");
        assert_eq!(sniff(b"plain text, no markers"), S::Binary);
        assert_eq!(sniff(b""), S::Binary, "empty body");
    }

    // Regression guard: the HTML rewriter rebuilds each download URL from the
    // FILENAME, so a relative upstream href can never survive (this is why the
    // earlier "relative-url leak" was a false alarm), and the #sha256 fragment
    // is preserved.
    #[test]
    fn test_rewrite_upstream_urls_is_relative_safe_and_keeps_fragment() {
        let html = concat!(
            "<a href=\"../../packages/ab/foo-1.0-py3-none-any.whl#sha256=dead\">w</a>",
            "<a href=\"foo-1.0.tar.gz\">s</a>"
        );
        let out = super::rewrite_upstream_urls(html, "r", "p");
        assert!(!out.contains("../../"), "relative path survived: {out}");
        assert!(
            out.contains("/pypi/r/simple/p/foo-1.0-py3-none-any.whl#sha256=dead"),
            "wheel url/fragment wrong: {out}"
        );
        assert!(
            out.contains("/pypi/r/simple/p/foo-1.0.tar.gz"),
            "sdist url wrong: {out}"
        );
    }

    // Regression guard: the JSON rewriter rebuilds files[].url from the filename
    // (relative-safe), returns None for non-PEP-691 bodies, and preserves the
    // other file fields (hashes).
    #[test]
    fn test_rewrite_upstream_simple_json_rebuilds_and_preserves() {
        let json = br#"{"meta":{"api-version":"1.1"},"name":"p","files":[
            {"filename":"foo-1.0-py3-none-any.whl","url":"../../x/foo-1.0-py3-none-any.whl",
             "hashes":{"sha256":"deadbeef"}}]}"#;
        let out = super::rewrite_upstream_simple_json(json, "r", "p").expect("valid PEP 691");
        assert!(!out.contains("../../"), "relative url survived: {out}");
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            doc["files"][0]["url"],
            "/pypi/r/simple/p/foo-1.0-py3-none-any.whl"
        );
        assert_eq!(doc["files"][0]["hashes"]["sha256"], "deadbeef");
        // Not a PEP 691 body (no files array) -> None so the caller falls back.
        assert!(super::rewrite_upstream_simple_json(b"<html></html>", "r", "p").is_none());
        assert!(super::rewrite_upstream_simple_json(br#"{"nope":1}"#, "r", "p").is_none());
    }

    // Binary-distribution spec: the wheel compatibility tag is the last three
    // '-'-fields of the stem (python-abi-platform), lowercased; non-wheels and
    // too-short names have no tag.
    #[test]
    fn test_wheel_compat_tag_extracts_last_three_fields_lowercased() {
        use super::wheel_compat_tag as tag;
        assert_eq!(
            tag("numpy-1.0.0-cp39-cp39-manylinux1_x86_64.whl").as_deref(),
            Some("cp39-cp39-manylinux1_x86_64")
        );
        assert_eq!(
            tag("foo-1.0-py3-none-any.whl").as_deref(),
            Some("py3-none-any")
        );
        // A build tag (6 fields) still yields the trailing python-abi-platform.
        assert_eq!(
            tag("foo-1.0-1-py3-none-any.whl").as_deref(),
            Some("py3-none-any")
        );
        // Case-insensitive (tags are lowercased).
        assert_eq!(
            tag("Foo-1.0-CP39-CP39-Win_AMD64.whl").as_deref(),
            Some("cp39-cp39-win_amd64")
        );
        // Non-wheel and malformed names have no platform tag.
        assert_eq!(tag("foo-1.0.tar.gz"), None);
        assert_eq!(tag("foo-1.0.whl"), None);
    }

    #[test]
    fn test_pypi_content_type_by_extension() {
        use super::pypi_content_type as ct;
        assert_eq!(ct("x-1.0-py3-none-any.whl"), "application/zip");
        assert_eq!(ct("x.zip"), "application/zip");
        assert_eq!(ct("x-1.0.tar.gz"), "application/gzip");
        assert_eq!(ct("x-1.0.tar.bz2"), "application/x-bzip2");
        assert_eq!(ct("x-1.0.exe"), "application/octet-stream");
    }

    #[test]
    fn test_html_escape_escapes_markup_and_quotes() {
        use super::html_escape as esc;
        assert_eq!(esc("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(esc("\"q\" 'a'"), "&quot;q&quot; &#39;a&#39;");
        assert_eq!(esc("plain"), "plain");
    }

    // version_from_pypi_filename: the version is the field after the name for a
    // wheel, and the final '-'-segment for an sdist (project names may contain
    // '-', PEP 440 versions do not). Unknown/degenerate names have no version.
    #[test]
    fn test_version_from_pypi_filename() {
        use super::version_from_pypi_filename as ver;
        assert_eq!(ver("foo-1.2.3-py3-none-any.whl").as_deref(), Some("1.2.3"));
        assert_eq!(ver("my-cool-pkg-2.0.tar.gz").as_deref(), Some("2.0"));
        assert_eq!(ver("pkg-1.0.zip").as_deref(), Some("1.0"));
        assert_eq!(ver("pkg-3.1.tar.xz").as_deref(), Some("3.1"));
        assert_eq!(ver("nover.txt"), None);
        assert_eq!(ver("noversion.whl"), None);
    }

    // Security (#3107): the upload filename guard accepts real wheel/sdist names
    // and rejects path separators, parent references, and control characters.
    #[test]
    fn test_is_safe_upload_filename_rejects_traversal_and_separators() {
        use super::is_safe_upload_filename as safe;
        assert!(safe("dtfpkg-1.0.0-py3-none-any.whl"));
        assert!(safe("dtfpkg-1.0.0.tar.gz"));
        assert!(!safe("../evil.whl"));
        assert!(!safe("a/b.whl"));
        assert!(!safe("a\\b.whl"));
        assert!(!safe(".."));
        assert!(!safe("."));
        assert!(!safe(""));
        assert!(!safe("foo\0bar.whl"));
        assert!(!safe("x..y.whl"));
        // HTML metacharacters (defense-in-depth for the Simple-index render).
        assert!(!safe("x\"><script>.whl"));
        assert!(!safe("a<b.whl"));
        assert!(!safe("a>b.whl"));
    }

    // Review (security blocker): the <base> strip must reach a FIXPOINT — a
    // self-splicing decoy that reconstitutes a <base> after one pass must not
    // survive, or the proxy-bypass/host-disclosure returns.
    #[test]
    fn test_rewrite_upstream_urls_strips_spliced_base_tag() {
        let html = r#"<ba<base dummy>se href="//evil.example/"><a href="pkg-1.0.whl">pkg</a>"#;
        let out = super::rewrite_upstream_urls(html, "myrepo", "proj");
        assert!(
            !out.to_lowercase().contains("<base"),
            "reconstituted <base> survived: {out}"
        );
        assert!(!out.contains("evil.example"), "upstream host leaked: {out}");
        assert!(out.contains("/pypi/myrepo/simple/proj/pkg-1.0.whl"));
    }

    // Review (security blocker): a publisher-controlled filename must be
    // HTML-escaped in the Simple-index HTML page (stored XSS otherwise); wheels
    // also advertise data-core-metadata in the HTML branch (parity with JSON).
    #[test]
    fn test_build_simple_project_response_html_escapes_filename_and_advertises_core_metadata() {
        // A slash-free payload so `rsplit('/')` keeps the whole filename (a real
        // filename can't contain '/'; the injection vector is < > " ).
        let artifacts = vec![SimpleProjectArtifact {
            path: "evil\"><img src=y onerror=alert(1)>.whl".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 10,
            checksum_sha256: "cafe".to_string(),
            metadata: None,
            upload_time: None,
        }];
        let headers = HeaderMap::new(); // no Accept -> HTML branch
        let response =
            build_simple_project_response(&headers, "repo", "x", &artifacts, &[]).unwrap();
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<img"), "unescaped tag rendered: {html}");
        assert!(
            html.contains("&lt;img"),
            "filename not HTML-escaped: {html}"
        );
        assert!(html.contains("&quot;"), "quote not HTML-escaped: {html}");
        assert!(
            html.contains("data-core-metadata"),
            "wheel core-metadata not advertised in the HTML branch"
        );
    }

    // -- #3463: PEP 658 metadata repair on a proxy-cache-backed row --------

    /// The routing rule. `coordinated_retry_get` is the repair path for a
    /// LOCALLY stored artifact: it re-reads the same key under a cluster-wide
    /// hydration lease and 507s if the object is still absent. Nothing local
    /// ever writes a `proxy-cache/` key, so on such a row the lease, the
    /// second read and the ERROR log buy nothing — measured 1:1 with the miss,
    /// 32,681 times in 24h, never once succeeding.
    ///
    /// This pins the rule; `test_serve_metadata_defers_proxy_cache_repair_3463`
    /// below pins that `serve_metadata` actually consults it. Neither is
    /// sufficient alone.
    #[test]
    fn test_metadata_miss_repair_rule_3463() {
        assert_eq!(
            super::metadata_miss_repair(
                "proxy-cache/pypi-remote/simple/six/six-1.17.0.whl/__content__"
            ),
            super::MetadataMissRepair::CallerRecoversFromUpstream,
            "no local writer owns a proxy-cache key, so the local repair cannot succeed"
        );

        // Controls: a fix that returned CallerRecoversFromUpstream
        // unconditionally would pass the assertion above while stripping the
        // genuine local-storage repair from every hosted row.
        for key in [
            "pypi/six/1.17.0/six-1.17.0.whl",
            "maven/org/example/demo/1.0/demo-1.0.jar",
            // Not the reserved root: an ordinary key that merely looks similar.
            "npm/proxy-cache-notes/-/proxy-cache-notes-1.0.0.tgz",
        ] {
            assert_eq!(
                super::metadata_miss_repair(key),
                super::MetadataMissRepair::CoordinatedRetry,
                "{key} is a locally-written artifact and keeps the hydration repair"
            );
        }
    }

    /// End-to-end on the real function, pinning the CALL SITE rather than the
    /// helper: a `.metadata` request against a proxy-cache-backed row whose
    /// object is absent must skip the local repair and answer the
    /// metadata-specific 507 that tells the caller to recover from upstream —
    /// and must NOT re-read the key under the hydration lease (#3463).
    ///
    /// The two paths are distinguishable by the body they emit:
    /// `coordinated_retry_get` answers `artifact file unavailable`, the new
    /// path answers `artifact metadata unavailable` (which is also the wording
    /// `serve_virtual_metadata` already synthesises, so one resource now has
    /// one message whichever layer produced it). The read count is asserted
    /// too, because the message alone would be satisfied by a fix that still
    /// paid for the dead lease and re-read.
    ///
    /// The second half is the negative control that keeps a legitimate 507
    /// distinguishable: an identically-absent object behind a HOSTED key must
    /// still take the coordinated-retry path — same status, different message,
    /// and the extra read.
    ///
    /// FAILS ON MAIN: both rows answer `artifact file unavailable` after two
    /// reads.
    #[tokio::test]
    async fn test_serve_metadata_defers_proxy_cache_repair_3463() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "remote", "pypi").await;
        // A registered cloud backend, so the read goes through a handle whose
        // every `get` is observable.
        let (state, mem) = tdh::build_state_with_cloud(pool.clone(), "s3");
        sqlx::query("UPDATE repositories SET storage_backend = 's3' WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("point the repo at the observable backend");
        let repo_info = tdh::make_repo_info(repo_id, &repo_key, &storage_dir, "remote", None);
        let repo_info = crate::api::handlers::proxy_helpers::RepoInfo {
            storage_backend: "s3".to_string(),
            ..repo_info
        };

        // Two rows, same repository, same absent-object state, different key
        // layouts. Nothing is written to storage for either.
        let cached_file = "demo-1.0-py3-none-any.whl";
        let hosted_file = "demo-2.0-py3-none-any.whl";
        for (filename, storage_key) in [
            (
                cached_file,
                "proxy-cache/pypi-remote/simple/demo/demo-1.0-py3-none-any.whl/__content__",
            ),
            (hosted_file, "pypi/demo/2.0/demo-2.0-py3-none-any.whl"),
        ] {
            sqlx::query(
                "INSERT INTO artifacts ( \
                     repository_id, path, name, version, size_bytes, \
                     checksum_sha256, content_type, storage_key, uploaded_by \
                 ) VALUES ($1, $2, 'demo', '1.0', 42, $3, 'application/zip', $4, $5)",
            )
            .bind(repo_id)
            .bind(format!("demo/1.0/{filename}"))
            .bind(format!("sha-{filename}"))
            .bind(storage_key)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("seed artifact row");
        }

        let before = mem.get_count();
        let cached = super::serve_metadata(&state, &pool, &repo_info, cached_file).await;
        let cached_reads = mem.get_count() - before;
        let (cached_status, cached_body) = collect_serve_3220(cached).await;

        let before = mem.get_count();
        let hosted = super::serve_metadata(&state, &pool, &repo_info, hosted_file).await;
        let hosted_reads = mem.get_count() - before;
        let (hosted_status, hosted_body) = collect_serve_3220(hosted).await;

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            cached_status,
            StatusCode::INSUFFICIENT_STORAGE,
            "the member still owns the name, so it must stay 507 and never 404 (#3372)"
        );
        assert_eq!(
            String::from_utf8_lossy(&cached_body),
            "artifact metadata unavailable; retry later",
            "#3463: a proxy-cache-backed row must skip the local repair and hand the caller \
             the signal it recovers from, not `coordinated_retry_get`'s answer"
        );
        assert_eq!(
            cached_reads, 1,
            "#3463: the key must be read once; the coordinated re-read cannot succeed on a \
             key no local writer owns and only costs a lease plus a second round trip"
        );

        assert_eq!(
            hosted_status,
            StatusCode::INSUFFICIENT_STORAGE,
            "negative control: a hosted row with an absent object is still 507"
        );
        assert_eq!(
            String::from_utf8_lossy(&hosted_body),
            "artifact file unavailable; retry later",
            "negative control: a hosted row is a real local-storage fault and must KEEP the \
             coordinated hydration repair"
        );
        assert!(
            hosted_reads > cached_reads && hosted_reads >= 2,
            "negative control: the hosted row must still be re-read under the hydration lease \
             (observed {hosted_reads} reads vs {cached_reads} for the proxy-cache row); an \
             exact count is not pinned because it is an internal of the coordinator"
        );
    }
}

/// #3149 — upstream `Content-Encoding` forwarding on PyPI file serves.
///
/// `build_streaming_file_response` is the SINGLE response builder behind all
/// six PyPI file-serving call sites (last-known-good replay, remote cache-hit,
/// remote cache-miss, the two virtual arms, and the scan-pending serve). Each
/// hands it the whole `StreamingFetchResult`, so none of them can drop the
/// coding independently -- the builder is the only regression point, and these
/// guards cover it for every call site at once.
///
/// It read `content_length` (the CODED length) and discarded
/// `content_encoding`, so pip received compressed bytes advertised as a plain
/// wheel and failed the hash check.
#[cfg(test)]
mod content_encoding_forwarding_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    fn result_with_encoding(
        body: &'static [u8],
        encoding: Option<&str>,
    ) -> crate::services::proxy_service::StreamingFetchResult {
        let data = Bytes::from_static(body);
        let len = data.len() as u64;
        crate::services::proxy_service::StreamingFetchResult {
            body: Box::pin(futures::stream::once(async move {
                Ok::<Bytes, crate::error::AppError>(data)
            })),
            content_type: Some("application/zip".to_string()),
            content_length: Some(len),
            artifact_id: None,
            etag: None,
            content_encoding: encoding.map(str::to_owned),
            commit_sha: None,
        }
    }

    /// A coded upstream wheel must arrive declared.
    #[tokio::test]
    async fn test_build_streaming_file_response_forwards_content_encoding() {
        let resp = build_streaming_file_response(
            "numpy-1.0-py3-none-any.whl",
            // deflate, not gzip: with every fixture gzip, hardcoding "gzip" in
            // this builder -- the single choke point for six PyPI serve paths --
            // left all three tests green.
            result_with_encoding(b"coded-wheel-bytes", Some("deflate")),
        );
        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_ENCODING).as_deref(),
            Some("deflate"),
            "upstream Content-Encoding must be forwarded or pip writes bytes \
             it cannot inflate and fails the hash check (#3149)",
        );
        // The coded length and the coding must describe the same bytes.
        assert_eq!(
            tdh::header_str(resp.headers(), CONTENT_LENGTH).as_deref(),
            Some("17"),
        );
    }

    /// Negative control: an uncoded serve must not gain a manufactured coding.
    #[tokio::test]
    async fn test_build_streaming_file_response_omits_absent_content_encoding() {
        let resp = build_streaming_file_response(
            "numpy-1.0-py3-none-any.whl",
            result_with_encoding(b"plain-wheel-bytes", None),
        );
        assert!(
            resp.headers().get(CONTENT_ENCODING).is_none(),
            "an uncoded serve must not have a coding manufactured for it",
        );
    }

    /// The body must reach the client byte-identical either way -- the fix
    /// declares the coding, it must never re-code or decode the payload.
    #[tokio::test]
    async fn test_build_streaming_file_response_passes_body_through_untouched() {
        let payload: &[u8] = b"coded-wheel-bytes";
        let resp = build_streaming_file_response(
            "numpy-1.0-py3-none-any.whl",
            result_with_encoding(b"coded-wheel-bytes", Some("gzip")),
        );
        let (status, body, _headers) = tdh::collect_response(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], payload);
    }
}

/// #3323 regression: the PyPI simple index must not disclose a PRIVATE virtual
/// member's projects, versions or filenames to a caller who could not read that
/// member directly.
///
/// `serve_file` (the BYTES) was gated by #2073; the INDEX was not. `simple_root`
/// and `simple_project` walked `fetch_virtual_members` unfiltered and neither
/// handler bound an auth extractor at all, so a public virtual parent published
/// a private member's full project list and per-project file list — names,
/// versions and SHA-256 hashes — to anonymous callers. Both handlers now bind
/// the caller and resolve members through
/// `proxy_helpers::authorized_virtual_members`.
#[cfg(test)]
mod virtual_index_member_authz_tests {
    use axum::http::HeaderMap;

    use crate::api::handlers::test_db_helpers as tdh;

    /// Seed one sdist row on a member so it can appear in the index.
    async fn seed_member_project(
        pool: &sqlx::PgPool,
        member_id: uuid::Uuid,
        project: &str,
        version: &str,
        uploaded_by: uuid::Uuid,
    ) {
        let filename = format!("{project}-{version}.tar.gz");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, 42, $5, 'application/gzip', $2, $6)",
        )
        .bind(member_id)
        .bind(&filename)
        .bind(project)
        .bind(version)
        .bind(format!("{:0>64}", project))
        .bind(uploaded_by)
        .execute(pool)
        .await
        .expect("seed member project");
    }

    #[allow(clippy::disallowed_methods)]
    // STREAMING-EXEMPT: test-only read of a bounded simple-index document.
    async fn body_of(result: Result<axum::response::Response, axum::response::Response>) -> String {
        let resp = match result {
            Ok(r) => r,
            Err(r) => r,
        };
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn simple_index_hides_a_private_members_projects_from_an_anonymous_caller() {
        let Some(fx) = tdh::Fixture::setup("virtual", "pypi").await else {
            return;
        };
        let (private_id, _pk, private_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        let (public_id, _puk, public_dir) = tdh::create_repo(&fx.pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(public_id)
            .execute(&fx.pool)
            .await
            .expect("publish the public member");
        tdh::link_virtual_member(&fx.pool, fx.repo_id, private_id, 1).await;
        tdh::link_virtual_member(&fx.pool, fx.repo_id, public_id, 2).await;
        seed_member_project(&fx.pool, private_id, "secretpkg", "1.0.0", fx.user_id).await;
        seed_member_project(&fx.pool, public_id, "openpkg", "2.0.0", fx.user_id).await;

        // Root index, anonymous: only the public member's project.
        let root = body_of(
            super::simple_root(
                axum::extract::State(fx.state.clone()),
                axum::Extension(None),
                axum::extract::Path(fx.repo_key.clone()),
                HeaderMap::new(),
            )
            .await,
        )
        .await;
        assert!(
            root.contains("openpkg"),
            "positive control: the PUBLIC member's project must still be listed, got {root}"
        );
        assert!(
            !root.contains("secretpkg"),
            "#3323: the root index must not disclose a PRIVATE member's project names \
             to an anonymous caller, got {root}"
        );

        // Per-project index, anonymous: the private member's files must not
        // surface, and the project must read as absent.
        let project = body_of(
            super::simple_project(
                axum::extract::State(fx.state.clone()),
                axum::Extension(None),
                axum::extract::Path((fx.repo_key.clone(), "secretpkg".to_string())),
                HeaderMap::new(),
            )
            .await,
        )
        .await;
        assert!(
            !project.contains("secretpkg-1.0.0.tar.gz"),
            "#3323: the per-project index must not disclose a PRIVATE member's \
             filenames to an anonymous caller, got {project}"
        );

        // Positive control: an admin sees it, so this is authorization and not
        // a blanket break of virtual index aggregation.
        let admin = tdh::admin_auth(fx.user_id, &fx.username);
        let admin_project = body_of(
            super::simple_project(
                axum::extract::State(fx.state.clone()),
                axum::Extension(Some(admin)),
                axum::extract::Path((fx.repo_key.clone(), "secretpkg".to_string())),
                HeaderMap::new(),
            )
            .await,
        )
        .await;
        assert!(
            admin_project.contains("secretpkg-1.0.0.tar.gz"),
            "an admin must still resolve the private member's project through the \
             virtual repo, got {admin_project}"
        );

        tdh::cleanup_member_repo(&fx.pool, private_id, &private_dir).await;
        tdh::cleanup_member_repo(&fx.pool, public_id, &public_dir).await;
        fx.teardown().await;
    }
}
