//! GOPROXY protocol handler.
//!
//! Implements the endpoints required for `go get` via GOPROXY protocol.
//!
//! Routes are mounted at `/go/{repo_key}/...`:
//!   GET  /go/{repo_key}/*module/@v/list             - List versions
//!   GET  /go/{repo_key}/*module/@v/{version}.info    - Version info (JSON)
//!   GET  /go/{repo_key}/*module/@v/{version}.mod     - Get go.mod
//!   GET  /go/{repo_key}/*module/@v/{version}.zip     - Download module zip
//!   GET  /go/{repo_key}/*module/@latest              - Latest version info
//!   PUT  /go/{repo_key}/*module/@v/{version}.zip     - Upload module zip
//!   PUT  /go/{repo_key}/*module/@v/{version}.mod     - Upload go.mod

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new().route("/:repo_key/*path", get(handle_get).put(handle_put))
}

// ---------------------------------------------------------------------------
// Module path encoding/decoding
// ---------------------------------------------------------------------------

/// Decode a GOPROXY-encoded module path.
/// Capital letters are encoded as `!` followed by the lowercase letter.
/// E.g., `github.com/!azure/go-sdk` → `github.com/Azure/go-sdk`
fn decode_module_path(encoded: &str) -> String {
    let mut result = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            if let Some(next) = chars.next() {
                result.push(next.to_ascii_uppercase());
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Encode a module path for GOPROXY.
/// Capital letters become `!` + lowercase.
fn encode_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            result.push('!');
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Parsed GOPROXY request.
enum GoProxyRequest {
    /// `/@v/list` — list all versions
    List { module: String },
    /// `/@v/{version}.info` — version metadata JSON
    Info { module: String, version: String },
    /// `/@v/{version}.mod` — go.mod file
    Mod { module: String, version: String },
    /// `/@v/{version}.zip` — module zip
    Zip { module: String, version: String },
    /// `/@latest` — latest version info
    Latest { module: String },
    /// `sumdb/...` — checksum database verification proxy
    SumDb {
        /// The sumdb host, e.g. `sum.golang.org`
        host: String,
        /// The remaining path after the host, e.g. `lookup/...` or `tile/...`
        path: String,
    },
}

/// Parse the wildcard path segment into a GoProxyRequest.
///
/// The path comes in as everything after `/:repo_key/`, e.g.:
///   `github.com/!azure/go-sdk/@v/list`
///   `github.com/!azure/go-sdk/@v/v1.0.0.info`
///   `github.com/!azure/go-sdk/@latest`
///   `sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0`
#[allow(clippy::result_large_err)]
fn parse_path(raw_path: &str) -> Result<GoProxyRequest, Response> {
    // Strip leading slash if present (axum wildcard may include it)
    let path = raw_path.strip_prefix('/').unwrap_or(raw_path);

    // Check for sumdb/ prefix — go.sum verification requests.
    // When GOPROXY is set, the Go toolchain sends checksum database queries
    // through the proxy at paths like sumdb/sum.golang.org/lookup/...
    if let Some(rest) = path.strip_prefix("sumdb/") {
        // Expected format: sumdb/{host}/{remaining_path}
        // e.g. sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0
        // e.g. sumdb/sum.golang.org/tile/8/0/000
        // e.g. sumdb/sum.golang.org/supported
        if let Some(slash_pos) = rest.find('/') {
            let host = rest[..slash_pos].to_string();
            let remaining = rest[slash_pos + 1..].to_string();
            if !host.is_empty() && !remaining.is_empty() {
                return Ok(GoProxyRequest::SumDb {
                    host,
                    path: remaining,
                });
            }
        }
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid sumdb path: expected sumdb/{host}/{path}",
        )
            .into_response());
    }

    // Check for /@latest suffix
    if let Some(module_encoded) = path.strip_suffix("/@latest") {
        let module = decode_module_path(module_encoded);
        return Ok(GoProxyRequest::Latest { module });
    }

    // Look for /@v/ separator
    let av_pos = path.find("/@v/").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid GOPROXY path: missing /@v/ or /@latest",
        )
            .into_response()
    })?;

    let module_encoded = &path[..av_pos];
    let operation = &path[av_pos + 4..]; // skip "/@v/"
    let module = decode_module_path(module_encoded);

    if operation == "list" {
        return Ok(GoProxyRequest::List { module });
    }

    if let Some(version) = operation.strip_suffix(".info") {
        return Ok(GoProxyRequest::Info {
            module,
            version: decode_module_path(version),
        });
    }

    if let Some(version) = operation.strip_suffix(".mod") {
        return Ok(GoProxyRequest::Mod {
            module,
            version: decode_module_path(version),
        });
    }

    if let Some(version) = operation.strip_suffix(".zip") {
        return Ok(GoProxyRequest::Zip {
            module,
            version: decode_module_path(version),
        });
    }

    Err((
        StatusCode::BAD_REQUEST,
        format!("Unknown GOPROXY operation: {}", operation),
    )
        .into_response())
}

use crate::api::middleware::auth::require_auth_with_bearer_fallback;

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_go_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["go"], "a Go").await
}

// ---------------------------------------------------------------------------
// GET handler — dispatches based on parsed path
// ---------------------------------------------------------------------------

async fn handle_get(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_go_repo(&state.db, &repo_key).await?;
    let request = parse_path(&path)?;

    match request {
        GoProxyRequest::List { module } => list_versions(&state, &repo, &module).await,
        GoProxyRequest::Info { module, version } => {
            version_info(&state, &repo, &module, &version).await
        }
        GoProxyRequest::Mod { module, version } => {
            get_mod_file(&state, auth.as_ref(), &repo, &module, &version, &ctx).await
        }
        GoProxyRequest::Zip { module, version } => {
            download_zip(&state, auth.as_ref(), &repo, &module, &version, &ctx).await
        }
        GoProxyRequest::Latest { module } => latest_version(&state, &repo, &module).await,
        GoProxyRequest::SumDb { host, path } => proxy_sumdb(&host, &path).await,
    }
}

// ---------------------------------------------------------------------------
// GET sumdb/... — Proxy to upstream checksum database
// ---------------------------------------------------------------------------

/// Hostnames the sumdb proxy is permitted to forward to.
///
/// SECURITY: `proxy_sumdb` builds `https://{host}/{path}` from URL path
/// components controlled by the caller. Without an allowlist this is an
/// SSRF vector — an attacker can request `sumdb/169.254.169.254/...`
/// to make the server fetch cloud metadata. Only well-known Go
/// checksum-database hosts may be proxied.
const SUMDB_ALLOWLIST: &[&str] = &["sum.golang.org", "sum.golang.google.cn"];

/// Returns true iff `host` is a permitted upstream sumdb hostname.
/// Comparison is case-insensitive per RFC 1035.
///
/// Visibility is `pub` (not `pub(crate)`) to expose the function to the
/// `tests/security_regression_tests.rs` integration test, which validates
/// the GHSA-mc8p-6758-jfp2 host allowlist from outside the crate.
pub fn is_sumdb_host_allowed(host: &str) -> bool {
    SUMDB_ALLOWLIST
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

/// Proxy a sumdb request to the upstream checksum database.
///
/// The Go toolchain performs go.sum verification by querying
/// `$GOPROXY/sumdb/sum.golang.org/{path}`. We forward these requests
/// to `https://{host}/{path}` (defaulting to sum.golang.org).
async fn proxy_sumdb(host: &str, path: &str) -> Result<Response, Response> {
    if !is_sumdb_host_allowed(host) {
        tracing::warn!(
            host = %host,
            "Rejected sumdb proxy request to disallowed host (SSRF prevention)"
        );
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "sumdb host '{}' is not in the allowlist of permitted upstreams",
                host
            ),
        )
            .into_response());
    }

    let url = format!("https://{}/{}", host, path);

    tracing::debug!("Proxying sumdb request to {}", url);

    let client = crate::services::http_client::default_client();
    let upstream_resp = client.get(&url).send().await.map_err(|e| {
        tracing::warn!("sumdb proxy request failed for {}: {}", url, e);
        (
            StatusCode::BAD_GATEWAY,
            format!("Failed to reach checksum database: {}", e),
        )
            .into_response()
    })?;

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    #[allow(clippy::disallowed_methods)]
    // STREAMING-EXEMPT: capped metadata read (upstream sumdb checksum-database response, not an artifact blob); bounded to <=16 MiB via axum::body::to_bytes so a hostile/broken upstream cannot OOM us; over-cap -> 502; tracked under #1608
    let body = axum::body::to_bytes(
        Body::from_stream(upstream_resp.bytes_stream()),
        16 * 1024 * 1024,
    )
    .await
    .map_err(|e| {
        tracing::warn!("sumdb proxy response read failed for {}: {}", url, e);
        (
            StatusCode::BAD_GATEWAY,
            format!("Failed to read checksum database response: {}", e),
        )
            .into_response()
    })?;

    // Forward the upstream status code (200, 404, etc.)
    Ok(Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT handler — dispatches based on parsed path
// ---------------------------------------------------------------------------

async fn handle_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: reject read-scoped API tokens on PUT.
    crate::api::middleware::auth::require_scope_response(auth.as_ref(), "write:artifacts")?;
    let user_id =
        require_auth_with_bearer_fallback(auth, &headers, &state.db, &state.config, "goproxy")
            .await?;
    let repo = resolve_go_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;
    let request = parse_path(&path)?;

    match request {
        GoProxyRequest::Zip { module, version } => {
            upload_zip(&state, &repo, &module, &version, user_id, body).await
        }
        GoProxyRequest::Mod { module, version } => {
            upload_mod(&state, &repo, &module, &version, user_id, body).await
        }
        _ => Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "PUT is only supported for .zip and .mod files",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /@v/list — List versions
// ---------------------------------------------------------------------------

/// Proxy a Go metadata request to the upstream for remote repos, or resolve
/// through virtual repo members. Returns `Ok(response)` if the proxy produced
/// a result, or `Err(())` if no proxy was available and the caller should fall
/// back to the local/not-found response.
async fn try_proxy_go_metadata(
    state: &SharedState,
    repo: &RepoInfo,
    upstream_path: &str,
    default_content_type: &str,
) -> Result<Response, ()> {
    // Remote repo: proxy to upstream. The upstream body is forwarded
    // VERBATIM (`.info` JSON / `.mod` bytes as the upstream served them), so
    // the upstream `Content-Encoding` must be re-declared when present
    // (RFC 9110 §8.4, #3260) — nothing on this path decodes.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            if let Ok((content, content_type, content_encoding)) =
                proxy_helpers::proxy_fetch_capped_encoded(
                    proxy,
                    repo.id,
                    &repo.key,
                    upstream_url,
                    upstream_path,
                    proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
                )
                .await
            {
                return Ok(proxy_helpers::forward_verbatim_metadata(
                    content,
                    content_type,
                    default_content_type,
                    content_encoding,
                ));
            }
        }
    }

    // Virtual repo: try each member in priority order. Same verbatim-forward
    // contract as the Remote arm above: the member's coding is re-declared.
    if repo.repo_type == RepositoryType::Virtual {
        let ct = default_content_type.to_string();
        if let Ok(resp) = proxy_helpers::resolve_virtual_metadata(
            &state.db,
            state.proxy_service.as_deref(),
            repo.id,
            upstream_path,
            |bytes, content_encoding, _key| {
                let ct = ct.clone();
                async move {
                    Ok(proxy_helpers::forward_verbatim_metadata(
                        bytes,
                        None,
                        &ct,
                        content_encoding,
                    ))
                }
            },
        )
        .await
        {
            return Ok(resp);
        }
    }

    Err(())
}

/// Parse a goproxy `@v/list` document into its version lines.
fn parse_version_list(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// Rebuild a goproxy `@v/list` document without the blocked versions,
/// preserving the order of the surviving lines.
fn filter_version_list(body: &str, blocked: &std::collections::HashSet<String>) -> String {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !blocked.contains(*line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Fetch a Go metadata document from the repository's upstream — or, for a
/// virtual repository, from its remote members in priority order — returning
/// the id of the repository that actually served it alongside the body. The
/// source id is what the age-gate listing filter resolves policy from: for a
/// virtual repository each member's own gate configuration governs its
/// contribution (#2264).
///
/// Deliberately DROPS the upstream `Content-Encoding` (#3260): every caller
/// PARSES the returned body (`@v/list` line filtering, `@latest` JSON) and
/// serves a document it rebuilt itself, so the upstream coding never
/// describes the bytes that leave the handler. Verbatim forwards go through
/// [`try_proxy_go_metadata`] / `get_mod_file`, which re-declare the coding.
async fn fetch_go_metadata_with_source(
    state: &SharedState,
    repo: &RepoInfo,
    upstream_path: &str,
) -> Option<(uuid::Uuid, Bytes)> {
    let proxy = state.proxy_service.as_ref()?;
    if repo.repo_type == RepositoryType::Remote {
        let upstream_url = repo.upstream_url.as_deref()?;
        let (content, _content_type) = proxy_helpers::proxy_fetch_capped(
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            upstream_path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
        )
        .await
        .ok()?;
        return Some((repo.id, content));
    }
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id)
            .await
            .ok()?;
        for member in members {
            if member.repo_type != crate::models::repository::RepositoryType::Remote {
                continue;
            }
            let Some(upstream_url) = member.upstream_url.as_deref() else {
                continue;
            };
            if let Ok((content, _content_type)) = proxy_helpers::proxy_fetch_capped(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                upstream_path,
                proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            )
            .await
            {
                return Some((member.id, content));
            }
        }
    }
    None
}

/// Filter a `@v/list` document through the serving repository's download age
/// gate. Parsing and rebuilding are pure; the policy runs through the shared
/// batch evaluation, so the version list and the `.zip` download gate decide
/// from the same clock — a version withheld here is refused there, and vice
/// versa. Ungated repositories pass through with no policy reads.
async fn filter_go_version_list(
    state: &SharedState,
    repository_id: uuid::Uuid,
    module: &str,
    body: &str,
) -> Result<String, Response> {
    let Some(age_gate) = state.age_gate_service.as_ref() else {
        return Ok(body.to_string());
    };
    let params = crate::services::age_gate_service::resolve_repo_params(&state.db, repository_id)
        .await
        .map_err(|e| e.into_response())?;
    if !crate::services::age_gate_service::AgeGateService::gating_requested(&params) {
        return Ok(body.to_string());
    }
    // `@v/list` lines carry no timestamps; under `first_seen` (the only mode
    // Go supports) the basis is this server's own observation of each listed
    // version — the upstream-served document is the existence evidence.
    let versions: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> = parse_version_list(body)
        .into_iter()
        .map(|version| (version, None))
        .collect();
    let blocked = age_gate
        .evaluate_versions_batch(&params, module, &versions)
        .await
        .map_err(|e| e.into_response())?;
    Ok(filter_version_list(body, &blocked))
}

/// Whether the age gate withholds `version` from `@latest`-shaped responses
/// for the serving repository. A blocked latest surfaces as 404 to the `go`
/// client, which then resolves from the filtered `@v/list` — so "latest"
/// quietly becomes the newest version old enough to serve.
async fn go_latest_version_is_blocked(
    state: &SharedState,
    repository_id: uuid::Uuid,
    module: &str,
    version: &str,
    time: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<bool, Response> {
    let Some(age_gate) = state.age_gate_service.as_ref() else {
        return Ok(false);
    };
    let params = crate::services::age_gate_service::resolve_repo_params(&state.db, repository_id)
        .await
        .map_err(|e| e.into_response())?;
    if !crate::services::age_gate_service::AgeGateService::gating_requested(&params) {
        return Ok(false);
    }
    let blocked = age_gate
        .evaluate_versions_batch(&params, module, &[(version.to_string(), time)])
        .await
        .map_err(|e| e.into_response())?;
    Ok(blocked.contains(version))
}

/// Enforce the download age gate for one repository serving `module@version`
/// as a `.zip` (#2264). Policy is re-resolved from the repositories row; the
/// caller's struct only pre-screens. Under `first_seen` — the only mode Go
/// supports — an existing observation is the basis; otherwise a successful
/// upstream `.info` fetch is the existence evidence that starts the clock. A
/// version with no basis blocks (451, review row created), so an unpublished
/// name cannot be pre-aged by requesting it early.
async fn enforce_go_zip_age_gate(
    state: &SharedState,
    repository_id: uuid::Uuid,
    module: &str,
    version: &str,
) -> Result<(), Response> {
    use crate::services::age_gate_service::{resolve_repo_params, AgeGateService};

    let params = resolve_repo_params(&state.db, repository_id)
        .await
        .map_err(|e| e.into_response())?;
    if !AgeGateService::gating_requested(&params) {
        return Ok(());
    }
    AgeGateService::require_enforceable(&params).map_err(|e| e.into_response())?;
    let Some(svc) = state.age_gate_service.as_ref() else {
        return Err(proxy_helpers::age_gate_unavailable_response(
            &params.key,
            module,
        ));
    };
    // Lookup-only pass first: the common case (version already observed via a
    // listing) needs no upstream round-trip.
    let mut basis = svc
        .download_basis(&params, module, version, None, false)
        .await
        .map_err(|e| e.into_response())?;
    if basis.is_none() {
        let exists = go_version_exists_upstream(state, &params, module, version).await;
        if exists {
            basis = svc
                .download_basis(&params, module, version, None, true)
                .await
                .map_err(|e| e.into_response())?;
        }
    }
    // Go has no last-known-good substitution: a block is the terminal 451.
    let lkg_opt = proxy_helpers::enforce_age_gate(
        state.age_gate_service.as_deref(),
        &params,
        module,
        version,
        basis,
    )
    .await?;
    if let Some(blocked) = lkg_opt {
        return Err(proxy_helpers::age_gate_blocked_response(
            blocked.review_id,
            module,
            version,
            params.age_gate_min_age_days,
            None,
        ));
    }
    Ok(())
}

/// Positive existence evidence for `module@version`: the upstream serves its
/// `.info` document. Failures are treated as "no evidence" — the gate then
/// blocks without starting a clock, never the reverse. The body (and hence
/// its `Content-Encoding`, #3260) is discarded: only reachability matters.
async fn go_version_exists_upstream(
    state: &SharedState,
    params: &crate::services::age_gate_service::AgeGateRepoParams,
    module: &str,
    version: &str,
) -> bool {
    let Some(proxy) = state.proxy_service.as_ref() else {
        return false;
    };
    let Some(upstream_url) = params.upstream_url.as_deref() else {
        return false;
    };
    let upstream_path = build_go_upstream_path(module, version, "info");
    proxy_helpers::proxy_fetch_capped(
        proxy,
        params.id,
        &params.key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    .is_ok()
}

async fn list_versions(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
) -> Result<Response, Response> {
    let versions: Vec<Option<String>> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY version
        "#,
        repo.id,
        module
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let body = build_version_list(&versions);
    // A remote repository can hold hydrated `artifacts` rows; its local list
    // is filtered against the same policy as the proxied one (ungated repos
    // pass straight through).
    let body = filter_go_version_list(state, repo.id, module, &body).await?;

    if body.is_empty() {
        // Virtual repo: the version list also lives in the artifact tables of
        // local (non-Remote) member repos, which `try_proxy_go_metadata` does
        // not consult. Aggregate distinct versions across those members so
        // a module stored only in a Local member is listed (#1782).
        if repo.repo_type == RepositoryType::Virtual {
            let member_versions: Vec<Option<String>> = sqlx::query_scalar(
                r#"
                SELECT DISTINCT a.version
                FROM artifacts a
                INNER JOIN virtual_repo_members vrm ON a.repository_id = vrm.member_repo_id
                INNER JOIN repositories member ON member.id = vrm.member_repo_id
                WHERE vrm.virtual_repo_id = $1
                  AND member.repo_type != 'remote'::repository_type
                  AND a.name = $2
                  AND a.is_deleted = false
                  AND a.version IS NOT NULL
                ORDER BY a.version
                "#,
            )
            .bind(repo.id)
            .bind(module)
            .fetch_all(&state.db)
            .await
            .map_err(crate::api::handlers::db_err)?;

            let member_body = build_version_list(&member_versions);

            if !member_body.is_empty() {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from(member_body))
                    .unwrap());
            }
        }

        let upstream_path = build_go_upstream_list_path(module);
        if let Some((source_repo_id, content)) =
            fetch_go_metadata_with_source(state, repo, &upstream_path).await
        {
            let upstream_body = String::from_utf8_lossy(&content).into_owned();
            let filtered =
                filter_go_version_list(state, source_repo_id, module, &upstream_body).await?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(filtered))
                .unwrap());
        }

        return Err((StatusCode::NOT_FOUND, "module not found").into_response());
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.info — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT a.created_at
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.version = $3
          AND a.is_deleted = false
        ORDER BY a.created_at ASC
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Version {} not found for module {}", version, module),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            // Virtual repo: the version may be stored in a local (non-Remote)
            // member repo whose artifact rows `try_proxy_go_metadata` never
            // queries. Look across member repos for the earliest matching
            // artifact before falling through to the upstream proxy (#1782).
            if repo.repo_type == RepositoryType::Virtual {
                if let Some(member_row) = sqlx::query!(
                    r#"
                    SELECT a.created_at
                    FROM artifacts a
                    INNER JOIN virtual_repo_members vrm ON a.repository_id = vrm.member_repo_id
                    WHERE vrm.virtual_repo_id = $1
                      AND a.name = $2
                      AND a.version = $3
                      AND a.is_deleted = false
                    ORDER BY a.created_at ASC
                    LIMIT 1
                    "#,
                    repo.id,
                    module,
                    version
                )
                .fetch_optional(&state.db)
                .await
                .map_err(crate::api::handlers::db_err)?
                {
                    let time_str = format_go_timestamp(&member_row.created_at);
                    let info = build_version_info_json(version, &time_str);
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(info))
                        .unwrap());
                }
            }

            let upstream_path = build_go_upstream_path(module, version, "info");
            if let Ok(resp) =
                try_proxy_go_metadata(state, repo, &upstream_path, "application/json").await
            {
                return Ok(resp);
            }
            return Err(not_found);
        }
    };

    let time_str = format_go_timestamp(&artifact.created_at);

    let info = build_version_info_json(version, &time_str);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(info))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.mod — Get go.mod
// ---------------------------------------------------------------------------

async fn get_mod_file(
    state: &SharedState,
    auth: Option<&crate::api::middleware::auth::AuthExtension>,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%.mod'
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("go.mod not found for {}@{}", module, version),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Verbatim forward of the upstream go.mod bytes: the
                    // upstream `Content-Encoding` must be re-declared when
                    // present (RFC 9110 §8.4, #3260).
                    let upstream_path = build_go_upstream_path(module, version, "mod");
                    let (content, content_type, content_encoding) =
                        proxy_helpers::proxy_fetch_capped_encoded(
                            proxy,
                            repo.id,
                            &repo.key,
                            upstream_url,
                            &upstream_path,
                            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
                        )
                        .await?;
                    return Ok(proxy_helpers::forward_verbatim_metadata(
                        content,
                        content_type,
                        "text/plain; charset=utf-8",
                        content_encoding,
                    ));
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = build_go_upstream_path(module, version, "mod");
                let module_clone = module.to_string();
                let version_clone = version.to_string();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let name = module_clone.clone();
                        let ver = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version_and_suffix(
                                &db, &state, member_id, &location, &name, &ver, "%.mod",
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    "text/plain; charset=utf-8",
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

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, ctx).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.zip — Download module zip
// ---------------------------------------------------------------------------

async fn download_zip(
    state: &SharedState,
    auth: Option<&crate::api::middleware::auth::AuthExtension>,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    // Age gate (#2264): the `.zip` is the gated artifact. The struct only
    // pre-screens (ungated repositories skip the policy read); the gate
    // itself re-resolves policy from the repositories row. Virtual members
    // are gated per member below, each under its own configuration.
    if repo.age_gate_enabled {
        enforce_go_zip_age_gate(state, repo.id, module, version).await?;
    }

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%.zip'
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Module zip not found for {}@{}", module, version),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = build_go_upstream_path(module, version, "zip");
                    // #895: stream large module .zip; default Content-Type
                    // matches the buffered handler's prior fallback so the
                    // Go toolchain still sees `application/zip` when
                    // upstream omits the header (review N2).
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo.key,
                        upstream_url,
                        &upstream_path,
                        "application/zip",
                    )
                    .await;
                }
            }

            // Virtual repo: try each member in priority order. Gated remote
            // members that withhold this version are excluded up front —
            // another (ungated, or aged-past-threshold) member may still
            // serve it. If a gated member blocked and nobody else served,
            // the structured 451 is the answer, not a bare 404.
            if repo.repo_type == RepositoryType::Virtual {
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
                // #3178: authorize the member set against the CALLER before any
                // format-specific filtering, so a member this caller could not
                // read directly can never reach the byte resolver.
                let members =
                    proxy_helpers::authorize_virtual_members(&state.db, auth, repo.id, members)
                        .await;
                let mut allowed = Vec::with_capacity(members.len());
                let mut blocked_response = None;
                for member in members {
                    if member.repo_type == crate::models::repository::RepositoryType::Remote
                        && member.age_gate_enabled
                    {
                        if let Err(resp) =
                            enforce_go_zip_age_gate(state, member.id, module, version).await
                        {
                            blocked_response = Some(resp);
                            continue;
                        }
                    }
                    allowed.push(member);
                }

                let db = state.db.clone();
                let upstream_path = build_go_upstream_path(module, version, "zip");
                let module_clone = module.to_string();
                let version_clone = version.to_string();
                let result = proxy_helpers::resolve_virtual_download_from_members(
                    allowed,
                    state.proxy_service.as_deref(),
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let name = module_clone.clone();
                        let ver = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version_and_suffix(
                                &db, &state, member_id, &location, &name, &ver, "%.zip",
                            )
                            .await
                        }
                    },
                )
                .await;

                return match result {
                    Ok(fetched) => {
                        proxy_helpers::stream_fetch_result(fetched, "application/zip", None)
                    }
                    Err(err) => Err(blocked_response.unwrap_or(err)),
                };
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

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, ctx).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            "Content-Disposition",
            build_go_zip_content_disposition(module, version),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@latest — Latest version info
// ---------------------------------------------------------------------------

async fn latest_version(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        repo.id,
        module
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("No versions found for module {}", module),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            let upstream_path = build_go_upstream_latest_path(module);
            if let Some((source_repo_id, content)) =
                fetch_go_metadata_with_source(state, repo, &upstream_path).await
            {
                // Gate the advertised version: a blocked (or unparseable)
                // "latest" is withheld as 404 so the client re-resolves from
                // the filtered version list instead of learning about — and
                // then failing on — a version this repository will not serve.
                let json: Option<serde_json::Value> = serde_json::from_slice(&content).ok();
                let version = json
                    .as_ref()
                    .and_then(|j| j.get("Version"))
                    .and_then(|v| v.as_str());
                let Some(version) = version else {
                    return Err(
                        (StatusCode::NOT_FOUND, "no latest version available").into_response()
                    );
                };
                let time = json
                    .as_ref()
                    .and_then(|j| j.get("Time"))
                    .and_then(|t| t.as_str())
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| t.with_timezone(&chrono::Utc));
                if go_latest_version_is_blocked(state, source_repo_id, module, version, time)
                    .await?
                {
                    return Err(
                        (StatusCode::NOT_FOUND, "no latest version available").into_response()
                    );
                }
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

    let version = artifact.version.unwrap_or_default();
    let time_str = format_go_timestamp(&artifact.created_at);

    // Same policy for the local-rows arm: a remote repository's hydrated
    // artifact must not advertise a version its download gate withholds.
    if go_latest_version_is_blocked(state, repo.id, module, &version, None).await? {
        return Err((StatusCode::NOT_FOUND, "no latest version available").into_response());
    }

    let info = build_version_info_json(&version, &time_str);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(info))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /@v/{version}.zip — Upload module zip
// ---------------------------------------------------------------------------

async fn upload_zip(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    user_id: uuid::Uuid,
    body: Bytes,
) -> Result<Response, Response> {
    let artifact_path = build_go_zip_artifact_path(module, version);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE '%.zip' AND is_deleted = false",
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        crate::api::handlers::db_err(e)
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("Module zip {}@{} already exists", module, version),
        )
            .into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = build_go_zip_storage_key(module, version);
    proxy_helpers::guard_cross_repo_write(state, repo.id, &repo.storage_backend, &storage_key)
        .await?;

    // Store the file
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        module,
        version,
        size_bytes,
        checksum,
        "application/zip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store metadata
    let metadata = build_go_artifact_metadata(module, version, "zip");

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'go', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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

    info!("Go module upload: {}@{} (zip)", module, version);

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /@v/{version}.mod — Upload go.mod
// ---------------------------------------------------------------------------

async fn upload_mod(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    user_id: uuid::Uuid,
    body: Bytes,
) -> Result<Response, Response> {
    let artifact_path = build_go_mod_artifact_path(module, version);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE '%.mod' AND is_deleted = false",
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        crate::api::handlers::db_err(e)
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("go.mod for {}@{} already exists", module, version),
        )
            .into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = build_go_mod_storage_key(module, version);
    proxy_helpers::guard_cross_repo_write(state, repo.id, &repo.storage_backend, &storage_key)
        .await?;

    // Store the file
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        module,
        version,
        size_bytes,
        checksum,
        "text/plain",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store metadata
    let metadata = build_go_artifact_metadata(module, version, "mod");

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'go', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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

    info!("Go module upload: {}@{} (go.mod)", module, version);

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Path/JSON builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build a version info JSON string (used by .info and @latest endpoints).
fn build_version_info_json(version: &str, time_str: &str) -> String {
    serde_json::json!({
        "Version": version,
        "Time": time_str,
    })
    .to_string()
}

/// Format a chrono DateTime into Go-compatible timestamp string.
fn format_go_timestamp(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Build a newline-separated version list from a vec of optional version strings.
fn build_version_list(versions: &[Option<String>]) -> String {
    versions
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the artifact path for a Go module zip.
fn build_go_zip_artifact_path(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("{}/{}/{}.zip", encoded_module, version, version)
}

/// Build the storage key for a Go module zip.
fn build_go_zip_storage_key(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("go/{}/{}/{}.zip", encoded_module, version, version)
}

/// Build the artifact path for a Go go.mod file.
fn build_go_mod_artifact_path(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("{}/{}/go.mod", encoded_module, version)
}

/// Build the storage key for a Go go.mod file.
fn build_go_mod_storage_key(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("go/{}/{}/go.mod", encoded_module, version)
}

/// Build Go module metadata JSON for storage.
fn build_go_artifact_metadata(module: &str, version: &str, file_type: &str) -> serde_json::Value {
    serde_json::json!({
        "module": module,
        "version": version,
        "type": file_type,
    })
}

/// Build Content-Disposition header for Go zip downloads.
fn build_go_zip_content_disposition(module: &str, version: &str) -> String {
    format!(
        "attachment; filename=\"{}@{}.zip\"",
        encode_module_path(module),
        version
    )
}

/// Build the upstream path for a Go module request (used by remote/virtual repos).
fn build_go_upstream_path(module: &str, version: &str, ext: &str) -> String {
    let encoded_module = encode_module_path(module);
    let encoded_version = encode_module_path(version);
    format!("{}/@v/{}.{}", encoded_module, encoded_version, ext)
}

/// Build the upstream path for a Go module version-list request.
fn build_go_upstream_list_path(module: &str) -> String {
    let encoded = encode_module_path(module);
    format!("{}/@v/list", encoded)
}

/// Build the upstream path for a Go module @latest request.
fn build_go_upstream_latest_path(module: &str) -> String {
    let encoded = encode_module_path(module);
    format!("{}/@latest", encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    #[test]
    fn parse_version_list_trims_and_drops_blank_lines() {
        assert_eq!(
            parse_version_list("v1.0.0\n  v1.1.0 \n\nv2.0.0\n"),
            vec!["v1.0.0", "v1.1.0", "v2.0.0"]
        );
        assert!(parse_version_list("").is_empty());
    }

    #[test]
    fn filter_version_list_preserves_order_of_survivors() {
        let blocked: std::collections::HashSet<String> =
            ["v1.1.0".to_string()].into_iter().collect();
        assert_eq!(
            filter_version_list("v1.0.0\nv1.1.0\nv2.0.0", &blocked),
            "v1.0.0\nv2.0.0"
        );
        assert_eq!(
            filter_version_list("v1.1.0", &blocked),
            "",
            "a fully blocked list is empty, not absent"
        );
    }

    /// End-to-end Go age-gate slice (#2264): a gated `first_seen` remote repo
    /// filters young versions from `@v/list`, withholds a young `@latest` as
    /// 404 (the client then resolves from the filtered list), and blocks the
    /// `.zip` download with the structured 451 — then serves all three once
    /// the observations age past the threshold. `.info` stays readable
    /// throughout (version-addressed metadata, deliberately ungated).
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: buffering response bodies in test assertions is not an artifact path (#1608)
    #[tokio::test]
    async fn go_age_gate_filters_list_latest_and_blocks_zip_db() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "go").await else {
            return;
        };
        let upstream = MockServer::start().await;
        let module = "example.com/gated";
        Mock::given(method("GET"))
            .and(path(format!("/{module}/@v/list")))
            .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\nv1.1.0"))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{module}/@latest")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Version": "v1.1.0",
                "Time": "2020-01-01T00:00:00Z",
            })))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{module}/@v/v1.1.0.zip")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"zip-bytes".to_vec()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{module}/@v/v1.1.0.info")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Version": "v1.1.0",
                "Time": "2020-01-01T00:00:00Z",
            })))
            .mount(&upstream)
            .await;

        sqlx::query(
            "UPDATE repositories SET upstream_url = $1, age_gate_enabled = true, \
             age_gate_min_age_days = 30, age_gate_mode = 'first_seen' WHERE id = $2",
        )
        .bind(upstream.uri())
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("configure gated go repo");

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), storage_path.as_str());
        let state =
            tdh::build_state_with_proxy_and_age_gate(fx.pool.clone(), storage_path.as_str(), proxy);
        let mut repo = fx.repo_info("remote", Some(&upstream.uri()));
        // The struct pre-screens; the gate re-resolves policy from the row
        // updated above, so both must agree the gate is on.
        repo.format = "go".to_string();
        repo.age_gate_enabled = true;
        repo.age_gate_min_age_days = 30;
        repo.age_gate_mode = "first_seen".to_string();

        async fn body_string(response: Response) -> String {
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("read body");
            String::from_utf8_lossy(&bytes).into_owned()
        }

        // First sight: the upstream-served list is the existence evidence,
        // both versions are observed and withheld.
        let listed = list_versions(&state, &repo, module)
            .await
            .expect("list must succeed");
        assert_eq!(body_string(listed).await, "", "young versions are withheld");
        let observations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM age_gate_version_observations WHERE repository_id = $1",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("count observations");
        assert_eq!(observations, 2, "listing observes every advertised version");

        // Young @latest is withheld as 404 (client falls back to the list).
        let err = latest_version(&state, &repo, module)
            .await
            .expect_err("young latest must be withheld");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);

        // Seed an older cached version so the shared seam returns an LKG
        // outcome. Go deliberately does not substitute it, but its terminal
        // 451 must still carry the real review id from that outcome.
        let lkg_id = tdh::seed_artifact(
            &state,
            &fx.pool,
            &repo,
            &format!("go/{module}/v0.9.0.zip"),
            &format!("{module}/v0.9.0/v0.9.0.zip"),
            module,
            "v0.9.0",
            "application/zip",
            bytes::Bytes::from_static(b"PK\x03\x04 old-lkg"),
            fx.user_id,
        )
        .await;

        // The requested artifact itself blocks with the structured 451.
        let ctx = Default::default();
        let err = download_zip(
            &state,
            tdh::admin_auth_ext().as_ref(),
            &repo,
            module,
            "v1.1.0",
            &ctx,
        )
        .await
        .expect_err("young zip must block");
        assert_eq!(err.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        let blocked: serde_json::Value =
            serde_json::from_str(&body_string(err).await).expect("451 JSON body");
        let review_id = blocked["review_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .expect("real review id");
        assert_ne!(review_id, uuid::Uuid::nil());
        sqlx::query("DELETE FROM artifacts WHERE id = $1")
            .bind(lkg_id)
            .execute(&fx.pool)
            .await
            .expect("remove temporary LKG fixture");

        // Version-addressed metadata stays readable while the zip is gated.
        let info = version_info(&state, &repo, module, "v1.1.0")
            .await
            .expect(".info is metadata and passes");
        assert_eq!(info.status(), StatusCode::OK);

        // Age the observations: list, latest, and zip all serve.
        sqlx::query(
            "UPDATE age_gate_version_observations SET first_seen_at = NOW() - INTERVAL '90 days' \
             WHERE repository_id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("backdate observations");

        let listed = list_versions(&state, &repo, module)
            .await
            .expect("aged list must succeed");
        assert_eq!(body_string(listed).await, "v1.0.0\nv1.1.0");
        let latest = latest_version(&state, &repo, module)
            .await
            .expect("aged latest must serve");
        let latest_body = body_string(latest).await;
        assert!(latest_body.contains("v1.1.0"), "got {latest_body}");
        let zip = download_zip(
            &state,
            tdh::admin_auth_ext().as_ref(),
            &repo,
            module,
            "v1.1.0",
            &ctx,
        )
        .await
        .expect("aged zip must serve");
        assert_eq!(zip.status(), StatusCode::OK);

        tdh::cleanup(&fx.pool, fx.repo_id, fx.user_id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);
    }

    #[test]
    fn test_decode_module_path() {
        assert_eq!(
            decode_module_path("github.com/!azure/go-sdk"),
            "github.com/Azure/go-sdk"
        );
        assert_eq!(
            decode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
        assert_eq!(
            decode_module_path("github.com/!big!corp/!my!lib"),
            "github.com/BigCorp/MyLib"
        );
    }

    #[test]
    fn test_encode_module_path() {
        assert_eq!(
            encode_module_path("github.com/Azure/go-sdk"),
            "github.com/!azure/go-sdk"
        );
        assert_eq!(
            encode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_parse_path_list() {
        let req = parse_path("github.com/user/repo/@v/list").unwrap();
        match req {
            GoProxyRequest::List { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected List"),
        }
    }

    #[test]
    fn test_parse_path_info() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.info").unwrap();
        match req {
            GoProxyRequest::Info { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Info"),
        }
    }

    #[test]
    fn test_parse_path_mod() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.mod").unwrap();
        match req {
            GoProxyRequest::Mod { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Mod"),
        }
    }

    #[test]
    fn test_parse_path_zip() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.zip").unwrap();
        match req {
            GoProxyRequest::Zip { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Zip"),
        }
    }

    #[test]
    fn test_parse_path_latest() {
        let req = parse_path("github.com/user/repo/@latest").unwrap();
        match req {
            GoProxyRequest::Latest { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected Latest"),
        }
    }

    #[test]
    fn test_parse_path_with_leading_slash() {
        let req = parse_path("/github.com/user/repo/@v/list").unwrap();
        match req {
            GoProxyRequest::List { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected List"),
        }
    }

    #[test]
    fn test_parse_path_encoded_module() {
        let req = parse_path("github.com/!azure/go-sdk/@v/v2.0.0.info").unwrap();
        match req {
            GoProxyRequest::Info { module, version } => {
                assert_eq!(module, "github.com/Azure/go-sdk");
                assert_eq!(version, "v2.0.0");
            }
            _ => panic!("Expected Info"),
        }
    }

    #[test]
    fn test_parse_path_invalid() {
        assert!(parse_path("github.com/user/repo/invalid").is_err());
    }

    // -----------------------------------------------------------------------
    // sumdb path parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_sumdb_lookup() {
        let req = parse_path("sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "sum.golang.org");
                assert_eq!(path, "lookup/golang.org/x/text@v0.14.0");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_tile() {
        let req = parse_path("sumdb/sum.golang.org/tile/8/0/000").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "sum.golang.org");
                assert_eq!(path, "tile/8/0/000");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_supported() {
        let req = parse_path("sumdb/sum.golang.org/supported").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "sum.golang.org");
                assert_eq!(path, "supported");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_latest() {
        let req = parse_path("sumdb/sum.golang.org/latest").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "sum.golang.org");
                assert_eq!(path, "latest");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_with_leading_slash() {
        let req = parse_path("/sumdb/sum.golang.org/lookup/example.com/pkg@v1.0.0").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "sum.golang.org");
                assert_eq!(path, "lookup/example.com/pkg@v1.0.0");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_custom_host() {
        let req = parse_path("sumdb/custom.sumdb.example.com/lookup/mod@v1.0.0").unwrap();
        match req {
            GoProxyRequest::SumDb { host, path } => {
                assert_eq!(host, "custom.sumdb.example.com");
                assert_eq!(path, "lookup/mod@v1.0.0");
            }
            _ => panic!("Expected SumDb"),
        }
    }

    #[test]
    fn test_parse_sumdb_no_path_returns_error() {
        assert!(parse_path("sumdb/sum.golang.org").is_err());
    }

    #[test]
    fn test_parse_sumdb_empty_host_returns_error() {
        assert!(parse_path("sumdb//lookup").is_err());
    }

    #[test]
    fn test_parse_sumdb_only_prefix_returns_error() {
        assert!(parse_path("sumdb/").is_err());
    }

    // -----------------------------------------------------------------------
    // build_version_info_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_info_json_basic() {
        let json = build_version_info_json("v1.2.3", "2024-01-15T10:30:00Z");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Version"], "v1.2.3");
        assert_eq!(parsed["Time"], "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_build_version_info_json_prerelease() {
        let json = build_version_info_json("v0.1.0-alpha.1", "2024-06-01T00:00:00Z");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Version"], "v0.1.0-alpha.1");
    }

    #[test]
    fn test_build_version_info_json_valid_json() {
        let json = build_version_info_json("v2.0.0", "2025-12-25T12:00:00Z");
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    // -----------------------------------------------------------------------
    // format_go_timestamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_go_timestamp() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2024, 3, 15, 9, 30, 0).unwrap();
        assert_eq!(format_go_timestamp(&dt), "2024-03-15T09:30:00Z");
    }

    #[test]
    fn test_format_go_timestamp_midnight() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(format_go_timestamp(&dt), "2025-01-01T00:00:00Z");
    }

    // -----------------------------------------------------------------------
    // build_version_list
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_list_basic() {
        let versions = vec![
            Some("v1.0.0".to_string()),
            Some("v1.1.0".to_string()),
            Some("v2.0.0".to_string()),
        ];
        assert_eq!(build_version_list(&versions), "v1.0.0\nv1.1.0\nv2.0.0");
    }

    #[test]
    fn test_build_version_list_with_nones() {
        let versions = vec![
            Some("v1.0.0".to_string()),
            None,
            Some("v2.0.0".to_string()),
            None,
        ];
        assert_eq!(build_version_list(&versions), "v1.0.0\nv2.0.0");
    }

    #[test]
    fn test_build_version_list_empty() {
        let versions: Vec<Option<String>> = vec![];
        assert_eq!(build_version_list(&versions), "");
    }

    #[test]
    fn test_build_version_list_all_none() {
        let versions: Vec<Option<String>> = vec![None, None, None];
        assert_eq!(build_version_list(&versions), "");
    }

    // -----------------------------------------------------------------------
    // build_go_zip_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_artifact_path_simple() {
        assert_eq!(
            build_go_zip_artifact_path("github.com/user/repo", "v1.0.0"),
            "github.com/user/repo/v1.0.0/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_zip_artifact_path_uppercase() {
        assert_eq!(
            build_go_zip_artifact_path("github.com/Azure/go-sdk", "v2.0.0"),
            "github.com/!azure/go-sdk/v2.0.0/v2.0.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_zip_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_storage_key_simple() {
        assert_eq!(
            build_go_zip_storage_key("github.com/user/repo", "v1.0.0"),
            "go/github.com/user/repo/v1.0.0/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_zip_storage_key_encoded() {
        assert_eq!(
            build_go_zip_storage_key("github.com/Azure/SDK", "v3.0.0"),
            "go/github.com/!azure/!s!d!k/v3.0.0/v3.0.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_mod_artifact_path / storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_mod_artifact_path() {
        assert_eq!(
            build_go_mod_artifact_path("github.com/user/repo", "v1.0.0"),
            "github.com/user/repo/v1.0.0/go.mod"
        );
    }

    #[test]
    fn test_build_go_mod_storage_key() {
        assert_eq!(
            build_go_mod_storage_key("github.com/user/repo", "v1.0.0"),
            "go/github.com/user/repo/v1.0.0/go.mod"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_artifact_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_artifact_metadata_zip() {
        let meta = build_go_artifact_metadata("github.com/user/repo", "v1.0.0", "zip");
        assert_eq!(meta["module"], "github.com/user/repo");
        assert_eq!(meta["version"], "v1.0.0");
        assert_eq!(meta["type"], "zip");
    }

    #[test]
    fn test_build_go_artifact_metadata_mod() {
        let meta = build_go_artifact_metadata("github.com/user/repo", "v2.0.0", "mod");
        assert_eq!(meta["type"], "mod");
    }

    // -----------------------------------------------------------------------
    // build_go_zip_content_disposition
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_content_disposition_simple() {
        assert_eq!(
            build_go_zip_content_disposition("github.com/user/repo", "v1.0.0"),
            "attachment; filename=\"github.com/user/repo@v1.0.0.zip\""
        );
    }

    #[test]
    fn test_build_go_zip_content_disposition_encoded() {
        assert_eq!(
            build_go_zip_content_disposition("github.com/Azure/go-sdk", "v2.0.0"),
            "attachment; filename=\"github.com/!azure/go-sdk@v2.0.0.zip\""
        );
    }

    // -----------------------------------------------------------------------
    // build_go_upstream_path
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Upstream proxy path construction for list/info/latest
    // (covers the paths built by the new proxy fallback code)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_upstream_list_path_simple() {
        assert_eq!(
            build_go_upstream_list_path("github.com/user/repo"),
            "github.com/user/repo/@v/list"
        );
    }

    #[test]
    fn test_build_go_upstream_list_path_encoded() {
        assert_eq!(
            build_go_upstream_list_path("github.com/Azure/go-sdk"),
            "github.com/!azure/go-sdk/@v/list"
        );
    }

    #[test]
    fn test_build_go_upstream_info_path_simple() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "info"),
            "github.com/user/repo/@v/v1.0.0.info"
        );
    }

    #[test]
    fn test_build_go_upstream_info_path_prerelease() {
        assert_eq!(
            build_go_upstream_path("golang.org/x/text", "v0.14.0-rc.1", "info"),
            "golang.org/x/text/@v/v0.14.0-rc.1.info"
        );
    }

    #[test]
    fn test_build_go_upstream_latest_path_simple() {
        assert_eq!(
            build_go_upstream_latest_path("github.com/user/repo"),
            "github.com/user/repo/@latest"
        );
    }

    #[test]
    fn test_build_go_upstream_latest_path_encoded() {
        assert_eq!(
            build_go_upstream_latest_path("github.com/Azure/go-sdk"),
            "github.com/!azure/go-sdk/@latest"
        );
    }

    #[test]
    fn test_version_list_merge_dedup() {
        // Simulates the merge logic used in virtual repo list_versions
        let list_a = "v1.0.0\nv1.1.0\nv2.0.0";
        let list_b = "v1.1.0\nv2.0.0\nv3.0.0";
        let merged: Vec<&str> = [list_a, list_b]
            .iter()
            .flat_map(|text| text.lines())
            .filter(|l| !l.is_empty())
            .collect();
        // The handler collects all versions (including duplicates) from members
        assert_eq!(merged.len(), 6);
        assert!(merged.contains(&"v1.0.0"));
        assert!(merged.contains(&"v3.0.0"));
    }

    #[test]
    fn test_version_list_merge_empty_inputs() {
        let lists: Vec<&str> = vec![];
        let merged: Vec<&str> = lists
            .iter()
            .flat_map(|text| text.lines())
            .filter(|l| !l.is_empty())
            .collect();
        assert!(merged.is_empty());
    }

    #[test]
    fn test_build_go_upstream_path_zip() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "zip"),
            "github.com/user/repo/@v/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_upstream_path_mod() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "mod"),
            "github.com/user/repo/@v/v1.0.0.mod"
        );
    }

    #[test]
    fn test_build_go_upstream_path_info() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "info"),
            "github.com/user/repo/@v/v1.0.0.info"
        );
    }

    #[test]
    fn test_build_go_upstream_path_encoded() {
        assert_eq!(
            build_go_upstream_path("github.com/Azure/go-sdk", "v2.0.0", "zip"),
            "github.com/!azure/go-sdk/@v/v2.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_upstream_path_encodes_version() {
        assert_eq!(
            build_go_upstream_path("github.com/Azure/go-sdk", "v2.0.0-RC1", "info"),
            "github.com/!azure/go-sdk/@v/v2.0.0-!r!c1.info"
        );
    }

    // -----------------------------------------------------------------------
    // encode_module_path round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "github.com/Azure/Go-SDK";
        let encoded = encode_module_path(original);
        let decoded = decode_module_path(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_roundtrip_no_uppercase() {
        let original = "github.com/user/repo";
        let encoded = encode_module_path(original);
        assert_eq!(encoded, original); // no change
        assert_eq!(decode_module_path(&encoded), original);
    }

    #[test]
    fn test_decode_multiple_consecutive_bangs() {
        // Two consecutive capital letters: AB -> !a!b
        assert_eq!(
            decode_module_path("github.com/!a!b/pkg"),
            "github.com/AB/pkg"
        );
    }

    // -----------------------------------------------------------------------
    // Sumdb host allowlist (SSRF prevention)
    //
    // proxy_sumdb forwards requests to https://{host}/{path} where {host}
    // comes from the URL path component sumdb/{host}/.... Without an
    // allowlist this is a textbook SSRF: an attacker can request
    // /goproxy/{repo}/sumdb/169.254.169.254/latest/meta-data/iam/...
    // and the server will fetch cloud metadata on their behalf.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_proxy_sumdb_rejects_aws_metadata_ssrf() {
        // SECURITY: must reject SSRF attempts to AWS metadata service.
        let result = proxy_sumdb("169.254.169.254", "latest/meta-data/").await;
        let response = result.expect_err("proxy_sumdb must reject SSRF; instead it allowed it");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "expected FORBIDDEN for SSRF attempt, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_proxy_sumdb_rejects_internal_service_ssrf() {
        // SECURITY: must reject SSRF attempts to internal cluster services.
        let result = proxy_sumdb("internal-postgres.svc.cluster.local", "anything").await;
        let response = result.expect_err("proxy_sumdb must reject internal-service SSRF");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_sumdb_allowlist_accepts_known_hosts() {
        assert!(is_sumdb_host_allowed("sum.golang.org"));
        assert!(is_sumdb_host_allowed("sum.golang.google.cn"));
    }

    #[test]
    fn test_sumdb_allowlist_is_case_insensitive() {
        // Hostnames are case-insensitive per RFC 1035.
        assert!(is_sumdb_host_allowed("SUM.GOLANG.ORG"));
        assert!(is_sumdb_host_allowed("Sum.Golang.Org"));
    }

    #[test]
    fn test_sumdb_allowlist_rejects_cloud_metadata_endpoints() {
        // SECURITY: cloud metadata endpoints are common SSRF targets.
        assert!(!is_sumdb_host_allowed("169.254.169.254"));
        assert!(!is_sumdb_host_allowed("metadata.google.internal"));
        assert!(!is_sumdb_host_allowed("metadata.azure.com"));
    }

    #[test]
    fn test_sumdb_allowlist_rejects_internal_services() {
        assert!(!is_sumdb_host_allowed("localhost"));
        assert!(!is_sumdb_host_allowed("127.0.0.1"));
        assert!(!is_sumdb_host_allowed(
            "internal-postgres.svc.cluster.local"
        ));
    }

    #[test]
    fn test_sumdb_allowlist_rejects_typosquatting() {
        // SECURITY: prevent attacks via near-miss domain names.
        assert!(!is_sumdb_host_allowed("sum.golang.org.evil.com"));
        assert!(!is_sumdb_host_allowed("evil.com.sum.golang.org"));
        assert!(!is_sumdb_host_allowed("sum-golang-org.evil.com"));
    }

    // -----------------------------------------------------------------------
    // Virtual Go repo over a Local member (#1782).
    //
    // Three regressions, all driven end-to-end through the goproxy router with
    // a virtual repo whose sole member is a Local repo holding a module's
    // `.mod` and `.zip` (the `.mod` is seeded FIRST so the pre-fix
    // `local_fetch_by_name_version` would return go.mod bytes for a `.zip`
    // request):
    //   1. `/@v/list`  must list the version from the local member (was 404).
    //   2. `/@v/{v}.info` must return 200 + JSON (was 404).
    //   3. `/@v/{v}.zip` must return the ZIP bytes, and `/@v/{v}.mod` the
    //      go.mod bytes — never the same artifact for both.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_virtual_go_local_member_list_info_zip_mod() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bytes::Bytes;
        use uuid::Uuid;

        // The fixture repo is the LOCAL member that physically holds the bytes.
        let Some(fx) = tdh::Fixture::setup("local", "go").await else {
            return;
        };

        let module = "example.com/qa-test-module";
        let version = "v1.0.0";
        let member = fx.repo_info("local", None);

        // Seed the .mod FIRST, then the .zip — order matters for the bug.
        let mod_bytes = b"module example.com/qa-test-module\n";
        let zip_bytes = b"PK\x03\x04 this-is-the-zip-archive-not-the-gomod";
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &member,
            &format!("go/{}/{}.mod", module, version),
            &format!("{}/{}/go.mod", module, version),
            module,
            version,
            "text/plain; charset=utf-8",
            Bytes::from_static(mod_bytes),
            fx.user_id,
        )
        .await;
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &member,
            &format!("go/{}/{}.zip", module, version),
            &format!("{}/{}/{}.zip", module, version, version),
            module,
            version,
            "application/zip",
            Bytes::from_static(zip_bytes),
            fx.user_id,
        )
        .await;

        // Build the virtual repo (shares the fixture's state/storage root so the
        // local-member fetch can read the seeded bytes back).
        let virtual_id = Uuid::new_v4();
        let virtual_key = format!("v-go-1782-{}", virtual_id.simple());
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'go'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(&*fx.storage_dir.to_string_lossy())
        .execute(&fx.pool)
        .await
        .expect("insert virtual repo");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert virtual member");

        // A hydrated Remote member must not leak its cached rows through the
        // virtual repo's Local-member aggregation. Its versions are evaluated
        // only through the source-aware upstream path, under that member's
        // own gate.
        let remote_id = Uuid::new_v4();
        let remote_key = format!("r-go-gated-{}", remote_id.simple());
        sqlx::query(
            "INSERT INTO repositories
             (id, key, name, storage_path, repo_type, format, upstream_url,
              age_gate_enabled, age_gate_min_age_days, age_gate_mode)
             VALUES ($1, $2, $2, $3, 'remote'::repository_type,
                     'go'::repository_format, 'https://proxy.golang.org',
                     true, 30, 'first_seen')",
        )
        .bind(remote_id)
        .bind(&remote_key)
        .bind(&*fx.storage_dir.to_string_lossy())
        .execute(&fx.pool)
        .await
        .expect("insert gated remote member");
        let remote = tdh::make_repo_info(
            remote_id,
            &remote_key,
            &fx.storage_dir,
            "remote",
            Some("https://proxy.golang.org"),
        );
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &remote,
            &format!("go/{module}/v9.9.9.zip"),
            &format!("{module}/v9.9.9/v9.9.9.zip"),
            module,
            "v9.9.9",
            "application/zip",
            Bytes::from_static(b"PK\x03\x04 young-remote-version"),
            fx.user_id,
        )
        .await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 2)",
        )
        .bind(virtual_id)
        .bind(remote_id)
        .execute(&fx.pool)
        .await
        .expect("insert gated remote virtual member");

        let send = |uri: String| {
            let router = fx.router_with_auth(super::router());
            async move {
                let req = Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap();
                tdh::send(router, req).await
            }
        };

        // 1. /@v/list
        let (list_status, list_body) = send(format!("/{}/{}/@v/list", virtual_key, module)).await;
        // 2. /@v/{v}.info
        let (info_status, _info_body) =
            send(format!("/{}/{}/@v/{}.info", virtual_key, module, version)).await;
        // 3a. /@v/{v}.zip
        let (zip_status, zip_resp) =
            send(format!("/{}/{}/@v/{}.zip", virtual_key, module, version)).await;
        // 3b. /@v/{v}.mod
        let (mod_status, mod_resp) =
            send(format!("/{}/{}/@v/{}.mod", virtual_key, module, version)).await;

        // Cleanup the virtual repo + members before asserting.
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&fx.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(&fx.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(remote_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert_eq!(
            list_status,
            StatusCode::OK,
            "list must resolve from the local member (#1782)"
        );
        assert_eq!(
            String::from_utf8_lossy(&list_body).trim(),
            version,
            "list must contain the member's version"
        );
        assert_eq!(
            info_status,
            StatusCode::OK,
            "info must resolve from the local member (#1782)"
        );
        assert_eq!(
            zip_status,
            StatusCode::OK,
            "zip must resolve from the local member"
        );
        assert_eq!(
            &zip_resp[..],
            zip_bytes,
            "zip endpoint must serve the .zip artifact, not go.mod (#1782)"
        );
        assert_eq!(
            mod_status,
            StatusCode::OK,
            "mod must resolve from the local member"
        );
        assert_eq!(
            &mod_resp[..],
            mod_bytes,
            "mod endpoint must serve the go.mod artifact, not the zip (#1782)"
        );
    }

    /// #3260: goproxy forwards `.info` / `.mod` upstream bodies VERBATIM —
    /// the Remote arm of `try_proxy_go_metadata`, `get_mod_file`'s Remote
    /// arm, and the Virtual arm via `resolve_virtual_metadata` — so the
    /// upstream `Content-Encoding` must be re-declared (RFC 9110 §8.4, the
    /// header describes the coding of the bytes as transferred) and
    /// `Content-Length` must describe the coded bytes actually sent (§8.6).
    /// Nothing on this path decodes (`http_client::base_client_builder`
    /// disables every codec and advertises `Accept-Encoding: identity`), so
    /// before the fix a coded upstream module document was persisted by `go`
    /// as if it were plain.
    ///
    /// Deflate (non-gzip) coded upstream plus an uncoded control in the SAME
    /// fixture — see `tdh::coded_fixture` for why gzip would prove less.
    #[tokio::test]
    async fn test_go_metadata_forwards_upstream_content_encoding_verbatim_db() {
        let Some(fx) = tdh::Fixture::setup("remote", "go").await else {
            return;
        };
        let (plain, coded, coded_mock, plain_mock) =
            tdh::coded_and_plain_upstreams("deflate", "application/json", b"go-meta-3260 ").await;

        // fx repo = the coded Remote (Remote-arm probes); a second coded
        // Remote wrapped by a Virtual (Virtual-arm probe, cold cache so the
        // upstream pass of `resolve_virtual_metadata` runs); a plain Remote +
        // Virtual pair as the uncoded control.
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &coded_mock.uri()).await;
        let (coded_member_id, _cm_key, virt_coded_id, virt_coded_key) =
            tdh::create_remote_and_virtual(&fx.pool, "go", &coded_mock.uri()).await;
        let (plain_id, plain_key, virt_plain_id, virt_plain_key) =
            tdh::create_remote_and_virtual(&fx.pool, "go", &plain_mock.uri()).await;

        // Remote arm, `.info` (`try_proxy_go_metadata`).
        let uri = format!("/{}/example.com/coded/@v/v1.0.0.info", fx.repo_key);
        let (body, headers) =
            tdh::probe_ok(tdh::router_anon(super::router(), state.clone()), uri).await;
        tdh::assert_coded_forward(&headers, &body, &coded, &plain, "remote .info");

        // Remote arm, `.mod` (`get_mod_file`).
        let uri = format!("/{}/example.com/coded/@v/v1.0.0.mod", fx.repo_key);
        let (body, headers) =
            tdh::probe_ok(tdh::router_anon(super::router(), state.clone()), uri).await;
        tdh::assert_coded_forward(&headers, &body, &coded, &plain, "remote .mod");

        // Virtual arm, `.info` (`resolve_virtual_metadata` transform).
        let uri = format!("/{}/example.com/coded/@v/v1.0.0.info", virt_coded_key);
        let (body, headers) =
            tdh::probe_ok(tdh::router_anon(super::router(), state.clone()), uri).await;
        tdh::assert_coded_forward(&headers, &body, &coded, &plain, "virtual .info");

        // Controls: uncoded upstream through the same three arms.
        for (key, what) in [
            (&plain_key, "control remote .info"),
            (&virt_plain_key, "control virtual .info"),
        ] {
            let uri = format!("/{}/example.com/coded/@v/v1.0.0.info", key);
            let (body, headers) =
                tdh::probe_ok(tdh::router_anon(super::router(), state.clone()), uri).await;
            tdh::assert_plain_forward(&headers, &body, &plain, what);
        }
        let uri = format!("/{}/example.com/coded/@v/v1.0.0.mod", plain_key);
        let (body, headers) =
            tdh::probe_ok(tdh::router_anon(super::router(), state.clone()), uri).await;
        tdh::assert_plain_forward(&headers, &body, &plain, "control remote .mod");

        for id in [virt_coded_id, coded_member_id, virt_plain_id, plain_id] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&fx.pool)
                .await;
        }
        fx.teardown().await;
    }
}
