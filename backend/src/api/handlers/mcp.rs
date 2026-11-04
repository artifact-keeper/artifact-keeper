//! MCP Registry API v0.1 (and the `/v0` alias) for hosted `mcp` repositories
//! (#5253): `/mcp/{repo_key}/v0.1/...`.
//!
//! Reads go through [`decide_mcp_serve`](crate::formats::mcp::decide_mcp_serve):
//! a held version is omitted from every listing and answers an exact read
//! with the unknown-name 404 (the reason only for callers who hold the
//! repository). Every non-2xx answer is `application/problem+json` with
//! `Cache-Control: no-store`. Publishing resolves every package to this
//! instance's own repositories (`services::mcp_packages`); nothing here opens
//! an outbound connection.

use std::collections::HashMap;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Router;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::mcp::{
    self as fmt, BackingGate, GateAudience, GateOutcome, HoldKind, McpError, PackagePin,
    PackagePolicy, RegistryState, ServeDecision, ServerStatus, StoredVersion, VersionState,
};
use crate::services::mcp_curation;
use crate::services::mcp_lint;
use crate::services::mcp_packages::{self, GateCtx};

pub const MOUNT_PREFIX: &str = "/mcp";
/// The registry API versions served, each under `/{repo_key}/{version}`.
pub const API_VERSIONS: &[&str] = &["v0.1", "v0"];

type HandlerResult = Result<Response, Response>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The route-local CORS policy of the read routes: any origin, no
/// credentials, the headers a private-registry check sends.
pub(crate) fn read_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

pub fn router() -> Router<SharedState> {
    let mut read = Router::new();
    let mut write = Router::new();
    let mut bundles = Router::new();
    for v in API_VERSIONS {
        let p = |tail: &str| format!("/:repo_key/{v}{tail}");
        read = read
            .route(&p("/servers"), get(list_servers))
            .route(&p("/servers/:ns/versions"), get(list_versions_encoded))
            .route(&p("/servers/:ns/:name/versions"), get(list_versions_split))
            .route(
                &p("/servers/:ns/versions/:version"),
                get(get_version_encoded),
            )
            .route(
                &p("/servers/:ns/:name/versions/:version"),
                get(get_version_split),
            )
            .route(&p("/ping"), get(ping))
            .route(&p("/health"), get(health))
            .route(&p("/version"), get(version))
            .merge(super::mcp_edges::read_routes(v));
        write = write
            .route(&p("/publish"), post(publish_server))
            .route(
                &p("/servers/:ns/versions/:version/status"),
                patch(update_version_status_encoded),
            )
            .route(
                &p("/servers/:ns/:name/versions/:version/status"),
                patch(update_version_status_split),
            )
            .route(
                &p("/servers/:ns/status"),
                patch(update_server_status_encoded),
            )
            .route(
                &p("/servers/:ns/:name/status"),
                patch(update_server_status_split),
            );
        // Phase 2/3 write path (#5253): bundle download on the read routes,
        // validate/edit/delete under the document limit, bundle upload
        // streamed with its own cap.
        read = read.merge(super::mcp_write::read_routes(v));
        write = write.merge(super::mcp_write::document_routes(v));
        bundles = bundles.merge(super::mcp_write::bundle_routes(v));
    }
    // `ensure_problem` sits INSIDE the read routes' CORS layer, so a refusal
    // it re-renders still carries `Access-Control-Allow-Origin`; the outer
    // one covers the write routes and the router's own fallbacks.
    read.layer(axum::middleware::map_response(ensure_problem))
        .layer(read_cors())
        .merge(write.layer(DefaultBodyLimit::max(fmt::MCP_PUBLISH_MAX_BYTES)))
        .merge(bundles)
        // Capability snapshots, diff and probe requests (#5253, C2).
        .merge(super::mcp_capabilities::router())
        .layer(axum::middleware::map_response(ensure_problem))
}

/// Outermost guard of the `/mcp/` surface (mounted in `main.rs` next to
/// [`mcp_cors_preflight`]). The shared middleware in front of the MCP router
/// (authentication, repository visibility, rate limiting, upload admission)
/// answers with its own plain-text bodies; on an `/mcp/` path this re-renders
/// such a refusal as `application/problem+json` with `Cache-Control:
/// no-store` (keeping its `WWW-Authenticate` and `Retry-After`), and gives a
/// read refusal the read routes' `Access-Control-Allow-Origin: *` so a
/// browser client can read it. Every other path passes through untouched.
pub async fn mcp_surface_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let on_surface = request.uri().path().starts_with("/mcp/");
    let read = matches!(*request.method(), Method::GET | Method::HEAD);
    let resp = next.run(request).await;
    if !on_surface {
        return resp;
    }
    let retry_after = resp.headers().get(header::RETRY_AFTER).cloned();
    let mut out = ensure_problem(resp).await;
    if let Some(v) = retry_after {
        out.headers_mut().entry(header::RETRY_AFTER).or_insert(v);
    }
    let status = out.status();
    if read
        && (status.is_client_error() || status.is_server_error())
        && !out
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    {
        // What [`read_cors`] adds to a response (an `Any` origin adds no
        // `Vary`), so a refusal from the shared middleware carries the same
        // headers as the router's own.
        out.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    out
}

/// The safety net behind "every refusal on this surface is problem+json with
/// `no-store`": a refusal that did not come from this module's own builders
/// (an extractor rejection, a method mismatch) is re-rendered.
async fn ensure_problem(resp: Response) -> Response {
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }
    let already = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/problem+json"));
    if already {
        return resp;
    }
    match status.as_u16() {
        404 => not_found(),
        405 => problem(
            405,
            "mcp_method_not_allowed",
            "This method is not supported on this route",
            serde_json::json!({}),
        ),
        413 => mcp_error(McpError::TooLarge),
        400 | 415 | 422 => problem(
            status.as_u16(),
            "mcp_bad_request",
            "The request is malformed",
            serde_json::json!({}),
        ),
        _ => reproblem(resp),
    }
}

/// Answer a CORS preflight for an MCP read route before the instance-wide
/// CORS layer (same-origin by default) refuses it: that layer answers every
/// preflight itself, so the route-local [`read_cors`] never sees one. Mounted
/// outside the global CORS layer in `main.rs`.
pub async fn mcp_cors_preflight(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if is_mcp_preflight(request.method(), request.uri().path(), request.headers()) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET,OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "authorization,content-type",
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "600")
            .body(Body::empty())
            .unwrap();
    }
    next.run(request).await
}

/// A preflight (`OPTIONS` + `Access-Control-Request-Method: GET`) for a path
/// under [`MOUNT_PREFIX`].
pub fn is_mcp_preflight(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS
        && path.starts_with("/mcp/")
        && headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|m| m.eq_ignore_ascii_case("GET"))
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

fn with_refusal_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// An RFC 9457 refusal with AK's machine code.
pub fn problem(status: u16, code: &str, detail: &str, extra: serde_json::Value) -> Response {
    let body = fmt::problem_body(status, code, detail, extra);
    refusal_bytes(status, serde_json::to_vec(&body).unwrap_or_default())
}

pub(crate) fn refusal_bytes(status: u16, body: Vec<u8>) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    with_refusal_headers((status, body).into_response())
}

/// The unknown-name answer, byte for byte the reader-only refusal.
pub fn not_found() -> Response {
    refusal_bytes(404, fmt::NOT_FOUND_BODY.as_bytes().to_vec())
}

pub(crate) fn mcp_error(e: McpError) -> Response {
    if let McpError::Internal(cause) | McpError::Misconfigured(cause) = &e {
        tracing::error!(error = %cause, code = e.code(), "MCP registry request failed");
    }
    problem(e.status(), e.code(), &e.detail(), serde_json::json!({}))
}

pub(crate) fn internal(e: impl std::fmt::Display) -> Response {
    mcp_error(McpError::Internal(e.to_string()))
}

/// Re-render a plain refusal from a shared gate (auth, hosted-only,
/// promotion-only) as problem+json, keeping its status and challenge.
pub(crate) fn reproblem(resp: Response) -> Response {
    let status = resp.status();
    let (code, detail) = match status.as_u16() {
        401 => ("mcp_unauthorized", "Authentication required"),
        403 => (
            "mcp_forbidden",
            "This credential may not write to this repository",
        ),
        405 => (
            "mcp_read_only",
            "This repository does not accept publishes (remote repository)",
        ),
        409 => (
            "mcp_promotion_only",
            "This repository only accepts promoted artifacts",
        ),
        400 => (
            "mcp_read_only",
            "This repository does not accept publishes (virtual repository)",
        ),
        429 => ("mcp_rate_limited", "Too many requests; retry later"),
        503 => ("mcp_unavailable", "Service temporarily unavailable"),
        _ => ("mcp_internal_error", "internal error"),
    };
    let mut out = problem(status.as_u16(), code, detail, serde_json::json!({}));
    if let Some(challenge) = resp.headers().get(header::WWW_AUTHENTICATE) {
        out.headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge.clone());
    }
    out
}

pub(crate) fn json_ok(status: StatusCode, value: &serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(value).unwrap_or_default(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Shared lookups
// ---------------------------------------------------------------------------

/// The MCP repository named by the path. Any miss (unknown key, another
/// format) is the unknown-name 404, so the surface does not tell an MCP
/// repository from any other key.
pub(crate) async fn resolve_mcp_repo(db: &PgPool, key: &str) -> Result<RepoInfo, Response> {
    match proxy_helpers::resolve_repo_by_key(db, key, &["mcp"], "an MCP registry").await {
        Ok(repo) => Ok(repo),
        Err(resp) if resp.status().is_server_error() => Err(reproblem(resp)),
        Err(_) => Err(not_found()),
    }
}

/// Hosted and Remote MCP repositories serve their stored rows (a Remote's
/// are the upstream entries its sync ingested). A Virtual repository answers
/// 501 until its read path lands.
pub(crate) fn reject_if_not_hosted_read(repo: &RepoInfo) -> Result<(), Response> {
    if matches!(repo.repo_type.as_str(), "local" | "staging" | "remote") {
        return Ok(());
    }
    Err(problem(
        501,
        "mcp_not_implemented",
        "Virtual MCP registries are not available in this release",
        serde_json::json!({}),
    ))
}

/// `ns/name` from either route spelling: the encoded single segment
/// (`com.acme%2Fweather`, decoded by the extractor) or the literal slash.
pub fn server_name(ns: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!("{ns}/{n}"),
        None => ns.to_string(),
    }
}

/// Whether `caller` may read why a version is held.
pub(crate) async fn audience(
    db: &PgPool,
    auth: Option<&AuthExtension>,
    repo_id: Uuid,
) -> GateAudience {
    let Some(ext) = auth else {
        return GateAudience::ReaderOnly;
    };
    match crate::api::handlers::quarantine::caller_passes_reason_gate(db, ext, repo_id).await {
        Ok(true) => GateAudience::ReasonGated,
        _ => GateAudience::ReaderOnly,
    }
}

/// One stored server version row.
#[derive(Debug, Clone)]
pub(crate) struct VersionRow {
    pub(crate) artifact_id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) checksum: String,
    pub(crate) quarantine_status: Option<String>,
    pub(crate) quarantine_until: Option<DateTime<Utc>>,
    pub(crate) stored: StoredVersion,
}

pub(crate) type RawRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    serde_json::Value,
);

pub(crate) fn rows_from_raw(raw: Vec<RawRow>) -> Vec<VersionRow> {
    raw.into_iter()
        .filter_map(|(artifact_id, repository_id, name, version, checksum, qs, qu, meta)| {
            let stored = StoredVersion::from_metadata(&meta);
            if stored.is_none() {
                tracing::warn!(artifact_id = %artifact_id, "MCP server version has no readable metadata; skipped");
            }
            Some(VersionRow {
                artifact_id,
                repository_id,
                name,
                version,
                checksum,
                quarantine_status: qs,
                quarantine_until: qu,
                stored: stored?,
            })
        })
        .collect()
}

pub(crate) const ROW_COLUMNS: &str =
    "a.id, a.repository_id, a.name, a.version, a.checksum_sha256, a.quarantine_status, \
     a.quarantine_until, m.metadata";

/// Every live version of `name` in `repo_id`, text-ordered by version.
pub(crate) async fn versions_of<'e>(
    db: impl sqlx::PgExecutor<'e>,
    repo_id: Uuid,
    name: &str,
) -> Result<Vec<VersionRow>, Response> {
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.name = $2 AND a.is_deleted = false \
           AND m.format = 'mcp' \
         ORDER BY a.version"
    );
    let raw: Vec<RawRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .bind(name)
        .fetch_all(db)
        .await
        .map_err(internal)?;
    Ok(rows_from_raw(raw))
}

/// The server.json artifact's own hold, from the download gate.
async fn own_hold(db: &PgPool, artifact_id: Uuid) -> Result<Option<HoldKind>, ()> {
    match crate::services::quarantine_service::enforce_download_gate(db, artifact_id).await {
        Ok(()) => Ok(None),
        Err(e) => match mcp_packages::outcome_for_gate_error(&e) {
            GateOutcome::Quarantine => Ok(Some(HoldKind::Quarantine)),
            GateOutcome::ScanPolicy => Ok(Some(HoldKind::ScanPolicy)),
            _ => Err(()),
        },
    }
}

pub(crate) fn instance_url(base: &str, repo_key: &str, name: &str, version: &str) -> String {
    format!(
        "{}/mcp/{}/v0.1/servers/{}/versions/{}",
        base.trim_end_matches('/'),
        repo_key,
        urlencoding::encode(name),
        urlencoding::encode(version)
    )
}

/// The version's repository-level hold (deny list, Remote curation, server
/// age gate), `Err` when it cannot be evaluated.
async fn repo_hold(ctx: GateCtx<'_>, row: &VersionRow) -> Result<Option<HoldKind>, ()> {
    let policy = mcp_curation::load_serve_policy(ctx.db, row.repository_id).await?;
    let holds = mcp_curation::repo_holds(
        ctx,
        &policy,
        row.repository_id,
        &[(row.artifact_id, &row.name, &row.version)],
    )
    .await?;
    Ok(holds.get(&row.artifact_id).copied())
}

/// Decide one row for `audience`, evaluating the version's own hold (the
/// server.json artifact's, then the repository-level one) and every backing
/// gate. The one per-row serve decision of the MCP surface; a Virtual
/// repository decides each member's rows with it.
pub(crate) async fn decide_row(
    ctx: GateCtx<'_>,
    row: &VersionRow,
    policy_now: PackagePolicy,
    include_deleted: bool,
    audience: GateAudience,
    instance: String,
) -> ServeDecision {
    let mut gates: Vec<BackingGate> = Vec::new();
    let own = match own_hold(ctx.db, row.artifact_id).await {
        Ok(h) => h,
        Err(()) => {
            gates.push(BackingGate {
                package: "server.json".into(),
                outcome: GateOutcome::Unavailable,
            });
            None
        }
    };
    let own = match own {
        Some(h) => Some(h),
        None => repo_hold(ctx, row).await.unwrap_or_else(|()| {
            gates.push(BackingGate {
                package: "curation".into(),
                outcome: GateOutcome::Unavailable,
            });
            None
        }),
    };
    gates.extend(mcp_packages::backing_gates(ctx, &row.stored, policy_now).await);
    // A version whose packages are still being filled is held as
    // `resolving` (its pending packages have no pin yet).
    let own = own.or(row.stored.resolving.then_some(HoldKind::Resolving));
    let state = VersionState {
        name: row.name.clone(),
        version: row.version.clone(),
        status: row.stored.registry.status,
        own_hold: own,
        include_deleted,
        instance,
    };
    fmt::decide_mcp_serve(&state, &gates, audience)
}

/// The served entry of one row. `is_latest` is whether the row is its
/// server's newest servable version now ([`newest_servable`]), not the
/// stored flag: the stored flag ignores holds, so a held newer version would
/// otherwise leave no entry marked latest while `/versions/latest` answers
/// with this one.
pub(crate) fn served_entry(
    row: &VersionRow,
    repo: &RepoInfo,
    base: &str,
    is_latest: bool,
) -> serde_json::Value {
    let server = fmt::rewrite_packages_for_serve(
        &row.stored.server,
        &row.stored.pins,
        row.stored.policy,
        base,
    );
    let mut registry = row.stored.registry.clone();
    registry.is_latest = is_latest;
    let mut source = serde_json::json!({
        "repository": repo.key,
        "artifactId": row.artifact_id,
        "sha256": row.checksum,
        "packagePolicy": row.stored.policy.as_str(),
    });
    let upstream = row.stored.upstream.as_ref();
    source["origin"] = fmt::served_origin(upstream).into();
    source["upstreamVerified"] = fmt::upstream_verified(upstream).into();
    if let Some(url) = upstream.and_then(|u| u.get("origin")) {
        source["kind"] = "upstream".into();
        source["upstreamUrl"] = url.clone();
    }
    fmt::envelope(server, &registry, source)
}

/// The repository's package policy now (a read failure is fail-closed: the
/// versions are gated as `own-repos`).
pub(crate) async fn current_policy(db: &PgPool, repo_id: Uuid) -> PackagePolicy {
    mcp_packages::load_settings(db, repo_id)
        .await
        .map(|s| s.policy)
        .unwrap_or(PackagePolicy::OwnRepos)
}

// ---------------------------------------------------------------------------
// Refusal audit (sampled)
// ---------------------------------------------------------------------------

const REFUSAL_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether a refusal of `(artifact, caller)` should be audited now: at most
/// once per [`REFUSAL_AUDIT_WINDOW`] per replica.
fn refusal_audit_due(artifact_id: Uuid, caller: &str) -> bool {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static SEEN: OnceLock<Mutex<HashMap<(Uuid, String), Instant>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    if seen.len() > 10_000 {
        seen.retain(|_, at| now.duration_since(*at) < REFUSAL_AUDIT_WINDOW);
    }
    let key = (artifact_id, caller.to_string());
    match seen.get(&key) {
        Some(at) if now.duration_since(*at) < REFUSAL_AUDIT_WINDOW => false,
        _ => {
            seen.insert(key, now);
            true
        }
    }
}

pub(crate) fn audit_refusal(
    db: &PgPool,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    row: &VersionRow,
    hold_class: &str,
    audience: GateAudience,
) {
    let caller = auth
        .map(|a| a.user_id.to_string())
        .unwrap_or_else(|| "anonymous".to_string());
    if !refusal_audit_due(row.artifact_id, &caller) {
        return;
    }
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    let mut entry = AuditEntry::new(
        AuditAction::McpServerDownloadRefused,
        ResourceType::Artifact,
    )
    .resource(row.artifact_id)
    .resource_name(format!("{}@{}", row.name, row.version))
    .with_request_client_ip()
    .details(serde_json::json!({
        "repository": repo.key,
        "repository_id": repo.id,
        "server": row.name,
        "version": row.version,
        "hold_class": hold_class,
        "reason_disclosed": audience == GateAudience::ReasonGated,
        "anonymous": auth.is_none(),
    }));
    if let Some(a) = auth {
        entry = entry.user(a.user_id);
    }
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
}

/// `MCP_GATE_UNAVAILABLE`: a serve gate could not be evaluated and the
/// surface failed closed. Sampled like the refusal audit, keyed on the
/// version (or, for a listing batch, the repository).
fn audit_gate_unavailable(
    db: &PgPool,
    repository_id: Uuid,
    subject: Uuid,
    details: serde_json::Value,
) {
    if !refusal_audit_due(subject, "gate-unavailable") {
        return;
    }
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    let mut details = details;
    details["repository_id"] = repository_id.to_string().into();
    let entry = AuditEntry::new(AuditAction::McpGateUnavailable, ResourceType::Repository)
        .resource(repository_id)
        .details(details);
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
}

/// A listing batch was omitted because a gate could not be evaluated.
fn listing_gate_unavailable(db: &PgPool, repository_id: Uuid) {
    tracing::warn!(repository_id = %repository_id, "MCP listing gate unavailable; batch omitted");
    audit_gate_unavailable(
        db,
        repository_id,
        repository_id,
        serde_json::json!({"surface": "listing"}),
    );
}

// ---------------------------------------------------------------------------
// GET /servers
// ---------------------------------------------------------------------------

/// The parsed `GET /servers` query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQuery {
    pub limit: i64,
    pub cursor: Option<(String, String)>,
    pub search: Option<String>,
    pub version: Option<String>,
    pub updated_since: Option<DateTime<Utc>>,
    pub include_deleted: bool,
}

fn parse_bool(key: &str, v: &str) -> Result<bool, McpError> {
    match v {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(McpError::invalid_query(key, "must be true or false")),
    }
}

/// Parse the listing query with upstream's rules: `limit` 1.. (default 30,
/// values over 100 clamp, 0/negative/non-numeric 400), `search` >= 3
/// characters (422), `updated_since` RFC 3339 (400) and forcing
/// `include_deleted` (an explicit `include_deleted=false` with it is 400).
pub fn parse_list_query(q: &HashMap<String, String>) -> Result<ListQuery, McpError> {
    let limit = match q.get("limit").map(|s| s.trim()) {
        None | Some("") => fmt::DEFAULT_LIMIT,
        Some(s) => match s.parse::<i64>() {
            Ok(n) if n >= 1 => n.min(fmt::MAX_LIMIT),
            _ => {
                return Err(McpError::invalid_query(
                    "limit",
                    "must be a positive integer",
                ))
            }
        },
    };
    let cursor = match q.get("cursor").filter(|c| !c.is_empty()) {
        Some(c) => Some(fmt::decode_cursor(c)?),
        None => None,
    };
    let search = match q.get("search").filter(|s| !s.is_empty()) {
        Some(s) if s.chars().count() < 3 => return Err(McpError::SearchTooShort),
        Some(s) if s.chars().count() > 200 => {
            return Err(McpError::invalid_query(
                "search",
                "must be at most 200 characters",
            ))
        }
        Some(s) => Some(s.clone()),
        None => None,
    };
    let updated_since = match q.get("updated_since").filter(|s| !s.is_empty()) {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|_| {
                    McpError::invalid_query("updated_since", "must be an RFC 3339 timestamp")
                })?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    let include_deleted = match q.get("include_deleted") {
        Some(v) => {
            let b = parse_bool("include_deleted", v)?;
            if !b && updated_since.is_some() {
                return Err(McpError::invalid_query(
                    "include_deleted",
                    "updated_since always includes deleted versions",
                ));
            }
            b
        }
        None => updated_since.is_some(),
    };
    let version = q.get("version").filter(|v| !v.is_empty()).cloned();
    Ok(ListQuery {
        limit,
        cursor,
        search,
        version,
        updated_since,
        include_deleted,
    })
}

/// One keyset batch of listing candidates, with what the scan read: rows
/// whose metadata cannot be parsed are dropped from `rows`, so paging decides
/// on `raw_len` and resumes after `last`.
pub(crate) struct ListingBatch {
    pub(crate) rows: Vec<VersionRow>,
    pub(crate) raw_len: usize,
    pub(crate) last: Option<(String, String)>,
}

pub(crate) async fn fetch_listing_batch(
    db: &PgPool,
    repo_id: Uuid,
    q: &ListQuery,
    after: Option<&(String, String)>,
    batch: i64,
) -> Result<ListingBatch, Response> {
    let pattern = q
        .search
        .as_deref()
        .map(|s| format!("%{}%", super::escape_like_literal(s)));
    let exact_version = q.version.as_deref().filter(|v| *v != "latest");
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcp' \
           AND ($2::text IS NULL OR a.name ILIKE $2 ESCAPE '\\') \
           AND ($3::text IS NULL OR a.version = $3) \
           AND ($4::timestamptz IS NULL \
                OR (m.metadata->'registry'->>'updatedAt')::timestamptz >= $4) \
           AND ($5 OR COALESCE(m.metadata->'registry'->>'status', 'active') <> 'deleted') \
           AND ($6::text IS NULL OR (a.name, a.version) > ($6, $7)) \
         ORDER BY a.name, a.version LIMIT $8"
    );
    let raw: Vec<RawRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .bind(pattern)
        .bind(exact_version)
        .bind(q.updated_since)
        .bind(q.include_deleted)
        .bind(after.map(|c| c.0.clone()))
        .bind(after.map(|c| c.1.clone()).unwrap_or_default())
        .bind(batch)
        .fetch_all(db)
        .await
        .map_err(internal)?;
    let raw_len = raw.len();
    let last = raw.last().map(|r| (r.2.clone(), r.3.clone()));
    Ok(ListingBatch {
        rows: rows_from_raw(raw),
        raw_len,
        last,
    })
}

/// The rows of `rows` the reader-only gate admits, in order. A gate that
/// cannot be evaluated omits the whole batch (fail closed). The listing half
/// of [`decide_row`]: a Virtual repository filters each member's rows with
/// it.
pub(crate) async fn servable(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: Vec<VersionRow>,
    policy_now: PackagePolicy,
) -> Vec<VersionRow> {
    if rows.is_empty() {
        return rows;
    }
    let listing: Vec<mcp_packages::ListingRow> = rows
        .iter()
        .map(|r| mcp_packages::ListingRow {
            artifact_id: r.artifact_id,
            quarantine_status: r.quarantine_status.clone(),
            quarantine_until: r.quarantine_until,
            stored: r.stored.clone(),
        })
        .collect();
    let refused = match mcp_packages::listing_refusals(ctx, repo_id, &listing, policy_now).await {
        Ok(refused) => refused,
        Err(mcp_packages::GateUnavailable) => {
            listing_gate_unavailable(ctx.db, repo_id);
            return Vec::new();
        }
    };
    let rows: Vec<VersionRow> = rows
        .into_iter()
        .filter(|r| !refused.contains(&r.artifact_id))
        .collect();
    let held = match mcp_curation::load_serve_policy(ctx.db, repo_id).await {
        Ok(policy) => {
            let keys: Vec<mcp_curation::ServeRow<'_>> = rows
                .iter()
                .map(|r| (r.artifact_id, r.name.as_str(), r.version.as_str()))
                .collect();
            mcp_curation::repo_holds(ctx, &policy, repo_id, &keys).await
        }
        Err(()) => Err(()),
    };
    match held {
        Ok(held) => rows
            .into_iter()
            .filter(|r| !held.contains_key(&r.artifact_id))
            .collect(),
        Err(()) => {
            listing_gate_unavailable(ctx.db, repo_id);
            Vec::new()
        }
    }
}

/// How many of a server's newest candidates `latest` evaluates before it
/// gives up on the server (a server whose newest versions are all held).
const MAX_LATEST_WALK: usize = 100;
const LATEST_WALK_CHUNK: usize = 10;

/// A server's newest servable version (by [`fmt::latest_order`], `deleted`
/// excluded) among `rows` (all of its versions), and how many rows the
/// reader-only gate evaluated to find it. Rows in `known` are already known
/// servable (they passed the gate in this request) and are not re-evaluated.
pub(crate) async fn newest_servable(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: Vec<VersionRow>,
    known: &std::collections::HashSet<Uuid>,
    policy_now: PackagePolicy,
) -> (Option<VersionRow>, usize) {
    let candidates = latest_candidates(rows);
    let mut evaluated = 0;
    for chunk in candidates
        .chunks(LATEST_WALK_CHUNK)
        .take(MAX_LATEST_WALK / LATEST_WALK_CHUNK)
    {
        let unknown: Vec<VersionRow> = chunk
            .iter()
            .filter(|r| !known.contains(&r.artifact_id))
            .cloned()
            .collect();
        evaluated += unknown.len();
        let ok: std::collections::HashSet<Uuid> = servable(ctx, repo_id, unknown, policy_now)
            .await
            .into_iter()
            .map(|r| r.artifact_id)
            .collect();
        if let Some(row) = chunk
            .iter()
            .find(|r| known.contains(&r.artifact_id) || ok.contains(&r.artifact_id))
        {
            return (Some(row.clone()), evaluated);
        }
    }
    (None, evaluated)
}

/// The artifact ids among `rows` (servable rows of one response) that are
/// their server's newest servable version.
async fn latest_ids(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: &[VersionRow],
    policy_now: PackagePolicy,
) -> Result<std::collections::HashSet<Uuid>, Response> {
    let known: std::collections::HashSet<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    let names: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    let mut out = std::collections::HashSet::new();
    for name in names {
        let all = versions_of(ctx.db, repo_id, name).await?;
        if let (Some(row), _) = newest_servable(ctx, repo_id, all, &known, policy_now).await {
            out.insert(row.artifact_id);
        }
    }
    Ok(out)
}

/// Serve `rows` (all servable) with each one's `isLatest` computed now.
async fn served_entries(
    ctx: GateCtx<'_>,
    repo: &RepoInfo,
    base: &str,
    rows: &[VersionRow],
    policy_now: PackagePolicy,
) -> Result<Vec<serde_json::Value>, Response> {
    let latest = latest_ids(ctx, repo.id, rows, policy_now).await?;
    Ok(rows
        .iter()
        .map(|r| served_entry(r, repo, base, latest.contains(&r.artifact_id)))
        .collect())
}

async fn list_servers(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let repo = resolve_mcp_repo(&state.db, &repo_key).await?;
    if repo.repo_type == "virtual" {
        return super::mcp_virtual::list_servers(
            &state,
            auth.as_ref(),
            &repo,
            &query,
            base.as_str(),
        )
        .await;
    }
    reject_if_not_hosted_read(&repo)?;
    let q = parse_list_query(&query).map_err(mcp_error)?;
    let policy_now = current_policy(&state.db, repo.id).await;
    let ctx = GateCtx::of(&state, false);
    let (entries, next) = if q.version.as_deref() == Some("latest") {
        list_latest(ctx, &repo, &q, policy_now, base.as_str()).await?
    } else {
        list_versions_page(ctx, &repo, &q, policy_now, base.as_str()).await?
    };
    Ok(json_ok(StatusCode::OK, &fmt::list_envelope(entries, next)))
}

/// Upper bound on the rows one listing request reads and gates, so a
/// repository whose rows are almost all held cannot turn one request into a
/// full scan. A scan the bound stops still answers a resume cursor.
pub(crate) const MAX_LISTING_ROWS: usize = 1000;

async fn list_versions_page(
    ctx: GateCtx<'_>,
    repo: &RepoInfo,
    q: &ListQuery,
    policy_now: PackagePolicy,
    base: &str,
) -> Result<(Vec<serde_json::Value>, Option<String>), Response> {
    let want = q.limit as usize;
    let mut out: Vec<VersionRow> = Vec::new();
    let mut after = q.cursor.clone();
    let mut read = 0usize;
    let exhausted = loop {
        let batch = fetch_listing_batch(ctx.db, repo.id, q, after.as_ref(), q.limit + 1).await?;
        read += batch.raw_len;
        let exhausted = (batch.raw_len as i64) <= q.limit;
        if let Some(last) = batch.last {
            after = Some(last);
        }
        out.extend(servable(ctx, repo.id, batch.rows, policy_now).await);
        if out.len() > want || exhausted || read >= MAX_LISTING_ROWS {
            break exhausted;
        }
    };
    let next = if out.len() > want {
        let last = &out[want - 1];
        Some(fmt::encode_cursor(&last.name, &last.version))
    } else if !exhausted {
        // The row bound stopped the scan (almost every row held): resume
        // after the last row read instead of presenting a short last page.
        after.as_ref().map(|(n, v)| fmt::encode_cursor(n, v))
    } else {
        None
    };
    out.truncate(want);
    Ok((
        served_entries(ctx, repo, base, &out, policy_now).await?,
        next,
    ))
}

/// Server names of a listing, in order, after `name_after`.
pub(crate) async fn fetch_server_names(
    db: &PgPool,
    repo_id: Uuid,
    search: Option<&str>,
    name_after: Option<&str>,
    limit: i64,
) -> Result<Vec<String>, Response> {
    let pattern = search.map(|s| format!("%{}%", super::escape_like_literal(s)));
    sqlx::query_scalar(
        "SELECT a.name FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcp' \
           AND ($2::text IS NULL OR a.name ILIKE $2 ESCAPE '\\') \
           AND ($3::text IS NULL OR a.name > $3) \
         GROUP BY a.name ORDER BY a.name LIMIT $4",
    )
    .bind(repo_id)
    .bind(pattern)
    .bind(name_after)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(internal)
}

/// Gate evaluations one `version=latest` listing spends before it answers
/// with a resume cursor (each server costs at least one).
pub(crate) const MAX_LATEST_BUDGET: usize = 1000;

/// `version=latest`: one entry per server, its newest servable version.
/// The newest is picked from all of a server's versions first; only then do
/// `updated_since` (on the picked version) apply, so an older version is
/// never presented as latest because the newest was not updated recently.
/// The cursor names the last server decided; work is bounded by
/// [`MAX_LATEST_BUDGET`] and a stopped scan answers a resume cursor.
async fn list_latest(
    ctx: GateCtx<'_>,
    repo: &RepoInfo,
    q: &ListQuery,
    policy_now: PackagePolicy,
    base: &str,
) -> Result<(Vec<serde_json::Value>, Option<String>), Response> {
    let want = q.limit as usize;
    let mut out: Vec<VersionRow> = Vec::new();
    let mut name_after = q.cursor.as_ref().map(|(name, _)| name.clone());
    let mut last_done: Option<String> = None;
    let mut budget = MAX_LATEST_BUDGET;
    let mut more = false;
    let none = std::collections::HashSet::new();
    'scan: loop {
        let names = fetch_server_names(
            ctx.db,
            repo.id,
            q.search.as_deref(),
            name_after.as_deref(),
            (want + 1) as i64,
        )
        .await?;
        let names_exhausted = names.len() <= want;
        for name in names {
            if out.len() == want || budget == 0 {
                more = true;
                break 'scan;
            }
            let all = versions_of(ctx.db, repo.id, &name).await?;
            let (picked, evaluated) = newest_servable(ctx, repo.id, all, &none, policy_now).await;
            budget = budget.saturating_sub(evaluated.max(1));
            if let Some(row) = picked.filter(|r| {
                q.updated_since
                    .is_none_or(|since| r.stored.registry.updated_at >= since)
            }) {
                out.push(row);
            }
            last_done = Some(name);
        }
        if names_exhausted {
            break;
        }
        name_after = last_done.clone();
    }
    let next = if more {
        last_done.as_deref().map(|n| fmt::encode_cursor(n, "-"))
    } else {
        None
    };
    Ok((
        out.iter()
            .map(|r| served_entry(r, repo, base, true))
            .collect(),
        next,
    ))
}

// ---------------------------------------------------------------------------
// GET /servers/{name}/versions[/{version}]
// ---------------------------------------------------------------------------

pub(crate) fn include_deleted_param(q: &HashMap<String, String>) -> Result<bool, Response> {
    match q.get("include_deleted") {
        Some(v) => parse_bool("include_deleted", v).map_err(mcp_error),
        None => Ok(false),
    }
}

async fn list_versions_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    list_versions_impl(
        &state,
        auth.as_ref(),
        &repo_key,
        &server_name(&ns, None),
        &q,
        base.as_str(),
    )
    .await
}

async fn list_versions_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name)): Path<(String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let name = server_name(&ns, Some(&name));
    list_versions_impl(&state, auth.as_ref(), &repo_key, &name, &q, base.as_str()).await
}

async fn list_versions_impl(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo_key: &str,
    name: &str,
    q: &HashMap<String, String>,
    base: &str,
) -> HandlerResult {
    let repo = resolve_mcp_repo(&state.db, repo_key).await?;
    let include_deleted = include_deleted_param(q)?;
    if repo.repo_type == "virtual" {
        return super::mcp_virtual::list_versions(state, auth, &repo, name, include_deleted, base)
            .await;
    }
    reject_if_not_hosted_read(&repo)?;
    let served = servable_versions(state, &repo, name, include_deleted).await?;
    if served.is_empty() {
        return Err(not_found());
    }
    // Every servable version is in hand: the newest of them is the latest.
    let latest = latest_candidates(served.clone())
        .first()
        .map(|r| r.artifact_id);
    let entries = served
        .iter()
        .map(|r| served_entry(r, &repo, base, Some(r.artifact_id) == latest))
        .collect();
    Ok(json_ok(StatusCode::OK, &fmt::list_envelope(entries, None)))
}

/// Every servable version of `name` in `repo` (the reader-only listing
/// gate), in version-text order: the per-repository core of
/// `GET /servers/{name}/versions`, shared with the Virtual read path.
pub(crate) async fn servable_versions(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    include_deleted: bool,
) -> Result<Vec<VersionRow>, Response> {
    let policy_now = current_policy(&state.db, repo.id).await;
    let ctx = GateCtx::of(state, false);
    let mut rows: Vec<VersionRow> = versions_of(&state.db, repo.id, name)
        .await?
        .into_iter()
        .filter(|r| include_deleted || r.stored.registry.status != ServerStatus::Deleted)
        .collect();
    // Bounded work: at most the newest MAX_LISTING_ROWS versions are gated
    // and listed (in version-text order, as before).
    if rows.len() > MAX_LISTING_ROWS {
        rows.sort_by(|a, b| {
            fmt::latest_order(
                (b.version.as_str(), Some(b.stored.registry.published_at)),
                (a.version.as_str(), Some(a.stored.registry.published_at)),
            )
        });
        rows.truncate(MAX_LISTING_ROWS);
        rows.sort_by(|a, b| a.version.cmp(&b.version));
    }
    Ok(servable(ctx, repo.id, rows, policy_now).await)
}

async fn get_version_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, version)): Path<(String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let name = server_name(&ns, None);
    get_version_impl(
        &state,
        auth.as_ref(),
        &repo_key,
        &name,
        &version,
        &q,
        base.as_str(),
    )
    .await
}

async fn get_version_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name, version)): Path<(String, String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let name = server_name(&ns, Some(&name));
    get_version_impl(
        &state,
        auth.as_ref(),
        &repo_key,
        &name,
        &version,
        &q,
        base.as_str(),
    )
    .await
}

/// Candidates for `latest`, newest first: every non-deleted version.
pub(crate) fn latest_candidates(mut rows: Vec<VersionRow>) -> Vec<VersionRow> {
    rows.retain(|r| r.stored.registry.status != ServerStatus::Deleted);
    rows.sort_by(|a, b| {
        fmt::latest_order(
            (b.version.as_str(), Some(b.stored.registry.published_at)),
            (a.version.as_str(), Some(a.stored.registry.published_at)),
        )
    });
    rows
}

async fn get_version_impl(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo_key: &str,
    name: &str,
    version: &str,
    q: &HashMap<String, String>,
    base: &str,
) -> HandlerResult {
    let repo = resolve_mcp_repo(&state.db, repo_key).await?;
    let include_deleted = include_deleted_param(q)?;
    if repo.repo_type == "virtual" {
        return super::mcp_virtual::get_version(
            state,
            auth,
            &repo,
            name,
            version,
            include_deleted,
            base,
        )
        .await;
    }
    reject_if_not_hosted_read(&repo)?;
    let is_latest = version == "latest";
    let audience = audience(&state.db, auth, repo.id).await;
    match walk_candidates(
        state,
        auth,
        &repo,
        name,
        version,
        include_deleted,
        audience,
        base,
    )
    .await?
    {
        CandidateWalk::Served { row, all } => {
            // `latest` answers the newest servable version by construction;
            // an exact version is latest when no newer version is servable
            // (the reader-only listing gate).
            let latest = is_latest || is_newest_servable(state, &repo, &row, all).await;
            let mut entry = served_entry(&row, &repo, base, latest);
            super::mcp_write::ticket_bundle_urls(state, auth, &row.stored, &mut entry, base).await;
            Ok(json_ok(StatusCode::OK, &entry))
        }
        CandidateWalk::Refused(resp) => {
            // `latest` with nothing servable is the plain unknown-name answer
            // for a reader; a repository holder learns why the newest
            // version is held.
            if is_latest && audience == GateAudience::ReaderOnly {
                return Err(not_found());
            }
            Err(resp)
        }
        CandidateWalk::NotFound => Err(not_found()),
    }
}

/// What one repository answers for an exact or `latest` read of `name`.
pub(crate) enum CandidateWalk {
    /// A candidate passed every gate; `all` is every version of the server
    /// (for the `isLatest` computation).
    Served {
        row: VersionRow,
        all: Vec<VersionRow>,
    },
    /// Every candidate is held: the first refusal for `audience` (or the
    /// fail-closed 503 of an unevaluable gate), already audited.
    Refused(Response),
    /// No version of that name (or no candidate for `latest`).
    NotFound,
}

/// The per-repository detail decision: evaluate the candidates of
/// `name`@`version` (`latest`: every non-deleted version, newest first) in
/// `repo` with [`decide_row`] until one is servable. An unevaluable gate on a
/// newer candidate fails closed (503), never falling back past a version that
/// may be servable. Shared by the hosted, Remote and Virtual read paths, so a
/// hold expressed in [`decide_row`] applies to every repository type.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn walk_candidates(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name: &str,
    version: &str,
    include_deleted: bool,
    audience: GateAudience,
    base: &str,
) -> Result<CandidateWalk, Response> {
    let rows = versions_of(&state.db, repo.id, name).await?;
    let candidates: Vec<VersionRow> = if version == "latest" {
        latest_candidates(rows.clone())
    } else {
        rows.iter()
            .filter(|r| r.version == version)
            .cloned()
            .collect()
    };
    if candidates.is_empty() {
        return Ok(CandidateWalk::NotFound);
    }
    let policy_now = current_policy(&state.db, repo.id).await;
    let ctx = GateCtx::of(state, true);
    let mut first_refusal: Option<(Response, &VersionRow, &'static str)> = None;
    for row in &candidates {
        let instance = instance_url(base, &repo.key, &row.name, &row.version);
        match decide_row(ctx, row, policy_now, include_deleted, audience, instance).await {
            ServeDecision::Serve => {
                return Ok(CandidateWalk::Served {
                    row: row.clone(),
                    all: rows,
                })
            }
            ServeDecision::Refuse {
                status,
                body,
                hold_class,
            } => {
                let resp = refusal_bytes(status, serde_json::to_vec(&body).unwrap_or_default());
                if status == 503 {
                    audit_refusal(&state.db, auth, repo, row, hold_class, audience);
                    audit_gate_unavailable(
                        &state.db,
                        repo.id,
                        row.artifact_id,
                        serde_json::json!({
                            "surface": "detail",
                            "repository": repo.key,
                            "server": row.name,
                            "version": row.version,
                        }),
                    );
                    return Ok(CandidateWalk::Refused(resp));
                }
                if first_refusal.is_none() {
                    first_refusal = Some((resp, row, hold_class));
                }
            }
        }
    }
    let (resp, row, hold_class) = first_refusal.expect("candidates is non-empty");
    if hold_class != "deleted" {
        audit_refusal(&state.db, auth, repo, row, hold_class, audience);
    }
    Ok(CandidateWalk::Refused(resp))
}

/// Whether `row` is the newest servable version among `all` (every version
/// of its server in `repo`), by the reader-only listing gate.
pub(crate) async fn is_newest_servable(
    state: &SharedState,
    repo: &RepoInfo,
    row: &VersionRow,
    all: Vec<VersionRow>,
) -> bool {
    let policy_now = current_policy(&state.db, repo.id).await;
    let known = std::iter::once(row.artifact_id).collect();
    let listing = GateCtx::of(state, false);
    newest_servable(listing, repo.id, all, &known, policy_now)
        .await
        .0
        .is_some_and(|l| l.artifact_id == row.artifact_id)
}

// ---------------------------------------------------------------------------
// GET /ping, /health, /version
// ---------------------------------------------------------------------------

/// The repository a `/ping`, `/health` or `/version` names must be a hosted
/// MCP registry: any other key answers the unknown-name 404, as every other
/// route of this surface does.
async fn utility_repo(state: &SharedState, repo_key: &str) -> Result<(), Response> {
    let repo = resolve_mcp_repo(&state.db, repo_key).await?;
    if repo.repo_type == "virtual" {
        return Ok(());
    }
    reject_if_not_hosted_read(&repo)
}

async fn ping(State(state): State<SharedState>, Path(repo_key): Path<String>) -> HandlerResult {
    utility_repo(&state, &repo_key).await?;
    Ok(json_ok(
        StatusCode::OK,
        &serde_json::json!({"status": "ok"}),
    ))
}

async fn health(State(state): State<SharedState>, Path(repo_key): Path<String>) -> HandlerResult {
    utility_repo(&state, &repo_key).await?;
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => Ok(json_ok(
            StatusCode::OK,
            &serde_json::json!({"status": "ok"}),
        )),
        Err(_) => Err(problem(
            503,
            "mcp_unavailable",
            "The registry database is unavailable",
            serde_json::json!({}),
        )),
    }
}

async fn version(State(state): State<SharedState>, Path(repo_key): Path<String>) -> HandlerResult {
    utility_repo(&state, &repo_key).await?;
    Ok(json_ok(
        StatusCode::OK,
        &serde_json::json!({"version": env!("CARGO_PKG_VERSION")}),
    ))
}

// ---------------------------------------------------------------------------
// POST /publish
// ---------------------------------------------------------------------------

/// The hosted-write gates every MCP write shares.
pub(super) async fn writable_repo(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
) -> Result<(AuthExtension, RepoInfo), Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let ext = match require_auth_basic_scope(auth, "mcp", "write:artifacts") {
        Ok(ext) => ext,
        Err(resp) if resp.status() == StatusCode::FORBIDDEN => {
            return Err(problem(
                403,
                "mcp_forbidden",
                "This token does not carry the write:artifacts scope",
                serde_json::json!({}),
            ))
        }
        Err(resp) => return Err(reproblem(resp)),
    };
    let repo = resolve_mcp_repo(&state.db, repo_key).await?;
    if !ext.can_access_repo(repo.id) {
        return Err(problem(
            403,
            "mcp_forbidden",
            "This token is not scoped to this repository",
            serde_json::json!({}),
        ));
    }
    super::mcp_virtual::reject_write_if_virtual(&repo)?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type).map_err(reproblem)?;
    Ok((ext, repo))
}

/// A body the extractor refused: over the publish cap (413) or unreadable.
pub(super) fn body_rejection(status: StatusCode) -> Response {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        mcp_error(McpError::TooLarge)
    } else {
        mcp_error(McpError::invalid("", "the request body could not be read"))
    }
}

/// Parse, validate, namespace-check and reduce a submitted document.
pub(super) fn admit_document(
    body: &[u8],
    settings: &mcp_packages::McpSettings,
) -> Result<fmt::ServerJson, McpError> {
    let mut server = fmt::parse_server_json(body)?;
    fmt::validate_server_json(&server)?;
    let namespace = fmt::namespace_of(&server.name).to_string();
    if fmt::is_reserved_namespace(&server.name) {
        return Err(McpError::ReservedNamespace { namespace });
    }
    if !fmt::namespace_allowed(&server.name, &settings.namespace_allow) {
        return Err(McpError::NamespaceNotAllowed { namespace });
    }
    fmt::reduce_publisher_meta(&mut server)?;
    super::mcp_capabilities::admit_declared(&server)?;
    Ok(server)
}

/// The name-level gates every hosted write of a server document runs once
/// the name is known (publish, admin edit, bundle upload): the repository's
/// `mcp_server_deny` list, then the namespace write gate
/// (`mcp_require_namespace_grant`, CI claims).
pub(super) async fn name_write_gates(
    state: &SharedState,
    ext: &AuthExtension,
    repo: &RepoInfo,
    name: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    refuse_denied_name(&state.db, repo, name).await?;
    super::mcp_edges::require_namespace_write(state, ext, repo.id, name, "write", headers).await
}

/// Refuse a publish whose name matches the repository's `mcp_server_deny`
/// list (403 `mcp_server_denied`); deny always wins.
async fn refuse_denied_name(db: &PgPool, repo: &RepoInfo, name: &str) -> Result<(), Response> {
    let settings = crate::services::mcp_settings::load(db, repo.id, &repo.repo_type)
        .await
        .map_err(internal)?;
    if mcp_curation::is_denied(&settings.mcp_server_deny.unwrap_or_default(), name) {
        return Err(mcp_error(McpError::ServerDenied {
            name: name.to_string(),
        }));
    }
    Ok(())
}

/// Insert the server.json row, its metadata and the OCI retention holds in
/// one quota-admitted transaction: a version whose metadata could not be
/// written must not exist (it would be invisible yet block a republish).
pub(super) async fn insert_server_rows(
    db: &PgPool,
    artifact: proxy_helpers::NewArtifact<'_>,
    metadata: &serde_json::Value,
    pins: &[PackagePin],
    upload_hold_until: Option<DateTime<Utc>>,
    resolve_for: Option<Uuid>,
) -> Result<(Uuid, Vec<(Uuid, Uuid)>), Response> {
    use crate::services::quarantine_service::{HoldSource, QuarantineState};
    let repository_id = artifact.repository_id;
    let path = artifact.path.to_string();
    let name = artifact.name.to_string();
    let mut tx = super::publish_quota::begin_admitted_publish(
        db,
        repository_id,
        artifact.path,
        artifact.size_bytes,
    )
    .await?;
    let artifact_id = match proxy_helpers::insert_artifact_row(&mut tx, artifact).await {
        Ok(id) => id,
        Err(resp) => {
            drop(tx);
            // A concurrent publish of the same version won the unique path.
            let exists: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 \
                 AND is_deleted = false",
            )
            .bind(repository_id)
            .bind(&path)
            .fetch_optional(db)
            .await
            .unwrap_or(None);
            return Err(if exists.is_some() {
                mcp_error(McpError::VersionExists)
            } else {
                resp
            });
        }
    };
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'mcp', $2)",
    )
    .bind(artifact_id)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    let hold_rows = mcp_packages::hold_pins(&mut tx, pins)
        .await
        .map_err(internal)?;
    // A version stored `resolving` commits with its fill job (#5253).
    if let Some(user) = resolve_for {
        crate::services::mcp_resolver::enqueue(&mut tx, artifact_id, repository_id, user)
            .await
            .map_err(internal)?;
    }
    // The upload-time quarantine hold commits with the row, so the version is
    // never listed in the window before a post-commit hold would land.
    if let Some(until) = upload_hold_until {
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = $2, quarantine_until = $3, \
             quarantine_source = $4 WHERE id = $1",
        )
        .bind(artifact_id)
        .bind(QuarantineState::Quarantined.as_str())
        .bind(until)
        .bind(HoldSource::Upload.as_str())
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    recompute_latest_in(&mut tx, repository_id, &name)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
        .bind(repository_id)
        .execute(db)
        .await;
    Ok((artifact_id, hold_rows))
}

/// Whether `path` names a version that was deleted through the artifact API
/// and still sits in the trash. Its name stays reserved until an
/// administrator purges it, so a version is write-once across a generic
/// delete too (a tombstone that outlives the purge comes later).
pub(super) async fn trashed_version_exists(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
) -> Result<bool, Response> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM artifacts WHERE repository_id = $1 AND path = $2 \
         AND is_deleted = true)",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_one(db)
    .await
    .map_err(internal)
}

/// Remove the stored bytes of a publish whose row was never written, unless
/// a row (a concurrent identical publish that won) references the same
/// content-addressed key. Best-effort.
pub(super) async fn discard_unreferenced_bytes(state: &SharedState, repo: &RepoInfo, key: &str) {
    let referenced: Result<bool, _> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM artifacts WHERE repository_id = $1 AND storage_key = $2)",
    )
    .bind(repo.id)
    .bind(key)
    .fetch_one(&state.db)
    .await;
    if !matches!(referenced, Ok(false)) {
        return;
    }
    match state.storage_for_repo(&repo.storage_location()) {
        Ok(storage) => {
            if let Err(e) = storage.delete(key).await {
                tracing::warn!(key, error = %e, "MCP publish: could not remove unreferenced bytes");
            }
        }
        Err(e) => tracing::warn!(key, error = %e, "MCP publish: storage unavailable for cleanup"),
    }
}

/// `(version, publishedAt)`: what [`fmt::latest_order`] compares.
type LatestKey<'a> = (&'a str, Option<DateTime<Utc>>);

/// Take the per-server advisory lock every registry-state write of `name`
/// serialises on, for the rest of the caller's transaction.
pub(super) async fn lock_server(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("mcp-latest/{repo_id}/{name}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// Recompute `registry.isLatest` for every version of `name`, inside the
/// caller's transaction and under the per-server lock: the newest
/// non-deleted version by [`fmt::latest_order`] (publish time breaks ties).
pub(crate) async fn recompute_latest_in(
    tx: &mut sqlx::PgConnection,
    repo_id: Uuid,
    name: &str,
) -> Result<(), sqlx::Error> {
    lock_server(&mut *tx, repo_id, name).await?;
    let rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT a.id, a.version, m.metadata->'registry' FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.name = $2 AND a.is_deleted = false \
           AND m.format = 'mcp'",
    )
    .bind(repo_id)
    .bind(name)
    .fetch_all(&mut *tx)
    .await?;
    let parsed: Vec<(Uuid, &str, Option<RegistryState>)> = rows
        .iter()
        .map(|(id, v, r)| (*id, v.as_str(), serde_json::from_value(r.clone()).ok()))
        .collect();
    let candidates: Vec<(usize, LatestKey<'_>)> = parsed
        .iter()
        .enumerate()
        .filter_map(|(i, (_, v, r))| match r {
            Some(r) if r.status != ServerStatus::Deleted => Some((i, (*v, Some(r.published_at)))),
            _ => None,
        })
        .collect();
    let latest = candidates
        .iter()
        .max_by(|a, b| fmt::latest_order(a.1, b.1))
        .map(|(i, _)| *i);
    for (i, (id, _, r)) in parsed.iter().enumerate() {
        let Some(r) = r else { continue };
        let want = latest == Some(i);
        if r.is_latest != want {
            sqlx::query(
                "UPDATE artifact_metadata SET metadata = \
                 jsonb_set(metadata, '{registry,isLatest}', to_jsonb($2::boolean)) \
                 WHERE artifact_id = $1",
            )
            .bind(id)
            .bind(want)
            .execute(&mut *tx)
            .await?;
        }
    }
    Ok(())
}

/// `MCP_PACKAGE_PINNED`, one row per resolved entry.
pub(super) fn audit_pins(
    db: &PgPool,
    user_id: Uuid,
    repo: &RepoInfo,
    artifact_id: Uuid,
    server: &fmt::ServerJson,
    pins: &[PackagePin],
) {
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    for pin in pins {
        let entry = AuditEntry::new(AuditAction::McpPackagePinned, ResourceType::Artifact)
            .user(user_id)
            .resource(artifact_id)
            .resource_name(format!("{}@{}", server.name, server.version))
            .with_request_client_ip()
            .details(serde_json::json!({
                "repository": repo.key,
                "server": server.name,
                "version": server.version,
                "index": pin.index,
                "registry_type": pin.registry_type,
                "submitted": pin.submitted,
                "resolved_repository": pin.resolved.repository,
                "digest": pin.resolved.digest,
                "sha256": pin.resolved.sha256,
                "warnings": pin.resolved.warnings,
            }));
        tokio::spawn(audit_fire_and_forget(db.clone(), entry));
    }
}

pub(super) async fn stored_row(db: &PgPool, artifact_id: Uuid) -> Result<VersionRow, Response> {
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.id = $1"
    );
    let raw: Vec<RawRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(artifact_id)
        .fetch_all(db)
        .await
        .map_err(internal)?;
    rows_from_raw(raw)
        .pop()
        .ok_or_else(|| internal("published version vanished"))
}

async fn publish_server(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let (ext, repo) = writable_repo(&state, auth, &repo_key).await?;
    let body = body.map_err(|r| body_rejection(r.status()))?;
    repo.reject_if_promotion_only(false).map_err(reproblem)?;
    let settings = mcp_packages::load_settings(&state.db, repo.id)
        .await
        .map_err(mcp_error)?;
    let mut server = admit_document(&body, &settings).map_err(mcp_error)?;
    name_write_gates(&state, &ext, &repo, &server.name, &headers).await?;
    super::mcp_write::add_staged_bundles(&state.db, &repo, &settings, &mut server, base.as_str())
        .await?;
    super::mcp_write::refuse_tombstoned(&state.db, repo.id, &server.name, &server.version).await?;
    let resolution = crate::services::mcp_resolver::resolve_document(
        &state,
        &settings,
        crate::services::mcp_resolver::Target {
            repo_id: repo.id,
            repo_key: &repo.key,
            name: &server.name,
            version: &server.version,
        },
        &server,
        base.as_str(),
    )
    .await
    .map_err(mcp_error)?;
    let pins = resolution.pins.clone();
    let resolving = !resolution.pending.is_empty();
    let lint = mcp_lint::McpLintScanner::check_publish(&state, repo.id, &server, &pins)
        .await
        .map_err(IntoResponse::into_response)?;

    let bytes = fmt::canonical_bytes(&server);
    let sha256 = fmt::sha256_hex(&bytes);
    let path = fmt::storage_path(&server.name, &server.version);
    crate::services::upload_service::validate_artifact_path(&path)
        .map_err(|e| mcp_error(McpError::invalid("", e.to_string())))?;
    if trashed_version_exists(&state.db, repo.id, &path).await? {
        return Err(mcp_error(McpError::VersionExists));
    }
    proxy_helpers::ensure_unique_artifact_path(&state.db, repo.id, &path, "exists")
        .await
        .map_err(|resp| match resp.status() {
            StatusCode::CONFLICT => mcp_error(McpError::VersionExists),
            _ => reproblem(resp),
        })?;
    let key = fmt::storage_key(&server.name, &server.version, &sha256);
    let size_bytes = bytes.len() as i64;
    proxy_helpers::put_artifact_bytes(&state, &repo, &key, Bytes::from(bytes))
        .await
        .map_err(reproblem)?;

    let registry = RegistryState::new_active(Utc::now());
    let metadata = crate::services::mcp_resolver::metadata_with_resolution(
        &state.db,
        fmt::metadata_doc(&server, &registry, settings.policy, &pins),
        &resolution,
        ext.user_id,
        base.as_str(),
    )
    .await
    .map_err(mcp_error)?;
    // The repository's upload-time quarantine (Package Age Policy), applied
    // inside the insert transaction below; the repository is hosted here.
    let upload_hold_until = {
        use crate::services::quarantine_service as qs;
        let config = qs::resolve_config(&state.db, repo.id).await;
        qs::should_quarantine(&config).then(|| qs::quarantine_until(&config, Utc::now()))
    };
    let inserted = insert_server_rows(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &path,
            name: &server.name,
            version: &server.version,
            size_bytes,
            checksum_sha256: &sha256,
            content_type: "application/json",
            storage_key: &key,
            uploaded_by: ext.user_id,
        },
        &metadata,
        &pins,
        upload_hold_until,
        resolving.then_some(ext.user_id),
    )
    .await;
    let (artifact_id, hold_rows) = match inserted {
        Ok(ids) => ids,
        Err(resp) => {
            discard_unreferenced_bytes(&state, &repo, &key).await;
            return Err(resp);
        }
    };
    mcp_lint::record_after_write(&state.db, artifact_id, &lint, mcp_lint::SERVER_JSON_SOURCE).await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;
    // A digest-path manifest row a retention hold created is new to the
    // scanner: scan it like a pushed manifest, so a scan policy that requires
    // a scan does not hold the pinned image forever.
    for (backing_repo, row) in hold_rows {
        crate::services::scanner_service::trigger_scan_on_upload(
            &state.db,
            state.scanner_service.clone(),
            backing_repo,
            row,
        )
        .await;
    }
    audit_pins(&state.db, ext.user_id, &repo, artifact_id, &server, &pins);
    super::mcp_write::record_version_facts(&state, artifact_id, Some(ext.user_id)).await;
    crate::services::package_service::register_published_package_with_metadata(
        &state.db,
        &state.event_bus,
        repo.id,
        &server.name,
        &server.version,
        size_bytes,
        &sha256,
        Some(&server.description),
        Some(fmt::catalog_metadata(&metadata)),
    )
    .await;
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        &headers,
        repo.id,
        artifact_id,
        &path,
        size_bytes,
    )
    .await;
    tracing::info!(
        "MCP publish: {}@{} to repo {} ({} packages pinned)",
        server.name,
        server.version,
        repo.key,
        pins.len()
    );
    super::mcp_write::audit_published(
        &state.db,
        ext.user_id,
        &repo,
        artifact_id,
        &server,
        &resolution,
    );
    let row = stored_row(&state.db, artifact_id).await?;
    let latest = row_is_latest(&state, &repo, &row, settings.policy).await;
    let entry = served_entry(&row, &repo, base.as_str(), latest);
    Ok(super::mcp_write::publish_answer(entry, &resolution))
}

/// Whether `row` is its server's newest servable version (the reader-only
/// gate), for a write's response. A read failure answers `false`.
pub(super) async fn row_is_latest(
    state: &SharedState,
    repo: &RepoInfo,
    row: &VersionRow,
    policy_now: PackagePolicy,
) -> bool {
    let Ok(all) = versions_of(&state.db, repo.id, &row.name).await else {
        return false;
    };
    let ctx = GateCtx::of(state, false);
    newest_servable(ctx, repo.id, all, &Default::default(), policy_now)
        .await
        .0
        .is_some_and(|l| l.artifact_id == row.artifact_id)
}

// ---------------------------------------------------------------------------
// PATCH .../status
// ---------------------------------------------------------------------------

/// `StatusUpdateRequest`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StatusUpdate {
    status: String,
    #[serde(default)]
    status_message: Option<String>,
}

fn parse_status_update(body: &[u8]) -> Result<(ServerStatus, Option<String>), McpError> {
    let u: StatusUpdate = serde_json::from_slice(body)
        .map_err(|e| McpError::invalid("", format!("invalid status update: {e}")))?;
    let status = ServerStatus::parse(&u.status)
        .ok_or_else(|| McpError::invalid("status", "must be one of active, deprecated, deleted"))?;
    Ok((status, u.status_message))
}

/// Apply a validated status change to one stored registry state.
pub(super) fn apply_status(
    current: &RegistryState,
    next: ServerStatus,
    message: Option<&str>,
    now: DateTime<Utc>,
) -> Result<RegistryState, McpError> {
    fmt::validate_status_change(current.status, next, message)?;
    Ok(RegistryState {
        status: next,
        status_message: message.map(str::to_string),
        status_changed_at: now,
        updated_at: now,
        ..current.clone()
    })
}

pub(super) async fn write_registry<'e>(
    db: impl sqlx::PgExecutor<'e>,
    artifact_id: Uuid,
    r: &RegistryState,
) -> Result<(), Response> {
    sqlx::query(
        "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{registry}', $2) \
         WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .bind(serde_json::to_value(r).unwrap_or_default())
    .execute(db)
    .await
    .map_err(internal)?;
    Ok(())
}

async fn update_version_status_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, version)): Path<(String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, None);
    update_status_impl(
        &state,
        auth,
        &repo_key,
        &name,
        Some(&version),
        (&body, &headers),
        base.as_str(),
    )
    .await
}

async fn update_version_status_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name, version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, Some(&name));
    update_status_impl(
        &state,
        auth,
        &repo_key,
        &name,
        Some(&version),
        (&body, &headers),
        base.as_str(),
    )
    .await
}

async fn update_server_status_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns)): Path<(String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, None);
    update_status_impl(
        &state,
        auth,
        &repo_key,
        &name,
        None,
        (&body, &headers),
        base.as_str(),
    )
    .await
}

async fn update_server_status_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, ns, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let body = body.map_err(|r| body_rejection(r.status()))?;
    let name = server_name(&ns, Some(&name));
    update_status_impl(
        &state,
        auth,
        &repo_key,
        &name,
        None,
        (&body, &headers),
        base.as_str(),
    )
    .await
}

/// One version (`version = Some`) or every version of a server. A
/// whole-server change skips versions already in the target status and is
/// refused when that leaves none.
async fn update_status_impl(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    name: &str,
    version: Option<&str>,
    (body, headers): (&[u8], &HeaderMap),
    base: &str,
) -> HandlerResult {
    let (ext, repo) = writable_repo(state, auth, repo_key).await?;
    // A status change is a write, gated like a publish.
    repo.reject_if_promotion_only(false).map_err(reproblem)?;
    super::mcp_edges::require_namespace_write(state, &ext, repo.id, name, "write", headers).await?;
    let (next, message) = parse_status_update(body).map_err(mcp_error)?;
    let status_lint = mcp_lint::McpLintScanner::check_status_message(message.as_deref())
        .map_err(IntoResponse::into_response)?;
    // One transaction under the per-server lock: every version changes or
    // none does, and `isLatest` is recomputed from the state just written.
    let mut tx = state.db.begin().await.map_err(internal)?;
    lock_server(&mut tx, repo.id, name)
        .await
        .map_err(internal)?;
    let rows: Vec<VersionRow> = versions_of(&mut *tx, repo.id, name)
        .await?
        .into_iter()
        .filter(|r| version.is_none_or(|v| r.version == v))
        .collect();
    if rows.is_empty() {
        return Err(not_found());
    }
    let now = Utc::now();
    let mut changed = Vec::new();
    let mut transitions = Vec::new();
    for row in &rows {
        match apply_status(&row.stored.registry, next, message.as_deref(), now) {
            Ok(updated) => {
                write_registry(&mut *tx, row.artifact_id, &updated).await?;
                changed.push(row.artifact_id);
                transitions.push((row, row.stored.registry.status, updated));
            }
            Err(e) if version.is_some() || row.stored.registry.status != next => {
                return Err(mcp_error(e))
            }
            Err(_) => {}
        }
    }
    if changed.is_empty() {
        return Err(mcp_error(McpError::invalid(
            "status",
            format!("every version is already {}", next.as_str()),
        )));
    }
    recompute_latest_in(&mut tx, repo.id, name)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    for (row, from, to) in &transitions {
        super::mcp_write::audit_status_changed(&state.db, ext.user_id, &repo, row, *from, to);
    }
    for id in &changed {
        let source = mcp_lint::STATUS_MESSAGE_SOURCE;
        mcp_lint::record_after_write(&state.db, *id, &status_lint, source).await;
        super::mcp_write::refresh_catalog_row(&state.db, *id).await;
    }
    let policy_now = current_policy(&state.db, repo.id).await;
    let all = versions_of(&state.db, repo.id, name).await?;
    let latest = newest_servable(
        GateCtx::of(state, false),
        repo.id,
        all,
        &Default::default(),
        policy_now,
    )
    .await
    .0
    .map(|r| r.artifact_id);
    let mut entries = Vec::new();
    for id in &changed {
        let row = stored_row(&state.db, *id).await?;
        entries.push(served_entry(&row, &repo, base, Some(*id) == latest));
    }
    let out = match version {
        Some(_) => entries.pop().unwrap_or_default(),
        None => serde_json::json!({"updatedCount": entries.len(), "servers": entries}),
    };
    Ok(json_ok(StatusCode::OK, &out))
}

// ---------------------------------------------------------------------------
// Shared with the capability routes (`mcp_capabilities.rs`)
// ---------------------------------------------------------------------------

/// The MCP repository named by a path, as every route of this surface
/// resolves it (unknown key: the unknown-name 404).
pub(crate) async fn mcp_repo(db: &PgPool, key: &str) -> Result<RepoInfo, Response> {
    resolve_mcp_repo(db, key).await
}

/// The stored `name@version` of `repo` that `auth` may see, with the stored
/// document: a reason-gated caller (the repository's holders and admins)
/// sees every stored version, so the approval queue can diff a held one; a
/// reader sees only a version that is servable to readers now, and
/// everything else is the unknown-name 404.
pub(crate) async fn visible_version(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name: &str,
    version: &str,
    base: &str,
) -> Result<(Uuid, StoredVersion, GateAudience), Response> {
    let row = versions_of(&state.db, repo.id, name)
        .await?
        .into_iter()
        .find(|r| r.version == version)
        .ok_or_else(not_found)?;
    let audience = audience(&state.db, auth, repo.id).await;
    if audience == GateAudience::ReasonGated || servable_row(state, repo, &row, base).await {
        return Ok((row.artifact_id, row.stored, audience));
    }
    Err(not_found())
}

async fn servable_row(state: &SharedState, repo: &RepoInfo, row: &VersionRow, base: &str) -> bool {
    let policy_now = current_policy(&state.db, repo.id).await;
    let instance = instance_url(base, &repo.key, &row.name, &row.version);
    matches!(
        decide_row(
            GateCtx::of(state, false),
            row,
            policy_now,
            false,
            GateAudience::ReaderOnly,
            instance,
        )
        .await,
        ServeDecision::Serve
    )
}

/// Whether the stored version `artifact_id` of `repo` is servable to readers
/// now (the sandbox only ever runs a version whose gates pass).
pub(crate) async fn artifact_servable(
    state: &SharedState,
    repo: &RepoInfo,
    artifact_id: Uuid,
    base: &str,
) -> bool {
    match stored_row(&state.db, artifact_id).await {
        Ok(row) => servable_row(state, repo, &row, base).await,
        Err(_) => false,
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::Request;

    // -----------------------------------------------------------------------
    // Pure helpers
    // -----------------------------------------------------------------------

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn list_query_rules() {
        assert_eq!(parse_list_query(&q(&[])).unwrap().limit, fmt::DEFAULT_LIMIT);
        assert_eq!(
            parse_list_query(&q(&[("limit", "500")])).unwrap().limit,
            fmt::MAX_LIMIT
        );
        assert_eq!(parse_list_query(&q(&[("limit", "7")])).unwrap().limit, 7);
        for bad in ["0", "-1", "x", "1.5"] {
            assert_eq!(
                parse_list_query(&q(&[("limit", bad)]))
                    .unwrap_err()
                    .status(),
                400,
                "{bad}"
            );
        }
        assert_eq!(
            parse_list_query(&q(&[("cursor", "!!")]))
                .unwrap_err()
                .status(),
            400
        );
        let c = fmt::encode_cursor("com.acme/a", "1.0.0");
        assert_eq!(
            parse_list_query(&q(&[("cursor", &c)])).unwrap().cursor,
            Some(("com.acme/a".into(), "1.0.0".into()))
        );
        assert_eq!(
            parse_list_query(&q(&[("search", "ab")])).unwrap_err(),
            McpError::SearchTooShort
        );
        assert_eq!(
            parse_list_query(&q(&[("search", "abc")]))
                .unwrap()
                .search
                .as_deref(),
            Some("abc")
        );
        let since = parse_list_query(&q(&[("updated_since", "2026-01-01T00:00:00Z")])).unwrap();
        assert!(since.include_deleted && since.updated_since.is_some());
        assert_eq!(
            parse_list_query(&q(&[
                ("updated_since", "2026-01-01T00:00:00Z"),
                ("include_deleted", "false")
            ]))
            .unwrap_err()
            .status(),
            400
        );
        assert_eq!(
            parse_list_query(&q(&[("updated_since", "yesterday")]))
                .unwrap_err()
                .status(),
            400
        );
        let long = "x".repeat(201);
        for bad in [
            &[("limit", "0")][..],
            &[("cursor", "!!")],
            &[("updated_since", "yesterday")],
            &[("include_deleted", "maybe")],
            &[("search", long.as_str())],
        ] {
            assert_eq!(
                parse_list_query(&q(bad)).unwrap_err().code(),
                "mcp_invalid_query",
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_list_query(&q(&[("include_deleted", "maybe")]))
                .unwrap_err()
                .status(),
            400
        );
        assert!(
            parse_list_query(&q(&[("include_deleted", "true")]))
                .unwrap()
                .include_deleted
        );
        assert_eq!(
            parse_list_query(&q(&[("version", "latest")]))
                .unwrap()
                .version
                .as_deref(),
            Some("latest")
        );
    }

    #[test]
    fn small_helpers() {
        assert_eq!(server_name("com.acme/w", None), "com.acme/w");
        assert_eq!(server_name("com.acme", Some("w")), "com.acme/w");
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("GET"),
        );
        assert!(is_mcp_preflight(
            &Method::OPTIONS,
            "/mcp/r/v0.1/servers",
            &h
        ));
        assert!(!is_mcp_preflight(&Method::OPTIONS, "/npm/r/x", &h));
        assert!(!is_mcp_preflight(&Method::GET, "/mcp/r/v0.1/servers", &h));
        assert!(!is_mcp_preflight(
            &Method::OPTIONS,
            "/mcp/r/v0.1/servers",
            &HeaderMap::new()
        ));
        let id = Uuid::new_v4();
        assert!(refusal_audit_due(id, "anonymous"));
        assert!(!refusal_audit_due(id, "anonymous"));
        assert!(refusal_audit_due(id, "someone-else"));
        assert_eq!(
            instance_url("https://ak.test/", "r", "com.acme/w", "1.0.0"),
            "https://ak.test/mcp/r/v0.1/servers/com.acme%2Fw/versions/1.0.0"
        );
        let now = Utc::now();
        let cur = RegistryState::new_active(now);
        let next = apply_status(&cur, ServerStatus::Deprecated, Some("use 2"), now).unwrap();
        assert_eq!(
            (next.status, next.status_message.as_deref()),
            (ServerStatus::Deprecated, Some("use 2"))
        );
        assert!(apply_status(&cur, ServerStatus::Active, None, now).is_err());
        assert!(parse_status_update(br#"{"status":"deleted"}"#).is_ok());
        assert!(parse_status_update(br#"{"status":"held"}"#).is_err());
        assert!(parse_status_update(br#"{"status":"active","extra":1}"#).is_err());
        assert_eq!(body_rejection(StatusCode::PAYLOAD_TOO_LARGE).status(), 413);
        assert_eq!(body_rejection(StatusCode::BAD_REQUEST).status(), 400);
        for (status, want) in [
            (401, 401),
            (403, 403),
            (405, 405),
            (409, 409),
            (400, 400),
            (503, 503),
            (500, 500),
        ] {
            let resp = reproblem(
                Response::builder()
                    .status(status)
                    .header(header::WWW_AUTHENTICATE, "Basic realm=\"mcp\"")
                    .body(Body::empty())
                    .unwrap(),
            );
            assert_eq!(resp.status().as_u16(), want);
            assert_eq!(
                resp.headers()[header::CONTENT_TYPE],
                "application/problem+json"
            );
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
            assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
        }
    }

    #[tokio::test]
    async fn refusals_are_always_problem_json() {
        for (status, ct) in [
            (StatusCode::METHOD_NOT_ALLOWED, None),
            (StatusCode::BAD_REQUEST, Some("text/plain")),
            (StatusCode::NOT_FOUND, None),
            (StatusCode::PAYLOAD_TOO_LARGE, None),
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, None),
            (StatusCode::INTERNAL_SERVER_ERROR, None),
        ] {
            let mut b = Response::builder().status(status);
            if let Some(ct) = ct {
                b = b.header(header::CONTENT_TYPE, ct);
            }
            let out = ensure_problem(b.body(Body::empty()).unwrap()).await;
            assert_eq!(out.status(), status);
            assert_eq!(
                out.headers()[header::CONTENT_TYPE],
                "application/problem+json"
            );
            assert_eq!(out.headers()[header::CACHE_CONTROL], "no-store");
        }
        let ok = ensure_problem(StatusCode::OK.into_response()).await;
        assert!(ok.headers().get(header::CACHE_CONTROL).is_none());
        let p = ensure_problem(not_found()).await;
        assert_eq!(p.status(), StatusCode::NOT_FOUND);
    }

    /// T6 ratchet: the MCP modules never build an HTTP client or call the
    /// proxy fetch helpers, so no publisher-supplied URL is ever dereferenced.
    #[test]
    fn mcp_modules_never_build_an_http_client() {
        for (file, src) in [
            ("api/handlers/mcp.rs", include_str!("mcp.rs")),
            ("formats/mcp.rs", include_str!("../../formats/mcp.rs")),
            (
                "services/mcp_packages.rs",
                include_str!("../../services/mcp_packages.rs"),
            ),
            (
                "services/mcp_curation.rs",
                include_str!("../../services/mcp_curation.rs"),
            ),
            (
                "services/mcp_catalog.rs",
                include_str!("../../services/mcp_catalog.rs"),
            ),
            ("api/handlers/mcp_remote.rs", include_str!("mcp_remote.rs")),
            (
                "api/handlers/mcp_virtual.rs",
                include_str!("mcp_virtual.rs"),
            ),
            ("api/handlers/mcp_edges.rs", include_str!("mcp_edges.rs")),
            (
                "services/mcp_lint.rs",
                include_str!("../../services/mcp_lint.rs"),
            ),
            (
                "services/mcp_health.rs",
                include_str!("../../services/mcp_health.rs"),
            ),
            ("api/handlers/mcp_health.rs", include_str!("mcp_health.rs")),
            (
                "api/handlers/mcp_capabilities.rs",
                include_str!("mcp_capabilities.rs"),
            ),
            (
                "services/mcp_capabilities.rs",
                include_str!("../../services/mcp_capabilities.rs"),
            ),
            (
                "services/mcp_introspection.rs",
                include_str!("../../services/mcp_introspection.rs"),
            ),
        ] {
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            for needle in [
                concat!("reqwest", "::"),
                concat!("Client", "::builder("),
                concat!("proxy", "_fetch"),
                concat!("http_client", "::"),
                concat!("TcpStream", "::connect"),
            ] {
                assert!(
                    !production.contains(needle),
                    "{file} must not open outbound connections ({needle})"
                );
            }
        }
    }

    /// The Remote sync is the one MCP module that reads a URL, and only the
    /// repository's configured upstream through the proxy helper (SSRF
    /// guard, size cap, upstream credentials): never a client of its own.
    #[test]
    fn mcp_remote_sync_fetches_only_through_the_proxy_helper() {
        let src = include_str!("../../services/mcp_remote.rs");
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        for needle in [
            concat!("reqwest", "::"),
            concat!("Client", "::builder("),
            concat!("http_client", "::"),
            concat!("TcpStream", "::connect"),
        ] {
            assert!(!production.contains(needle), "{needle}");
        }
        assert_eq!(
            production
                .matches(concat!("proxy_fetch", "_capped_with_format("))
                .count(),
            1
        );
    }

    // -----------------------------------------------------------------------
    // DB-backed fixtures
    // -----------------------------------------------------------------------

    fn doc(name: &str, version: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut d = serde_json::json!({
            "$schema": fmt::SCHEMA_URL,
            "name": name,
            "description": "Weather tools",
            "version": version,
        });
        if let (Some(o), serde_json::Value::Object(e)) = (d.as_object_mut(), extra) {
            o.extend(e);
        }
        if d.get("packages").is_none() && d.get("remotes").is_none() {
            d["remotes"] = serde_json::json!([{"type": "streamable-http", "url": "https://mcp.acme.test/mcp"}]);
        }
        d
    }

    fn npm_pkg(identifier: &str, version: Option<&str>) -> serde_json::Value {
        let mut p = serde_json::json!({
            "registryType": "npm", "identifier": identifier, "transport": {"type": "stdio"},
        });
        if let Some(v) = version {
            p["version"] = v.into();
        }
        p
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<&serde_json::Value>,
    ) -> (StatusCode, Bytes, HeaderMap) {
        let mut b = Request::builder().method(method).uri(uri);
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let body = body
            .map(|v| Body::from(serde_json::to_vec(v).unwrap()))
            .unwrap_or_else(Body::empty);
        tdh::send_with_headers(app, b.body(body).unwrap()).await
    }

    fn json(b: &Bytes) -> serde_json::Value {
        serde_json::from_slice(b).unwrap_or(serde_json::Value::Null)
    }

    struct Env {
        fx: tdh::Fixture,
        extra_repos: Vec<(Uuid, std::path::PathBuf)>,
    }

    impl Env {
        async fn new() -> Option<Self> {
            let fx = tdh::Fixture::setup("local", "mcp").await?;
            Some(Self {
                fx,
                extra_repos: Vec::new(),
            })
        }
        fn member(&self) -> Router {
            self.fx.router_with_auth(super::router())
        }
        fn anon(&self) -> Router {
            self.fx.router_anon(super::router())
        }
        fn url(&self, tail: &str) -> String {
            format!("/{}/v0.1{tail}", self.fx.repo_key)
        }
        async fn publish(&self, d: &serde_json::Value) -> (StatusCode, serde_json::Value) {
            let (s, b, _) = call(self.member(), "POST", &self.url("/publish"), Some(d)).await;
            (s, json(&b))
        }
        async fn get(&self, app: Router, tail: &str) -> (StatusCode, Bytes, HeaderMap) {
            call(app, "GET", &self.url(tail), None).await
        }
        async fn config(&self, key: &str, value: &str) {
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (repository_id, key) DO UPDATE SET value = $3",
            )
            .bind(self.fx.repo_id)
            .bind(key)
            .bind(value)
            .execute(&self.fx.pool)
            .await
            .unwrap();
        }
        async fn repo(&mut self, repo_type: &str, format: &str) -> RepoInfo {
            let (id, key, dir) = tdh::create_repo(&self.fx.pool, repo_type, format).await;
            self.extra_repos.push((id, dir.clone()));
            let mut info = tdh::make_repo_info(id, &key, &dir, repo_type, None);
            info.format = format.to_string();
            info
        }
        async fn npm_backing(&mut self, versions: &[&str]) -> (RepoInfo, Vec<Uuid>) {
            let npm = self.repo("local", "npm").await;
            let mut ids = Vec::new();
            for v in versions {
                ids.push(
                    tdh::seed_artifact_with_checksum(
                        &self.fx.state,
                        &self.fx.pool,
                        &npm,
                        &format!("npm/echo-{v}.tgz"),
                        &format!("@acme/echo/-/echo-{v}.tgz"),
                        "@acme/echo",
                        v,
                        "application/octet-stream",
                        Bytes::from_static(b"tgz"),
                        self.fx.user_id,
                        &"e".repeat(64),
                    )
                    .await,
                );
            }
            self.config(
                mcp_packages::REPOS_KEY,
                &serde_json::json!({"npm": npm.key}).to_string(),
            )
            .await;
            (npm, ids)
        }
        async fn hold(&self, artifact_id: Uuid, status: Option<&str>) {
            sqlx::query("UPDATE artifacts SET quarantine_status = $2, quarantine_source = 'admin', quarantine_until = NULL WHERE id = $1")
                .bind(artifact_id)
                .bind(status)
                .execute(&self.fx.pool)
                .await
                .unwrap();
        }
        async fn server_artifact(&self, name: &str, version: &str) -> Uuid {
            tdh::artifact_id_at(
                &self.fx.pool,
                self.fx.repo_id,
                &fmt::storage_path(name, version),
            )
            .await
        }
        async fn teardown(self) {
            for (id, dir) in &self.extra_repos {
                let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
                    .bind(id)
                    .execute(&self.fx.pool)
                    .await;
                tdh::cleanup_member_repo(&self.fx.pool, *id, dir).await;
            }
            let _ = sqlx::query("DELETE FROM packages WHERE repository_id = $1")
                .bind(self.fx.repo_id)
                .execute(&self.fx.pool)
                .await;
            self.fx.teardown().await;
        }
    }

    fn assert_refusal_headers(h: &HeaderMap) {
        assert_eq!(h[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    // -----------------------------------------------------------------------
    // Publish
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deny_list_refuses_publish_and_hides_on_serve() {
        let Some(env) = Env::new().await else {
            return;
        };
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let (s, _) = env
            .publish(&doc("com.acme/keep", "1.0.0", serde_json::json!({})))
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = env
            .publish(&doc("com.acme/later", "1.0.0", serde_json::json!({})))
            .await;
        assert_eq!(s, StatusCode::OK);
        env.config(
            crate::services::mcp_settings::SERVER_DENY_KEY,
            r#"["com.evil/*", "com.acme/later"]"#,
        )
        .await;
        let (s, body) = env
            .publish(&doc("Com.Evil/x", "1.0.0", serde_json::json!({})))
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "mcp_server_denied");
        // A version published before the glob is hidden from then on.
        let (s, b, _) = env.get(env.anon(), "/servers").await;
        assert_eq!(s, StatusCode::OK);
        let names: Vec<String> = json(&b)["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["server"]["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, ["com.acme/keep"]);
        let (s, b, h) = env
            .get(env.anon(), "/servers/com.acme%2Flater/versions/1.0.0")
            .await;
        assert_eq!(
            (s, b.as_ref()),
            (StatusCode::NOT_FOUND, fmt::NOT_FOUND_BODY.as_bytes())
        );
        assert_refusal_headers(&h);
        env.teardown().await;
    }

    #[tokio::test]
    async fn publish_npm_package_under_own_repos() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (npm, _) = env.npm_backing(&["1.0.0"]).await;
        let d = doc(
            "com.acme/echo",
            "1.0.0",
            serde_json::json!({"packages": [npm_pkg("@acme/echo", Some("1.0.0"))]}),
        );
        let (status, body) = env.publish(&d).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["server"]["packages"][0]["registryBaseUrl"],
            format!("http://localhost/npm/{}", npm.key)
        );
        let official = &body["_meta"][fmt::OFFICIAL_META_KEY];
        assert_eq!(
            (official["status"].as_str(), official["isLatest"].as_bool()),
            (Some("active"), Some(true))
        );
        let id = env.server_artifact("com.acme/echo", "1.0.0").await;
        assert_eq!(
            tdh::audit_count_eventually(&env.fx.pool, id, "MCP_PACKAGE_PINNED", 1).await,
            1
        );
        assert!(
            tdh::catalog_row(&env.fx.pool, env.fx.repo_id, "com.acme/echo")
                .await
                .is_some()
        );

        // Write-once: identical and different bytes both conflict.
        let (status, body) = env.publish(&d).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("mcp_version_exists"))
        );
        let mut changed = d.clone();
        changed["description"] = "Other".into();
        assert_eq!(env.publish(&changed).await.0, StatusCode::CONFLICT);

        // Reads: list, versions, exact, latest, /v0 alias, literal slash.
        let (s, list, _) = env.get(env.anon(), "/servers").await;
        assert_eq!(s, StatusCode::OK);
        let list = json(&list);
        assert_eq!(list["metadata"]["count"], 1);
        assert!(list["metadata"].get("nextCursor").is_none());
        let (_, v0, _) = call(
            env.anon(),
            "GET",
            &format!("/{}/v0/servers", env.fx.repo_key),
            None,
        )
        .await;
        assert_eq!(json(&v0), list);
        for tail in [
            "/servers/com.acme%2Fecho/versions/1.0.0",
            "/servers/com.acme/echo/versions/1.0.0",
            "/servers/com.acme%2Fecho/versions/latest",
        ] {
            let (s, b, _) = env.get(env.anon(), tail).await;
            assert_eq!(s, StatusCode::OK, "{tail}");
            assert_eq!(json(&b)["server"]["name"], "com.acme/echo");
        }
        let (s, b, _) = env.get(env.anon(), "/servers/com.acme/echo/versions").await;
        assert_eq!(
            (s, json(&b)["metadata"]["count"].as_i64()),
            (StatusCode::OK, Some(1))
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn publish_refusals() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (status, _, h) = call(
            env.anon(),
            "POST",
            &env.url("/publish"),
            Some(&doc("com.acme/a", "1", serde_json::json!({}))),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_refusal_headers(&h);
        let (_npm, _) = env.npm_backing(&["1.0.0"]).await;
        let pkg = |p: serde_json::Value| {
            doc(
                "com.acme/echo",
                "1.0.0",
                serde_json::json!({"packages": [p]}),
            )
        };
        let mut external = npm_pkg("@acme/echo", Some("1.0.0"));
        external["registryBaseUrl"] = "https://registry.npmjs.org".into();
        let mcpb = serde_json::json!({"registryType": "mcpb", "identifier": "https://g.test/x.mcpb", "fileSha256": "a".repeat(64), "transport": {"type": "stdio"}});
        let oci_latest = serde_json::json!({"registryType": "oci", "identifier": "ghcr.io/acme/mcp:latest", "transport": {"type": "stdio"}});
        let oci_legacy = serde_json::json!({"registryType": "oci", "identifier": "ghcr.io/acme/mcp:1", "version": "1", "transport": {"type": "stdio"}});
        for (d, status, code) in [
            (pkg(external), 422, "mcp_external_registry"),
            (pkg(mcpb), 422, "mcp_package_not_found"),
            (
                pkg(npm_pkg("@acme/echo", None)),
                422,
                "mcp_package_version_unpinned",
            ),
            (
                pkg(npm_pkg("@acme/missing", Some("1.0.0"))),
                422,
                "mcp_package_not_found",
            ),
            (pkg(oci_latest), 422, "mcp_oci_floating_tag"),
            (pkg(oci_legacy), 422, "mcp_oci_legacy_fields"),
            (
                doc("io.modelcontextprotocol/x", "1", serde_json::json!({})),
                403,
                "mcp_namespace_reserved",
            ),
            (
                doc("bad name", "1", serde_json::json!({})),
                400,
                "mcp_invalid_server_json",
            ),
        ] {
            let (s, b, h) = call(env.member(), "POST", &env.url("/publish"), Some(&d)).await;
            let b = json(&b);
            assert_eq!(
                (s.as_u16(), b["error"].as_str()),
                (status, Some(code)),
                "{b}"
            );
            assert_refusal_headers(&h);
            assert_eq!(b["type"], "about:blank");
        }
        env.config(mcp_packages::NAMESPACE_ALLOW_KEY, r#"["com.acme"]"#)
            .await;
        assert_eq!(
            env.publish(&doc("org.other/x", "1", serde_json::json!({})))
                .await
                .1["error"],
            "mcp_namespace_not_allowed"
        );
        assert_eq!(
            env.publish(&doc("com.acme.sub/x", "1", serde_json::json!({})))
                .await
                .0,
            StatusCode::OK
        );

        // 256 KiB + 1 answers 413 problem+json.
        let big = Body::from(vec![b' '; fmt::MCP_PUBLISH_MAX_BYTES + 1]);
        let req = Request::builder()
            .method("POST")
            .uri(env.url("/publish"))
            .body(big)
            .unwrap();
        let (s, b, h) = tdh::send_with_headers(env.member(), req).await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (StatusCode::PAYLOAD_TOO_LARGE, Some("mcp_too_large"))
        );
        assert_refusal_headers(&h);

        // A token without write:artifacts.
        let mut ro = tdh::make_auth(env.fx.user_id, &env.fx.username);
        ro.is_api_token = true;
        ro.scopes = Some(vec!["read:artifacts".into()]);
        let app = tdh::router_with_auth(super::router(), env.fx.state.clone(), ro);
        assert_eq!(
            call(
                app,
                "POST",
                &env.url("/publish"),
                Some(&doc("com.acme/a", "1", serde_json::json!({})))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        // A token scoped to another repository says so.
        let mut other = tdh::make_auth(env.fx.user_id, &env.fx.username);
        other.is_api_token = true;
        other.scopes = Some(vec!["write:artifacts".into()]);
        other.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![Uuid::new_v4()]);
        let app = tdh::router_with_auth(super::router(), env.fx.state.clone(), other);
        let (s, b, h) = call(
            app,
            "POST",
            &env.url("/publish"),
            Some(&doc("com.acme/a", "1", serde_json::json!({}))),
        )
        .await;
        let b = json(&b);
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["error"], "mcp_forbidden");
        assert!(b["detail"]
            .as_str()
            .unwrap()
            .contains("not scoped to this repository"));
        assert_refusal_headers(&h);

        // Another format's repository is not an MCP registry.
        let npm = env.repo("local", "npm").await;
        let (s, b, _) = call(
            env.member(),
            "POST",
            &format!("/{}/v0.1/publish", npm.key),
            Some(&doc("com.acme/a", "1", serde_json::json!({}))),
        )
        .await;
        assert_eq!(
            (s, &b[..]),
            (StatusCode::NOT_FOUND, fmt::NOT_FOUND_BODY.as_bytes())
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn open_policy_stores_and_serves_packages_verbatim() {
        let Some(env) = Env::new().await else { return };
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let mut p = npm_pkg("@acme/elsewhere", Some("3.0.0"));
        p["registryBaseUrl"] = "https://registry.npmjs.org".into();
        let (s, body) = env
            .publish(&doc(
                "com.acme/open",
                "1.0.0",
                serde_json::json!({"packages": [p]}),
            ))
            .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        assert_eq!(
            body["server"]["packages"][0]["registryBaseUrl"],
            "https://registry.npmjs.org"
        );
        let (s, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fopen/versions/latest")
            .await;
        assert_eq!(
            (
                s,
                json(&b)["_meta"][fmt::AK_SOURCE_META_KEY]["packagePolicy"].as_str()
            ),
            (StatusCode::OK, Some("open"))
        );
        // Switching back to own-repos leaves the version unresolvable.
        env.config(mcp_packages::POLICY_KEY, "own-repos").await;
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fopen/versions/1.0.0")
            .await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("mcp_unresolvable"))
        );
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // OCI
    // -----------------------------------------------------------------------

    fn index_body(seed: char) -> Vec<u8> {
        let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d(seed), "size": 1, "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d('9'), "size": 1, "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        }))
        .unwrap()
    }

    const INDEX_MT: &str = "application/vnd.oci.image.index.v1+json";

    async fn seed_oci(env: &mut Env) -> (RepoInfo, String) {
        let oci = env.repo("local", "docker").await;
        let body = index_body('a');
        let digest = format!("sha256:{}", fmt::sha256_hex(&body));
        let key = crate::api::handlers::oci_v2::manifest_storage_key(&digest);
        env.fx
            .state
            .storage_for_repo(&oci.storage_location())
            .unwrap()
            .put(&key, Bytes::from(body))
            .await
            .unwrap();
        sqlx::query("INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) VALUES ($1, 'acme/mcp', '1.2', $2, $3)")
            .bind(oci.id).bind(&digest).bind(INDEX_MT).execute(&env.fx.pool).await.unwrap();
        tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &oci,
            "test-seed/oci-manifest-row",
            "v2/acme/mcp/manifests/1.2",
            "acme/mcp",
            "1.2",
            INDEX_MT,
            Bytes::from_static(b"{}"),
            env.fx.user_id,
            fmt::sha256_hex(&index_body('a')).as_str(),
        )
        .await;
        // The platform children a multi-arch push writes by digest.
        for child in ['a', '9'] {
            let hex = child.to_string().repeat(64);
            tdh::seed_artifact_with_checksum(
                &env.fx.state,
                &env.fx.pool,
                &oci,
                &format!("test-seed/oci-child-{child}"),
                &format!("v2/acme/mcp/manifests/sha256:{hex}"),
                "acme/mcp",
                &format!("sha256:{hex}"),
                "application/vnd.oci.image.manifest.v1+json",
                Bytes::from_static(b"{}"),
                env.fx.user_id,
                &hex,
            )
            .await;
        }
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"oci": oci.key}).to_string(),
        )
        .await;
        (oci, digest)
    }

    fn oci_doc(identifier: &str) -> serde_json::Value {
        doc(
            "com.acme/img",
            "1.0.0",
            serde_json::json!({"packages": [
                {"registryType": "oci", "identifier": identifier, "transport": {"type": "stdio"}}
            ]}),
        )
    }

    #[tokio::test]
    async fn oci_tag_is_pinned_held_and_drift_audited() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (oci, digest) = seed_oci(&mut env).await;
        // A Local backing repository holds only images pushed to this
        // instance: another host is external, even when the path exists.
        assert_eq!(
            env.publish(&oci_doc("ghcr.io/acme/mcp:1.2")).await.1["error"],
            "mcp_external_registry"
        );
        let own = |tail: &str| format!("localhost/{}/acme/{tail}", oci.key);
        let (s, body) = env.publish(&oci_doc(&own("mcp:1.2"))).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let served = body["server"]["packages"][0]["identifier"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            served,
            format!("localhost/{}/acme/mcp:1.2@{digest}", oci.key)
        );
        let resolved = &body["server"]["packages"][0]["_meta"][fmt::AK_RESOLVED_META_KEY];
        assert_eq!(resolved["submittedIdentifier"], own("mcp:1.2"));
        assert_eq!(resolved["children"].as_array().map(Vec::len), Some(2));
        let held: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = $1 AND tag = $2 AND manifest_digest = $2)")
            .bind(oci.id).bind(&digest).fetch_one(&env.fx.pool).await.unwrap();
        assert!(held, "the digest-keyed retention row is written");

        // The tag moves: the served digest does not, the drift is recorded.
        let moved = index_body('b');
        let moved_digest = format!("sha256:{}", fmt::sha256_hex(&moved));
        crate::api::handlers::oci_v2::persist_tag_and_refs(
            &env.fx.pool,
            oci.id,
            "acme/mcp",
            "1.2",
            &moved_digest,
            INDEX_MT,
            &crate::api::handlers::oci_v2::ManifestClass::Index,
            &moved,
        )
        .await
        .unwrap();
        // A push rewrites the tag's manifest row in place.
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $2 WHERE repository_id = $1 AND path = 'v2/acme/mcp/manifests/1.2'")
            .bind(oci.id)
            .bind(fmt::sha256_hex(&moved))
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let (s, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fimg/versions/1.0.0")
            .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(json(&b)["server"]["packages"][0]["identifier"], served);
        // The gate follows the pinned digest, not the rewritten tag row: a
        // held platform child holds the version.
        let children: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM artifacts WHERE repository_id = $1 AND path LIKE 'v2/acme/mcp/manifests/sha256:%'")
            .bind(oci.id)
            .fetch_all(&env.fx.pool)
            .await
            .unwrap();
        for child in &children {
            env.hold(*child, Some("rejected")).await;
        }
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fimg/versions/1.0.0")
            .await;
        assert_eq!(
            (s, json(&b)["gate"].as_str()),
            (StatusCode::NOT_FOUND, Some("scan_policy"))
        );
        for child in &children {
            env.hold(*child, None).await;
        }
        let id = env.server_artifact("com.acme/img", "1.0.0").await;
        let drift: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata->'packages'->0->'drift' FROM artifact_metadata WHERE artifact_id = $1",
        )
        .bind(id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(drift["observedDigest"], moved_digest);
        assert_eq!(
            tdh::audit_count(&env.fx.pool, id, "MCP_PIN_DRIFT_DETECTED").await,
            1
        );
        // The same observation again marks nothing new (no second audit).
        assert!(mcp_packages::mark_pin_drift(
            &env.fx.pool,
            oci.id,
            "acme/mcp",
            "1.2",
            &moved_digest
        )
        .await
        .unwrap()
        .is_empty());
        // The tag back on the pinned digest clears the mark.
        assert!(
            mcp_packages::mark_pin_drift(&env.fx.pool, oci.id, "acme/mcp", "1.2", &digest)
                .await
                .unwrap()
                .is_empty()
        );
        let cleared: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT metadata->'packages'->0->'drift' FROM artifact_metadata WHERE artifact_id = $1",
        )
        .bind(id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert!(cleared.is_none(), "{cleared:?}");

        // Floating and digest-only forms.
        assert_eq!(
            env.publish(&oci_doc(&own("mcp"))).await.1["error"],
            "mcp_oci_floating_tag"
        );
        let mut by_digest = oci_doc(&own(&format!("mcp@{digest}")));
        by_digest["version"] = "2.0.0".into();
        let (s, b) = env.publish(&by_digest).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            b["server"]["packages"][0]["identifier"],
            format!("localhost/{}/acme/mcp@{digest}", oci.key)
        );
        let mut unknown = oci_doc(&own("other:1"));
        unknown["version"] = "3.0.0".into();
        assert_eq!(
            env.publish(&unknown).await.1["error"],
            "mcp_package_not_found"
        );
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Held versions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn held_backing_package_hides_the_version() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                "com.acme/db",
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;

        let (_, list, _) = env.get(env.anon(), "/servers").await;
        let versions: Vec<String> = json(&list)["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["server"]["version"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(versions, vec!["1.0.0"]);
        let (_, latest, _) = env
            .get(env.anon(), "/servers/com.acme%2Fdb/versions/latest")
            .await;
        assert_eq!(
            json(&latest)["server"]["version"],
            "1.0.0",
            "latest falls back to the newest servable"
        );
        let (_, latest_list, _) = env.get(env.anon(), "/servers?version=latest").await;
        assert_eq!(
            json(&latest_list)["servers"][0]["server"]["version"],
            "1.0.0"
        );

        let (_, unknown, unknown_h) = env
            .get(env.anon(), "/servers/com.acme%2Fnope/versions/1.0.0")
            .await;
        let (s, held, held_h) = env
            .get(env.anon(), "/servers/com.acme%2Fdb/versions/2.0.0")
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(
            held, unknown,
            "anonymous held answer is byte-identical to an unknown name"
        );
        assert_eq!(&held[..], fmt::NOT_FOUND_BODY.as_bytes());
        assert_refusal_headers(&held_h);
        assert_refusal_headers(&unknown_h);

        let (s, reason, h) = env
            .get(env.member(), "/servers/com.acme%2Fdb/versions/2.0.0")
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_refusal_headers(&h);
        let r = json(&reason);
        assert_eq!(
            (
                r["error"].as_str(),
                r["gate"].as_str(),
                r["package"].as_str()
            ),
            (
                Some("mcp_backing_artifact_blocked"),
                Some("quarantine"),
                Some("npm:@acme/echo@2.0.0")
            )
        );
        let text = String::from_utf8(reason.to_vec()).unwrap();
        assert!(
            !text.contains(&npm.key) && !text.contains(&ids[1].to_string()),
            "{text}"
        );
        let id2 = env.server_artifact("com.acme/db", "2.0.0").await;
        assert!(
            tdh::audit_count_eventually(&env.fx.pool, id2, "MCP_SERVER_DOWNLOAD_REFUSED", 1).await
                >= 1
        );

        // Both versions held: latest is the plain 404 for a reader.
        env.hold(ids[0], Some("quarantined")).await;
        let (s, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fdb/versions/latest")
            .await;
        assert_eq!(
            (s, &b[..]),
            (StatusCode::NOT_FOUND, fmt::NOT_FOUND_BODY.as_bytes())
        );
        assert_eq!(
            env.get(env.anon(), "/servers/com.acme%2Fdb/versions")
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // Releasing restores; the server.json's own hold is `mcp_pending_review`.
        env.hold(ids[0], None).await;
        env.hold(ids[1], None).await;
        assert_eq!(
            env.get(env.anon(), "/servers/com.acme%2Fdb/versions/2.0.0")
                .await
                .0,
            StatusCode::OK
        );
        env.hold(id2, Some("quarantined")).await;
        let (_, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fdb/versions/2.0.0")
            .await;
        assert_eq!(json(&b)["error"], "mcp_pending_review");
        env.hold(id2, Some("rejected")).await;
        let (_, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fdb/versions/2.0.0")
            .await;
        assert_eq!(json(&b)["error"], "mcp_rejected");
        // A deleted backing artifact makes the version unresolvable.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(ids[0])
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let (_, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fdb/versions/1.0.0")
            .await;
        assert_eq!(json(&b)["error"], "mcp_unresolvable");
        env.teardown().await;
    }

    #[tokio::test]
    async fn unevaluable_gate_fails_closed_with_503() {
        let Some(env) = Env::new().await else { return };
        assert_eq!(
            env.publish(&doc("com.acme/w", "1.0.0", serde_json::json!({})))
                .await
                .0,
            StatusCode::OK
        );
        let row = versions_of(&env.fx.pool, env.fx.repo_id, "com.acme/w")
            .await
            .unwrap()
            .remove(0);
        let closed = tdh::try_pool().await.unwrap();
        closed.close().await;
        let ctx = GateCtx {
            db: &closed,
            age_gate: None,
            record_reviews: false,
        };
        for audience in [GateAudience::ReaderOnly, GateAudience::ReasonGated] {
            match decide_row(
                ctx,
                &row,
                PackagePolicy::OwnRepos,
                false,
                audience,
                "i".into(),
            )
            .await
            {
                ServeDecision::Refuse { status, body, .. } => {
                    assert_eq!(
                        (status, body["error"].as_str()),
                        (503, Some("mcp_gate_unavailable"))
                    );
                }
                ServeDecision::Serve => panic!("a gate that cannot be read must not serve"),
            }
        }
        let listing = vec![mcp_packages::ListingRow {
            artifact_id: row.artifact_id,
            quarantine_status: None,
            quarantine_until: None,
            stored: row.stored.clone(),
        }];
        assert!(
            mcp_packages::listing_refusals(ctx, env.fx.repo_id, &listing, PackagePolicy::OwnRepos)
                .await
                .is_err()
                || servable(
                    ctx,
                    env.fx.repo_id,
                    vec![row.clone()],
                    PackagePolicy::OwnRepos
                )
                .await
                .is_empty()
        );
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Listing, status, CORS
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn listing_paging_filters_and_status() {
        let Some(env) = Env::new().await else { return };
        let empty = env.get(env.anon(), "/servers").await;
        assert_eq!(
            json(&empty.1),
            serde_json::json!({"servers": [], "metadata": {"count": 0}})
        );
        for name in ["com.acme/alpha", "com.acme/beta", "com.acme/weather"] {
            for v in ["1.0.0", "1.10.0"] {
                assert_eq!(
                    env.publish(&doc(name, v, serde_json::json!({}))).await.0,
                    StatusCode::OK
                );
            }
        }
        assert_eq!(
            env.publish(&doc("com.acme/weather", "1.2.0", serde_json::json!({})))
                .await
                .0,
            StatusCode::OK
        );
        // One held row in the middle still yields full pages.
        let held = env.server_artifact("com.acme/beta", "1.0.0").await;
        env.hold(held, Some("quarantined")).await;
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let tail = match &cursor {
                Some(c) => format!("/servers?limit=2&cursor={c}"),
                None => "/servers?limit=2".into(),
            };
            let (s, b, _) = env.get(env.anon(), &tail).await;
            assert_eq!(s, StatusCode::OK);
            let b = json(&b);
            pages += 1;
            for e in b["servers"].as_array().unwrap() {
                seen.push(format!(
                    "{}@{}",
                    e["server"]["name"].as_str().unwrap(),
                    e["server"]["version"].as_str().unwrap()
                ));
            }
            match b["metadata"]["nextCursor"].as_str() {
                Some(c) => {
                    assert_eq!(b["metadata"]["count"], 2);
                    cursor = Some(c.to_string());
                }
                None => break,
            }
        }
        assert_eq!(pages, 3);
        assert_eq!(
            seen,
            vec![
                "com.acme/alpha@1.0.0",
                "com.acme/alpha@1.10.0",
                "com.acme/beta@1.10.0",
                "com.acme/weather@1.0.0",
                "com.acme/weather@1.10.0",
                "com.acme/weather@1.2.0"
            ]
        );
        let (_, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fweather/versions")
            .await;
        let order: Vec<String> = json(&b)["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["server"]["version"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(order, vec!["1.0.0", "1.10.0", "1.2.0"]);
        let (_, b, _) = env.get(env.anon(), "/servers?version=latest").await;
        let latest: Vec<String> = json(&b)["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}@{}",
                    e["server"]["name"].as_str().unwrap(),
                    e["server"]["version"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            latest,
            vec![
                "com.acme/alpha@1.10.0",
                "com.acme/beta@1.10.0",
                "com.acme/weather@1.10.0"
            ]
        );
        let (_, b, _) = env.get(env.anon(), "/servers?version=latest&limit=2").await;
        let b = json(&b);
        assert_eq!(b["metadata"]["count"], 2);
        let c = b["metadata"]["nextCursor"].as_str().unwrap().to_string();
        let (_, b, _) = env
            .get(
                env.anon(),
                &format!("/servers?version=latest&limit=2&cursor={c}"),
            )
            .await;
        let b = json(&b);
        assert_eq!(b["servers"][0]["server"]["name"], "com.acme/weather");
        assert!(b["metadata"].get("nextCursor").is_none());
        let (_, b, _) = env.get(env.anon(), "/servers?version=1.2.0").await;
        assert_eq!(json(&b)["metadata"]["count"], 1);
        let (s, b, h) = env.get(env.anon(), "/servers?search=ab").await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("mcp_search_too_short")
            )
        );
        assert_refusal_headers(&h);
        let (_, b, _) = env.get(env.anon(), "/servers?search=wea").await;
        assert_eq!(json(&b)["metadata"]["count"], 3);
        let (_, b, _) = env.get(env.anon(), "/servers?search=%25%25%25").await;
        assert_eq!(
            json(&b)["metadata"]["count"],
            0,
            "a % in search is a literal"
        );
        assert_eq!(
            env.get(env.anon(), "/servers?cursor=garbage!").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            env.get(env.anon(), "/servers?limit=0").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            env.get(
                env.anon(),
                "/servers?updated_since=2020-01-01T00:00:00Z&include_deleted=false"
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );

        // Status: deprecated stays listed, deleted leaves list and latest.
        let patch = |tail: &str, body: serde_json::Value| {
            let app = env.member();
            let uri = env.url(tail);
            async move { call(app, "PATCH", &uri, Some(&body)).await }
        };
        let (s, b, _) = patch(
            "/servers/com.acme%2Fweather/versions/1.10.0/status",
            serde_json::json!({"status": "deprecated", "statusMessage": "use 1.2"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{:?}", json(&b));
        assert_eq!(
            json(&b)["_meta"][fmt::OFFICIAL_META_KEY]["statusMessage"],
            "use 1.2"
        );
        let (s, _, _) = patch(
            "/servers/com.acme%2Fweather/versions/1.10.0/status",
            serde_json::json!({"status": "deprecated"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "same-state transition");
        let (s, _, _) = patch(
            "/servers/com.acme/weather/versions/1.10.0/status",
            serde_json::json!({"status": "deleted"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (_, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fweather/versions/latest")
            .await;
        assert_eq!(json(&b)["server"]["version"], "1.2.0");
        assert_eq!(
            env.get(env.anon(), "/servers/com.acme%2Fweather/versions/1.10.0")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (s, b, _) = env
            .get(
                env.anon(),
                "/servers/com.acme%2Fweather/versions/1.10.0?include_deleted=true",
            )
            .await;
        assert_eq!(
            (
                s,
                json(&b)["_meta"][fmt::OFFICIAL_META_KEY]["status"].as_str()
            ),
            (StatusCode::OK, Some("deleted"))
        );
        let (_, b, _) = env.get(env.anon(), "/servers?search=weather").await;
        assert_eq!(json(&b)["metadata"]["count"], 2);
        let (_, b, _) = env
            .get(env.anon(), "/servers?search=weather&include_deleted=true")
            .await;
        assert_eq!(json(&b)["metadata"]["count"], 3);
        let (_, b, _) = env
            .get(
                env.anon(),
                "/servers?updated_since=2020-01-01T00:00:00Z&search=weather",
            )
            .await;
        assert_eq!(json(&b)["metadata"]["count"], 3);
        let is_latest: Vec<(String, bool)> = sqlx::query_as("SELECT a.version, (m.metadata->'registry'->>'isLatest')::boolean FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id WHERE a.repository_id = $1 AND a.name = 'com.acme/weather' ORDER BY a.version")
            .bind(env.fx.repo_id).fetch_all(&env.fx.pool).await.unwrap();
        assert_eq!(
            is_latest,
            vec![
                ("1.0.0".into(), false),
                ("1.10.0".into(), false),
                ("1.2.0".into(), true)
            ]
        );
        let (s, b, _) = patch(
            "/servers/com.acme%2Falpha/status",
            serde_json::json!({"status": "deprecated"}),
        )
        .await;
        assert_eq!(
            (s, json(&b)["updatedCount"].as_i64()),
            (StatusCode::OK, Some(2))
        );
        assert_eq!(
            patch(
                "/servers/com.acme%2Fnope/status",
                serde_json::json!({"status": "deprecated"})
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let anon = call(
            env.anon(),
            "PATCH",
            &env.url("/servers/com.acme%2Falpha/status"),
            Some(&serde_json::json!({"status": "active"})),
        )
        .await;
        assert_eq!(anon.0, StatusCode::UNAUTHORIZED);
        env.teardown().await;
    }

    #[tokio::test]
    async fn new_version_moves_is_latest() {
        let Some(env) = Env::new().await else { return };
        assert_eq!(
            env.publish(&doc("com.acme/l", "1.0.0", serde_json::json!({})))
                .await
                .0,
            StatusCode::OK
        );
        let (_, b) = env
            .publish(&doc("com.acme/l", "1.1.0", serde_json::json!({})))
            .await;
        assert_eq!(b["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"], true);
        let (_, b, _) = env
            .get(env.anon(), "/servers/com.acme%2Fl/versions/1.0.0")
            .await;
        assert_eq!(json(&b)["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"], false);
        let (s, b, _) = env.get(env.anon(), "/ping").await;
        assert_eq!(
            (s, json(&b)["status"].as_str()),
            (StatusCode::OK, Some("ok"))
        );
        assert_eq!(env.get(env.anon(), "/health").await.0, StatusCode::OK);
        assert_eq!(
            json(&env.get(env.anon(), "/version").await.1)["version"],
            env!("CARGO_PKG_VERSION")
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn cors_and_security_headers() {
        let Some(env) = Env::new().await else { return };
        let app = env.anon().layer(axum::middleware::from_fn(
            crate::api::middleware::security_headers::security_headers_middleware,
        ));
        let req = Request::builder()
            .uri(env.url("/servers"))
            .header(header::ORIGIN, "https://github.com")
            .body(Body::empty())
            .unwrap();
        let (s, _, h) = tdh::send_with_headers(app.clone(), req).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let preflight = Request::builder()
            .method("OPTIONS")
            .uri(env.url("/servers"))
            .header(header::ORIGIN, "https://github.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap();
        let (_, _, h) = tdh::send_with_headers(app, preflight).await;
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(h[header::ACCESS_CONTROL_ALLOW_METHODS]
            .to_str()
            .unwrap()
            .contains("GET"));
        assert!(h[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap()
            .contains("authorization"));
        // The outer preflight answer, ahead of a same-origin instance CORS layer.
        let outer = Router::new()
            .fallback(|| async { StatusCode::IM_A_TEAPOT })
            .layer(CorsLayer::new())
            .layer(axum::middleware::from_fn(mcp_cors_preflight));
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/mcp/r/v0.1/servers")
            .header(header::ORIGIN, "https://github.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .unwrap();
        let (s, _, h) = tdh::send_with_headers(outer.clone(), req).await;
        assert_eq!(
            (s, h[header::ACCESS_CONTROL_ALLOW_ORIGIN].to_str().unwrap()),
            (StatusCode::OK, "*")
        );
        let (s, _, _) = tdh::send_with_headers(
            outer,
            Request::builder()
                .uri("/other")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::IM_A_TEAPOT);
        env.teardown().await;
    }

    /// Through the real visibility middleware: anonymous reads of a private
    /// repository and a read-only grant's publish are refused before the
    /// handler; a public repository is readable anonymously.
    #[tokio::test]
    async fn visibility_middleware_gates_the_surface() {
        use crate::api::middleware::auth::{repo_visibility_middleware, RepoVisibilityState};
        use std::sync::Arc;
        let Some(env) = Env::new().await else { return };
        let auth_service = Arc::new(crate::services::auth_service::AuthService::new(
            env.fx.pool.clone(),
            Arc::new(env.fx.state.config.clone()),
        ));
        let vis = RepoVisibilityState {
            auth_service: auth_service.clone(),
            db: env.fx.pool.clone(),
            repo_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            repo_miss_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            permission_service: Arc::new(
                crate::services::permission_service::PermissionService::new(env.fx.pool.clone()),
            ),
        };
        let app = Router::new()
            .nest(MOUNT_PREFIX, super::router())
            .with_state(env.fx.state.clone())
            .layer(axum::middleware::from_fn_with_state(
                vis,
                repo_visibility_middleware,
            ));
        let get = |auth: Option<&str>| {
            let mut b = Request::builder().uri(format!("/mcp/{}/v0.1/servers", env.fx.repo_key));
            if let Some(a) = auth {
                b = b.header(header::AUTHORIZATION, a);
            }
            b.body(Body::empty()).unwrap()
        };
        assert_eq!(
            tdh::send(app.clone(), get(None)).await.0,
            StatusCode::UNAUTHORIZED,
            "private repository"
        );
        // Behind the surface guard (as `main.rs` mounts it), the middleware's
        // refusal is problem+json with `no-store` and keeps its challenge.
        let guarded = app
            .clone()
            .layer(axum::middleware::from_fn(mcp_surface_guard));
        let (s, b, h) = tdh::send_with_headers(guarded, get(None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_refusal_headers(&h);
        assert_eq!(json(&b)["error"], "mcp_unauthorized");
        assert!(h.contains_key(header::WWW_AUTHENTICATE));
        let (reader, reader_name) = tdh::create_user(&env.fx.pool).await;
        tdh::grant_repo_role(&env.fx.pool, env.fx.repo_id, reader, "reader").await;
        let _ = reader_name;
        let bearer = tdh::bearer_for(&env.fx.state, reader).await;
        assert_eq!(
            tdh::send(app.clone(), get(Some(&bearer))).await.0,
            StatusCode::OK
        );
        let publish = Request::builder()
            .method("POST")
            .uri(format!("/mcp/{}/v0.1/publish", env.fx.repo_key))
            .header(header::AUTHORIZATION, &bearer)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&doc("com.acme/a", "1", serde_json::json!({}))).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            tdh::send(app.clone(), publish).await.0,
            StatusCode::FORBIDDEN,
            "read-only grant"
        );
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let app2 = Router::new()
            .nest(MOUNT_PREFIX, super::router())
            .with_state(env.fx.state.clone())
            .layer(axum::middleware::from_fn_with_state(
                RepoVisibilityState {
                    auth_service,
                    db: env.fx.pool.clone(),
                    repo_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
                    repo_miss_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
                    permission_service: Arc::new(
                        crate::services::permission_service::PermissionService::new(
                            env.fx.pool.clone(),
                        ),
                    ),
                },
                repo_visibility_middleware,
            ));
        assert_eq!(
            tdh::send(app2, get(None)).await.0,
            StatusCode::OK,
            "public repository"
        );
        tdh::cleanup_user(&env.fx.pool, reader).await;
        env.teardown().await;
    }

    /// T6: publisher URLs are never dereferenced, on publish or on any read.
    #[tokio::test]
    async fn mcp_no_outbound() {
        let Some(env) = Env::new().await else { return };
        let (mock, _guard) = tdh::non_loopback_mock_server().await;
        let target = mock.uri();
        let d = doc(
            "com.acme/probe",
            "1.0.0",
            serde_json::json!({
                "websiteUrl": format!("{target}/site"),
                "repository": {"url": format!("{target}/repo"), "source": "github"},
                "icons": [{"src": format!("{target}/icon.png")}],
                "remotes": [{"type": "streamable-http", "url": "http://127.0.0.1:1/mcp"}, {"type": "sse", "url": format!("{target}/sse")}],
            }),
        );
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        for tail in [
            "/servers",
            "/servers/com.acme%2Fprobe/versions",
            "/servers/com.acme%2Fprobe/versions/1.0.0",
            "/servers/com.acme%2Fprobe/versions/latest",
        ] {
            assert_eq!(env.get(env.anon(), tail).await.0, StatusCode::OK, "{tail}");
        }
        let (s, _, _) = call(
            env.member(),
            "PATCH",
            &env.url("/servers/com.acme%2Fprobe/versions/1.0.0/status"),
            Some(&serde_json::json!({"status": "deprecated"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(mock.received_requests().await.unwrap_or_default().len(), 0);
        let path: String =
            sqlx::query_scalar("SELECT path FROM artifacts WHERE repository_id = $1")
                .bind(env.fx.repo_id)
                .fetch_one(&env.fx.pool)
                .await
                .unwrap();
        assert_eq!(path, "servers/com.acme/probe/1.0.0/server.json");
        tdh::drop_mock_server(mock).await;
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Review fixes (#5253 review)
    // -----------------------------------------------------------------------

    fn latest_flag(entry: &serde_json::Value) -> Option<bool> {
        entry["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"].as_bool()
    }

    /// The age gate of a Remote a pinned package was pulled through holds
    /// the version until the cached copy is old enough or a review approves
    /// it; a rejection holds; no age-gate service fails closed.
    #[tokio::test]
    async fn backing_package_age_gate_holds_the_version() {
        use crate::services::age_gate_service::AgeGateService;
        use std::sync::Arc;
        let Some(mut env) = Env::new().await else {
            return;
        };
        let remote = env.repo("remote", "npm").await;
        sqlx::query(
            "UPDATE repositories SET age_gate_enabled = true, age_gate_min_age_days = 7 \
             WHERE id = $1",
        )
        .bind(remote.id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let cached = tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &remote,
            "npm/echo-age.tgz",
            "@acme/echo/-/echo-1.0.0.tgz",
            "@acme/echo",
            "1.0.0",
            "application/octet-stream",
            Bytes::from_static(b"tgz"),
            env.fx.user_id,
            &"a".repeat(64),
        )
        .await;
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"npm": remote.key}).to_string(),
        )
        .await;
        let d = doc(
            "com.acme/aged",
            "1.0.0",
            serde_json::json!({"packages": [npm_pkg("@acme/echo", Some("1.0.0"))]}),
        );
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let row = versions_of(&env.fx.pool, env.fx.repo_id, "com.acme/aged")
            .await
            .unwrap()
            .remove(0);
        let svc = AgeGateService::new(
            env.fx.pool.clone(),
            Arc::new(crate::services::event_bus::EventBus::new(4)),
        );
        let ctx = |record_reviews| GateCtx {
            db: &env.fx.pool,
            age_gate: Some(&svc),
            record_reviews,
        };
        let decide = |ctx, audience| {
            decide_row(
                ctx,
                &row,
                PackagePolicy::OwnRepos,
                false,
                audience,
                "i".into(),
            )
        };
        // Cached just now: held. The listing is read-only and omits it.
        match decide(ctx(false), GateAudience::ReasonGated).await {
            ServeDecision::Refuse { status, body, .. } => {
                assert_eq!(status, 404);
                assert_eq!(body["error"], "mcp_age_gate_blocked");
                assert_eq!(body["gate"], "age_gate");
                assert_eq!(body["min_age_days"], 7);
                assert_eq!(body["requested_age_days"], 0);
                assert!(body["review_id"].is_null(), "{body}");
            }
            ServeDecision::Serve => panic!("a package younger than the age gate must hold"),
        }
        match decide(ctx(false), GateAudience::ReaderOnly).await {
            ServeDecision::Refuse { body, .. } => {
                assert_eq!(
                    serde_json::to_vec(&body).unwrap(),
                    fmt::NOT_FOUND_BODY.as_bytes()
                )
            }
            ServeDecision::Serve => panic!("held for readers too"),
        }
        assert!(servable(
            ctx(false),
            env.fx.repo_id,
            vec![row.clone()],
            PackagePolicy::OwnRepos
        )
        .await
        .is_empty());
        let reviews = || async {
            sqlx::query_as::<_, (Uuid, String, Option<DateTime<Utc>>)>(
                "SELECT id, status, upstream_published_at FROM age_gate_reviews \
                 WHERE repository_id = $1 AND package_name = '@acme/echo' \
                   AND package_version = '1.0.0'",
            )
            .bind(remote.id)
            .fetch_all(&env.fx.pool)
            .await
            .unwrap()
        };
        assert!(reviews().await.is_empty(), "a listing records nothing");
        // An exact read records a pending review an administrator can act on,
        // with an unknown publish time (never the cache time).
        let review_id = match decide(ctx(true), GateAudience::ReasonGated).await {
            ServeDecision::Refuse { body, .. } => body["review_id"].as_str().unwrap().to_string(),
            ServeDecision::Serve => panic!("still held"),
        };
        let recorded = reviews().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0.to_string(), review_id);
        assert_eq!((recorded[0].1.as_str(), recorded[0].2), ("pending", None));
        // A manual approval releases it, everywhere.
        sqlx::query(
            "UPDATE age_gate_reviews SET status = 'approved', reviewed_by = $2 WHERE id = $1",
        )
        .bind(recorded[0].0)
        .bind(env.fx.user_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(
            decide(ctx(false), GateAudience::ReaderOnly).await,
            ServeDecision::Serve
        );
        assert_eq!(
            servable(
                ctx(false),
                env.fx.repo_id,
                vec![row.clone()],
                PackagePolicy::OwnRepos
            )
            .await
            .len(),
            1
        );
        // A rejection holds, old or not.
        sqlx::query("UPDATE age_gate_reviews SET status = 'rejected' WHERE id = $1")
            .bind(recorded[0].0)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
            .bind(cached)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert!(matches!(
            decide(ctx(false), GateAudience::ReasonGated).await,
            ServeDecision::Refuse { body, .. } if body["error"] == "mcp_age_gate_blocked"
        ));
        // No review, cached 30 days ago: old enough.
        sqlx::query("DELETE FROM age_gate_reviews WHERE repository_id = $1")
            .bind(remote.id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(
            decide(ctx(false), GateAudience::ReaderOnly).await,
            ServeDecision::Serve
        );
        // A gated Remote with no age-gate service cannot be evaluated: 503.
        let blind = GateCtx {
            db: &env.fx.pool,
            age_gate: None,
            record_reviews: false,
        };
        assert!(matches!(
            decide(blind, GateAudience::ReaderOnly).await,
            ServeDecision::Refuse { status: 503, .. }
        ));
        env.teardown().await;
    }

    /// A stored proxy-scan verdict of the Remote an npm package was pulled
    /// through holds the version (it was only enforced for OCI pins).
    #[tokio::test]
    async fn remote_proxy_verdict_holds_a_non_oci_pin() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let remote = env.repo("remote", "npm").await;
        let sha = format!("{:064x}", Uuid::new_v4().as_u128());
        tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &remote,
            "npm/echo-verdict.tgz",
            "@acme/echo/-/echo-1.0.0.tgz",
            "@acme/echo",
            "1.0.0",
            "application/octet-stream",
            Bytes::from_static(b"tgz"),
            env.fx.user_id,
            &sha,
        )
        .await;
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"npm": remote.key}).to_string(),
        )
        .await;
        let d = doc(
            "com.acme/verdict",
            "1.0.0",
            serde_json::json!({"packages": [npm_pkg("@acme/echo", Some("1.0.0"))]}),
        );
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let tail = "/servers/com.acme%2Fverdict/versions/1.0.0";
        assert_eq!(env.get(env.anon(), tail).await.0, StatusCode::OK);
        tdh::enable_proxy_scan(&env.fx.pool, remote.id, "fail_open").await;
        sqlx::query(
            "INSERT INTO proxy_scan_results (checksum_sha256, scan_type, verdict, findings_count, \
             critical_count, high_count, medium_count, low_count, max_severity) \
             VALUES ($1, 'grype', 'vulnerable', 1, 1, 0, 0, 0, 'critical')",
        )
        .bind(&sha)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (s, b, _) = env.get(env.member(), tail).await;
        assert_eq!(
            (s, json(&b)["gate"].as_str()),
            (StatusCode::NOT_FOUND, Some("scan_policy"))
        );
        let (_, list, _) = env.get(env.anon(), "/servers").await;
        assert_eq!(json(&list)["metadata"]["count"], 0);
        for sql in ["DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1"] {
            let _ = sqlx::query(sql).bind(&sha).execute(&env.fx.pool).await;
        }
        let _ = sqlx::query("DELETE FROM scan_configs WHERE repository_id = $1")
            .bind(remote.id)
            .execute(&env.fx.pool)
            .await;
        env.teardown().await;
    }

    /// A single-arch image pinned by tag through a Virtual mapping whose
    /// member is Local: the member gets the retention hold, and the version
    /// stays gateable (and served) after the tag moves.
    #[tokio::test]
    async fn single_arch_pin_through_a_virtual_survives_a_tag_move() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let member = env.repo("local", "docker").await;
        let virt = env.repo("virtual", "docker").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virt.id)
        .bind(member.id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let image = |seed: char| {
            let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": d(seed), "size": 1},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d('7'), "size": 1}],
            }))
            .unwrap()
        };
        const IMAGE_MT: &str = "application/vnd.oci.image.manifest.v1+json";
        let body = image('c');
        let hex = fmt::sha256_hex(&body);
        let digest = format!("sha256:{hex}");
        env.fx
            .state
            .storage_for_repo(&member.storage_location())
            .unwrap()
            .put(
                &crate::api::handlers::oci_v2::manifest_storage_key(&digest),
                Bytes::from(body),
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) VALUES ($1, 'acme/one', '1.0', $2, $3)")
            .bind(member.id).bind(&digest).bind(IMAGE_MT).execute(&env.fx.pool).await.unwrap();
        // A tag push writes only the tag-path manifest row.
        crate::api::handlers::oci_v2::upsert_manifest_artifact(
            &env.fx.pool,
            member.id,
            "acme/one",
            "1.0",
            &digest,
            IMAGE_MT,
            &crate::api::handlers::oci_v2::manifest_storage_key(&digest),
            10,
            Some(env.fx.user_id),
            None,
        )
        .await
        .unwrap();
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"oci": virt.key}).to_string(),
        )
        .await;
        let mut d = oci_doc("ghcr.io/acme/one:1.0");
        d["name"] = "com.acme/one".into();
        let (s, b) = env.publish(&d).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        // The member (Local) holds the pin, though the mapping is Virtual.
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = $1 AND tag = $2 AND manifest_digest = $2)",
        )
        .bind(member.id)
        .bind(&digest)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert!(held, "retention hold in the resolved (member) repository");
        let digest_row: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 \
             AND checksum_sha256 = $3 AND is_deleted = false",
        )
        .bind(member.id)
        .bind(format!("v2/acme/one/manifests/{digest}"))
        .bind(&hex)
        .fetch_optional(&env.fx.pool)
        .await
        .unwrap();
        let digest_row = digest_row.expect("the hold writes a digest-path manifest row");

        // The tag moves: the push rewrites the tag-path row in place.
        let moved = image('d');
        let moved_digest = format!("sha256:{}", fmt::sha256_hex(&moved));
        crate::api::handlers::oci_v2::upsert_manifest_artifact(
            &env.fx.pool,
            member.id,
            "acme/one",
            "1.0",
            &moved_digest,
            IMAGE_MT,
            &crate::api::handlers::oci_v2::manifest_storage_key(&moved_digest),
            10,
            Some(env.fx.user_id),
            None,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE oci_tags SET manifest_digest = $2 WHERE repository_id = $1 AND tag = '1.0'",
        )
        .bind(member.id)
        .bind(&moved_digest)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let tail = "/servers/com.acme%2Fone/versions/1.0.0";
        let (s, b, _) = env.get(env.anon(), tail).await;
        assert_eq!(
            s,
            StatusCode::OK,
            "still gateable after the tag move: {:?}",
            json(&b)
        );
        // ... and gated on the pinned bytes' own row.
        env.hold(digest_row, Some("rejected")).await;
        let (s, b, _) = env.get(env.member(), tail).await;
        assert_eq!(
            (s, json(&b)["gate"].as_str()),
            (StatusCode::NOT_FOUND, Some("scan_policy"))
        );
        env.teardown().await;
    }

    /// `isLatest` is the newest servable version on every read, and
    /// `version=latest` picks the newest before `updated_since` filters.
    #[tokio::test]
    async fn is_latest_follows_holds_and_latest_ignores_older_updates() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (_npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                "com.acme/lat",
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        let (_, list, _) = env.get(env.anon(), "/servers").await;
        let list = json(&list);
        assert_eq!(list["metadata"]["count"], 1);
        assert_eq!(latest_flag(&list["servers"][0]), Some(true), "{list}");
        let (_, versions, _) = env
            .get(env.anon(), "/servers/com.acme%2Flat/versions")
            .await;
        assert_eq!(latest_flag(&json(&versions)["servers"][0]), Some(true));
        let (_, exact, _) = env
            .get(env.anon(), "/servers/com.acme%2Flat/versions/1.0.0")
            .await;
        assert_eq!(latest_flag(&json(&exact)), Some(true));
        env.hold(ids[1], None).await;
        let (_, exact, _) = env
            .get(env.anon(), "/servers/com.acme%2Flat/versions/1.0.0")
            .await;
        assert_eq!(latest_flag(&json(&exact)), Some(false));
        let (_, list, _) = env.get(env.anon(), "/servers").await;
        let flags: Vec<Option<bool>> = json(&list)["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(latest_flag)
            .collect();
        assert_eq!(flags, vec![Some(false), Some(true)]);

        // 2.0.0 was last updated long ago, 1.0.0 recently: the latest is
        // still 2.0.0, which `updated_since` then filters out.
        let v2 = env.server_artifact("com.acme/lat", "2.0.0").await;
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{registry,updatedAt}', \
             to_jsonb('2020-01-01T00:00:00Z'::text)) WHERE artifact_id = $1",
        )
        .bind(v2)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (_, l, _) = env
            .get(
                env.anon(),
                "/servers?version=latest&updated_since=2025-01-01T00:00:00Z",
            )
            .await;
        assert_eq!(json(&l)["metadata"]["count"], 0, "{}", json(&l));
        let (_, l, _) = env.get(env.anon(), "/servers?version=latest").await;
        assert_eq!(json(&l)["servers"][0]["server"]["version"], "2.0.0");
        env.teardown().await;
    }

    /// Rows whose metadata cannot be read do not end a listing early, and a
    /// `version=latest` listing pages by server with a resume cursor.
    #[tokio::test]
    async fn listing_cursor_survives_unreadable_rows() {
        let Some(env) = Env::new().await else { return };
        for name in ["com.acme/pa", "com.acme/pb", "com.acme/pc", "com.acme/pd"] {
            assert_eq!(
                env.publish(&doc(name, "1.0.0", serde_json::json!({})))
                    .await
                    .0,
                StatusCode::OK
            );
        }
        let pb = env.server_artifact("com.acme/pb", "1.0.0").await;
        sqlx::query("UPDATE artifact_metadata SET metadata = '{}'::jsonb WHERE artifact_id = $1")
            .bind(pb)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let names = |v: &serde_json::Value| -> Vec<String> {
            v["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["server"]["name"].as_str().unwrap().to_string())
                .collect()
        };
        let (_, p1, _) = env.get(env.anon(), "/servers?limit=2").await;
        let p1 = json(&p1);
        assert_eq!(names(&p1), vec!["com.acme/pa", "com.acme/pc"]);
        let cursor = p1["metadata"]["nextCursor"]
            .as_str()
            .expect("a dropped row does not end the listing")
            .to_string();
        let (_, p2, _) = env
            .get(env.anon(), &format!("/servers?limit=2&cursor={cursor}"))
            .await;
        let p2 = json(&p2);
        assert_eq!(names(&p2), vec!["com.acme/pd"]);
        assert!(p2["metadata"].get("nextCursor").is_none());

        let (_, l1, _) = env.get(env.anon(), "/servers?version=latest&limit=1").await;
        let l1 = json(&l1);
        assert_eq!(names(&l1), vec!["com.acme/pa"]);
        let c = l1["metadata"]["nextCursor"].as_str().unwrap().to_string();
        let (_, l2, _) = env
            .get(
                env.anon(),
                &format!("/servers?version=latest&limit=2&cursor={c}"),
            )
            .await;
        let l2 = json(&l2);
        assert_eq!(names(&l2), vec!["com.acme/pc", "com.acme/pd"]);
        assert!(l2["metadata"].get("nextCursor").is_none(), "{l2}");
        env.teardown().await;
    }

    /// Mapping a repository needs read on it, and an unreadable repository
    /// answers exactly like a missing one.
    #[tokio::test]
    async fn mapping_needs_read_on_the_backing_repository() {
        use crate::models::repository::RepositoryFormat;
        let Some(mut env) = Env::new().await else {
            return;
        };
        let npm = env.repo("local", "npm").await;
        let pypi = env.repo("local", "pypi").await;
        let (uid, uname) = tdh::create_user(&env.fx.pool).await;
        let caller = tdh::make_auth(uid, &uname);
        let try_map = |key: String| {
            let pool = env.fx.pool.clone();
            let caller = caller.clone();
            async move {
                let map: std::collections::BTreeMap<String, String> =
                    [("npm".to_string(), key)].into_iter().collect();
                mcp_packages::settings_to_store(
                    &pool,
                    &caller,
                    &RepositoryFormat::Mcp,
                    None,
                    Some(&map),
                    None,
                    false,
                )
                .await
                .map_err(|e| e.to_string())
            }
        };
        let hidden = try_map(npm.key.clone()).await.unwrap_err();
        let missing = try_map("ph-no-such-repo".into()).await.unwrap_err();
        assert_eq!(
            hidden.replace(&npm.key, "K"),
            missing.replace("ph-no-such-repo", "K"),
            "not readable answers as not found"
        );
        // An internal repository still needs a grant.
        sqlx::query("UPDATE repositories SET visibility = 'internal' WHERE id = $1")
            .bind(npm.id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert!(try_map(npm.key.clone()).await.is_err());
        tdh::grant_repo_role(&env.fx.pool, npm.id, uid, "reader").await;
        assert!(try_map(npm.key.clone()).await.is_ok());
        // A format mismatch is only reported for a readable repository.
        tdh::publish_repo(&env.fx.pool, pypi.id).await;
        assert!(try_map(pypi.key.clone())
            .await
            .unwrap_err()
            .contains("is a pypi repository"));
        tdh::cleanup_user(&env.fx.pool, uid).await;
        env.teardown().await;
    }

    /// Write paths: a status change is refused on a promotion-only
    /// repository, a version deleted through the artifact API cannot be
    /// republished while it is in the trash, and the utility routes answer
    /// only for an MCP registry.
    #[tokio::test]
    async fn write_gates_and_utility_routes() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let d = doc("com.acme/wg", "1.0.0", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        env.fx.set_promotion_only(true).await;
        let (s, b, _) = call(
            env.member(),
            "PATCH",
            &env.url("/servers/com.acme%2Fwg/versions/1.0.0/status"),
            Some(&serde_json::json!({"status": "deprecated"})),
        )
        .await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (StatusCode::CONFLICT, Some("mcp_promotion_only"))
        );
        env.fx.set_promotion_only(false).await;
        let id = env.server_artifact("com.acme/wg", "1.0.0").await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let mut changed = d.clone();
        changed["description"] = "Different bytes".into();
        let (s, b) = env.publish(&changed).await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::CONFLICT, Some("mcp_version_exists"))
        );
        let npm = env.repo("local", "npm").await;
        for tail in ["ping", "health", "version"] {
            let (s, b, h) = call(
                env.anon(),
                "GET",
                &format!("/{}/v0.1/{tail}", npm.key),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{tail}");
            assert_eq!(&b[..], fmt::NOT_FOUND_BODY.as_bytes());
            assert_refusal_headers(&h);
        }
        env.teardown().await;
    }

    /// Generic artifact writes into an MCP registry are refused (they would
    /// bypass validation, namespace policy and pinning); trusted
    /// replication still lands.
    #[test]
    fn generic_writes_into_an_mcp_registry_are_refused() {
        use crate::api::handlers::repositories::reject_generic_write_to_mcp;
        use crate::models::repository::RepositoryFormat;
        let user = tdh::make_auth(Uuid::new_v4(), "u");
        let admin = tdh::admin_auth(Uuid::new_v4(), "a");
        let plain = HeaderMap::new();
        let mut replication = HeaderMap::new();
        replication.insert(
            "x-artifact-keeper-replication",
            HeaderValue::from_static("true"),
        );
        let refused = reject_generic_write_to_mcp(&RepositoryFormat::Mcp, &user, &plain)
            .expect_err("a member's generic write");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Mcp, &admin, &plain).is_err());
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Mcp, &user, &replication).is_err());
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Mcp, &admin, &replication).is_ok());
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Npm, &user, &plain).is_ok());
    }

    /// Refusals from the shared middleware on `/mcp/` paths are
    /// problem+json with `no-store` and the read CORS headers; other paths
    /// are untouched; a refusal the router re-renders keeps its CORS header.
    #[tokio::test]
    async fn surface_guard_and_cors_order() {
        let plain = |status: StatusCode| async move {
            let mut r = (status, "plain text").into_response();
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"ak\""),
            );
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("7"));
            r
        };
        let app = Router::new()
            .route(
                "/mcp/r/v0.1/servers",
                get(move || plain(StatusCode::UNAUTHORIZED)),
            )
            .route(
                "/mcp/r/v0.1/limited",
                get(move || plain(StatusCode::TOO_MANY_REQUESTS)),
            )
            .route(
                "/mcp/r/v0.1/hidden",
                get(|| async { StatusCode::NOT_FOUND }),
            )
            .route("/npm/r/x", get(move || plain(StatusCode::UNAUTHORIZED)))
            .layer(axum::middleware::from_fn(mcp_surface_guard));
        let send = |uri: &str| {
            tdh::send_with_headers(
                app.clone(),
                Request::builder()
                    .uri(uri)
                    .header(header::ORIGIN, "https://github.com")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let (s, b, h) = send("/mcp/r/v0.1/servers").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_refusal_headers(&h);
        assert_eq!(json(&b)["error"], "mcp_unauthorized");
        assert_eq!(h[header::WWW_AUTHENTICATE], "Bearer realm=\"ak\"");
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        let (s, b, h) = send("/mcp/r/v0.1/limited").await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_refusal_headers(&h);
        assert_eq!(json(&b)["error"], "mcp_rate_limited");
        assert_eq!(h[header::RETRY_AFTER], "7");
        let (_, _, h) = send("/npm/r/x").await;
        assert_eq!(h[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert!(h.get(header::CACHE_CONTROL).is_none());

        // A middleware 404 carries the headers of the router's own
        // unknown-name answer, so the two cannot be told apart.
        let (s, b, guarded) = send("/mcp/r/v0.1/hidden").await;
        assert_eq!(
            (s, &b[..]),
            (StatusCode::NOT_FOUND, fmt::NOT_FOUND_BODY.as_bytes())
        );
        let own = Router::new()
            .route("/mcp/r/v0.1/hidden", get(|| async { not_found() }))
            .layer(read_cors());
        let (_, own_b, own_h) = tdh::send_with_headers(
            own,
            Request::builder()
                .uri("/mcp/r/v0.1/hidden")
                .header(header::ORIGIN, "https://github.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(own_b, b);
        let names = |h: &HeaderMap| -> Vec<(String, String)> {
            let mut v: Vec<(String, String)> = h
                .iter()
                .filter(|(k, _)| *k != header::CONTENT_LENGTH && *k != header::DATE)
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&guarded), names(&own_h));

        // Inside the router: a re-rendered refusal on a read route keeps the
        // read CORS header (ensure_problem sits inside read_cors).
        let Some(env) = Env::new().await else { return };
        let (s, _, h) = tdh::send_with_headers(
            env.anon(),
            Request::builder()
                .method("DELETE")
                .uri(env.url("/servers"))
                .header(header::ORIGIN, "https://github.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
        assert_refusal_headers(&h);
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        env.teardown().await;
    }
}
