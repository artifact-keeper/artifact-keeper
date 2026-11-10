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
    RegistryState, ServeDecision, ServerStatus, StoredVersion, VersionState,
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
/// browser client can read it. A read answer never carries
/// `Access-Control-Allow-Credentials`: the instance CORS layer (development
/// mode, `allow_credentials`) adds it to every response it handles, and a
/// read route is any-origin without credentials, so the header is dropped
/// and an origin the instance layer echoed becomes `*` again. Every other
/// path passes through untouched.
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
    if read {
        let h = out.headers_mut();
        h.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
        if h.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
            h.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            );
        }
    }
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

/// A JSON answer that no cache may keep: a version detail (which can carry
/// a per-caller bundle ticket), a write's result, a token. Listings use
/// [`json_listing`].
pub(crate) fn json_ok(status: StatusCode, value: &serde_json::Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::to_vec(value).unwrap_or_default(),
    )
        .into_response()
}

/// A listing (`/servers`, `/servers/{name}/versions`): what it holds is
/// decided per caller and can change on the next read (a hold, a deny-list
/// entry), so only the caller's own cache may keep it, revalidated on every
/// use and keyed on the credential.
pub(crate) fn json_listing(value: &serde_json::Value) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "private, no-cache"),
            (header::VARY, "Authorization, Cookie"),
        ],
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

/// The routes only a Hosted or Remote MCP repository serves (`/validate`,
/// bundle downloads, and the stored-row reads a Virtual dispatches to its
/// own read path before reaching here). A Virtual repository answers `501
/// mcp_not_implemented` on them: it has no rows or bundles of its own.
pub(crate) fn reject_if_not_hosted_read(repo: &RepoInfo) -> Result<(), Response> {
    if matches!(repo.repo_type.as_str(), "local" | "staging" | "remote") {
        return Ok(());
    }
    Err(problem(
        501,
        "mcp_not_implemented",
        "A Virtual MCP registry does not serve this endpoint: it has no documents or bundles \
         of its own; call it on one of the Virtual's member repositories",
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
    gates.extend(mcp_packages::backing_gates(ctx, &row.stored).await);
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
    let server = fmt::rewrite_packages_for_serve(&row.stored.server, &row.stored.pins, base);
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
        // Rows ingested before the origin was stored stripped may still
        // carry userinfo: strip it on serve as well.
        source["upstreamUrl"] = match url.as_str() {
            Some(u) => crate::services::mcp_remote::display_upstream(u).into(),
            None => url.clone(),
        };
    }
    fmt::envelope(server, &registry, source)
}

/// The server.json a generic content route serves for the stored artifact
/// `artifact_id` (#5452): the repository download, the tree content and the
/// artifact metadata routes. It is the document the registry surface serves,
/// every pinned package rewritten to its Artifact Keeper coordinates
/// ([`fmt::rewrite_packages_for_serve`]), never the stored submission, whose
/// `registryBaseUrl` or image host may name a registry Artifact Keeper does
/// not gate. `Ok(None)` for an artifact that is not an MCP server version (a
/// bundle, or any other format); an MCP metadata document that does not parse
/// is an error, never a fallback to the stored bytes.
pub(crate) async fn served_server_json(
    db: &PgPool,
    artifact_id: Uuid,
    base: &str,
) -> crate::error::Result<Option<serde_json::Value>> {
    let doc: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT metadata FROM artifact_metadata WHERE artifact_id = $1 AND format = 'mcp'",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
    let Some(doc) = doc else {
        return Ok(None);
    };
    let stored = StoredVersion::from_metadata(&doc).ok_or_else(|| {
        crate::error::AppError::Internal("unreadable MCP server version".to_string())
    })?;
    Ok(Some(fmt::rewrite_packages_for_serve(
        &stored.server,
        &stored.pins,
        base,
    )))
}

/// An artifact's metadata document with an MCP server version's `server`
/// replaced by its served form ([`served_server_json`]); unchanged when
/// `served` is `None` (any other artifact).
pub(crate) fn with_served_server(
    mut metadata: serde_json::Value,
    served: Option<serde_json::Value>,
) -> serde_json::Value {
    if let (Some(doc), Some(obj)) = (served, metadata.as_object_mut()) {
        obj.insert("server".into(), doc);
    }
    metadata
}

// ---------------------------------------------------------------------------
// The generic catalog (`/api/v1/packages`) view
// ---------------------------------------------------------------------------

/// The rows of `rows` a reader is shown on a listing, in order: the one
/// visibility predicate of every generic surface (#5454). A soft-deleted
/// (`deleted`) version is left out, then [`servable`] applies the
/// reader-only gate (held, refused, resolving, unresolvable, shadowed or
/// denied versions go; an unevaluable gate omits them all, fail closed).
pub(crate) async fn reader_listed(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: Vec<VersionRow>,
) -> Vec<VersionRow> {
    let rows: Vec<VersionRow> = rows
        .into_iter()
        .filter(|r| r.stored.registry.status != fmt::ServerStatus::Deleted)
        .collect();
    servable(ctx, repo_id, rows).await
}

/// What `/api/v1/packages` shows a caller of an MCP catalog row (#5253). The
/// row records the newest version published or ingested, whatever its holds;
/// the registry surface decides per reader ([`servable`]), and so does the
/// catalog now.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CatalogView {
    /// The row as stored. `servable` is whether readers are served that
    /// version now (a holder sees a held version, flagged).
    Keep { servable: bool },
    /// A reader is shown the server's newest servable version instead
    /// (`artifact_id` is its server.json artifact).
    Show {
        artifact_id: Uuid,
        version: String,
        description: Option<String>,
        metadata: serde_json::Value,
    },
    /// No version of the server is served to this reader: no row.
    Hide,
}

/// The [`CatalogView`] of the MCP catalog row `name@version` in `repo_id` for
/// `auth`. A holder (instance admin, or `read` through a grant or role: the
/// reason gate) keeps the row; any other reader sees the newest version the
/// reader-only gate serves, or nothing. A gate that cannot be evaluated
/// hides the row from readers (fail closed).
pub(crate) async fn catalog_view(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo_id: Uuid,
    name: &str,
    version: &str,
) -> CatalogView {
    let Ok(rows) = versions_of(&state.db, repo_id, name).await else {
        return CatalogView::Hide;
    };
    let ctx = GateCtx::of(state, false);
    let own: Vec<VersionRow> = rows
        .iter()
        .filter(|r| r.version == version)
        .cloned()
        .collect();
    let own_servable = !own.is_empty() && !reader_listed(ctx, repo_id, own).await.is_empty();
    if own_servable || audience(&state.db, auth, repo_id).await == GateAudience::ReasonGated {
        return CatalogView::Keep {
            servable: own_servable,
        };
    }
    let none = std::collections::HashSet::new();
    let Ok(Some(row)) = newest_servable(ctx, repo_id, rows, &none).await.0 else {
        return CatalogView::Hide;
    };
    let metadata: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(row.artifact_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some(metadata) = metadata else {
        return CatalogView::Hide;
    };
    CatalogView::Show {
        artifact_id: row.artifact_id,
        version: row.version.clone(),
        description: metadata
            .pointer("/server/description")
            .and_then(|d| d.as_str())
            .map(str::to_string),
        metadata: fmt::catalog_metadata(&metadata),
    }
}

/// The versions of `name` in `repo_id` a `/api/v1/packages/{id}/versions`
/// caller may see: `None` for a holder (all of them), otherwise the versions
/// readers are served now.
pub(crate) async fn catalog_visible_versions(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo_id: Uuid,
    name: &str,
) -> Option<std::collections::HashSet<String>> {
    if audience(&state.db, auth, repo_id).await == GateAudience::ReasonGated {
        return None;
    }
    let Ok(rows) = versions_of(&state.db, repo_id, name).await else {
        return Some(Default::default());
    };
    Some(
        reader_listed(GateCtx::of(state, false), repo_id, rows)
            .await
            .into_iter()
            .map(|r| r.version)
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// The generic artifact routes (`/api/v1/repositories/{key}/artifacts`, ...)
// ---------------------------------------------------------------------------

/// The `name@version` an artifact path of an MCP repository belongs to: its
/// `servers/<name>/<version>/server.json`, or a bundle stored beside it
/// (`servers/<name>/<version>/bundles/<file>`). `None` for any other path.
pub(crate) fn owning_version(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("servers/")?;
    let nv = match rest.strip_suffix("/server.json") {
        Some(nv) => nv,
        None => &rest[..rest.find("/bundles/")?],
    };
    let (name, version) = nv.rsplit_once('/')?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

/// The MCP serve decision for the generic artifact routes (#5253): a
/// listing, a metadata read, a revision history or a download of an MCP
/// repository's artifact answers a reader exactly as the `/v0.1` surface
/// does. A holder (instance administrator, or `read` through a grant or role:
/// the reason gate) sees every stored version; any other caller sees an
/// artifact only while its owning version is served to readers now
/// ([`decide_row`] with the reader audience and no deleted versions), so a
/// held, refused, resolving, unresolvable or soft-deleted version is left out
/// of listings and is the route's plain `404` elsewhere. A path that belongs
/// to no server version, and a gate that cannot be evaluated, are hidden from
/// readers (fail closed). Decisions are cached per repository and version
/// for one request.
pub(crate) struct GenericArtifactGate<'a> {
    state: &'a SharedState,
    auth: Option<&'a AuthExtension>,
    repos: HashMap<Uuid, GateRepo>,
    decided: HashMap<(Uuid, String, String), bool>,
    /// Per repository, the `(name, version)`s the listing decision serves.
    listed: HashMap<Uuid, std::collections::HashSet<(String, String)>>,
}

/// How many server versions of one repository a generic listing evaluates
/// with the listing decision in one request (in chunks of
/// [`LISTING_GATE_CHUNK`]). Versions past it are hidden from readers (fail
/// closed); the generic routes say so where they report a total.
pub(crate) const GENERIC_LISTING_VERSION_CAP: i64 = 10_000;
const LISTING_GATE_CHUNK: usize = 1_000;

/// What [`GenericArtifactGate`] knows of one repository.
#[derive(Clone)]
enum GateRepo {
    /// Not an MCP registry: this gate does not apply.
    NotMcp,
    /// An MCP registry, and whether the caller holds it.
    Mcp(Box<RepoInfo>, bool),
    /// An MCP registry that could not be resolved: hidden (fail closed).
    Unavailable,
}

impl<'a> GenericArtifactGate<'a> {
    pub(crate) fn new(state: &'a SharedState, auth: Option<&'a AuthExtension>) -> Self {
        Self {
            state,
            auth,
            repos: HashMap::new(),
            decided: HashMap::new(),
            listed: HashMap::new(),
        }
    }

    /// Whether the caller sees every stored version of each of `repo_ids`
    /// (none is an MCP registry, or the caller holds each one that is).
    pub(crate) async fn holds_all(&mut self, repo_ids: &[Uuid]) -> bool {
        for id in repo_ids {
            match self.repo(*id).await {
                GateRepo::NotMcp | GateRepo::Mcp(_, true) => {}
                _ => return false,
            }
        }
        true
    }

    /// [`Self::visible`] for a listing row: the listing decision of the
    /// registry surface ([`servable`], uncached `listing_refusals_fresh`),
    /// evaluated once per repository for all its versions, soft-deleted ones
    /// excluded. A holder sees every row.
    pub(crate) async fn visible_listed(&mut self, repo_id: Uuid, path: &str) -> bool {
        let repo = match self.repo(repo_id).await {
            GateRepo::NotMcp => return true,
            GateRepo::Unavailable => return false,
            GateRepo::Mcp(_, true) => return true,
            GateRepo::Mcp(repo, false) => repo,
        };
        let Some((name, version)) = owning_version(path) else {
            return false;
        };
        if !self.listed.contains_key(&repo_id) {
            let set = self.listed_versions(&repo).await;
            self.listed.insert(repo_id, set);
        }
        self.listed[&repo_id].contains(&(name.to_string(), version.to_string()))
    }

    /// The `(name, version)`s of MCP registry `repo_id` that the listing
    /// decision serves to readers, whether or not this caller holds it;
    /// empty when it is not an MCP registry or cannot be resolved (fail
    /// closed). Search (#5397) builds a set shared across callers from it.
    pub(crate) async fn reader_listed_versions(
        &mut self,
        repo_id: Uuid,
    ) -> std::collections::HashSet<(String, String)> {
        match self.repo(repo_id).await {
            GateRepo::Mcp(repo, _) => self.listed_versions(&repo).await,
            GateRepo::NotMcp | GateRepo::Unavailable => Default::default(),
        }
    }

    async fn listed_versions(
        &self,
        repo: &RepoInfo,
    ) -> std::collections::HashSet<(String, String)> {
        let sql = format!(
            "SELECT {ROW_COLUMNS} FROM artifacts a \
             JOIN artifact_metadata m ON m.artifact_id = a.id \
             WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcp' \
             ORDER BY a.name, a.version LIMIT $2"
        );
        let raw: Vec<RawRow> = match sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(repo.id)
            .bind(GENERIC_LISTING_VERSION_CAP)
            .fetch_all(&self.state.db)
            .await
        {
            Ok(raw) => raw,
            Err(_) => return Default::default(),
        };
        let rows = rows_from_raw(raw);
        let ctx = GateCtx::of(self.state, false);
        let mut out = std::collections::HashSet::new();
        for chunk in rows.chunks(LISTING_GATE_CHUNK) {
            for r in reader_listed(ctx, repo.id, chunk.to_vec()).await {
                out.insert((r.name, r.version));
            }
        }
        out
    }

    async fn repo(&mut self, repo_id: Uuid) -> GateRepo {
        if let Some(r) = self.repos.get(&repo_id) {
            return r.clone();
        }
        let key: Result<Option<String>, sqlx::Error> =
            sqlx::query_scalar("SELECT key FROM repositories WHERE id = $1 AND format = 'mcp'")
                .bind(repo_id)
                .fetch_optional(&self.state.db)
                .await;
        let found = match key {
            Ok(None) => GateRepo::NotMcp,
            Ok(Some(key)) => match resolve_mcp_repo(&self.state.db, &key).await {
                Ok(info) => {
                    let holder = audience(&self.state.db, self.auth, repo_id).await
                        == GateAudience::ReasonGated;
                    GateRepo::Mcp(Box::new(info), holder)
                }
                Err(_) => GateRepo::Unavailable,
            },
            Err(_) => GateRepo::Unavailable,
        };
        self.repos.insert(repo_id, found.clone());
        found
    }

    /// Whether the caller may see the artifact at `path` of `repo_id`.
    /// Always `true` for a repository that is not an MCP registry.
    pub(crate) async fn visible(&mut self, repo_id: Uuid, path: &str) -> bool {
        let repo = match self.repo(repo_id).await {
            GateRepo::NotMcp => return true,
            GateRepo::Unavailable => return false,
            GateRepo::Mcp(_, true) => return true,
            GateRepo::Mcp(repo, false) => repo,
        };
        let Some((name, version)) = owning_version(path) else {
            return false;
        };
        let key = (repo_id, name.to_string(), version.to_string());
        if let Some(v) = self.decided.get(&key) {
            return *v;
        }
        let row = match versions_of(&self.state.db, repo_id, name).await {
            Ok(rows) => rows.into_iter().find(|r| r.version == version),
            Err(_) => None,
        };
        let ok = match row {
            Some(row) => servable_row(self.state, repo.as_ref(), &row, "").await,
            None => false,
        };
        self.decided.insert(key, ok);
        ok
    }
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
    /// Where the listing resumes ([`fmt::ListingResume::default`]: the start).
    pub cursor: fmt::ListingResume,
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
/// `cursor` is opened with `open_cursor` (a sealed position, see
/// [`fmt::CursorSeal`]).
pub fn parse_list_query(
    q: &HashMap<String, String>,
    open_cursor: impl FnOnce(&str) -> Result<fmt::ListingResume, McpError>,
) -> Result<ListQuery, McpError> {
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
        Some(c) => open_cursor(c)?,
        None => fmt::ListingResume::default(),
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
/// on `raw_len`, resumes after `last` and feeds `read` (every row read, in
/// order, by id and key) to a [`fmt::ListingResume`] ([`advance_resume`]).
pub(crate) struct ListingBatch {
    pub(crate) rows: Vec<VersionRow>,
    pub(crate) raw_len: usize,
    pub(crate) last: Option<(String, String)>,
    pub(crate) read: Vec<(Uuid, (String, String))>,
}

/// Account in `at` for the rows a batch read, of which `served` were
/// served.
pub(crate) fn advance_resume(
    at: &mut fmt::ListingResume,
    read: &[(Uuid, (String, String))],
    served: &[VersionRow],
) {
    let served: std::collections::HashSet<Uuid> = served.iter().map(|r| r.artifact_id).collect();
    for (id, key) in read {
        at.advance_one(*id, key.clone(), served.contains(id));
    }
}

/// The keyset position a listing resumed at `at` continues strictly after
/// (#5453): the row `at.read` names (looked up in `repo_id`, deleted rows
/// included, so a version deleted between pages moves nothing), or the last
/// served row when there is none or it was purged. For a `version=latest`
/// listing only the name counts.
pub(crate) async fn resume_after(
    db: &PgPool,
    repo_id: Uuid,
    at: &fmt::ListingResume,
) -> Result<Option<(String, String)>, Response> {
    if let Some(id) = at.read {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT name, version FROM artifacts WHERE id = $1 AND repository_id = $2",
        )
        .bind(id)
        .bind(repo_id)
        .fetch_optional(db)
        .await
        .map_err(internal)?;
        if let Some((name, version)) = row {
            return Ok(Some((name, version.unwrap_or_default())));
        }
    }
    Ok(at.after.clone())
}

/// The rows after `after`.
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
    let read: Vec<(Uuid, (String, String))> = raw
        .iter()
        .map(|r| (r.0, (r.2.clone(), r.3.clone())))
        .collect();
    Ok(ListingBatch {
        rows: rows_from_raw(raw),
        raw_len,
        last: read.last().map(|(_, k)| k.clone()),
        read,
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
) -> Vec<VersionRow> {
    servable_checked(ctx, repo_id, rows)
        .await
        .unwrap_or_default()
}

/// [`servable`], telling an unevaluable gate (already logged and audited)
/// apart from "nothing servable", for a caller that must not fall through
/// to another candidate (an older version, a lower-priority member) when a
/// gate is down.
pub(crate) async fn servable_checked(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: Vec<VersionRow>,
) -> Result<Vec<VersionRow>, mcp_packages::GateUnavailable> {
    if rows.is_empty() {
        return Ok(rows);
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
    let refused = match mcp_packages::listing_refusals(ctx, repo_id, &listing).await {
        Ok(refused) => refused,
        Err(mcp_packages::GateUnavailable) => {
            listing_gate_unavailable(ctx.db, repo_id);
            return Err(mcp_packages::GateUnavailable);
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
        Ok(held) => Ok(rows
            .into_iter()
            .filter(|r| !held.contains_key(&r.artifact_id))
            .collect()),
        Err(()) => {
            listing_gate_unavailable(ctx.db, repo_id);
            Err(mcp_packages::GateUnavailable)
        }
    }
}

/// How many of a server's newest candidates `latest` evaluates before it
/// gives up on the server (a server whose newest versions are all held).
/// The one bound of every `latest` decision: the detail walk
/// ([`walk_candidates`]) and the listings' `isLatest` and `version=latest`
/// ([`newest_servable`]) read the same window, so they always agree.
pub(crate) const MAX_LATEST_WALK: usize = 100;
const LATEST_WALK_CHUNK: usize = 10;

/// The candidates `latest` may answer, newest first: the newest
/// [`MAX_LATEST_WALK`] of [`latest_candidates`].
pub(crate) fn latest_window(rows: Vec<VersionRow>) -> Vec<VersionRow> {
    let mut candidates = latest_candidates(rows);
    candidates.truncate(MAX_LATEST_WALK);
    candidates
}

/// A server's newest servable version (by [`fmt::latest_order`], `deleted`
/// excluded, within [`latest_window`]) among `rows` (all of its versions),
/// and how many rows the reader-only gate evaluated to find it. Rows in
/// `known` are already known servable (they passed the gate in this
/// request) and are not re-evaluated. A gate that cannot be evaluated stops
/// the walk (`Err`): an older version is never presented as latest because
/// a newer one could not be decided.
pub(crate) async fn newest_servable(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: Vec<VersionRow>,
    known: &std::collections::HashSet<Uuid>,
) -> (
    Result<Option<VersionRow>, mcp_packages::GateUnavailable>,
    usize,
) {
    let candidates = latest_window(rows);
    let mut evaluated = 0;
    for chunk in candidates.chunks(LATEST_WALK_CHUNK) {
        let unknown: Vec<VersionRow> = chunk
            .iter()
            .filter(|r| !known.contains(&r.artifact_id))
            .cloned()
            .collect();
        evaluated += unknown.len();
        let ok: std::collections::HashSet<Uuid> =
            match servable_checked(ctx, repo_id, unknown).await {
                Ok(rows) => rows.into_iter().map(|r| r.artifact_id).collect(),
                Err(e) => return (Err(e), evaluated),
            };
        if let Some(row) = chunk
            .iter()
            .find(|r| known.contains(&r.artifact_id) || ok.contains(&r.artifact_id))
        {
            return (Ok(Some(row.clone())), evaluated);
        }
    }
    (Ok(None), evaluated)
}

/// The artifact ids among `rows` (servable rows of one response) that are
/// their server's newest servable version.
async fn latest_ids(
    ctx: GateCtx<'_>,
    repo_id: Uuid,
    rows: &[VersionRow],
) -> Result<std::collections::HashSet<Uuid>, Response> {
    let known: std::collections::HashSet<Uuid> = rows.iter().map(|r| r.artifact_id).collect();
    let names: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    let mut out = std::collections::HashSet::new();
    for name in names {
        let all = versions_of(ctx.db, repo_id, name).await?;
        if let (Ok(Some(row)), _) = newest_servable(ctx, repo_id, all, &known).await {
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
) -> Result<Vec<serde_json::Value>, Response> {
    let latest = latest_ids(ctx, repo.id, rows).await?;
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
    let seal = cursor_seal(&state);
    let q = parse_list_query(&query, |c| {
        seal.decode_resume(repo.id, fmt::cursor_kind::SERVERS, c)
    })
    .map_err(mcp_error)?;
    let ctx = GateCtx::of(&state, false);
    let (entries, next) = if q.version.as_deref() == Some("latest") {
        list_latest(ctx, &repo, &q, base.as_str()).await?
    } else {
        list_versions_page(ctx, &repo, &q, base.as_str()).await?
    };
    let next = next.map(|at| seal.encode_resume(repo.id, fmt::cursor_kind::SERVERS, &at));
    Ok(json_listing(&fmt::list_envelope(entries, next)))
}

/// Upper bound on the rows one listing request reads and gates, so a
/// repository whose rows are almost all held cannot turn one request into a
/// full scan. A scan the bound stops still answers a resume cursor.
pub(crate) const MAX_LISTING_ROWS: usize = 1000;

/// The seal of this instance's listing cursors (see [`fmt::CursorSeal`]),
/// keyed from the `jwt_secret` every replica shares.
pub(crate) fn cursor_seal(state: &crate::api::AppState) -> fmt::CursorSeal {
    fmt::CursorSeal::from_secret(&state.config.jwt_secret)
}

/// A listing page and where the next page resumes (sealed by the caller).
type PageOut = (Vec<serde_json::Value>, Option<fmt::ListingResume>);

async fn list_versions_page(
    ctx: GateCtx<'_>,
    repo: &RepoInfo,
    q: &ListQuery,
    base: &str,
) -> Result<PageOut, Response> {
    let want = q.limit as usize;
    let mut out: Vec<VersionRow> = Vec::new();
    // The scan's own position (internal, may be a held row), and the resume
    // point a cursor may carry (the last served row, and the id of the last
    // row read past it).
    let mut after = resume_after(ctx.db, repo.id, &q.cursor).await?;
    let mut resume = q.cursor.clone();
    let mut read = 0usize;
    let exhausted = loop {
        let batch = fetch_listing_batch(ctx.db, repo.id, q, after.as_ref(), q.limit + 1).await?;
        read += batch.raw_len;
        let exhausted = (batch.raw_len as i64) <= q.limit;
        if let Some(last) = batch.last.clone() {
            after = Some(last);
        }
        let served = servable(ctx, repo.id, batch.rows).await;
        advance_resume(&mut resume, &batch.read, &served);
        out.extend(served);
        if out.len() > want || exhausted || read >= MAX_LISTING_ROWS {
            break exhausted;
        }
    };
    let next = if out.len() > want {
        let last = &out[want - 1];
        Some(fmt::ListingResume::after(&last.name, &last.version))
    } else if !exhausted {
        // The row bound stopped the scan (almost every row held): resume
        // past the rows read instead of presenting a short last page, naming
        // the last one by its id only (#5453).
        Some(resume)
    } else {
        None
    };
    out.truncate(want);
    Ok((served_entries(ctx, repo, base, &out).await?, next))
}

/// Server names of a listing, in order, after `name_after`, each with the
/// id of one of its rows (what a [`fmt::ListingResume`] names it by).
pub(crate) async fn fetch_server_names(
    db: &PgPool,
    repo_id: Uuid,
    search: Option<&str>,
    name_after: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, Uuid)>, Response> {
    let pattern = search.map(|s| format!("%{}%", super::escape_like_literal(s)));
    sqlx::query_as(
        "SELECT a.name, (array_agg(a.id))[1] FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
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

/// The version half of a `version=latest` listing's position (it pages by
/// server name).
pub(crate) const LATEST_POSITION: &str = "-";

/// Gate evaluations one `version=latest` listing spends before it answers
/// with a resume cursor (each server costs at least one).
pub(crate) const MAX_LATEST_BUDGET: usize = 1000;

/// `version=latest`: one entry per server, its newest servable version.
/// The newest is picked from all of a server's versions first; only then do
/// `updated_since` (on the picked version) apply, so an older version is
/// never presented as latest because the newest was not updated recently.
/// The cursor names the last server served and, by row id only, the last
/// server decided past it (#5453); work is bounded by [`MAX_LATEST_BUDGET`]
/// and a stopped scan answers a resume cursor.
async fn list_latest(
    ctx: GateCtx<'_>,
    repo: &RepoInfo,
    q: &ListQuery,
    base: &str,
) -> Result<PageOut, Response> {
    let want = q.limit as usize;
    let mut out: Vec<VersionRow> = Vec::new();
    let mut name_after = resume_after(ctx.db, repo.id, &q.cursor)
        .await?
        .map(|(name, _)| name);
    let mut resume = q.cursor.clone();
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
        for (name, id) in names {
            if out.len() == want || budget == 0 {
                more = true;
                break 'scan;
            }
            let all = versions_of(ctx.db, repo.id, &name).await?;
            let (picked, evaluated) = newest_servable(ctx, repo.id, all, &none).await;
            budget = budget.saturating_sub(evaluated.max(1));
            // An unevaluable gate omits the server (never an older version).
            let picked = picked.ok().flatten().filter(|r| {
                q.updated_since
                    .is_none_or(|since| r.stored.registry.updated_at >= since)
            });
            resume.advance_one(id, (name.clone(), LATEST_POSITION.into()), picked.is_some());
            out.extend(picked);
            name_after = Some(name);
        }
        if names_exhausted {
            break;
        }
    }
    let next = more.then_some(resume);
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
    // An unevaluable gate omits every version (the listing contract).
    let served = servable_versions(state, &repo, name, include_deleted)
        .await?
        .unwrap_or_default();
    if served.is_empty() {
        return Err(not_found());
    }
    // `isLatest` is what `latest` answers: the newest servable version
    // within the `latest` window (rows already gated here are not gated
    // again).
    let latest = {
        let known = served.iter().map(|r| r.artifact_id).collect();
        let all = versions_of(&state.db, repo.id, name).await?;
        newest_servable(GateCtx::of(state, false), repo.id, all, &known)
            .await
            .0
            .ok()
            .flatten()
            .map(|r| r.artifact_id)
    };
    let entries = served
        .iter()
        .map(|r| served_entry(r, &repo, base, Some(r.artifact_id) == latest))
        .collect();
    Ok(json_listing(&fmt::list_envelope(entries, None)))
}

/// Every servable version of `name` in `repo` (the reader-only listing
/// gate), in version-text order: the per-repository core of
/// `GET /servers/{name}/versions`, shared with the Virtual read path.
/// `Ok(Err(_))`: a gate could not be evaluated.
pub(crate) async fn servable_versions(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    include_deleted: bool,
) -> Result<Result<Vec<VersionRow>, mcp_packages::GateUnavailable>, Response> {
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
    Ok(servable_checked(ctx, repo.id, rows).await)
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
/// `name`@`version` (`latest`: the [`latest_window`], newest first) in
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
        latest_window(rows.clone())
    } else {
        rows.iter()
            .filter(|r| r.version == version)
            .cloned()
            .collect()
    };
    if candidates.is_empty() {
        miss_shaped_work(state, repo, name, version).await;
        return Ok(CandidateWalk::NotFound);
    }
    let ctx = GateCtx::of(state, true);
    let mut first_refusal: Option<(Response, &VersionRow, &'static str)> = None;
    for row in &candidates {
        let instance = instance_url(base, &repo.key, &row.name, &row.version);
        match decide_row(ctx, row, include_deleted, audience, instance).await {
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

/// The gate-shaped reads a miss runs before it answers (#5396), so a name or
/// version that does not exist costs about what a held one does: the
/// package policy, the server.json's own download gate (for an artifact that
/// does not exist), the repository's serve policy and its repository-level
/// holds (deny list, Remote curation, server age gate) for the requested
/// `name@version`. Results are discarded, nothing is recorded (no age-gate
/// review, no audit). What a held version still does on top (one lookup per
/// pinned backing package) is the residual documented in
/// docs/mcp-registry.md.
async fn miss_shaped_work(state: &SharedState, repo: &RepoInfo, name: &str, version: &str) {
    #[cfg(test)]
    MISS_SHAPED_WORK.with(|n| n.set(n.get() + 1));
    let ctx = GateCtx::of(state, false);
    let _ = own_hold(ctx.db, Uuid::nil()).await;
    if let Ok(policy) = mcp_curation::load_serve_policy(ctx.db, repo.id).await {
        let _ =
            mcp_curation::repo_holds(ctx, &policy, repo.id, &[(Uuid::nil(), name, version)]).await;
    }
}

#[cfg(test)]
thread_local! {
    /// How many misses ran [`miss_shaped_work`] on this thread.
    static MISS_SHAPED_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether `row` is the newest servable version among `all` (every version
/// of its server in `repo`), by the reader-only listing gate.
pub(crate) async fn is_newest_servable(
    state: &SharedState,
    repo: &RepoInfo,
    row: &VersionRow,
    all: Vec<VersionRow>,
) -> bool {
    let known = std::iter::once(row.artifact_id).collect();
    let listing = GateCtx::of(state, false);
    newest_servable(listing, repo.id, all, &known)
        .await
        .0
        .ok()
        .flatten()
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
    // The installation check runs once the staged bundles are added
    // (`fmt::check_installable`): a bundle-only document gets its `mcpb`
    // entry from the upload.
    fmt::validate_server_json_before_bundles(&server)?;
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

/// The stored server name a publish of `name` into the hosted repository
/// `repo_id` would be a case-only twin of (#5434): a recorded name equal to
/// `name` ignoring letter case but not equal exactly, when `name` itself was
/// never recorded there. `None` when the publish may proceed.
///
/// Names are read from the version ledger `mcp_version_tombstones`, which
/// records every server name the repository ever stored (live, soft-deleted,
/// trashed or purged; only a never-served failed version is released), so a
/// deleted name still blocks its look-alikes. A name already recorded is
/// never refused, even when a twin of it was stored before this rule.
///
/// Case folding is [`OwnedNames::key`](super::mcp_virtual::OwnedNames::key)
/// in Rust and `lower()` in SQL, as the Virtual's hosted-shadows-remote rule
/// (#5394) compares names; server names are ASCII (`NAME_RE`), where this
/// agrees with the deny lists' ASCII-insensitive globs. Indexed by
/// `idx_mcp_version_tombstones_name_ci` (migration 336).
pub(super) async fn case_twin_of<'e>(
    db: impl sqlx::PgExecutor<'e>,
    repo_id: Uuid,
    name: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT t.name FROM mcp_version_tombstones t \
         WHERE t.repository_id = $1 AND lower(t.name) = $2 AND t.name <> $3 \
           AND NOT EXISTS (SELECT 1 FROM mcp_version_tombstones e \
                           WHERE e.repository_id = $1 AND e.name = $3) \
         ORDER BY t.created_at, t.name LIMIT 1",
    )
    .bind(repo_id)
    .bind(super::mcp_virtual::OwnedNames::key(name))
    .bind(name)
    .fetch_optional(db)
    .await
}

fn name_case_conflict(name: &str, existing: String) -> Response {
    mcp_error(McpError::NameCaseConflict {
        name: name.to_string(),
        existing,
    })
}

/// The early, unlocked [`case_twin_of`] refusal (`409
/// mcp_name_case_conflict`), before a publish does any resolution or
/// storage work. [`refuse_case_only_twin_in`] is the authoritative check.
pub(super) async fn refuse_case_only_twin(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
) -> Result<(), Response> {
    match case_twin_of(db, repo_id, name).await.map_err(internal)? {
        Some(existing) => Err(name_case_conflict(name, existing)),
        None => Ok(()),
    }
}

/// The authoritative case-only-twin refusal, inside the publish
/// transaction: take the case-insensitive name lock, then look. Two
/// concurrent publishes of `io.acme/tool` and `io.Acme/tool` take the same
/// lock, so the second sees the first's committed ledger row and is refused.
///
/// Lock order: the caller holds the quota admission and nothing MCP-specific
/// yet; this lock is taken before the per-server [`lock_server`] (taken by
/// [`recompute_latest_in`] later in the same transaction) and only on the
/// hosted publish path. It lives in the two-key advisory space, so it can
/// never collide with a single-key `lock_server` hash.
pub(super) async fn refuse_case_only_twin_in(
    tx: &mut sqlx::PgConnection,
    repo_id: Uuid,
    name: &str,
) -> Result<(), Response> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('mcp-name-ci'), hashtext($1))")
        .bind(format!(
            "mcp-name-ci/{repo_id}/{}",
            super::mcp_virtual::OwnedNames::key(name)
        ))
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    match case_twin_of(&mut *tx, repo_id, name)
        .await
        .map_err(internal)?
    {
        Some(existing) => Err(name_case_conflict(name, existing)),
        None => Ok(()),
    }
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
    // A hosted publish never adds a case-only twin of a recorded name
    // (#5434); `insert_server_rows` is the hosted publish's insert only.
    refuse_case_only_twin_in(&mut tx, repository_id, &name).await?;
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
    refuse_case_only_twin(&state.db, repo.id, &server.name).await?;
    super::mcp_write::add_staged_bundles(&state.db, &repo, &mut server, base.as_str()).await?;
    fmt::check_installable(&server).map_err(mcp_error)?;
    mcp_packages::refuse_unreadable_backing(&state.db, &ext, &settings, &server)
        .await
        .map_err(mcp_error)?;
    super::mcp_write::refuse_tombstoned(&state.db, repo.id, &server.name, &server.version).await?;
    // A version whose async resolution failed is replaced by this publish.
    crate::services::mcp_write::release_failed_version(
        &state.db,
        repo.id,
        &server.name,
        &server.version,
    )
    .await
    .map_err(internal)?;
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
    let key = fmt::storage_key(
        fmt::KeyScope::of(&repo.storage_backend, repo.id),
        &server.name,
        &server.version,
        &sha256,
    );
    let size_bytes = bytes.len() as i64;
    proxy_helpers::put_artifact_bytes(&state, &repo, &key, Bytes::from(bytes))
        .await
        .map_err(reproblem)?;

    let registry = RegistryState::new_active(Utc::now());
    let metadata = crate::services::mcp_resolver::metadata_with_resolution(
        &state.db,
        fmt::metadata_doc(&server, &registry, settings.policy, &pins),
        &resolution,
        &ext,
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
    let latest = row_is_latest(&state, &repo, &row).await;
    let entry = served_entry(&row, &repo, base.as_str(), latest);
    Ok(super::mcp_write::publish_answer(entry, &resolution))
}

/// Whether `row` is its server's newest servable version (the reader-only
/// gate), for a write's response. A read failure answers `false`.
pub(super) async fn row_is_latest(state: &SharedState, repo: &RepoInfo, row: &VersionRow) -> bool {
    let Ok(all) = versions_of(&state.db, repo.id, &row.name).await else {
        return false;
    };
    let ctx = GateCtx::of(state, false);
    newest_servable(ctx, repo.id, all, &Default::default())
        .await
        .0
        .ok()
        .flatten()
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
    let all = versions_of(&state.db, repo.id, name).await?;
    let latest = newest_servable(GateCtx::of(state, false), repo.id, all, &Default::default())
        .await
        .0
        .ok()
        .flatten()
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
    reader_decision(state, repo, row, base).await == Servability::Servable
}

async fn reader_decision(
    state: &SharedState,
    repo: &RepoInfo,
    row: &VersionRow,
    base: &str,
) -> Servability {
    let instance = instance_url(base, &repo.key, &row.name, &row.version);
    Servability::of(
        &decide_row(
            GateCtx::of(state, false),
            row,
            false,
            GateAudience::ReaderOnly,
            instance,
        )
        .await,
    )
}

/// A reader serve decision, three-way: an introspection claim or completion
/// cancels its job only on a definite hold, never because a gate could not
/// be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Servability {
    Servable,
    /// Refused: the version (or a backing package) is held.
    Held,
    /// A gate could not be evaluated (`503 mcp_gate_unavailable`): retry
    /// later.
    Unavailable,
}

impl Servability {
    pub(crate) fn of(decision: &ServeDecision) -> Self {
        match decision {
            ServeDecision::Serve => Self::Servable,
            ServeDecision::Refuse { status: 503, .. } => Self::Unavailable,
            ServeDecision::Refuse { .. } => Self::Held,
        }
    }
}

/// Whether the stored version `artifact_id` of `repo` is servable to readers
/// now (the sandbox only ever runs a version whose gates pass). A version
/// whose row cannot be read is [`Servability::Unavailable`]: the caller has
/// already found it (a deleted version is the caller's definite refusal).
pub(crate) async fn artifact_servability(
    state: &SharedState,
    repo: &RepoInfo,
    artifact_id: Uuid,
    base: &str,
) -> Servability {
    match stored_row(&state.db, artifact_id).await {
        Ok(row) => reader_decision(state, repo, &row, base).await,
        Err(_) => Servability::Unavailable,
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

    fn test_seal() -> fmt::CursorSeal {
        fmt::CursorSeal::from_secret("mcp-handler-tests-secret-0123456789abcdef")
    }

    fn parse(q: &HashMap<String, String>) -> Result<ListQuery, McpError> {
        parse_list_query(q, |c| {
            test_seal().decode_resume(Uuid::nil(), fmt::cursor_kind::SERVERS, c)
        })
    }

    #[test]
    fn servability_is_three_way() {
        let refuse = |status| ServeDecision::Refuse {
            status,
            body: serde_json::json!({}),
            hold_class: "x",
        };
        assert_eq!(
            Servability::of(&ServeDecision::Serve),
            Servability::Servable
        );
        assert_eq!(Servability::of(&refuse(503)), Servability::Unavailable);
        assert_eq!(Servability::of(&refuse(404)), Servability::Held);
    }

    #[test]
    fn list_query_rules() {
        assert_eq!(parse(&q(&[])).unwrap().limit, fmt::DEFAULT_LIMIT);
        assert_eq!(
            parse(&q(&[("limit", "500")])).unwrap().limit,
            fmt::MAX_LIMIT
        );
        assert_eq!(parse(&q(&[("limit", "7")])).unwrap().limit, 7);
        for bad in ["0", "-1", "x", "1.5"] {
            assert_eq!(
                parse(&q(&[("limit", bad)])).unwrap_err().status(),
                400,
                "{bad}"
            );
        }
        assert_eq!(parse(&q(&[("cursor", "!!")])).unwrap_err().status(), 400);
        let c = test_seal().encode_position(
            Uuid::nil(),
            fmt::cursor_kind::SERVERS,
            "com.acme/a",
            "1.0.0",
        );
        assert_eq!(
            parse(&q(&[("cursor", &c)])).unwrap().cursor,
            fmt::ListingResume::after("com.acme/a", "1.0.0")
        );
        let past = fmt::ListingResume {
            after: None,
            read: Some(Uuid::new_v4()),
        };
        let c = test_seal().encode_resume(Uuid::nil(), fmt::cursor_kind::SERVERS, &past);
        assert_eq!(parse(&q(&[("cursor", &c)])).unwrap().cursor, past);
        assert_eq!(
            parse(&q(&[("search", "ab")])).unwrap_err(),
            McpError::SearchTooShort
        );
        assert_eq!(
            parse(&q(&[("search", "abc")])).unwrap().search.as_deref(),
            Some("abc")
        );
        let since = parse(&q(&[("updated_since", "2026-01-01T00:00:00Z")])).unwrap();
        assert!(since.include_deleted && since.updated_since.is_some());
        assert_eq!(
            parse(&q(&[
                ("updated_since", "2026-01-01T00:00:00Z"),
                ("include_deleted", "false")
            ]))
            .unwrap_err()
            .status(),
            400
        );
        assert_eq!(
            parse(&q(&[("updated_since", "yesterday")]))
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
                parse(&q(bad)).unwrap_err().code(),
                "mcp_invalid_query",
                "{bad:?}"
            );
        }
        assert_eq!(
            parse(&q(&[("include_deleted", "maybe")]))
                .unwrap_err()
                .status(),
            400
        );
        assert!(
            parse(&q(&[("include_deleted", "true")]))
                .unwrap()
                .include_deleted
        );
        assert_eq!(
            parse(&q(&[("version", "latest")]))
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
        fn member_router(&self, router: Router<SharedState>) -> Router {
            self.fx.router_with_auth(router)
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
            // A publisher must be able to read a backing repository it pins
            // from (`refuse_unreadable_backing`).
            tdh::grant_repo_role(&self.fx.pool, id, self.fx.user_id, "reader").await;
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

    /// The stored pins of `name@version` (`metadata.packages`).
    async fn stored_pins(env: &Env, name: &str, version: &str) -> serde_json::Value {
        sqlx::query_scalar(
            "SELECT metadata->'packages' FROM artifact_metadata WHERE artifact_id = $1",
        )
        .bind(env.server_artifact(name, version).await)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap()
    }

    /// #5452: under `open` a package must still resolve through the mapped
    /// backing repository. `registryBaseUrl` may name another registry, but
    /// the served document carries the AK coordinates, the stored pin agrees
    /// with them and records that the submitted coordinates were replaced,
    /// and the backing artifact's gates apply. A package the backing
    /// repository does not hold, or whose `registryType` has no backing
    /// repository, is refused and stores nothing. A version stored unpinned
    /// under `open` before the fix is `unresolvable`, under either policy.
    #[tokio::test]
    async fn open_policy_pins_and_gates_npm_and_pypi_packages() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let (npm, ids) = env.npm_backing(&["1.0.0"]).await;
        let pypi = env.repo("local", "pypi").await;
        tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &pypi,
            "pypi/acme-tool-2.0.0.whl",
            "acme-tool/2.0.0/acme_tool-2.0.0-py3-none-any.whl",
            "acme-tool",
            "2.0.0",
            "application/octet-stream",
            Bytes::from_static(b"whl"),
            env.fx.user_id,
            &"f".repeat(64),
        )
        .await;
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"npm": npm.key, "pypi": pypi.key}).to_string(),
        )
        .await;
        let foreign = |ty: &str, id: &str, v: &str, url: &str| {
            serde_json::json!({"registryType": ty, "identifier": id, "version": v,
                "registryBaseUrl": url, "transport": {"type": "stdio"}})
        };
        let one = |name: &str, p: serde_json::Value| {
            doc(name, "1.0.0", serde_json::json!({"packages": [p]}))
        };

        // Not in the backing repository, or no backing repository at all:
        // refused, nothing stored.
        let npm_evil = foreign("npm", "@evil/pkg", "3.0.0", "https://npm.evil.test");
        let pypi_evil = foreign("pypi", "evil-tool", "1.0", "https://pypi.evil.test/simple");
        let cargo_evil = foreign("cargo", "evil", "1.0.0", "https://crates.evil.test");
        for (name, p, code) in [
            ("com.acme/npm-evil", npm_evil, "mcp_package_not_found"),
            ("com.acme/pypi-evil", pypi_evil, "mcp_package_not_found"),
            ("com.acme/cargo-evil", cargo_evil, "mcp_external_registry"),
        ] {
            let (s, b) = env.publish(&one(name, p)).await;
            assert_eq!(
                (s, b["error"].as_str()),
                (StatusCode::UNPROCESSABLE_ENTITY, Some(code)),
                "{name}: {b}"
            );
            let stored: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2",
            )
            .bind(env.fx.repo_id)
            .bind(fmt::storage_path(name, "1.0.0"))
            .fetch_optional(&env.fx.pool)
            .await
            .unwrap();
            assert_eq!(stored, None, "{name}");
        }

        // In the backing repository: pinned and served from it.
        for (name, p, repo_key, sha) in [
            (
                "com.acme/npm-ok",
                foreign("npm", "@acme/echo", "1.0.0", "https://npm.evil.test"),
                &npm.key,
                "e",
            ),
            (
                "com.acme/pypi-ok",
                foreign(
                    "pypi",
                    "Acme_Tool",
                    "2.0.0",
                    "https://pypi.evil.test/simple",
                ),
                &pypi.key,
                "f",
            ),
        ] {
            let ty = p["registryType"].as_str().unwrap().to_string();
            let (s, b) = env.publish(&one(name, p)).await;
            assert_eq!(s, StatusCode::OK, "{name}: {b}");
            let own = format!("http://localhost/{ty}/{repo_key}");
            assert_eq!(b["server"]["packages"][0]["registryBaseUrl"], own, "{name}");
            let tail = format!("/servers/{}/versions/latest", urlencoding::encode(name));
            let (s, read, _) = env.get(env.anon(), &tail).await;
            let read = json(&read);
            assert_eq!(s, StatusCode::OK, "{name}: {read}");
            assert_eq!(read["server"]["packages"][0]["registryBaseUrl"], own);
            assert_eq!(
                read["_meta"][fmt::AK_SOURCE_META_KEY]["packagePolicy"],
                "open"
            );
            let pins = stored_pins(&env, name, "1.0.0").await;
            assert_eq!(pins[0]["resolved"]["repository"], repo_key.as_str());
            assert_eq!(pins[0]["resolved"]["sha256"], sha.repeat(64));
            assert_eq!(
                pins[0]["resolved"]["warnings"],
                serde_json::json!([mcp_packages::FOREIGN_COORDINATES_WARNING])
            );
        }

        // The backing artifact's gates apply to an `open` version.
        env.hold(ids[0], Some("quarantined")).await;
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fnpm-ok/versions/1.0.0")
            .await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("mcp_backing_artifact_blocked"))
        );
        let (_, list, _) = env.get(env.anon(), "/servers").await;
        assert_eq!(
            listed_names(&json(&list)),
            ["com.acme/pypi-ok@1.0.0".to_string()]
        );

        // A version stored unpinned under `open` (as before #5452) is never
        // served: not under `open`, not under `own-repos`.
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{packages}', '[]') \
             WHERE artifact_id = $1",
        )
        .bind(env.server_artifact("com.acme/pypi-ok", "1.0.0").await)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        for policy in ["open", "own-repos"] {
            env.config(mcp_packages::POLICY_KEY, policy).await;
            let (s, b, _) = env
                .get(env.member(), "/servers/com.acme%2Fpypi-ok/versions/1.0.0")
                .await;
            assert_eq!(
                (s, json(&b)["error"].as_str()),
                (StatusCode::NOT_FOUND, Some("mcp_unresolvable")),
                "{policy}"
            );
            let (_, list, _) = env.get(env.anon(), "/servers").await;
            assert!(listed_names(&json(&list)).is_empty(), "{policy}");
        }
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

    /// #5452: under `open` an image named on another host is looked up by
    /// path in the backing repository and, when there, pinned to its digest
    /// and served at AK coordinates (the submitted identifier only in
    /// `_meta`); the backing manifest's gates apply. An image the backing
    /// repository does not hold is refused.
    #[tokio::test]
    async fn open_policy_pins_and_gates_oci_images() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (oci, digest) = seed_oci(&mut env).await;
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let mut evil = oci_doc("evil.example/acme/other:1.0");
        evil["name"] = "com.acme/evil-img".into();
        let (s, b) = env.publish(&evil).await;
        assert_eq!(
            (s, b["error"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("mcp_package_not_found")
            ),
            "{b}"
        );
        let (s, body) = env.publish(&oci_doc("ghcr.io/acme/mcp:1.2")).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let (s, read, _) = env
            .get(env.anon(), "/servers/com.acme%2Fimg/versions/1.0.0")
            .await;
        assert_eq!(s, StatusCode::OK);
        let pkg = &json(&read)["server"]["packages"][0];
        assert_eq!(
            pkg["identifier"],
            format!("localhost/{}/acme/mcp:1.2@{digest}", oci.key)
        );
        let resolved = &pkg["_meta"][fmt::AK_RESOLVED_META_KEY];
        assert_eq!(resolved["submittedIdentifier"], "ghcr.io/acme/mcp:1.2");
        assert_eq!(resolved["digest"], digest.as_str());
        let pins = stored_pins(&env, "com.acme/img", "1.0.0").await;
        assert_eq!(pins[0]["resolved"]["digest"], digest.as_str());
        assert_eq!(
            pins[0]["resolved"]["warnings"],
            serde_json::json!([mcp_packages::FOREIGN_COORDINATES_WARNING])
        );
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_source = 'admin' \
             WHERE repository_id = $1",
        )
        .bind(oci.id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fimg/versions/1.0.0")
            .await;
        assert_eq!(
            (s, json(&b)["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("mcp_backing_artifact_blocked"))
        );
        env.teardown().await;
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

    /// A public MCP registry with `com.acme/<name>-<random>` 1.0.0 and 2.0.0,
    /// 2.0.0 held through its backing npm package (the server.json row itself
    /// is not quarantined); returns the env, the server name and the held
    /// version's path. The name is unique per run: search spans every
    /// repository in the shared test database.
    async fn held_second_version(name: &str) -> Option<(Env, String, String)> {
        let mut env = Env::new().await?;
        let name = format!("{name}-{}", &Uuid::new_v4().simple().to_string()[..8]);
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (_npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                &format!("com.acme/{name}"),
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        Some((
            env,
            format!("com.acme/{name}"),
            format!("servers/com.acme/{name}/2.0.0/server.json"),
        ))
    }

    async fn get_json(app: Router, uri: String) -> serde_json::Value {
        let (s, b, _) = call(app, "GET", &uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {}", String::from_utf8_lossy(&b));
        json(&b)
    }

    /// #5253: `/api/v1/search/*` leaves out MCP versions a reader is not
    /// served. An anonymous reader finds only 1.0.0 in the advanced search
    /// (items and `total`, on every page), nothing for the held version's
    /// checksum, and no held path in the recent list; a holder finds both.
    #[tokio::test]
    async fn search_follows_the_serve_decision() {
        let Some((env, server, held)) = held_second_version("srch").await else {
            return;
        };
        let held_sha: String = sqlx::query_scalar(
            "SELECT checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(env.fx.repo_id)
        .bind(&held)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        let search = || crate::api::handlers::search::router();
        let anon = || env.fx.router_anon(search());
        let adv = get_json(anon(), format!("/advanced?name={server}&per_page=1")).await;
        assert_eq!(adv["pagination"]["total"], 1, "{adv}");
        assert!(!adv.to_string().contains("2.0.0"), "{adv}");
        let page2 = get_json(anon(), format!("/advanced?name={server}&per_page=1&page=2")).await;
        assert_eq!(page2["items"].as_array().unwrap().len(), 0, "{page2}");
        let by_sum = get_json(anon(), format!("/checksum?checksum={held_sha}")).await;
        assert_eq!(by_sum["artifacts"].as_array().unwrap().len(), 0, "{by_sum}");
        let recent = get_json(anon(), "/recent?limit=50".into()).await;
        assert!(!recent.to_string().contains(&held), "{recent}");
        let holder = get_json(
            env.fx.router_with_auth(search()),
            format!("/advanced?name={server}"),
        )
        .await;
        assert_eq!(holder["pagination"]["total"], 2, "{holder}");
        env.teardown().await;
    }

    /// #5454: one public registry with a visible server and three it does
    /// not serve: held (its server.json quarantined), soft-deleted (status
    /// `deleted`) and denied (`mcp_server_deny`). An anonymous caller and an
    /// authenticated caller with no grant see the visible server and nothing
    /// of the other three on every generic surface: search (quick, advanced
    /// with its total and facets, checksum, suggest, trending, recent), the
    /// artifact listing and its total, `/api/v1/packages` and a package's
    /// versions, the storage figures and storage tree, the tree browser and
    /// the tree content (the same `404` as a path that does not exist).
    #[tokio::test]
    async fn generic_surfaces_hide_every_unserved_version_from_readers() {
        let Some(env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let tag = Uuid::new_v4().simple().to_string()[..10].to_string();
        let name = |kind: &str| format!("com.acme/{kind}{tag}");
        for kind in ["vis", "held", "del", "deny"] {
            let d = doc(&name(kind), "1.0.0", serde_json::json!({}));
            assert_eq!(env.publish(&d).await.0, StatusCode::OK, "{kind}");
        }
        let mut ids = HashMap::new();
        for kind in ["held", "del", "deny"] {
            ids.insert(kind, env.server_artifact(&name(kind), "1.0.0").await);
        }
        env.hold(ids["held"], Some("quarantined")).await;
        let (s, b, _) = call(
            env.member(),
            "PATCH",
            &env.url(&format!(
                "/servers/{}/versions/1.0.0/status",
                name("del").replace('/', "%2F")
            )),
            Some(&serde_json::json!({"status": "deleted"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        env.config(
            crate::services::mcp_settings::SERVER_DENY_KEY,
            &serde_json::json!([name("deny")]).to_string(),
        )
        .await;
        tdh::recompute_storage_stats_with_retry(&env.fx.pool, false).await;
        let key = env.fx.repo_key.clone();
        let hidden: Vec<String> = ["held", "del", "deny"]
            .iter()
            .map(|k| format!("{k}{tag}"))
            .collect();
        let mut sums = Vec::new();
        for kind in ["held", "del", "deny"] {
            let sha: String =
                sqlx::query_scalar("SELECT checksum_sha256 FROM artifacts WHERE id = $1")
                    .bind(ids[kind])
                    .fetch_one(&env.fx.pool)
                    .await
                    .unwrap();
            sums.push(sha);
        }
        let pkg_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM packages WHERE repository_id = $1 AND name = ANY($2)",
        )
        .bind(env.fx.repo_id)
        .bind(
            ["held", "del", "deny"]
                .iter()
                .map(|k| name(k))
                .collect::<Vec<_>>(),
        )
        .fetch_all(&env.fx.pool)
        .await
        .unwrap();

        type Mk = fn() -> Router<SharedState>;
        let search: Mk = crate::api::handlers::search::router;
        let repos: Mk = crate::api::handlers::repositories::router;
        let packages: Mk = crate::api::handlers::packages::router;
        let tree: Mk = crate::api::handlers::tree::router;
        let mut cases: Vec<(Mk, String)> = vec![
            (search, format!("/quick?q={tag}&limit=50")),
            (search, "/quick?q=com.acme&limit=50".to_string()),
            (search, "/quick?q=server.json&limit=50".to_string()),
            (search, format!("/advanced?query={tag}&per_page=50")),
            (search, format!("/advanced?repository_key={key}&per_page=1")),
            (search, "/suggest?prefix=com.acme&limit=50".to_string()),
            (search, "/trending?limit=100".to_string()),
            (search, "/recent?limit=100".to_string()),
            (repos, format!("/{key}/artifacts?per_page=100&count=exact")),
            (
                repos,
                format!("/{key}/artifacts?per_page=1&page=2&count=exact"),
            ),
            (repos, format!("/{key}/artifacts?q={tag}")),
            (repos, format!("/{key}/storage/tree?depth=6")),
            (
                repos,
                format!("/{key}/storage/tree?depth=6&path=servers/com.acme"),
            ),
            (packages, format!("/?repository_key={key}&per_page=100")),
            (packages, format!("/?repository_key={key}&search={tag}")),
            (tree, format!("/?repository_key={key}")),
            (tree, format!("/?repository_key={key}&path=servers")),
            (
                tree,
                format!("/?repository_key={key}&path=servers/com.acme"),
            ),
        ];
        for sha in &sums {
            cases.push((search, format!("/checksum?checksum={sha}")));
        }
        for kind in ["held", "del", "deny"] {
            cases.push((search, format!("/quick?q={}&limit=50", name(kind))));
            cases.push((search, format!("/advanced?name={}", name(kind))));
        }
        let reader = outsider(&env).await;
        let mut leaks: Vec<String> = Vec::new();
        for (who, mk_app) in [
            (
                "anonymous",
                Box::new(|r: Router<SharedState>| env.fx.router_anon(r))
                    as Box<dyn Fn(Router<SharedState>) -> Router>,
            ),
            (
                "outsider",
                Box::new(|r: Router<SharedState>| as_caller(&env, &reader, r)),
            ),
        ] {
            for (mk, uri) in &cases {
                let (s, b, _) = call(mk_app(mk()), "GET", uri, None).await;
                let body = String::from_utf8_lossy(&b);
                assert!(
                    s == StatusCode::OK || s == StatusCode::NOT_FOUND,
                    "{who} {uri}: {s} {body}"
                );
                for h in &hidden {
                    if body.contains(h.as_str()) {
                        leaks.push(format!("{who} {uri} names {h}: {body}"));
                    }
                }
                if sums.iter().any(|sha| body.contains(sha.as_str())) {
                    leaks.push(format!("{who} {uri} names a hidden checksum"));
                }
            }
            assert!(leaks.is_empty(), "{}", leaks.join("\n"));
            // The visible server is still found.
            let quick = get_json(
                mk_app(search()),
                format!("/quick?q={}&limit=50", name("vis")),
            )
            .await;
            assert!(
                quick.to_string().contains(&format!("vis{tag}")),
                "{who}: {quick}"
            );
            let adv = get_json(
                mk_app(search()),
                format!("/advanced?repository_key={key}&per_page=50"),
            )
            .await;
            assert_eq!(adv["pagination"]["total"], 1, "{who}: {adv}");
            // The repository facet spans the caller's whole scope, not the
            // `repository_key` filter, and lists only the top 20 repositories
            // by count, so on a reused test database other repositories can
            // push this one out. Check this repository only: listed, it
            // counts its one visible row, not the four it stores; left out,
            // the list must be full (the advanced total above already pins
            // that hidden rows are not counted).
            let facet = adv["facets"]["repositories"].as_array().unwrap();
            match facet.iter().find(|f| f["value"] == key.as_str()) {
                Some(ours) => assert_eq!(ours["count"], 1, "{who}: {adv}"),
                None => assert_eq!(facet.len(), 20, "{who}: {adv}"),
            }
            let list = get_json(
                mk_app(repos()),
                format!("/{key}/artifacts?per_page=100&count=exact"),
            )
            .await;
            assert_eq!(list["pagination"]["total"], 1, "{who}: {list}");
            let pk = get_json(
                mk_app(packages()),
                format!("/?repository_key={key}&per_page=100"),
            )
            .await;
            assert_eq!(pk["pagination"]["total"], 1, "{who}: {pk}");
            let st = get_json(mk_app(repos()), format!("/{key}/storage")).await;
            assert_eq!(st["blob_count"], 1, "{who}: {st}");
            let stree = get_json(mk_app(repos()), format!("/{key}/storage/tree?depth=6")).await;
            assert_eq!(stree["node"]["file_count"], 1, "{who}: {stree}");
            for id in &pkg_ids {
                for tail in [format!("/{id}"), format!("/{id}/versions")] {
                    let (s, b, _) = call(mk_app(packages()), "GET", &tail, None).await;
                    let body = String::from_utf8_lossy(&b);
                    let empty = json(&b)["versions"]
                        .as_array()
                        .is_some_and(|v| v.is_empty());
                    assert!(
                        s == StatusCode::NOT_FOUND || empty,
                        "{who} package {tail}: {s} {body}"
                    );
                    for h in &hidden {
                        assert!(!body.contains(h.as_str()), "{who} {tail}: {body}");
                    }
                }
            }
            // Tree content: a hidden server.json is the 404 of a path that
            // does not exist (same status and body shape), never the document.
            let (ms, mb, _) = call(
                mk_app(tree()),
                "GET",
                &format!(
                    "/content?repository_key={key}&path=servers/com.acme/none{tag}/1.0.0/server.json"
                ),
                None,
            )
            .await;
            assert_eq!(ms, StatusCode::NOT_FOUND);
            // A hidden server's folder lists as a folder that does not exist.
            let folder = |n: &str| format!("/?repository_key={key}&path=servers/com.acme/{n}");
            let (fs, fb, _) =
                call(mk_app(tree()), "GET", &folder(&format!("none{tag}")), None).await;
            for kind in ["held", "del", "deny"] {
                let (s, b, _) = call(
                    mk_app(tree()),
                    "GET",
                    &folder(&format!("{kind}{tag}")),
                    None,
                )
                .await;
                assert_eq!(
                    (
                        s,
                        String::from_utf8_lossy(&b).replace(&format!("{kind}{tag}"), "X")
                    ),
                    (
                        fs,
                        String::from_utf8_lossy(&fb).replace(&format!("none{tag}"), "X")
                    ),
                    "{who} tree folder {kind}"
                );
            }
            for kind in ["held", "del", "deny"] {
                let path = format!("servers/com.acme/{kind}{tag}/1.0.0/server.json");
                let (s, b, _) = call(
                    mk_app(tree()),
                    "GET",
                    &format!("/content?repository_key={key}&path={path}"),
                    None,
                )
                .await;
                assert_eq!(s, StatusCode::NOT_FOUND, "{who} content {kind}");
                assert_eq!(
                    String::from_utf8_lossy(&b).replace(&format!("{kind}{tag}"), "X"),
                    String::from_utf8_lossy(&mb).replace(&format!("none{tag}"), "X"),
                    "{who} content {kind} must read as a missing path"
                );
            }
            let (s, _, _) = call(
                mk_app(tree()),
                "GET",
                &format!(
                    "/content?repository_key={key}&path=servers/com.acme/vis{tag}/1.0.0/server.json"
                ),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{who} visible content");
        }
        env.teardown().await;
    }

    /// #5397: search shares one registry's reader served set across
    /// requests. Eight concurrent anonymous searches and one after them
    /// compute it once (single flight), and a holder's search never computes
    /// it. A version stored while the set is fresh stays hidden from readers
    /// until it is recomputed (fail closed), and is shown once it is.
    #[tokio::test]
    async fn search_shares_the_reader_served_set() {
        use crate::api::handlers::search::{reader_served_computations, MCP_SEARCH_SERVED_TTL};
        let Some((env, server, _held)) = held_second_version("share").await else {
            return;
        };
        let repo = env.fx.repo_id;
        let search = || crate::api::handlers::search::router();
        let uri = format!("/advanced?name={server}");
        let started = std::time::Instant::now();
        let concurrent = (0..8).map(|_| get_json(env.fx.router_anon(search()), uri.clone()));
        for adv in futures::future::join_all(concurrent).await {
            assert_eq!(adv["pagination"]["total"], 1, "{adv}");
        }
        let holder = get_json(env.fx.router_with_auth(search()), uri.clone()).await;
        assert_eq!(holder["pagination"]["total"], 2, "{holder}");
        let d = doc(&server, "3.0.0", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let adv = get_json(env.fx.router_anon(search()), uri.clone()).await;
        // Only meaningful while the first set is still fresh.
        if started.elapsed() < MCP_SEARCH_SERVED_TTL {
            assert_eq!(reader_served_computations(repo), 1);
            assert_eq!(adv["pagination"]["total"], 1, "{adv}");
            assert!(!adv.to_string().contains("3.0.0"), "{adv}");
        }
        tokio::time::sleep(MCP_SEARCH_SERVED_TTL).await;
        let adv = get_json(env.fx.router_anon(search()), uri).await;
        assert_eq!(adv["pagination"]["total"], 2, "{adv}");
        assert!(adv.to_string().contains("3.0.0"), "{adv}");
        env.teardown().await;
    }

    /// #5397: the reader served set reads at most its row cap of rows (by
    /// path) and leaves the rest out, so they are hidden; a held version is
    /// never in it.
    #[tokio::test]
    async fn reader_served_set_is_capped_and_fails_closed() {
        use crate::api::handlers::search::compute_reader_served;
        let Some((env, server, held)) = held_second_version("cap").await else {
            return;
        };
        let d = doc(&server, "3.0.0", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let held_id = tdh::artifact_id_at(&env.fx.pool, env.fx.repo_id, &held).await;
        let v1 = env.server_artifact(&server, "1.0.0").await;
        let v3 = env.server_artifact(&server, "3.0.0").await;
        let all = compute_reader_served(&env.fx.state, env.fx.repo_id, 100).await;
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(all.contains(&v1) && all.contains(&v3), "{all:?}");
        assert!(!all.contains(&held_id), "{all:?}");
        let capped = compute_reader_served(&env.fx.state, env.fx.repo_id, 1).await;
        assert_eq!(capped, vec![v1], "the first row by path, the rest hidden");
        // A repository that is not an MCP registry serves nothing here.
        let none = compute_reader_served(&env.fx.state, Uuid::new_v4(), 100).await;
        assert!(none.is_empty());
        env.teardown().await;
    }

    /// #5253: an MCP registry's storage tree, for a reader, counts only the
    /// versions it is served: one server.json, no 2.0.0 node, although the
    /// materialized rollup (what a holder sees) counts both.
    #[tokio::test]
    async fn storage_tree_follows_the_serve_decision() {
        let Some((env, _server, _held)) = held_second_version("tree").await else {
            return;
        };
        let key = env.fx.repo_key.clone();
        // The materialized rollup counts both versions (what a holder sees);
        // a reader's tree must not.
        tdh::recompute_storage_stats_with_retry(&env.fx.pool, false).await;
        let repos = || crate::api::handlers::repositories::router();
        let holder = get_json(
            env.fx.router_with_auth(repos()),
            format!("/{key}/storage/tree?depth=5"),
        )
        .await;
        assert_eq!(holder["node"]["file_count"], 2, "{holder}");
        let tree = get_json(
            env.fx.router_anon(repos()),
            format!("/{key}/storage/tree?depth=5"),
        )
        .await;
        assert_eq!(tree["node"]["file_count"], 1, "{tree}");
        assert!(!tree.to_string().contains("2.0.0"), "{tree}");
        env.teardown().await;
    }

    /// #5253: a reader's artifact listing total counts only the versions it
    /// is served, on every page, and is exact; a holder's counts both.
    #[tokio::test]
    async fn listing_totals_follow_the_serve_decision() {
        let Some((env, _server, _held)) = held_second_version("tot").await else {
            return;
        };
        let key = env.fx.repo_key.clone();
        let repos = || crate::api::handlers::repositories::router();
        for page in [1, 2] {
            let list = get_json(
                env.fx.router_anon(repos()),
                format!("/{key}/artifacts?per_page=1&page={page}&count=exact"),
            )
            .await;
            assert_eq!(list["pagination"]["total"], 1, "page {page}: {list}");
            assert_eq!(list["total_is_exact"], true, "{list}");
        }
        let list = get_json(
            env.fx.router_with_auth(repos()),
            format!("/{key}/artifacts?per_page=1&count=exact"),
        )
        .await;
        assert_eq!(list["pagination"]["total"], 2, "{list}");
        env.teardown().await;
    }

    /// An authenticated caller with no grant on the (public) fixture registry:
    /// it reads the registry, but does not hold it.
    async fn outsider(env: &Env) -> AuthExtension {
        let (uid, uname) = tdh::create_user(&env.fx.pool).await;
        tdh::make_auth(uid, &uname)
    }

    /// `r` as `auth`, with both auth extensions, as `auth_middleware` does.
    fn as_caller(env: &Env, auth: &AuthExtension, r: Router<SharedState>) -> Router {
        tdh::router_with_auth_ext(r, env.fx.state.clone(), auth.clone())
    }

    fn fixture_user(env: &Env) -> AuthExtension {
        tdh::make_auth(env.fx.user_id, &env.fx.username)
    }

    async fn scan_row(env: &Env, artifact_id: Uuid) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, completed_at) \
             VALUES ($1, $2, 'mcp_lint', 'completed', NOW()) RETURNING id",
        )
        .bind(artifact_id)
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap()
    }

    /// #5253: the security scan listings leave out the scans of a version a
    /// non-holder is not served. The repository listings (`total` included),
    /// the artifact-scoped listing (empty, as for a missing artifact) and the
    /// scan and findings reads (`404`) of the held 2.0.0's `mcp_lint` row;
    /// a holder sees both rows.
    #[tokio::test]
    async fn scan_listings_follow_the_serve_decision() {
        let Some((env, name, _held)) = held_second_version("scan").await else {
            return;
        };
        let key = env.fx.repo_key.clone();
        let repo_id = env.fx.repo_id;
        let served_id = env.server_artifact(&name, "1.0.0").await;
        let held_id = env.server_artifact(&name, "2.0.0").await;
        // Publishing lints each server.json (`mcp_lint`); one more row each
        // makes the counts independent of how many that wrote.
        scan_row(&env, served_id).await;
        scan_row(&env, held_id).await;
        let count = |id: Option<Uuid>| {
            let pool = env.fx.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM scan_results WHERE repository_id = $1 \
                     AND ($2::uuid IS NULL OR artifact_id = $2)",
                )
                .bind(repo_id)
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let served_scans = count(Some(served_id)).await;
        let all_scans = count(None).await;
        assert!(all_scans > served_scans && served_scans >= 1);
        let held_scan: Uuid =
            sqlx::query_scalar("SELECT id FROM scan_results WHERE artifact_id = $1 LIMIT 1")
                .bind(held_id)
                .fetch_one(&env.fx.pool)
                .await
                .unwrap();
        let reader = outsider(&env).await;
        let holder = fixture_user(&env);
        let repo_scans = || crate::api::handlers::security::repo_security_router();
        let security = || crate::api::handlers::security::router();

        let list = get_json(
            as_caller(&env, &reader, repo_scans()),
            format!("/{key}/security/scans?per_page=1"),
        )
        .await;
        assert_eq!(list["total"], served_scans, "{list}");
        assert!(!list.to_string().contains(&held_id.to_string()), "{list}");
        let list = get_json(
            as_caller(&env, &reader, repo_scans()),
            format!("/{key}/security/scans?per_page=1&page=2"),
        )
        .await;
        assert_eq!(list["total"], served_scans, "page 2: {list}");
        assert!(!list.to_string().contains(&held_id.to_string()), "{list}");
        let list = get_json(
            as_caller(&env, &reader, security()),
            format!("/scans?repository_id={repo_id}&per_page=100"),
        )
        .await;
        assert_eq!(list["total"], served_scans, "{list}");
        assert!(!list.to_string().contains(&held_id.to_string()), "{list}");
        for uri in [
            format!("/artifacts/{held_id}/scans"),
            format!("/scans?artifact_id={held_id}"),
        ] {
            let list = get_json(as_caller(&env, &reader, security()), uri.clone()).await;
            assert_eq!(list["total"], 0, "{uri}: {list}");
            assert_eq!(list["items"].as_array().unwrap().len(), 0, "{uri}: {list}");
        }
        let missing = Uuid::new_v4();
        for (uri, missing_uri) in [
            (format!("/scans/{held_scan}"), format!("/scans/{missing}")),
            (
                format!("/scans/{held_scan}/findings"),
                format!("/scans/{missing}/findings"),
            ),
        ] {
            let (s, b, _) = call(as_caller(&env, &reader, security()), "GET", &uri, None).await;
            let (ms, mb, _) = call(
                as_caller(&env, &reader, security()),
                "GET",
                &missing_uri,
                None,
            )
            .await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!((s, b), (ms, mb), "{uri} must read as a missing scan");
        }

        let list = get_json(
            as_caller(&env, &holder, repo_scans()),
            format!("/{key}/security/scans"),
        )
        .await;
        assert_eq!(list["total"], all_scans, "{list}");
        let (s, _, _) = call(
            as_caller(&env, &holder, security()),
            "GET",
            &format!("/scans/{held_scan}"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&env.fx.pool)
            .await;
        env.teardown().await;
    }

    /// #5253: the by-id sub-resources of an artifact answer a held version as
    /// a missing artifact for a caller who does not hold the registry (the
    /// same status, and where the route's body names no id, the same body),
    /// while a holder still reads them.
    #[tokio::test]
    async fn by_id_sub_resources_follow_the_serve_decision() {
        let Some((env, server, _held)) = held_second_version("byid").await else {
            return;
        };
        let held_id = env.server_artifact(&server, "2.0.0").await;
        let missing = Uuid::new_v4();
        let reader = outsider(&env).await;
        let holder = fixture_user(&env);
        let artifacts = || crate::api::handlers::artifacts::router();
        let quarantine = || crate::api::handlers::quarantine::router();
        let quality = || crate::api::handlers::quality_gates::router();
        let sbom = || crate::api::handlers::sbom::router();
        let analysis = || crate::api::handlers::package_analysis::router();
        type Mk = fn() -> Router<SharedState>;
        // (router, uri template with `{}` for the id, holder status,
        // whether the body of a missing id is id-free and must match).
        let cases: [(Mk, &str, StatusCode, bool); 7] = [
            (artifacts, "/{}/labels", StatusCode::OK, false),
            (quarantine, "/{}", StatusCode::OK, true),
            (quality, "/checks?artifact_id={}", StatusCode::OK, true),
            (quality, "/health/artifacts/{}", StatusCode::NOT_FOUND, true),
            (sbom, "/by-artifact/{}", StatusCode::NOT_FOUND, true),
            (sbom, "/cve/history/by-artifact/{}", StatusCode::OK, true),
            (
                analysis,
                "/{}/package-analysis",
                StatusCode::NOT_FOUND,
                true,
            ),
        ];
        for (mk, tpl, holder_status, same_body) in cases {
            let uri = tpl.replace("{}", &held_id.to_string());
            let missing_uri = tpl.replace("{}", &missing.to_string());
            let (s, b, _) = call(as_caller(&env, &reader, mk()), "GET", &uri, None).await;
            let (ms, mb, _) = call(as_caller(&env, &reader, mk()), "GET", &missing_uri, None).await;
            assert_eq!(
                s,
                StatusCode::NOT_FOUND,
                "{uri}: {}",
                String::from_utf8_lossy(&b)
            );
            assert_eq!(ms, StatusCode::NOT_FOUND, "{missing_uri}");
            if same_body {
                assert_eq!(
                    String::from_utf8_lossy(&b),
                    String::from_utf8_lossy(&mb),
                    "{uri} must read as a missing artifact"
                );
            }
            let (hs, hb, _) = call(as_caller(&env, &holder, mk()), "GET", &uri, None).await;
            assert_eq!(
                hs,
                holder_status,
                "holder {uri}: {}",
                String::from_utf8_lossy(&hb)
            );
        }
        // A holder's 404s above come from the route's own data (no score, no
        // SBOM, no analysis), not from the serve decision: their bodies are
        // not the missing artifact's.
        let (_, hb, _) = call(
            as_caller(&env, &holder, sbom()),
            "GET",
            &format!("/by-artifact/{held_id}"),
            None,
        )
        .await;
        let (_, mb, _) = call(
            as_caller(&env, &holder, sbom()),
            "GET",
            &format!("/by-artifact/{missing}"),
            None,
        )
        .await;
        assert_ne!(hb, mb);
        env.teardown().await;
    }

    /// #5253: `artifacts-missing` reports a held version's path as
    /// `not_found` (whatever the checksum) to a caller who does not hold the
    /// registry, exactly like a path that does not exist; a holder is told
    /// it is present.
    #[tokio::test]
    async fn presence_check_follows_the_serve_decision() {
        let Some((env, _server, held)) = held_second_version("pres").await else {
            return;
        };
        let key = env.fx.repo_key.clone();
        let held_sha: String = sqlx::query_scalar(
            "SELECT lower(checksum_sha256) FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(env.fx.repo_id)
        .bind(&held)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        let other_sha = "f".repeat(64);
        let body = serde_json::json!({"items": [
            {"path": held, "sha256": held_sha},
            {"path": held, "sha256": other_sha},
            {"path": "servers/com.acme/none/1.0.0/server.json", "sha256": held_sha},
        ]});
        let presence = || crate::api::handlers::artifact_presence::repo_router();
        let uri = format!("/{key}/artifacts-missing");
        let (s, b, _) = call(env.fx.router_anon(presence()), "POST", &uri, Some(&body)).await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let reasons: Vec<String> = json(&b)["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["reason"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            reasons,
            ["not_found", "not_found", "not_found"],
            "{}",
            json(&b)
        );
        let (s, b, _) = call(
            env.fx.router_with_auth(presence()),
            "POST",
            &uri,
            Some(&body),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let reasons: Vec<String> = json(&b)["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["reason"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(reasons, ["checksum_mismatch", "not_found"], "{}", json(&b));
        env.teardown().await;
    }

    /// #5253: `/api/v1/packages` counts only the catalog rows a reader is
    /// shown, on every page: a server whose only version is held through
    /// its backing package is neither listed nor counted. A holder counts it.
    #[tokio::test]
    async fn package_totals_follow_the_serve_decision() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (_npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for (name, v) in [("com.acme/shown", "1.0.0"), ("com.acme/hidden", "2.0.0")] {
            let d = doc(
                name,
                "1.0.0",
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        // The hidden server's row is the newest, so it would sit on page 1.
        sqlx::query(
            "UPDATE packages SET updated_at = NOW() + interval '1 hour' \
             WHERE repository_id = $1 AND name = 'com.acme/hidden'",
        )
        .bind(env.fx.repo_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let api = || crate::api::handlers::packages::router();
        let key = env.fx.repo_key.clone();
        let mut names = Vec::new();
        for page in [1, 2] {
            let list = get_json(
                env.fx.router_anon(api()),
                format!("/?repository_key={key}&per_page=1&page={page}"),
            )
            .await;
            assert_eq!(list["pagination"]["total"], 1, "page {page}: {list}");
            assert_eq!(list["pagination"]["total_pages"], 1, "page {page}: {list}");
            for i in list["items"].as_array().unwrap() {
                names.push(i["name"].as_str().unwrap().to_string());
            }
        }
        assert_eq!(names, ["com.acme/shown"]);
        let list = get_json(
            env.fx.router_with_auth(api()),
            format!("/?repository_key={key}&per_page=1"),
        )
        .await;
        assert_eq!(list["pagination"]["total"], 2, "{list}");
        env.teardown().await;
    }

    /// #5253: a catalog row whose stored version is held shows a reader the
    /// newest servable version with that version's own size and times, never
    /// the held one's, and a download count over the served versions only
    /// (#5346 counts from the download history); a holder counts every
    /// version.
    #[tokio::test]
    async fn catalog_row_figures_follow_the_shown_version() {
        let Some((env, server, _held)) = held_second_version("fig").await else {
            return;
        };
        let (pkg, row_version): (Uuid, String) = sqlx::query_as(
            "SELECT id, version FROM packages WHERE repository_id = $1 AND name = $2",
        )
        .bind(env.fx.repo_id)
        .bind(&server)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(row_version, "2.0.0");
        // Make the held version's figures unmistakable.
        sqlx::query(
            "UPDATE packages SET size_bytes = 987654, download_count = 4242, \
             created_at = '2001-01-01T00:00:00Z', updated_at = '2001-01-02T00:00:00Z' \
             WHERE id = $1",
        )
        .bind(pkg)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (size, created): (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT size_bytes, created_at FROM package_versions \
                 WHERE package_id = $1 AND version = '1.0.0'",
        )
        .bind(pkg)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        // Downloads of the served 1.0.0 and of the held 2.0.0, as the
        // download path records them.
        for (version, n) in [("1.0.0", 2), ("2.0.0", 5)] {
            let artifact = env.server_artifact(&server, version).await;
            for _ in 0..n {
                sqlx::query("INSERT INTO download_statistics (artifact_id) VALUES ($1)")
                    .bind(artifact)
                    .execute(&env.fx.pool)
                    .await
                    .unwrap();
            }
        }
        let api = || crate::api::handlers::packages::router();
        let row = get_json(env.fx.router_anon(api()), format!("/{pkg}")).await;
        assert_eq!(row["version"], "1.0.0", "{row}");
        assert_eq!(row["size_bytes"], size, "{row}");
        assert_eq!(row["download_count"], 2, "served versions only: {row}");
        let at = |f: &str| {
            chrono::DateTime::parse_from_rfc3339(row[f].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        assert_eq!(at("created_at"), created, "{row}");
        assert_eq!(at("updated_at"), created, "{row}");
        assert!(!row.to_string().contains("2001-01"), "{row}");
        let held_row = get_json(env.fx.router_with_auth(api()), format!("/{pkg}")).await;
        assert_eq!(held_row["size_bytes"], 987654, "{held_row}");
        assert_eq!(
            held_row["download_count"], 7,
            "a holder counts both: {held_row}"
        );
        env.teardown().await;
    }

    /// #5253: a reader of an MCP registry is shown storage figures of the
    /// versions it is served only (`GET /{key}/storage` and
    /// `storage_used_bytes` of `GET /{key}`); a holder the stored total
    /// (`storage_used_bytes`; the holder's `/storage` is the materialized
    /// rollup, unchanged).
    #[tokio::test]
    async fn storage_totals_follow_the_serve_decision() {
        let Some((env, _server, held)) = held_second_version("stor").await else {
            return;
        };
        let key = env.fx.repo_key.clone();
        let size_of = |path: String| {
            let pool = env.fx.pool.clone();
            let repo = env.fx.repo_id;
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT size_bytes FROM artifacts WHERE repository_id = $1 AND path = $2",
                )
                .bind(repo)
                .bind(path)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let held_size = size_of(held.clone()).await;
        let served_size = size_of(held.replace("/2.0.0/", "/1.0.0/")).await;
        let repos = || crate::api::handlers::repositories::router();
        let stats = get_json(env.fx.router_anon(repos()), format!("/{key}/storage")).await;
        assert_eq!(stats["logical_bytes"], served_size, "{stats}");
        assert_eq!(stats["blob_count"], 1, "{stats}");
        let detail = get_json(env.fx.router_anon(repos()), format!("/{key}")).await;
        assert_eq!(detail["storage_used_bytes"], served_size, "{detail}");
        let detail = get_json(env.fx.router_with_auth(repos()), format!("/{key}")).await;
        assert_eq!(
            detail["storage_used_bytes"],
            served_size + held_size,
            "{detail}"
        );
        env.teardown().await;
    }

    /// #5253: the generic artifact routes apply the MCP serve decision. With
    /// 2.0.0 held through its backing npm package (the server.json row itself
    /// is not quarantined), an anonymous reader of the public registry gets
    /// no 2.0.0 row from the artifact listing and the routes' plain `404`
    /// from the metadata, revision-history, download and by-id routes, while
    /// 1.0.0 is served. A holder keeps access. Releasing the hold serves
    /// 2.0.0 again.
    #[tokio::test]
    async fn generic_artifact_routes_follow_the_serve_decision() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (_npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                "com.acme/gen",
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        let key = env.fx.repo_key.clone();
        let held = "servers/com.acme/gen/2.0.0/server.json";
        let served = "servers/com.acme/gen/1.0.0/server.json";
        let held_id = env.server_artifact("com.acme/gen", "2.0.0").await;
        let repos = || crate::api::handlers::repositories::router();
        let downloads = || crate::api::handlers::repositories::download_router();
        let by_id = || crate::api::handlers::artifacts::router();
        let anon = |r: Router<SharedState>| env.fx.router_anon(r);
        let member = |r: Router<SharedState>| env.fx.router_with_auth(r);
        let listed = |app: Router| {
            let uri = format!("/{key}/artifacts?per_page=100");
            async move {
                let (s, b, _) = call(app, "GET", &uri, None).await;
                assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
                let mut paths: Vec<String> = json(&b)["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| i["path"].as_str().unwrap().to_string())
                    .collect();
                paths.sort();
                paths
            }
        };
        assert_eq!(listed(anon(repos())).await, [served.to_string()]);
        assert_eq!(
            listed(member(repos())).await,
            [served.to_string(), held.to_string()]
        );
        let status = |app: Router, uri: String| async move { call(app, "GET", &uri, None).await.0 };
        for (path, want) in [(held, StatusCode::NOT_FOUND), (served, StatusCode::OK)] {
            assert_eq!(
                status(anon(repos()), format!("/{key}/artifacts/{path}")).await,
                want,
                "metadata {path}"
            );
            assert_eq!(
                status(anon(downloads()), format!("/{key}/download/{path}")).await,
                want,
                "download {path}"
            );
        }
        assert_eq!(
            status(anon(repos()), format!("/{key}/versions/{held}")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(anon(by_id()), format!("/{held_id}")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(anon(by_id()), format!("/{held_id}/metadata")).await,
            StatusCode::NOT_FOUND
        );
        // A holder reads the held version's metadata and record.
        assert_eq!(
            status(member(repos()), format!("/{key}/artifacts/{held}")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(member(by_id()), format!("/{held_id}")).await,
            StatusCode::OK
        );
        // Released: served to readers again.
        env.hold(ids[1], None).await;
        assert_eq!(
            status(anon(repos()), format!("/{key}/artifacts/{held}")).await,
            StatusCode::OK
        );
        assert_eq!(listed(anon(repos())).await.len(), 2);
        env.teardown().await;
    }

    /// #5452: the generic content routes serve an MCP server.json as the
    /// registry does, its packages at their pinned AK coordinates: the
    /// repository download (GET and HEAD), the artifact metadata (by path and
    /// by id) and the tree content. The submitted foreign `registryBaseUrl`
    /// appears only as `_meta[...resolved].submittedRegistryBaseUrl`.
    #[tokio::test]
    async fn generic_routes_serve_the_pinned_server_json() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let (npm, _) = env.npm_backing(&["1.0.0"]).await;
        let mut p = npm_pkg("@acme/echo", Some("1.0.0"));
        p["registryBaseUrl"] = "https://npm.evil.test".into();
        let d = doc(
            "com.acme/gen",
            "1.0.0",
            serde_json::json!({"packages": [p]}),
        );
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let key = env.fx.repo_key.clone();
        let path = "servers/com.acme/gen/1.0.0/server.json";
        let id = env.server_artifact("com.acme/gen", "1.0.0").await;
        let own = format!("http://localhost/npm/{}", npm.key);
        let check = |server: &serde_json::Value, route: &str| {
            let pkg = &server["packages"][0];
            assert_eq!(pkg["registryBaseUrl"], own.as_str(), "{route}: {server}");
            assert_eq!(
                pkg["_meta"][fmt::AK_RESOLVED_META_KEY]["submittedRegistryBaseUrl"],
                "https://npm.evil.test",
                "{route}"
            );
        };
        let anon = |r: Router<SharedState>| env.fx.router_anon(r);
        let get = |app: Router, uri: String| async move { call(app, "GET", &uri, None).await };

        let downloads = || crate::api::handlers::repositories::download_router();
        let (s, b, h) = get(anon(downloads()), format!("/{key}/download/{path}")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h["x-checksum-sha256"], fmt::sha256_hex(&b).as_str());
        check(&json(&b), "download");
        let downloads_now = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
            )
            .bind(id)
            .fetch_one(&env.fx.pool)
            .await
            .unwrap()
        };
        let mut counted = 0;
        for _ in 0..80 {
            counted = downloads_now().await;
            if counted > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(counted >= 1, "the download is counted");
        let (s, b, h) = call(
            anon(downloads()),
            "HEAD",
            &format!("/{key}/download/{path}"),
            None,
        )
        .await;
        assert_eq!((s, b.len()), (StatusCode::OK, 0));
        assert!(
            h[header::CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > 0
        );

        let repos = || crate::api::handlers::repositories::router();
        let (s, b, h) = get(anon(repos()), format!("/{key}/artifacts/{path}")).await;
        assert_eq!(
            (s, h[header::CACHE_CONTROL].to_str().unwrap()),
            (StatusCode::OK, "no-store")
        );
        check(&json(&b)["metadata"]["server"], "metadata");
        let by_id = || crate::api::handlers::artifacts::router();
        let (s, b, h) = get(anon(by_id()), format!("/{id}/metadata")).await;
        assert_eq!(
            (s, h[header::CACHE_CONTROL].to_str().unwrap()),
            (StatusCode::OK, "no-store")
        );
        check(&json(&b)["metadata"]["server"], "metadata by id");
        let tree = || crate::api::handlers::tree::router();
        let (s, b, _) = get(
            anon(tree()),
            format!("/content?repository_key={key}&path={path}"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        check(&json(&b), "tree content");
        // The download gate still applies: a holder of a quarantined
        // server.json is refused, not served the rewritten document.
        env.hold(id, Some("quarantined")).await;
        let member = env.fx.router_with_auth(downloads());
        let (s, _, _) = get(member, format!("/{key}/download/{path}")).await;
        assert_eq!(s, StatusCode::CONFLICT);
        env.teardown().await;
    }

    /// The tree browser (`/api/v1/tree`, `/api/v1/tree/content`) applies
    /// the serve decision: a reader gets no node for a held version (and no
    /// folder that only held versions fill) and the plain 404 for its
    /// server.json, while a holder browses and reads it. MCP content is
    /// never cached, and a non-public repository's bytes only privately.
    #[tokio::test]
    async fn tree_browser_follows_the_serve_decision() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                "com.acme/tree",
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        let key = env.fx.repo_key.clone();
        let tree = || crate::api::handlers::tree::router();
        let names = |app: Router, path: &str| {
            let uri = format!("/?repository_key={key}&path={path}");
            async move {
                let (s, b, _) = call(app, "GET", &uri, None).await;
                assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
                json(&b)["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n["name"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            }
        };
        let anon = || env.fx.router_anon(tree());
        let member = || env.fx.router_with_auth(tree());
        assert_eq!(names(anon(), "servers/com.acme/tree").await, ["1.0.0"]);
        assert_eq!(
            names(member(), "servers/com.acme/tree").await,
            ["1.0.0", "2.0.0"]
        );
        assert_eq!(names(anon(), "servers/com.acme/tree/2.0.0").await.len(), 0);

        let content = |app: Router, path: &str| {
            let uri = format!("/content?repository_key={key}&path={path}");
            async move { call(app, "GET", &uri, None).await }
        };
        let held = "servers/com.acme/tree/2.0.0/server.json";
        let served = "servers/com.acme/tree/1.0.0/server.json";
        let missing = "servers/com.acme/tree/9.0.0/server.json";
        let (s, held_body, _) = content(anon(), held).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, missing_body, _) = content(anon(), missing).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(
            json(&held_body)["message"]
                .as_str()
                .map(|m| m.replace("2.0.0", "9.0.0")),
            json(&missing_body)["message"].as_str().map(str::to_string),
            "a held version answers as a missing one"
        );
        let (s, b, h) = content(anon(), served).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(json(&b)["version"], "1.0.0");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        let (s, b, h) = content(member(), held).await;
        assert_eq!(s, StatusCode::OK, "a holder reads the held version");
        assert_eq!(json(&b)["version"], "2.0.0");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");

        // Another format: a public repository may be cached publicly, a
        // private one only by the caller.
        let npm_path = "@acme/echo/-/echo-1.0.0.tgz";
        let npm_content = |app: Router| {
            let uri = format!("/content?repository_key={}&path={npm_path}", npm.key);
            async move { call(app, "GET", &uri, None).await }
        };
        let (s, _, h) = npm_content(member()).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CACHE_CONTROL], "private, max-age=3600");
        tdh::publish_repo(&env.fx.pool, npm.id).await;
        let (s, _, h) = npm_content(anon()).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=3600");
        env.teardown().await;
    }

    /// Successful `/v0.1` reads say how they may be cached: a detail (which
    /// can carry a per-caller bundle ticket) never is, a listing only by the
    /// caller and only after revalidation, keyed on the credential.
    #[tokio::test]
    async fn registry_reads_are_not_shared_cached() {
        let Some(env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let d = doc("com.acme/cache", "1.0.0", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        for tail in [
            "/servers/com.acme%2Fcache/versions/1.0.0",
            "/servers/com.acme%2Fcache/versions/latest",
        ] {
            let (s, _, h) = env.get(env.anon(), tail).await;
            assert_eq!(s, StatusCode::OK, "{tail}");
            assert_eq!(h[header::CACHE_CONTROL], "no-store", "{tail}");
        }
        for tail in ["/servers", "/servers/com.acme%2Fcache/versions"] {
            let (s, _, h) = env.get(env.anon(), tail).await;
            assert_eq!(s, StatusCode::OK, "{tail}");
            assert_eq!(h[header::CACHE_CONTROL], "private, no-cache", "{tail}");
            assert_eq!(h[header::VARY], "Authorization, Cookie", "{tail}");
        }
        env.teardown().await;
    }

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
            match decide_row(ctx, &row, false, audience, "i".into()).await {
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
            mcp_packages::listing_refusals(ctx, env.fx.repo_id, &listing)
                .await
                .is_err()
                || servable(ctx, env.fx.repo_id, vec![row.clone()])
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

    /// #5458: through the real visibility middleware and the surface guard,
    /// every hosted write (publish, status change, introspection probe) by an
    /// administrator of ANOTHER repository answers an existing private key
    /// byte for byte (status, headers, body) as it answers an unknown key,
    /// and changes nothing. A member who can read keeps the 403.
    #[tokio::test]
    async fn write_denials_to_non_readers_match_an_unknown_key() {
        use crate::api::middleware::auth::{repo_visibility_middleware, RepoVisibilityState};
        use std::sync::Arc;
        let Some(env) = Env::new().await else { return };
        let d = doc("com.acme/a", "1.0.0", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        let auth_service = Arc::new(crate::services::auth_service::AuthService::new(
            env.fx.pool.clone(),
            Arc::new(env.fx.state.config.clone()),
        ));
        let app = Router::new()
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
            ))
            .layer(axum::middleware::from_fn(mcp_surface_guard));
        // An administrator of a different repository, not of the instance.
        let (foreign, _) = tdh::create_user(&env.fx.pool).await;
        let (own_id, _, own_dir) = tdh::create_repo(&env.fx.pool, "local", "mcp").await;
        tdh::grant_repo_role(&env.fx.pool, own_id, foreign, "repository-owner").await;
        let foreign_bearer = tdh::bearer_for(&env.fx.state, foreign).await;
        let (reader, _) = tdh::create_user(&env.fx.pool).await;
        tdh::grant_repo_role(&env.fx.pool, env.fx.repo_id, reader, "reader").await;
        let reader_bearer = tdh::bearer_for(&env.fx.state, reader).await;
        let unknown = format!("ak5458-unknown-{}", Uuid::new_v4());
        let version = "/servers/com.acme%2Fa/versions/1.0.0";
        let writes: [(&str, String, Option<serde_json::Value>); 3] = [
            ("POST", "/publish".to_string(), Some(d.clone())),
            (
                "PATCH",
                format!("{version}/status"),
                Some(serde_json::json!({"status": "deleted"})),
            ),
            ("POST", format!("{version}/capabilities/probe"), None),
        ];
        let send =
            |key: &str, bearer: &str, verb: &str, tail: &str, body: Option<&serde_json::Value>| {
                let mut b = Request::builder()
                    .method(verb)
                    .uri(format!("/mcp/{key}/v0.1{tail}"))
                    .header(header::AUTHORIZATION, bearer);
                if body.is_some() {
                    b = b.header(header::CONTENT_TYPE, "application/json");
                }
                let body = body
                    .map(|v| Body::from(serde_json::to_vec(v).unwrap()))
                    .unwrap_or_else(Body::empty);
                tdh::send_with_headers(app.clone(), b.body(body).unwrap())
            };
        for (verb, tail, body) in &writes {
            let existing = send(&env.fx.repo_key, &foreign_bearer, verb, tail, body.as_ref()).await;
            let missing = send(&unknown, &foreign_bearer, verb, tail, body.as_ref()).await;
            assert_eq!(existing.0, StatusCode::NOT_FOUND, "{verb} {tail}");
            assert_eq!(
                &existing.1[..],
                fmt::NOT_FOUND_BODY.as_bytes(),
                "{verb} {tail}"
            );
            assert_eq!(
                existing, missing,
                "{verb} {tail}: existing private vs unknown"
            );
            assert_refusal_headers(&existing.2);
            assert!(!existing.2.contains_key(header::WWW_AUTHENTICATE));
            // A member who can read already knows the repository exists.
            let (s, b, h) = send(&env.fx.repo_key, &reader_bearer, verb, tail, body.as_ref()).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{verb} {tail}: reader");
            assert_eq!(json(&b)["error"], "mcp_forbidden");
            assert_refusal_headers(&h);
        }
        // Nothing changed: one stored version, still active, no probe job.
        let rows = versions_of(&env.fx.pool, env.fx.repo_id, "com.acme/a")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stored.registry.status, ServerStatus::Active);
        let jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mcp_introspection_jobs WHERE repository_id = $1",
        )
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(jobs, 0);
        tdh::cleanup_member_repo(&env.fx.pool, own_id, &own_dir).await;
        tdh::cleanup_user(&env.fx.pool, foreign).await;
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
        let decide = |ctx, audience| decide_row(ctx, &row, false, audience, "i".into());
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
        assert!(servable(ctx(false), env.fx.repo_id, vec![row.clone()])
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
            servable(ctx(false), env.fx.repo_id, vec![row.clone()])
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

    // -----------------------------------------------------------------------
    // #5457: a rejection follows the digest across every alias and survives
    // a tag move, on the native OCI and the MCP routes alike.
    // -----------------------------------------------------------------------

    /// How D1 is refused: an administrator's quarantine, or the scanner's
    /// rejection (the quarantined -> rejected API transition).
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Refusal {
        Manual,
        Scanner,
    }

    /// Which alias of D1 is refused, and when.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum RefuseAt {
        /// D1's tag-path row, before the tag moves to D2.
        TagRow,
        /// D1's digest-path row, before the tag moves.
        DigestRow,
        /// D1's digest-path row, after the tag moved (its only alias then).
        DigestRowAfterMove,
    }

    /// A Local docker repository with a Virtual over it, an MCP registry
    /// (the fixture) mapped onto the Local, and an MCP Virtual over the
    /// registry: the four read routes of #5457.
    struct AliasRig {
        env: Env,
        docker: RepoInfo,
        oci_virtual: RepoInfo,
        mcp_virtual: RepoInfo,
        bearer: String,
    }

    const ALIAS_IMAGE: &str = "acme/app";
    const ALIAS_MT: &str = "application/vnd.oci.image.manifest.v1+json";

    impl AliasRig {
        async fn new() -> Option<Self> {
            let mut env = Env::new().await?;
            let docker = env.repo("local", "docker").await;
            tdh::grant_repo_actions(&env.fx.pool, docker.id, env.fx.user_id, &["read", "write"])
                .await;
            let oci_virtual = env.repo("virtual", "docker").await;
            tdh::link_virtual_member(&env.fx.pool, oci_virtual.id, docker.id, 1).await;
            let mcp_virtual = env.repo("virtual", "mcp").await;
            tdh::link_virtual_member(&env.fx.pool, mcp_virtual.id, env.fx.repo_id, 1).await;
            env.config(
                mcp_packages::REPOS_KEY,
                &serde_json::json!({"oci": docker.key}).to_string(),
            )
            .await;
            let bearer = tdh::bearer_for(&env.fx.state, env.fx.user_id).await;
            Some(Self {
                env,
                docker,
                oci_virtual,
                mcp_virtual,
                bearer,
            })
        }

        /// A native OCI manifest request as the fixture user.
        async fn oci(
            &self,
            method: &str,
            repo_key: &str,
            reference: &str,
            body: Bytes,
        ) -> axum::response::Response {
            use tower::ServiceExt;
            let mut req = Request::builder()
                .method(method)
                .uri(format!("/{repo_key}/{ALIAS_IMAGE}/manifests/{reference}"))
                .header(header::AUTHORIZATION, &self.bearer);
            if method == "PUT" {
                req = req.header(header::CONTENT_TYPE, ALIAS_MT);
            }
            crate::api::handlers::oci_v2::router(None)
                .with_state(self.env.fx.state.clone())
                .oneshot(req.body(Body::from(body)).unwrap())
                .await
                .unwrap()
        }

        /// Push a fresh image as tag `1.0` through the native push path;
        /// returns its digest.
        async fn push(&self, build: &str) -> String {
            let body = format!(
                r#"{{"schemaVersion":2,"mediaType":"{ALIAS_MT}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{c}","size":1}},"layers":[],"annotations":{{"build":"{build}-{u}"}}}}"#,
                c = "1".repeat(64),
                u = Uuid::new_v4()
            );
            let resp = self
                .oci("PUT", &self.docker.key, "1.0", Bytes::from(body))
                .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "push {build}");
            resp.headers()["Docker-Content-Digest"]
                .to_str()
                .unwrap()
                .to_string()
        }

        async fn native(&self, repo_key: &str, reference: &str) -> StatusCode {
            self.oci("GET", repo_key, reference, Bytes::new())
                .await
                .status()
        }

        /// Publish `com.acme/app@<version>` pinned to the image's tag `1.0`.
        async fn publish(&self, version: &str) {
            let mut d = oci_doc(&format!("localhost/{}/{ALIAS_IMAGE}:1.0", self.docker.key));
            d["name"] = "com.acme/app".into();
            d["version"] = version.into();
            let (s, b) = self.env.publish(&d).await;
            assert_eq!(s, StatusCode::OK, "publish {version}: {b}");
        }

        /// The MCP detail of `version` through the registry (status, gate)
        /// and through the MCP Virtual (status).
        async fn mcp(&self, version: &str) -> ((StatusCode, Option<String>), StatusCode) {
            let tail = format!("/v0.1/servers/com.acme%2Fapp/versions/{version}");
            let (hosted, b, _) = call(
                self.env.member(),
                "GET",
                &format!("/{}{tail}", self.env.fx.repo_key),
                None,
            )
            .await;
            let gate = json(&b)["gate"].as_str().map(str::to_string);
            let (virt, _, _) = call(
                self.env.member(),
                "GET",
                &format!("/{}{tail}", self.mcp_virtual.key),
                None,
            )
            .await;
            ((hosted, gate), virt)
        }

        /// The `(path, quarantine_status)` of every live manifest row of
        /// `digest` in the Local repository.
        async fn rows_of(&self, digest: &str) -> Vec<(String, Option<String>)> {
            sqlx::query_as(
                "SELECT path, quarantine_status FROM artifacts WHERE repository_id = $1 \
                 AND checksum_sha256 = $2 AND is_deleted = false ORDER BY path",
            )
            .bind(self.docker.id)
            .bind(digest.trim_start_matches("sha256:"))
            .fetch_all(&self.env.fx.pool)
            .await
            .unwrap()
        }

        async fn row_id(&self, reference: &str) -> Uuid {
            tdh::artifact_id_at(
                &self.env.fx.pool,
                self.docker.id,
                &format!("v2/{ALIAS_IMAGE}/manifests/{reference}"),
            )
            .await
        }

        /// Refuse `artifact_id` through the quarantine API, as an
        /// administrator (and then the scanner) would.
        async fn refuse(&self, artifact_id: Uuid, how: Refusal) {
            let admin = || {
                tdh::router_with_auth(
                    crate::api::handlers::quarantine::router(),
                    self.env.fx.state.clone(),
                    tdh::admin_auth(self.env.fx.user_id, &self.env.fx.username),
                )
            };
            let mut steps = vec![("quarantine", r#"{"reason":"admin hold"}"#)];
            if how == Refusal::Scanner {
                steps.push(("reject", r#"{"reason":"scanner: critical findings"}"#));
            }
            for (action, body) in steps {
                let (s, b) = tdh::send(
                    admin(),
                    tdh::post(
                        format!("/{artifact_id}/{action}"),
                        "application/json",
                        Bytes::from_static(body.as_bytes()),
                    ),
                )
                .await;
                assert_eq!(
                    s,
                    StatusCode::OK,
                    "{action}: {}",
                    String::from_utf8_lossy(&b)
                );
            }
        }

        /// D1 is refused on all four routes, with the mechanism's answer.
        async fn assert_refused(&self, d1: &str, how: Refusal, when: &str) {
            let (native, gate) = match how {
                Refusal::Manual => (StatusCode::CONFLICT, "quarantine"),
                Refusal::Scanner => (StatusCode::FORBIDDEN, "scan_policy"),
            };
            assert_eq!(
                (
                    self.native(&self.docker.key, d1).await,
                    self.native(&self.oci_virtual.key, d1).await
                ),
                (native, native),
                "{when}: D1 by digest, native hosted and Virtual"
            );
            assert_eq!(
                self.mcp("1.0.0").await,
                (
                    (StatusCode::NOT_FOUND, Some(gate.to_string())),
                    StatusCode::NOT_FOUND
                ),
                "{when}: the version pinned to D1, MCP hosted and Virtual"
            );
        }

        /// `(generic download, tree content)` status of the manifest row at
        /// `reference`, the two path-addressed reads.
        async fn path_reads(&self, reference: &str) -> (StatusCode, StatusCode) {
            let path = format!("v2/{ALIAS_IMAGE}/manifests/{reference}");
            let key = &self.docker.key;
            let (download, _) = tdh::send(
                self.env
                    .fx
                    .router_with_auth(crate::api::handlers::repositories::download_router()),
                tdh::get(format!("/{key}/download/{path}")),
            )
            .await;
            let (tree, _) = tdh::send(
                self.env
                    .fx
                    .router_with_auth(crate::api::handlers::tree::router()),
                tdh::get(format!("/content?repository_key={key}&path={path}")),
            )
            .await;
            (download, tree)
        }

        /// Upsert the manifest row of `reference` to `digest` through the
        /// shared upsert every manifest writer uses (no tag row, no bytes).
        async fn upsert(&self, reference: &str, digest: &str) {
            crate::api::handlers::oci_v2::upsert_manifest_artifact(
                &self.env.fx.pool,
                self.docker.id,
                ALIAS_IMAGE,
                reference,
                digest,
                ALIAS_MT,
                &crate::api::handlers::oci_v2::manifest_storage_key(digest),
                10,
                Some(self.env.fx.user_id),
                None,
            )
            .await
            .unwrap();
        }

        /// Set the hold of the row at `reference` (`until` as SQL).
        async fn set_hold(&self, reference: &str, status: &str, until: &str, source: &str) {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE artifacts SET quarantine_status = $3, quarantine_until = {until}, \
                 quarantine_source = $4 WHERE repository_id = $1 AND path = $2"
            )))
            .bind(self.docker.id)
            .bind(format!("v2/{ALIAS_IMAGE}/manifests/{reference}"))
            .bind(status)
            .bind(source)
            .execute(&self.env.fx.pool)
            .await
            .unwrap();
        }

        /// `(status, timed, source, is_deleted)` of the row at `reference`.
        async fn hold_at(
            &self,
            reference: &str,
        ) -> Option<(Option<String>, bool, Option<String>, bool)> {
            sqlx::query_as(
                "SELECT quarantine_status, quarantine_until IS NOT NULL, quarantine_source, \
                        is_deleted \
                 FROM artifacts WHERE repository_id = $1 AND path = $2",
            )
            .bind(self.docker.id)
            .bind(format!("v2/{ALIAS_IMAGE}/manifests/{reference}"))
            .fetch_optional(&self.env.fx.pool)
            .await
            .unwrap()
        }

        async fn teardown(self) {
            self.env.teardown().await;
        }
    }

    /// The #5457 reproduction: push D1 as `1.0`, MCP-publish it (the pin
    /// writes D1's digest-path row), refuse one alias of D1, move `1.0` to
    /// D2. D1 stays refused under every alias on every route; D2 is served
    /// on every route (it was never refused); and the rows show the hold on
    /// D1's surviving alias, not on the tag row that now names D2.
    async fn rejection_follows_the_digest(how: Refusal, at: RefuseAt) {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("d1").await;
        rig.publish("1.0.0").await;
        let tag_row = rig.row_id("1.0").await;
        let d1_row = rig.row_id(&d1).await;
        assert_eq!(
            rig.native(&rig.docker.key, &d1).await,
            StatusCode::OK,
            "control: D1 is served before any refusal"
        );
        match at {
            RefuseAt::TagRow => rig.refuse(tag_row, how).await,
            RefuseAt::DigestRow => rig.refuse(d1_row, how).await,
            RefuseAt::DigestRowAfterMove => {}
        }
        if at != RefuseAt::DigestRowAfterMove {
            rig.assert_refused(&d1, how, "before the move").await;
            assert_eq!(
                rig.native(&rig.oci_virtual.key, "1.0").await,
                rig.native(&rig.docker.key, &d1).await,
                "before the move: the tag answers as its digest"
            );
        }

        let d2 = rig.push("d2").await;
        assert_ne!(d1, d2);
        assert_eq!(
            rig.row_id("1.0").await,
            tag_row,
            "the tag row is rewritten in place"
        );
        if at == RefuseAt::DigestRowAfterMove {
            rig.refuse(d1_row, how).await;
        }
        rig.publish("2.0.0").await;

        rig.assert_refused(&d1, how, "after the move").await;
        for (key, reference) in [
            (&rig.docker.key, "1.0"),
            (&rig.docker.key, d2.as_str()),
            (&rig.oci_virtual.key, "1.0"),
            (&rig.oci_virtual.key, d2.as_str()),
        ] {
            assert_eq!(
                rig.native(key, reference).await,
                StatusCode::OK,
                "D2 is served: {key} {reference}"
            );
        }
        assert_eq!(
            rig.mcp("2.0.0").await,
            ((StatusCode::OK, None), StatusCode::OK),
            "the version pinned to D2, MCP hosted and Virtual"
        );

        // Both aliases, in the rows: D1 is left with its digest-path row only,
        // and that row carries the refusal; the tag row names D2, clean.
        let refused = match how {
            Refusal::Manual => "quarantined",
            Refusal::Scanner => "rejected",
        };
        assert_eq!(
            rig.rows_of(&d1).await,
            vec![(
                format!("v2/{ALIAS_IMAGE}/manifests/{d1}"),
                Some(refused.to_string())
            )]
        );
        let d2_rows = rig.rows_of(&d2).await;
        assert!(
            d2_rows.contains(&(format!("v2/{ALIAS_IMAGE}/manifests/1.0"), None)),
            "{d2_rows:?}"
        );
        assert!(d2_rows.iter().all(|(_, s)| s.is_none()), "{d2_rows:?}");
        rig.teardown().await;
    }

    #[tokio::test]
    async fn manual_quarantine_of_the_tag_row_follows_the_digest_5457() {
        rejection_follows_the_digest(Refusal::Manual, RefuseAt::TagRow).await;
    }

    #[tokio::test]
    async fn scanner_rejection_of_the_tag_row_follows_the_digest_5457() {
        rejection_follows_the_digest(Refusal::Scanner, RefuseAt::TagRow).await;
    }

    #[tokio::test]
    async fn manual_quarantine_of_the_digest_row_survives_the_move_5457() {
        rejection_follows_the_digest(Refusal::Manual, RefuseAt::DigestRow).await;
    }

    #[tokio::test]
    async fn scanner_rejection_of_the_digest_row_survives_the_move_5457() {
        rejection_follows_the_digest(Refusal::Scanner, RefuseAt::DigestRow).await;
    }

    #[tokio::test]
    async fn manual_quarantine_after_the_move_refuses_d1_5457() {
        rejection_follows_the_digest(Refusal::Manual, RefuseAt::DigestRowAfterMove).await;
    }

    #[tokio::test]
    async fn scanner_rejection_after_the_move_refuses_d1_5457() {
        rejection_follows_the_digest(Refusal::Scanner, RefuseAt::DigestRowAfterMove).await;
    }

    /// A digest no stored manifest has, for row-level cases.
    fn row_digest() -> String {
        format!(
            "sha256:{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        )
    }

    /// #5457 without an MCP pin: a tag push writes no digest-path row, so the
    /// hold of a moved tag's row is carried onto a new one and D1 stays
    /// refused by digest. A weaker hold carried later never downgrades it,
    /// and a re-push of the same bytes keeps the row's own hold.
    #[tokio::test]
    async fn moved_tag_hold_is_carried_without_a_pin_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("solo").await;
        let tag_row = rig.row_id("1.0").await;
        rig.refuse(tag_row, Refusal::Scanner).await;
        assert_eq!(rig.rows_of(&d1).await.len(), 1, "no digest-path row yet");
        let d2 = rig.push("solo-next").await;
        let digest_path = |d: &str| format!("v2/{ALIAS_IMAGE}/manifests/{d}");
        assert_eq!(
            rig.rows_of(&d1).await,
            vec![(digest_path(&d1), Some("rejected".to_string()))]
        );
        assert_eq!(
            rig.native(&rig.docker.key, &d1).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(rig.native(&rig.docker.key, "1.0").await, StatusCode::OK);

        // A live timed hold on the tag row (now D2); a re-push of the same
        // bytes keeps it; the row then moves back to D1: the hold goes to a
        // new D2 digest-path row, D1's rejection is not downgraded.
        rig.set_hold("1.0", "quarantined", "NOW() + INTERVAL '1 hour'", "upload")
            .await;
        for (digest, held) in [(&d2, "1.0".to_string()), (&d1, d2.clone())] {
            rig.upsert("1.0", digest).await;
            assert_eq!(
                rig.rows_of(&d2).await,
                vec![(
                    format!("v2/{ALIAS_IMAGE}/manifests/{held}"),
                    Some("quarantined".to_string())
                )]
            );
        }
        assert_eq!(
            rig.rows_of(&d1).await,
            vec![
                (digest_path("1.0"), None),
                (digest_path(&d1), Some("rejected".to_string())),
            ]
        );
        // Both refusals hold by digest, each with its own answer.
        assert_eq!(
            (
                rig.native(&rig.docker.key, &d1).await,
                rig.native(&rig.docker.key, &d2).await
            ),
            (StatusCode::FORBIDDEN, StatusCode::CONFLICT)
        );
        rig.teardown().await;
    }

    /// #5457 review: what a move carries, row by row. A hold that no longer
    /// refuses (an expired timed hold) is not carried; a soft-deleted digest
    /// row is revived with the STRONGER of its own and the carried hold; a
    /// release is not undone by a carried timed hold; a manifest migrated
    /// under a content-addressed storage key is carried by its checksum.
    #[tokio::test]
    async fn the_carry_keeps_the_stronger_hold_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let live = "NOW() + INTERVAL '1 hour'";
        // Expired timed hold: nothing to carry.
        let (d1, d2) = (row_digest(), row_digest());
        rig.upsert("expired", &d1).await;
        rig.set_hold(
            "expired",
            "quarantined",
            "NOW() - INTERVAL '1 minute'",
            "upload",
        )
        .await;
        rig.upsert("expired", &d2).await;
        assert_eq!(rig.hold_at(&d1).await, None, "no row for an expired hold");

        // Soft-deleted rejected digest row + a live timed hold on the tag:
        // revived, still rejected.
        let (d1, d2) = (row_digest(), row_digest());
        rig.upsert(&d1, &d1).await;
        rig.set_hold(&d1, "rejected", "NULL", "admin").await;
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
        )
        .bind(rig.docker.id)
        .bind(format!("v2/{ALIAS_IMAGE}/manifests/{d1}"))
        .execute(&rig.env.fx.pool)
        .await
        .unwrap();
        rig.upsert("deleted", &d1).await;
        rig.set_hold("deleted", "quarantined", live, "upload").await;
        rig.upsert("deleted", &d2).await;
        assert_eq!(
            rig.hold_at(&d1).await,
            Some((Some("rejected".into()), false, Some("admin".into()), false))
        );

        // An administrator's release outranks a carried timed hold; a
        // carried permanent quarantine outranks the release.
        for (hold, until, expected) in [
            ("quarantined", live, Some(("released", false))),
            ("quarantined", "NULL", Some(("quarantined", false))),
        ] {
            let (d1, d2) = (row_digest(), row_digest());
            rig.upsert(&d1, &d1).await;
            rig.set_hold(&d1, "released", "NULL", "admin").await;
            rig.upsert("released", &d1).await;
            rig.set_hold("released", hold, until, "admin").await;
            rig.upsert("released", &d2).await;
            let got = rig.hold_at(&d1).await.unwrap();
            assert_eq!(
                got.0.as_deref().map(|s| (s, got.1)),
                expected,
                "{hold} until {until}"
            );
        }

        // A migrated row with a content-addressed key is carried by checksum.
        let (d1, d2) = (row_digest(), row_digest());
        rig.upsert("migrated", &d1).await;
        sqlx::query("UPDATE artifacts SET storage_key = 'cas/ab/cd/abcd' WHERE repository_id = $1 AND path = $2")
            .bind(rig.docker.id)
            .bind(format!("v2/{ALIAS_IMAGE}/manifests/migrated"))
            .execute(&rig.env.fx.pool)
            .await
            .unwrap();
        rig.set_hold("migrated", "rejected", "NULL", "admin").await;
        rig.upsert("migrated", &d2).await;
        assert_eq!(
            rig.hold_at(&d1).await,
            Some((Some("rejected".into()), false, Some("admin".into()), false))
        );
        rig.teardown().await;
    }

    /// #5457 review: a scan-policy hold (written as the scanner writes it)
    /// carried by a tag move is recorded as an administrator's, so the
    /// acknowledgement release, which passes a row with no scan of its own,
    /// cannot lift it; D1 stays refused.
    #[tokio::test]
    async fn a_carried_scan_policy_hold_is_not_released_by_an_acknowledgement_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("scan").await;
        let tag_row = rig.row_id("1.0").await;
        // The scanner's policy-violation write (scanner_service).
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NULL, \
             quarantine_reason = 'max_severity exceeded', \
             quarantine_source = CASE WHEN quarantine_status = 'quarantined' \
                                           AND quarantine_until IS NULL \
                                      THEN quarantine_source ELSE 'scan_policy' END \
             WHERE id = $1 AND quarantine_status IS DISTINCT FROM 'rejected'",
        )
        .bind(tag_row)
        .execute(&rig.env.fx.pool)
        .await
        .unwrap();
        rig.push("scan-next").await;
        assert_eq!(
            rig.hold_at(&d1).await,
            Some((
                Some("quarantined".into()),
                false,
                Some("admin".into()),
                false
            ))
        );
        let carried = rig.row_id(&d1).await;
        assert!(
            !crate::services::quarantine_service::release_cleared_scan_policy_hold(
                &rig.env.fx.pool,
                carried,
                None,
                "acknowledgement"
            )
            .await
            .unwrap(),
            "the acknowledgement release must not lift the carried hold"
        );
        assert_eq!(rig.native(&rig.docker.key, &d1).await, StatusCode::CONFLICT);
        rig.teardown().await;
    }

    /// #5457 review: the path-addressed reads (the generic download and the
    /// tree content endpoint) gate a manifest with every alias of its digest:
    /// D1's digest path is refused while only its tag row is held, and the
    /// tag path while only its digest row is.
    #[tokio::test]
    async fn path_addressed_reads_gate_every_alias_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("paths").await;
        rig.publish("1.0.0").await;
        // Control: neither read refuses before a hold. (The generic
        // download of a docker repository's manifest answers 502 past the
        // gate here, from its storage read; only the gate is under test.)
        let (download, tree) = rig.path_reads(&d1).await;
        assert!(
            ![StatusCode::CONFLICT, StatusCode::FORBIDDEN].contains(&download)
                && tree == StatusCode::OK,
            "control: {download} {tree}"
        );
        rig.refuse(rig.row_id("1.0").await, Refusal::Manual).await;
        assert_eq!(
            rig.path_reads(&d1).await,
            (StatusCode::CONFLICT, StatusCode::CONFLICT),
            "digest path, tag row held"
        );
        rig.set_hold("1.0", "released", "NULL", "admin").await;
        rig.refuse(rig.row_id(&d1).await, Refusal::Scanner).await;
        assert_eq!(
            rig.path_reads("1.0").await,
            (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
            "tag path, digest row rejected"
        );
        rig.teardown().await;
    }

    /// #5457 review: with the upload-time quarantine on, D2 gets its own
    /// timed upload hold on the rewritten tag row, not D1's rejection, and
    /// D1's rejection moves to its digest-path row.
    #[tokio::test]
    async fn with_upload_holds_d2_gets_its_own_timed_hold_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             VALUES ($1, 'quarantine_enabled', 'true'), ($1, 'quarantine_duration_minutes', '60')",
        )
        .bind(rig.docker.id)
        .execute(&rig.env.fx.pool)
        .await
        .unwrap();
        crate::services::quarantine_service::invalidate_config_cache(rig.docker.id);
        let d1 = rig.push("held").await;
        assert_eq!(
            rig.hold_at("1.0").await,
            Some((
                Some("quarantined".into()),
                true,
                Some("upload".into()),
                false
            )),
            "control: the push is held"
        );
        rig.refuse(rig.row_id("1.0").await, Refusal::Scanner).await;
        let d2 = rig.push("held-next").await;
        assert_eq!(
            rig.hold_at("1.0").await,
            Some((
                Some("quarantined".into()),
                true,
                Some("upload".into()),
                false
            )),
            "D2's own upload hold"
        );
        assert_eq!(
            rig.hold_at(&d1).await.map(|h| h.0),
            Some(Some("rejected".into()))
        );
        assert_eq!(
            (
                rig.native(&rig.docker.key, &d1).await,
                rig.native(&rig.docker.key, &d2).await
            ),
            (StatusCode::FORBIDDEN, StatusCode::CONFLICT)
        );
        crate::services::quarantine_service::invalidate_config_cache(rig.docker.id);
        rig.teardown().await;
    }

    /// #5457 review: two concurrent pushes moving a rejected tag both
    /// commit, and D1's rejection survives on its digest-path row whichever
    /// lands first.
    #[tokio::test]
    async fn concurrent_tag_moves_keep_the_rejection_5457() {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("race").await;
        rig.refuse(rig.row_id("1.0").await, Refusal::Scanner).await;
        let (d2, d3) = tokio::join!(rig.push("race-a"), rig.push("race-b"));
        assert_ne!(d2, d3);
        assert_eq!(
            rig.rows_of(&d1).await,
            vec![(
                format!("v2/{ALIAS_IMAGE}/manifests/{d1}"),
                Some("rejected".to_string())
            )]
        );
        assert_eq!(
            rig.native(&rig.docker.key, &d1).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(rig.native(&rig.docker.key, "1.0").await, StatusCode::OK);
        rig.teardown().await;
    }

    /// #5618: an administrator's hold on the tag row that commits while a
    /// push moving the tag waits for that row's lock is carried to D1, not
    /// cleared with the rewrite. The interleaving is forced: the hold's
    /// UPDATE (the statement `quarantine_now` or the reject runs) is held
    /// open in a transaction, the push starts and is observed blocked on
    /// that transaction (`pg_blocking_pids`), and only then does the hold
    /// commit. The push's statement therefore started before the hold was
    /// visible and decides the carry after it committed.
    async fn hold_committed_during_a_tag_move_is_carried(how: Refusal) {
        let Some(rig) = AliasRig::new().await else {
            return;
        };
        let d1 = rig.push("inflight").await;
        rig.publish("1.0.0").await;
        let tag_row = rig.row_id("1.0").await;
        let pool = &rig.env.fx.pool;

        let status = match how {
            Refusal::Manual => "quarantined",
            Refusal::Scanner => "rejected",
        };
        let mut admin = pool.begin().await.unwrap();
        let admin_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *admin)
            .await
            .unwrap();
        let held = sqlx::query(
            "UPDATE artifacts SET quarantine_status = $2, quarantine_until = NULL, \
             quarantine_reason = 'admin hold', quarantine_source = 'admin' \
             WHERE id = $1 AND is_deleted = false",
        )
        .bind(tag_row)
        .bind(status)
        .execute(&mut *admin)
        .await
        .unwrap();
        assert_eq!(held.rows_affected(), 1);

        let commit_once_blocked = async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut blocked = false;
            while std::time::Instant::now() < deadline {
                blocked = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                     WHERE $1 = ANY(pg_blocking_pids(pid)))",
                )
                .bind(admin_pid)
                .fetch_one(pool)
                .await
                .unwrap();
                if blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            admin.commit().await.unwrap();
            blocked
        };
        let (d2, blocked) = tokio::join!(rig.push("inflight-next"), commit_once_blocked);
        assert!(
            blocked,
            "precondition: the push waited on the uncommitted hold"
        );
        assert_ne!(d1, d2);

        // D1 is refused by digest (native hosted and Virtual) and through the
        // MCP version pinned to it; D2 is served under the moved tag.
        rig.assert_refused(&d1, how, "after the in-flight move")
            .await;
        assert_eq!(
            rig.rows_of(&d1).await,
            vec![(
                format!("v2/{ALIAS_IMAGE}/manifests/{d1}"),
                Some(status.to_string())
            )],
            "the hold committed during the move is on D1's digest row"
        );
        for (key, reference) in [
            (&rig.docker.key, "1.0"),
            (&rig.docker.key, d2.as_str()),
            (&rig.oci_virtual.key, "1.0"),
        ] {
            assert_eq!(
                rig.native(key, reference).await,
                StatusCode::OK,
                "D2 is served: {key} {reference}"
            );
        }
        let d1_rows = crate::services::oci_manifests::alias_rows(pool, rig.docker.id, &[&d1])
            .await
            .unwrap();
        assert!(
            d1_rows
                .iter()
                .all(|r| r.quarantine_status.as_deref() == Some(status)),
            "every alias of D1 is held: {d1_rows:?}"
        );
        rig.teardown().await;
    }

    #[tokio::test]
    async fn quarantine_committed_during_a_tag_move_is_carried_5618() {
        hold_committed_during_a_tag_move_is_carried(Refusal::Manual).await;
    }

    #[tokio::test]
    async fn rejection_committed_during_a_tag_move_is_carried_5618() {
        hold_committed_during_a_tag_move_is_carried(Refusal::Scanner).await;
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

    /// #5253: `/api/v1/packages` rows of an MCP registry follow the serve
    /// decision. A reader (anonymous on a public registry) is shown the
    /// server's newest servable version, never the held one's version or
    /// description, and no row for a server with nothing servable (also not
    /// by id); `/versions` lists only servable versions. A holder keeps the
    /// stored row, flagged `servable: false`.
    #[tokio::test]
    async fn catalog_rows_follow_the_serve_decision() {
        let Some(env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let with_desc = |name: &str, v: &str, desc: &str| {
            let mut d = doc(name, v, serde_json::json!({}));
            d["description"] = desc.into();
            d
        };
        for (name, v, desc) in [
            ("com.acme/held", "1.0.0", "One"),
            ("com.acme/held", "2.0.0", "Two secret"),
            ("com.acme/gone", "1.0.0", "Gone secret"),
        ] {
            let (s, b) = env.publish(&with_desc(name, v, desc)).await;
            assert_eq!(s, StatusCode::OK, "{b}");
        }
        env.hold(
            env.server_artifact("com.acme/held", "2.0.0").await,
            Some("quarantined"),
        )
        .await;
        env.hold(
            env.server_artifact("com.acme/gone", "1.0.0").await,
            Some("quarantined"),
        )
        .await;
        let packages = |app: Router, uri: String| async move {
            let (s, b, _) = call(app, "GET", &uri, None).await;
            assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            json(&b)
        };
        let list = format!("/?repository_key={}", env.fx.repo_key);
        let api = || crate::api::handlers::packages::router();
        let anon = packages(env.fx.router_anon(api()), list.clone()).await;
        let rows: Vec<(String, String, String, bool)> = anon["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["name"].as_str().unwrap().to_string(),
                    r["version"].as_str().unwrap().to_string(),
                    r["description"].as_str().unwrap_or_default().to_string(),
                    r["metadata"]["servable"].as_bool().unwrap_or(false),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [(
                "com.acme/held".to_string(),
                "1.0.0".to_string(),
                "One".to_string(),
                true
            )],
            "{anon}"
        );
        assert_eq!(anon["items"][0]["metadata"]["version"], "1.0.0");
        assert_eq!(anon["pagination"]["total"], 1, "{anon}");
        assert!(!anon.to_string().contains("secret"), "{anon}");
        let member = packages(env.member_router(api()), list).await;
        let mut seen: Vec<(String, String, bool)> = member["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["name"].as_str().unwrap().to_string(),
                    r["version"].as_str().unwrap().to_string(),
                    r["metadata"]["servable"].as_bool().unwrap(),
                )
            })
            .collect();
        seen.sort();
        // (`com.acme/gone`, whose only version is quarantined, is not a live
        // catalog row for anyone: `live_package_predicate`.)
        assert_eq!(
            seen,
            [("com.acme/held".to_string(), "2.0.0".to_string(), false)]
        );
        let id_of = |name: &str| {
            let pool = env.fx.pool.clone();
            let repo = env.fx.repo_id;
            let name = name.to_string();
            async move {
                let id: Uuid = sqlx::query_scalar(
                    "SELECT id FROM packages WHERE repository_id = $1 AND name = $2",
                )
                .bind(repo)
                .bind(name)
                .fetch_one(&pool)
                .await
                .unwrap();
                id.to_string()
            }
        };
        let (s, _, _) = call(
            env.fx.router_anon(api()),
            "GET",
            &format!("/{}", id_of("com.acme/gone").await),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let versions = packages(
            env.fx.router_anon(api()),
            format!("/{}/versions", id_of("com.acme/held").await),
        )
        .await;
        assert!(!versions.to_string().contains("2.0.0"), "{versions}");
        env.teardown().await;
    }

    /// S4 (#5253): a pin matches exactly what the backing format's download
    /// route serves for the identifier and version a client requests, and
    /// nothing wider. Cargo: case-insensitive, but `foo-bar` is not
    /// `foo_bar`. NuGet: case-insensitive id, the normalised lowercase version
    /// a V3 client requests, compared exactly with the stored version (so
    /// `1.0` pins the row stored as `1.0.0`, never the one stored as `1.0`).
    #[tokio::test]
    async fn pins_match_what_the_download_route_serves() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let cargo = env.repo("local", "cargo").await;
        let nuget = env.repo("local", "nuget").await;
        let seed =
            |repo: RepoInfo, path: &'static str, name: &'static str, v: &'static str, sha: char| {
                let state = env.fx.state.clone();
                let pool = env.fx.pool.clone();
                let user = env.fx.user_id;
                async move {
                    tdh::seed_artifact_with_checksum(
                        &state,
                        &pool,
                        &repo,
                        &format!("s4/{path}"),
                        path,
                        name,
                        v,
                        "application/octet-stream",
                        Bytes::from_static(b"pkg"),
                        user,
                        &sha.to_string().repeat(64),
                    )
                    .await
                }
            };
        seed(
            cargo.clone(),
            "crates/foo_bar/1.0.0.crate",
            "foo_bar",
            "1.0.0",
            'a',
        )
        .await;
        seed(nuget.clone(), "x/1.0/x.1.0.nupkg", "x", "1.0", 'b').await;
        seed(nuget.clone(), "x/1.0.0/x.1.0.0.nupkg", "x", "1.0.0", 'c').await;
        seed(
            nuget.clone(),
            "y/1.0.0-Beta/y.1.0.0-Beta.nupkg",
            "y",
            "1.0.0-Beta",
            'd',
        )
        .await;
        env.config(
            mcp_packages::REPOS_KEY,
            &serde_json::json!({"cargo": cargo.key, "nuget": nuget.key}).to_string(),
        )
        .await;
        let publish =
            |server: &'static str, ty: &'static str, id: &'static str, v: &'static str| {
                doc(
                    server,
                    "1.0.0",
                    serde_json::json!({"packages": [{"registryType": ty, "identifier": id,
                    "version": v, "transport": {"type": "stdio"}}]}),
                )
            };
        let pinned = |server: &'static str| {
            let pool = env.fx.pool.clone();
            let repo = env.fx.repo_id;
            async move {
                let sha: Option<String> = sqlx::query_scalar(
                    "SELECT m.metadata#>>'{packages,0,resolved,sha256}' FROM artifacts a \
                     JOIN artifact_metadata m ON m.artifact_id = a.id \
                     WHERE a.repository_id = $1 AND a.name = $2",
                )
                .bind(repo)
                .bind(server)
                .fetch_one(&pool)
                .await
                .unwrap();
                sha.unwrap_or_default()
            }
        };
        // Cargo: another crate behind a `-`/`_` swap is not pinned.
        let (s, b) = env
            .publish(&publish("com.acme/c1", "cargo", "foo-bar", "1.0.0"))
            .await;
        assert_eq!(
            (s, b["error"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("mcp_package_not_found")
            ),
            "{b}"
        );
        let (s, b) = env
            .publish(&publish("com.acme/c2", "cargo", "Foo_Bar", "1.0.0"))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(pinned("com.acme/c2").await, "a".repeat(64));
        // NuGet: `1.0` is requested as `1.0.0`; the `1.0.0` row is pinned.
        let (s, b) = env
            .publish(&publish("com.acme/n1", "nuget", "X", "1.0"))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(pinned("com.acme/n1").await, "c".repeat(64));
        // A row stored as `1.0.0-Beta` is never served for `1.0.0-beta`.
        let (s, b) = env
            .publish(&publish("com.acme/n2", "nuget", "y", "1.0.0-beta"))
            .await;
        assert_eq!(
            (s, b["error"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("mcp_package_not_found")
            ),
            "{b}"
        );
        env.teardown().await;
    }

    /// #5253 existence oracle: a publisher with MCP write but no read on the
    /// mapped backing repository gets the same `422 mcp_package_not_found`
    /// for a package that exists there and for one that does not, and
    /// nothing is stored. With read the answers are the precise ones again.
    #[tokio::test]
    async fn unreadable_backing_package_answers_like_a_missing_one() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (npm, _) = env.npm_backing(&["1.0.0"]).await;
        let pkg = |v: &str| {
            doc(
                "com.acme/echo",
                "1.0.0",
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            )
        };
        sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1 AND user_id = $2")
            .bind(npm.id)
            .bind(env.fx.user_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let (s_there, there) = env.publish(&pkg("1.0.0")).await;
        let (s_missing, missing) = env.publish(&pkg("9.9.9")).await;
        assert_eq!(
            (s_there, there["error"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("mcp_package_not_found")
            ),
            "an existing package in an unreadable repository: {there}"
        );
        assert_eq!(s_missing, s_there);
        assert_eq!(
            there.to_string().replace("1.0.0", "V"),
            missing
                .to_string()
                .replace("9.9.9", "V")
                .replace("1.0.0", "V"),
            "existing and missing answer alike"
        );
        assert!(!there.to_string().contains(&npm.key), "{there}");
        let stored: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(env.fx.repo_id)
                .fetch_one(&env.fx.pool)
                .await
                .unwrap();
        assert_eq!(stored, 0);
        // With read: the missing package names the repository, the
        // existing one publishes.
        tdh::grant_repo_role(&env.fx.pool, npm.id, env.fx.user_id, "reader").await;
        let (s, b) = env.publish(&pkg("9.9.9")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(b.to_string().contains(&npm.key), "{b}");
        let (s, b) = env.publish(&pkg("1.0.0")).await;
        assert_eq!(s, StatusCode::OK, "{b}");
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
    /// bypass validation, namespace policy and pinning); a peer replication
    /// under an administrator's token still lands.
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
        // #5368: a service account is not a peer (the header is client-set).
        let mut service_account = user.clone();
        service_account.is_service_account = true;
        assert!(reject_generic_write_to_mcp(
            &RepositoryFormat::Mcp,
            &service_account,
            &replication
        )
        .is_err());
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Mcp, &admin, &replication).is_ok());
        assert!(reject_generic_write_to_mcp(&RepositoryFormat::Npm, &user, &plain).is_ok());
        assert!(reject_generic_write_to_mcp(
            &RepositoryFormat::Npm,
            &service_account,
            &replication
        )
        .is_ok());
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

    /// D3: behind an instance CORS layer with credentials (the development
    /// configuration in `main.rs`), a read answer is still any-origin
    /// without credentials; other paths keep the instance policy.
    #[tokio::test]
    async fn read_routes_never_allow_credentials() {
        let instance = CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::predicate(|_, _| true))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::AUTHORIZATION])
            .allow_credentials(true);
        let read = Router::new()
            .route("/mcp/r/v0.1/servers", get(|| async { "ok" }))
            .route(
                "/mcp/r/v0.1/servers/x/versions",
                get(|| async { not_found() }),
            )
            .layer(read_cors());
        let app = read
            .route("/api/v1/x", get(|| async { "ok" }))
            .layer(instance)
            .layer(axum::middleware::from_fn(mcp_surface_guard));
        let send = |uri: &str| {
            tdh::send_with_headers(
                app.clone(),
                Request::builder()
                    .uri(uri)
                    .header(header::ORIGIN, "https://vscode.dev")
                    .header(header::AUTHORIZATION, "Bearer x")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        for uri in ["/mcp/r/v0.1/servers", "/mcp/r/v0.1/servers/x/versions"] {
            let (_, _, h) = send(uri).await;
            assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*", "{uri}");
            assert!(
                h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none(),
                "{uri}: {h:?}"
            );
        }
        let (_, _, h) = send("/api/v1/x").await;
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://vscode.dev");
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
    }

    /// The event stream applies the serve decision: a reader of a public MCP
    /// registry who does not hold it gets an artifact event only for a
    /// version it is served, and a holder for both.
    #[tokio::test]
    async fn event_stream_follows_the_serve_decision() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let (_npm, ids) = env.npm_backing(&["1.0.0", "2.0.0"]).await;
        for v in ["1.0.0", "2.0.0"] {
            let d = doc(
                "com.acme/events",
                v,
                serde_json::json!({"packages": [npm_pkg("@acme/echo", Some(v))]}),
            );
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        env.hold(ids[1], Some("quarantined")).await;
        let served = env.server_artifact("com.acme/events", "1.0.0").await;
        let held = env.server_artifact("com.acme/events", "2.0.0").await;
        let (reader_id, reader_name) = tdh::create_user(&env.fx.pool).await;
        let event = |id: Uuid| {
            crate::services::event_bus::DomainEvent::now_for_repo(
                "artifact.uploaded",
                id,
                env.fx.repo_id,
                None,
            )
        };
        let admitted = |auth: AuthExtension| {
            let state = env.fx.state.clone();
            async move {
                let mut audience = crate::api::handlers::events::Audience::new(state, auth);
                (
                    audience.admit(event(served)).await.is_some(),
                    audience.admit(event(held)).await.is_some(),
                )
            }
        };
        let reader = admitted(tdh::make_auth(reader_id, &reader_name)).await;
        let holder = admitted(tdh::make_auth(env.fx.user_id, &env.fx.username)).await;
        tdh::cleanup_user(&env.fx.pool, reader_id).await;
        env.teardown().await;
        assert_eq!(reader, (true, false), "a reader: served yes, held no");
        assert_eq!(holder, (true, true), "a holder sees both");
    }

    fn listed_names(b: &serde_json::Value) -> Vec<String> {
        b["servers"]
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
            .collect()
    }

    /// Finding 4: a listing cursor is sealed. It names no row a client can
    /// read (the row may be held), a cursor built by hand is the
    /// `400 invalid cursor`, and a cursor of one repository is refused by
    /// another.
    #[tokio::test]
    async fn listing_cursors_are_sealed_to_their_repository() {
        use base64::Engine as _;
        let Some(mut env) = Env::new().await else {
            return;
        };
        for name in ["com.acme/a", "com.acme/b", "com.acme/c"] {
            assert_eq!(
                env.publish(&doc(name, "1.0.0", serde_json::json!({})))
                    .await
                    .0,
                StatusCode::OK
            );
        }
        let held = env.server_artifact("com.acme/b", "1.0.0").await;
        env.hold(held, Some("quarantined")).await;
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let unseal = |c: &str| {
            String::from_utf8_lossy(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(c)
                    .unwrap(),
            )
            .into_owned()
        };
        for (first, rest) in [
            ("/servers?limit=1", "/servers?limit=1&cursor="),
            (
                "/servers?version=latest&limit=1",
                "/servers?version=latest&limit=1&cursor=",
            ),
        ] {
            let (s, b, _) = env.get(env.member(), first).await;
            let b = json(&b);
            assert_eq!(s, StatusCode::OK, "{b}");
            assert_eq!(listed_names(&b), vec!["com.acme/a@1.0.0"]);
            let c = b["metadata"]["nextCursor"].as_str().unwrap().to_string();
            assert!(!unseal(&c).contains("com.acme"), "{first}: {c}");
            let (s, b, _) = env.get(env.member(), &format!("{rest}{c}")).await;
            let b = json(&b);
            assert_eq!(s, StatusCode::OK, "{b}");
            assert_eq!(listed_names(&b), vec!["com.acme/c@1.0.0"], "{first}");
            // The position a client would make up to resume after (or probe
            // for) a row of its choosing.
            for forged in [b64("com.acme/a:1.0.0"), b64("com.acme/b:-")] {
                let (s, b, _) = env.get(env.member(), &format!("{rest}{forged}")).await;
                assert_eq!(
                    (s, json(&b)["error"].as_str()),
                    (StatusCode::BAD_REQUEST, Some("mcp_invalid_query")),
                    "{first}: {forged}"
                );
            }
            let other = env.repo("local", "mcp").await;
            let (s, _, _) = call(
                env.member(),
                "GET",
                &format!("/{}/v0.1/servers?cursor={c}", other.key),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{first}: replayed elsewhere");
        }
        env.teardown().await;
    }

    /// `n` held copies of the held server.json row `template`, named
    /// `com.acme/held-<from..from+n>` at version 7.7.7.
    async fn held_copies(env: &Env, template: Uuid, from: i32, n: i32) {
        sqlx::query(
            "WITH src AS (SELECT * FROM artifacts WHERE id = $1), \
             made AS ( \
               INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                   checksum_sha256, content_type, storage_key, uploaded_by, origin, \
                   quarantine_status, quarantine_source) \
               SELECT src.repository_id, \
                   'servers/com.acme/held-' || lpad(i::text, 4, '0') || '/7.7.7/server.json', \
                   'com.acme/held-' || lpad(i::text, 4, '0'), src.version, src.size_bytes, \
                   src.checksum_sha256, src.content_type, src.storage_key, src.uploaded_by, \
                   src.origin, 'quarantined', 'admin' \
               FROM src, generate_series($2, $2 + $3 - 1) AS i \
               RETURNING id, name) \
             INSERT INTO artifact_metadata (artifact_id, format, metadata) \
             SELECT made.id, 'mcp', jsonb_set(m.metadata, '{server,name}', to_jsonb(made.name)) \
             FROM made, artifact_metadata m WHERE m.artifact_id = $1",
        )
        .bind(template)
        .bind(from)
        .bind(n)
        .execute(&env.fx.pool)
        .await
        .unwrap();
    }

    /// A public registry with the clean servers `clean` (version 1.0.0) and
    /// `held` held servers `com.acme/held-0000..` (version 7.7.7).
    async fn cursor_fixture(clean: &[&str], held: i32) -> Option<Env> {
        let env = Env::new().await?;
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        env.config(mcp_packages::POLICY_KEY, "open").await;
        let d = doc("com.acme/held-0000", "7.7.7", serde_json::json!({}));
        assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        for name in clean {
            let d = doc(name, "1.0.0", serde_json::json!({}));
            assert_eq!(env.publish(&d).await.0, StatusCode::OK);
        }
        let template = env.server_artifact("com.acme/held-0000", "7.7.7").await;
        env.hold(template, Some("quarantined")).await;
        held_copies(&env, template, 1, held - 1).await;
        Some(env)
    }

    /// Walk the listing `first` (a `limit=1` query) page by page as `app`,
    /// calling `between` with each cursor's id before the next page. Asserts
    /// that no cursor, opened with the instance's seal, names a held server
    /// (`held-`) or version (7.7.7), and that the walk ends. Returns the
    /// entries seen and the number of cursors.
    async fn walk_cursors<F, Fut>(
        env: &Env,
        app: &Router,
        first: &str,
        mut between: F,
    ) -> (Vec<String>, usize)
    where
        F: FnMut(Option<Uuid>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let seal = cursor_seal(&env.fx.state);
        let mut seen = Vec::new();
        let mut tail = first.to_string();
        for cursors in 0..10 {
            let (s, b, _) = env.get(app.clone(), &tail).await;
            let b = json(&b);
            assert_eq!(s, StatusCode::OK, "{tail}: {b}");
            seen.extend(listed_names(&b));
            let Some(c) = b["metadata"]["nextCursor"].as_str() else {
                return (seen, cursors);
            };
            let parts = seal.open(env.fx.repo_id, c).unwrap();
            assert!(
                !parts
                    .iter()
                    .any(|p| p.contains("held") || p.contains("7.7.7")),
                "{first}: the cursor names a held row: {parts:?}"
            );
            // The id of the row the cursor resumes after, if it names one.
            let read = parts.get(3).and_then(|p| Uuid::parse_str(p).ok());
            between(read).await;
            tail = format!("{first}&cursor={c}");
        }
        panic!("{first}: the walk did not end");
    }

    const CURSOR_WALKS: [&str; 2] = ["/servers?limit=1", "/servers?version=latest&limit=1"];

    /// #5453: a cursor never names a row the reader is not served, not even
    /// sealed. More held servers than one request reads (the row bound and
    /// the `latest` budget) sort before the one clean server; a `limit=1`
    /// walk of the raw and the `latest` listing, anonymous and as an
    /// authenticated outsider, reaches the clean server exactly once and
    /// ends, and no cursor of either walk carries a held name or version.
    #[tokio::test]
    async fn listing_cursors_name_no_unserved_row() {
        let n = (MAX_LISTING_ROWS.max(MAX_LATEST_BUDGET) + 1) as i32;
        let Some(env) = cursor_fixture(&["com.acme/zz-clean"], n).await else {
            return;
        };
        let reader = outsider(&env).await;
        for (who, app) in [
            ("anonymous", env.anon()),
            ("outsider", as_caller(&env, &reader, super::router())),
        ] {
            for first in CURSOR_WALKS {
                let (seen, cursors) = walk_cursors(&env, &app, first, |_| async {}).await;
                assert!(cursors >= 1, "{who} {first}: the bound was not reached");
                assert_eq!(seen, vec!["com.acme/zz-clean@1.0.0"], "{who} {first}");
            }
        }
        env.teardown().await;
    }

    /// #5453: held rows at the end of the listing, more than one request
    /// reads: the page after the clean server is the bounded one, its cursor
    /// names no held row, and the walk ends on an empty last page.
    #[tokio::test]
    async fn listing_cursor_past_trailing_held_rows() {
        let n = (MAX_LISTING_ROWS.max(MAX_LATEST_BUDGET) + 1) as i32;
        let Some(env) = cursor_fixture(&["com.acme/aa-clean"], n).await else {
            return;
        };
        for first in CURSOR_WALKS {
            let (seen, cursors) = walk_cursors(&env, &env.anon(), first, |_| async {}).await;
            assert!(cursors >= 1, "{first}: the bound was not reached");
            assert_eq!(seen, vec!["com.acme/aa-clean@1.0.0"], "{first}");
        }
        env.teardown().await;
    }

    /// #5453: rows deleted inside the stretch a cursor skipped (soft-deleted,
    /// and the row the cursor resumes after removed) move nothing: the walk
    /// still returns every visible row after the stretch, once.
    #[tokio::test]
    async fn listing_cursor_survives_deletes_inside_the_stretch() {
        let n = (MAX_LISTING_ROWS.max(MAX_LATEST_BUDGET) + 1) as i32;
        let clean = ["com.acme/aa-first", "com.acme/zz-1", "com.acme/zz-2"];
        let Some(env) = cursor_fixture(&clean, n).await else {
            return;
        };
        let pool = env.fx.pool.clone();
        let repo = env.fx.repo_id;
        for first in CURSOR_WALKS {
            let (seen, cursors) = walk_cursors(&env, &env.anon(), first, |read| {
                let pool = pool.clone();
                async move {
                    // Soft-delete 100 held rows before the resume row, and
                    // remove the resume row itself.
                    sqlx::query(
                        "UPDATE artifact_metadata SET metadata = \
                         jsonb_set(metadata, '{registry,status}', '\"deleted\"') \
                         WHERE artifact_id IN ( \
                           SELECT a.id FROM artifacts a \
                           JOIN artifact_metadata m ON m.artifact_id = a.id \
                           WHERE a.repository_id = $1 AND a.name LIKE 'com.acme/held-%' \
                             AND a.is_deleted = false \
                             AND m.metadata->'registry'->>'status' IS DISTINCT FROM 'deleted' \
                           ORDER BY a.name LIMIT 100)",
                    )
                    .bind(repo)
                    .execute(&pool)
                    .await
                    .unwrap();
                    if let Some(id) = read {
                        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
                            .bind(id)
                            .execute(&pool)
                            .await
                            .unwrap();
                    }
                }
            })
            .await;
            assert!(cursors >= 1, "{first}: the bound was not reached");
            assert_eq!(
                seen,
                vec![
                    "com.acme/aa-first@1.0.0",
                    "com.acme/zz-1@1.0.0",
                    "com.acme/zz-2@1.0.0"
                ],
                "{first}"
            );
            // Restore for the next walk.
            sqlx::query(
                "UPDATE artifact_metadata m SET \
                 metadata = jsonb_set(m.metadata, '{registry,status}', '\"active\"') \
                 FROM artifacts a WHERE a.id = m.artifact_id AND a.repository_id = $1 \
                   AND a.name LIKE 'com.acme/held-%'",
            )
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE artifacts SET is_deleted = false WHERE repository_id = $1 \
                 AND name LIKE 'com.acme/held-%'",
            )
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        }
        env.teardown().await;
    }

    /// Finding 13: `latest` reads the same window on every surface. With the
    /// newest `MAX_LATEST_WALK` versions held, the oldest (servable) version
    /// is not `latest` for the detail read, `isLatest` or `version=latest`.
    #[tokio::test]
    async fn latest_window_is_the_same_on_every_surface() {
        let Some(env) = Env::new().await else { return };
        for i in 0..=MAX_LATEST_WALK {
            let (s, b) = env
                .publish(&doc(
                    "com.acme/many",
                    &format!("1.0.{i}"),
                    serde_json::json!({}),
                ))
                .await;
            assert_eq!(s, StatusCode::OK, "{b}");
        }
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_source = 'admin', \
             quarantine_until = NULL WHERE repository_id = $1 AND name = 'com.acme/many' \
             AND version <> '1.0.0'",
        )
        .bind(env.fx.repo_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fmany/versions/latest")
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{}", json(&b));
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fmany/versions/1.0.0")
            .await;
        let b = json(&b);
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"], false);
        let (s, b, _) = env
            .get(env.member(), "/servers/com.acme%2Fmany/versions")
            .await;
        let b = json(&b);
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(listed_names(&b), vec!["com.acme/many@1.0.0"]);
        assert_eq!(
            b["servers"][0]["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"],
            false
        );
        let (_, b, _) = env.get(env.member(), "/servers").await;
        let b = json(&b);
        assert_eq!(listed_names(&b), vec!["com.acme/many@1.0.0"]);
        assert_eq!(
            b["servers"][0]["_meta"][fmt::OFFICIAL_META_KEY]["isLatest"],
            false
        );
        let (_, b, _) = env.get(env.member(), "/servers?version=latest").await;
        assert!(listed_names(&json(&b)).is_empty(), "{}", json(&b));
        env.teardown().await;
    }

    /// #5396: a miss (unknown name, unknown version, `latest` of an unknown
    /// name) runs the gate-shaped reads a held version's refusal runs before
    /// it answers the unknown-name `404`; a read that has candidates does
    /// not run them again.
    #[tokio::test]
    async fn a_miss_runs_the_gate_shaped_work_of_a_held_read() {
        let Some(env) = Env::new().await else { return };
        assert_eq!(
            env.publish(&doc("com.acme/t", "1.0.0", serde_json::json!({})))
                .await
                .0,
            StatusCode::OK
        );
        let held = env.server_artifact("com.acme/t", "1.0.0").await;
        env.hold(held, Some("quarantined")).await;
        let count = || MISS_SHAPED_WORK.with(|n| n.get());
        let before = count();
        for tail in [
            "/servers/com.acme%2Fnone/versions/1.0.0",
            "/servers/com.acme%2Fnone/versions/latest",
            "/servers/com.acme%2Ft/versions/9.9.9",
        ] {
            let (s, _, _) = env.get(env.member(), tail).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{tail}");
        }
        assert_eq!(count() - before, 3, "every miss ran the gate-shaped work");
        let before = count();
        let (s, _, _) = env
            .get(env.member(), "/servers/com.acme%2Ft/versions/1.0.0")
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(count(), before, "a held read decides its candidate instead");
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #5456: the pin is what the Virtual backing repository's route serves
    // -----------------------------------------------------------------------

    use crate::api::handlers::mcp_shadow_fixtures as sf;

    /// One backing format, spelled as a client spells it.
    struct ShadowCase {
        ty: &'static str,
        name: &'static str,
        /// The version published to the package repository.
        published: &'static str,
        /// The version the server.json names (PyPI: `1.0.0` for a package
        /// published as `1.0`, PEP 440-equal).
        pinned: &'static str,
    }

    const SHADOW_CASES: [ShadowCase; 4] = [
        ShadowCase {
            ty: "npm",
            name: "@acme/echo",
            published: "1.0.0",
            pinned: "1.0.0",
        },
        ShadowCase {
            ty: "pypi",
            name: "Acme_Echo",
            published: "1.0",
            pinned: "1.0.0",
        },
        ShadowCase {
            ty: "nuget",
            name: "Acme.Echo",
            published: "1.0.0",
            pinned: "1.0.0",
        },
        ShadowCase {
            ty: "cargo",
            name: "acme-echo",
            published: "1.0.0",
            pinned: "1.0.0",
        },
    ];

    const SHADOW_TAIL: &str = "/servers/com.acme%2Fshadow/versions/1.0.0";

    /// What the MCP surface says about `com.acme/shadow@1.0.0`.
    #[derive(Debug, PartialEq, Eq)]
    enum View {
        Served,
        /// Held: the holder's `error` and `gate`.
        Held(String, Option<String>),
    }

    fn held(error: &str, gate: Option<&str>) -> View {
        View::Held(error.to_string(), gate.map(str::to_string))
    }

    fn shadowed() -> View {
        held("mcp_unresolvable", Some("shadowed"))
    }

    impl Env {
        /// A Virtual of `ty` with one new member of each `(repo_type,
        /// priority)`, mapped as this registry's `ty` backing repository.
        async fn shadow_virtual(
            &mut self,
            ty: &str,
            members: &[(&str, i32)],
        ) -> (RepoInfo, Vec<RepoInfo>) {
            let virt = self.repo("virtual", ty).await;
            let mut out = Vec::new();
            for (repo_type, priority) in members {
                let m = self.repo(repo_type, ty).await;
                tdh::link_virtual_member(&self.fx.pool, virt.id, m.id, *priority).await;
                out.push(m);
            }
            self.config(
                mcp_packages::REPOS_KEY,
                &serde_json::json!({ ty: virt.key }).to_string(),
            )
            .await;
            (virt, out)
        }

        async fn publish_pkg(
            &self,
            case: &ShadowCase,
            repo: &RepoInfo,
            seed: &[u8],
            file: Option<&str>,
        ) -> sf::PublishedPackage {
            sf::publish_native(
                &self.fx,
                case.ty,
                &repo.key,
                repo.id,
                case.name,
                case.published,
                seed,
                file,
            )
            .await
        }

        async fn publish_shadow_server(
            &self,
            case: &ShadowCase,
        ) -> (StatusCode, serde_json::Value) {
            self.publish(&doc(
                "com.acme/shadow",
                "1.0.0",
                serde_json::json!({"packages": [{"registryType": case.ty,
                    "identifier": case.name, "version": case.pinned,
                    "transport": {"type": "stdio"}}]}),
            ))
            .await
        }

        /// The stored `resolved.sha256`.
        async fn pinned_sha(&self) -> String {
            let id = self.server_artifact("com.acme/shadow", "1.0.0").await;
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT metadata#>>'{packages,0,resolved,sha256}' FROM artifact_metadata \
                 WHERE artifact_id = $1",
            )
            .bind(id)
            .fetch_one(&self.fx.pool)
            .await
            .unwrap()
            .unwrap_or_default()
        }

        async fn native(
            &self,
            case: &ShadowCase,
            virt: &RepoInfo,
            tail: &str,
        ) -> (StatusCode, Option<String>) {
            sf::native_get(&self.fx, case.ty, &format!("/{}{tail}", virt.key)).await
        }

        /// The exact read (anonymous: `200` or the plain `404`; holder: the
        /// refusal's `error` and `gate`) and the listing, which must agree.
        async fn view(&self) -> View {
            let (anon, body, _) = self.get(self.anon(), SHADOW_TAIL).await;
            let (_, list, _) = self.get(self.anon(), "/servers").await;
            let listed = json(&list)["metadata"]["count"].as_i64();
            if anon == StatusCode::OK {
                assert_eq!(listed, Some(1), "served but not listed");
                return View::Served;
            }
            assert_eq!(body.as_ref(), fmt::NOT_FOUND_BODY.as_bytes());
            assert_eq!(listed, Some(0), "held but listed");
            let (_, held, _) = self.get(self.member(), SHADOW_TAIL).await;
            let held = json(&held);
            let text = |k: &str| held[k].as_str().map(str::to_string);
            View::Held(text("error").unwrap_or_default(), text("gate"))
        }

        async fn soft_delete(&self, ids: &[Uuid]) {
            sqlx::query("UPDATE artifacts SET is_deleted = $2 WHERE id = ANY($1)")
                .bind(ids)
                .bind(true)
                .execute(&self.fx.pool)
                .await
                .unwrap();
        }

        /// A Remote member of `virt` at `priority` whose upstream serves
        /// `case` with the bytes `body`.
        async fn upstream_member(
            &mut self,
            case: &ShadowCase,
            virt: &RepoInfo,
            priority: i32,
            body: &[u8],
        ) -> (Uuid, String, sf::MockUpstream) {
            let (id, key, dir) = tdh::attach_remote_member(
                &self.fx.pool,
                virt.id,
                case.ty,
                "http://unset",
                priority,
            )
            .await;
            self.extra_repos.push((id, dir));
            tdh::grant_repo_role(&self.fx.pool, id, self.fx.user_id, "reader").await;
            let up =
                sf::mock_upstream(&self.fx, case.ty, id, case.name, case.published, body, None)
                    .await;
            (id, key, up)
        }
    }

    /// #5456: bytes B published later at the pinned coordinate in a member
    /// that outranks the pinned one change what the advertised Virtual URL
    /// delivers, so the version is held (`gate: shadowed`) instead of served
    /// with a pin and a gate that no longer describe the download. Removing B
    /// serves it again, still pinned to (and delivering) A. Every package is
    /// published through its format's real upload route.
    #[tokio::test]
    async fn late_virtual_shadowing_holds_the_version_5456() {
        for case in &SHADOW_CASES {
            let ty = case.ty;
            let Some(mut env) = Env::new().await else {
                return;
            };
            let (virt, m) = env.shadow_virtual(ty, &[("local", 1), ("local", 2)]).await;
            let a = env.publish_pkg(case, &m[1], b"approved A", None).await;
            let (s, b) = env.publish_shadow_server(case).await;
            assert_eq!(s, StatusCode::OK, "{ty}: {b}");
            assert_eq!(
                b["server"]["packages"][0]["registryBaseUrl"],
                mcp_packages::backing_base_url("http://localhost", ty, &virt.key),
                "{ty}: the advertised URL is the Virtual"
            );
            assert_eq!(env.pinned_sha().await, a.sha256, "{ty}");
            assert_eq!(env.view().await, View::Served, "{ty}");
            assert_eq!(
                env.native(case, &virt, &a.download_tail).await,
                (StatusCode::OK, Some(a.sha256.clone())),
                "{ty}: before shadowing the advertised URL delivers the pin"
            );

            let b = env.publish_pkg(case, &m[0], b"shadowing B", None).await;
            assert_eq!(
                env.native(case, &virt, &a.download_tail).await,
                (StatusCode::OK, Some(b.sha256.clone())),
                "{ty}: the Virtual now serves H (unchanged for non-MCP clients)"
            );
            assert_eq!(
                env.pinned_sha().await,
                a.sha256,
                "{ty}: the pin never moves"
            );
            assert_eq!(env.view().await, shadowed(), "{ty}");

            env.soft_delete(&b.artifact_ids).await;
            assert_eq!(env.view().await, View::Served, "{ty}");
            assert_eq!(
                env.native(case, &virt, &a.download_tail).await,
                (StatusCode::OK, Some(a.sha256.clone())),
                "{ty}: served again, and the download is A again"
            );
            env.teardown().await;
        }
    }

    /// #5456 quarantine orders, each in a clean fixture: the MCP read and the
    /// advertised native download agree on every order.
    #[tokio::test]
    async fn virtual_shadowing_quarantine_orders_agree_5456() {
        for case in &SHADOW_CASES {
            let ty = case.ty;
            for order in ["a", "b-then-a", "b"] {
                let Some(mut env) = Env::new().await else {
                    return;
                };
                let (virt, m) = env.shadow_virtual(ty, &[("local", 1), ("local", 2)]).await;
                let a = env.publish_pkg(case, &m[1], b"approved A", None).await;
                assert_eq!(
                    env.publish_shadow_server(case).await.0,
                    StatusCode::OK,
                    "{ty}"
                );
                let b = match order {
                    "a" => None,
                    _ => Some(env.publish_pkg(case, &m[0], b"shadowing B", None).await),
                };
                let target = match &b {
                    Some(b) if order == "b" => b.artifact_ids[0],
                    _ => a.artifact_ids[0],
                };
                env.hold(target, Some("quarantined")).await;
                let (native, delivered) = env.native(case, &virt, &a.download_tail).await;
                let label = format!("{ty} {order}");
                match (order, &b) {
                    // A quarantined, nothing shadows it: both refuse A.
                    ("a", _) => {
                        assert_eq!(
                            env.view().await,
                            held("mcp_backing_artifact_blocked", Some("quarantine")),
                            "{label}"
                        );
                        assert_ne!(native, StatusCode::OK, "{label}");
                    }
                    // Shadowed, then A quarantined: the Virtual serves B to
                    // every client; the approved document is never served.
                    ("b-then-a", Some(b)) => {
                        assert_eq!(env.view().await, shadowed(), "{label}");
                        assert_eq!(delivered.as_deref(), Some(b.sha256.as_str()), "{label}");
                    }
                    // B quarantined: the Virtual refuses the coordinate (it
                    // does not fall through to A, #3220), and so does MCP.
                    _ => {
                        assert_eq!(env.view().await, shadowed(), "{label}");
                        assert_ne!(native, StatusCode::OK, "{label}");
                    }
                }
                env.teardown().await;
            }
        }
    }

    /// #5456: a Remote member ranked above the hosted package serves the
    /// version from its upstream whether or not it has cached it. npm and
    /// NuGet refuse such a publish, and hold an approved version once such a
    /// member appears (the download then returns the upstream's bytes);
    /// PyPI refuses any Remote member; Cargo's exact-version owner guard
    /// withholds every Remote member, so the pin stands.
    #[tokio::test]
    async fn higher_ranked_remote_shadows_even_uncached_5456() {
        for case in &SHADOW_CASES {
            let ty = case.ty;
            let Some(mut env) = Env::new().await else {
                return;
            };
            let (virt, m) = env.shadow_virtual(ty, &[("local", 2)]).await;
            let a = env.publish_pkg(case, &m[0], b"approved A", None).await;
            let (_, remote_key, up) = env.upstream_member(case, &virt, 1, b"upstream B").await;
            let (s, b) = env.publish_shadow_server(case).await;
            if ty == "cargo" {
                assert_eq!(s, StatusCode::OK, "{b}");
                assert_eq!(env.view().await, View::Served);
                assert_eq!(
                    sf::native_get_with_state(
                        &up.state,
                        &env.fx,
                        ty,
                        &format!("/{}{}", virt.key, a.download_tail)
                    )
                    .await,
                    (StatusCode::OK, Some(a.sha256.clone())),
                    "cargo: the owner guard serves the hosted crate"
                );
            } else {
                assert_eq!(
                    (s, b["error"].as_str()),
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Some("mcp_package_shadowed")
                    ),
                    "{ty}: {b}"
                );
                let detail = b["detail"].as_str().unwrap_or_default();
                assert!(
                    detail.contains(&remote_key) && detail.contains(&m[0].key),
                    "{ty}: {detail}"
                );
            }
            env.teardown().await;
            // The mock upstream holds the process-wide SSRF allowlist lock
            // (`non_loopback_mock_server`), which is not reentrant: release
            // it before the next mock upstream is started below.
            drop(up);

            // Late: approved first, then the Remote member joins above.
            if ty == "cargo" {
                continue;
            }
            let Some(mut env) = Env::new().await else {
                return;
            };
            let (virt, m) = env.shadow_virtual(ty, &[("local", 2)]).await;
            let a = env.publish_pkg(case, &m[0], b"approved A", None).await;
            assert_eq!(
                env.publish_shadow_server(case).await.0,
                StatusCode::OK,
                "{ty}"
            );
            assert_eq!(env.view().await, View::Served, "{ty}");
            let (remote, _, up) = env.upstream_member(case, &virt, 1, b"upstream B").await;
            assert_eq!(
                env.view().await,
                shadowed(),
                "{ty}: held with nothing cached"
            );
            let got = sf::native_get_with_state(
                &up.state,
                &env.fx,
                ty,
                &format!("/{}{}", virt.key, a.download_tail),
            )
            .await;
            if ty == "pypi" {
                // The PEP 708 guard serves the hosted sdist itself; PyPI is
                // held for the other distributions the Remote can serve.
                assert_eq!(got.0, StatusCode::OK, "{ty}");
            } else {
                assert_eq!(
                    got,
                    (StatusCode::OK, Some(fmt::sha256_hex(b"upstream B"))),
                    "{ty}: why it is held: the download is the upstream's bytes"
                );
            }

            // The upgrade remedy: rank the hosted member above the Remote
            // (PyPI: remove the Remote). The hold clears on the next read,
            // with no republish.
            let remedy = if ty == "pypi" {
                "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2"
            } else {
                "UPDATE virtual_repo_members SET priority = 0 \
                 WHERE virtual_repo_id = $1 AND member_repo_id <> $2"
            };
            sqlx::query(remedy)
                .bind(virt.id)
                .bind(remote)
                .execute(&env.fx.pool)
                .await
                .unwrap();
            assert_eq!(env.view().await, View::Served, "{ty}: the hold clears");
            env.teardown().await;
        }
    }

    /// #5456: npm isolate mode withholds every Remote member for a hosted
    /// name, so a Remote-first Virtual in isolate mode pins the hosted
    /// package and is not held when the Remote has the name cached.
    #[tokio::test]
    async fn npm_isolate_mode_virtual_is_not_held_5456() {
        let case = &SHADOW_CASES[0];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (virt, m) = env.shadow_virtual("npm", &[("local", 2)]).await;
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, 'true')",
        )
        .bind(virt.id)
        .bind(crate::api::handlers::npm::NPM_VIRTUAL_ISOLATE_HOSTED_NAMES_KEY)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let a = env.publish_pkg(case, &m[0], b"approved A", None).await;
        let (remote, _, up) = env.upstream_member(case, &virt, 1, b"upstream B").await;
        let (s, b) = env.publish_shadow_server(case).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, \
             size_bytes, checksum_sha256) VALUES ($1, '@acme/echo/-/echo-1.0.0.tgz', 'k', 'm', 1, $2)",
        )
        .bind(remote)
        .bind("b".repeat(64))
        .execute(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(env.view().await, View::Served);
        assert_eq!(
            sf::native_get_with_state(
                &up.state,
                &env.fx,
                "npm",
                &format!("/{}{}", virt.key, a.download_tail)
            )
            .await,
            (StatusCode::OK, Some(a.sha256.clone()))
        );
        env.teardown().await;
    }

    /// #5456 Cargo cache pin: a crate pinned from a Remote member's proxy
    /// cache is held once any hosted member of the Virtual publishes the same
    /// `name@version`, whatever its priority: the exact-version owner guard
    /// then serves the hosted crate instead.
    #[tokio::test]
    async fn cargo_cache_pin_held_by_a_later_hosted_publish_5456() {
        let case = &SHADOW_CASES[3];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (virt, m) = env.shadow_virtual("cargo", &[("local", 2)]).await;
        let (remote, _, _up) = env.upstream_member(case, &virt, 1, b"upstream A").await;
        seed_crate_cache(&env.fx.pool, remote).await;
        let (s, b) = env.publish_shadow_server(case).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(env.view().await, View::Served);
        env.publish_pkg(case, &m[0], b"hosted B", None).await;
        assert_eq!(env.view().await, shadowed());
        env.teardown().await;
    }

    /// Seed `remote`'s proxy cache with the case's crate (`acme-echo@1.0.0`).
    async fn seed_crate_cache(pool: &sqlx::PgPool, remote: Uuid) {
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, \
             size_bytes, checksum_sha256) VALUES ($1, 'api/v1/crates/acme-echo/1.0.0/download', \
             'k', 'm', 1, $2)",
        )
        .bind(remote)
        .bind("a".repeat(64))
        .execute(pool)
        .await
        .unwrap();
    }

    /// #5456: the asynchronous fill applies the same cache-pin refusal as the
    /// synchronous publish. A crate the Remote member caches after the publish
    /// was accepted (`202`), while a hosted member of the Virtual now holds
    /// the same `name@version` (so the owner guard serves the hosted crate),
    /// fails the job with `mcp_package_shadowed` instead of resolving into a
    /// version that is held for ever.
    #[tokio::test]
    async fn async_fill_refuses_a_shadowed_cache_pin_5456() {
        let case = &SHADOW_CASES[3];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (virt, m) = env.shadow_virtual("cargo", &[("local", 2)]).await;
        let (remote, _, up) = env.upstream_member(case, &virt, 1, b"upstream A").await;
        let (s, b) = env.publish_shadow_server(case).await;
        assert_eq!(s, StatusCode::ACCEPTED, "nothing cached or hosted yet: {b}");
        let id = env.server_artifact("com.acme/shadow", "1.0.0").await;
        env.publish_pkg(case, &m[0], b"hosted B", None).await;
        seed_crate_cache(&env.fx.pool, remote).await;
        assert!(crate::services::mcp_resolver::run_job(&up.state, id).await);
        let res: serde_json::Value = sqlx::query_scalar(
            "SELECT COALESCE(metadata->'resolution', 'null'::jsonb) FROM artifact_metadata \
             WHERE artifact_id = $1",
        )
        .bind(id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(res["state"], "failed", "{res}");
        assert_eq!(res["error"]["error"], "mcp_package_shadowed", "{res}");
        env.teardown().await;
    }

    /// #5456: a cache pin is bound to the repository its key named. Once the
    /// Virtual is renamed and a non-Virtual repository takes its key, the
    /// advertised URL serves that repository, so the version is held.
    #[tokio::test]
    async fn cache_pin_held_when_its_key_names_another_repository_5456() {
        let case = &SHADOW_CASES[3];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (virt, _) = env.shadow_virtual("cargo", &[("local", 2)]).await;
        let (remote, _, _up) = env.upstream_member(case, &virt, 1, b"upstream A").await;
        seed_crate_cache(&env.fx.pool, remote).await;
        let (s, b) = env.publish_shadow_server(case).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(env.view().await, View::Served);
        let other = env.repo("local", "cargo").await;
        for (id, key) in [
            (virt.id, format!("{}-renamed", virt.key)),
            (other.id, virt.key.clone()),
        ] {
            sqlx::query("UPDATE repositories SET key = $2 WHERE id = $1")
                .bind(id)
                .bind(key)
                .execute(&env.fx.pool)
                .await
                .unwrap();
        }
        assert_eq!(env.view().await, shadowed());
        env.teardown().await;
    }

    /// #5456 PyPI is per file: the pin covers every hosted file of the
    /// version (`1.0` is `1.0.0`), and a file of the version in any member,
    /// a file named for the project but uploaded under another one, or a
    /// pinned file that is gone, holds it.
    #[tokio::test]
    async fn pypi_pin_covers_every_file_of_the_version_5456() {
        let case = &SHADOW_CASES[1];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (_virt, m) = env
            .shadow_virtual("pypi", &[("local", 1), ("local", 2)])
            .await;
        env.publish_pkg(case, &m[0], b"sdist A", None).await;
        let wheel = env
            .publish_pkg(
                case,
                &m[0],
                b"wheel A",
                Some("acme_echo-1.0-py3-none-any.whl"),
            )
            .await;
        let (s, b) = env.publish_shadow_server(case).await;
        assert_eq!(s, StatusCode::OK, "published as 1.0, pinned as 1.0.0: {b}");
        assert_eq!(env.view().await, View::Served);

        // A wheel in the member BELOW the pinned one.
        let below = env
            .publish_pkg(
                case,
                &m[1],
                b"wheel B",
                Some("acme_echo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
            )
            .await;
        assert_eq!(env.view().await, shadowed(), "a member below adds a wheel");
        env.soft_delete(&below.artifact_ids).await;
        assert_eq!(env.view().await, View::Served);

        // A file named for the project, uploaded under another project.
        let other = sf::publish_native(
            &env.fx,
            "pypi",
            &m[1].key,
            m[1].id,
            "zzz",
            "1.0",
            b"zzz",
            Some("acme_echo-1.0.zip"),
        )
        .await;
        assert_eq!(
            env.view().await,
            shadowed(),
            "served for acme-echo's file name"
        );
        env.soft_delete(&other.artifact_ids).await;
        assert_eq!(env.view().await, View::Served);

        // One pinned file gone (the other still gated and served).
        env.soft_delete(&wheel.artifact_ids).await;
        assert_eq!(env.view().await, shadowed(), "a pinned file is gone");
        env.teardown().await;
    }

    /// #5456: the walk the check models is the route's: a nested Virtual's
    /// members are inlined at its slot, and equal priorities are walked by
    /// repository key.
    #[tokio::test]
    async fn nested_virtuals_and_equal_priorities_follow_the_walk_5456() {
        let case = &SHADOW_CASES[0];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (virt, m) = env.shadow_virtual("npm", &[("local", 2)]).await;
        let nested = env.repo("virtual", "npm").await;
        let inner = env.repo("local", "npm").await;
        tdh::link_virtual_member(&env.fx.pool, nested.id, inner.id, 1).await;
        tdh::link_virtual_member(&env.fx.pool, virt.id, nested.id, 1).await;
        env.publish_pkg(case, &m[0], b"approved A", None).await;
        assert_eq!(env.publish_shadow_server(case).await.0, StatusCode::OK);
        assert_eq!(env.view().await, View::Served);
        env.publish_pkg(case, &inner, b"nested B", None).await;
        assert_eq!(env.view().await, shadowed(), "through the nested Virtual");
        env.teardown().await;

        let Some(mut env) = Env::new().await else {
            return;
        };
        let (_virt, mut m) = env
            .shadow_virtual("npm", &[("local", 1), ("local", 1)])
            .await;
        m.sort_by(|x, y| x.key.cmp(&y.key));
        env.publish_pkg(case, &m[1], b"approved A", None).await;
        assert_eq!(env.publish_shadow_server(case).await.0, StatusCode::OK);
        assert_eq!(env.view().await, View::Served);
        env.publish_pkg(case, &m[0], b"equal-priority B", None)
            .await;
        assert_eq!(
            env.view().await,
            shadowed(),
            "the smaller key is walked first"
        );
        env.teardown().await;
    }

    /// #5456: a pinned member that leaves the Virtual leaves nothing to
    /// deliver the pin, and a pinned row whose bytes changed in place is no
    /// longer the pinned row.
    #[tokio::test]
    async fn member_removal_and_in_place_rewrite_hold_the_version_5456() {
        let case = &SHADOW_CASES[2];
        let Some(mut env) = Env::new().await else {
            return;
        };
        let (_virt, m) = env.shadow_virtual("nuget", &[("local", 1)]).await;
        let a = env.publish_pkg(case, &m[0], b"approved A", None).await;
        assert_eq!(env.publish_shadow_server(case).await.0, StatusCode::OK);
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $2 WHERE id = $1")
            .bind(a.artifact_ids[0])
            .bind("f".repeat(64))
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(
            env.view().await,
            held("mcp_unresolvable", None),
            "rewritten in place"
        );
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $2 WHERE id = $1")
            .bind(a.artifact_ids[0])
            .bind(&a.sha256)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(env.view().await, View::Served);
        sqlx::query("DELETE FROM virtual_repo_members WHERE member_repo_id = $1")
            .bind(m[0].id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(env.view().await, shadowed(), "the pinned member left");
        env.teardown().await;
    }
}
