//! Capability snapshots on the MCP surface and the introspection worker API
//! (#5253, Phase 2/3). Exact shapes: `docs/mcp-registry.md`, "Capabilities
//! and introspection".
//!
//! Repository routes (both API versions, both server-name spellings):
//!
//! * `GET  /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities`
//! * `POST /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities`
//!   (CI / gateway report; repository write)
//! * `GET  /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities/diff`
//! * `POST /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities/probe`
//!   (repository admin; queues introspection jobs when settings allow)
//!
//! Worker routes (`/api/v1/mcp/introspection`, an API token carrying the
//! dedicated `mcp:introspect` scope):
//!
//! * `POST /jobs/claim`
//! * `POST /jobs/{id}/complete`
//!
//! Nothing here connects to an MCP server: the worker that does is the
//! separate `ak-mcp-introspector` binary.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::mcp::{self as surface, problem, server_name};
use crate::api::handlers::proxy_helpers::RepoInfo;
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::mcp::{self as fmt, GateAudience, McpError};
use crate::services::mcp_capabilities::{
    self as caps, AuthState, CapabilitySet, NewSnapshot, Outcome, SnapshotRow, Source,
};
use crate::services::mcp_introspection::{self as jobs, JobKind};

/// The dedicated scope of the introspection worker's credential.
pub const INTROSPECT_SCOPE: &str = "mcp:introspect";
/// Nesting cap of an ingest body (JSON Schemas nest).
pub const INGEST_MAX_DEPTH: usize = 64;
/// Default and maximum number of snapshot summaries listed.
pub const DEFAULT_HISTORY: i64 = 50;
pub const MAX_HISTORY: i64 = 200;
/// The spec caveat every capability response carries.
pub const NOTICE: &str = "Capability lists are untrusted. Tools may vary by the authorization \
     presented, annotations are server-asserted, and a declared list is a claim, not an \
     observation. No snapshot marks a server safe.";

type HandlerResult = Result<Response, Response>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The repository routes, merged into `mcp::router()`.
pub fn router() -> Router<SharedState> {
    let mut read = Router::new();
    let mut write = Router::new();
    for v in surface::API_VERSIONS {
        for spelling in ["/servers/:ns/versions/:version", "/servers/:ns/:name/versions/:version"] {
            let p = |tail: &str| format!("/:repo_key/{v}{spelling}/capabilities{tail}");
            read = read
                .route(&p(""), get(get_capabilities))
                .route(&p("/diff"), get(get_diff));
            write = write
                .route(&p(""), post(post_capabilities))
                .route(&p("/probe"), post(post_probe));
        }
    }
    read.layer(surface::read_cors())
        .merge(write.layer(DefaultBodyLimit::max(caps::INGEST_MAX_BYTES)))
}

/// The worker routes, nested at `/api/v1/mcp/introspection` behind
/// `auth_middleware`.
pub fn worker_router() -> Router<SharedState> {
    Router::new()
        .route("/jobs/claim", post(claim_job))
        .route("/jobs/:id/complete", post(complete_job))
        .layer(DefaultBodyLimit::max(caps::INGEST_MAX_BYTES))
}

// ---------------------------------------------------------------------------
// Publish hooks
// ---------------------------------------------------------------------------

/// Validate the declared capabilities block of a document at publish.
pub fn admit_declared(server: &fmt::ServerJson) -> Result<(), McpError> {
    let Some(meta) = &server.meta else {
        return Ok(());
    };
    let block = meta.get(caps::CAPABILITIES_META_KEY).or_else(|| {
        meta.get(fmt::PUBLISHER_META_KEY)?
            .get(caps::CAPABILITIES_META_KEY)
    });
    match block {
        Some(b) => caps::validate_declared_block(b)
            .map(|_| ())
            .map_err(|e| McpError::invalid(e.path, e.message)),
        None => Ok(()),
    }
}

/// After a version is stored: record its declared snapshots and queue the
/// introspection jobs its repository's settings allow. Failures are logged;
/// the publish already succeeded.
pub async fn after_publish(db: &PgPool, artifact_id: Uuid, user_id: Uuid) {
    if let Err(e) = caps::record_declared_snapshot(db, artifact_id).await {
        tracing::warn!(error = %e, %artifact_id, "declared MCP capabilities not recorded");
    }
    if let Err(e) = jobs::enqueue_for_artifact(db, artifact_id, Some(user_id)).await {
        tracing::warn!(error = %e, %artifact_id, "MCP introspection jobs not queued");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json_resp(status: StatusCode, v: &Value) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(v).unwrap_or_default(),
    )
        .into_response()
}

fn bad_request(path: &str, msg: &str) -> Response {
    let detail = if path.is_empty() {
        msg.to_string()
    } else {
        format!("{path}: {msg}")
    };
    problem(400, "mcp_invalid_capabilities", &detail, json!({}))
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "MCP capabilities request failed");
    problem(500, "mcp_internal_error", "internal error", json!({}))
}

fn app_error(e: crate::error::AppError) -> Response {
    use crate::error::AppError;
    match e {
        AppError::Authorization(m) => problem(403, "mcp_forbidden", &m, json!({})),
        AppError::Authentication(m) => problem(401, "mcp_unauthorized", &m, json!({})),
        AppError::ServiceUnavailable(m) => problem(503, "mcp_unavailable", &m, json!({})),
        AppError::NotFound(_) => surface::not_found(),
        other => internal(other),
    }
}

/// The path parameters of either server-name spelling.
struct VersionPath {
    repo_key: String,
    name: String,
    version: String,
}

fn version_path(p: &HashMap<String, String>) -> VersionPath {
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    VersionPath {
        repo_key: get("repo_key"),
        name: server_name(&get("ns"), p.get("name").map(String::as_str)),
        version: get("version"),
    }
}

/// The repository and the visible version a request names.
struct Target {
    repo: RepoInfo,
    artifact_id: Uuid,
    audience: GateAudience,
}

async fn target(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    p: &VersionPath,
    base: &str,
) -> Result<Target, Response> {
    let repo = surface::mcp_repo(&state.db, &p.repo_key).await?;
    let (artifact_id, _, audience) =
        surface::visible_version(state, auth, &repo, &p.name, &p.version, base).await?;
    Ok(Target {
        repo,
        artifact_id,
        audience,
    })
}

fn parse_source(q: &HashMap<String, String>) -> Result<Option<Source>, Response> {
    match q.get("source").map(String::as_str) {
        None | Some("") => Ok(None),
        Some(s) => Source::parse(s)
            .map(Some)
            .ok_or_else(|| bad_request("source", "unknown source")),
    }
}

/// `limit` in `1..=MAX_HISTORY` (default [`DEFAULT_HISTORY`]).
pub fn parse_limit(q: &HashMap<String, String>) -> Result<i64, Response> {
    match q.get("limit") {
        None => Ok(DEFAULT_HISTORY),
        Some(v) => match v.parse::<i64>() {
            Ok(n) if n >= 1 => Ok(n.min(MAX_HISTORY)),
            _ => Err(bad_request("limit", "must be a positive integer")),
        },
    }
}

// ---------------------------------------------------------------------------
// GET .../capabilities
// ---------------------------------------------------------------------------

async fn get_capabilities(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(p): Path<HashMap<String, String>>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let p = version_path(&p);
    let t = target(&state, auth.as_ref(), &p, base.as_str()).await?;
    let source = parse_source(&q)?;
    let limit = parse_limit(&q)?;
    let rows = caps::list_snapshots(&state.db, t.artifact_id, None, MAX_HISTORY)
        .await
        .map_err(internal)?;
    let current = match q.get("snapshot") {
        Some(id) => {
            let id = Uuid::parse_str(id).map_err(|_| bad_request("snapshot", "not a UUID"))?;
            Some(
                rows.iter()
                    .find(|r| r.id == id)
                    .ok_or_else(surface::not_found)?,
            )
        }
        None => caps::pick_current(&rows, source),
    };
    let listed: Vec<Value> = rows
        .iter()
        .filter(|r| source.is_none_or(|s| r.source == s.as_str()))
        .take(limit as usize)
        .map(SnapshotRow::summary_json)
        .collect();
    let modes = jobs::modes(&state.db, t.repo.id).await.map_err(app_error)?;
    let mut introspection = json!({
        "remoteProbe": modes.probe,
        "probeEnabled": modes.probe_enabled(),
        "sandbox": modes.sandbox,
        "sandboxEnabled": modes.sandbox_enabled(),
    });
    // Job state is for the repository's holders, not every reader.
    if t.audience == GateAudience::ReasonGated {
        let list = jobs::list_jobs(&state.db, t.artifact_id, 20)
            .await
            .map_err(app_error)?;
        introspection["jobs"] = Value::Array(list.iter().map(jobs::JobRow::to_json).collect());
    }
    Ok(json_resp(
        StatusCode::OK,
        &json!({
            "repository": t.repo.key,
            "server": p.name,
            "version": p.version,
            "artifactId": t.artifact_id,
            "current": current.map(SnapshotRow::to_json),
            "snapshots": listed,
            "introspection": introspection,
            "notice": NOTICE,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST .../capabilities (CI / gateway report)
// ---------------------------------------------------------------------------

/// A validated report.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub source: Source,
    pub generated_by: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub protocol_version: Option<String>,
    pub auth_state: AuthState,
    pub ttl_ms: Option<i64>,
    pub cache_scope: Option<String>,
    pub set: CapabilitySet,
}

fn opt_string(o: &serde_json::Map<String, Value>, k: &str, max: usize) -> Result<Option<String>, Response> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= max => Ok(Some(s.clone())),
        Some(_) => Err(bad_request(k, &format!("must be a string of at most {max} bytes"))),
    }
}

/// Parse and validate a report body (pure; `now` bounds `observedAt`).
pub fn parse_report(body: &[u8], now: DateTime<Utc>) -> Result<Report, Response> {
    if fmt::json_depth_exceeds(body, INGEST_MAX_DEPTH) {
        return Err(bad_request("", &format!("nesting deeper than {INGEST_MAX_DEPTH}")));
    }
    let doc: Value =
        serde_json::from_slice(body).map_err(|_| bad_request("", "body is not valid JSON"))?;
    let Some(o) = doc.as_object() else {
        return Err(bad_request("", "must be a JSON object"));
    };
    let source = match o.get("source").and_then(|s| s.as_str()).and_then(Source::parse) {
        Some(s) if s.is_reportable() => s,
        _ => {
            return Err(bad_request(
                "source",
                "must be `ci_reported` or `gateway_reported`",
            ))
        }
    };
    let observed_at = match opt_string(o, "observedAt", 64)? {
        None => now,
        Some(s) => {
            let t = DateTime::parse_from_rfc3339(&s)
                .map_err(|_| bad_request("observedAt", "must be an RFC 3339 timestamp"))?
                .with_timezone(&Utc);
            if t > now + chrono::Duration::minutes(5) {
                return Err(bad_request("observedAt", "is in the future"));
            }
            t
        }
    };
    let auth_state = match opt_string(o, "authState", 32)? {
        None => AuthState::Unknown,
        Some(s) => AuthState::parse(&s).ok_or_else(|| bad_request("authState", "unknown value"))?,
    };
    let cache_scope = opt_string(o, "cacheScope", 16)?;
    if cache_scope
        .as_deref()
        .is_some_and(|c| !matches!(c, "public" | "private"))
    {
        return Err(bad_request("cacheScope", "must be `public` or `private`"));
    }
    let ttl_ms = match o.get("ttlMs") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_i64()
                .filter(|n| *n >= 0)
                .ok_or_else(|| bad_request("ttlMs", "must be a non-negative integer"))?,
        ),
    };
    let set = CapabilitySet::from_doc(&doc).map_err(|e| bad_request(&e.path, &e.message))?;
    Ok(Report {
        source,
        generated_by: opt_string(o, "generatedBy", caps::MAX_LABEL_LEN)?,
        observed_at,
        protocol_version: opt_string(o, "protocolVersion", 64)?,
        auth_state,
        ttl_ms,
        cache_scope,
        set,
    })
}

/// The display label of a report: the source's label and who sent it (the
/// caller cannot choose it, so a report never reads as an AK observation).
pub fn report_provenance(source: Source, username: &str, generated_by: Option<&str>) -> String {
    match generated_by {
        Some(g) => format!("{} ({username}, {g})", source.default_provenance()),
        None => format!("{} ({username})", source.default_provenance()),
    }
}

async fn post_capabilities(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(p): Path<HashMap<String, String>>,
    base: RequestBaseUrl,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let p = version_path(&p);
    let ext = require_auth_basic_scope(auth, "mcp", "write:artifacts").map_err(|r| {
        let s = r.status().as_u16();
        problem(s, if s == 401 { "mcp_unauthorized" } else { "mcp_forbidden" },
            "Reporting capabilities needs write:artifacts on this repository", json!({}))
    })?;
    let body = body.map_err(|r| {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            problem(413, "mcp_too_large", "capability reports are capped at 1 MiB", json!({}))
        } else {
            bad_request("", "the request body could not be read")
        }
    })?;
    let t = target(&state, Some(&ext), &p, base.as_str()).await?;
    crate::api::handlers::repositories::require_repo_action(
        &ext,
        t.repo.id,
        "write",
        &state.permission_service,
    )
    .await
    .map_err(app_error)?;
    let report = parse_report(&body, Utc::now())?;
    let snap = NewSnapshot {
        repository_id: t.repo.id,
        artifact_id: t.artifact_id,
        server_name: p.name.clone(),
        server_version: p.version.clone(),
        source: report.source,
        provenance: report_provenance(report.source, &ext.username, report.generated_by.as_deref()),
        origin: report.generated_by.clone(),
        reported_by: Some(ext.user_id),
        auth_state: report.auth_state,
        outcome: Outcome::Ok,
        protocol_version: report.protocol_version,
        observed_at: report.observed_at,
        ttl_ms: report.ttl_ms,
        cache_scope: report.cache_scope,
        set: report.set,
        worker_version: None,
        details: json!({}),
    };
    let (ins, drift) = caps::store(&state.db, &snap, &t.repo.key)
        .await
        .map_err(app_error)?;
    Ok(json_resp(
        StatusCode::CREATED,
        &json!({
            "snapshot": ins.snapshot.to_json(),
            "previousSnapshotId": ins.previous.as_ref().map(|s| s.id),
            "drift": drift.map(|scan_id| json!({"scanId": scan_id})),
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET .../capabilities/diff
// ---------------------------------------------------------------------------

/// The newest version older than `version` among `versions`
/// (`compare_versions_for_latest` order).
pub fn previous_version(versions: &[String], version: &str) -> Option<String> {
    use std::cmp::Ordering;
    versions
        .iter()
        .filter(|v| fmt::compare_versions_for_latest(v, version) == Ordering::Less)
        .max_by(|a, b| fmt::compare_versions_for_latest(a, b))
        .cloned()
}

/// Resolve a `from`/`to` value: a snapshot id of this server, else a version
/// of it (its current snapshot).
async fn resolve_side(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name: &str,
    value: &str,
    source: Option<Source>,
    base: &str,
) -> Result<Option<SnapshotRow>, Response> {
    if let Ok(id) = Uuid::parse_str(value) {
        if let Some(s) = caps::get_snapshot(&state.db, id).await.map_err(internal)? {
            if s.repository_id == repo.id && s.server_name == name {
                surface::visible_version(state, auth, repo, name, &s.server_version, base).await?;
                return Ok(Some(s));
            }
        }
    }
    let (artifact_id, _, _) =
        surface::visible_version(state, auth, repo, name, value, base).await?;
    let rows = caps::list_snapshots(&state.db, artifact_id, None, MAX_HISTORY)
        .await
        .map_err(internal)?;
    Ok(caps::pick_current(&rows, source).cloned())
}

async fn get_diff(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(p): Path<HashMap<String, String>>,
    Query(q): Query<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let p = version_path(&p);
    let t = target(&state, auth.as_ref(), &p, base.as_str()).await?;
    let source = parse_source(&q)?;
    let a = auth.as_ref();
    let base = base.as_str();
    let to = match q.get("to").filter(|v| !v.is_empty()) {
        Some(v) => resolve_side(&state, a, &t.repo, &p.name, v, source, base).await?,
        None => {
            let rows = caps::list_snapshots(&state.db, t.artifact_id, None, MAX_HISTORY)
                .await
                .map_err(internal)?;
            caps::pick_current(&rows, source).cloned()
        }
    };
    let Some(to) = to else {
        return Err(problem(
            404,
            "mcp_capabilities_not_found",
            "No capability snapshot exists for this server version",
            json!({}),
        ));
    };
    let from = match q.get("from").filter(|v| !v.is_empty()) {
        Some(v) => resolve_side(&state, a, &t.repo, &p.name, v, source, base).await?,
        None => default_from(&state, a, &t.repo, &p.name, &to, base).await?,
    };
    let d = caps::diff(from.as_ref().map(SnapshotRow::set).as_ref(), &to.set());
    let mut out = caps::diff_json(&d);
    if let Some(o) = out.as_object_mut() {
        o.insert("from".into(), json!(from.as_ref().map(SnapshotRow::summary_json)));
        o.insert("to".into(), to.summary_json());
        o.insert("fromVersion".into(), json!(from.as_ref().map(|s| &s.server_version)));
        o.insert("toVersion".into(), json!(to.server_version));
        o.insert("notice".into(), json!(NOTICE));
    }
    Ok(json_resp(StatusCode::OK, &out))
}

/// The default `from`: the previous snapshot of the same source for the same
/// version, else the current snapshot (same source) of the previous version.
async fn default_from(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name: &str,
    to: &SnapshotRow,
    base: &str,
) -> Result<Option<SnapshotRow>, Response> {
    let rows = caps::list_snapshots(&state.db, to.artifact_id, None, MAX_HISTORY)
        .await
        .map_err(internal)?;
    if let Some(prev) = caps::pick_previous(&rows, to) {
        return Ok(Some(prev.clone()));
    }
    let versions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT server_version FROM mcp_capability_snapshots \
         WHERE repository_id = $1 AND server_name = $2",
    )
    .bind(repo.id)
    .bind(name)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    let Some(prev) = previous_version(&versions, &to.server_version) else {
        return Ok(None);
    };
    match surface::visible_version(state, auth, repo, name, &prev, base).await {
        Ok((artifact_id, _, _)) => {
            let rows = caps::list_snapshots(&state.db, artifact_id, None, MAX_HISTORY)
                .await
                .map_err(internal)?;
            Ok(caps::pick_current(&rows, to.source()).cloned())
        }
        // A previous version the caller may not see is no baseline.
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// POST .../capabilities/probe
// ---------------------------------------------------------------------------

async fn post_probe(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(p): Path<HashMap<String, String>>,
    base: RequestBaseUrl,
) -> HandlerResult {
    let p = version_path(&p);
    let ext = require_auth_basic_scope(auth, "mcp", "write:artifacts").map_err(|r| {
        let s = r.status().as_u16();
        problem(s, if s == 401 { "mcp_unauthorized" } else { "mcp_forbidden" },
            "Requesting introspection needs repository admin", json!({}))
    })?;
    let t = target(&state, Some(&ext), &p, base.as_str()).await?;
    crate::api::handlers::repositories::require_repo_admin(
        &ext,
        t.repo.id,
        &state.permission_service,
    )
    .await
    .map_err(app_error)?;
    let modes = jobs::modes(&state.db, t.repo.id).await.map_err(app_error)?;
    if !modes.probe_enabled() && !modes.sandbox_enabled() {
        return Err(problem(
            409,
            "mcp_introspection_disabled",
            "Introspection is off for this repository (mcp_probe_remotes, \
             mcp_sandbox_introspection)",
            json!({}),
        ));
    }
    let queued = jobs::enqueue_for_artifact(&state.db, t.artifact_id, Some(ext.user_id))
        .await
        .map_err(app_error)?;
    let open: Vec<Value> = jobs::list_jobs(&state.db, t.artifact_id, 20)
        .await
        .map_err(app_error)?
        .iter()
        .filter(|j| matches!(j.status.as_str(), "pending" | "claimed"))
        .map(jobs::JobRow::to_json)
        .collect();
    Ok(json_resp(
        StatusCode::ACCEPTED,
        &json!({ "queued": queued, "jobs": open }),
    ))
}

// ---------------------------------------------------------------------------
// Worker API
// ---------------------------------------------------------------------------

/// Whether `auth` is the introspector's dedicated credential: an API token
/// minted with the `mcp:introspect` scope. A broad (`*`, `admin`) or
/// interactive credential does not qualify.
pub fn is_introspector(auth: &AuthExtension) -> bool {
    auth.scopes
        .as_ref()
        .is_some_and(|s| s.iter().any(|x| x == INTROSPECT_SCOPE))
}

fn require_introspector(auth: Option<AuthExtension>) -> Result<AuthExtension, Response> {
    match auth {
        None => Err(problem(401, "mcp_unauthorized", "Authentication required", json!({}))),
        Some(a) if is_introspector(&a) => Ok(a),
        Some(_) => Err(problem(
            403,
            "mcp_forbidden",
            "The introspection worker API needs a token with the mcp:introspect scope",
            json!({}),
        )),
    }
}

/// `{kinds?, workerId?}`: which job kinds this worker runs.
pub fn parse_claim(body: &[u8]) -> Result<(Vec<JobKind>, String), Response> {
    let doc: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body).map_err(|_| bad_request("", "body is not valid JSON"))?
    };
    let kinds = match doc.get("kinds") {
        None | Some(Value::Null) => JobKind::ALL.to_vec(),
        Some(Value::Array(a)) => {
            let mut out = Vec::new();
            for k in a {
                let k = k
                    .as_str()
                    .and_then(JobKind::parse)
                    .ok_or_else(|| bad_request("kinds", "unknown job kind"))?;
                if !out.contains(&k) {
                    out.push(k);
                }
            }
            if out.is_empty() {
                return Err(bad_request("kinds", "must not be empty"));
            }
            out
        }
        Some(_) => return Err(bad_request("kinds", "must be an array")),
    };
    let worker = doc
        .get("workerId")
        .and_then(|w| w.as_str())
        .unwrap_or("ak-mcp-introspector")
        .chars()
        .take(128)
        .collect();
    Ok((kinds, worker))
}

/// The worker's per-job limits (the worker enforces them).
pub fn job_limits(kind: JobKind) -> Value {
    match kind {
        JobKind::RemoteProbe => json!({
            "connectTimeoutMs": 10_000, "totalTimeoutMs": 30_000,
            "maxResponseBytes": caps::INGEST_MAX_BYTES, "maxItems": caps::MAX_ITEMS,
            "followRedirects": false,
        }),
        JobKind::SandboxRun => json!({
            "wallClockMs": 120_000, "maxResponseBytes": caps::INGEST_MAX_BYTES,
            "maxItems": caps::MAX_ITEMS, "network": "ak-only",
        }),
    }
}

async fn claim_job(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    base: RequestBaseUrl,
    body: Bytes,
) -> HandlerResult {
    require_introspector(auth)?;
    let (kinds, worker) = parse_claim(&body)?;
    // A job that cannot run any more is cancelled and the next one tried.
    for _ in 0..10 {
        let Some(claim) = jobs::claim(&state.db, &kinds, &worker).await.map_err(app_error)? else {
            return Ok(StatusCode::NO_CONTENT.into_response());
        };
        match claim_payload(&state, &claim, base.as_str()).await? {
            Ok(payload) => return Ok(json_resp(StatusCode::OK, &payload)),
            Err(reason) => {
                jobs::cancel(&state.db, &claim.job, &reason)
                    .await
                    .map_err(app_error)?;
            }
        }
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn claim_payload(
    state: &SharedState,
    claim: &jobs::Claim,
    base: &str,
) -> Result<Result<Value, String>, Response> {
    let job = &claim.job;
    let Some(kind) = job.kind() else {
        return Ok(Err("unknown job kind".into()));
    };
    let Some(v) = caps::version_ref(&state.db, job.artifact_id)
        .await
        .map_err(internal)?
    else {
        return Ok(Err("server version deleted".into()));
    };
    let Some(stored) = fmt::StoredVersion::from_metadata(&v.metadata) else {
        return Ok(Err("unreadable server version".into()));
    };
    let repo = surface::mcp_repo(&state.db, &v.repository_key).await?;
    if kind == JobKind::SandboxRun && !surface::artifact_servable(state, &repo, v.artifact_id, base).await
    {
        // Only a version whose gates pass is ever executed: the bytes run
        // are the bytes AK scanned.
        return Ok(Err("server version is held".into()));
    }
    let served = fmt::rewrite_packages_for_serve(&stored.server, &stored.pins, stored.policy, base);
    let target = match jobs::job_target(kind, &job.target_key, &stored, &served) {
        Ok(t) => t,
        Err(_) => return Ok(Err("target no longer eligible".into())),
    };
    Ok(Ok(json!({
        "jobId": job.id,
        "claimToken": claim.token,
        "kind": kind.as_str(),
        "attempt": job.attempts,
        "leaseExpiresAt": job.lease_expires_at,
        "repository": v.repository_key,
        "server": {"name": v.name, "version": v.version, "artifactId": v.artifact_id},
        "akBaseUrl": base.trim_end_matches('/'),
        "target": target,
        "limits": job_limits(kind),
    })))
}

async fn complete_job(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> HandlerResult {
    require_introspector(auth)?;
    if fmt::json_depth_exceeds(&body, INGEST_MAX_DEPTH) {
        return Err(bad_request("", &format!("nesting deeper than {INGEST_MAX_DEPTH}")));
    }
    let result: jobs::WorkerResult = serde_json::from_slice(&body)
        .map_err(|e| bad_request("", &format!("unreadable result: {e}")))?;
    let job = jobs::get_job(&state.db, id)
        .await
        .map_err(app_error)?
        .filter(|j| jobs::token_matches(j, &result.claim_token))
        .ok_or_else(|| {
            problem(
                409,
                "mcp_claim_invalid",
                "This job is not claimed with that token (lease expired or already completed)",
                json!({}),
            )
        })?;
    let parsed = jobs::parse_result(&result).map_err(|e| bad_request(&e.path, &e.message))?;
    let out = match jobs::complete(&state.db, &job, &result, parsed)
        .await
        .map_err(app_error)?
    {
        jobs::Completed::Stored {
            snapshot,
            drift_scan,
        } => json!({
            "status": "stored",
            "snapshotId": snapshot.id,
            "contentHash": snapshot.content_hash,
            "drift": drift_scan.map(|scan_id| json!({"scanId": scan_id})),
        }),
        jobs::Completed::Retry { not_before } => json!({
            "status": "retry",
            "notBefore": not_before,
        }),
    };
    Ok(json_resp(StatusCode::OK, &out))
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn report_parsing() {
        let now = Utc::now();
        let r = parse_report(
            br#"{"source":"ci_reported","tools":[{"name":"a"}],"generatedBy":"gh-actions",
                 "authState":"none","ttlMs":5,"cacheScope":"public","protocolVersion":"2026-07-28",
                 "observedAt":"2026-01-01T00:00:00Z"}"#,
            now,
        )
        .unwrap();
        assert_eq!(r.source, Source::CiReported);
        assert_eq!(r.set.tools.len(), 1);
        assert_eq!(r.generated_by.as_deref(), Some("gh-actions"));
        assert_eq!(r.ttl_ms, Some(5));
        let d = parse_report(br#"{"source":"gateway_reported"}"#, now).unwrap();
        assert_eq!(d.observed_at, now);
        assert_eq!(d.auth_state, AuthState::Unknown);
        let future = (now + chrono::Duration::hours(1)).to_rfc3339();
        let bad: Vec<Vec<u8>> = vec![
            b"nope".to_vec(),
            b"[]".to_vec(),
            br#"{"source":"remote_probe"}"#.to_vec(),
            br#"{}"#.to_vec(),
            br#"{"source":"ci_reported","observedAt":"yesterday"}"#.to_vec(),
            format!(r#"{{"source":"ci_reported","observedAt":"{future}"}}"#).into_bytes(),
            br#"{"source":"ci_reported","authState":"x"}"#.to_vec(),
            br#"{"source":"ci_reported","cacheScope":"shared"}"#.to_vec(),
            br#"{"source":"ci_reported","ttlMs":-1}"#.to_vec(),
            br#"{"source":"ci_reported","generatedBy":7}"#.to_vec(),
            br#"{"source":"ci_reported","tools":[{}]}"#.to_vec(),
            format!(r#"{{"source":"ci_reported","x":{}1{}}}"#, "[".repeat(70), "]".repeat(70))
                .into_bytes(),
        ];
        for b in bad {
            let resp = parse_report(&b, now).unwrap_err();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));
        }
    }

    #[test]
    fn provenance_and_helpers() {
        assert_eq!(
            report_provenance(Source::CiReported, "alice", None),
            "reported by CI (alice)"
        );
        assert_eq!(
            report_provenance(Source::GatewayReported, "bob", Some("toolhive")),
            "reported by a gateway (bob, toolhive)"
        );
        let vs: Vec<String> = ["1.0.0", "1.2.0", "2.0.0", "1.10.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(previous_version(&vs, "2.0.0").as_deref(), Some("1.10.0"));
        assert_eq!(previous_version(&vs, "1.0.0"), None);
        assert_eq!(parse_limit(&q(&[])).unwrap(), DEFAULT_HISTORY);
        assert_eq!(parse_limit(&q(&[("limit", "999")])).unwrap(), MAX_HISTORY);
        assert!(parse_limit(&q(&[("limit", "0")])).is_err());
        assert!(parse_source(&q(&[("source", "bogus")])).is_err());
        assert_eq!(parse_source(&q(&[("source", "")])).unwrap(), None);
        assert_eq!(
            parse_source(&q(&[("source", "remote_probe")])).unwrap(),
            Some(Source::RemoteProbe)
        );
        let vp = version_path(&q(&[("repo_key", "r"), ("ns", "com.acme"), ("name", "x"), ("version", "1")]));
        assert_eq!(vp.name, "com.acme/x");
        assert_eq!(version_path(&q(&[("ns", "com.acme/x")])).name, "com.acme/x");
        assert_eq!(job_limits(JobKind::RemoteProbe)["followRedirects"], false);
        assert_eq!(job_limits(JobKind::SandboxRun)["wallClockMs"], 120_000);
    }

    #[test]
    fn claim_parsing_and_scope() {
        let (k, w) = parse_claim(b"").unwrap();
        assert_eq!(k, JobKind::ALL.to_vec());
        assert_eq!(w, "ak-mcp-introspector");
        let (k, w) = parse_claim(br#"{"kinds":["sandbox_run","sandbox_run"],"workerId":"w1"}"#).unwrap();
        assert_eq!(k, vec![JobKind::SandboxRun]);
        assert_eq!(w, "w1");
        for b in [&br#"{"kinds":[]}"#[..], br#"{"kinds":["x"]}"#, br#"{"kinds":"x"}"#, b"{"] {
            assert!(parse_claim(b).is_err());
        }
        let mut a = crate::api::handlers::test_db_helpers::make_auth(Uuid::nil(), "w");
        assert!(!is_introspector(&a), "interactive credentials do not qualify");
        a.scopes = Some(vec!["*".into()]);
        assert!(!is_introspector(&a), "a wildcard token is not the dedicated credential");
        a.scopes = Some(vec![INTROSPECT_SCOPE.into()]);
        assert!(is_introspector(&a));
        assert_eq!(require_introspector(None).unwrap_err().status(), 401);
    }

    #[test]
    fn declared_block_admission() {
        let mut s: fmt::ServerJson = serde_json::from_value(json!({
            "name": "com.acme/x", "description": "d", "version": "1",
            "remotes": [{"type": "sse", "url": "https://x.test"}],
        }))
        .unwrap();
        assert!(admit_declared(&s).is_ok());
        let mut meta = serde_json::Map::new();
        meta.insert(caps::CAPABILITIES_META_KEY.into(), json!({"tools": [{"name": "a"}]}));
        s.meta = Some(meta.clone());
        assert!(admit_declared(&s).is_ok());
        meta.insert(caps::CAPABILITIES_META_KEY.into(), json!({"tools": [{}]}));
        s.meta = Some(meta);
        assert!(matches!(admit_declared(&s), Err(McpError::Invalid { .. })));
        let mut meta = serde_json::Map::new();
        meta.insert(
            fmt::PUBLISHER_META_KEY.into(),
            json!({ caps::CAPABILITIES_META_KEY: {"tools": "x"} }),
        );
        s.meta = Some(meta);
        assert!(admit_declared(&s).is_err());
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{header, Request};

    async fn call(app: Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let body = body
            .map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap_or_else(Body::empty);
        let (s, bytes, _) = tdh::send_with_headers(app, b.body(body).unwrap()).await;
        (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    struct Env {
        fx: tdh::Fixture,
    }

    impl Env {
        fn admin(&self) -> Router {
            tdh::router_with_auth(
                surface::router(),
                self.fx.state.clone(),
                tdh::admin_auth(self.fx.user_id, &self.fx.username),
            )
        }
        fn anon(&self) -> Router {
            self.fx.router_anon(surface::router())
        }
        fn worker(&self, scopes: Option<Vec<String>>) -> Router {
            let mut a = tdh::make_auth(self.fx.user_id, &self.fx.username);
            a.is_api_token = true;
            a.scopes = scopes;
            tdh::router_with_auth(worker_router(), self.fx.state.clone(), a)
        }
        fn url(&self, tail: &str) -> String {
            format!(
                "/{}/v0.1/servers/com.acme%2Fweather/versions/1.0.0/capabilities{tail}",
                self.fx.repo_key
            )
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
    }

    fn doc(version: &str, caps_block: Value) -> Value {
        json!({
            "$schema": fmt::SCHEMA_URL, "name": "com.acme/weather", "description": "Weather",
            "version": version,
            "remotes": [{"type": "streamable-http", "url": "https://mcp.acme.test/mcp"}],
            "_meta": { caps::CAPABILITIES_META_KEY: caps_block },
        })
    }

    #[tokio::test]
    async fn capabilities_lifecycle_end_to_end() {
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        let publish = format!("/{}/v0.1/publish", env.fx.repo_key);
        // A malformed declaration is refused at publish.
        let (s, b) = call(env.admin(), "POST", &publish, Some(doc("0.9.0", json!({"tools": [{}]})))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, b) = call(
            env.admin(),
            "POST",
            &publish,
            Some(doc("1.0.0", json!({"tools": [{"name": "get_weather", "description": "Forecast"}]}))),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");

        // Readers see the declared snapshot; no job state.
        let (s, b) = call(env.anon(), "GET", &env.url(""), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["current"]["source"], "publisher_declared");
        assert_eq!(b["current"]["observed"], false);
        assert_eq!(b["current"]["tools"][0]["name"], "get_weather");
        assert_eq!(b["introspection"]["probeEnabled"], false);
        assert!(b["introspection"].get("jobs").is_none());
        assert_eq!(b["notice"], NOTICE);
        let declared_id = b["current"]["id"].as_str().unwrap().to_string();
        let (s, _) = call(env.anon(), "GET", &env.url("").replace("1.0.0", "9.9.9"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // CI reports; the second one differs: tool_drift.
        let report = |tools: Value| json!({"source": "ci_reported", "generatedBy": "gha", "tools": tools});
        let (s, b) = call(env.anon(), "POST", &env.url(""), Some(report(json!([])))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{b}");
        let (s, b) = call(env.admin(), "POST", &env.url(""), Some(json!({"source": "remote_probe"}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, b) = call(env.admin(), "POST", &env.url(""), Some(report(json!([{"name": "get_weather"}])))).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert!(b["drift"].is_null());
        assert!(b["snapshot"]["provenance"].as_str().unwrap().starts_with("reported by CI ("));
        let (s, b) = call(
            env.admin(),
            "POST",
            &env.url(""),
            Some(report(json!([{"name": "get_weather"},
                {"name": "delete_city", "annotations": {"destructiveHint": true}}]))),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert!(b["drift"]["scanId"].is_string(), "{b}");

        // Diff: default is against the previous CI report.
        let (s, b) = call(env.anon(), "GET", &env.url("/diff"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["to"]["source"], "ci_reported");
        assert_eq!(b["summary"]["tools"]["added"], 1);
        assert_eq!(b["summary"]["destructiveAdded"], json!(["delete_city"]));
        let (s, b) = call(env.anon(), "GET", &env.url(&format!("/diff?from={declared_id}")), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["from"]["id"], declared_id);
        assert_eq!(b["summary"]["tools"]["changed"], 1, "{b}");
        let (s, _) = call(env.anon(), "GET", &env.url("/diff?source=sandbox_run"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = call(env.anon(), "GET", &env.url("?source=nope"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, b) = call(env.anon(), "GET", &env.url(&format!("?snapshot={declared_id}&limit=1")), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["current"]["id"], declared_id);
        assert_eq!(b["snapshots"].as_array().unwrap().len(), 1);

        // Probing is opt-in.
        let (s, b) = call(env.admin(), "POST", &env.url("/probe"), None).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only").await;
        let (s, b) = call(env.admin(), "POST", &env.url("/probe"), None).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert_eq!(b["jobs"].as_array().unwrap().len(), 1);
        let (s, b) = call(env.admin(), "GET", &env.url(""), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["introspection"]["jobs"][0]["status"], "pending");

        // The worker API needs the dedicated scope.
        let (s, _) = call(env.worker(None), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let w = env.worker(Some(vec![INTROSPECT_SCOPE.into()]));
        let (s, job) = call(w.clone(), "POST", "/jobs/claim", Some(json!({"kinds": ["remote_probe"]}))).await;
        assert_eq!(s, StatusCode::OK, "{job}");
        assert_eq!(job["target"]["url"], "https://mcp.acme.test/mcp");
        let id = job["jobId"].as_str().unwrap();
        let (s, _) = call(w.clone(), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "one open job per target");
        let complete = format!("/jobs/{id}/complete");
        let (s, _) = call(w.clone(), "POST", &complete, Some(json!({"claimToken": "wrong", "outcome": "ok"}))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        // A transient failure goes back to the queue.
        let (s, b) = call(w.clone(), "POST", &complete, Some(json!({"claimToken": job["claimToken"], "outcome": "timeout"}))).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["status"], "retry");
        sqlx::query("UPDATE mcp_introspection_jobs SET not_before = NOW() WHERE id = $1")
            .bind(Uuid::parse_str(id).unwrap())
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let (s, job) = call(w.clone(), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, b) = call(
            w.clone(),
            "POST",
            &complete,
            Some(json!({"claimToken": job["claimToken"], "outcome": "ok", "protocolVersion": "2026-07-28",
                        "tools": [{"name": "get_weather"}], "ttlMs": 1000})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["status"], "stored");
        let (s, _) = call(w, "POST", &complete, Some(json!({"claimToken": job["claimToken"], "outcome": "ok"}))).await;
        assert_eq!(s, StatusCode::CONFLICT, "a completed job cannot be completed again");
        let (_, b) = call(env.anon(), "GET", &env.url(""), None).await;
        assert_eq!(b["current"]["source"], "remote_probe", "an observation is the current view");

        // Scheduler pass: nothing expired, the fresh probe is not due.
        jobs::scheduler_tick(&env.fx.pool).await;
        let open: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_introspection_jobs WHERE repository_id = $1 AND status = 'pending'",
        )
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(open, 0);
        // An old probe is re-queued.
        sqlx::query("UPDATE mcp_introspection_jobs SET completed_at = NOW() - INTERVAL '7 hours' WHERE repository_id = $1")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(jobs::requeue_due_probes(&env.fx.pool).await.unwrap(), 1);
        // An expired claim is reaped.
        let w = env.worker(Some(vec![INTROSPECT_SCOPE.into()]));
        let (s, _) = call(w, "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::OK);
        sqlx::query("UPDATE mcp_introspection_jobs SET lease_expires_at = NOW() - INTERVAL '1 minute' WHERE repository_id = $1 AND status = 'claimed'")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        assert_eq!(jobs::reap_expired(&env.fx.pool).await.unwrap(), 1);

        let _ = sqlx::query("DELETE FROM packages WHERE repository_id = $1")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await;
        env.fx.teardown().await;
    }
}
