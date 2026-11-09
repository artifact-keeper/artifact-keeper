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
use crate::api::handlers::mcp::{self as surface, problem, server_name, Servability};
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
pub const MAX_HISTORY: i64 = caps::HISTORY_WINDOW;
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
        for spelling in [
            "/servers/:ns/versions/:version",
            "/servers/:ns/:name/versions/:version",
        ] {
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
/// The OpenAPI paths of the introspection worker API.
#[derive(utoipa::OpenApi)]
#[openapi(paths(claim_job, complete_job))]
pub struct McpIntrospectionWorkerApiDoc;

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
pub async fn after_publish(db: &PgPool, artifact_id: Uuid, user_id: Option<Uuid>) {
    if let Err(e) = caps::record_declared_snapshot(db, artifact_id).await {
        tracing::warn!(error = %e, %artifact_id, "declared MCP capabilities not recorded");
    }
    if let Err(e) = jobs::enqueue_for_artifact(db, artifact_id, user_id).await {
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

fn opt_string(
    o: &serde_json::Map<String, Value>,
    k: &str,
    max: usize,
) -> Result<Option<String>, Response> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= max => Ok(Some(s.clone())),
        Some(_) => Err(bad_request(
            k,
            &format!("must be a string of at most {max} bytes"),
        )),
    }
}

/// Parse and validate a report body (pure; `now` bounds `observedAt`).
pub fn parse_report(body: &[u8], now: DateTime<Utc>) -> Result<Report, Response> {
    if fmt::json_depth_exceeds(body, INGEST_MAX_DEPTH) {
        return Err(bad_request(
            "",
            &format!("nesting deeper than {INGEST_MAX_DEPTH}"),
        ));
    }
    let doc: Value =
        serde_json::from_slice(body).map_err(|_| bad_request("", "body is not valid JSON"))?;
    let Some(o) = doc.as_object() else {
        return Err(bad_request("", "must be a JSON object"));
    };
    let source = match o
        .get("source")
        .and_then(|s| s.as_str())
        .and_then(Source::parse)
    {
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
        Some(s) => DateTime::parse_from_rfc3339(&s)
            .map_err(|_| bad_request("observedAt", "must be an RFC 3339 timestamp"))?
            .with_timezone(&Utc),
    };
    let auth_state = match opt_string(o, "authState", 32)? {
        None => AuthState::Unknown,
        Some(s) => AuthState::parse(&s).ok_or_else(|| bad_request("authState", "unknown value"))?,
    };
    let cache_scope = opt_string(o, "cacheScope", 16)?;
    let ttl_ms = match o.get("ttlMs") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_i64()
                .ok_or_else(|| bad_request("ttlMs", "must be an integer"))?,
        ),
    };
    // A report answers the worker result's metadata bounds and code (#5543).
    jobs::validate_metadata(Some(observed_at), cache_scope.as_deref(), ttl_ms, now)
        .map_err(|e| invalid_metadata(&e))?;
    // Skew is tolerated, never ranked above arrival (#5464).
    let observed_at = observed_at.min(now);
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
    headers: axum::http::HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> HandlerResult {
    let p = version_path(&p);
    let ext = require_auth_basic_scope(auth, "mcp", "write:artifacts").map_err(|r| {
        let s = r.status().as_u16();
        problem(
            s,
            if s == 401 {
                "mcp_unauthorized"
            } else {
                "mcp_forbidden"
            },
            "Reporting capabilities needs write:artifacts on this repository",
            json!({}),
        )
    })?;
    let body = body.map_err(|r| {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            problem(
                413,
                "mcp_too_large",
                "capability reports are capped at 1 MiB",
                json!({}),
            )
        } else {
            bad_request("", "the request body could not be read")
        }
    })?;
    let t = target(&state, Some(&ext), &p, base.as_str()).await?;
    // A capability report is an MCP write of this server name: the token's
    // repository scope, then the namespace write gate every other MCP write
    // runs (plain write, or a matching `mcp_namespaces` grant;
    // `mcp_require_namespace_grant`).
    if !ext.can_access_repo(t.repo.id) {
        return Err(out_of_scope());
    }
    crate::api::handlers::mcp_edges::require_namespace_write(
        &state, &ext, t.repo.id, &p.name, "write", &headers,
    )
    .await?;
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
            // `false`: the report repeats the newest one of the same source
            // and origin, whose `lastSeenAt` was bumped instead (#5386).
            "created": ins.created,
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
        o.insert(
            "from".into(),
            json!(from.as_ref().map(SnapshotRow::summary_json)),
        );
        o.insert("to".into(), to.summary_json());
        o.insert(
            "fromVersion".into(),
            json!(from.as_ref().map(|s| &s.server_version)),
        );
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
        problem(
            s,
            if s == 401 {
                "mcp_unauthorized"
            } else {
                "mcp_forbidden"
            },
            "Requesting introspection needs repository admin",
            json!({}),
        )
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

/// `403`: the credential's repository scope does not cover the repository a
/// write (a capability report, a worker claim or result) is for.
fn out_of_scope() -> Response {
    problem(
        403,
        "mcp_forbidden",
        "This token is not scoped to this repository",
        json!({}),
    )
}

fn require_introspector(auth: Option<AuthExtension>) -> Result<AuthExtension, Response> {
    match auth {
        None => Err(problem(
            401,
            "mcp_unauthorized",
            "Authentication required",
            json!({}),
        )),
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

#[utoipa::path(
    post,
    operation_id = "mcp_introspection_claim_job",
    path = "/jobs/claim",
    context_path = "/api/v1/mcp/introspection",
    tag = "mcp",
    security(("bearer_auth" = [])),
    request_body(content = Object, description = "`{kinds?: [\"remote_probe\" | \"sandbox_run\"], workerId?}`"),
    responses(
        (status = 200, body = Object, description = "A claimed job: jobId, claimToken, kind, target and limits"),
        (status = 204, description = "Nothing is due"),
        (status = 400, description = "Malformed request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Not an `mcp:introspect` API token (`mcp_forbidden`)"),
        (status = 503, description = "`mcp_gate_unavailable`: nothing servable was found and a candidate's gates could not be evaluated; it is back in the queue"),
    )
)]
async fn claim_job(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    base: RequestBaseUrl,
    body: Bytes,
) -> HandlerResult {
    // The token's repository scope bounds which jobs it may be handed
    // (#5460): a token restricted to repository A never claims B's job.
    let auth = require_introspector(auth)?;
    let scope = auth.access_scope();
    let (kinds, worker) = parse_claim(&body)?;
    // A job that cannot run any more is cancelled, one whose gates cannot be
    // evaluated now is released to the queue, and the next one tried. Only
    // when nothing servable was found and a gate was unavailable is the
    // answer `503` rather than `204`.
    let mut unavailable = false;
    for _ in 0..10 {
        // The claim is bound to this principal (#5465).
        let Some(claim) = jobs::claim(&state.db, &kinds, &worker, auth.user_id, &scope)
            .await
            .map_err(app_error)?
        else {
            break;
        };
        match claim_payload(&state, &claim, base.as_str()).await? {
            Ok(payload) => return Ok(json_resp(StatusCode::OK, &payload)),
            Err(Unclaimable::Cancel(reason)) => {
                jobs::cancel(&state.db, &claim.job, &reason)
                    .await
                    .map_err(app_error)?;
            }
            Err(Unclaimable::GateUnavailable) => {
                jobs::release(&state.db, &claim.job, "serve gate unavailable")
                    .await
                    .map_err(app_error)?;
                unavailable = true;
            }
        }
    }
    if unavailable {
        return Err(gate_unavailable());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Why a claimed job is not handed to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unclaimable {
    /// It cannot run any more: cancelled with this reason.
    Cancel(String),
    /// Its gates could not be evaluated: released to the queue.
    GateUnavailable,
}

async fn claim_payload(
    state: &SharedState,
    claim: &jobs::Claim,
    base: &str,
) -> Result<Result<Value, Unclaimable>, Response> {
    let job = &claim.job;
    let cancel = |reason: &str| Ok(Err(Unclaimable::Cancel(reason.into())));
    let Some(kind) = job.kind() else {
        return cancel("unknown job kind");
    };
    let Some(v) = caps::version_ref(&state.db, job.artifact_id)
        .await
        .map_err(internal)?
    else {
        return cancel("server version deleted");
    };
    let Some(stored) = fmt::StoredVersion::from_metadata(&v.metadata) else {
        return cancel("unreadable server version");
    };
    let repo = surface::mcp_repo(&state.db, &v.repository_key).await?;
    // Only a version whose gates pass is ever introspected: a sandbox run
    // executes exactly the bytes AK scanned, and a remote probe contacts a
    // held, blocked or unapproved version's endpoints no more than a reader
    // could. A gate that cannot be evaluated is no hold: the caller hands
    // the claim back to the queue, never cancels it.
    match surface::artifact_servability(state, &repo, v.artifact_id, base).await {
        Servability::Servable => {}
        Servability::Held => return cancel("server version is held"),
        Servability::Unavailable => return Ok(Err(Unclaimable::GateUnavailable)),
    }
    let served = fmt::rewrite_packages_for_serve(&stored.server, &stored.pins, base);
    let target = match jobs::job_target(kind, &job.target_key, &stored, &served) {
        Ok(t) => t,
        Err(_) => return cancel("target no longer eligible"),
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

#[utoipa::path(
    post,
    operation_id = "mcp_introspection_complete_job",
    path = "/jobs/{id}/complete",
    context_path = "/api/v1/mcp/introspection",
    tag = "mcp",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Job id")),
    request_body(content = Object, description = "The worker's result: claimToken, outcome, the lists on success"),
    responses(
        (status = 200, body = Object, description = "`{status: \"stored\", snapshotId, contentHash, current, drift}` (`current`: whether the stored snapshot is the version's current view now) or `{status: \"retry\", notBefore}`"),
        (status = 400, description = "Malformed result (`mcp_invalid_capabilities`), or invalid result metadata (`mcp_invalid_result_metadata`: an `observedAt` outside the claim's window, an unknown `cacheScope`, a negative or too large `ttlMs`); nothing was stored and the claim is unchanged"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Not an `mcp:introspect` API token, or the token is not scoped to the job's repository (`mcp_forbidden`)"),
        (status = 409, description = "`mcp_claim_invalid`: the token does not match the current claim, the claim is held by another worker identity, or its lease expired; `mcp_target_ineligible`: the server version or a backing package stopped being eligible after the claim, and the job was cancelled"),
        (status = 503, description = "`mcp_gate_unavailable`: the server version's gates could not be evaluated; nothing was stored and the claim is unchanged"),
    )
)]
async fn complete_job(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    base: RequestBaseUrl,
    body: Bytes,
) -> HandlerResult {
    let auth = require_introspector(auth)?;
    let scope = auth.access_scope();
    if fmt::json_depth_exceeds(&body, INGEST_MAX_DEPTH) {
        return Err(bad_request(
            "",
            &format!("nesting deeper than {INGEST_MAX_DEPTH}"),
        ));
    }
    let result: jobs::WorkerResult = serde_json::from_slice(&body)
        .map_err(|e| bad_request("", &format!("unreadable result: {e}")))?;
    let claim_invalid = || {
        problem(
            409,
            "mcp_claim_invalid",
            "This job is not claimed with that token (lease expired or already completed)",
            json!({}),
        )
    };
    // The claim is single-owner (#5465): a token presented by a principal
    // other than the one that claimed the job is the same `409` as a wrong
    // token, answered before the result is even read, so it reveals nothing
    // about the token or the job.
    let job = jobs::get_job(&state.db, id)
        .await
        .map_err(app_error)?
        .filter(|j| jobs::claim_matches(j, &result.claim_token, auth.user_id))
        .ok_or_else(claim_invalid)?;
    let parsed = jobs::parse_result(&result).map_err(|e| bad_request(&e.path, &e.message))?;
    // Observation and cache metadata is refused before any gate is evaluated
    // or anything locked (#5466); `jobs::complete` checks it again for its
    // other callers.
    jobs::validate_metadata(
        result.observed_at,
        result.cache_scope.as_deref(),
        result.ttl_ms,
        Utc::now(),
    )
    .map_err(|e| invalid_metadata(&e))?;
    // The full serve gate a claim passes, evaluated again now (#5463); the
    // version's and its backing packages' holds are re-read under lock in
    // the transaction as well.
    let servable = match version_servable(&state, job.artifact_id, base.as_str()).await? {
        Servability::Servable => true,
        Servability::Held => false,
        // No verdict is no hold: the claim stays for the worker to retry or
        // the reaper to return.
        Servability::Unavailable => return Err(gate_unavailable()),
    };
    // The claim token proves only the claim; the repository scope is
    // re-checked against the job's repository inside the transaction that
    // ends the claim (#5460).
    let out = match jobs::complete(
        &state.db,
        &job,
        &result,
        parsed,
        auth.user_id,
        &scope,
        servable,
    )
        .await
        .map_err(app_error)?
    {
        jobs::Completed::Stored {
            snapshot,
            drift_scan,
            current,
        } => json!({
            "status": "stored",
            "snapshotId": snapshot.id,
            "contentHash": snapshot.content_hash,
            "current": current,
            "drift": drift_scan.map(|scan_id| json!({"scanId": scan_id})),
        }),
        jobs::Completed::Retry { not_before } => json!({
            "status": "retry",
            "notBefore": not_before,
        }),
        // The claim ended between the token check and the store (a duplicate
        // or concurrent completion, the reaper): nothing was stored (#5389).
        jobs::Completed::ClaimLost => return Err(claim_invalid()),
        // The token's scope does not cover the job's repository:
        // nothing was stored and the claim is unchanged (#5460).
        jobs::Completed::Forbidden => return Err(out_of_scope()),
        // The target stopped being eligible after the claim: nothing was
        // stored and the job is cancelled (#5463).
        jobs::Completed::Ineligible { reason } => {
            return Err(problem(
                409,
                "mcp_target_ineligible",
                "This job's server version is no longer eligible for introspection; the job was cancelled",
                json!({"reason": reason}),
            ))
        }
        jobs::Completed::Invalid(e) => return Err(invalid_metadata(&e)),
    };
    Ok(json_resp(StatusCode::OK, &out))
}

/// The serve gate a claim passes ([`claim_payload`]) for the server version
/// `artifact_id` now: a deleted version is [`Servability::Held`]. A
/// repository that vanished since the claim answers its own `404` from
/// `mcp_repo`, leaving the claim for the reaper.
async fn version_servable(
    state: &SharedState,
    artifact_id: Uuid,
    base: &str,
) -> Result<Servability, Response> {
    let Some(v) = caps::version_ref(&state.db, artifact_id)
        .await
        .map_err(internal)?
    else {
        return Ok(Servability::Held);
    };
    let repo = surface::mcp_repo(&state.db, &v.repository_key).await?;
    Ok(surface::artifact_servability(state, &repo, artifact_id, base).await)
}

/// `400 mcp_invalid_result_metadata`: a worker result's or a CI/gateway
/// report's `observedAt`, `cacheScope` or `ttlMs` was refused (#5464, #5466,
/// #5543). A refused result stores nothing and leaves the claim unchanged: the
/// worker may resubmit a corrected result while its lease lasts.
fn invalid_metadata(e: &caps::CapError) -> Response {
    problem(
        400,
        "mcp_invalid_result_metadata",
        &format!("{}: {}", e.path, e.message),
        json!({"field": e.path}),
    )
}

/// `503 mcp_gate_unavailable`: a gate could not be evaluated.
fn gate_unavailable() -> Response {
    problem(
        503,
        "mcp_gate_unavailable",
        "The registry could not evaluate this server version's gates; retry later",
        json!({}),
    )
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
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
            format!(
                r#"{{"source":"ci_reported","x":{}1{}}}"#,
                "[".repeat(70),
                "]".repeat(70)
            )
            .into_bytes(),
        ];
        for b in bad {
            let resp = parse_report(&b, now).unwrap_err();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{}",
                String::from_utf8_lossy(&b)
            );
        }
    }

    /// #5543: a report's observation and cache metadata is validated like a
    /// worker result's (#5466): the same bounds, the same
    /// `mcp_invalid_result_metadata` code, and the offending `field`. A report
    /// that is merely malformed still answers `mcp_invalid_capabilities`.
    #[tokio::test]
    async fn report_metadata_answers_the_result_code_and_bounds() {
        let now = Utc::now();
        let skew = chrono::Duration::seconds(caps::OBSERVED_AT_SKEW_SECS);
        // streaming-invariant: test-only read of a small, bounded refusal body (#1608)
        #[allow(clippy::disallowed_methods)]
        async fn refusal(body: String, now: DateTime<Utc>) -> (StatusCode, Value) {
            let resp = parse_report(body.as_bytes(), now).unwrap_err();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        }
        let report = |extra: Value| {
            let mut body = json!({"source": "gateway_reported"});
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            body.to_string()
        };

        let far = (now + skew + chrono::Duration::seconds(1)).to_rfc3339();
        for (extra, field) in [
            (json!({"observedAt": far}), "observedAt"),
            (json!({"cacheScope": "shared"}), "cacheScope"),
            (json!({"cacheScope": "PUBLIC"}), "cacheScope"),
            (json!({"ttlMs": -1}), "ttlMs"),
            (json!({"ttlMs": jobs::MAX_TTL_MS + 1}), "ttlMs"),
            (json!({"ttlMs": i64::MAX}), "ttlMs"),
        ] {
            let (status, b) = refusal(report(extra), now).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{b}");
            assert_eq!(b["error"], "mcp_invalid_result_metadata", "{b}");
            assert_eq!(b["field"], field, "{b}");
        }

        // The boundaries are accepted, and an `observedAt` inside the skew
        // window is stored as of its arrival.
        for extra in [
            json!({"observedAt": (now - chrono::Duration::days(365)).to_rfc3339()}),
            json!({"observedAt": (now + skew).to_rfc3339()}),
            json!({"cacheScope": "public", "ttlMs": 0}),
            json!({"cacheScope": "private", "ttlMs": jobs::MAX_TTL_MS}),
        ] {
            assert!(parse_report(report(extra).as_bytes(), now).is_ok());
        }
        let ahead = parse_report(
            report(json!({"observedAt": (now + skew).to_rfc3339()})).as_bytes(),
            now,
        )
        .unwrap();
        assert_eq!(ahead.observed_at, now);

        for body in [
            r#"{"source":"ci_reported","observedAt":"yesterday"}"#,
            r#"{"source":"ci_reported","ttlMs":"5"}"#,
            r#"{"source":"ci_reported","cacheScope":7}"#,
        ] {
            let (status, b) = refusal(body.to_string(), now).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{b}");
            assert_eq!(b["error"], "mcp_invalid_capabilities", "{b}");
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
        let vs: Vec<String> = ["1.0.0", "1.2.0", "2.0.0", "1.10.0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
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
        let vp = version_path(&q(&[
            ("repo_key", "r"),
            ("ns", "com.acme"),
            ("name", "x"),
            ("version", "1"),
        ]));
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
        let (k, w) =
            parse_claim(br#"{"kinds":["sandbox_run","sandbox_run"],"workerId":"w1"}"#).unwrap();
        assert_eq!(k, vec![JobKind::SandboxRun]);
        assert_eq!(w, "w1");
        for b in [
            &br#"{"kinds":[]}"#[..],
            br#"{"kinds":["x"]}"#,
            br#"{"kinds":"x"}"#,
            b"{",
        ] {
            assert!(parse_claim(b).is_err());
        }
        let mut a = crate::api::handlers::test_db_helpers::make_auth(Uuid::nil(), "w");
        assert!(
            !is_introspector(&a),
            "interactive credentials do not qualify"
        );
        a.scopes = Some(vec!["*".into()]);
        assert!(
            !is_introspector(&a),
            "a wildcard token is not the dedicated credential"
        );
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
        meta.insert(
            caps::CAPABILITIES_META_KEY.into(),
            json!({"tools": [{"name": "a"}]}),
        );
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
    use crate::models::access_scope::AccessScope;
    use axum::body::Body;
    use axum::http::{header, Request};

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
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

    /// The job queue and the snapshot retention pass are global: the tests
    /// that claim, re-queue or prune take this lock so they do not hand each
    /// other's jobs out or count each other's re-queues.
    static QUEUE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
            self.worker_with(scopes, AccessScope::Admin)
        }
        /// An `mcp:introspect` service-account token restricted to `repos`,
        /// with no broader instance privilege (#5460).
        fn scoped_worker(&self, repos: Vec<Uuid>) -> Router {
            self.worker_with(
                Some(vec![INTROSPECT_SCOPE.into()]),
                AccessScope::Restricted(repos),
            )
        }
        fn worker_with(&self, scopes: Option<Vec<String>>, repos: AccessScope) -> Router {
            let mut a = tdh::make_auth(self.fx.user_id, &self.fx.username);
            a.is_api_token = true;
            a.is_service_account = true;
            a.scopes = scopes;
            a.allowed_repo_ids = repos;
            tdh::router_with_auth(worker_router(), self.fx.state.clone(), a)
        }
        fn url(&self, tail: &str) -> String {
            format!(
                "/{}/v0.1/servers/com.acme%2Fweather/versions/1.0.0/capabilities{tail}",
                self.fx.repo_key
            )
        }
        async fn publish(&self, version: &str) {
            self.publish_doc(doc(version, json!({"tools": [{"name": "get_weather"}]})))
                .await;
        }
        async fn publish_doc(&self, doc: Value) {
            let publish = format!("/{}/v0.1/publish", self.fx.repo_key);
            let (s, b) = call(self.admin(), "POST", &publish, Some(doc)).await;
            assert_eq!(s, StatusCode::OK, "{b}");
        }
        fn introspector(&self) -> Router {
            self.worker(Some(vec![INTROSPECT_SCOPE.into()]))
        }
        /// An `mcp:introspect` token, unrestricted, of another principal
        /// `user` (#5465).
        fn introspector_as(&self, user: Uuid, username: &str) -> Router {
            let mut a = tdh::make_auth(user, username);
            a.is_api_token = true;
            a.is_service_account = true;
            a.scopes = Some(vec![INTROSPECT_SCOPE.into()]);
            a.allowed_repo_ids = AccessScope::Admin;
            tdh::router_with_auth(worker_router(), self.fx.state.clone(), a)
        }
        /// Users recorded on the `MCP_CAPABILITIES_INGESTED` audit rows of
        /// `artifact_id`'s `remote_probe` snapshots, waiting up to `wait` for the fire-and-forget write.
        async fn ingest_audits(
            &self,
            artifact_id: Uuid,
            want: usize,
            wait: std::time::Duration,
        ) -> Vec<Option<Uuid>> {
            let deadline = std::time::Instant::now() + wait;
            loop {
                let users: Vec<Option<Uuid>> = sqlx::query_scalar(
                    "SELECT user_id FROM audit_log \
                     WHERE action = 'MCP_CAPABILITIES_INGESTED' AND resource_id = $1 \
                       AND details->>'source' = 'remote_probe'",
                )
                .bind(artifact_id)
                .fetch_all(&self.fx.pool)
                .await
                .unwrap();
                if users.len() >= want || std::time::Instant::now() >= deadline {
                    return users;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        /// `POST /jobs/{job}/complete` as the introspector.
        async fn complete(&self, job: Uuid, result: Value) -> (StatusCode, Value) {
            let uri = format!("/jobs/{job}/complete");
            call(self.introspector(), "POST", &uri, Some(result)).await
        }
        /// The current view of version 1.0.0, as a reader sees it.
        async fn current(&self) -> Value {
            let (s, b) = call(self.admin(), "GET", &self.url(""), None).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b["current"].clone()
        }
        async fn artifact(&self, version: &str) -> Uuid {
            sqlx::query_scalar(
                "SELECT id FROM artifacts WHERE repository_id = $1 \
                   AND name = 'com.acme/weather' AND version = $2",
            )
            .bind(self.fx.repo_id)
            .bind(version)
            .fetch_one(&self.fx.pool)
            .await
            .unwrap()
        }
        /// Claim the open probe of `artifact_id` with `token`, without the
        /// global claim query (which could hand out another test's job).
        async fn claim_probe(&self, artifact_id: Uuid, token: &str) -> jobs::JobRow {
            self.claim_target(artifact_id, "remote:0", token).await
        }
        /// [`Self::claim_probe`] of the probe of remote `target`, queueing it
        /// first when no job of it is open. The claim is held by this
        /// fixture's user, the principal of [`Self::introspector`] (#5465).
        async fn claim_target(&self, artifact_id: Uuid, target: &str, token: &str) -> jobs::JobRow {
            self.claim_target_as(artifact_id, target, token, Some(self.fx.user_id))
                .await
        }
        /// [`Self::claim_target`], held by `owner` (`None`: a claim taken
        /// before migration 338 recorded owners).
        async fn claim_target_as(
            &self,
            artifact_id: Uuid,
            target: &str,
            token: &str,
            owner: Option<Uuid>,
        ) -> jobs::JobRow {
            jobs::enqueue_for_artifact(&self.fx.pool, artifact_id, None)
                .await
                .unwrap();
            let id: Uuid = sqlx::query_scalar(
                "UPDATE mcp_introspection_jobs SET status = 'claimed', \
                   attempts = attempts + 1, claimed_by = 'test', claimed_at = NOW(), \
                   lease_expires_at = NOW() + INTERVAL '10 minutes', claim_token_hash = $3, \
                   claimed_by_user_id = $4 \
                 WHERE artifact_id = $1 AND kind = 'remote_probe' AND target_key = $2 \
                   AND status = 'pending' \
                 RETURNING id",
            )
            .bind(artifact_id)
            .bind(target)
            .bind(caps::sha256_hex(token.as_bytes()))
            .bind(owner)
            .fetch_one(&self.fx.pool)
            .await
            .unwrap();
            jobs::get_job(&self.fx.pool, id).await.unwrap().unwrap()
        }
        async fn exec(&self, sql: &'static str, id: Uuid) {
            sqlx::query(sql)
                .bind(id)
                .execute(&self.fx.pool)
                .await
                .unwrap();
        }
        async fn snapshots(&self, artifact_id: Uuid, source: Source) -> i64 {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM mcp_capability_snapshots \
                 WHERE artifact_id = $1 AND source = $2",
            )
            .bind(artifact_id)
            .bind(source.as_str())
            .fetch_one(&self.fx.pool)
            .await
            .unwrap()
        }
        async fn cleanup(self) {
            for sql in [
                "DELETE FROM mcp_introspection_jobs WHERE repository_id = $1",
                "DELETE FROM repository_config WHERE repository_id = $1",
                "DELETE FROM packages WHERE repository_id = $1",
            ] {
                let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(self.fx.repo_id)
                    .execute(&self.fx.pool)
                    .await;
            }
            self.fx.teardown().await;
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
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        let publish = format!("/{}/v0.1/publish", env.fx.repo_key);
        // A malformed declaration is refused at publish.
        let (s, b) = call(
            env.admin(),
            "POST",
            &publish,
            Some(doc("0.9.0", json!({"tools": [{}]}))),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, b) = call(
            env.admin(),
            "POST",
            &publish,
            Some(doc(
                "1.0.0",
                json!({"tools": [{"name": "get_weather", "description": "Forecast"}]}),
            )),
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
        let (s, _) = call(
            env.anon(),
            "GET",
            &env.url("").replace("1.0.0", "9.9.9"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // CI reports; the second one differs: tool_drift.
        let report =
            |tools: Value| json!({"source": "ci_reported", "generatedBy": "gha", "tools": tools});
        let (s, b) = call(env.anon(), "POST", &env.url(""), Some(report(json!([])))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{b}");
        let (s, b) = call(
            env.admin(),
            "POST",
            &env.url(""),
            Some(json!({"source": "remote_probe"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, b) = call(
            env.admin(),
            "POST",
            &env.url(""),
            Some(report(json!([{"name": "get_weather"}]))),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert!(b["drift"].is_null());
        assert!(b["snapshot"]["provenance"]
            .as_str()
            .unwrap()
            .starts_with("reported by CI ("));
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
        // The reported tools are linted onto the server.json artifact under
        // their own source.
        let titles: Vec<String> = sqlx::query_scalar(
            "SELECT f.title FROM scan_findings f JOIN scan_results r ON r.id = f.scan_result_id \
             WHERE r.repository_id = $1 AND r.scan_type = 'mcp_lint' \
               AND f.source = 'mcp_lint/capabilities:ci_reported'",
        )
        .bind(env.fx.repo_id)
        .fetch_all(&env.fx.pool)
        .await
        .unwrap();
        assert!(
            titles.iter().any(|t| t == "mcp_lint/destructive_tool"),
            "{titles:?}"
        );

        // Diff: default is against the previous CI report.
        let (s, b) = call(env.anon(), "GET", &env.url("/diff"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["to"]["source"], "ci_reported");
        assert_eq!(b["summary"]["tools"]["added"], 1);
        assert_eq!(b["summary"]["destructiveAdded"], json!(["delete_city"]));
        let (s, b) = call(
            env.anon(),
            "GET",
            &env.url(&format!("/diff?from={declared_id}")),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["from"]["id"], declared_id);
        assert_eq!(b["summary"]["tools"]["changed"], 1, "{b}");
        let (s, _) = call(
            env.anon(),
            "GET",
            &env.url("/diff?source=sandbox_run"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = call(env.anon(), "GET", &env.url("?source=nope"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, b) = call(
            env.anon(),
            "GET",
            &env.url(&format!("?snapshot={declared_id}&limit=1")),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["current"]["id"], declared_id);
        assert_eq!(b["snapshots"].as_array().unwrap().len(), 1);

        // Probing is opt-in.
        let (s, b) = call(env.admin(), "POST", &env.url("/probe"), None).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
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
        let (s, job) = call(
            w.clone(),
            "POST",
            "/jobs/claim",
            Some(json!({"kinds": ["remote_probe"]})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{job}");
        assert_eq!(job["target"]["url"], "https://mcp.acme.test/mcp");
        let id = job["jobId"].as_str().unwrap();
        let (s, _) = call(w.clone(), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "one open job per target");
        let complete = format!("/jobs/{id}/complete");
        let (s, _) = call(
            w.clone(),
            "POST",
            &complete,
            Some(json!({"claimToken": "wrong", "outcome": "ok"})),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        // A transient failure goes back to the queue.
        let (s, b) = call(
            w.clone(),
            "POST",
            &complete,
            Some(json!({"claimToken": job["claimToken"], "outcome": "timeout"})),
        )
        .await;
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
        let (s, _) = call(
            w,
            "POST",
            &complete,
            Some(json!({"claimToken": job["claimToken"], "outcome": "ok"})),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::CONFLICT,
            "a completed job cannot be completed again"
        );
        let (_, b) = call(env.anon(), "GET", &env.url(""), None).await;
        assert_eq!(
            b["current"]["source"], "remote_probe",
            "an observation is the current view"
        );

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

    /// Review finding 4: a capability report runs the MCP namespace write
    /// gate (`mcp_require_namespace_grant`, `conditions.mcp_namespaces`).
    #[tokio::test]
    async fn capability_reports_run_the_namespace_gate() {
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        let publish = format!("/{}/v0.1/publish", env.fx.repo_key);
        let (s, b) = call(
            env.admin(),
            "POST",
            &publish,
            Some(doc("1.0.0", json!({"tools": [{"name": "get_weather"}]}))),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let member = || {
            tdh::router_with_auth(
                surface::router(),
                env.fx.state.clone(),
                tdh::make_auth(env.fx.user_id, &env.fx.username),
            )
        };
        let report = json!({"source": "ci_reported", "tools": [{"name": "get_weather"}]});
        // A plain repository member may report.
        let (s, b) = call(member(), "POST", &env.url(""), Some(report.clone())).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        // Under mcp_require_namespace_grant the plain write no longer does.
        env.config(
            crate::services::mcp_settings::REQUIRE_NAMESPACE_GRANT_KEY,
            "true",
        )
        .await;
        let (s, b) = call(member(), "POST", &env.url(""), Some(report.clone())).await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("mcp_namespace_not_granted")),
            "{b}"
        );
        // A grant for another namespace does not help; a matching one does.
        let rule = tdh::grant_permission(
            &env.fx.pool,
            "user",
            env.fx.user_id,
            "repository",
            env.fx.repo_id,
            &["write"],
        )
        .await;
        let set_ns = |ns: &'static str| {
            sqlx::query("UPDATE permissions SET conditions = $2 WHERE id = $1")
                .bind(rule)
                .bind(json!({"mcp_namespaces": [ns]}))
                .execute(&env.fx.pool)
        };
        set_ns("com.other").await.unwrap();
        let (s, _) = call(member(), "POST", &env.url(""), Some(report.clone())).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        set_ns("com.acme").await.unwrap();
        let (s, b) = call(member(), "POST", &env.url(""), Some(report)).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");

        for sql in [
            "DELETE FROM permissions WHERE target_id = $1",
            "DELETE FROM repository_config WHERE repository_id = $1",
            "DELETE FROM packages WHERE repository_id = $1",
        ] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(env.fx.repo_id)
                .execute(&env.fx.pool)
                .await;
        }
        env.fx.teardown().await;
    }

    /// #5543: through the endpoint, a CI or gateway report whose
    /// observation or cache metadata is out of bounds answers `400
    /// mcp_invalid_result_metadata` with the offending `field`, like a worker
    /// result (#5466), and stores no snapshot.
    #[tokio::test]
    async fn invalid_report_metadata_stores_nothing() {
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.publish("1.0.0").await;
        let version = env.artifact("1.0.0").await;
        let skew = chrono::Duration::seconds(caps::OBSERVED_AT_SKEW_SECS);
        let far = (Utc::now() + skew + chrono::Duration::seconds(60)).to_rfc3339();
        let tools = json!([{"name": "tainted"}]);
        for (source, report, field) in [
            (
                Source::CiReported,
                json!({"source": "ci_reported", "tools": tools, "ttlMs": jobs::MAX_TTL_MS + 1}),
                "ttlMs",
            ),
            (
                Source::GatewayReported,
                json!({"source": "gateway_reported", "tools": tools, "observedAt": far}),
                "observedAt",
            ),
            (
                Source::CiReported,
                json!({"source": "ci_reported", "tools": tools, "cacheScope": "shared"}),
                "cacheScope",
            ),
        ] {
            let (s, b) = call(env.admin(), "POST", &env.url(""), Some(report.clone())).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{report}: {b}");
            assert_eq!(b["error"], "mcp_invalid_result_metadata", "{b}");
            assert_eq!(b["field"], field, "{b}");
            assert_eq!(env.snapshots(version, source).await, 0, "{report}");
        }
        assert_eq!(env.current().await["source"], "publisher_declared");
        env.cleanup().await;
    }

    /// Review finding 13: a remote probe of a held version is never handed
    /// to the worker (the same servability gate as a sandbox run).
    #[tokio::test]
    async fn probes_of_held_versions_are_not_handed_out() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        let publish = format!("/{}/v0.1/publish", env.fx.repo_key);
        let (s, b) = call(
            env.admin(),
            "POST",
            &publish,
            Some(doc("1.0.0", json!({"tools": [{"name": "get_weather"}]}))),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        let (s, b) = call(env.admin(), "POST", &env.url("/probe"), None).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let artifact_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND name = 'com.acme/weather'",
        )
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        let job = jobs::list_jobs(&env.fx.pool, artifact_id, 5)
            .await
            .unwrap()
            .into_iter()
            .find(|j| j.kind() == Some(JobKind::RemoteProbe))
            .expect("a queued probe");
        let claim = jobs::Claim {
            job,
            token: "t".into(),
        };
        let base = "http://localhost";
        assert!(
            claim_payload(&env.fx.state, &claim, base)
                .await
                .unwrap()
                .is_ok(),
            "a servable version's probe is handed out"
        );
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_source = 'admin' \
             WHERE id = $1",
        )
        .bind(artifact_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(
            claim_payload(&env.fx.state, &claim, base).await.unwrap(),
            Err(Unclaimable::Cancel("server version is held".to_string()))
        );
        for sql in [
            "DELETE FROM mcp_introspection_jobs WHERE repository_id = $1",
            "DELETE FROM repository_config WHERE repository_id = $1",
            "DELETE FROM packages WHERE repository_id = $1",
        ] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(env.fx.repo_id)
                .execute(&env.fx.pool)
                .await;
        }
        env.fx.teardown().await;
    }

    fn probe_snapshot(
        env: &Env,
        artifact_id: Uuid,
        origin: &str,
        tools: Value,
        outcome: Outcome,
        observed_at: DateTime<Utc>,
    ) -> NewSnapshot {
        NewSnapshot {
            repository_id: env.fx.repo_id,
            artifact_id,
            server_name: "com.acme/weather".into(),
            server_version: "1.0.0".into(),
            source: Source::RemoteProbe,
            provenance: Source::RemoteProbe.default_provenance().into(),
            origin: Some(origin.into()),
            reported_by: None,
            auth_state: AuthState::None,
            outcome,
            protocol_version: None,
            observed_at,
            ttl_ms: None,
            cache_scope: None,
            set: CapabilitySet {
                tools: tools.as_array().cloned().unwrap_or_default(),
                ..Default::default()
            },
            worker_version: None,
            details: json!({}),
        }
    }

    /// #5389: two completions of one claim (both past the handler's token
    /// check) store exactly one snapshot; the second ends nothing and is
    /// answered as an invalid claim. The retry path likewise.
    #[tokio::test]
    async fn a_duplicate_completion_stores_nothing() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let job = env.claim_probe(artifact_id, "tok-1").await;
        let ok = |tools: Value| jobs::WorkerResult {
            claim_token: "tok-1".into(),
            outcome: "ok".into(),
            tools: Some(tools),
            ..Default::default()
        };
        let r1 = ok(json!([{"name": "get_weather"}]));
        let first = jobs::complete(
            &env.fx.pool,
            &job,
            &r1,
            jobs::parse_result(&r1).unwrap(),
            env.fx.user_id,
            &AccessScope::Admin,
            true,
        )
        .await
        .unwrap();
        let jobs::Completed::Stored { snapshot, .. } = &first else {
            panic!("the first completion stores: {first:?}");
        };
        // A different list, so a deduplicated repeat cannot hide a second
        // store.
        let r2 = ok(json!([{"name": "get_weather"}, {"name": "delete_city"}]));
        let second = jobs::complete(
            &env.fx.pool,
            &job,
            &r2,
            jobs::parse_result(&r2).unwrap(),
            env.fx.user_id,
            &AccessScope::Admin,
            true,
        )
        .await
        .unwrap();
        assert!(
            matches!(second, jobs::Completed::ClaimLost),
            "a duplicate completion stores nothing: {second:?}"
        );
        assert_eq!(env.snapshots(artifact_id, Source::RemoteProbe).await, 1);
        let done = jobs::get_job(&env.fx.pool, job.id).await.unwrap().unwrap();
        assert_eq!(done.status, "completed");
        assert_eq!(done.snapshot_id, Some(snapshot.id));
        let drift_scans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1 AND scan_type = 'external'",
        )
        .bind(artifact_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(drift_scans, 0, "no drift from a lost claim");

        // The retry path respects the claim too.
        let queued = jobs::enqueue_for_artifact(&env.fx.pool, artifact_id, None)
            .await
            .unwrap();
        assert_eq!(queued.len(), 1);
        let job = env.claim_probe(artifact_id, "tok-2").await;
        let timeout = jobs::WorkerResult {
            claim_token: "tok-2".into(),
            outcome: "timeout".into(),
            ..Default::default()
        };
        let parsed = jobs::parse_result(&timeout).unwrap();
        let first = jobs::complete(
            &env.fx.pool,
            &job,
            &timeout,
            parsed.clone(),
            env.fx.user_id,
            &AccessScope::Admin,
            true,
        )
        .await
        .unwrap();
        assert!(matches!(first, jobs::Completed::Retry { .. }), "{first:?}");
        let second = jobs::complete(
            &env.fx.pool,
            &job,
            &timeout,
            parsed,
            env.fx.user_id,
            &AccessScope::Admin,
            true,
        )
        .await
        .unwrap();
        assert!(
            matches!(second, jobs::Completed::ClaimLost),
            "a duplicate retry ends nothing: {second:?}"
        );
        env.cleanup().await;
    }

    /// The job row fields a denied claim or completion must leave alone.
    async fn job_state(
        pool: &PgPool,
        id: Uuid,
    ) -> (
        String,
        i32,
        Option<String>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    ) {
        let j = jobs::get_job(pool, id).await.unwrap().unwrap();
        (
            j.status,
            j.attempts,
            j.claim_token_hash,
            j.snapshot_id,
            j.completed_at,
        )
    }

    /// #5460: an `mcp:introspect` worker scoped to private repository A can
    /// neither claim nor complete private repository B's job, whatever claim
    /// token it holds, and a scope change between claim and completion is
    /// honoured at completion. Same-repository work and the cross-job token
    /// check are unaffected.
    #[tokio::test]
    async fn a_repository_scoped_worker_cannot_cross_repositories() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fa) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let Some(fb) = tdh::Fixture::setup("local", "mcp").await else {
            fa.teardown().await;
            return;
        };
        let (a, b) = (Env { fx: fa }, Env { fx: fb });
        let private: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repositories WHERE id = ANY($1) AND is_public = false",
        )
        .bind(vec![a.fx.repo_id, b.fx.repo_id])
        .fetch_one(&a.fx.pool)
        .await
        .unwrap();
        assert_eq!(private, 2, "both repositories are private");
        // Only B probes at first: its version gets a pending job, A's none.
        b.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        a.publish("1.0.0").await;
        b.publish("1.0.0").await;
        let (art_a, art_b) = (a.artifact("1.0.0").await, b.artifact("1.0.0").await);
        let job_b: Uuid = sqlx::query_scalar(
            "SELECT id FROM mcp_introspection_jobs WHERE artifact_id = $1 AND status = 'pending'",
        )
        .bind(art_b)
        .fetch_one(&b.fx.pool)
        .await
        .unwrap();
        let worker_a = || a.scoped_worker(vec![a.fx.repo_id]);
        let pool = &a.fx.pool;

        // Claim: B's due job is never handed to the A-scoped worker.
        let before = job_state(pool, job_b).await;
        let (s, body) = call(worker_a(), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "B's job handed to A: {body}");
        assert_eq!(job_state(pool, job_b).await, before, "B's job unchanged");
        assert_eq!(before.0, "pending");

        // Completion: with B's claim token in hand (here forged, and held by
        // the A worker's own principal, so the claim-owner check of #5465
        // passes and the repository scope is what refuses), the A-scoped
        // worker still stores nothing, for a result or a retry.
        b.claim_target_as(art_b, "remote:0", "tok-b", Some(a.fx.user_id))
            .await;
        let claimed = job_state(pool, job_b).await;
        let complete_b = format!("/jobs/{job_b}/complete");
        for result in [
            json!({"claimToken": "tok-b", "outcome": "ok",
                   "tools": [{"name": "exfiltrate"}]}),
            json!({"claimToken": "tok-b", "outcome": "timeout"}),
        ] {
            let (s, body) = call(worker_a(), "POST", &complete_b, Some(result)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
            assert_eq!(body["error"], "mcp_forbidden", "{body}");
            assert_eq!(job_state(pool, job_b).await, claimed, "B's claim untouched");
        }
        assert_eq!(b.snapshots(art_b, Source::RemoteProbe).await, 0);
        let (_, caps_b) = call(b.admin(), "GET", &b.url(""), None).await;
        assert_eq!(caps_b["current"]["source"], "publisher_declared");

        // The denials left B's claim current: its token still proves it.
        // (A worker other than the claimant cannot complete it either:
        // `a_claim_completes_only_for_its_owner`, #5465.)
        let still = jobs::get_job(pool, job_b).await.unwrap().unwrap();
        assert!(
            jobs::token_matches(&still, "tok-b"),
            "B's claim stays valid"
        );

        // Benign: A's own job is claimed and completed by the A worker.
        a.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        jobs::enqueue_for_artifact(pool, art_a, None).await.unwrap();
        let (s, job) = call(worker_a(), "POST", "/jobs/claim", None).await;
        assert_eq!(s, StatusCode::OK, "{job}");
        assert_eq!(job["repository"], a.fx.repo_key.as_str());
        let job_a = Uuid::parse_str(job["jobId"].as_str().unwrap()).unwrap();
        let complete_a = format!("/jobs/{job_a}/complete");
        let ok_a = json!({"claimToken": job["claimToken"], "outcome": "ok",
                          "tools": [{"name": "get_weather"}]});

        // Cross-job: another job's valid claim token (B's, still current)
        // does not complete A's.
        let (s, _) = call(
            worker_a(),
            "POST",
            &complete_a,
            Some(json!({"claimToken": "tok-b", "outcome": "ok"})),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT, "a token proves only its own job");

        // Scope change after the claim: the credential no longer covers A
        // (here: restricted to B), so the completion is refused. In
        // production the change reaches `complete` once the API-token
        // validation cache (300 s) has expired; this router carries the new
        // scope directly.
        let claimed = job_state(pool, job_a).await;
        let (s, body) = call(
            a.scoped_worker(vec![b.fx.repo_id]),
            "POST",
            &complete_a,
            Some(ok_a.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(job_state(pool, job_a).await, claimed);
        assert_eq!(a.snapshots(art_a, Source::RemoteProbe).await, 0);
        let (s, body) = call(worker_a(), "POST", &complete_a, Some(ok_a)).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "stored");
        let (_, caps_a) = call(a.admin(), "GET", &a.url(""), None).await;
        assert_eq!(caps_a["current"]["source"], "remote_probe");

        // Target binding: a job filed under A for B's server version is
        // neither handed to nor completable by the A worker.
        let forged: Uuid = sqlx::query_scalar(
            "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, target_key) \
             VALUES ($1, $2, 'remote_probe', 'remote:forged') RETURNING id",
        )
        .bind(a.fx.repo_id)
        .bind(art_b)
        .fetch_one(pool)
        .await
        .unwrap();
        let (s, body) = call(worker_a(), "POST", "/jobs/claim", None).await;
        assert_eq!(
            s,
            StatusCode::NO_CONTENT,
            "mis-bound job handed out: {body}"
        );
        sqlx::query(
            "UPDATE mcp_introspection_jobs SET status = 'claimed', attempts = 1, \
               lease_expires_at = NOW() + INTERVAL '10 minutes', claim_token_hash = $2, \
               claimed_by_user_id = $3 \
             WHERE id = $1",
        )
        .bind(forged)
        .bind(caps::sha256_hex(b"tok-forged"))
        .bind(a.fx.user_id)
        .execute(pool)
        .await
        .unwrap();
        let claimed = job_state(pool, forged).await;
        let (s, body) = call(
            worker_a(),
            "POST",
            &format!("/jobs/{forged}/complete"),
            Some(json!({"claimToken": "tok-forged", "outcome": "ok"})),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(job_state(pool, forged).await, claimed);
        assert_eq!(b.snapshots(art_b, Source::RemoteProbe).await, 0);

        a.cleanup().await;
        b.cleanup().await;
    }

    /// #5460: the repository filter sits in the claim's candidate selection,
    /// not after it. An older out-of-scope job queued ahead of a due
    /// in-scope one does not shadow it: the A worker gets A's job, not `204`,
    /// and B's job is left pending.
    #[tokio::test]
    async fn a_scoped_worker_skips_older_out_of_scope_jobs() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fa) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let Some(fb) = tdh::Fixture::setup("local", "mcp").await else {
            fa.teardown().await;
            return;
        };
        let (a, b) = (Env { fx: fa }, Env { fx: fb });
        a.publish("1.0.0").await;
        b.publish("1.0.0").await;
        let pool = &a.fx.pool;
        // Neither repository has a claimed job, so the fair ordering ties and
        // B's job, due decades earlier, is first in line.
        let mut queued = Vec::new();
        for (env, due) in [(&b, "1999-01-01"), (&a, "2000-01-01")] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, \
                   target_key, not_before, created_at) \
                 VALUES ($1, $2, 'remote_probe', 'remote:0', $3::timestamptz, $3::timestamptz) \
                 RETURNING id",
            )
            .bind(env.fx.repo_id)
            .bind(env.artifact("1.0.0").await)
            .bind(due)
            .fetch_one(pool)
            .await
            .unwrap();
            queued.push(id);
        }
        let (job_b, job_a) = (queued[0], queued[1]);
        let before = job_state(pool, job_b).await;
        let (s, job) = call(
            a.scoped_worker(vec![a.fx.repo_id]),
            "POST",
            "/jobs/claim",
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{job}");
        assert_eq!(job["jobId"], job_a.to_string());
        assert_eq!(job_state(pool, job_b).await, before, "B's job untouched");
        assert_eq!(before.0, "pending");
        a.cleanup().await;
        b.cleanup().await;
    }

    fn ok_result(token: &str, tools: Value) -> Value {
        json!({"claimToken": token, "outcome": "ok", "tools": tools})
    }

    async fn snapshot_count(env: &Env, artifact_id: Uuid) -> i64 {
        env.snapshots(artifact_id, Source::RemoteProbe).await
    }

    /// Post every result in `results` to `job` at once, deterministically
    /// interleaved: a side connection holds the job row `FOR UPDATE` while
    /// the completions pass the handler's token check and pre-check and
    /// queue on the claim lock (as many as the fixture pool lets open a
    /// transaction), and only then lets them go. Without the claim lock's
    /// re-check (#5389) every queued completion would store.
    async fn race(env: &Env, job: Uuid, results: Vec<Value>) -> Vec<(StatusCode, Value)> {
        // Two side connections: the lock holder, and a poller outside its
        // transaction (`pg_stat_activity` is a snapshot within one).
        let side = crate::testing::try_pool_with(2).await.expect("side pool");
        let mut holder = side.begin().await.unwrap();
        sqlx::query("SELECT id FROM mcp_introspection_jobs WHERE id = $1 FOR UPDATE")
            .bind(job)
            .execute(&mut *holder)
            .await
            .unwrap();
        let queued = results
            .len()
            .min(env.fx.pool.options().get_max_connections() as usize);
        assert!(queued >= 2, "a race needs two queued completions");
        let uri = format!("/jobs/{job}/complete");
        let tasks: Vec<_> = results
            .into_iter()
            .map(|r| {
                let (app, uri) = (env.introspector(), uri.clone());
                tokio::spawn(async move { call(app, "POST", &uri, Some(r)).await })
            })
            .collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock' \
                   AND query LIKE '%FROM mcp_introspection_jobs j%FOR UPDATE OF j%'",
            )
            .fetch_one(&side)
            .await
            .unwrap();
            if waiting as usize >= queued {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {waiting} of {queued} completions queued on the claim lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        holder.commit().await.unwrap();
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    }

    /// #5461: concurrent completions of one claim, identical and divergent,
    /// through the HTTP handler and queued together on the claim lock
    /// ([`race`]): exactly one stores, every other one is the claim conflict
    /// and stores nothing. A transient retry racing a
    /// successful result never leaves a stored snapshot behind a pending job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_completions_of_one_claim_have_one_winner() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let job = env.claim_probe(artifact_id, "tok-race").await;
        let weather = json!([{"name": "get_weather"}]);
        let results = vec![
            ok_result("tok-race", weather.clone()),
            ok_result("tok-race", weather.clone()),
            ok_result("tok-race", json!([{"name": "get_weather"}, {"name": "rm"}])),
            ok_result("tok-race", json!([{"name": "other"}])),
        ];
        let answers = race(&env, job.id, results).await;
        let stored: Vec<&Value> = answers
            .iter()
            .filter(|(s, _)| *s == StatusCode::OK)
            .map(|(_, b)| b)
            .collect();
        assert_eq!(stored.len(), 1, "exactly one winner: {answers:?}");
        assert_eq!(stored[0]["status"], "stored");
        for (s, b) in answers.iter().filter(|(s, _)| *s != StatusCode::OK) {
            assert_eq!(*s, StatusCode::CONFLICT, "{b}");
            assert_eq!(b["error"], "mcp_claim_invalid", "{b}");
        }
        assert_eq!(snapshot_count(&env, artifact_id).await, 1);
        let done = jobs::get_job(&env.fx.pool, job.id).await.unwrap().unwrap();
        assert_eq!(done.status, "completed");
        assert_eq!(
            done.snapshot_id.map(|id| id.to_string()),
            stored[0]["snapshotId"].as_str().map(String::from)
        );

        // Retry against success: whichever wins, no snapshot behind a
        // pending job.
        for round in 0..2 {
            let before = snapshot_count(&env, artifact_id).await;
            let token = format!("tok-retry-{round}");
            let job = env.claim_probe(artifact_id, &token).await;
            let answers = race(
                &env,
                job.id,
                vec![
                    json!({"claimToken": token, "outcome": "timeout"}),
                    ok_result(&token, json!([{"name": format!("t{round}")}])),
                ],
            )
            .await;
            let winners: Vec<&Value> = answers
                .iter()
                .filter(|(s, _)| *s == StatusCode::OK)
                .map(|(_, b)| b)
                .collect();
            assert_eq!(winners.len(), 1, "round {round}: {answers:?}");
            let after = jobs::get_job(&env.fx.pool, job.id).await.unwrap().unwrap();
            let added = snapshot_count(&env, artifact_id).await - before;
            match winners[0]["status"].as_str() {
                Some("stored") => {
                    assert_eq!((after.status.as_str(), added), ("completed", 1));
                    assert!(after.snapshot_id.is_some());
                }
                Some("retry") => {
                    assert_eq!((after.status.as_str(), added), ("pending", 0));
                    assert!(after.snapshot_id.is_none());
                    // Free the target for the next round.
                    env.exec(
                        "UPDATE mcp_introspection_jobs SET status = 'cancelled' WHERE id = $1",
                        job.id,
                    )
                    .await;
                }
                other => panic!("round {round}: {other:?}"),
            }
        }
        env.cleanup().await;
    }

    /// #5463 review: a job whose gates cannot be evaluated is released, not
    /// cancelled, with a doubling backoff; the first `RELEASE_REFUNDS`
    /// releases hand the attempt back, later ones spend it, and a job out of
    /// attempts fails instead of cycling forever.
    #[tokio::test]
    async fn released_jobs_back_off_and_eventually_fail() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let max = jobs::RELEASE_REFUNDS + 3;
        let mut last_delay = 0;
        for n in 0..max {
            let job = env.claim_probe(artifact_id, &format!("tok-rel-{n}")).await;
            let before = Utc::now();
            let status = jobs::release(&env.fx.pool, &job, "gate unavailable")
                .await
                .unwrap()
                .expect("the current claim is released");
            let after = jobs::get_job(&env.fx.pool, job.id).await.unwrap().unwrap();
            let refunded = n < jobs::RELEASE_REFUNDS;
            assert_eq!(
                after.attempts,
                if refunded {
                    job.attempts - 1
                } else {
                    job.attempts
                },
                "release {n}"
            );
            if !refunded && job.attempts >= job.max_attempts {
                assert_eq!(status, "failed", "release {n}");
                assert!(after.completed_at.is_some());
                break;
            }
            assert_eq!(status, "pending", "release {n}");
            let delay = jobs::release_delay_secs(n);
            assert!(delay >= last_delay, "backoff grows");
            last_delay = delay;
            let due = (after.not_before - before).num_seconds();
            assert!(
                (delay - 2..=delay + 2).contains(&due),
                "release {n}: {due} vs {delay}"
            );
            // Due now, for the next round's claim.
            env.exec(
                "UPDATE mcp_introspection_jobs SET not_before = NOW() WHERE id = $1",
                job.id,
            )
            .await;
            assert!(n + 1 < max, "the job never failed");
        }
        // A release of a claim that is no longer current changes nothing.
        let stale = jobs::JobRow {
            claim_token_hash: Some("gone".into()),
            ..jobs::list_jobs(&env.fx.pool, artifact_id, 1).await.unwrap()[0].clone()
        };
        assert_eq!(
            jobs::release(&env.fx.pool, &stale, "x").await.unwrap(),
            None
        );
        assert_eq!(
            jobs::release_delay_secs(100),
            60 << jobs::RELEASE_BACKOFF_CAP
        );
        env.cleanup().await;
    }

    /// #5462: a claim whose lease has expired cannot complete, for a result
    /// or a retry, even though the reaper has not run: nothing is stored and
    /// the job is left for the reaper, which returns it to the queue. A live
    /// lease completes.
    #[tokio::test]
    async fn an_expired_claim_cannot_complete_before_the_reaper_runs() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let job = env.claim_probe(artifact_id, "tok-old").await;
        env.exec(
            "UPDATE mcp_introspection_jobs SET lease_expires_at = NOW() - INTERVAL '1 second' \
             WHERE id = $1",
            job.id,
        )
        .await;
        let expired = job_state(&env.fx.pool, job.id).await;
        for result in [
            ok_result("tok-old", json!([{"name": "get_weather"}])),
            json!({"claimToken": "tok-old", "outcome": "timeout"}),
        ] {
            let (s, b) = env.complete(job.id, result).await;
            assert_eq!(s, StatusCode::CONFLICT, "{b}");
            assert_eq!(b["error"], "mcp_claim_invalid", "{b}");
            assert_eq!(job_state(&env.fx.pool, job.id).await, expired);
        }
        assert_eq!(snapshot_count(&env, artifact_id).await, 0);
        assert_eq!(env.current().await["source"], "publisher_declared");
        jobs::reap_expired(&env.fx.pool).await.unwrap();
        let reaped = jobs::get_job(&env.fx.pool, job.id).await.unwrap().unwrap();
        assert_eq!(reaped.status, "pending");

        // Benign: a live lease completes.
        let job = env.claim_probe(artifact_id, "tok-live").await;
        let (s, b) = env
            .complete(
                job.id,
                ok_result("tok-live", json!([{"name": "get_weather"}])),
            )
            .await;
        assert_eq!(
            (s, b["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{b}"
        );
        assert_eq!(env.current().await["source"], "remote_probe");
        env.cleanup().await;
    }

    /// #5463: a target that changes after the claim is revalidated when the
    /// result arrives. The version quarantined, rejected, marked deleted or
    /// deleted, or its backing package quarantined or deleted: the result is
    /// refused with `409 mcp_target_ineligible`, nothing is stored, the job
    /// is cancelled and the current view is unchanged. The in-transaction
    /// half refuses even when the serve gate passed just before. A worker
    /// whose repository scope was revoked gets `403` and changes nothing. An
    /// unchanged target completes. (Holder-visible capability state only:
    /// nothing here is about serving the package.)
    #[tokio::test]
    async fn completion_revalidates_the_target_after_the_claim() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        let pool = env.fx.pool.clone();
        let (npm_id, npm_key, npm_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let mut npm = tdh::make_repo_info(npm_id, &npm_key, &npm_dir, "local", None);
        npm.format = "npm".into();
        let package = tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &pool,
            &npm,
            "npm/echo-1.0.0.tgz",
            "@acme/echo/-/echo-1.0.0.tgz",
            "@acme/echo",
            "1.0.0",
            "application/octet-stream",
            Bytes::from_static(b"tgz"),
            env.fx.user_id,
            &"e".repeat(64),
        )
        .await;
        env.config(crate::services::mcp_packages::POLICY_KEY, "open")
            .await;
        env.config(
            crate::services::mcp_packages::REPOS_KEY,
            &json!({"npm": npm_key}).to_string(),
        )
        .await;
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        let mut d = doc("1.0.0", json!({"tools": [{"name": "get_weather"}]}));
        d["packages"] = json!([{"registryType": "npm", "identifier": "@acme/echo",
            "version": "1.0.0", "transport": {"type": "stdio"}}]);
        env.publish_doc(d).await;
        let version = env.artifact("1.0.0").await;
        let pinned: i64 = sqlx::query_scalar(
            "SELECT COALESCE(jsonb_array_length(metadata->'packages'), 0)::bigint FROM artifact_metadata \
             WHERE artifact_id = $1",
        )
        .bind(version)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pinned, 1, "the package is pinned");

        let variants: [(&str, &'static str, &'static str, Uuid); 6] = [
            (
                "version quarantined",
                "UPDATE artifacts SET quarantine_status = 'quarantined' WHERE id = $1",
                "UPDATE artifacts SET quarantine_status = NULL WHERE id = $1",
                version,
            ),
            (
                "version rejected",
                "UPDATE artifacts SET quarantine_status = 'rejected' WHERE id = $1",
                "UPDATE artifacts SET quarantine_status = NULL WHERE id = $1",
                version,
            ),
            (
                "registry status deleted",
                "UPDATE artifact_metadata SET metadata = \
                   jsonb_set(metadata, '{registry,status}', '\"deleted\"') WHERE artifact_id = $1",
                "UPDATE artifact_metadata SET metadata = \
                   jsonb_set(metadata, '{registry,status}', '\"active\"') WHERE artifact_id = $1",
                version,
            ),
            (
                "version deleted",
                "UPDATE artifacts SET is_deleted = true WHERE id = $1",
                "UPDATE artifacts SET is_deleted = false WHERE id = $1",
                version,
            ),
            (
                "backing package quarantined",
                "UPDATE artifacts SET quarantine_status = 'quarantined' WHERE id = $1",
                "UPDATE artifacts SET quarantine_status = NULL WHERE id = $1",
                package,
            ),
            (
                "backing artifact deleted",
                "UPDATE artifacts SET is_deleted = true WHERE id = $1",
                "UPDATE artifacts SET is_deleted = false WHERE id = $1",
                package,
            ),
        ];
        let result = |token: &str| ok_result(token, json!([{"name": "exfiltrate"}]));
        for (i, (what, mutate, restore, id)) in variants.into_iter().enumerate() {
            let token = format!("tok-gate-{i}");
            let job = env.claim_probe(version, &token).await;
            env.exec(mutate, id).await;
            let (s, b) = env.complete(job.id, result(&token)).await;
            assert_eq!(s, StatusCode::CONFLICT, "{what}: {b}");
            assert_eq!(b["error"], "mcp_target_ineligible", "{what}: {b}");
            let after = jobs::get_job(&pool, job.id).await.unwrap().unwrap();
            assert_eq!(after.status, "cancelled", "{what}");
            assert!(after.snapshot_id.is_none(), "{what}");
            assert_eq!(snapshot_count(&env, version).await, 0, "{what}");
            env.exec(restore, id).await;
            assert_eq!(
                env.current().await["source"],
                "publisher_declared",
                "{what}"
            );
        }

        // The serve gate passed before the change landed: the transaction's
        // own re-read still refuses.
        for (what, id) in [("version", version), ("backing package", package)] {
            let token = format!("tok-late-{what}");
            let job = env.claim_probe(version, &token).await;
            env.exec(
                "UPDATE artifacts SET quarantine_status = 'quarantined' WHERE id = $1",
                id,
            )
            .await;
            let r: jobs::WorkerResult = serde_json::from_value(result(&token)).unwrap();
            let parsed = jobs::parse_result(&r).unwrap();
            let out = jobs::complete(
                &pool,
                &job,
                &r,
                parsed,
                env.fx.user_id,
                &AccessScope::Admin,
                true,
            )
            .await
            .unwrap();
            assert!(
                matches!(out, jobs::Completed::Ineligible { .. }),
                "{what}: {out:?}"
            );
            assert_eq!(snapshot_count(&env, version).await, 0, "{what}");
            env.exec(
                "UPDATE artifacts SET quarantine_status = NULL WHERE id = $1",
                id,
            )
            .await;
        }

        // The worker's repository scope revoked: 403, the claim untouched.
        let job = env.claim_probe(version, "tok-acl").await;
        let claimed = job_state(&pool, job.id).await;
        let (s, b) = call(
            env.scoped_worker(vec![Uuid::new_v4()]),
            "POST",
            &format!("/jobs/{}/complete", job.id),
            Some(result("tok-acl")),
        )
        .await;
        assert_eq!(
            (s, b["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("mcp_forbidden"))
        );
        assert_eq!(job_state(&pool, job.id).await, claimed);
        assert_eq!(snapshot_count(&env, version).await, 0);

        // Unchanged: the same claim completes.
        let (s, b) = env.complete(job.id, result("tok-acl")).await;
        assert_eq!(
            (s, b["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{b}"
        );
        assert_eq!(env.current().await["source"], "remote_probe");

        env.exec("DELETE FROM packages WHERE repository_id = $1", npm_id)
            .await;
        tdh::cleanup_member_repo(&pool, npm_id, &npm_dir).await;
        env.cleanup().await;
    }

    /// #5464: the current view follows validated `observedAt` freshness, not
    /// arrival. A probe observed earlier but completed later is stored as
    /// history (`current: false`) and does not replace the fresher one; a
    /// later, fresher observation does. An `observedAt` in the future or
    /// before the job's claim is refused and leaves the claim as it was.
    #[tokio::test]
    async fn a_stale_observation_never_replaces_a_fresher_current_one() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        let mut d = doc("1.0.0", json!({"tools": [{"name": "get_weather"}]}));
        d["remotes"] = json!([
            {"type": "streamable-http", "url": "https://mcp.acme.test/mcp"},
            {"type": "streamable-http", "url": "https://mcp2.acme.test/mcp"},
        ]);
        env.publish_doc(d).await;
        let version = env.artifact("1.0.0").await;
        let stale = env.claim_target(version, "remote:0", "tok-stale").await;
        let fresh = env.claim_target(version, "remote:1", "tok-fresh").await;
        let now = Utc::now();
        let at = |r: Value, t: DateTime<Utc>| {
            let mut r = r;
            r["observedAt"] = json!(t);
            r
        };
        let (s, fresh_body) = env
            .complete(
                fresh.id,
                at(ok_result("tok-fresh", json!([{"name": "fresh"}])), now),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{fresh_body}");
        let older = now - chrono::Duration::minutes(2);
        let (s, b) = env
            .complete(
                stale.id,
                at(ok_result("tok-stale", json!([{"name": "stale"}])), older),
            )
            .await;
        assert_eq!(
            (s, b["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{b}"
        );
        let current = env.current().await;
        assert_eq!(current["tools"][0]["name"], "fresh", "{current}");
        assert_eq!(snapshot_count(&env, version).await, 2, "history kept");
        assert_eq!(fresh_body["current"], true, "{fresh_body}");
        assert_eq!(b["current"], false, "a stale observation is history: {b}");
        let drift_scans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1 AND scan_type = 'external'",
        )
        .bind(version)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(drift_scans, 0, "history raises no drift");

        // Out-of-window timestamps are refused; the claim stays.
        let job = env.claim_target(version, "remote:0", "tok-next").await;
        let claimed = job_state(&env.fx.pool, job.id).await;
        for t in [
            now + chrono::Duration::hours(1),
            now - chrono::Duration::days(1),
        ] {
            let (s, b) = env
                .complete(job.id, at(ok_result("tok-next", json!([{"name": "x"}])), t))
                .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
            assert_eq!(job_state(&env.fx.pool, job.id).await, claimed);
        }
        // A later, fresher observation becomes current.
        let (s, b) = env
            .complete(
                job.id,
                at(
                    ok_result("tok-next", json!([{"name": "newest"}])),
                    Utc::now(),
                ),
            )
            .await;
        assert_eq!(
            (s, b["current"].as_bool()),
            (StatusCode::OK, Some(true)),
            "{b}"
        );
        assert_eq!(env.current().await["tools"][0]["name"], "newest");
        // A stored failure is never the current view.
        let job = env.claim_target(version, "remote:1", "tok-fail").await;
        let (s, b) = env
            .complete(
                job.id,
                json!({"claimToken": "tok-fail", "outcome": "auth_required"}),
            )
            .await;
        assert_eq!(
            (s, b["current"].as_bool()),
            (StatusCode::OK, Some(false)),
            "{b}"
        );
        assert_eq!(env.current().await["tools"][0]["name"], "newest");
        env.cleanup().await;
    }

    /// #5465: a claim is bound to the principal that took it. Another
    /// `mcp:introspect` worker holding the claim token gets exactly the
    /// wrong-token `409 mcp_claim_invalid`, for a result or a retry, valid
    /// or invalid, through the handler and the service alike; nothing is
    /// stored, audited or ended, and the claimant still completes, audited
    /// as itself. A claim with no recorded owner (taken before migration
    /// 338) is completable by no one and is reaped as usual.
    #[tokio::test]
    async fn a_claim_completes_only_for_its_owner() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let version = env.artifact("1.0.0").await;
        let pool = env.fx.pool.clone();
        let (b_user, b_name) = tdh::create_service_account(&pool).await;
        let worker_b = || env.introspector_as(b_user, &b_name);

        // Worker A claims through the API: the claim records A.
        let (s, job) = call(
            env.introspector(),
            "POST",
            "/jobs/claim",
            Some(json!({"kinds": ["remote_probe"], "workerId": "worker-a"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{job}");
        assert_eq!(job["server"]["artifactId"], version.to_string());
        let id = Uuid::parse_str(job["jobId"].as_str().unwrap()).unwrap();
        let token = job["claimToken"].as_str().unwrap().to_string();
        let row = jobs::get_job(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.claimed_by_user_id, Some(env.fx.user_id));
        let complete = format!("/jobs/{id}/complete");

        // The reference answer: a token that is not this job's.
        let (s, wrong_token) = call(
            worker_b(),
            "POST",
            &complete,
            Some(ok_result("not-the-token", json!([{"name": "x"}]))),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT, "{wrong_token}");
        assert_eq!(wrong_token["error"], "mcp_claim_invalid");

        let claimed = job_state(&pool, id).await;
        for result in [
            ok_result(&token, json!([{"name": "foreign"}])),
            json!({"claimToken": token, "outcome": "timeout"}),
            // Invalid metadata is not even read: no oracle either way.
            json!({"claimToken": token, "outcome": "ok", "ttlMs": -1}),
            json!({"claimToken": token, "outcome": "nope"}),
        ] {
            let (s, body) = call(worker_b(), "POST", &complete, Some(result.clone())).await;
            assert_eq!(
                (s, &body),
                (StatusCode::CONFLICT, &wrong_token),
                "{result}: indistinguishable from a wrong token"
            );
            assert_eq!(job_state(&pool, id).await, claimed, "{result}");
        }
        // Past the handler (a caller that skipped `claim_matches`), the
        // transaction's claim lock refuses B too.
        let r: jobs::WorkerResult =
            serde_json::from_value(ok_result(&token, json!([{"name": "foreign"}]))).unwrap();
        let out = jobs::complete(
            &pool,
            &row,
            &r,
            jobs::parse_result(&r).unwrap(),
            b_user,
            &AccessScope::Admin,
            true,
        )
        .await
        .unwrap();
        assert!(matches!(out, jobs::Completed::ClaimLost), "{out:?}");
        assert_eq!(job_state(&pool, id).await, claimed);
        assert_eq!(snapshot_count(&env, version).await, 0);
        assert_eq!(env.current().await["source"], "publisher_declared");

        // A, the owner, completes its claim; the snapshot and the audit
        // record name A.
        let (s, body) = call(
            env.introspector(),
            "POST",
            &complete,
            Some(ok_result(&token, json!([{"name": "get_weather"}]))),
        )
        .await;
        assert_eq!(
            (s, body["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{body}"
        );
        let reported_by: Option<Uuid> =
            sqlx::query_scalar("SELECT reported_by FROM mcp_capability_snapshots WHERE id = $1")
                .bind(Uuid::parse_str(body["snapshotId"].as_str().unwrap()).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reported_by, Some(env.fx.user_id));
        let audits = env
            .ingest_audits(version, 1, std::time::Duration::from_secs(5))
            .await;
        assert_eq!(
            audits,
            vec![Some(env.fx.user_id)],
            "audited as the completing worker"
        );
        assert_eq!(snapshot_count(&env, version).await, 1);

        // A claim without a recorded owner: no one completes it, and the
        // reaper returns it to the queue once its lease expires.
        let unowned = env
            .claim_target_as(version, "remote:0", "tok-legacy", None)
            .await;
        let claimed = job_state(&pool, unowned.id).await;
        for worker in [env.introspector(), worker_b()] {
            let (s, body) = call(
                worker,
                "POST",
                &format!("/jobs/{}/complete", unowned.id),
                Some(ok_result("tok-legacy", json!([{"name": "legacy"}]))),
            )
            .await;
            assert_eq!((s, &body), (StatusCode::CONFLICT, &wrong_token));
        }
        assert_eq!(job_state(&pool, unowned.id).await, claimed);
        env.exec(
            "UPDATE mcp_introspection_jobs SET lease_expires_at = NOW() - INTERVAL '1 second' \
             WHERE id = $1",
            unowned.id,
        )
        .await;
        jobs::reap_expired(&pool).await.unwrap();
        let reaped = jobs::get_job(&pool, unowned.id).await.unwrap().unwrap();
        assert_eq!(reaped.status, "pending");
        assert_eq!(snapshot_count(&env, version).await, 1);

        env.cleanup().await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(b_user)
            .execute(&pool)
            .await;
    }

    /// #5466: a result whose observation or cache metadata is invalid (an
    /// `observedAt` beyond the clock-skew window, an unknown `cacheScope`, a
    /// negative or too large `ttlMs`) is refused with `400
    /// mcp_invalid_result_metadata` before anything is locked: no snapshot,
    /// no current-view change, no audit, no job transition, and the claim
    /// stays usable, so the worker's corrected result then completes. The
    /// boundaries (in-window future `observedAt`, `ttlMs` 0 and the cap, both
    /// scopes) are accepted.
    #[tokio::test]
    async fn invalid_result_metadata_stores_nothing() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        let version = env.artifact("1.0.0").await;
        let pool = env.fx.pool.clone();
        let job = env.claim_probe(version, "tok-meta").await;
        let claimed = job_state(&pool, job.id).await;
        let skew = chrono::Duration::seconds(caps::OBSERVED_AT_SKEW_SECS);
        let with = |extra: Value| {
            let mut r = ok_result("tok-meta", json!([{"name": "tainted"}]));
            for (k, v) in extra.as_object().unwrap() {
                r[k] = v.clone();
            }
            r
        };
        let far = Utc::now() + chrono::Duration::days(365);
        let past_skew = Utc::now() + skew + chrono::Duration::seconds(60);
        for (result, field) in [
            (with(json!({"cacheScope": "shared"})), "cacheScope"),
            (with(json!({"cacheScope": "PUBLIC"})), "cacheScope"),
            (with(json!({"ttlMs": -1})), "ttlMs"),
            (with(json!({"ttlMs": jobs::MAX_TTL_MS + 1})), "ttlMs"),
            (with(json!({"ttlMs": i64::MAX})), "ttlMs"),
            (with(json!({"observedAt": far})), "observedAt"),
            (with(json!({"observedAt": past_skew})), "observedAt"),
            // A retry carries no snapshot, but its metadata is checked too.
            (
                json!({"claimToken": "tok-meta", "outcome": "timeout", "ttlMs": -5}),
                "ttlMs",
            ),
        ] {
            let (s, b) = env.complete(job.id, result.clone()).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{result}: {b}");
            assert_eq!(b["error"], "mcp_invalid_result_metadata", "{b}");
            assert_eq!(b["field"], field, "{b}");
            assert_eq!(job_state(&pool, job.id).await, claimed, "{result}");
            assert_eq!(snapshot_count(&env, version).await, 0, "{result}");
        }
        // The service entry point refuses before it locks anything: with the
        // job row locked elsewhere it still answers at once.
        let side = crate::testing::try_pool_with(1).await.expect("side pool");
        let mut holder = side.begin().await.unwrap();
        sqlx::query("SELECT id FROM mcp_introspection_jobs WHERE id = $1 FOR UPDATE")
            .bind(job.id)
            .execute(&mut *holder)
            .await
            .unwrap();
        let r: jobs::WorkerResult =
            serde_json::from_value(with(json!({"cacheScope": "shared"}))).unwrap();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            jobs::complete(
                &pool,
                &job,
                &r,
                jobs::parse_result(&r).unwrap(),
                env.fx.user_id,
                &AccessScope::Admin,
                true,
            ),
        )
        .await
        .expect("refused without waiting on the claim lock")
        .unwrap();
        assert!(
            matches!(&out, jobs::Completed::Invalid(e) if e.path == "cacheScope"),
            "{out:?}"
        );
        holder.rollback().await.unwrap();
        assert_eq!(env.current().await["source"], "publisher_declared");
        assert!(
            env.ingest_audits(version, 1, std::time::Duration::from_millis(500))
                .await
                .is_empty(),
            "no audit record for a refused result"
        );

        // The claim stayed usable: the corrected result completes. An
        // `observedAt` inside the skew window is stored as of its arrival;
        // `ttlMs` 0 and `private` are valid.
        let ahead = Utc::now() + chrono::Duration::seconds(60);
        let (s, b) = env
            .complete(
                job.id,
                with(json!({"observedAt": ahead, "ttlMs": 0, "cacheScope": "private"})),
            )
            .await;
        assert_eq!(
            (s, b["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{b}"
        );
        let (observed_at, ttl_ms, scope): (DateTime<Utc>, Option<i64>, Option<String>) =
            sqlx::query_as(
                "SELECT observed_at, ttl_ms, cache_scope FROM mcp_capability_snapshots \
                 WHERE id = $1",
            )
            .bind(Uuid::parse_str(b["snapshotId"].as_str().unwrap()).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(observed_at < ahead, "clamped to arrival: {observed_at}");
        assert_eq!((ttl_ms, scope.as_deref()), (Some(0), Some("private")));
        // The cap and `public` are valid too.
        let job = env.claim_probe(version, "tok-cap").await;
        let (s, b) = env
            .complete(
                job.id,
                json!({"claimToken": "tok-cap", "outcome": "ok", "tools": [{"name": "capped"}],
                       "ttlMs": jobs::MAX_TTL_MS, "cacheScope": "public"}),
            )
            .await;
        assert_eq!(
            (s, b["status"].as_str()),
            (StatusCode::OK, Some("stored")),
            "{b}"
        );
        assert_eq!(snapshot_count(&env, version).await, 2);
        env.cleanup().await;
    }

    /// #5386: a snapshot repeating the newest one of its (version, source,
    /// origin) bumps `last_seen_at` instead of adding a row, with no drift; a
    /// different one is a new row.
    #[tokio::test]
    async fn repeated_snapshots_are_deduplicated() {
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let key = env.fx.repo_key.clone();
        let t0 = DateTime::from_timestamp(Utc::now().timestamp() - 7200, 0).unwrap();
        let hour = chrono::Duration::hours(1);
        let a = json!([{"name": "get_weather"}]);
        let b = json!([{"name": "get_weather"}, {"name": "delete_city"}]);
        let snap = |tools: &Value, outcome, at| {
            probe_snapshot(&env, artifact_id, "remote:0", tools.clone(), outcome, at)
        };

        let (first, drift) = caps::store(&env.fx.pool, &snap(&a, Outcome::Ok, t0), &key)
            .await
            .unwrap();
        assert!(first.created && drift.is_none());
        let (again, drift) = caps::store(&env.fx.pool, &snap(&a, Outcome::Ok, t0 + hour), &key)
            .await
            .unwrap();
        assert!(!again.created, "the same content is not stored twice");
        assert!(drift.is_none());
        assert_eq!(again.snapshot.id, first.snapshot.id);
        assert_eq!(again.snapshot.observed_at, t0);
        assert_eq!(again.snapshot.last_seen_at, Some(t0 + hour));
        assert_eq!(
            again.snapshot.summary_json()["lastSeenAt"],
            json!(t0 + hour)
        );
        assert_eq!(env.snapshots(artifact_id, Source::RemoteProbe).await, 1);

        let (changed, drift) =
            caps::store(&env.fx.pool, &snap(&b, Outcome::Ok, t0 + hour * 2), &key)
                .await
                .unwrap();
        assert!(changed.created);
        assert_ne!(changed.snapshot.id, first.snapshot.id);
        assert!(drift.is_some(), "a changed list still drifts");
        assert_eq!(env.snapshots(artifact_id, Source::RemoteProbe).await, 2);

        // A failed attempt repeats too; another origin is its own history.
        let empty = json!([]);
        let (t1, _) = caps::store(
            &env.fx.pool,
            &snap(&empty, Outcome::Timeout, t0 + hour * 3),
            &key,
        )
        .await
        .unwrap();
        let (t2, _) = caps::store(
            &env.fx.pool,
            &snap(&empty, Outcome::Timeout, t0 + hour * 4),
            &key,
        )
        .await
        .unwrap();
        assert!(t1.created && !t2.created);
        let other = probe_snapshot(&env, artifact_id, "remote:1", b.clone(), Outcome::Ok, t0);
        let (o, _) = caps::store(&env.fx.pool, &other, &key).await.unwrap();
        assert!(o.created, "dedupe is per origin");
        assert_eq!(env.snapshots(artifact_id, Source::RemoteProbe).await, 4);

        // A CI report that repeats the previous one answers `created: false`.
        let report = json!({"source": "ci_reported", "generatedBy": "gha",
                            "tools": [{"name": "get_weather"}]});
        let (s, r1) = call(env.admin(), "POST", &env.url(""), Some(report.clone())).await;
        assert_eq!(s, StatusCode::CREATED, "{r1}");
        assert_eq!(r1["created"], true);
        let (s, r2) = call(env.admin(), "POST", &env.url(""), Some(report)).await;
        assert_eq!(s, StatusCode::CREATED, "{r2}");
        assert_eq!(r2["created"], false);
        assert_eq!(r2["snapshot"]["id"], r1["snapshot"]["id"]);
        assert!(r2["drift"].is_null());
        assert_eq!(env.snapshots(artifact_id, Source::CiReported).await, 1);
        env.cleanup().await;
    }

    /// #5386: the scheduler pass keeps the newest `SNAPSHOT_KEEP` snapshots
    /// per (version, source, origin) plus every one still referenced: the
    /// newest successful one, one a drift finding names, one the newest job
    /// of the target points at.
    #[tokio::test]
    async fn snapshot_history_is_pruned_to_the_retention_limit() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.publish("1.0.0").await;
        let artifact_id = env.artifact("1.0.0").await;
        let key = env.fx.repo_key.clone();
        let pool = env.fx.pool.clone();
        let now = Utc::now();
        // A then B: a drift finding naming both; B is the newest ok one.
        let (a, _) = caps::store(
            &pool,
            &probe_snapshot(
                &env,
                artifact_id,
                "remote:0",
                json!([{"name": "a"}]),
                Outcome::Ok,
                now,
            ),
            &key,
        )
        .await
        .unwrap();
        let (b, drift) = caps::store(
            &pool,
            &probe_snapshot(
                &env,
                artifact_id,
                "remote:0",
                json!([{"name": "b"}]),
                Outcome::Ok,
                now,
            ),
            &key,
        )
        .await
        .unwrap();
        assert!(drift.is_some());
        let insert_failed = |days_ago: i64| {
            let pool = pool.clone();
            let repo = env.fx.repo_id;
            async move {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO mcp_capability_snapshots (repository_id, artifact_id, \
                       server_name, server_version, source, provenance, origin, outcome, \
                       observed_at, tools_hash, content_hash, created_at) \
                     VALUES ($1, $2, 'com.acme/weather', '1.0.0', 'remote_probe', 'p', \
                       'remote:0', 'timeout', NOW(), 'x', 'x', \
                       NOW() - make_interval(secs => $3)) RETURNING id",
                )
                .bind(repo)
                .bind(artifact_id)
                .bind(days_ago as f64 * 86400.0)
                .fetch_one(&pool)
                .await
                .unwrap();
                id
            }
        };
        for (id, days) in [(a.snapshot.id, 10.0), (b.snapshot.id, 9.0)] {
            sqlx::query(
                "UPDATE mcp_capability_snapshots SET \
                   created_at = NOW() - make_interval(secs => $2) WHERE id = $1",
            )
            .bind(id)
            .bind(days * 86400.0)
            .execute(&pool)
            .await
            .unwrap();
        }
        let by_newest_job = insert_failed(8).await;
        let by_older_job = insert_failed(7).await;
        for i in 0..25 {
            sqlx::query(
                "INSERT INTO mcp_capability_snapshots (repository_id, artifact_id, \
                   server_name, server_version, source, provenance, origin, outcome, \
                   observed_at, tools_hash, content_hash, created_at) \
                 VALUES ($1, $2, 'com.acme/weather', '1.0.0', 'remote_probe', 'p', \
                   'remote:0', 'timeout', NOW(), 'x', 'x', \
                   NOW() - INTERVAL '1 day' + make_interval(secs => $3))",
            )
            .bind(env.fx.repo_id)
            .bind(artifact_id)
            .bind(i as f64)
            .execute(&pool)
            .await
            .unwrap();
        }
        let mut job_ids = Vec::new();
        for (snapshot, days) in [(by_older_job, 3.0), (by_newest_job, 2.0)] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, \
                   target_key, status, snapshot_id, completed_at, created_at) \
                 VALUES ($1, $2, 'remote_probe', 'remote:0', 'completed', $3, NOW(), \
                   NOW() - make_interval(secs => $4)) RETURNING id",
            )
            .bind(env.fx.repo_id)
            .bind(artifact_id)
            .bind(snapshot)
            .bind(days * 86400.0)
            .fetch_one(&pool)
            .await
            .unwrap();
            job_ids.push(id);
        }
        assert_eq!(env.snapshots(artifact_id, Source::RemoteProbe).await, 29);

        jobs::scheduler_tick(&pool).await;
        let keep = caps::SNAPSHOT_KEEP;
        assert_eq!(
            env.snapshots(artifact_id, Source::RemoteProbe).await,
            keep + 3,
            "the newest {keep} plus the three referenced rows"
        );
        for (id, why) in [
            (a.snapshot.id, "named by the drift finding"),
            (b.snapshot.id, "the newest successful snapshot"),
            (by_newest_job, "the newest job's snapshot"),
        ] {
            assert!(
                caps::get_snapshot(&pool, id).await.unwrap().is_some(),
                "{why} is kept"
            );
        }
        assert!(caps::get_snapshot(&pool, by_older_job)
            .await
            .unwrap()
            .is_none());
        let older = jobs::get_job(&pool, job_ids[0]).await.unwrap().unwrap();
        assert_eq!(
            older.snapshot_id, None,
            "the foreign key clears the reference"
        );
        assert_eq!(older.status, "completed");
        // The declared history is its own group, untouched.
        assert_eq!(
            env.snapshots(artifact_id, Source::PublisherDeclared).await,
            1
        );
        // Idempotent.
        jobs::scheduler_tick(&pool).await;
        assert_eq!(
            env.snapshots(artifact_id, Source::RemoteProbe).await,
            keep + 3
        );
        env.cleanup().await;
    }

    /// #5386: due re-probes are queued for each server's latest version and
    /// recently published versions only.
    #[tokio::test]
    async fn reprobes_skip_old_versions() {
        let _queue = QUEUE_LOCK.lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let env = Env { fx };
        env.config(crate::services::mcp_settings::PROBE_KEY, "hosted_only")
            .await;
        env.publish("1.0.0").await;
        env.publish("2.0.0").await;
        let (v1, v2) = (env.artifact("1.0.0").await, env.artifact("2.0.0").await);
        // Every probe done 7 h ago; both versions published 60 days ago, so
        // only 2.0.0 (the latest) is due.
        sqlx::query(
            "UPDATE mcp_introspection_jobs SET status = 'completed', \
               completed_at = NOW() - INTERVAL '7 hours', claim_token_hash = NULL \
             WHERE repository_id = $1",
        )
        .bind(env.fx.repo_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let published = |id: Uuid, days: i32| {
            let pool = env.fx.pool.clone();
            async move {
                sqlx::query(
                    "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, \
                       '{registry,publishedAt}', to_jsonb(to_char((NOW() - make_interval(days => $2)) \
                       AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))) \
                     WHERE artifact_id = $1",
                )
                .bind(id)
                .bind(days)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
        published(v1, 60).await;
        published(v2, 60).await;
        let pending = |id: Uuid| {
            let pool = env.fx.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM mcp_introspection_jobs \
                     WHERE artifact_id = $1 AND status = 'pending'",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let latest: Vec<(String, Option<bool>)> = sqlx::query_as(
            "SELECT a.version, (m.metadata->'registry'->>'isLatest')::boolean FROM artifacts a \
             JOIN artifact_metadata m ON m.artifact_id = a.id WHERE a.repository_id = $1 \
             ORDER BY a.version",
        )
        .bind(env.fx.repo_id)
        .fetch_all(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(
            latest,
            vec![
                (String::from("1.0.0"), Some(false)),
                (String::from("2.0.0"), Some(true))
            ]
        );
        jobs::requeue_due_probes(&env.fx.pool).await.unwrap();
        assert_eq!(pending(v2).await, 1, "the latest version is re-probed");
        assert_eq!(pending(v1).await, 0, "an old version is not");
        // A version published in the window is re-probed.
        published(v1, jobs::REPROBE_RECENT_DAYS - 25).await;
        jobs::requeue_due_probes(&env.fx.pool).await.unwrap();
        assert_eq!(pending(v1).await, 1, "a recent version is re-probed");
        env.cleanup().await;
    }
}
