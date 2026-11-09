//! Agent Plugins repository handlers (#5251).
//!
//! Hosts AI coding-agent plugin bundles (Claude Code, Cursor, Codex,
//! GitHub Copilot / VS Code, Agent Plugins Standard) as one zip per version
//! and generates the marketplace documents those agents and the `ak` CLI read.
//!
//! Routes are mounted at `/agentplugins`:
//!
//!   PUT  /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip   - Publish (raw zip body)
//!   GET  /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip   - Download (also HEAD)
//!   GET  /agentplugins/{repo}/marketplace.json                        - Unified index
//!   GET  /agentplugins/{repo}/claude-marketplace.json                 - Claude Code marketplace
//!   GET  /agentplugins/{repo}/{cursor,codex,vscode}-marketplace.json  - Per-harness indexes
//!   GET  /agentplugins/{repo}/{name}/index.json                       - Versions of one plugin
//!   GET  /agentplugins/t/{token}/{repo}/...                           - Every read route above,
//!                                                                       token in the path (D8)
//!
//! A hosted repository builds the documents from the database on every
//! request (D7), so a delete or a quarantine hold is reflected immediately;
//! they carry an `ETag` and answer `If-None-Match` with `304`. A Remote
//! repository (#5289) proxies another Artifact Keeper's hosted repository:
//! its documents are fetched through the proxy service and rewritten to point
//! at this instance (the upstream `sha256` is kept), and its archives are
//! fetched, checked against that `sha256`, and cached. Virtual repositories
//! are not supported yet. Protocol reference: `docs/agent-plugins.md`.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH,
};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::middleware::download_telemetry::DownloadContext;
use crate::api::SharedState;
use crate::formats::agent_plugins::{
    self as ap, IndexContext, IndexedVersion, Marketplace, PluginMetadata, FORMAT_KEY,
};
use crate::models::repository::RepositoryType;
use crate::util::bounded_archive;

/// Request header carrying the client's SHA-256 of the uploaded zip.
const CHECKSUM_HEADER: &str = "x-checksum-sha256";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/:document", get(document))
        .route("/:repo_key/:name/index.json", get(versions_index))
        .route(
            "/:repo_key/:name/:version/:file",
            get(download).put(publish_plugin),
        )
        .merge(token_router())
}

/// The read routes again under `/t/{token}` (D8). The visibility middleware
/// authenticates the path token (`agentplugins_url_token`), and every URL the
/// documents generate keeps the prefix, so a Claude Code marketplace added
/// from a token URL also downloads its archives with it. Token URLs carry a
/// secret: no shared cache may keep them and no Referer may leak them.
fn token_router() -> Router<SharedState> {
    Router::new()
        .route("/t/:token/:repo_key/:document", get(document_with_token))
        .route(
            "/t/:token/:repo_key/:name/index.json",
            get(versions_index_with_token),
        )
        .route(
            "/t/:token/:repo_key/:name/:version/:file",
            get(download_with_token),
        )
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                let headers = response.headers_mut();
                headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
                headers.insert(CACHE_CONTROL, "private, no-store".parse().unwrap());
                response
            },
        ))
}

// ---------------------------------------------------------------------------
// Repository resolution and shared helpers
// ---------------------------------------------------------------------------

/// Virtual Agent Plugins repositories have no merge rule yet (#5289 phase 2).
#[allow(clippy::result_large_err)]
fn reject_if_virtual(repo: &RepoInfo) -> Result<(), Response> {
    if repo.repo_type == RepositoryType::Virtual {
        return Err((
            StatusCode::BAD_REQUEST,
            "Agent Plugins virtual repositories are not supported yet; use a hosted or \
             remote repository",
        )
            .into_response());
    }
    Ok(())
}

async fn resolve_agentplugins_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo =
        proxy_helpers::resolve_repo_by_key(db, repo_key, &[FORMAT_KEY], "an Agent Plugins").await?;
    reject_if_virtual(&repo)?;
    Ok(repo)
}

fn is_remote(repo: &RepoInfo) -> bool {
    repo.repo_type == RepositoryType::Remote
}

/// A token route must have authenticated through its path token. The
/// visibility middleware validates the token and injects the caller; a
/// token route reached with no caller never presented a usable credential.
#[allow(clippy::result_large_err)]
fn require_token_caller(auth: &Option<AuthExtension>) -> Result<(), Response> {
    if auth.is_some() {
        return Ok(());
    }
    Err(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"agentplugins\"")
        .body(Body::from("A valid token is required in the URL path"))
        .unwrap())
}

fn not_found(what: &str) -> Response {
    (StatusCode::NOT_FOUND, format!("{what} not found")).into_response()
}

/// The rows the format serves: written by a native publish (or replicated
/// from one, which carries the same metadata document), so their
/// `artifact_metadata.format` is `agentplugins` and their path is exactly the
/// canonical `{name}/{version}/{name}-{version}.zip`. Anything else in the
/// repository (a generic REST upload under another path, or one with no
/// agent-plugin metadata) was never validated as a bundle and is neither
/// indexed nor downloaded through `/agentplugins` (#5251 review M2).
const ARCHIVE_ROWS_SQL: &str = "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
            a.storage_key, a.created_at, am.metadata, a.quarantine_status, a.quarantine_until \
     FROM artifacts a \
     JOIN artifact_metadata am ON am.artifact_id = a.id \
     WHERE a.repository_id = $1 AND a.is_deleted = false \
       AND am.format = 'agentplugins' AND a.version IS NOT NULL \
       AND a.path = a.name || '/' || a.version || '/' || a.name || '-' || a.version || '.zip' \
       AND ($2::text IS NULL OR a.path = $2) \
     ORDER BY a.name, a.version, a.created_at, a.id";

#[derive(sqlx::FromRow)]
struct ArchiveRow {
    id: Uuid,
    name: String,
    version: String,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    created_at: chrono::DateTime<chrono::Utc>,
    metadata: serde_json::Value,
    quarantine_status: Option<String>,
    quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Native archive rows of a repository, or the one at `path`.
async fn archive_rows(
    db: &PgPool,
    repo_id: Uuid,
    path: Option<&str>,
) -> Result<Vec<ArchiveRow>, Response> {
    sqlx::query_as::<_, ArchiveRow>(ARCHIVE_ROWS_SQL)
        .bind(repo_id)
        .bind(path)
        .fetch_all(db)
        .await
        .map_err(crate::api::handlers::db_err)
}

/// Whether any enabled scan policy applies to the repository. A read error
/// answers `true`, which only costs the per-row policy evaluation.
async fn scan_policy_applies(db: &PgPool, repo_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM scan_policies sp WHERE sp.is_enabled = true \
           AND (sp.repository_id = $1 OR sp.repository_id IS NULL))",
    )
    .bind(repo_id)
    .fetch_one(db)
    .await
    .unwrap_or(true)
}

/// The download gate for one archive: quarantine and upload holds, then the
/// scan policy (`block_unscanned`, `block_on_fail`, `max_severity`), exactly
/// as `quarantine_service::enforce_download_gate` decides it. The download
/// handler AND the index builder call this one function, so an index never
/// advertises a version its download refuses (#5251 review M1).
async fn archive_gate(
    db: &PgPool,
    repo_id: Uuid,
    row: &ArchiveRow,
    policy_applies: bool,
) -> crate::error::Result<()> {
    crate::services::quarantine_service::enforce_download_gate_for_row(
        db,
        &crate::services::quarantine_service::DownloadGateRow {
            artifact_id: row.id,
            repository_id: repo_id,
            quarantine_status: row.quarantine_status.as_deref(),
            quarantine_until: row.quarantine_until,
            scan_policy_applies: policy_applies,
        },
    )
    .await
}

/// Every servable version in the repository: native archive rows whose
/// download the gate would allow. A refused version is left out before the
/// documents pick each plugin's latest version, so the newest version that
/// can actually be downloaded is the one advertised.
async fn servable_versions(db: &PgPool, repo_id: Uuid) -> Result<Vec<IndexedVersion>, Response> {
    let rows = archive_rows(db, repo_id, None).await?;
    let policy_applies = scan_policy_applies(db, repo_id).await;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if ap::parse_semver(&row.version).is_err()
            || archive_gate(db, repo_id, &row, policy_applies)
                .await
                .is_err()
        {
            continue;
        }
        let Ok(metadata) = serde_json::from_value::<PluginMetadata>(row.metadata) else {
            continue;
        };
        out.push(IndexedVersion {
            name: row.name,
            version: row.version,
            sha256: row.checksum_sha256,
            size_bytes: row.size_bytes,
            published_at: row.created_at,
            metadata,
        });
    }
    Ok(out)
}

async fn repo_description(db: &PgPool, repo_id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT description FROM repositories WHERE id = $1")
        .bind(repo_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

fn index_context(
    base_url: &RequestBaseUrl,
    repo_key: &str,
    description: Option<String>,
    token: Option<String>,
) -> IndexContext {
    IndexContext {
        repo_key: repo_key.to_string(),
        description,
        origin: base_url.as_str().trim_end_matches('/').to_string(),
        token,
    }
}

/// Serve a generated JSON document with an ETag, answering a matching
/// `If-None-Match` with `304`. `no-cache` lets a cache keep the document but
/// forces revalidation, so a delete or a hold is seen on the next read (the
/// token router overrides it with `private, no-store`).
fn json_document(headers: &HeaderMap, doc: &serde_json::Value) -> Response {
    let body = serde_json::to_vec_pretty(doc).unwrap_or_default();
    let etag = ap::document_etag(&body);
    let matched = headers
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| ap::if_none_match_matches(v, &etag));
    let builder = Response::builder()
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, "no-cache");
    if matched {
        return builder
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap();
    }
    builder
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

// ---------------------------------------------------------------------------
// GET marketplace documents and {name}/index.json
// ---------------------------------------------------------------------------

/// What a read route needs besides its own path parameters.
struct ReadRequest {
    state: SharedState,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    token: Option<String>,
}

async fn serve_document(req: ReadRequest, repo_key: String, document: String) -> Response {
    let Some(kind) = Marketplace::ALL
        .into_iter()
        .find(|m| m.file_name() == document)
    else {
        return not_found("Document");
    };
    let repo = match resolve_agentplugins_repo(&req.state.db, &repo_key).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if is_remote(&repo) {
        return remote::serve_document(req, repo, kind)
            .await
            .unwrap_or_else(|resp| resp);
    }
    let versions = match servable_versions(&req.state.db, repo.id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let description = repo_description(&req.state.db, repo.id).await;
    let ctx = index_context(&req.base_url, &repo_key, description, req.token);
    json_document(&req.headers, &ap::build_marketplace(kind, &ctx, &versions))
}

async fn serve_versions_index(req: ReadRequest, repo_key: String, name: String) -> Response {
    let repo = match resolve_agentplugins_repo(&req.state.db, &repo_key).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if is_remote(&repo) {
        return remote::serve_versions_index(req, repo, name)
            .await
            .unwrap_or_else(|resp| resp);
    }
    let versions = match servable_versions(&req.state.db, repo.id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ctx = index_context(&req.base_url, &repo_key, None, req.token);
    match ap::build_versions_index(&name, &ctx, &versions) {
        Some(doc) => json_document(&req.headers, &doc),
        None => not_found("Plugin"),
    }
}

async fn document(
    State(state): State<SharedState>,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    Path((repo_key, document)): Path<(String, String)>,
) -> Response {
    let req = ReadRequest {
        state,
        headers,
        base_url,
        token: None,
    };
    serve_document(req, repo_key, document).await
}

async fn document_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    Path((token, repo_key, document)): Path<(String, String, String)>,
) -> Response {
    if let Err(resp) = require_token_caller(&auth) {
        return resp;
    }
    let req = ReadRequest {
        state,
        headers,
        base_url,
        token: Some(token),
    };
    serve_document(req, repo_key, document).await
}

async fn versions_index(
    State(state): State<SharedState>,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    Path((repo_key, name)): Path<(String, String)>,
) -> Response {
    let req = ReadRequest {
        state,
        headers,
        base_url,
        token: None,
    };
    serve_versions_index(req, repo_key, name).await
}

async fn versions_index_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    Path((token, repo_key, name)): Path<(String, String, String)>,
) -> Response {
    if let Err(resp) = require_token_caller(&auth) {
        return resp;
    }
    let req = ReadRequest {
        state,
        headers,
        base_url,
        token: Some(token),
    };
    serve_versions_index(req, repo_key, name).await
}

// ---------------------------------------------------------------------------
// GET / HEAD the zip
// ---------------------------------------------------------------------------

/// Serve a stored archive.
///
/// The body is ALWAYS streamed from storage by this handler, never answered
/// with a presigned redirect to S3/GCS/Azure, even when the backend can sign
/// URLs. Claude Code sends a private marketplace's configured `headers` on
/// archive downloads only on the marketplace URL's origin and drops every
/// header on a redirect to another origin, so a redirect would turn each
/// authenticated install into a 401 at the object store.
async fn serve_download(
    state: SharedState,
    method: Method,
    repo_key: String,
    (name, version, file): (String, String, String),
    ctx: DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_agentplugins_repo(&state.db, &repo_key).await?;
    if ap::validate_coordinates(&name, &version, &file).is_err() {
        return Err(not_found("Plugin archive"));
    }
    if is_remote(&repo) {
        return remote::serve_download(&state, &method, &repo, (&name, &version), &ctx).await;
    }
    let path = ap::artifact_path(&name, &version);
    let artifact = archive_rows(&state.db, repo.id, Some(&path))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| not_found("Plugin archive"))?;
    let policy_applies = scan_policy_applies(&state.db, repo.id).await;
    archive_gate(&state.db, repo.id, &artifact, policy_applies)
        .await
        .map_err(|e| e.into_response())?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"{}\"",
                ap::archive_filename(&name, &version)
            ),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-Checksum-Sha256", &artifact.checksum_sha256)
        .header(ETAG, format!("\"{}\"", artifact.checksum_sha256));
    if method == Method::HEAD {
        return Ok(response.body(Body::empty()).unwrap());
    }

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::api::handlers::storage_err_message(&e),
            )
                .into_response()
        })?;
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;
    Ok(response.body(Body::from_stream(stream)).unwrap())
}

async fn download(
    State(state): State<SharedState>,
    method: Method,
    Path((repo_key, name, version, file)): Path<(String, String, String, String)>,
    ctx: DownloadContext,
) -> Result<Response, Response> {
    serve_download(state, method, repo_key, (name, version, file), ctx).await
}

async fn download_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    method: Method,
    Path((_token, repo_key, name, version, file)): Path<(String, String, String, String, String)>,
    ctx: DownloadContext,
) -> Result<Response, Response> {
    require_token_caller(&auth)?;
    serve_download(state, method, repo_key, (name, version, file), ctx).await
}

// ---------------------------------------------------------------------------
// Remote repositories (#5289)
// ---------------------------------------------------------------------------

/// A Remote repository proxying another Artifact Keeper's hosted Agent
/// Plugins repository: `upstream_url` is `https://central/agentplugins/<key>`
/// (or the `/agentplugins/t/<token>/<key>` form), and every fetch goes
/// through the proxy service, so the upstream credentials, the upstream
/// filter, the origin policy and the proxy cache all apply as for any other
/// Remote.
///
/// Documents are fetched as mutable proxy entries and rewritten by
/// [`ap::rewrite_proxied_marketplace`] / [`ap::rewrite_proxied_versions_index`].
/// An archive is fetched only for a version the upstream `{name}/index.json`
/// lists, and the bytes must hash to the `sha256` listed there: a body that
/// does not is never cached and the download answers `502`.
mod remote {
    use super::*;
    use crate::models::repository::RepositoryFormat;
    use crate::services::proxy_service::ProxyService;

    /// Largest archive a Remote proxies: Claude Code itself refuses archives
    /// over 256 MiB. The archive is buffered (it is checked before any byte
    /// is served), under the shared proxy metadata byte budget.
    pub(super) const REMOTE_ARCHIVE_MAX_BYTES: usize = 256 * 1024 * 1024;

    fn bad_gateway(message: impl Into<String>) -> Response {
        (StatusCode::BAD_GATEWAY, message.into()).into_response()
    }

    /// The proxy service and the upstream URL of a Remote.
    #[allow(clippy::result_large_err)]
    fn upstream<'a>(
        state: &'a SharedState,
        repo: &'a RepoInfo,
    ) -> Result<(&'a ProxyService, &'a str), Response> {
        let proxy = state.proxy_service.as_deref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "The proxy service is not available",
            )
                .into_response()
        })?;
        let upstream_url = repo
            .upstream_url
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| bad_gateway("This remote repository has no upstream URL"))?;
        Ok((proxy, upstream_url))
    }

    /// Whether a proxied body carries a content coding this handler would
    /// have to undo before reading it.
    fn is_coded(content_encoding: Option<&str>) -> bool {
        content_encoding.is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"))
    }

    /// Fetch an upstream document (`path` relative to `upstream_url`) through
    /// the proxy cache, as a mutable entry, and parse it.
    async fn fetch_json(
        state: &SharedState,
        repo: &RepoInfo,
        path: &str,
    ) -> Result<serde_json::Value, Response> {
        let (proxy, upstream_url) = upstream(state, repo)?;
        let max = proxy_helpers::DEFAULT_METADATA_MAX_BYTES;
        let _budget = proxy_helpers::proxy_metadata_budget().reserve(max).await;
        let body = proxy_helpers::proxy_fetch_capped_encoded_with_format(
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            path,
            max,
            RepositoryFormat::AgentPlugins,
        )
        .await?;
        if is_coded(body.content_encoding.as_deref()) {
            return Err(bad_gateway(format!(
                "The upstream {path} arrived content coded; expected identity"
            )));
        }
        serde_json::from_slice(&body.content)
            .map_err(|e| bad_gateway(format!("The upstream {path} is not JSON: {e}")))
    }

    pub(super) async fn serve_document(
        req: ReadRequest,
        repo: RepoInfo,
        kind: Marketplace,
    ) -> Result<Response, Response> {
        let upstream_doc = fetch_json(&req.state, &repo, kind.file_name()).await?;
        let description = repo_description(&req.state.db, repo.id).await;
        let ctx = index_context(&req.base_url, &repo.key, description, req.token);
        let doc = ap::rewrite_proxied_marketplace(upstream_doc, &ctx).map_err(bad_gateway)?;
        Ok(json_document(&req.headers, &doc))
    }

    pub(super) async fn serve_versions_index(
        req: ReadRequest,
        repo: RepoInfo,
        name: String,
    ) -> Result<Response, Response> {
        if ap::validate_slug(&name).is_err() {
            return Err(not_found("Plugin"));
        }
        let upstream_doc = fetch_json(&req.state, &repo, &format!("{name}/index.json")).await?;
        let ctx = index_context(&req.base_url, &repo.key, None, req.token);
        match ap::rewrite_proxied_versions_index(upstream_doc, &name, &ctx).map_err(bad_gateway)? {
            Some(doc) => Ok(json_document(&req.headers, &doc)),
            None => Err(not_found("Plugin")),
        }
    }

    /// Whether `content` is the archive whose SHA-256 is `expected`
    /// (lowercase hex). Hashed off the async runtime.
    pub(super) async fn archive_matches(
        content: bytes::Bytes,
        content_encoding: Option<String>,
        expected: String,
    ) -> bool {
        if is_coded(content_encoding.as_deref()) {
            return false;
        }
        tokio::task::spawn_blocking(move || {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&content)) == expected
        })
        .await
        .unwrap_or(false)
    }

    /// The byte cap of one archive fetch: the size the upstream index lists,
    /// or [`REMOTE_ARCHIVE_MAX_BYTES`] when it lists none.
    #[allow(clippy::result_large_err)]
    pub(super) fn archive_cap(size_bytes: Option<u64>) -> Result<usize, Response> {
        match size_bytes {
            None => Ok(REMOTE_ARCHIVE_MAX_BYTES),
            Some(size) if size <= REMOTE_ARCHIVE_MAX_BYTES as u64 => Ok((size as usize).max(1)),
            Some(size) => Err(bad_gateway(format!(
                "The upstream archive is {size} bytes, over the {REMOTE_ARCHIVE_MAX_BYTES} \
                 bytes a remote repository proxies"
            ))),
        }
    }

    pub(super) async fn serve_download(
        state: &SharedState,
        method: &Method,
        repo: &RepoInfo,
        (name, version): (&str, &str),
        ctx: &DownloadContext,
    ) -> Result<Response, Response> {
        // The expected digest comes from the upstream's own index of the
        // plugin (a mutable proxy entry, shared with the index route).
        let index = fetch_json(state, repo, &format!("{name}/index.json")).await?;
        let archive = ap::proxied_archive(&index, name, version)
            .ok_or_else(|| not_found("Plugin archive"))?;
        let cap = archive_cap(archive.size_bytes)?;
        let builder = |len: usize| {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/zip")
                .header(
                    CONTENT_DISPOSITION,
                    format!(
                        "attachment; filename=\"{}\"",
                        ap::archive_filename(name, version)
                    ),
                )
                .header(CONTENT_LENGTH, len.to_string())
                .header("X-Checksum-Sha256", &archive.sha256)
                .header(ETAG, format!("\"{}\"", archive.sha256))
        };
        if *method == Method::HEAD {
            if let Some(size) = archive.size_bytes {
                return Ok(builder(size as usize).body(Body::empty()).unwrap());
            }
        }

        let (proxy, upstream_url) = upstream(state, repo)?;
        let fetch_path = ap::artifact_path(name, version);
        let cache_path = ap::remote_cache_path(name, version, &archive.sha256);
        let expected = archive.sha256.clone();
        let check = move |content: bytes::Bytes,
                          encoding: Option<String>|
              -> futures::future::BoxFuture<'static, bool> {
            Box::pin(archive_matches(content, encoding, expected.clone()))
        };
        let _budget = proxy_helpers::proxy_metadata_budget().reserve(cap).await;
        let body = proxy_helpers::proxy_fetch_capped_with_cache_key_encoded_format(
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            &fetch_path,
            &cache_path,
            cap,
            RepositoryFormat::AgentPlugins,
            &check,
        )
        .await?;
        // The check kept a mismatching body out of the cache; it is returned
        // anyway, and never served.
        if !archive_matches(
            body.content.clone(),
            body.content_encoding.clone(),
            archive.sha256.clone(),
        )
        .await
        {
            tracing::warn!(
                repo = %repo.key,
                plugin = name,
                version,
                "upstream agent plugin archive does not match the sha256 its index lists; refusing it"
            );
            return Err(bad_gateway(
                "The upstream archive does not match the sha256 its index lists",
            ));
        }
        let response = builder(body.content.len());
        if *method == Method::HEAD {
            return Ok(response.body(Body::empty()).unwrap());
        }
        proxy_helpers::record_proxy_download(state, repo.id, &repo.key, &cache_path, ctx).await;
        Ok(response.body(Body::from(body.content)).unwrap())
    }
}

// ---------------------------------------------------------------------------
// PUT the zip (publish)
// ---------------------------------------------------------------------------

/// Delete a stored object no artifact row references (the leftover of a
/// publish that did not commit). Best-effort.
async fn discard_unreferenced_object(state: &SharedState, repo: &RepoInfo, storage_key: &str) {
    let referenced: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM artifacts WHERE repository_id = $1 AND storage_key = $2)",
    )
    .bind(repo.id)
    .bind(storage_key)
    .fetch_one(&state.db)
    .await
    .ok();
    if referenced == Some(false) {
        if let Ok(storage) = state.storage_for_repo(&repo.storage_location()) {
            let _ = storage.delete(storage_key).await;
        }
    }
}

/// The storage key a published archive is written to:
/// `agentplugins/{repository_id}/{sha256}/{name}/{version}/{name}-{version}.zip`
/// on a shared cloud namespace (S3/GCS/Azure), the repo-scoped shape of the
/// #2624 scheme npm (#4293) and Conan (#4694) use.
///
/// The content-only `agentplugins/{sha256}/...` key every repository used to
/// share made a second repository publishing byte-identical archives (a
/// staging and a production repository on one bucket) fail the
/// cross-repository write guard with 409 "already owned by another
/// repository" (#5267). The SHA-256 stays inside the per-repository prefix,
/// so a losing concurrent publish of different bytes to the same version
/// still writes its own object and never overwrites the winner's.
/// Filesystem backends (one directory per repository) and
/// `STORAGE_KEY_SCHEME=flat` keep `agentplugins/{sha256}/...`. Existing
/// objects are untouched: downloads resolve the object through the
/// `storage_key` its artifact row recorded.
fn plugin_storage_key(
    scheme: crate::storage::StorageKeyScheme,
    storage_backend: &str,
    repo_id: Uuid,
    sha256: &str,
    artifact_path: &str,
) -> String {
    scheme.write_key(
        storage_backend,
        FORMAT_KEY,
        repo_id,
        &format!("{sha256}/{artifact_path}"),
    )
}

/// Read the optional `X-Checksum-Sha256` header, lowercased.
fn declared_checksum(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CHECKSUM_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
}

/// Inspect the staged zip as a plugin bundle (section 4 of the design),
/// under an ingest-extraction permit and off the async runtime.
async fn inspect_staged(
    state: &SharedState,
    repo: &RepoInfo,
    staged: &super::repositories::GenericStagedBody,
    name: &str,
    version: &str,
) -> Result<PluginMetadata, Response> {
    let local = super::repositories::materialize_staged_for_repo(state, repo, staged).await?;
    let path = local.path().to_path_buf();
    let (slug, ver) = (name.to_string(), version.to_string());
    let joined = bounded_archive::with_ingest_extraction_async(|| async move {
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&path)
                .map_err(|e| format!("Cannot open the staged upload: {e}"))?;
            ap::analyze_zip(std::io::BufReader::new(file), &slug, &ver)
        })
        .await
    })
    .await
    .map_err(|e| e.into_response())?;
    drop(local);
    match joined {
        Ok(Ok(meta)) => Ok(meta),
        Ok(Err(msg)) => Err((StatusCode::BAD_REQUEST, msg).into_response()),
        Err(e) => Err(proxy_helpers::internal_error("Bundle inspection", e)),
    }
}

/// The 201 body of a publish.
fn publish_response(ctx: &IndexContext, meta: &PluginMetadata) -> serde_json::Value {
    serde_json::json!({
        "name": meta.name,
        "version": meta.version,
        "sha256": meta.sha256,
        "size_bytes": meta.size_bytes,
        "harnesses": meta.harnesses,
        "marketplace_name": ap::sanitize_marketplace_name(&ctx.repo_key),
        "download_url": ctx.download_url(&meta.name, &meta.version),
        "marketplaces": ctx.marketplace_urls(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn publish_plugin(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    base_url: RequestBaseUrl,
    Path((repo_key, name, version, file)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, FORMAT_KEY, "write:artifacts")?.user_id;
    let repo = resolve_agentplugins_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    ap::validate_coordinates(&name, &version, &file)
        .map_err(|msg| (StatusCode::BAD_REQUEST, msg).into_response())?;
    let artifact_path = ap::artifact_path(&name, &version);
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    // Versions are immutable (D6): refuse before reading the body. This check
    // does not touch a trashed version; the trash entry is only purged once
    // the upload has validated (review L2).
    let already_published = || async {
        let live: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 \
             AND is_deleted = false",
        )
        .bind(repo.id)
        .bind(&artifact_path)
        .fetch_optional(&state.db)
        .await
        .map_err(crate::api::handlers::db_err)?;
        match live {
            Some(_) => Err((
                StatusCode::CONFLICT,
                "Plugin version already exists; published versions are immutable",
            )
                .into_response()),
            None => Ok(()),
        }
    };
    already_published().await?;

    // Stream the body to a bounded staging area while hashing it (#1608).
    let (staged, digests) = super::repositories::GenericStagedBody::stage_for_repo(
        &state,
        &repo,
        body.into_data_stream(),
    )
    .await?;
    if staged.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty upload body").into_response());
    }
    if let Some(declared) = declared_checksum(&headers) {
        if declared != digests.sha256 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "X-Checksum-Sha256 mismatch: declared {declared} but the body hashes to {}",
                    digests.sha256
                ),
            )
                .into_response());
        }
    }

    let mut meta = inspect_staged(&state, &repo, &staged, &name, &version).await?;
    let size_bytes = staged.size_bytes();
    meta.sha256 = digests.sha256.clone();
    meta.size_bytes = size_bytes;

    // A deleted version stays immutable (review L3): only the identical bytes
    // may be re-published (an idempotent restore), because Claude Code only
    // re-downloads when the version string changes.
    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::AgentPlugins,
        repo.id,
        &artifact_path,
        &digests.sha256,
    )
    .await
    .map_err(|e| match e {
        crate::error::AppError::Conflict(_) => (
            StatusCode::CONFLICT,
            format!(
                "{name} {version} was deleted; a deleted version can only be re-published \
                 with identical content. Publish a new version instead"
            ),
        )
            .into_response(),
        other => other.into_response(),
    })?;

    // Repo-scoped on a shared cloud namespace (#5267) and content-addressed
    // inside that prefix, so a concurrent publish of different bytes to the
    // same version cannot overwrite the object the winning row points at.
    let storage_key = plugin_storage_key(
        crate::storage::StorageKeyScheme::from_env(),
        &repo.storage_backend,
        repo.id,
        &digests.sha256,
        &artifact_path,
    );
    proxy_helpers::put_staged_body(
        &state,
        &repo,
        super::publish_quota::PublishAt::StorageKey(&storage_key),
        &storage_key,
        staged,
        &digests,
    )
    .await?;

    // The row and its metadata commit together, inside the transaction that
    // admits the publish against the quotas: the harness tags decide which
    // documents list the version, so a row without them must never be
    // visible (review L1).
    let stored = serde_json::to_value(&meta).unwrap_or_default();
    let committed: Result<Uuid, Response> = async {
        let mut tx = super::publish_quota::begin_admitted_publish(
            &state.db,
            repo.id,
            &artifact_path,
            size_bytes,
        )
        .await?;
        let id = proxy_helpers::insert_artifact_row(
            &mut tx,
            proxy_helpers::NewArtifact {
                repository_id: repo.id,
                path: &artifact_path,
                name: &name,
                version: &version,
                size_bytes,
                checksum_sha256: &digests.sha256,
                content_type: "application/zip",
                storage_key: &storage_key,
                uploaded_by: user_id,
            },
        )
        .await?;
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(FORMAT_KEY)
        .bind(&stored)
        .execute(&mut *tx)
        .await
        .map_err(crate::api::handlers::db_err)?;
        tx.commit().await.map_err(crate::api::handlers::db_err)?;
        Ok(id)
    }
    .await;
    let artifact_id = match committed {
        Ok(id) => id,
        Err(resp) => {
            // Nothing committed: drop the object this attempt wrote unless a
            // row (a concurrent publish of the identical bytes) uses it, then
            // answer the lost race as the 409 it is (review L8).
            discard_unreferenced_object(&state, &repo, &storage_key).await;
            already_published().await?;
            return Err(resp);
        }
    };
    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        FORMAT_KEY,
        &name,
        &version,
        size_bytes,
        &digests.sha256,
        meta.description.as_deref(),
    )
    .await;
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        &headers,
        repo.id,
        artifact_id,
        &artifact_path,
        size_bytes,
    )
    .await;

    info!(
        "Agent plugin publish: {} {} ({:?}) to repo {}",
        name, version, meta.harnesses, repo_key
    );
    let ctx = index_context(&base_url, &repo_key, None, None);
    Ok((
        StatusCode::CREATED,
        axum::Json(publish_response(&ctx, &meta)),
    )
        .into_response())
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::formats::agent_plugins::test_zip;
    use bytes::Bytes;
    use serde_json::{json, Value};

    const STANDARD: &[u8] =
        br#"{"$schema":"https://agent-plugins.org/schemas/plugin-1.0.0.json","name":"std-tools","version":"0.1.0","description":"Standard skills"}"#;

    /// A Claude Code plugin zip. Every call returns distinct bytes (a nonce
    /// in the command body), so tests running in parallel against one
    /// database never publish identical archives; a test that needs the same
    /// bytes twice clones the result (#5267).
    fn claude_zip(name: &str, version: &str) -> Vec<u8> {
        let nonce = format!("# deploy {}", Uuid::new_v4());
        let manifest = format!(
            r#"{{"name":"{name}","version":"{version}","description":"Deploy commands","author":{{"name":"Example Team"}},"license":"MIT","keywords":["deploy"]}}"#
        );
        test_zip(&[
            (".claude-plugin/plugin.json", manifest.as_bytes()),
            ("commands/deploy.md", nonce.as_bytes()),
            ("skills/deploy/SKILL.md", b"# skill"),
            ("hooks/hooks.json", b"{}"),
        ])
    }

    fn put_zip(
        fx: &tdh::Fixture,
        name: &str,
        version: &str,
        zip: Vec<u8>,
    ) -> axum::http::Request<Body> {
        tdh::put(
            format!("/{}/{name}/{version}/{name}-{version}.zip", fx.repo_key),
            Bytes::from(zip),
        )
    }

    async fn publish(
        fx: &tdh::Fixture,
        name: &str,
        version: &str,
        zip: Vec<u8>,
    ) -> (StatusCode, Value) {
        let (status, body) = tdh::send(
            fx.router_with_auth(super::router()),
            put_zip(fx, name, version, zip),
        )
        .await;
        let value = serde_json::from_slice(&body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
        (status, value)
    }

    async fn get_json(app: Router, uri: String) -> (StatusCode, Value) {
        let (status, body) = tdh::send(app, tdh::get(uri)).await;
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn plugin_names(doc: &Value) -> Vec<String> {
        doc["plugins"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|p| p["name"].as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn declared_checksum_header_is_normalised() {
        let mut h = HeaderMap::new();
        assert_eq!(declared_checksum(&h), None);
        h.insert(CHECKSUM_HEADER, " ABCD ".parse().unwrap());
        assert_eq!(declared_checksum(&h).as_deref(), Some("abcd"));
        h.insert(CHECKSUM_HEADER, "".parse().unwrap());
        assert_eq!(declared_checksum(&h), None);
    }

    #[test]
    fn token_caller_is_required_on_token_routes() {
        let resp = require_token_caller(&None).unwrap_err();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(require_token_caller(&Some(tdh::make_auth(Uuid::nil(), "u"))).is_ok());
    }

    #[test]
    fn plugin_storage_key_is_repo_scoped_on_shared_namespaces_5267() {
        use crate::storage::StorageKeyScheme::{Flat, RepoScoped};
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let path = "p/1.0.0/p-1.0.0.zip";
        let key = |scheme, backend, repo| plugin_storage_key(scheme, backend, repo, "abc", path);
        assert_eq!(
            key(RepoScoped, "s3", a),
            format!("agentplugins/{a}/abc/p/1.0.0/p-1.0.0.zip")
        );
        assert_ne!(key(RepoScoped, "gcs", a), key(RepoScoped, "gcs", b));
        for (scheme, backend) in [(RepoScoped, "filesystem"), (Flat, "s3"), (Flat, "azure")] {
            assert_eq!(
                key(scheme, backend, a),
                "agentplugins/abc/p/1.0.0/p-1.0.0.zip",
                "{scheme:?} on {backend}"
            );
        }
    }

    #[test]
    fn json_document_answers_if_none_match() {
        let doc = json!({"a": 1});
        let first = json_document(&HeaderMap::new(), &doc);
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[CACHE_CONTROL], "no-cache");
        let etag = first.headers()[ETAG].to_str().unwrap().to_string();
        let mut h = HeaderMap::new();
        h.insert(IF_NONE_MATCH, etag.parse().unwrap());
        let second = json_document(&h, &doc);
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(second.headers()[ETAG].to_str().unwrap(), etag);
        h.insert(IF_NONE_MATCH, "\"stale\"".parse().unwrap());
        assert_eq!(json_document(&h, &doc).status(), StatusCode::OK);
    }

    /// Publish -> 201 fields -> download headers and bytes -> 409.
    #[tokio::test]
    async fn publish_download_and_conflict_5251() {
        use sha2::{Digest, Sha256};
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let zip = claude_zip("deploy-tools", "1.2.0");
        let sha = format!("{:x}", Sha256::digest(&zip));

        let (status, body) = publish(&fx, "deploy-tools", "1.2.0", zip.clone()).await;
        let (dl_status, dl_body, dl_headers) = tdh::send_with_headers(
            fx.router_anon(super::router()),
            tdh::get(format!(
                "/{}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
                fx.repo_key
            )),
        )
        .await;
        let (head_status, head_body, head_headers) = tdh::send_with_headers(
            fx.router_anon(super::router()),
            tdh::head(format!(
                "/{}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip",
                fx.repo_key
            )),
        )
        .await;
        let (again, again_body) = publish(&fx, "deploy-tools", "1.2.0", zip.clone()).await;
        let meta: Option<Value> = sqlx::query_scalar(
            "SELECT am.metadata FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id \
             WHERE a.repository_id = $1",
        )
        .bind(fx.repo_id)
        .fetch_optional(&fx.pool)
        .await
        .unwrap();
        let catalog = tdh::catalog_row(&fx.pool, fx.repo_id, "deploy-tools").await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["name"], "deploy-tools");
        assert_eq!(body["version"], "1.2.0");
        assert_eq!(body["sha256"], sha);
        assert_eq!(body["size_bytes"], json!(zip.len()));
        assert_eq!(body["harnesses"], json!(["claude"]));
        let key = &fx.repo_key;
        assert_eq!(
            body["download_url"],
            format!(
                "http://localhost/agentplugins/{key}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip"
            )
        );
        assert_eq!(
            body["marketplaces"]["claude"],
            format!("http://localhost/agentplugins/{key}/claude-marketplace.json")
        );
        for k in ["cursor", "codex", "vscode", "all"] {
            assert!(body["marketplaces"][k].is_string(), "{k}");
        }

        assert_eq!(dl_status, StatusCode::OK);
        assert_eq!(&dl_body[..], &zip[..]);
        assert_eq!(dl_headers[CONTENT_TYPE], "application/zip");
        assert_eq!(
            dl_headers[CONTENT_DISPOSITION],
            "attachment; filename=\"deploy-tools-1.2.0.zip\""
        );
        assert_eq!(dl_headers[CONTENT_LENGTH], zip.len().to_string().as_str());
        assert_eq!(dl_headers["x-checksum-sha256"], sha.as_str());
        assert_eq!(dl_headers[ETAG], format!("\"{sha}\"").as_str());
        assert_eq!(head_status, StatusCode::OK);
        assert!(head_body.is_empty());
        assert_eq!(head_headers[CONTENT_LENGTH], zip.len().to_string().as_str());

        assert_eq!(again, StatusCode::CONFLICT, "{again_body}");

        let meta = meta.expect("metadata row");
        assert_eq!(meta["components"]["commands"], 1);
        assert_eq!(meta["components"]["skills"], json!(["deploy"]));
        assert_eq!(meta["components"]["hooks"], true);
        assert_eq!(
            meta["manifest_paths"],
            json!([".claude-plugin/plugin.json"])
        );
        assert_eq!(meta["sha256"], sha);
        let catalog = catalog.expect("catalog row");
        assert_eq!(catalog.version, "1.2.0");
    }

    /// Downloads of a published archive are the count the Packages API
    /// reports for that version and its package (#5260): the agent-plugins
    /// route records the same `download_statistics` rows as every other
    /// hosted serve, and the catalog count reads them from there.
    #[tokio::test]
    async fn downloads_show_in_package_counts_5260() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let zip_bytes = claude_zip("counted", "1.0.0");
        let sha = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&zip_bytes))
        };
        let (status, body) = publish(&fx, "counted", "1.0.0", zip_bytes).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let artifact_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND checksum_sha256 = $2",
        )
        .bind(fx.repo_id)
        .bind(&sha)
        .fetch_one(&fx.pool)
        .await
        .expect("published artifact");
        let package_id: Uuid =
            sqlx::query_scalar("SELECT id FROM packages WHERE repository_id = $1 AND name = $2")
                .bind(fx.repo_id)
                .bind("counted")
                .fetch_one(&fx.pool)
                .await
                .expect("published package");

        let app = tdh::router_with_auth(
            Router::new()
                .nest("/agentplugins", super::router())
                .nest("/packages", crate::api::handlers::packages::router()),
            fx.state.clone(),
            tdh::make_auth(fx.user_id, &fx.username),
        );
        for _ in 0..3 {
            let (dl_status, _) = tdh::send(
                app.clone(),
                tdh::get(format!(
                    "/agentplugins/{}/counted/1.0.0/counted-1.0.0.zip",
                    fx.repo_key
                )),
            )
            .await;
            assert_eq!(dl_status, StatusCode::OK);
        }
        assert_eq!(
            tdh::download_count_eventually(&fx.pool, artifact_id, 3).await,
            3
        );

        let (detail_status, detail_body) =
            tdh::send(app.clone(), tdh::get(format!("/packages/{package_id}"))).await;
        let (versions_status, versions_body) = tdh::send(
            app.clone(),
            tdh::get(format!("/packages/{package_id}/versions")),
        )
        .await;
        let (list_status, list_body) = tdh::send(
            app,
            tdh::get(format!("/packages?repository_key={}", fx.repo_key)),
        )
        .await;
        fx.teardown().await;

        assert_eq!(
            detail_status,
            StatusCode::OK,
            "detail: {}",
            String::from_utf8_lossy(&detail_body)
        );
        assert_eq!(
            versions_status,
            StatusCode::OK,
            "versions: {}",
            String::from_utf8_lossy(&versions_body)
        );
        assert_eq!(
            list_status,
            StatusCode::OK,
            "list: {}",
            String::from_utf8_lossy(&list_body)
        );
        let detail: Value = serde_json::from_slice(&detail_body).expect("detail json");
        let versions: Value = serde_json::from_slice(&versions_body).expect("versions json");
        let list: Value = serde_json::from_slice(&list_body).expect("list json");
        assert_eq!(detail["download_count"], 3);
        assert_eq!(versions["versions"][0]["version"], "1.0.0");
        assert_eq!(versions["versions"][0]["download_count"], 3);
        let listed = list["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["name"] == "counted")
            .expect("counted package listed");
        assert_eq!(listed["download_count"], 3);
    }

    /// Every class of refused publish is a 400 and stores nothing.
    #[tokio::test]
    async fn refused_publishes_are_400_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let ok = claude_zip("p", "1.0.0");
        let cases: Vec<(&str, String, Vec<u8>, Option<&str>)> = vec![
            (
                "no manifest",
                "p/1.0.0/p-1.0.0.zip".into(),
                test_zip(&[("README.md", b"x")]),
                None,
            ),
            (
                "not a zip",
                "p/1.0.0/p-1.0.0.zip".into(),
                b"plain".to_vec(),
                None,
            ),
            ("empty body", "p/1.0.0/p-1.0.0.zip".into(), Vec::new(), None),
            (
                "traversal",
                "p/1.0.0/p-1.0.0.zip".into(),
                test_zip(&[(".claude-plugin/plugin.json", b"{}"), ("../x", b"x")]),
                None,
            ),
            (
                "name conflict",
                "p/1.0.0/p-1.0.0.zip".into(),
                test_zip(&[(".claude-plugin/plugin.json", br#"{"name":"q"}"#)]),
                None,
            ),
            (
                "version conflict",
                "p/1.0.0/p-1.0.0.zip".into(),
                test_zip(&[(".claude-plugin/plugin.json", br#"{"version":"0.9.0"}"#)]),
                None,
            ),
            (
                "ambiguous root",
                "p/1.0.0/p-1.0.0.zip".into(),
                test_zip(&[("a/plugin.json", b"{}"), ("b/x.md", b"x")]),
                None,
            ),
            ("bad semver", "p/1.0/p-1.0.zip".into(), ok.clone(), None),
            (
                "build metadata",
                "p/1.0.0+hotfix/p-1.0.0+hotfix.zip".into(),
                ok.clone(),
                None,
            ),
            ("bad slug", "P/1.0.0/P-1.0.0.zip".into(), ok.clone(), None),
            (
                "wrong filename",
                "p/1.0.0/other.zip".into(),
                ok.clone(),
                None,
            ),
            (
                "checksum mismatch",
                "p/1.0.0/p-1.0.0.zip".into(),
                ok.clone(),
                Some("00"),
            ),
        ];
        let mut observed = Vec::new();
        for (label, path, zip, checksum) in cases {
            let mut req = tdh::put(format!("/{}/{path}", fx.repo_key), Bytes::from(zip));
            if let Some(c) = checksum {
                req.headers_mut()
                    .insert(CHECKSUM_HEADER, c.parse().unwrap());
            }
            let (status, body) = tdh::send(fx.router_with_auth(super::router()), req).await;
            observed.push((label, status, String::from_utf8_lossy(&body).into_owned()));
        }
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        // A correct checksum is accepted.
        use sha2::{Digest, Sha256};
        let mut req = put_zip(&fx, "p", "1.0.0", ok.clone());
        req.headers_mut().insert(
            CHECKSUM_HEADER,
            format!("{:X}", Sha256::digest(&ok)).parse().unwrap(),
        );
        let (good, _) = tdh::send(fx.router_with_auth(super::router()), req).await;
        // Anonymous publish is refused.
        let (anon, _) = tdh::send(
            fx.router_anon(super::router()),
            put_zip(&fx, "p", "2.0.0", ok),
        )
        .await;
        fx.teardown().await;

        for (label, status, body) in &observed {
            assert_eq!(*status, StatusCode::BAD_REQUEST, "{label}: {body}");
        }
        let msg = |l: &str| observed.iter().find(|o| o.0 == l).unwrap().2.clone();
        assert!(msg("version conflict").contains("Claude Code resolves"));
        assert!(msg("name conflict").contains("declares name"));
        assert!(msg("checksum mismatch").contains("X-Checksum-Sha256 mismatch"));
        assert_eq!(rows, 0, "no refused publish may leave a row");
        assert_eq!(good, StatusCode::CREATED);
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
    }

    /// Every document end to end, latest selection, `index.json`, 304,
    /// quarantine exclusion and delete reflection.
    #[tokio::test]
    async fn index_documents_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let multi = test_zip(&[
            ("bundle/", b""),
            ("bundle/.claude-plugin/plugin.json", br#"{"name":"multi"}"#),
            ("bundle/.cursor-plugin/plugin.json", br#"{"name":"multi"}"#),
            ("bundle/.codex-plugin/plugin.json", br#"{"name":"multi"}"#),
        ]);
        for (name, version, zip) in [
            ("deploy-tools", "1.0.0", claude_zip("deploy-tools", "1.0.0")),
            ("deploy-tools", "1.2.0", claude_zip("deploy-tools", "1.2.0")),
            (
                "deploy-tools",
                "2.0.0-rc.1",
                claude_zip("deploy-tools", "2.0.0-rc.1"),
            ),
            (
                "std-tools",
                "0.1.0",
                test_zip(&[("plugin.json", STANDARD), ("mcp.json", b"{}")]),
            ),
            ("multi", "3.0.0", multi),
        ] {
            let (status, body) = publish(&fx, name, version, zip).await;
            assert_eq!(status, StatusCode::CREATED, "{name} {version}: {body}");
        }
        let key = fx.repo_key.clone();
        let app = || fx.router_anon(super::router());

        let mut docs = std::collections::HashMap::new();
        for kind in Marketplace::ALL {
            let (status, doc) = get_json(app(), format!("/{key}/{}", kind.file_name())).await;
            assert_eq!(status, StatusCode::OK, "{}", kind.file_name());
            docs.insert(kind.file_name(), doc);
        }
        let (missing_doc, _) = get_json(app(), format!("/{key}/other.json")).await;
        let (idx_status, idx) = get_json(app(), format!("/{key}/deploy-tools/index.json")).await;
        let (idx_missing, _) = get_json(app(), format!("/{key}/nope/index.json")).await;

        // 304 on a matching If-None-Match.
        let (_, _, h1) =
            tdh::send_with_headers(app(), tdh::get(format!("/{key}/claude-marketplace.json")))
                .await;
        let etag = h1[ETAG].to_str().unwrap().to_string();
        let mut req = tdh::get(format!("/{key}/claude-marketplace.json"));
        req.headers_mut()
            .insert(IF_NONE_MATCH, etag.parse().unwrap());
        let (not_modified, _) = tdh::send(app(), req).await;

        // Quarantine the rc: the index falls back to 1.2.0 and the download refuses.
        let rc_id = tdh::artifact_id_at(
            &fx.pool,
            fx.repo_id,
            "deploy-tools/2.0.0-rc.1/deploy-tools-2.0.0-rc.1.zip",
        )
        .await;
        sqlx::query("UPDATE artifacts SET quarantine_status = 'quarantined' WHERE id = $1")
            .bind(rc_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (_, held_doc) = get_json(app(), format!("/{key}/claude-marketplace.json")).await;
        let (held_dl, _) = tdh::send(
            app(),
            tdh::get(format!(
                "/{key}/deploy-tools/2.0.0-rc.1/deploy-tools-2.0.0-rc.1.zip"
            )),
        )
        .await;
        let mut req = tdh::get(format!("/{key}/claude-marketplace.json"));
        req.headers_mut()
            .insert(IF_NONE_MATCH, etag.parse().unwrap());
        let (changed, _) = tdh::send(app(), req).await;

        // A soft delete drops the version from every document.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND name = 'std-tools'")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (_, after_delete) = get_json(app(), format!("/{key}/vscode-marketplace.json")).await;
        fx.teardown().await;

        assert_eq!(
            plugin_names(&docs["marketplace.json"]),
            vec!["deploy-tools", "multi", "std-tools"]
        );
        assert_eq!(
            plugin_names(&docs["claude-marketplace.json"]),
            vec!["deploy-tools", "multi", "std-tools"]
        );
        assert_eq!(
            plugin_names(&docs["cursor-marketplace.json"]),
            vec!["multi", "std-tools"]
        );
        assert_eq!(
            plugin_names(&docs["codex-marketplace.json"]),
            vec!["multi", "std-tools"]
        );
        assert_eq!(
            plugin_names(&docs["vscode-marketplace.json"]),
            vec!["std-tools"]
        );
        let unified = &docs["marketplace.json"];
        assert_eq!(unified["$schema"], ap::UNIFIED_SCHEMA);
        assert!(docs["claude-marketplace.json"].get("$schema").is_none());
        let deploy = &unified["plugins"][0];
        assert_eq!(deploy["version"], "2.0.0-rc.1");
        assert_eq!(deploy["source"]["source"], "archive");
        assert_eq!(deploy["license"], "MIT");
        assert_eq!(deploy["author"]["name"], "Example Team");
        assert_eq!(
            unified["plugins"][1]["metadata"]["harnesses"],
            json!(["claude", "cursor", "codex"])
        );
        assert_eq!(unified["plugins"][2]["metadata"]["components"]["mcp"], true);

        assert_eq!(missing_doc, StatusCode::NOT_FOUND);
        assert_eq!(idx_status, StatusCode::OK);
        assert_eq!(idx["latest"], "2.0.0-rc.1");
        assert_eq!(idx["versions"].as_array().unwrap().len(), 3);
        assert_eq!(idx_missing, StatusCode::NOT_FOUND);
        assert_eq!(not_modified, StatusCode::NOT_MODIFIED);

        assert_eq!(held_doc["plugins"][0]["version"], "1.2.0");
        assert_ne!(
            held_dl,
            StatusCode::OK,
            "a quarantined archive must not download"
        );
        assert_eq!(changed, StatusCode::OK, "a hold must change the ETag");
        assert_eq!(plugin_names(&after_delete), Vec::<String>::new());
    }

    /// The production composition: the router nested at `/agentplugins`
    /// under `repo_visibility_middleware`, so path tokens are really
    /// validated, with the global `security_headers_middleware` outermost as
    /// `main.rs` applies it to the whole app, so the headers asserted are
    /// the ones a client receives (#5259).
    fn full_stack(state: &crate::api::SharedState) -> Router {
        use crate::api::middleware::auth::{repo_visibility_middleware, RepoVisibilityState};
        let vis = RepoVisibilityState {
            auth_service: std::sync::Arc::new(crate::services::auth_service::AuthService::new(
                state.db.clone(),
                std::sync::Arc::new(state.config.clone()),
            )),
            db: state.db.clone(),
            repo_cache: state.repo_cache.clone(),
            repo_miss_cache: state.repo_miss_cache.clone(),
            permission_service: state.permission_service.clone(),
        };
        Router::new()
            .nest("/agentplugins", super::router())
            .layer(axum::middleware::from_fn_with_state(
                vis,
                repo_visibility_middleware,
            ))
            .layer(axum::middleware::from_fn(
                crate::api::middleware::security_headers::security_headers_middleware,
            ))
            .with_state(state.clone())
    }

    /// Mint a read token for `user_id`, restricted to `repo_id` exactly as
    /// `POST /api/v1/repositories/{key}/tokens` does.
    async fn repo_read_token(fx: &tdh::Fixture, repo_id: Uuid, name: &str) -> (String, Uuid) {
        let auth = crate::services::auth_service::AuthService::new(
            fx.pool.clone(),
            std::sync::Arc::new(fx.state.config.clone()),
        );
        let (token, id) = auth
            .generate_api_token(fx.user_id, name, vec!["read:artifacts".into()], Some(30))
            .await
            .expect("mint token");
        sqlx::query("UPDATE api_tokens SET repository_restricted = true WHERE id = $1")
            .bind(id)
            .execute(&fx.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(id)
            .bind(repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        (token, id)
    }

    /// Token routes through the real visibility middleware on a private
    /// repository: a valid repository-scoped token reads documents and
    /// archives (URLs keep the prefix, `private, no-store`); a bogus,
    /// expired, revoked or other-repository token is refused.
    #[tokio::test]
    async fn token_routes_validate_real_tokens_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let (status, _) = publish(
            &fx,
            "deploy-tools",
            "1.0.0",
            claude_zip("deploy-tools", "1.0.0"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        sqlx::query("UPDATE repositories SET visibility = 'private' WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (other_id, _, other_dir) = tdh::create_repo(&fx.pool, "local", "agentplugins").await;
        let (valid, _) = repo_read_token(&fx, fx.repo_id, "ap-valid").await;
        let (expired, expired_id) = repo_read_token(&fx, fx.repo_id, "ap-expired").await;
        let (revoked, revoked_id) = repo_read_token(&fx, fx.repo_id, "ap-revoked").await;
        let (elsewhere, _) = repo_read_token(&fx, other_id, "ap-elsewhere").await;
        sqlx::query("UPDATE api_tokens SET expires_at = NOW() - INTERVAL '1 day' WHERE id = $1")
            .bind(expired_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1")
            .bind(revoked_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let app = full_stack(&fx.state);
        let key = fx.repo_key.clone();
        let doc = |t: &str| format!("/agentplugins/t/{t}/{key}/claude-marketplace.json");
        let (ok, body, headers) = tdh::send_with_headers(app.clone(), tdh::get(doc(&valid))).await;
        let (idx, _) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/agentplugins/t/{valid}/{key}/deploy-tools/index.json"
            )),
        )
        .await;
        let (dl, dl_body) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/agentplugins/t/{valid}/{key}/deploy-tools/1.0.0/deploy-tools-1.0.0.zip"
            )),
        )
        .await;
        let mut refused = Vec::new();
        for (label, t) in [
            ("bogus", "ak_not_a_real_token".to_string()),
            ("expired", expired),
            ("revoked", revoked),
            ("other repository", elsewhere),
        ] {
            refused.push((label, tdh::send(app.clone(), tdh::get(doc(&t))).await.0));
        }
        let (anon, _) = tdh::send(
            app.clone(),
            tdh::get(format!("/agentplugins/{key}/claude-marketplace.json")),
        )
        .await;
        // Without the middleware (a misrouted request), a token route with no
        // authenticated caller still refuses.
        let (bare, _) = tdh::send(
            fx.router_anon(super::router()),
            tdh::get(format!("/t/x/{key}/claude-marketplace.json")),
        )
        .await;
        tdh::cleanup_member_repo(&fx.pool, other_id, &other_dir).await;
        fx.teardown().await;

        assert_eq!(ok, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "private, no-store");
        // Through the global security-headers layer the route's stricter
        // policy must survive, not be replaced by the default (#5259).
        assert_eq!(headers["x-frame-options"], "DENY", "global layer ran");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        let doc: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["plugins"][0]["source"]["url"],
            format!(
                "http://localhost/agentplugins/t/{valid}/{key}/deploy-tools/1.0.0/deploy-tools-1.0.0.zip"
            )
        );
        assert_eq!(idx, StatusCode::OK);
        assert_eq!(dl, StatusCode::OK);
        assert!(!dl_body.is_empty());
        for (label, status) in refused {
            assert!(
                matches!(status, StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND),
                "{label} token must be refused, got {status}"
            );
        }
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
        assert_eq!(bare, StatusCode::UNAUTHORIZED);
    }

    /// Review M1: with a `block_unscanned` policy the freshly published (never
    /// scanned) version is refused by the download gate, so no index lists
    /// it; once it is allowed again it is advertised as latest.
    #[tokio::test]
    async fn index_skips_versions_the_scan_policy_refuses_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let (s1, _) = publish(&fx, "p", "1.0.0", claude_zip("p", "1.0.0")).await;
        // Treat 1.0.0 as scanned clean: the policy then lets it through.
        sqlx::query(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
             findings_count, critical_count, high_count, medium_count, low_count, info_count, \
             completed_at) \
             SELECT id, repository_id, 'dependency', 'completed', 0, 0, 0, 0, 0, 0, NOW() \
             FROM artifacts WHERE repository_id = $1 AND version = '1.0.0'",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("record a clean scan for 1.0.0");
        let policy_id: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
             block_on_fail, is_enabled) VALUES ($1, $2, 'critical', true, false, true) RETURNING id",
        )
        .bind(format!("ap-5251-{}", Uuid::new_v4()))
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("create block_unscanned policy");
        let (s2, _) = publish(&fx, "p", "1.1.0", claude_zip("p", "1.1.0")).await;
        let app = || fx.router_anon(super::router());
        let key = fx.repo_key.clone();
        let (dl_new, _) = tdh::send(app(), tdh::get(format!("/{key}/p/1.1.0/p-1.1.0.zip"))).await;
        let (dl_old, _) = tdh::send(app(), tdh::get(format!("/{key}/p/1.0.0/p-1.0.0.zip"))).await;
        let (_, claude) = get_json(app(), format!("/{key}/claude-marketplace.json")).await;
        let (_, idx) = get_json(app(), format!("/{key}/p/index.json")).await;
        sqlx::query("DELETE FROM scan_policies WHERE id = $1")
            .bind(policy_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (_, after) = get_json(app(), format!("/{key}/claude-marketplace.json")).await;
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
        assert_eq!(dl_new, StatusCode::FORBIDDEN, "unscanned 1.1.0 is refused");
        assert_eq!(dl_old, StatusCode::OK, "scanned 1.0.0 is served");
        assert_eq!(claude["plugins"][0]["version"], "1.0.0");
        assert_eq!(idx["latest"], "1.0.0");
        assert_eq!(idx["versions"].as_array().unwrap().len(), 1);
        assert_eq!(after["plugins"][0]["version"], "1.1.0");
    }

    /// Review M2: rows a native publish did not write (no agentplugins
    /// metadata, or a path other than the canonical one) are neither indexed
    /// nor downloaded, and the index is stable across reads.
    #[tokio::test]
    async fn only_native_rows_are_indexed_and_served_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let (s1, published) = publish(&fx, "hello", "1.0.0", claude_zip("hello", "1.0.0")).await;
        let repo = fx.repo_info("local", None);
        let traversal = test_zip(&[(".claude-plugin/plugin.json", b"{}"), ("../evil", b"x")]);
        // (A) a generic upload at the canonical path of an unpublished version.
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            "generic/hello-2.0.0.zip",
            "hello/2.0.0/hello-2.0.0.zip",
            "hello",
            "2.0.0",
            "application/zip",
            Bytes::from(traversal.clone()),
            fx.user_id,
        )
        .await;
        // (B) a second row with the same coordinates under another file name,
        // even carrying agentplugins metadata.
        let other = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            "generic/other.zip",
            "hello/1.0.0/other.zip",
            "hello",
            "1.0.0",
            "application/zip",
            Bytes::from(traversal),
            fx.user_id,
        )
        .await;
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
             VALUES ($1, 'agentplugins', '{\"harnesses\":[\"claude\"]}')",
        )
        .bind(other)
        .execute(&fx.pool)
        .await
        .unwrap();
        let app = || fx.router_anon(super::router());
        let key = fx.repo_key.clone();
        let (_, idx) = get_json(app(), format!("/{key}/hello/index.json")).await;
        let mut etags = std::collections::BTreeSet::new();
        for _ in 0..4 {
            let (_, _, h) =
                tdh::send_with_headers(app(), tdh::get(format!("/{key}/marketplace.json"))).await;
            etags.insert(h[ETAG].to_str().unwrap().to_string());
        }
        let (_, all) = get_json(app(), format!("/{key}/marketplace.json")).await;
        let (dl_foreign, _) = tdh::send(
            app(),
            tdh::get(format!("/{key}/hello/2.0.0/hello-2.0.0.zip")),
        )
        .await;
        fx.teardown().await;

        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(
            idx["latest"], "1.0.0",
            "the generic 2.0.0 row is not a version"
        );
        assert_eq!(idx["versions"].as_array().unwrap().len(), 1);
        assert_eq!(idx["versions"][0]["sha256"], published["sha256"]);
        assert_eq!(all["plugins"][0]["source"]["sha256"], published["sha256"]);
        assert_eq!(etags.len(), 1, "the index must be stable across reads");
        assert_eq!(dl_foreign, StatusCode::NOT_FOUND);
    }

    /// Review L2 and L3: a refused publish leaves a trashed version in the
    /// trash; a deleted version can be restored with identical bytes but not
    /// replaced with different ones.
    #[tokio::test]
    async fn deleted_versions_stay_immutable_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let original = claude_zip("p", "1.0.0");
        let (s1, _) = publish(&fx, "p", "1.0.0", original.clone()).await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (empty, _) = publish(&fx, "p", "1.0.0", Vec::new()).await;
        let trashed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND is_deleted = true",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        let changed = test_zip(&[
            (".claude-plugin/plugin.json", br#"{"name":"p"}"#),
            ("commands/new.md", b"# new"),
        ]);
        let (different, different_body) = publish(&fx, "p", "1.0.0", changed).await;
        let (identical, _) = publish(&fx, "p", "1.0.0", original).await;
        fx.teardown().await;

        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(empty, StatusCode::BAD_REQUEST);
        assert_eq!(
            trashed, 1,
            "a refused publish must not purge the trash entry"
        );
        assert_eq!(different, StatusCode::CONFLICT, "{different_body}");
        assert!(different_body
            .as_str()
            .unwrap_or_default()
            .contains("Publish a new version instead"));
        assert_eq!(
            identical,
            StatusCode::CREATED,
            "identical bytes restore the version"
        );
    }

    /// Review L8: a publish that did not commit removes its own object, but
    /// never one a row still references.
    #[tokio::test]
    async fn uncommitted_publish_objects_are_discarded_5251() {
        let Some(fx) = tdh::Fixture::setup("local", "agentplugins").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let storage = fx.state.storage_for_repo(&repo.storage_location()).unwrap();
        storage
            .put("agentplugins/orphan", Bytes::from_static(b"x"))
            .await
            .unwrap();
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            "agentplugins/kept",
            "p/1.0.0/p-1.0.0.zip",
            "p",
            "1.0.0",
            "application/zip",
            Bytes::from_static(b"y"),
            fx.user_id,
        )
        .await;
        discard_unreferenced_object(&fx.state, &repo, "agentplugins/orphan").await;
        discard_unreferenced_object(&fx.state, &repo, "agentplugins/kept").await;
        let orphan = storage.exists("agentplugins/orphan").await.unwrap_or(true);
        let kept = storage.exists("agentplugins/kept").await.unwrap_or(false);
        fx.teardown().await;
        assert!(!orphan, "an unreferenced object is removed");
        assert!(kept, "a referenced object is kept");
    }

    /// Virtual repositories are refused on every route until their merge rule
    /// exists (#5289 phase 2); a Remote refuses a publish with 405.
    #[tokio::test]
    async fn virtual_repositories_are_refused_and_remotes_are_read_only_5289() {
        let Some(fx) = tdh::Fixture::setup("virtual", "agentplugins").await else {
            return;
        };
        let key = fx.repo_key.clone();
        let mut statuses = Vec::new();
        for uri in [
            format!("/{key}/marketplace.json"),
            format!("/{key}/p/index.json"),
            format!("/{key}/p/1.0.0/p-1.0.0.zip"),
        ] {
            statuses.push(
                tdh::send(fx.router_with_auth(super::router()), tdh::get(uri))
                    .await
                    .0,
            );
        }
        let (put, _) = publish(&fx, "p", "1.0.0", claude_zip("p", "1.0.0")).await;
        fx.teardown().await;
        assert!(
            statuses.iter().all(|s| *s == StatusCode::BAD_REQUEST),
            "{statuses:?}"
        );
        assert_eq!(put, StatusCode::BAD_REQUEST);

        let Some(fx) = tdh::Fixture::setup("remote", "agentplugins").await else {
            return;
        };
        let (put, body) = publish(&fx, "p", "1.0.0", claude_zip("p", "1.0.0")).await;
        fx.teardown().await;
        assert_eq!(put, StatusCode::METHOD_NOT_ALLOWED, "{body}");
    }

    // ---- Remote repositories (#5289) --------------------------------------

    /// The upstream ("central") repository key in the wiremock layout.
    const CENTRAL: &str = "central";

    /// One version as the central AK lists it.
    fn central_version(name: &str, version: &str, zip: &[u8]) -> IndexedVersion {
        use sha2::{Digest, Sha256};
        IndexedVersion {
            name: name.into(),
            version: version.into(),
            sha256: format!("{:x}", Sha256::digest(zip)),
            size_bytes: zip.len() as i64,
            published_at: chrono::Utc::now(),
            metadata: PluginMetadata {
                name: name.into(),
                version: version.into(),
                harnesses: vec!["claude".into()],
                description: Some("Deploy commands".into()),
                ..PluginMetadata::default()
            },
        }
    }

    /// A wiremock "central AK" serving the documents its hosted repository
    /// would generate for `versions` (built with the real generator, with the
    /// central instance's own external URL, which is not the URL the Remote
    /// reaches it at). The archives are mounted by each test.
    async fn central_ak(
        versions: &[IndexedVersion],
    ) -> (wiremock::MockServer, tdh::SsrfTestAllowlistGuard) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let (server, guard) = tdh::non_loopback_mock_server().await;
        let ctx = IndexContext {
            repo_key: CENTRAL.into(),
            description: Some("Central plugins".into()),
            origin: "https://central.example.com".into(),
            token: None,
        };
        for kind in Marketplace::ALL {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/agentplugins/{CENTRAL}/{}",
                    kind.file_name()
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(ap::build_marketplace(kind, &ctx, versions)),
                )
                .mount(&server)
                .await;
        }
        let names: std::collections::BTreeSet<&str> =
            versions.iter().map(|v| v.name.as_str()).collect();
        for name in names {
            Mock::given(method("GET"))
                .and(path(format!("/agentplugins/{CENTRAL}/{name}/index.json")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        ap::build_versions_index(name, &ctx, versions).expect("index"),
                    ),
                )
                .mount(&server)
                .await;
        }
        (server, guard)
    }

    /// Mount the archive of `name` `version` on the central AK, answering
    /// `body`, expected exactly `times` times.
    async fn mount_archive(
        server: &wiremock::MockServer,
        name: &str,
        version: &str,
        body: Vec<u8>,
        times: u64,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(format!(
                "/agentplugins/{CENTRAL}/{}",
                ap::artifact_path(name, version)
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/zip")
                    .set_body_bytes(body),
            )
            .expect(times)
            .mount(server)
            .await;
    }

    /// Point the fixture Remote at the central AK and wire the proxy service
    /// in. The fixture is set up BEFORE the mock server, so a run without a
    /// database returns before any `expect` is mounted.
    async fn wire_remote(
        fx: &tdh::Fixture,
        server: &wiremock::MockServer,
    ) -> (SharedState, tempfile::TempDir) {
        let upstream = format!("{}/agentplugins/{CENTRAL}", server.uri());
        tdh::rewire_remote_proxy(fx, &upstream).await
    }

    /// The Remote serves the central marketplace with every archive URL and
    /// `versions_url` pointing at itself, the upstream `sha256` unchanged, and
    /// its own marketplace name; `{name}/index.json` likewise.
    #[tokio::test]
    async fn remote_documents_point_at_the_remote_and_keep_sha256_5289() {
        let zip = claude_zip("deploy-tools", "1.2.0");
        let versions = vec![central_version("deploy-tools", "1.2.0", &zip)];
        let Some(fx) = tdh::Fixture::setup("remote", "agentplugins").await else {
            return;
        };
        let (server, _guard) = central_ak(&versions).await;
        let (state, _dir) = wire_remote(&fx, &server).await;
        let key = fx.repo_key.clone();
        let app = || tdh::router_anon(super::router(), state.clone());
        let (status, doc) = get_json(app(), format!("/{key}/claude-marketplace.json")).await;
        let (unified_status, unified) = get_json(app(), format!("/{key}/marketplace.json")).await;
        let (idx_status, idx) = get_json(app(), format!("/{key}/deploy-tools/index.json")).await;
        let (bad_slug, _) = get_json(app(), format!("/{key}/Bad_Slug/index.json")).await;
        fx.teardown().await;

        let base = format!("http://localhost/agentplugins/{key}");
        let archive_url = format!("{base}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip");
        assert_eq!(status, StatusCode::OK, "{doc}");
        assert_eq!(doc["name"], ap::sanitize_marketplace_name(&key));
        assert_eq!(doc["metadata"]["repository"], key);
        assert_eq!(doc["owner"]["url"], "http://localhost");
        assert_eq!(doc["description"], "Central plugins");
        let entry = &doc["plugins"][0];
        assert_eq!(entry["source"]["source"], "archive");
        assert_eq!(entry["source"]["url"], archive_url);
        assert_eq!(entry["source"]["sha256"], versions[0].sha256);
        assert_eq!(
            entry["metadata"]["versions_url"],
            format!("{base}/deploy-tools/index.json")
        );
        assert_eq!(unified_status, StatusCode::OK);
        assert_eq!(unified["$schema"], ap::UNIFIED_SCHEMA);
        assert_eq!(unified["plugins"][0]["source"]["url"], archive_url);

        assert_eq!(idx_status, StatusCode::OK, "{idx}");
        assert_eq!(idx["latest"], "1.2.0");
        assert_eq!(idx["versions"][0]["url"], archive_url);
        assert_eq!(idx["versions"][0]["sha256"], versions[0].sha256);
        assert_eq!(bad_slug, StatusCode::NOT_FOUND);
    }

    /// An archive is fetched once and served from the proxy cache after that
    /// (the second download makes no upstream request), with the hosted
    /// download headers; HEAD is answered from the index.
    #[tokio::test]
    async fn remote_archive_is_verified_and_cached_5289() {
        let zip = claude_zip("deploy-tools", "1.2.0");
        let versions = vec![central_version("deploy-tools", "1.2.0", &zip)];
        let Some(fx) = tdh::Fixture::setup("remote", "agentplugins").await else {
            return;
        };
        let (server, _guard) = central_ak(&versions).await;
        mount_archive(&server, "deploy-tools", "1.2.0", zip.clone(), 1).await;
        let (state, _dir) = wire_remote(&fx, &server).await;
        let uri = format!("/{}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip", fx.repo_key);
        let app = || tdh::router_anon(super::router(), state.clone());
        let first = tdh::send_with_headers(app(), tdh::get(uri.clone())).await;
        let second = tdh::send_with_headers(app(), tdh::get(uri.clone())).await;
        let head = tdh::send_with_headers(app(), tdh::head(uri.clone())).await;
        let (missing, _) = tdh::send(
            app(),
            tdh::get(format!(
                "/{}/deploy-tools/9.9.9/deploy-tools-9.9.9.zip",
                fx.repo_key
            )),
        )
        .await;
        fx.teardown().await;
        server.verify().await;

        let sha = versions[0].sha256.as_str();
        for (status, body, headers) in [&first, &second] {
            assert_eq!(*status, StatusCode::OK, "{}", String::from_utf8_lossy(body));
            assert_eq!(&body[..], &zip[..]);
            assert_eq!(headers[CONTENT_TYPE], "application/zip");
            assert_eq!(headers["x-checksum-sha256"], sha);
            assert_eq!(headers[ETAG], format!("\"{sha}\"").as_str());
            assert_eq!(headers[CONTENT_LENGTH], zip.len().to_string().as_str());
        }
        assert_eq!(head.0, StatusCode::OK);
        assert!(head.1.is_empty());
        assert_eq!(head.2[CONTENT_LENGTH], zip.len().to_string().as_str());
        assert_eq!(missing, StatusCode::NOT_FOUND);
    }

    /// Upstream bytes that do not hash to the `sha256` the upstream index
    /// lists are refused with 502 and never cached: the second download asks
    /// the upstream again (`expect(2)`).
    #[tokio::test]
    async fn remote_tampered_archive_is_refused_and_not_cached_5289() {
        let zip = claude_zip("deploy-tools", "1.2.0");
        let tampered = claude_zip("deploy-tools", "1.2.0");
        assert_ne!(zip, tampered);
        let versions = vec![central_version("deploy-tools", "1.2.0", &zip)];
        let Some(fx) = tdh::Fixture::setup("remote", "agentplugins").await else {
            return;
        };
        let (server, _guard) = central_ak(&versions).await;
        mount_archive(&server, "deploy-tools", "1.2.0", tampered, 2).await;
        let (state, _dir) = wire_remote(&fx, &server).await;
        let uri = format!("/{}/deploy-tools/1.2.0/deploy-tools-1.2.0.zip", fx.repo_key);
        let app = || tdh::router_anon(super::router(), state.clone());
        let (first, first_body) = tdh::send(app(), tdh::get(uri.clone())).await;
        let (second, _) = tdh::send(app(), tdh::get(uri.clone())).await;
        fx.teardown().await;
        server.verify().await;
        assert_eq!(
            first,
            StatusCode::BAD_GATEWAY,
            "{}",
            String::from_utf8_lossy(&first_body)
        );
        assert_eq!(second, StatusCode::BAD_GATEWAY);
    }

    /// Creating an Agent Plugins Remote through the API succeeds; a Virtual
    /// is still refused (#5289 phase 2).
    #[tokio::test]
    async fn create_agentplugins_remote_succeeds_and_virtual_is_refused_5289() {
        use crate::api::handlers::repositories::create_repository;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let state = tdh::build_state(pool.clone(), dir.path().to_str().unwrap());
        let admin = tdh::admin_auth(user_id, &username);
        let request = |repo_type: &str, key: &str| {
            Bytes::from(
                serde_json::to_vec(&json!({
                    "key": key,
                    "name": key,
                    "format": "agentplugins",
                    "repo_type": repo_type,
                    "upstream_url": "https://central.example.com/agentplugins/plugins",
                }))
                .unwrap(),
            )
        };
        let remote_key = format!("ap-remote-{}", Uuid::new_v4().simple());
        let remote = create_repository(
            State(state.clone()),
            Extension(Some(admin.clone())),
            request("remote", &remote_key),
        )
        .await;
        let virtual_key = format!("ap-virtual-{}", Uuid::new_v4().simple());
        let refused = create_repository(
            State(state.clone()),
            Extension(Some(admin.clone())),
            request("virtual", &virtual_key),
        )
        .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE key = ANY($1)")
            .bind(vec![remote_key.clone(), virtual_key.clone()])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;

        let remote = remote.expect("an agentplugins remote is created").0;
        assert_eq!(remote.key, remote_key);
        assert_eq!(remote.repo_type, "remote");
        match refused {
            Err(crate::error::AppError::Validation(msg)) => {
                assert!(msg.contains("phase 2"), "{msg}")
            }
            Err(other) => panic!("expected a validation error, got {other:?}"),
            Ok(_) => panic!("a virtual agentplugins repository must be refused"),
        }
    }

    /// The archive is streamed by the handler even when the storage backend
    /// can presign: Claude Code drops its configured headers on a redirect to
    /// another origin, so this format must never answer a download with 3xx.
    #[tokio::test]
    async fn download_never_redirects_to_presigned_storage_5251() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, dir) = cloud_repo(&pool).await;
        let (user_id, username) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let (state, _mem) = tdh::build_state_with_presigning_cloud(pool.clone(), "s3");
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let zip = claude_zip("p", "1.0.0");
        let (put, put_body) = tdh::send(
            app.clone(),
            tdh::put(
                format!("/{repo_key}/p/1.0.0/p-1.0.0.zip"),
                Bytes::from(zip.clone()),
            ),
        )
        .await;
        let mut results = Vec::new();
        for uri in [
            format!("/{repo_key}/p/1.0.0/p-1.0.0.zip"),
            format!("/t/tok/{repo_key}/p/1.0.0/p-1.0.0.zip"),
        ] {
            results.push(tdh::send(app.clone(), tdh::get(uri)).await);
        }
        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(dir);
        assert_eq!(
            put,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&put_body)
        );
        for (status, body) in results {
            assert!(!status.is_redirection(), "download answered {status}");
            assert_eq!(status, StatusCode::OK);
            assert_eq!(&body[..], &zip[..]);
        }
    }

    /// A hosted Agent Plugins repository on the `s3` backend; every such
    /// repository shares the one in-memory bucket of a cloud test state.
    async fn cloud_repo(pool: &PgPool) -> (Uuid, String, std::path::PathBuf) {
        let (repo_id, repo_key, dir) = tdh::create_repo(pool, "local", "agentplugins").await;
        sqlx::query(
            "UPDATE repositories SET storage_backend = 's3', storage_path = key WHERE id = $1",
        )
        .bind(repo_id)
        .execute(pool)
        .await
        .unwrap();
        (repo_id, repo_key, dir)
    }

    /// Two repositories on one shared bucket (staging and production)
    /// publishing byte-identical archives both succeed and each keeps its
    /// own object: the content-addressed key is scoped per repository, so
    /// the cross-repository write guard no longer answers the second 409
    /// (#5267).
    #[tokio::test]
    async fn identical_archives_publish_to_two_repositories_5267() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, staging_key, staging_dir) = cloud_repo(&pool).await;
        let (prod, prod_key, prod_dir) = cloud_repo(&pool).await;
        let (user_id, username) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, staging, user_id).await;
        tdh::grant_repo_access(&pool, prod, user_id).await;
        let (state, mem) = tdh::build_state_with_cloud(pool.clone(), "s3");
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let zip = claude_zip("p", "1.0.0");
        let uri = |key: &str| format!("/{key}/p/1.0.0/p-1.0.0.zip");
        let mut puts = Vec::new();
        let mut downloads = Vec::new();
        for key in [&staging_key, &prod_key] {
            let put = tdh::put(uri(key), Bytes::from(zip.clone()));
            puts.push(tdh::send(app.clone(), put).await);
        }
        for key in [&staging_key, &prod_key] {
            downloads.push(tdh::send(app.clone(), tdh::get(uri(key))).await);
        }
        let key_of = |repo: Uuid| {
            sqlx::query_scalar::<_, String>(
                "SELECT storage_key FROM artifacts WHERE repository_id = $1",
            )
            .bind(repo)
            .fetch_one(&pool)
        };
        let (staging_obj, prod_obj) = (key_of(staging).await, key_of(prod).await);
        let stored = mem.objects.lock().unwrap().len();
        // The user goes with the last repository, once no row references it.
        tdh::cleanup(&pool, staging, Uuid::nil()).await;
        tdh::cleanup(&pool, prod, user_id).await;
        let _ = std::fs::remove_dir_all(staging_dir);
        let _ = std::fs::remove_dir_all(prod_dir);

        for (status, body) in puts {
            assert_eq!(
                status,
                StatusCode::CREATED,
                "{}",
                String::from_utf8_lossy(&body)
            );
        }
        for (status, body) in downloads {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(&body[..], &zip[..]);
        }
        let (staging_obj, prod_obj) = (staging_obj.unwrap(), prod_obj.unwrap());
        assert_ne!(staging_obj, prod_obj, "each repository owns its own object");
        assert!(staging_obj.starts_with(&format!("agentplugins/{staging}/")));
        assert!(prod_obj.starts_with(&format!("agentplugins/{prod}/")));
        assert_eq!(stored, 2, "two physical objects in the shared bucket");
    }
}
