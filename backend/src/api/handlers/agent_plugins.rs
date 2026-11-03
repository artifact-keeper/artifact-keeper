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
//! Repositories are hosted only (D3). The documents are built from the
//! database on every request (D7), so a delete or a quarantine hold is
//! reflected immediately; they carry an `ETag` and answer `If-None-Match`
//! with `304`. Protocol reference: `docs/agent-plugins.md`.

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

#[allow(clippy::result_large_err)]
fn reject_if_not_hosted(repo: &RepoInfo) -> Result<(), Response> {
    if repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual {
        return Err((
            StatusCode::BAD_REQUEST,
            "Agent Plugins repositories are hosted-only; this repository is not hosted",
        )
            .into_response());
    }
    Ok(())
}

async fn resolve_agentplugins_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo =
        proxy_helpers::resolve_repo_by_key(db, repo_key, &[FORMAT_KEY], "an Agent Plugins").await?;
    reject_if_not_hosted(&repo)?;
    Ok(repo)
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

#[derive(sqlx::FromRow)]
struct VersionRow {
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    created_at: chrono::DateTime<chrono::Utc>,
    metadata: Option<serde_json::Value>,
    quarantine_status: Option<String>,
    quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Every servable version in the repository. A version the download gate
/// would refuse (quarantined, or under an active upload hold) is left out,
/// with the exact predicate `quarantine_service::check_download_allowed`
/// applies, so no index advertises an archive its download refuses.
async fn servable_versions(db: &PgPool, repo_id: Uuid) -> Result<Vec<IndexedVersion>, Response> {
    let rows = sqlx::query_as::<_, VersionRow>(
        "SELECT a.name, a.version, a.size_bytes, a.checksum_sha256, a.created_at, \
                am.metadata, a.quarantine_status, a.quarantine_until \
         FROM artifacts a \
         LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;
    let now = chrono::Utc::now();
    Ok(rows
        .into_iter()
        .filter(|r| {
            crate::services::quarantine_service::check_download_allowed(
                r.quarantine_status.as_deref(),
                r.quarantine_until,
                now,
            )
            .is_ok()
        })
        .filter_map(|r| {
            let version = r.version?;
            let metadata: PluginMetadata = r
                .metadata
                .and_then(|m| serde_json::from_value(m).ok())
                .unwrap_or_default();
            Some(IndexedVersion {
                name: r.name,
                version,
                sha256: r.checksum_sha256,
                size_bytes: r.size_bytes,
                published_at: r.created_at,
                metadata,
            })
        })
        .collect())
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

#[derive(sqlx::FromRow)]
struct StoredArchive {
    id: Uuid,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
}

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
    let path = ap::artifact_path(&name, &version);
    let artifact = sqlx::query_as::<_, StoredArchive>(
        "SELECT id, size_bytes, checksum_sha256, storage_key FROM artifacts \
         WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
    )
    .bind(repo.id)
    .bind(&path)
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| not_found("Plugin archive"))?;

    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
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
// PUT the zip (publish)
// ---------------------------------------------------------------------------

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

    // Versions are immutable (D6): refuse before reading the body.
    let ensure_unique = || {
        proxy_helpers::ensure_unique_artifact_path(
            &state.db,
            repo.id,
            &artifact_path,
            "Plugin version already exists; published versions are immutable",
        )
    };
    ensure_unique().await?;

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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Content-addressed key: a concurrent publish of different bytes to the
    // same version cannot overwrite the object the winning row points at.
    let storage_key = format!("{FORMAT_KEY}/{}/{artifact_path}", digests.sha256);
    proxy_helpers::put_staged_body(
        &state,
        &repo,
        super::publish_quota::PublishAt::StorageKey(&storage_key),
        &storage_key,
        staged,
        &digests,
    )
    .await?;

    // Quota admission and the upload hold run inside `insert_artifact`.
    let inserted = proxy_helpers::insert_artifact(
        &state.db,
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
    .await;
    let artifact_id = match inserted {
        Ok(id) => id,
        // Lost a race with a concurrent publish of the same version.
        Err(resp) => {
            ensure_unique().await?;
            return Err(resp);
        }
    };

    let stored = serde_json::to_value(&meta).unwrap_or_default();
    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, FORMAT_KEY, &stored)
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

    fn claude_zip(name: &str, version: &str) -> Vec<u8> {
        let manifest = format!(
            r#"{{"name":"{name}","version":"{version}","description":"Deploy commands","author":{{"name":"Example Team"}},"license":"MIT","keywords":["deploy"]}}"#
        );
        test_zip(&[
            (".claude-plugin/plugin.json", manifest.as_bytes()),
            ("commands/deploy.md", b"# deploy"),
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

    /// Token routes: 200 with an authenticated caller, archive URLs keep the
    /// `/t/{token}/` prefix, `private, no-store`; 401 without a caller.
    #[tokio::test]
    async fn token_routes_5251() {
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
        let key = fx.repo_key.clone();
        let doc_uri = format!("/t/ak_tok/{key}/claude-marketplace.json");
        let (ok, body, headers) = tdh::send_with_headers(
            fx.router_with_auth(super::router()),
            tdh::get(doc_uri.clone()),
        )
        .await;
        let (idx, _) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!("/t/ak_tok/{key}/deploy-tools/index.json")),
        )
        .await;
        let (dl, _) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!(
                "/t/ak_tok/{key}/deploy-tools/1.0.0/deploy-tools-1.0.0.zip"
            )),
        )
        .await;
        let (anon, _, anon_headers) =
            tdh::send_with_headers(fx.router_anon(super::router()), tdh::get(doc_uri)).await;
        let (anon_idx, _) = tdh::send(
            fx.router_anon(super::router()),
            tdh::get(format!("/t/ak_tok/{key}/deploy-tools/index.json")),
        )
        .await;
        let (anon_dl, _) = tdh::send(
            fx.router_anon(super::router()),
            tdh::get(format!(
                "/t/ak_tok/{key}/deploy-tools/1.0.0/deploy-tools-1.0.0.zip"
            )),
        )
        .await;
        fx.teardown().await;

        assert_eq!(ok, StatusCode::OK);
        assert_eq!(headers[CACHE_CONTROL], "private, no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        let doc: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["plugins"][0]["source"]["url"],
            format!("http://localhost/agentplugins/t/ak_tok/{key}/deploy-tools/1.0.0/deploy-tools-1.0.0.zip")
        );
        assert_eq!(idx, StatusCode::OK);
        assert_eq!(dl, StatusCode::OK);
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
        assert_eq!(anon_headers[CACHE_CONTROL], "private, no-store");
        assert_eq!(anon_idx, StatusCode::UNAUTHORIZED);
        assert_eq!(anon_dl, StatusCode::UNAUTHORIZED);
    }

    /// Non-hosted repositories are refused on every route (D3).
    #[tokio::test]
    async fn non_hosted_repositories_are_refused_5251() {
        let Some(fx) = tdh::Fixture::setup("remote", "agentplugins").await else {
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
    }

    /// The archive is streamed by the handler even when the storage backend
    /// can presign: Claude Code drops its configured headers on a redirect to
    /// another origin, so this format must never answer a download with 3xx.
    #[tokio::test]
    async fn download_never_redirects_to_presigned_storage_5251() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, dir) = tdh::create_repo(&pool, "local", "agentplugins").await;
        sqlx::query(
            "UPDATE repositories SET storage_backend = 's3', storage_path = key WHERE id = $1",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();
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
}
