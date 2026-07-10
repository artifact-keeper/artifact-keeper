//! RPM/YUM repository API handlers.
//!
//! Implements the endpoints required for `yum`/`dnf` package management.
//!
//! Routes are mounted at `/rpm/{repo_key}/...`:
//!   GET  /rpm/{repo_key}/repodata/repomd.xml       - Repository metadata index
//!   GET  /rpm/{repo_key}/repodata/primary.xml.gz    - Primary package metadata
//!   GET  /rpm/{repo_key}/repodata/filelists.xml.gz  - File lists (stub)
//!   GET  /rpm/{repo_key}/repodata/other.xml.gz      - Other metadata (stub)
//!   GET  /rpm/{repo_key}/repodata/updateinfo.xml.gz - Update advisories (stub)
//!   GET  /rpm/{repo_key}/repodata/repomd.xml.asc    - Detached GPG signature
//!   GET  /rpm/{repo_key}/repodata/repomd.xml.key    - Public key (PEM)
//!   GET  /rpm/{repo_key}/packages/*path              - Download RPM package
//!   PUT  /rpm/{repo_key}/packages/*path              - Upload RPM package
//!   POST /rpm/{repo_key}/upload                      - Upload RPM (alternative)

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Extension;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::signing_service::SigningService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Repodata endpoints
        .route("/:repo_key/repodata/repomd.xml", get(repomd_xml))
        .route("/:repo_key/repodata/primary.xml.gz", get(primary_xml_gz))
        .route(
            "/:repo_key/repodata/filelists.xml.gz",
            get(filelists_xml_gz),
        )
        .route("/:repo_key/repodata/other.xml.gz", get(other_xml_gz))
        .route(
            "/:repo_key/repodata/updateinfo.xml.gz",
            get(updateinfo_xml_gz),
        )
        // Signing endpoints
        .route("/:repo_key/repodata/repomd.xml.asc", get(repomd_xml_asc))
        .route("/:repo_key/repodata/repomd.xml.key", get(repomd_xml_key))
        // Hash-prefixed repodata files (e.g. abc123-primary.xml.gz). Upstream
        // RPM repos checksum-prefix the actual metadata payloads referenced
        // from repomd.xml. For Remote/Virtual repos we transparently proxy
        // any /repodata/* path so dnf/yum can follow the upstream layout.
        .route("/:repo_key/repodata/*path", get(repodata_proxy))
        // Package download and upload
        .route("/:repo_key/packages/*path", get(download_package))
        .route("/:repo_key/packages/*path", put(upload_package_put))
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_package_post))
        // Proxy fallback for upstream package paths that do not live under
        // /packages/ (many real-world RPM repos host RPMs at the repo root
        // or under arbitrary subpaths like Packages/p/ or pool/...). Only
        // Remote/Virtual repos are eligible; hosted repos 404 here. Kept
        // last so explicit routes above always win.
        .route("/:repo_key/*upstream_path", get(upstream_proxy))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_rpm_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["rpm", "yum"], "an RPM").await
}

/// Reject RPM uploads to non-hosted (Remote/Virtual) repositories.
///
/// `dnf`/`yum` only ever PUT/POST RPMs into hosted repos. Both Remote (proxy)
/// and Virtual (aggregate) repos must reject the write verb with
/// `405 Method Not Allowed` so clients receive a consistent, RFC-correct
/// response. The shared `reject_write_if_not_hosted` helper returns `400` for
/// Virtual repos (a contract other subsystems depend on), so RPM intercepts
/// the Virtual case here before delegating the Remote case (#1780).
#[allow(clippy::result_large_err)]
fn reject_rpm_write_if_not_hosted(repo_type: &str) -> Result<(), Response> {
    if repo_type == RepositoryType::Virtual {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Cannot publish to a virtual repository",
        )
            .into_response());
    }
    proxy_helpers::reject_write_if_not_hosted(repo_type)
}

/// For Remote RPM repos, proxy `upstream_path` from the configured
/// `upstream_url`. Returns `Ok(Some(response))` on a successful proxy
/// hit, `Ok(None)` when the repository is not a Remote that can serve
/// `upstream_path` (Hosted falls through to the local-generation path,
/// Virtual is currently treated the same as Hosted here pending a
/// follow-up that walks member repos), or `Err(response)` when the
/// upstream fetch itself fails.
///
/// This is the core of the fix for #1447: prior to this helper the
/// repodata handlers always read from the local artifact table even
/// when the repo was a proxy, so dnf saw an empty repository and
/// silently did nothing.
async fn try_proxy_repodata(
    state: &SharedState,
    repo: &RepoInfo,
    upstream_path: &str,
    default_content_type: &str,
) -> Result<Option<Response>, Response> {
    if repo.repo_type != RepositoryType::Remote {
        return Ok(None);
    }
    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok(None),
    };

    let (content, upstream_ct) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;

    let content_type = upstream_ct.unwrap_or_else(|| default_content_type.to_string());
    Ok(Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, content.len().to_string())
            .body(Body::from(content))
            .unwrap(),
    ))
}

/// Build the HTTP 200 response for serving an RPM package body.
///
/// Shared by the `/packages/*` download path and the upstream-proxy local
/// cache-hit path so both emit identical headers. The `body` is supplied by the
/// caller — always a streaming [`Body::from_stream`] over `get_stream` so the
/// whole `.rpm` is never buffered in memory (#1608, Core Invariant ①) — and
/// `size_bytes` is the stored artifact size used for the `Content-Length`
/// header (we must not read the object to learn its length).
fn build_rpm_package_response(
    body: Body,
    filename: &str,
    size_bytes: i64,
    checksum_sha256: &str,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-rpm")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, size_bytes.to_string())
        // `artifacts.checksum_sha256` is a fixed-width `CHAR(64)` column, so a
        // value shorter than 64 chars (e.g. test seeds) comes back space-padded.
        // Trim it so the header never carries trailing whitespace.
        .header("X-Checksum-SHA256", checksum_sha256.trim())
        .body(body)
        .unwrap()
}

// ---------------------------------------------------------------------------
// RPM filename parsing
// ---------------------------------------------------------------------------

/// Parse an RPM filename into (name, version, release, arch).
/// Expected format: `{name}-{version}-{release}.{arch}.rpm`
///
/// Examples:
///   my-package-1.0.0-1.x86_64.rpm -> ("my-package", "1.0.0", "1", "x86_64")
///   hello-2.10-1.el8.noarch.rpm   -> ("hello", "2.10", "1.el8", "noarch")
fn parse_rpm_filename(filename: &str) -> Option<(String, String, String, String)> {
    let stem = filename.strip_suffix(".rpm")?;

    // Find arch: last dot-separated segment
    let (before_arch, arch) = stem.rsplit_once('.')?;

    // Find release: last hyphen-separated segment
    let (before_release, release) = before_arch.rsplit_once('-')?;

    // Find version: last hyphen-separated segment of what remains
    let (name, version) = before_release.rsplit_once('-')?;

    if name.is_empty() || version.is_empty() || release.is_empty() || arch.is_empty() {
        return None;
    }

    Some((
        name.to_string(),
        version.to_string(),
        release.to_string(),
        arch.to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct RpmArtifact {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
}

async fn list_rpm_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
) -> Result<Vec<RpmArtifact>, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
        ORDER BY a.created_at DESC
        "#,
        repo_id
    )
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;

    Ok(rows
        .into_iter()
        .map(|r| RpmArtifact {
            id: r.id,
            path: r.path,
            name: r.name,
            version: r.version,
            size_bytes: r.size_bytes,
            checksum_sha256: r.checksum_sha256,
            storage_key: r.storage_key,
            metadata: r.metadata,
        })
        .collect())
}

/// Collect the RPM artifacts a repodata response should describe.
///
/// For Hosted (Local/Staging) repos this is just the repo's own artifacts.
/// For Virtual repos the metadata must reflect the union of every member
/// repo's packages — otherwise `repomd.xml`/`primary.xml.gz` advertise
/// `packages="0"` and `dnf` treats the aggregate repo as empty even though
/// the members hold packages (#1780). We resolve the member repo IDs via
/// `fetch_virtual_members` and concatenate each member's artifact list.
async fn collect_repodata_artifacts(
    db: &sqlx::PgPool,
    repo: &RepoInfo,
) -> Result<Vec<RpmArtifact>, Response> {
    if repo.repo_type != RepositoryType::Virtual {
        return list_rpm_artifacts(db, repo.id).await;
    }

    let members = proxy_helpers::fetch_virtual_members(db, repo.id).await?;
    let mut artifacts = Vec::new();
    for member in &members {
        artifacts.extend(list_rpm_artifacts(db, member.id).await?);
    }
    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Shared repomd.xml generation
// ---------------------------------------------------------------------------

fn generate_repomd_xml_content(artifacts: &[RpmArtifact]) -> String {
    // Generate primary.xml content and compute both the compressed (gzipped)
    // and uncompressed (open) sha256 + sizes. DNF/createrepo clients expect a
    // top-level <revision> plus per-<data> <open-checksum>/<open-size> elements
    // (#1780); omitting them causes stricter clients to reject the metadata.
    let primary_xml = generate_primary_xml(artifacts);
    let primary_open_sha256 = sha256_hex(primary_xml.as_bytes());
    let primary_open_size = primary_xml.len();
    let primary_gz = gzip_bytes(primary_xml.as_bytes());
    let primary_sha256 = sha256_hex(&primary_gz);

    let filelists_xml = generate_filelists_xml(artifacts);
    let filelists_open_sha256 = sha256_hex(filelists_xml.as_bytes());
    let filelists_open_size = filelists_xml.len();
    let filelists_gz = gzip_bytes(filelists_xml.as_bytes());
    let filelists_sha256 = sha256_hex(&filelists_gz);

    let other_xml = generate_other_xml(artifacts);
    let other_open_sha256 = sha256_hex(other_xml.as_bytes());
    let other_open_size = other_xml.len();
    let other_gz = gzip_bytes(other_xml.as_bytes());
    let other_sha256 = sha256_hex(&other_gz);

    let updateinfo_xml = generate_updateinfo_xml();
    let updateinfo_open_sha256 = sha256_hex(updateinfo_xml.as_bytes());
    let updateinfo_open_size = updateinfo_xml.len();
    let updateinfo_gz = gzip_bytes(updateinfo_xml.as_bytes());
    let updateinfo_sha256 = sha256_hex(&updateinfo_gz);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>{timestamp}</revision>
  <data type="primary">
    <location href="repodata/primary.xml.gz"/>
    <checksum type="sha256">{primary_sha256}</checksum>
    <open-checksum type="sha256">{primary_open_sha256}</open-checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{primary_size}</size>
    <open-size>{primary_open_size}</open-size>
  </data>
  <data type="filelists">
    <location href="repodata/filelists.xml.gz"/>
    <checksum type="sha256">{filelists_sha256}</checksum>
    <open-checksum type="sha256">{filelists_open_sha256}</open-checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{filelists_size}</size>
    <open-size>{filelists_open_size}</open-size>
  </data>
  <data type="other">
    <location href="repodata/other.xml.gz"/>
    <checksum type="sha256">{other_sha256}</checksum>
    <open-checksum type="sha256">{other_open_sha256}</open-checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{other_size}</size>
    <open-size>{other_open_size}</open-size>
  </data>
  <data type="updateinfo">
    <location href="repodata/updateinfo.xml.gz"/>
    <checksum type="sha256">{updateinfo_sha256}</checksum>
    <open-checksum type="sha256">{updateinfo_open_sha256}</open-checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{updateinfo_size}</size>
    <open-size>{updateinfo_open_size}</open-size>
  </data>
</repomd>
"#,
        primary_sha256 = primary_sha256,
        primary_open_sha256 = primary_open_sha256,
        filelists_sha256 = filelists_sha256,
        filelists_open_sha256 = filelists_open_sha256,
        other_sha256 = other_sha256,
        other_open_sha256 = other_open_sha256,
        updateinfo_sha256 = updateinfo_sha256,
        updateinfo_open_sha256 = updateinfo_open_sha256,
        timestamp = timestamp,
        primary_size = primary_gz.len(),
        primary_open_size = primary_open_size,
        filelists_size = filelists_gz.len(),
        filelists_open_size = filelists_open_size,
        other_size = other_gz.len(),
        other_open_size = other_open_size,
        updateinfo_size = updateinfo_gz.len(),
        updateinfo_open_size = updateinfo_open_size,
    )
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml
// ---------------------------------------------------------------------------

async fn repomd_xml(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    // #1447: for Remote repos proxy the upstream repomd.xml instead of
    // synthesizing an empty index from local artifacts.
    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/repomd.xml", "application/xml").await?
    {
        return Ok(resp);
    }

    let artifacts = collect_repodata_artifacts(&state.db, &repo).await?;
    let xml = generate_repomd_xml_content(&artifacts);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml.asc — Detached PGP signature
// ---------------------------------------------------------------------------

async fn repomd_xml_asc(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    // #1447: proxy the upstream detached signature for Remote repos.
    if let Some(resp) = try_proxy_repodata(
        &state,
        &repo,
        "repodata/repomd.xml.asc",
        "application/pgp-signature",
    )
    .await?
    {
        return Ok(resp);
    }

    let artifacts = collect_repodata_artifacts(&state.db, &repo).await?;
    let repomd_content = generate_repomd_xml_content(&artifacts);

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, repomd_content.as_bytes())
        .await
        .unwrap_or(None);

    match signature {
        Some(sig_bytes) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
            // Wrap base64 at 76 characters per line (PGP armor convention)
            let wrapped: Vec<&str> = b64
                .as_bytes()
                .chunks(76)
                .map(|c| std::str::from_utf8(c).unwrap_or(""))
                .collect();
            let armored = format!(
                "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
                wrapped.join("\n"),
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/pgp-signature")
                .body(Body::from(armored))
                .unwrap())
        }
        None => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml.key — Public key for rpm --import
// ---------------------------------------------------------------------------

async fn repomd_xml_key(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .unwrap_or(None);

    match public_key {
        Some(pem) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/x-pem-file")
            .body(Body::from(pem))
            .unwrap()),
        None => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/updateinfo.xml.gz — Update advisories (stub)
// ---------------------------------------------------------------------------

async fn updateinfo_xml_gz(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) = try_proxy_repodata(
        &state,
        &repo,
        "repodata/updateinfo.xml.gz",
        "application/gzip",
    )
    .await?
    {
        return Ok(resp);
    }

    let updateinfo_xml = generate_updateinfo_xml();
    let gz = gzip_bytes(updateinfo_xml.as_bytes());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, gz.len().to_string())
        .body(Body::from(gz))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/primary.xml.gz
// ---------------------------------------------------------------------------

async fn primary_xml_gz(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/primary.xml.gz", "application/gzip").await?
    {
        return Ok(resp);
    }

    let artifacts = collect_repodata_artifacts(&state.db, &repo).await?;

    let primary_xml = generate_primary_xml(&artifacts);
    let gz = gzip_bytes(primary_xml.as_bytes());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, gz.len().to_string())
        .body(Body::from(gz))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/filelists.xml.gz
// ---------------------------------------------------------------------------

async fn filelists_xml_gz(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) = try_proxy_repodata(
        &state,
        &repo,
        "repodata/filelists.xml.gz",
        "application/gzip",
    )
    .await?
    {
        return Ok(resp);
    }

    let artifacts = collect_repodata_artifacts(&state.db, &repo).await?;

    let filelists_xml = generate_filelists_xml(&artifacts);
    let gz = gzip_bytes(filelists_xml.as_bytes());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, gz.len().to_string())
        .body(Body::from(gz))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/other.xml.gz
// ---------------------------------------------------------------------------

async fn other_xml_gz(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/other.xml.gz", "application/gzip").await?
    {
        return Ok(resp);
    }

    let artifacts = collect_repodata_artifacts(&state.db, &repo).await?;

    let other_xml = generate_other_xml(&artifacts);
    let gz = gzip_bytes(other_xml.as_bytes());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, gz.len().to_string())
        .body(Body::from(gz))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/*path — Catch-all for hash-prefixed
// repodata files. Upstream RPM repositories typically reference their
// real metadata payloads via checksum-prefixed names listed inside
// repomd.xml (e.g. `repodata/abc123...-primary.xml.gz`). When the
// repository is Remote we proxy those paths verbatim; for Hosted
// repos there is no such file so we 404.
// ---------------------------------------------------------------------------

async fn repodata_proxy(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    let upstream_path = format!("repodata/{}", path);
    let default_ct = if path.ends_with(".gz") {
        "application/gzip"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".asc") {
        "application/pgp-signature"
    } else {
        "application/octet-stream"
    };

    if let Some(resp) = try_proxy_repodata(&state, &repo, &upstream_path, default_ct).await? {
        return Ok(resp);
    }

    Err((StatusCode::NOT_FOUND, "Not found").into_response())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/*upstream_path — Proxy fallback for upstream
// package locations that do not live under /packages/. Many real-world
// yum/dnf repositories host RPMs at the repository root or under
// vendor-specific subpaths (Packages/, pool/, el/6/x86_64/...).
//
// Hosted repos always 404 here (their packages must come via the
// explicit /packages/ route). Remote repos try the local cache by
// filename first, then fall back to streaming the upstream object.
// ---------------------------------------------------------------------------

async fn upstream_proxy(
    State(state): State<SharedState>,
    Path((repo_key, upstream_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if repo.repo_type != RepositoryType::Remote {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let filename = upstream_path.rsplit('/').next().unwrap_or(&upstream_path);

    // Cache hit by filename: serve the local copy.
    if let Some(hit) =
        proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await?
    {
        let artifact = sqlx::query!(
            "SELECT id, size_bytes, checksum_sha256, storage_key FROM artifacts WHERE id = $1",
            hit.id
        )
        .fetch_one(&state.db)
        .await
        .map_err(super::db_err)?;

        let storage = state
            .storage_for_repo(&repo.storage_location())
            .map_err(|e| e.into_response())?;
        crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
            .await
            .map_err(|e| e.into_response())?;
        // Stream the local cache hit instead of buffering the whole .rpm in
        // memory (#1608, Core Invariant ①). Content-Length comes from the
        // stored `size_bytes` so we keep the exact byte count without reading
        // the object first. A missing storage key surfaces as AppError::NotFound
        // from `get_stream`, matching the storage NotFound contract (#1016).
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

        return Ok(build_rpm_package_response(
            Body::from_stream(stream),
            filename,
            artifact.size_bytes,
            &artifact.checksum_sha256,
        ));
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    proxy_helpers::proxy_fetch_streaming_with_disposition(
        proxy,
        repo.id,
        &repo_key,
        upstream_url,
        &upstream_path,
        "application/x-rpm",
        Some(filename),
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/packages/*path — Download RPM package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, pkg_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    let filename = pkg_path.rsplit('/').next().unwrap_or(&pkg_path);

    let hit =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("packages/{}", pkg_path);
                let (default_ct, cd_filename) = if repo.repo_type == RepositoryType::Virtual {
                    ("application/x-rpm", Some(filename))
                } else {
                    ("application/octet-stream", None)
                };
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    &repo,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                        default_content_type: default_ct,
                        content_disposition_filename: cd_filename,
                        suppress_upstream_proxy: false,
                    },
                )
                .await?
                {
                    return Ok(resp);
                }
                return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
            }
        };

    // RPM hit-path needs the SHA256 to emit X-Checksum-SHA256, so re-query
    // to pick up the checksum field that the lightweight helper omits.
    let artifact = sqlx::query!(
        "SELECT id, size_bytes, checksum_sha256, storage_key FROM artifacts WHERE id = $1",
        hit.id
    )
    .fetch_one(&state.db)
    .await
    .map_err(super::db_err)?;

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
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    Ok(build_rpm_package_response(
        Body::from_stream(stream),
        filename,
        artifact.size_bytes,
        &artifact.checksum_sha256,
    ))
}

// ---------------------------------------------------------------------------
// PUT /rpm/{repo_key}/packages/*path — Upload RPM package
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, pkg_path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "rpm", "write")?.user_id;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    reject_rpm_write_if_not_hosted(&repo.repo_type)?;

    let filename = pkg_path.rsplit('/').next().unwrap_or(&pkg_path).to_string();

    if !filename.ends_with(".rpm") {
        return Err((StatusCode::BAD_REQUEST, "File must have .rpm extension").into_response());
    }

    store_rpm(&state, &repo, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// POST /rpm/{repo_key}/upload — Upload RPM package (alternative)
// ---------------------------------------------------------------------------

async fn upload_package_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "rpm", "write")?.user_id;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    reject_rpm_write_if_not_hosted(&repo.repo_type)?;

    // Try to get filename from Content-Disposition header, fall back to a hash-based name
    let filename = headers
        .get("Content-Disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split("filename=")
                .nth(1)
                .map(|f| f.trim_matches('"').trim_matches('\'').to_string())
        })
        .or_else(|| {
            headers
                .get("X-Package-Filename")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| {
            let hash = sha256_hex(&body);
            format!("{}.rpm", &hash[..16])
        });

    if !filename.ends_with(".rpm") {
        return Err((StatusCode::BAD_REQUEST, "File must have .rpm extension").into_response());
    }

    store_rpm(&state, &repo, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

async fn store_rpm(
    state: &SharedState,
    repo: &RepoInfo,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    let computed_sha256 = sha256_hex(&content);

    // Parse RPM filename for metadata
    let (pkg_name, pkg_version, release, arch) = parse_rpm_filename(filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid RPM filename '{}'. Expected format: {{name}}-{{version}}-{{release}}.{{arch}}.rpm",
                filename
            ),
        )
            .into_response()
    })?;

    let full_version = format!("{}-{}", pkg_version, release);
    let artifact_path = format!("packages/{}", filename);

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Package already exists",
    )
    .await?;

    let storage_key = format!("rpm/{}/{}", repo.id, filename);
    proxy_helpers::put_artifact_bytes(state, repo, &storage_key, content.clone()).await?;

    let size_bytes = content.len() as i64;

    // Insert artifact record
    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &pkg_name,
            version: &full_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/x-rpm",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    // Store RPM-specific metadata
    let rpm_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "release": release,
        "arch": arch,
        "filename": filename,
    });

    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "rpm", &rpm_metadata)
        .await;

    info!(
        "RPM upload: {}-{}-{}.{}.rpm to repo {}",
        pkg_name, pkg_version, release, arch, repo.id
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": pkg_name,
                "version": pkg_version,
                "release": release,
                "arch": arch,
                "sha256": computed_sha256,
                "size": size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// XML generation helpers
// ---------------------------------------------------------------------------

fn generate_primary_xml(artifacts: &[RpmArtifact]) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{}">
"#,
        artifacts.len()
    );

    for artifact in artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        // Extract metadata from artifact_metadata if available, else parse filename
        let (name, version, release, arch, summary) = if let Some(ref meta) = artifact.metadata {
            (
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&artifact.name)
                    .to_string(),
                meta.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string(),
                meta.get("release")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_string(),
                meta.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("noarch")
                    .to_string(),
                meta.get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        } else if let Some((n, v, r, a)) = parse_rpm_filename(filename) {
            (n, v, r, a, String::new())
        } else {
            (
                artifact.name.clone(),
                artifact.version.clone().unwrap_or_else(|| "0".to_string()),
                "1".to_string(),
                "noarch".to_string(),
                String::new(),
            )
        };

        xml.push_str(&format!(
            r#"  <package type="rpm">
    <name>{name}</name>
    <version epoch="0" ver="{version}" rel="{release}"/>
    <arch>{arch}</arch>
    <checksum type="sha256" pkgid="YES">{checksum}</checksum>
    <summary>{summary}</summary>
    <size package="{size}" installed="0"/>
    <location href="{location}"/>
  </package>
"#,
            name = xml_escape(&name),
            version = xml_escape(&version),
            release = xml_escape(&release),
            arch = xml_escape(&arch),
            checksum = artifact.checksum_sha256,
            summary = xml_escape(&summary),
            size = artifact.size_bytes,
            location = xml_escape(&artifact.path),
        ));
    }

    xml.push_str("</metadata>\n");
    xml
}

fn generate_filelists_xml(artifacts: &[RpmArtifact]) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="{}">
"#,
        artifacts.len()
    );

    for artifact in artifacts {
        let (name, version, release, _arch) = if let Some(ref meta) = artifact.metadata {
            (
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&artifact.name)
                    .to_string(),
                meta.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string(),
                meta.get("release")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_string(),
                meta.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("noarch")
                    .to_string(),
            )
        } else {
            let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
            parse_rpm_filename(filename).unwrap_or_else(|| {
                (
                    artifact.name.clone(),
                    artifact.version.clone().unwrap_or_else(|| "0".to_string()),
                    "1".to_string(),
                    "noarch".to_string(),
                )
            })
        };

        xml.push_str(&format!(
            r#"  <package pkgid="{checksum}" name="{name}" arch="{arch}">
    <version epoch="0" ver="{version}" rel="{release}"/>
  </package>
"#,
            checksum = artifact.checksum_sha256,
            name = xml_escape(&name),
            arch = if let Some(ref meta) = artifact.metadata {
                meta.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("noarch")
                    .to_string()
            } else {
                "noarch".to_string()
            },
            version = xml_escape(&version),
            release = xml_escape(&release),
        ));
    }

    xml.push_str("</filelists>\n");
    xml
}

fn generate_other_xml(artifacts: &[RpmArtifact]) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="{}">
"#,
        artifacts.len()
    );

    for artifact in artifacts {
        let (name, version, release) = if let Some(ref meta) = artifact.metadata {
            (
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&artifact.name)
                    .to_string(),
                meta.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string(),
                meta.get("release")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_string(),
            )
        } else {
            let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
            let parsed = parse_rpm_filename(filename);
            (
                parsed
                    .as_ref()
                    .map(|p| p.0.clone())
                    .unwrap_or_else(|| artifact.name.clone()),
                parsed
                    .as_ref()
                    .map(|p| p.1.clone())
                    .unwrap_or_else(|| artifact.version.clone().unwrap_or_else(|| "0".to_string())),
                parsed
                    .as_ref()
                    .map(|p| p.2.clone())
                    .unwrap_or_else(|| "1".to_string()),
            )
        };

        xml.push_str(&format!(
            r#"  <package pkgid="{checksum}" name="{name}" arch="{arch}">
    <version epoch="0" ver="{version}" rel="{release}"/>
  </package>
"#,
            checksum = artifact.checksum_sha256,
            name = xml_escape(&name),
            arch = if let Some(ref meta) = artifact.metadata {
                meta.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("noarch")
                    .to_string()
            } else {
                "noarch".to_string()
            },
            version = xml_escape(&version),
            release = xml_escape(&release),
        ));
    }

    xml.push_str("</otherdata>\n");
    xml
}

fn generate_updateinfo_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<updates></updates>
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("gzip write failed");
    encoder.finish().expect("gzip finish failed")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// Wrap a base64-encoded signature in PGP armor format.
    fn pgp_armor_signature(b64: &str) -> String {
        let wrapped: Vec<&str> = b64
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect();
        format!(
            "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
            wrapped.join("\n"),
        )
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (test-only)
    // -----------------------------------------------------------------------

    /// Build the artifact path for an RPM package.
    fn build_rpm_artifact_path(filename: &str) -> String {
        format!("packages/{}", filename)
    }

    /// Build the storage key for an RPM package.
    fn build_rpm_storage_key(repo_id: &uuid::Uuid, filename: &str) -> String {
        format!("rpm/{}/{}", repo_id, filename)
    }

    /// Build the full version string from version and release.
    fn build_rpm_full_version(version: &str, release: &str) -> String {
        format!("{}-{}", version, release)
    }

    /// Build RPM-specific metadata JSON.
    fn build_rpm_metadata(
        name: &str,
        version: &str,
        release: &str,
        arch: &str,
        filename: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
            "filename": filename,
        })
    }

    /// Build the upload response JSON.
    fn build_rpm_upload_response(
        name: &str,
        version: &str,
        release: &str,
        arch: &str,
        sha256: &str,
        size: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
            "sha256": sha256,
            "size": size,
        })
    }

    /// Extract RPM filename from headers, falling back to a hash-based name.
    fn extract_rpm_filename(headers: &HeaderMap, body_hash: &str) -> String {
        headers
            .get("Content-Disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split("filename=")
                    .nth(1)
                    .map(|f| f.trim_matches('"').trim_matches('\'').to_string())
            })
            .or_else(|| {
                headers
                    .get("X-Package-Filename")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("{}.rpm", &body_hash[..16]))
    }

    // -----------------------------------------------------------------------
    // parse_rpm_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rpm_filename_standard() {
        let result = parse_rpm_filename("my-package-1.0.0-1.x86_64.rpm");
        assert_eq!(
            result,
            Some((
                "my-package".to_string(),
                "1.0.0".to_string(),
                "1".to_string(),
                "x86_64".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_rpm_filename_with_el() {
        let result = parse_rpm_filename("hello-2.10-1.el8.noarch.rpm");
        assert_eq!(
            result,
            Some((
                "hello".to_string(),
                "2.10".to_string(),
                "1.el8".to_string(),
                "noarch".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_rpm_filename_complex_name() {
        let result = parse_rpm_filename("my-cool-app-3.2.1-2.fc38.aarch64.rpm");
        assert_eq!(
            result,
            Some((
                "my-cool-app".to_string(),
                "3.2.1".to_string(),
                "2.fc38".to_string(),
                "aarch64".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_rpm_filename_invalid() {
        assert_eq!(parse_rpm_filename("notanrpm.txt"), None);
        assert_eq!(parse_rpm_filename("bad.rpm"), None);
        assert_eq!(parse_rpm_filename(""), None);
    }

    #[test]
    fn test_parse_rpm_filename_src_rpm() {
        // Source RPMs still have .rpm extension in this parser
        let result = parse_rpm_filename("kernel-5.14.0-284.el9.src.rpm");
        assert!(result.is_some());
        let (name, version, release, arch) = result.unwrap();
        assert_eq!(name, "kernel");
        assert_eq!(version, "5.14.0");
        assert_eq!(release, "284.el9");
        assert_eq!(arch, "src");
    }

    #[test]
    fn test_parse_rpm_filename_single_char_name() {
        let result = parse_rpm_filename("a-1.0-1.x86_64.rpm");
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "a");
    }

    // -----------------------------------------------------------------------
    // xml_escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_xml_escape_all_entities() {
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
    }

    #[test]
    fn test_xml_escape_no_special_chars() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    #[test]
    fn test_xml_escape_empty_string() {
        assert_eq!(xml_escape(""), "");
    }

    #[test]
    fn test_xml_escape_ampersand_first() {
        // Verify & is escaped before other entities to avoid double-escaping
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("&&"), "&amp;&amp;");
    }

    #[test]
    fn test_xml_escape_all_ampersands() {
        assert_eq!(xml_escape("a&b&c"), "a&amp;b&amp;c");
    }

    // -----------------------------------------------------------------------
    // sha256_hex
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_hex_known_value() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hex_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_length() {
        let hash = sha256_hex(b"anything");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"test");
        let h2 = sha256_hex(b"test");
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // gzip_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_gzip_roundtrip() {
        let original = b"test data for gzip";
        let compressed = gzip_bytes(original);
        assert!(!compressed.is_empty());
        assert_ne!(compressed, original);

        // Decompress and verify
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed.as_bytes(), original);
    }

    #[test]
    fn test_gzip_bytes_empty_input() {
        let compressed = gzip_bytes(b"");
        assert!(!compressed.is_empty()); // gzip header still present
    }

    #[test]
    fn test_gzip_bytes_starts_with_gzip_magic() {
        let compressed = gzip_bytes(b"hello");
        assert!(compressed.len() >= 2);
        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);
    }

    // -----------------------------------------------------------------------
    // build_rpm_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpm_artifact_path_basic() {
        assert_eq!(
            build_rpm_artifact_path("my-package-1.0.0-1.x86_64.rpm"),
            "packages/my-package-1.0.0-1.x86_64.rpm"
        );
    }

    #[test]
    fn test_build_rpm_artifact_path_simple() {
        assert_eq!(build_rpm_artifact_path("hello.rpm"), "packages/hello.rpm");
    }

    #[test]
    fn test_build_rpm_artifact_path_complex() {
        assert_eq!(
            build_rpm_artifact_path("glibc-2.34-60.el9.aarch64.rpm"),
            "packages/glibc-2.34-60.el9.aarch64.rpm"
        );
    }

    // -----------------------------------------------------------------------
    // build_rpm_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpm_storage_key_basic() {
        let id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            build_rpm_storage_key(&id, "pkg-1.0-1.x86_64.rpm"),
            "rpm/00000000-0000-0000-0000-000000000001/pkg-1.0-1.x86_64.rpm"
        );
    }

    #[test]
    fn test_build_rpm_storage_key_different_uuid() {
        let id = uuid::Uuid::new_v4();
        let key = build_rpm_storage_key(&id, "test.rpm");
        assert!(key.starts_with("rpm/"));
        assert!(key.ends_with("/test.rpm"));
        assert!(key.contains(&id.to_string()));
    }

    // -----------------------------------------------------------------------
    // build_rpm_full_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpm_full_version_basic() {
        assert_eq!(build_rpm_full_version("1.0.0", "1"), "1.0.0-1");
    }

    #[test]
    fn test_build_rpm_full_version_with_el() {
        assert_eq!(build_rpm_full_version("2.10", "1.el8"), "2.10-1.el8");
    }

    #[test]
    fn test_build_rpm_full_version_complex() {
        assert_eq!(
            build_rpm_full_version("5.14.0", "284.30.1.el9_2"),
            "5.14.0-284.30.1.el9_2"
        );
    }

    // -----------------------------------------------------------------------
    // build_rpm_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpm_metadata_all_fields() {
        let meta = build_rpm_metadata("my-pkg", "1.0", "1", "x86_64", "my-pkg-1.0-1.x86_64.rpm");
        assert_eq!(meta["name"], "my-pkg");
        assert_eq!(meta["version"], "1.0");
        assert_eq!(meta["release"], "1");
        assert_eq!(meta["arch"], "x86_64");
        assert_eq!(meta["filename"], "my-pkg-1.0-1.x86_64.rpm");
    }

    #[test]
    fn test_build_rpm_metadata_noarch() {
        let meta = build_rpm_metadata(
            "python-six",
            "1.16.0",
            "1.el9",
            "noarch",
            "python-six-1.16.0-1.el9.noarch.rpm",
        );
        assert_eq!(meta["arch"], "noarch");
    }

    #[test]
    fn test_build_rpm_metadata_is_valid_json() {
        let meta = build_rpm_metadata("a", "b", "c", "d", "e");
        let s = serde_json::to_string(&meta).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(parsed.is_object());
    }

    // -----------------------------------------------------------------------
    // build_rpm_upload_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpm_upload_response_all_fields() {
        let resp = build_rpm_upload_response("pkg", "1.0", "1", "x86_64", "abc123", 1024);
        assert_eq!(resp["name"], "pkg");
        assert_eq!(resp["version"], "1.0");
        assert_eq!(resp["release"], "1");
        assert_eq!(resp["arch"], "x86_64");
        assert_eq!(resp["sha256"], "abc123");
        assert_eq!(resp["size"], 1024);
    }

    #[test]
    fn test_build_rpm_upload_response_zero_size() {
        let resp = build_rpm_upload_response("pkg", "1.0", "1", "noarch", "def", 0);
        assert_eq!(resp["size"], 0);
    }

    #[test]
    fn test_build_rpm_upload_response_large_size() {
        let resp = build_rpm_upload_response("big", "1.0", "1", "x86_64", "hash", 1_073_741_824);
        assert_eq!(resp["size"], 1_073_741_824i64);
    }

    // -----------------------------------------------------------------------
    // extract_rpm_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_rpm_filename_from_content_disposition() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            HeaderValue::from_static("attachment; filename=my-pkg-1.0-1.x86_64.rpm"),
        );
        assert_eq!(
            extract_rpm_filename(&headers, "somehash1234567890"),
            "my-pkg-1.0-1.x86_64.rpm"
        );
    }

    #[test]
    fn test_extract_rpm_filename_from_x_package_filename() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Package-Filename",
            HeaderValue::from_static("custom-name.rpm"),
        );
        assert_eq!(
            extract_rpm_filename(&headers, "somehash1234567890"),
            "custom-name.rpm"
        );
    }

    #[test]
    fn test_extract_rpm_filename_fallback_to_hash() {
        let headers = HeaderMap::new();
        let result = extract_rpm_filename(&headers, "abcdef1234567890abcdef");
        assert_eq!(result, "abcdef1234567890.rpm");
    }

    #[test]
    fn test_extract_rpm_filename_content_disposition_priority() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            HeaderValue::from_static("attachment; filename=from-cd.rpm"),
        );
        headers.insert(
            "X-Package-Filename",
            HeaderValue::from_static("from-header.rpm"),
        );
        // Content-Disposition has priority
        assert_eq!(extract_rpm_filename(&headers, "hash"), "from-cd.rpm");
    }

    #[test]
    fn test_extract_rpm_filename_quoted_filename() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            HeaderValue::from_static("attachment; filename=\"quoted.rpm\""),
        );
        assert_eq!(
            extract_rpm_filename(&headers, "hash1234567890123456"),
            "quoted.rpm"
        );
    }

    // -----------------------------------------------------------------------
    // pgp_armor_signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_pgp_armor_signature_basic() {
        let armored = pgp_armor_signature("dGVzdA==");
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(armored.ends_with("-----END PGP SIGNATURE-----\n"));
        assert!(armored.contains("dGVzdA=="));
    }

    #[test]
    fn test_pgp_armor_signature_wrapping() {
        // Create a long base64 string that exceeds 76 chars
        let long_b64 = "A".repeat(200);
        let armored = pgp_armor_signature(&long_b64);
        // Each line in the body should be at most 76 characters
        let body = armored
            .strip_prefix("-----BEGIN PGP SIGNATURE-----\n\n")
            .unwrap()
            .strip_suffix("\n-----END PGP SIGNATURE-----\n")
            .unwrap();
        for line in body.lines() {
            assert!(line.len() <= 76, "Line exceeds 76 chars: {}", line);
        }
    }

    #[test]
    fn test_pgp_armor_signature_empty() {
        let armored = pgp_armor_signature("");
        assert!(armored.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(armored.contains("-----END PGP SIGNATURE-----"));
    }

    #[test]
    fn test_pgp_armor_signature_short() {
        let armored = pgp_armor_signature("YQ==");
        assert!(armored.contains("YQ=="));
    }

    // -----------------------------------------------------------------------
    // XML generation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_primary_xml_empty() {
        let xml = generate_primary_xml(&[]);
        assert!(xml.contains("packages=\"0\""));
        assert!(xml.contains("</metadata>"));
        assert!(xml.contains("xmlns=\"http://linux.duke.edu/metadata/common\""));
    }

    #[test]
    fn test_generate_primary_xml_with_artifact() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/test-1.0-1.x86_64.rpm".to_string(),
            name: "test".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/test-1.0-1.x86_64.rpm".to_string(),
            metadata: Some(serde_json::json!({
                "name": "test",
                "version": "1.0",
                "release": "1",
                "arch": "x86_64",
            })),
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(xml.contains("packages=\"1\""));
        assert!(xml.contains("<name>test</name>"));
        assert!(xml.contains("ver=\"1.0\""));
        assert!(xml.contains("rel=\"1\""));
        assert!(xml.contains("<arch>x86_64</arch>"));
    }

    #[test]
    fn test_generate_primary_xml_escapes_special_chars() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/test-1.0-1.x86_64.rpm".to_string(),
            name: "test<pkg>".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 512,
            checksum_sha256: "def456".to_string(),
            storage_key: "rpm/1/test.rpm".to_string(),
            metadata: Some(serde_json::json!({
                "name": "test<pkg>",
                "version": "1.0",
                "release": "1",
                "arch": "x86_64",
            })),
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(xml.contains("test&lt;pkg&gt;"));
    }

    #[test]
    fn test_generate_filelists_xml_empty() {
        let xml = generate_filelists_xml(&[]);
        assert!(xml.contains("packages=\"0\""));
        assert!(xml.contains("</filelists>"));
    }

    #[test]
    fn test_generate_filelists_xml_with_artifact() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/hello-1.0-1.noarch.rpm".to_string(),
            name: "hello".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 256,
            checksum_sha256: "sha256hash".to_string(),
            storage_key: "rpm/1/hello.rpm".to_string(),
            metadata: Some(serde_json::json!({
                "name": "hello",
                "version": "1.0",
                "release": "1",
                "arch": "noarch",
            })),
        }];
        let xml = generate_filelists_xml(&artifacts);
        assert!(xml.contains("packages=\"1\""));
        assert!(xml.contains("name=\"hello\""));
        assert!(xml.contains("arch=\"noarch\""));
    }

    #[test]
    fn test_generate_other_xml_empty() {
        let xml = generate_other_xml(&[]);
        assert!(xml.contains("packages=\"0\""));
        assert!(xml.contains("</otherdata>"));
    }

    #[test]
    fn test_generate_other_xml_with_artifact() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/util-2.0-3.el9.x86_64.rpm".to_string(),
            name: "util".to_string(),
            version: Some("2.0-3".to_string()),
            size_bytes: 4096,
            checksum_sha256: "otherhash".to_string(),
            storage_key: "rpm/1/util.rpm".to_string(),
            metadata: Some(serde_json::json!({
                "name": "util",
                "version": "2.0",
                "release": "3.el9",
                "arch": "x86_64",
            })),
        }];
        let xml = generate_other_xml(&artifacts);
        assert!(xml.contains("packages=\"1\""));
        assert!(xml.contains("name=\"util\""));
    }

    #[test]
    fn test_generate_updateinfo_xml() {
        let xml = generate_updateinfo_xml();
        assert!(xml.contains("<updates></updates>"));
        assert!(xml.contains("<?xml version=\"1.0\""));
    }

    #[test]
    fn test_generate_repomd_xml_content_empty() {
        let xml = generate_repomd_xml_content(&[]);
        assert!(xml.contains("<repomd"));
        assert!(xml.contains("</repomd>"));
        assert!(xml.contains("type=\"primary\""));
        assert!(xml.contains("type=\"filelists\""));
        assert!(xml.contains("type=\"other\""));
        assert!(xml.contains("type=\"updateinfo\""));
        assert!(xml.contains("checksum type=\"sha256\""));
    }

    #[test]
    fn test_generate_repomd_xml_content_has_sizes() {
        let xml = generate_repomd_xml_content(&[]);
        assert!(xml.contains("<size>"));
    }

    // -----------------------------------------------------------------------
    // Primary XML with no metadata falls back to filename parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_primary_xml_no_metadata_fallback() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/curl-7.88.1-8.el9.x86_64.rpm".to_string(),
            name: "curl".to_string(),
            version: Some("7.88.1-8".to_string()),
            size_bytes: 2048,
            checksum_sha256: "fallbackhash".to_string(),
            storage_key: "rpm/1/curl.rpm".to_string(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        // Falls back to parse_rpm_filename from the path
        assert!(xml.contains("<name>curl</name>"));
        assert!(xml.contains("ver=\"7.88.1\""));
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for the proxy_helpers-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_rpm_download_404_when_missing() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/packages/missing-1.0-1.x86_64.rpm", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_download_serves_local() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "rpm/curl/7.88.1/curl-7.88.1-1.x86_64.rpm",
            "curl/7.88.1/curl-7.88.1-1.x86_64.rpm",
            "curl",
            "7.88.1",
            "application/x-rpm",
            bytes::Bytes::from_static(b"rpm-bytes"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/packages/curl-7.88.1-1.x86_64.rpm", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"rpm-bytes");
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_upload_unauthenticated_401() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::put(
            format!("/{}/packages/foo-1.0-1.x86_64.rpm", f.repo_key),
            bytes::Bytes::from_static(b"data"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_upload_remote_405() {
        let Some(f) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/packages/foo-1.0-1.x86_64.rpm", f.repo_key),
            bytes::Bytes::from_static(b"data"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_upload_succeeds_for_local() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let body: Vec<u8> = vec![0u8; 32];
        let req = tdh::put(
            format!("/{}/packages/curl-8.0.1-1.x86_64.rpm", f.repo_key),
            bytes::Bytes::from(body),
        );
        let (status, _) = tdh::send(app, req).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "got {}",
            status
        );
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_upload_invalid_filename_400() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/packages/notarpm.txt", f.repo_key),
            bytes::Bytes::from_static(b"data"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #1447: Remote RPM proxy must surface upstream repodata + packages.
    //
    // Prior to the fix, every /repodata/* handler called list_rpm_artifacts
    // and synthesized an empty repomd.xml from local rows, so dnf saw an
    // empty repo. These tests stand up a wiremock upstream, point a Remote
    // fixture at it, and drive the router end to end.
    // -----------------------------------------------------------------------

    /// Repoint the fixture's Remote repo at `upstream_url` and rebuild a
    /// SharedState that wires in a real ProxyService.
    async fn rewire_remote(
        fx: &tdh::Fixture,
        upstream_url: &str,
    ) -> (crate::api::SharedState, tempfile::TempDir) {
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream_url)
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");
        // Use a fresh tmp dir for the proxy cache so concurrent tests do
        // not collide on cache_storage_key paths.
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), dir.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), dir.path().to_str().unwrap(), proxy);
        (state, dir)
    }

    #[tokio::test]
    async fn test_rpm_remote_repomd_proxies_upstream_xml() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let server = MockServer::start().await;
        let upstream_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/abc123-primary.xml.gz"/>
  </data>
</repomd>"#;
        Mock::given(method("GET"))
            .and(path("/repodata/repomd.xml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/xml")
                    .set_body_bytes(upstream_xml.as_ref()),
            )
            .mount(&server)
            .await;

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);

        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/repomd.xml", fx.repo_key)),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != StatusCode::OK {
            teardown().await;
            panic!("repomd.xml proxy returned {}", status);
        }
        let bytes: &[u8] = &body;
        assert_eq!(bytes, upstream_xml.as_ref());
        // Sanity check: the response must NOT be the empty-local-repo
        // template that the pre-fix handler used to emit.
        assert!(
            !std::str::from_utf8(bytes)
                .unwrap_or("")
                .contains("primary.xml.gz\"/>\n    <checksum"),
            "repomd.xml should be the upstream body, not the locally generated one"
        );
        teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_remote_repodata_wildcard_proxies_hash_prefixed_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let server = MockServer::start().await;
        let primary_gz: &[u8] = b"\x1f\x8b\x08mock-primary-xml-gz";
        Mock::given(method("GET"))
            .and(path("/repodata/abc123-primary.xml.gz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/gzip")
                    .set_body_bytes(primary_gz),
            )
            .mount(&server)
            .await;

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);

        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/abc123-primary.xml.gz", fx.repo_key)),
        )
        .await;
        let teardown = || async { fx.teardown().await };
        if status != StatusCode::OK {
            teardown().await;
            panic!("repodata wildcard proxy returned {}", status);
        }
        assert_eq!(&body[..], primary_gz);
        teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_remote_upstream_proxy_serves_root_rpm() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let server = MockServer::start().await;
        let rpm_bytes: &[u8] = b"fake-rpm-binary";
        // Many real-world repos (e.g. packages.gitlab.com) host the RPMs
        // at the repository root, not under /packages/. The catch-all
        // upstream_proxy route covers that layout.
        Mock::given(method("GET"))
            .and(path("/gitlab-runner-1.0.0-1.x86_64.rpm"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-rpm")
                    .set_body_bytes(rpm_bytes),
            )
            .mount(&server)
            .await;

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);

        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/gitlab-runner-1.0.0-1.x86_64.rpm", fx.repo_key)),
        )
        .await;
        let teardown = || async { fx.teardown().await };
        if status != StatusCode::OK {
            teardown().await;
            panic!("upstream_proxy returned {}", status);
        }
        assert_eq!(&body[..], rpm_bytes);
        teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_local_repomd_still_generated_from_artifacts() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/repomd.xml", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Hosted repos keep the local-generation behaviour: an empty repo
        // still emits the repomd shell that references primary.xml.gz.
        let text = std::str::from_utf8(&body).unwrap_or("");
        assert!(text.contains("<repomd"));
        assert!(text.contains("primary.xml.gz"));
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_hosted_upstream_proxy_404s() {
        // Hosted repos must NOT honour the catch-all proxy route; otherwise
        // a typo'd local download would unexpectedly hit the internet (or
        // 502 confusingly). The route should 404 instead.
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/some-random-name.rpm", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Additional coverage for the #1447 fix: every repodata sibling handler
    // (primary/filelists/other/updateinfo) must also short-circuit to the
    // upstream proxy for Remote repos, repomd_xml.asc must proxy the
    // detached signature, and repodata_proxy must 404 for Hosted repos
    // (otherwise dnf's hash-prefixed lookups would silently 502).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rpm_remote_repodata_sibling_handlers_all_proxy_upstream() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let server = MockServer::start().await;
        // Each sibling handler advertises a different default content type
        // upstream; wiremock just needs to echo deterministic bodies so the
        // test can confirm each handler proxied the right path.
        let primary: &[u8] = b"\x1f\x8bPRIMARY";
        let filelists: &[u8] = b"\x1f\x8bFILELISTS";
        let other: &[u8] = b"\x1f\x8bOTHER";
        let updateinfo: &[u8] = b"\x1f\x8bUPDATEINFO";

        for (p, body) in [
            ("/repodata/primary.xml.gz", primary),
            ("/repodata/filelists.xml.gz", filelists),
            ("/repodata/other.xml.gz", other),
            ("/repodata/updateinfo.xml.gz", updateinfo),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/gzip")
                        .set_body_bytes(body),
                )
                .mount(&server)
                .await;
        }

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let teardown = || async { fx.teardown().await };

        for (suffix, expected) in [
            ("repodata/primary.xml.gz", primary),
            ("repodata/filelists.xml.gz", filelists),
            ("repodata/other.xml.gz", other),
            ("repodata/updateinfo.xml.gz", updateinfo),
        ] {
            let app = tdh::router_anon(super::router(), state.clone());
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, suffix))).await;
            if status != StatusCode::OK {
                teardown().await;
                panic!("{} proxy returned {}", suffix, status);
            }
            assert_eq!(&body[..], expected, "wrong body for {}", suffix);
        }

        teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_remote_repomd_asc_proxies_upstream_signature() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let server = MockServer::start().await;
        let sig: &[u8] =
            b"-----BEGIN PGP SIGNATURE-----\nupstream-sig\n-----END PGP SIGNATURE-----\n";
        Mock::given(method("GET"))
            .and(path("/repodata/repomd.xml.asc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/pgp-signature")
                    .set_body_bytes(sig),
            )
            .mount(&server)
            .await;

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/repomd.xml.asc", fx.repo_key)),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != StatusCode::OK {
            teardown().await;
            panic!("repomd.xml.asc proxy returned {}", status);
        }
        assert_eq!(&body[..], sig);
        teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_repodata_wildcard_404s_for_hosted_repos() {
        // The /repodata/*path catch-all must 404 on Hosted repos. Without
        // this guard, dnf's hash-prefixed metadata fetches would return
        // the wrong status and confuse the client.
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/abc123-primary.xml.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_upstream_proxy_404s_when_proxy_service_unavailable() {
        // Remote repo with NO proxy_service wired into SharedState (the
        // default fixture state). upstream_proxy reaches the
        // `(upstream_url, proxy) = (_, None)` fallback and must 404
        // rather than panic. Covers the cache-miss + no-proxy branch.
        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };
        let app = fx.router_anon(super::router());
        let (status, _) =
            tdh::send(app, tdh::get(format!("/{}/some-package.rpm", fx.repo_key))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_rpm_repodata_proxy_404s_for_remote_without_proxy_service() {
        // Same idea for /repodata/*path catch-all: without a wired
        // proxy_service, try_proxy_repodata returns Ok(None) and the
        // handler falls through to 404. Also drives every branch of
        // the content-type suffix detection (.xml, .asc, default).
        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };
        for suffix in [
            "repodata/abc-primary.xml",
            "repodata/repomd.xml.asc",
            "repodata/random-blob",
        ] {
            let app = fx.router_anon(super::router());
            let (status, _) =
                tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, suffix))).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "expected 404 for {}", suffix);
        }
        fx.teardown().await;
    }

    // -----------------------------------------------------------------------
    // build_rpm_package_response (#1608 streaming response builder)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_build_rpm_package_response_headers_and_streamed_body() {
        // The Content-Length MUST come from the supplied `size_bytes`
        // (the stored artifact size), NOT from re-reading the streamed body.
        // This pins the #1608 contract: the body is streamed via
        // `Body::from_stream`, yet the length header is exact.
        let payload: &[u8] = b"fake-rpm-payload-bytes";
        let stream = futures::stream::iter(vec![
            Ok::<bytes::Bytes, crate::error::AppError>(Bytes::from_static(b"fake-rpm-")),
            Ok(Bytes::from_static(b"payload-bytes")),
        ]);
        let body = Body::from_stream(stream);

        let resp = build_rpm_package_response(
            body,
            "gitlab-runner-1.0.0-1.x86_64.rpm",
            payload.len() as i64,
            "abc123checksum",
        );

        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            HeaderValue::from_static("application/x-rpm")
        );
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap(),
            HeaderValue::from_str(&payload.len().to_string()).unwrap()
        );
        assert_eq!(
            headers.get("Content-Disposition").unwrap(),
            HeaderValue::from_static("attachment; filename=\"gitlab-runner-1.0.0-1.x86_64.rpm\"")
        );
        assert_eq!(
            headers.get("X-Checksum-SHA256").unwrap(),
            HeaderValue::from_static("abc123checksum")
        );

        // The streamed body must reassemble to the exact original bytes.
        let collected = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("collect streamed rpm body");
        assert_eq!(&collected[..], payload);
    }

    #[tokio::test]
    async fn test_build_rpm_package_response_content_length_independent_of_body() {
        // Even when the body is empty, Content-Length reflects the stored
        // size_bytes argument — the builder never inspects the stream.
        let resp =
            build_rpm_package_response(Body::empty(), "pkg-2.0-1.noarch.rpm", 4096, "deadbeef");
        assert_eq!(
            resp.headers().get(CONTENT_LENGTH).unwrap(),
            HeaderValue::from_static("4096")
        );
    }

    // -----------------------------------------------------------------------
    // upstream_proxy local cache-hit streams the cached .rpm (#1608)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rpm_upstream_proxy_local_cache_hit_streams_bytes() {
        // A remote repo with a previously-cached .rpm must serve the local
        // copy by STREAMING it (get_stream + Body::from_stream) rather than
        // buffering, while emitting the right bytes and a Content-Length
        // taken from the stored size_bytes.
        use tower::ServiceExt;

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        let rpm_bytes = Bytes::from_static(b"cached-rpm-binary-contents-1234567890");
        let filename = "cached-pkg-1.2.3-1.x86_64.rpm";
        let storage_key = format!("rpm/{}/{}", fx.repo_id, filename);
        let repo = fx.repo_info("remote", Some("http://upstream.invalid"));

        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            &format!("packages/{}", filename),
            "cached-pkg",
            "1.2.3-1",
            "application/x-rpm",
            rpm_bytes.clone(),
            fx.user_id,
        )
        .await;

        let app = fx.router_anon(super::router());
        let req = tdh::get(format!("/{}/{}", fx.repo_key, filename));
        let resp = app.oneshot(req).await.expect("send cache-hit request");

        let teardown = || async { fx.teardown().await };
        if resp.status() != StatusCode::OK {
            let status = resp.status();
            teardown().await;
            panic!("cache-hit returned {}", status);
        }

        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let checksum_header = resp
            .headers()
            .get("X-Checksum-SHA256")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("collect cache-hit body");

        teardown().await;

        assert_eq!(
            &body[..],
            &rpm_bytes[..],
            "cache-hit body must match stored bytes"
        );
        assert_eq!(
            content_length.as_deref(),
            Some(rpm_bytes.len().to_string().as_str()),
            "Content-Length must equal stored size_bytes"
        );
        // seed_artifact stores checksum "test-seed"; verify it is surfaced.
        assert_eq!(checksum_header.as_deref(), Some("test-seed"));
    }

    // -----------------------------------------------------------------------
    // #1780: repomd.xml must carry <revision>, <open-checksum>, <open-size>
    // so stricter DNF/createrepo clients accept the metadata.
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_repomd_xml_content_has_revision_and_open_metadata() {
        let xml = generate_repomd_xml_content(&[]);
        // Top-level revision element present exactly once.
        assert!(xml.contains("<revision>"), "missing <revision>: {xml}");
        // Each of the four <data> blocks gets open-checksum + open-size.
        assert_eq!(
            xml.matches("<open-checksum type=\"sha256\">").count(),
            4,
            "expected 4 <open-checksum> elements: {xml}"
        );
        assert_eq!(
            xml.matches("<open-size>").count(),
            4,
            "expected 4 <open-size> elements: {xml}"
        );
    }

    #[test]
    fn test_generate_repomd_open_checksum_matches_uncompressed_primary() {
        // The primary <open-checksum> must equal sha256 of the *uncompressed*
        // primary.xml, while the regular <checksum> hashes the gzipped blob.
        let xml = generate_repomd_xml_content(&[]);
        let primary_xml = generate_primary_xml(&[]);
        let expected_open = sha256_hex(primary_xml.as_bytes());
        assert!(
            xml.contains(&format!(
                "<open-checksum type=\"sha256\">{expected_open}</open-checksum>"
            )),
            "primary open-checksum should hash the uncompressed primary.xml"
        );
        // And the compressed checksum must differ from the open one.
        let primary_gz_sha = sha256_hex(&gzip_bytes(primary_xml.as_bytes()));
        assert_ne!(expected_open, primary_gz_sha);
        assert!(xml.contains(&format!(
            "<checksum type=\"sha256\">{primary_gz_sha}</checksum>"
        )));
    }

    // -----------------------------------------------------------------------
    // #1780: PUT/POST to a virtual RPM repo must return 405 (not 400), to
    // match the remote-repo response.
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_rpm_write_virtual_returns_405() {
        let err = reject_rpm_write_if_not_hosted("virtual").unwrap_err();
        assert_eq!(err.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_reject_rpm_write_remote_returns_405() {
        let err = reject_rpm_write_if_not_hosted("remote").unwrap_err();
        assert_eq!(err.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_reject_rpm_write_local_is_ok() {
        assert!(reject_rpm_write_if_not_hosted("local").is_ok());
    }

    #[tokio::test]
    async fn test_rpm_upload_virtual_405() {
        let Some(f) = tdh::Fixture::setup("virtual", "rpm").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/packages/foo-1.0-1.x86_64.rpm", f.repo_key),
            bytes::Bytes::from_static(b"data"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #1780: Virtual repo repodata must aggregate member packages instead of
    // reporting packages="0".
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rpm_virtual_repomd_aggregates_member_packages() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let Some(f) = tdh::Fixture::setup("virtual", "rpm").await else {
            return;
        };

        // Create a hosted member repo and seed an RPM artifact into it.
        let (member_id, _member_key, _member_dir) = tdh::create_repo(&f.pool, "local", "rpm").await;
        let member_repo =
            tdh::make_repo_info(member_id, "rpm-virt-member", &f.storage_dir, "local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &member_repo,
            "rpm/member/agg-1.0-1.x86_64.rpm",
            "packages/agg-1.0-1.x86_64.rpm",
            "agg",
            "1.0-1",
            "application/x-rpm",
            bytes::Bytes::from_static(b"member-rpm-bytes"),
            f.user_id,
        )
        .await;

        // Wire the membership: virtual (f.repo_id) -> member.
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(f.repo_id)
        .bind(member_id)
        .execute(&f.pool)
        .await
        .expect("insert virtual member");

        // primary.xml.gz must report 1 package (decompress and inspect).
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/repodata/primary.xml.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut decoder = GzDecoder::new(&body[..]);
        let mut primary = String::new();
        decoder
            .read_to_string(&mut primary)
            .expect("decompress primary.xml.gz");
        assert!(
            primary.contains("packages=\"1\""),
            "virtual primary.xml should aggregate the member package, got: {primary}"
        );
        assert!(primary.contains("<name>agg</name>"));

        // Cleanup the extra member repo + membership.
        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .ok();
        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(member_id)
            .execute(&f.pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(member_id)
            .execute(&f.pool)
            .await
            .ok();
        f.teardown().await;
    }
}
