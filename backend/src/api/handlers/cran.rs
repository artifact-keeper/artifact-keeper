//! CRAN (Comprehensive R Archive Network) API handlers.
//!
//! Implements the endpoints required for R's `install.packages()` and package uploads.
//!
//! Routes are mounted at `/cran/{repo_key}/...`:
//!   GET  /cran/{repo_key}/src/contrib/PACKAGES            - Package index (text)
//!   GET  /cran/{repo_key}/src/contrib/PACKAGES.gz         - Gzipped package index
//!   GET  /cran/{repo_key}/src/contrib/{filename}          - Download source package
//!   GET  /cran/{repo_key}/bin/windows/contrib/{rversion}/PACKAGES - Windows binary index
//!   GET  /cran/{repo_key}/bin/macosx/contrib/{rversion}/PACKAGES  - macOS binary index
//!   PUT  /cran/{repo_key}/src/contrib/{filename}          - Upload package (auth required)

use crate::api::handlers::upload_body::UploadBody;
use std::io::Write as IoWrite;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::cran::CranHandler;
use crate::models::repository::{RepositoryFormat, RepositoryType};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Source package index
        .route("/:repo_key/src/contrib/PACKAGES", get(package_index))
        .route("/:repo_key/src/contrib/PACKAGES.gz", get(package_index_gz))
        // Source package download and upload
        .route(
            "/:repo_key/src/contrib/:filename",
            get(download_package).put(upload_package),
        )
        // Binary package indices
        .route(
            "/:repo_key/bin/windows/contrib/:rversion/PACKAGES",
            get(binary_index),
        )
        .route(
            "/:repo_key/bin/macosx/contrib/:rversion/PACKAGES",
            get(binary_index),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_cran_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["cran"], "a CRAN").await
}

/// Build a combined PACKAGES index from all virtual repository members.
/// Collects local member indexes via `build_source_index` and remote
/// member indexes via proxy, concatenating them with newline separators.
async fn build_virtual_combined_index(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_repo_id: uuid::Uuid,
) -> Result<(String, proxy_helpers::PartialMerge), Response> {
    // Caller-authorized member walk (#3323): the PACKAGES index is content, so
    // a member this caller may not read directly must not contribute entries.
    let members =
        proxy_helpers::authorized_virtual_members(&state.db, auth, virtual_repo_id).await?;
    let mut combined = String::new();

    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            let local_index = build_source_index(&state.db, member.id).await?;
            if !local_index.is_empty() {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&local_index);
            }
        }
    }

    let remote_indexes = proxy_helpers::collect_virtual_metadata(
        &state.db,
        auth,
        state.proxy_service.as_deref(),
        virtual_repo_id,
        "src/contrib/PACKAGES",
        |bytes, _member_key| async move {
            String::from_utf8(bytes.to_vec()).map_err(|_| {
                (StatusCode::BAD_GATEWAY, "Invalid UTF-8 from upstream").into_response()
            })
        },
    )
    .await?;

    for (_key, remote_index) in remote_indexes.documents {
        if !remote_index.is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(&remote_index);
        }
    }

    Ok((combined, remote_indexes.partial))
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/PACKAGES — Package index (text format)
// ---------------------------------------------------------------------------

/// Build the `src/contrib/PACKAGES` DCF document a request should be answered
/// with, by repository type.
///
/// * **Virtual** — the caller-authorized merge of every member's index.
/// * **Remote** — the upstream's own `PACKAGES` (the discovery document an R
///   client needs before it can install anything), merged over whatever is
///   held locally. See [`build_remote_source_index`].
/// * **Hosted / everything else** — the locally-catalogued rows.
///
/// Shared by [`package_index`] and [`package_index_gz`] so the plain and
/// gzipped routes can never disagree about which records the repository
/// advertises (the bug in #4877 was that the gzipped route shared the plain
/// route's local-only index, so BOTH were empty against a Remote upstream).
async fn build_source_index_document(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
) -> Result<(String, proxy_helpers::PartialMerge), Response> {
    if repo.repo_type == RepositoryType::Virtual {
        let (combined, partial) = build_virtual_combined_index(state, auth, repo.id).await?;
        return Ok((combined, partial));
    }

    let local = build_source_index(&state.db, repo.id).await?;

    if repo.repo_type == RepositoryType::Remote {
        match build_remote_source_index(state, repo).await {
            Ok(upstream) => {
                return Ok((
                    merge_upstream_source_index(&local, &upstream),
                    proxy_helpers::PartialMerge::default(),
                ))
            }
            // Upstream is unreachable or unparseable. With nothing held
            // locally there is no honest index to serve: an empty document is
            // indistinguishable from "upstream publishes no packages", which
            // is precisely the silent failure #4877 is about, so the
            // upstream's own error is surfaced. With packages held locally the
            // local set is still served, so an upstream outage cannot break
            // resolution of a package this repository already has.
            Err(err) if local.is_empty() => return Err(err),
            Err(err) => {
                tracing::warn!(
                    repository = %repo.key,
                    status = %err.status(),
                    "upstream CRAN PACKAGES unavailable; serving locally-held packages only"
                );
            }
        }
    }

    Ok((local, proxy_helpers::PartialMerge::default()))
}

async fn package_index(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    let (index, partial) = build_source_index_document(&state, auth.as_ref(), &repo).await?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, index.len().to_string())
        .body(Body::from(index))
        .unwrap();
    partial.mark(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/PACKAGES.gz — Gzipped package index
// ---------------------------------------------------------------------------

async fn package_index_gz(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    let (index, partial) = build_source_index_document(&state, auth.as_ref(), &repo).await?;

    let compressed = gzip_compress(index.as_bytes()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap();
    partial.mark(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/{filename} — Download source package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;

    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, &filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("src/contrib/{}", filename);
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    auth.as_ref(),
                    &repo,
                    &ctx,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(&filename),
                        default_content_type: "application/octet-stream",
                        content_disposition_filename: None,
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

    proxy_helpers::serve_local_artifact(
        &state,
        &repo,
        artifact.id,
        &artifact.storage_key,
        "application/x-gzip",
        Some(&filename),
        &ctx,
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/bin/{platform}/contrib/{rversion}/PACKAGES — Binary index
// ---------------------------------------------------------------------------

async fn binary_index(
    State(state): State<SharedState>,
    Path((repo_key, rversion)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.metadata->>'is_binary' = 'true'
        ORDER BY a.name, a.created_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(super::db_err)?;

    let _ = rversion; // Used for route matching; filtering done via metadata
    let mut index = String::new();
    for a in &artifacts {
        write_dcf_record(
            &mut index,
            &a.name,
            a.version.as_deref().unwrap_or_default(),
            a.metadata.as_ref(),
        );
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, index.len().to_string())
        .body(Body::from(index))
        .unwrap())
}

/// Append one CRAN DCF "Package/Version/Depends" record (followed by the
/// blank-line terminator) to `out`. Shared by the source and binary
/// PACKAGES index builders.
fn write_dcf_record(
    out: &mut String,
    name: &str,
    version: &str,
    metadata: Option<&serde_json::Value>,
) {
    out.push_str(&format!("Package: {}\n", name));
    out.push_str(&format!("Version: {}\n", version));
    if let Some(deps) = metadata
        .and_then(|m| m.get("depends"))
        .and_then(|v| v.as_str())
    {
        out.push_str(&format!("Depends: {}\n", deps));
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// PUT /cran/{repo_key}/src/contrib/{filename} — Upload package (auth required)
// ---------------------------------------------------------------------------

async fn upload_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
    headers: HeaderMap,
    UploadBody(body): UploadBody,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "cran", "write:artifacts")?.user_id;
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package file").into_response());
    }

    // Validate filename via format handler
    let path = format!("src/contrib/{}", filename);
    let path_info = CranHandler::parse_path(&path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid CRAN path: {}", e)).into_response()
    })?;

    let pkg_name = path_info.name.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Could not extract package name").into_response()
    })?;
    let pkg_version = path_info.version.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Could not extract package version").into_response()
    })?;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);

    // GHSA-vcq6-8hxw-4q67: the filename URL segment is spliced into the path
    // verbatim; reject traversal at ingest.
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Package version already exists",
    )
    .await?;

    let storage_key = format!("cran/{}/{}/{}", pkg_name, pkg_version, filename);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let pkg_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "filename": filename,
        "is_binary": false,
    });

    let size_bytes = body.len() as i64;

    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &pkg_name,
            version: &pkg_version,
            size_bytes,
            checksum_sha256: &computed_sha256,
            content_type: "application/x-gzip",
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await?;

    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "cran", &pkg_metadata)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    // Catalog row + the one artifact.uploaded webhook event this publish fires
    // (#3659, #3939). Not inside `insert_artifact`: its other callers already
    // register, so emitting there would double-deliver.
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        "cran",
        &pkg_name,
        &pkg_version,
        size_bytes,
        &computed_sha256,
        None,
    )
    .await;

    // #4725: fan out to subscribed push peers.
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
        "CRAN upload: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully uploaded CRAN package"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the `(package, version)` coordinates a CRAN client reconstructs the
/// download filename from, preferring the artifact's **actual stored filename**.
///
/// R's `install.packages()` turns each PACKAGES `Package`/`Version` pair back
/// into `{package}_{version}.tar.gz` and GETs it from `src/contrib/`, which the
/// download route resolves by filename suffix. Packages published natively are
/// stored at `{name}/{version}/{name}_{version}.tar.gz`, whose basename already
/// parses back to the same coordinates — so this is **byte-identical** for them.
/// But a package pushed through the generic chunked-upload flow is stored at its
/// bare filename with the whole basename as `name` and a `sha256-<prefix>`
/// fallback `version` (see `upload.rs::completed_format_artifact_version`), so
/// emitting the stored columns would advertise `{basename}_{sha256-…}.tar.gz`, a
/// path the suffix-resolving route can never serve. Re-deriving from the stored
/// filename keeps the index coherent with the served route for both upload
/// flows — the CRAN analogue of the helm `index.yaml` fix (#2753 / #2589).
///
/// Falls back to the stored `name`/`version` when the basename does not follow
/// the `{name}_{version}.tar.gz` convention (an arbitrary bare-path object that
/// no reconstruction could resolve anyway).
fn source_index_coordinates(path: &str, name: &str, version: &str) -> (String, String) {
    path.rsplit('/')
        .next()
        .filter(|f| !f.is_empty())
        .and_then(|filename| CranHandler::parse_path(&format!("src/contrib/{}", filename)).ok())
        .and_then(|info| Some((info.name?, info.version?)))
        .unwrap_or_else(|| (name.to_string(), version.to_string()))
}

/// Build PACKAGES index in CRAN DCF text format for source packages.
///
/// Rows under `bin/<platform>/contrib/` are binary packages a migration
/// imported at their source path (#2525): they are not source packages, and advertising them here
/// would send `install.packages()` after a `.tar.gz` that does not exist.
/// Native uploads never store under `bin/`.
async fn build_source_index(db: &PgPool, repo_id: uuid::Uuid) -> Result<String, Response> {
    use sqlx::Row;
    // Runtime query (not the `query!` macro) so the added `a.path` column does
    // not require regenerating the offline sqlx data for the `Check Rust` gate,
    // mirroring the helm index builder.
    let rows = sqlx::query(
        r#"
        SELECT a.name, a.version, a.path, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path NOT LIKE 'bin/%/contrib/%'
        ORDER BY a.name, a.created_at DESC
        "#,
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;

    let mut index = String::new();
    for row in &rows {
        let name: String = row.get("name");
        let version: Option<String> = row.get("version");
        let path: String = row.get("path");
        let metadata: Option<serde_json::Value> = row.get("metadata");

        let (pkg, ver) =
            source_index_coordinates(&path, &name, version.as_deref().unwrap_or_default());
        write_dcf_record(&mut index, &pkg, &ver, metadata.as_ref());
    }

    Ok(index)
}

// ---------------------------------------------------------------------------
// Remote (proxy) upstream index
// ---------------------------------------------------------------------------

/// One parsed DCF record from a `PACKAGES` document: the exact text of the
/// record (with its terminator normalised to a single trailing newline) and the
/// `(Package, Version)` identity an R client reconstructs the download filename
/// from.
#[derive(Debug)]
struct UpstreamDcfRecord {
    package: String,
    version: String,
    text: String,
}

/// Parse a CRAN `PACKAGES` DCF document into records, keeping each record's
/// text verbatim.
///
/// The upstream document carries far more than `Package`/`Version` — `Depends`,
/// `Imports`, `LinkingTo`, `License`, `MD5sum` and more — and R resolves a
/// package's dependency graph out of those fields. Re-rendering through
/// [`write_dcf_record`], which emits only the three fields the *local* index
/// builder stores, would silently strip them and break dependency resolution
/// for every package proxied from upstream. So the record text is preserved
/// byte-for-byte and only the `(Package, Version)` identity is extracted.
///
/// DCF records are separated by one or more blank lines; a continuation line
/// (leading whitespace) belongs to the field above it and is preserved as-is.
fn parse_upstream_dcf(document: &str) -> Vec<UpstreamDcfRecord> {
    let normalised = document.replace("\r\n", "\n").replace('\r', "\n");
    let mut records = Vec::new();
    let mut current: Vec<&str> = Vec::new();

    let flush = |lines: &mut Vec<&str>, out: &mut Vec<UpstreamDcfRecord>| {
        if lines.is_empty() {
            return;
        }
        let text = lines.join("\n");
        // Identity: the FIRST `Package:` and `Version:` value, ignoring the
        // leading whitespace DCF continuation lines carry.
        let field = |name: &str| {
            lines
                .iter()
                .find_map(|line| line.strip_prefix(name).map(|v| v.trim().to_string()))
                .filter(|v| !v.is_empty())
        };
        if let (Some(package), Some(version)) = (field("Package:"), field("Version:")) {
            out.push(UpstreamDcfRecord {
                package,
                version,
                text,
            });
        }
        lines.clear();
    };

    for line in normalised.split('\n') {
        if line.trim().is_empty() {
            flush(&mut current, &mut records);
        } else {
            current.push(line);
        }
    }
    flush(&mut current, &mut records);

    records
}

/// Fetch and parse a Remote repository's upstream `src/contrib/PACKAGES`,
/// returning the DCF document an index response should merge over the local
/// rows.
///
/// The document is the discovery half of a CRAN install — `install.packages()`
/// reads it to learn which `(Package, Version)` pairs exist before requesting
/// any tarball — so building the index from locally-catalogued rows alone
/// answered an empty `200` and made a Remote repository unusable (#4877). The
/// fetch is byte-capped and reserved against the shared buffered-metadata
/// budget, and goes through the proxy cache so the upstream round-trip is paid
/// once per cache TTL.
///
/// A `404` from upstream is **not** an error: it means the upstream publishes
/// no `PACKAGES` at that path, so there is honestly nothing to merge and the
/// locally-held rows stand alone.
///
/// A non-`404` failure is surfaced to the caller, which decides whether to fall
/// back to the local set (a Remote with locally-cached packages) or fail loudly
/// (nothing held locally — an empty index is indistinguishable from "upstream
/// publishes no packages", the silent failure this issue is about).
///
/// Upstreams that publish only the gzipped index are handled: the plain
/// `PACKAGES` is tried first (what CRAN and its mirrors serve unsigned and
/// unsurprising), and a `404` there falls back to `PACKAGES.gz`, which is
/// gunzipped in-process. Both are the same document in two codings.
async fn build_remote_source_index(
    state: &SharedState,
    repo: &RepoInfo,
) -> Result<String, Response> {
    let Some(upstream_url) = repo.upstream_url.as_deref() else {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Remote CRAN repository has no upstream URL configured",
        )
            .into_response());
    };
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is not available",
        )
            .into_response());
    };

    // CRAN indexes are whole-repository listings: real upstreams (CRAN itself
    // and its mirrors) ship a `PACKAGES` well past the 8 MiB default, so the
    // larger ceiling applies, exactly as it does for the helm index and the
    // PyPI simple index.
    let cap = proxy_helpers::LARGE_METADATA_MAX_BYTES;
    let plain = proxy_helpers::proxy_fetch_capped_budgeted(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        "src/contrib/PACKAGES",
        cap,
        RepositoryFormat::Cran,
    )
    .await;

    let document = match plain {
        Ok((bytes, _content_type, _budget_permit)) => {
            String::from_utf8(bytes.to_vec()).map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    "Invalid UTF-8 in upstream PACKAGES",
                )
                    .into_response()
            })?
        }
        // A `404` on the plain document may mean this upstream ships only the
        // gzipped index; anything else is a real failure the caller handles.
        Err(response) if response.status() == StatusCode::NOT_FOUND => {
            match fetch_upstream_gzip_index(proxy, repo, upstream_url, cap).await {
                Ok(Some(document)) => document,
                // No gzipped index either: the upstream publishes no PACKAGES.
                Ok(None) => return Ok(String::new()),
                Err(response) => return Err(response),
            }
        }
        Err(response) => return Err(response),
    };

    // Re-render each record as PACKAGES text: records are already
    // blank-line separated, so a record's own trailing `\n\n` is the separator.
    let mut index = String::new();
    for record in parse_upstream_dcf(&document) {
        index.push_str(&record.text);
        index.push_str("\n\n");
    }

    Ok(index)
}

/// Fetch and gunzip `src/contrib/PACKAGES.gz`. `Ok(None)` means the upstream
/// answered `404` for it too, i.e. it publishes no CRAN index at all.
async fn fetch_upstream_gzip_index(
    proxy: &crate::services::proxy_service::ProxyService,
    repo: &RepoInfo,
    upstream_url: &str,
    cap: usize,
) -> Result<Option<String>, Response> {
    let (bytes, _content_type, _budget_permit) = match proxy_helpers::proxy_fetch_capped_budgeted(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        "src/contrib/PACKAGES.gz",
        cap,
        RepositoryFormat::Cran,
    )
    .await
    {
        Ok(triple) => triple,
        Err(response) if response.status() == StatusCode::NOT_FOUND => return Ok(None),
        Err(response) => return Err(response),
    };

    let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut document = String::new();
    use std::io::Read as _;
    decoder.read_to_string(&mut document).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Invalid gzip in upstream PACKAGES.gz",
        )
            .into_response()
    })?;
    Ok(Some(document))
}

/// Merge an upstream `PACKAGES` document over the locally-built index.
///
/// Locally-held records win: a locally-catalogued package is served from
/// storage by the download route before upstream is ever consulted, and its row
/// carries the artifact's real stored coordinates, so replacing it with the
/// upstream record could advertise a filename the local path resolves
/// differently. An upstream record for a `(Package, Version)` that is not held
/// locally is appended; a different version of the same package is a different
/// record and is always appended, which is what lets an R client resolve a
/// version that only upstream carries.
fn merge_upstream_source_index(local: &str, upstream_index: &str) -> String {
    if upstream_index.is_empty() {
        return local.to_string();
    }

    let held: std::collections::HashSet<(String, String)> = parse_upstream_dcf(local)
        .into_iter()
        .map(|r| (r.package, r.version))
        .collect();

    let mut merged = local.to_string();
    for record in parse_upstream_dcf(upstream_index) {
        if held.contains(&(record.package, record.version)) {
            continue;
        }
        // DCF needs a blank line between records. `build_source_index` always
        // terminates a record with one, but a caller handing over a truncated
        // document must not have two records silently fused into one, so top
        // the terminator up rather than assuming it.
        if !merged.is_empty() && !merged.ends_with("\n\n") {
            if merged.ends_with('\n') {
                merged.push('\n');
            } else {
                merged.push_str("\n\n");
            }
        }
        merged.push_str(&record.text);
        merged.push_str("\n\n");
    }
    merged
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use flate2::read::GzDecoder;
    use std::io::Read;

    // -----------------------------------------------------------------------
    // extract_credentials — Bearer token
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_credentials — Basic auth
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // extract_credentials — edge cases
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // gzip_compress
    // -----------------------------------------------------------------------

    #[test]
    fn test_gzip_compress_roundtrip() {
        let original = b"Package: ggplot2\nVersion: 3.4.0\n\nPackage: dplyr\nVersion: 1.1.0\n";
        let compressed = gzip_compress(original).unwrap();

        // Compressed should be different from original (unless very small)
        assert!(!compressed.is_empty());

        // Decompress and verify roundtrip
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_gzip_compress_empty() {
        let compressed = gzip_compress(b"").unwrap();
        assert!(!compressed.is_empty()); // gzip header is still present

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_gzip_compress_large_input() {
        // A larger input to verify compression actually shrinks it
        let data = "Package: test\nVersion: 1.0.0\nDepends: R (>= 3.5.0)\n\n".repeat(100);
        let compressed = gzip_compress(data.as_bytes()).unwrap();

        // Compressed should be smaller than original for repetitive data
        assert!(compressed.len() < data.len());

        // Verify roundtrip
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, data.as_bytes());
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (same pattern used in upload_package)
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_artifact_path_traversal_rejected() {
        // GHSA-vcq6-8hxw-4q67: the `{filename}` URL segment was spliced into
        // the artifact path verbatim. upload_package now routes the composed
        // path through validate_artifact_path.
        for (name, version, filename) in [
            ("ggplot2", "3.4.0", "../../../evil.tar.gz"),
            ("..", "1.0.0", "pkg_1.0.0.tar.gz"),
            ("ggplot2", "3.4.0", "%2e%2e%2fevil.tar.gz"),
        ] {
            let path = format!("{}/{}/{}", name, version, filename);
            assert!(
                crate::services::upload_service::validate_artifact_path(&path).is_err(),
                "composed path from filename {filename:?} must be rejected"
            );
        }
        let ok = format!("{}/{}/{}", "ggplot2", "3.4.0", "ggplot2_3.4.0.tar.gz");
        assert!(crate::services::upload_service::validate_artifact_path(&ok).is_ok());
    }

    #[test]
    fn test_sha256_computation() {
        let data = b"test CRAN package data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        // SHA256 is always 64 hex chars
        assert_eq!(hash.len(), 64);
        // Same data must produce same hash
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let hash2 = format!("{:x}", hasher2.finalize());
        assert_eq!(hash, hash2);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/cran-local".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(repo.storage_path, "/data/cran-local");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/cran-remote".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://cloud.r-project.org".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://cloud.r-project.org")
        );
    }

    // -----------------------------------------------------------------------
    // Format-specific path and key patterns used in upload_package
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_path_format() {
        let pkg_name = "ggplot2";
        let pkg_version = "3.4.0";
        let filename = "ggplot2_3.4.0.tar.gz";
        let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);
        assert_eq!(artifact_path, "ggplot2/3.4.0/ggplot2_3.4.0.tar.gz");
    }

    #[test]
    fn test_storage_key_format() {
        let pkg_name = "dplyr";
        let pkg_version = "1.1.0";
        let filename = "dplyr_1.1.0.tar.gz";
        let storage_key = format!("cran/{}/{}/{}", pkg_name, pkg_version, filename);
        assert_eq!(storage_key, "cran/dplyr/1.1.0/dplyr_1.1.0.tar.gz");
    }

    #[test]
    fn test_metadata_json_format() {
        let pkg_name = "tidyr";
        let pkg_version = "1.3.0";
        let filename = "tidyr_1.3.0.tar.gz";
        let metadata = serde_json::json!({
            "name": pkg_name,
            "version": pkg_version,
            "filename": filename,
            "is_binary": false,
        });
        assert_eq!(metadata["name"], "tidyr");
        assert_eq!(metadata["version"], "1.3.0");
        assert_eq!(metadata["is_binary"], false);
    }

    // -----------------------------------------------------------------------
    // write_dcf_record — DCF text formatter shared by source + binary index
    // builders. Pure function, no DB or storage dependencies.
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_dcf_record_no_depends() {
        let mut out = String::new();
        write_dcf_record(&mut out, "ggplot2", "3.4.0", None);
        assert_eq!(out, "Package: ggplot2\nVersion: 3.4.0\n\n");
    }

    #[test]
    fn test_write_dcf_record_with_depends() {
        let mut out = String::new();
        let meta = serde_json::json!({"depends": "R (>= 3.5.0)"});
        write_dcf_record(&mut out, "dplyr", "1.1.0", Some(&meta));
        assert_eq!(
            out,
            "Package: dplyr\nVersion: 1.1.0\nDepends: R (>= 3.5.0)\n\n"
        );
    }

    #[test]
    fn test_write_dcf_record_metadata_without_depends_field() {
        let mut out = String::new();
        let meta = serde_json::json!({"is_binary": false});
        write_dcf_record(&mut out, "tidyr", "1.3.0", Some(&meta));
        // `depends` missing → no `Depends:` line.
        assert_eq!(out, "Package: tidyr\nVersion: 1.3.0\n\n");
    }

    #[test]
    fn test_write_dcf_record_depends_must_be_string() {
        let mut out = String::new();
        // `depends` present but not a string → no `Depends:` line.
        let meta = serde_json::json!({"depends": ["R", "tidyr"]});
        write_dcf_record(&mut out, "x", "0.1", Some(&meta));
        assert_eq!(out, "Package: x\nVersion: 0.1\n\n");
    }

    #[test]
    fn test_write_dcf_record_appends_to_existing() {
        let mut out = String::from("Package: prior\nVersion: 0.1\n\n");
        write_dcf_record(&mut out, "next", "0.2", None);
        assert!(out.starts_with("Package: prior\n"));
        assert!(out.ends_with("Package: next\nVersion: 0.2\n\n"));
    }

    #[test]
    fn test_write_dcf_record_blank_line_terminator() {
        let mut out = String::new();
        write_dcf_record(&mut out, "p", "1.0", None);
        // Records are separated by a blank line for DCF parsers.
        assert!(out.ends_with("\n\n"));
    }

    #[test]
    fn test_write_dcf_record_empty_version() {
        let mut out = String::new();
        write_dcf_record(&mut out, "noversion", "", None);
        assert_eq!(out, "Package: noversion\nVersion: \n\n");
    }

    // -----------------------------------------------------------------------
    // source_index_coordinates — advertise coordinates the download route can
    // resolve for both native and bare-path (generic) uploads (#2754).
    // -----------------------------------------------------------------------

    #[test]
    fn test_source_index_coordinates_native_path_is_byte_identical() {
        // Native upload path: `{name}/{version}/{name}_{version}.tar.gz`.
        // The stored columns already match the basename, so the advertised
        // coordinates are unchanged.
        let (pkg, ver) =
            source_index_coordinates("ggplot2/3.4.0/ggplot2_3.4.0.tar.gz", "ggplot2", "3.4.0");
        assert_eq!(pkg, "ggplot2");
        assert_eq!(ver, "3.4.0");
    }

    #[test]
    fn test_source_index_coordinates_bare_path_uses_filename() {
        // Bare-path generic upload: stored `name` is the whole basename and
        // `version` is the `sha256-<prefix>` fallback. The advertised
        // coordinates must come from the filename so the R client reconstructs
        // `dplyr_1.1.0.tar.gz` (which the suffix route serves), NOT
        // `dplyr_1.1.0.tar.gz_sha256-abcdef012345.tar.gz`.
        let (pkg, ver) = source_index_coordinates(
            "dplyr_1.1.0.tar.gz",
            "dplyr_1.1.0.tar.gz",
            "sha256-abcdef012345",
        );
        assert_eq!(pkg, "dplyr");
        assert_eq!(ver, "1.1.0");
        // Guard against a regression back to the broken reconstruction.
        assert_ne!(ver, "sha256-abcdef012345");
    }

    #[test]
    fn test_source_index_coordinates_non_cran_basename_falls_back() {
        // A bare-path object that is not a CRAN source package name falls back
        // to the stored columns (nothing could make it resolvable).
        let (pkg, ver) = source_index_coordinates("data.zip", "data.zip", "sha256-deadbeef");
        assert_eq!(pkg, "data.zip");
        assert_eq!(ver, "sha256-deadbeef");
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests for download_package, upload_package, and
    // build_source_index. Use the shared `test_db_helpers::Fixture` so this
    // file does not duplicate the per-test scaffolding.
    //
    // No-op without DATABASE_URL; the CI coverage job seeds Postgres so
    // these run there and instrument the refactored helper-call paths.
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    #[tokio::test]
    async fn test_cran_download_404_when_artifact_missing_local() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/missing_1.0.0.tar.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_download_serves_local_artifact_when_present() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/dplyr/1.1.0/dplyr_1.1.0.tar.gz",
            "dplyr/1.1.0/dplyr_1.1.0.tar.gz",
            "dplyr",
            "1.1.0",
            "application/x-gzip",
            Bytes::from_static(b"fake-r-pkg"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/dplyr_1.1.0.tar.gz", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"fake-r-pkg");
        f.teardown().await;
    }

    /// #4166: CRAN inserts through `proxy_helpers::insert_artifact`, which
    /// never triggered scan-on-upload. A native upload into a
    /// `scan_on_upload` repository must now enqueue a scan.
    #[tokio::test]
    async fn test_cran_upload_triggers_scan_on_upload_4166() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let req = tdh::put(
            format!("/{}/src/contrib/scanme_1.0.tar.gz", f.repo_key),
            Bytes::from_static(b"fake-r-pkg"),
        );
        let scans = tdh::native_upload_probe_scans(
            &f,
            super::router(),
            req,
            true,
            std::time::Duration::from_secs(30),
        )
        .await;
        f.teardown().await;
        assert!(
            scans > 0,
            "a native CRAN upload must enqueue a scan (#4166)"
        );
    }

    /// #4725: a native CRAN upload to a hosted repository must queue a push
    /// sync task for a subscribed push peer, and an upload that arrives as peer
    /// replication must not be fanned back out. Fails on `main` (nothing queued).
    #[tokio::test]
    async fn cran_upload_queues_push_sync_task_4725() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&f.pool, f.repo_id, "cran").await;

        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/src/contrib/repl4725_1.0.0.tar.gz", f.repo_key),
            Bytes::from_static(b"fake-r-pkg-4725"),
        );
        let (status, resp) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "CRAN upload must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&resp[..])
        );

        // A replicated upload (as the sync worker sends it) stores the package
        // but must not queue another task.
        let mut req = tdh::put(
            format!("/{}/src/contrib/repl4725_2.0.0.tar.gz", f.repo_key),
            Bytes::from_static(b"fake-r-pkg-4725"),
        );
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let app = f.router_with_auth(super::router());
        let (status, resp) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "replicated CRAN upload must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&resp[..])
        );

        let queued = tdh::queued_push_paths(&f.pool, peer_id, f.repo_id).await;
        tdh::delete_push_peer(&f.pool, peer_id).await;
        f.teardown().await;
        assert_eq!(
            queued,
            vec!["repl4725/1.0.0/repl4725_1.0.0.tar.gz".to_string()],
            "only the client upload queues a push task; the replicated one must not"
        );
    }

    /// #2525: a migrated binary package keeps its `bin/...` source path and
    /// must not be listed in the source `PACKAGES` index, while a migrated
    /// source package (canonical `<name>/<version>/<file>` path) is.
    #[tokio::test]
    async fn test_cran_source_index_excludes_migrated_binaries_2525() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/dplyr/1.1.4/dplyr_1.1.4.tar.gz",
            "dplyr/1.1.4/dplyr_1.1.4.tar.gz",
            "dplyr",
            "1.1.4",
            "application/x-gzip",
            Bytes::from_static(b"src-pkg"),
            f.user_id,
        )
        .await;
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/bin/windows/contrib/4.3/Rcpp_1.0.12.zip",
            "bin/windows/contrib/4.3/Rcpp_1.0.12.zip",
            "Rcpp_1.0.12.zip",
            "",
            "application/zip",
            Bytes::from_static(b"bin-pkg"),
            f.user_id,
        )
        .await;

        // A source package that happens to be called `bin` is stored at
        // `bin/<version>/...` and must still be listed.
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/bin/0.1/bin_0.1.tar.gz",
            "bin/0.1/bin_0.1.tar.gz",
            "bin",
            "0.1",
            "application/x-gzip",
            Bytes::from_static(b"src-pkg-named-bin"),
            f.user_id,
        )
        .await;

        let index = build_source_index(&f.pool, repo.id)
            .await
            .unwrap_or_else(|_| panic!("index builds"));
        assert!(index.contains("Package: dplyr"), "{index}");
        assert!(
            index.contains("Package: bin\n"),
            "a source package named `bin` stays listed: {index}"
        );
        assert!(
            !index.contains("Rcpp"),
            "binary rows must not reach the source index: {index}"
        );
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_upload_rejects_unauthenticated() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::put(
            format!("/{}/src/contrib/foo_1.0.tar.gz", f.repo_key),
            Bytes::from_static(b"data"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_upload_rejects_remote_repo() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/src/contrib/foo_1.0.tar.gz", f.repo_key),
            Bytes::from_static(b"pkg"),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_upload_rejects_empty_body() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let app = f.router_with_auth(super::router());
        let req = tdh::put(
            format!("/{}/src/contrib/foo_1.0.tar.gz", f.repo_key),
            Bytes::new(),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        f.teardown().await;
    }

    /// Also #3939: a CRAN upload registers its catalog row and fires exactly
    /// one `artifact.uploaded` (it used to fire none).
    #[tokio::test]
    async fn test_cran_upload_succeeds_for_hosted() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let mut events = f.state.event_bus.subscribe();
        let app = f.router_with_auth(super::router());
        let body: Vec<u8> = vec![0u8; 32];
        let req = tdh::put(
            format!("/{}/src/contrib/dplyr_1.1.0.tar.gz", f.repo_key),
            Bytes::from(body),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK);
        tdh::assert_one_artifact_uploaded(&mut events, &f.pool, f.repo_id, "dplyr", "1.1.0").await;
        let row = tdh::catalog_row(&f.pool, f.repo_id, "dplyr").await;
        f.teardown().await;
        assert_eq!(
            row.expect("a CRAN upload must write a packages row")
                .versions,
            vec!["1.1.0".to_string()]
        );
    }

    #[tokio::test]
    async fn test_cran_upload_conflict_returns_409() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let app1 = f.router_with_auth(super::router());
        let body1: Vec<u8> = vec![1u8; 16];
        let req1 = tdh::put(
            format!("/{}/src/contrib/dup_1.0.tar.gz", f.repo_key),
            Bytes::from(body1),
        );
        assert_eq!(tdh::send(app1, req1).await.0, StatusCode::OK);

        let app2 = f.router_with_auth(super::router());
        let body2: Vec<u8> = vec![1u8; 16];
        let req2 = tdh::put(
            format!("/{}/src/contrib/dup_1.0.tar.gz", f.repo_key),
            Bytes::from(body2),
        );
        let (status, _) = tdh::send(app2, req2).await;
        assert_eq!(status, StatusCode::CONFLICT);
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_package_index_empty_repo() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty());
        f.teardown().await;
    }

    #[tokio::test]
    async fn test_cran_package_index_with_seeded_artifact() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let id = crate::api::handlers::proxy_helpers::insert_artifact(
            &f.pool,
            crate::api::handlers::proxy_helpers::NewArtifact {
                repository_id: f.repo_id,
                path: "ggplot2/3.4.0/ggplot2_3.4.0.tar.gz",
                name: "ggplot2",
                version: "3.4.0",
                size_bytes: 50,
                checksum_sha256: "y",
                content_type: "application/x-gzip",
                storage_key: "cran/ggplot2/3.4.0/ggplot2_3.4.0.tar.gz",
                uploaded_by: f.user_id,
            },
        )
        .await
        .expect("insert");
        let meta = serde_json::json!({"depends": "R (>= 3.5.0)"});
        crate::api::handlers::proxy_helpers::record_artifact_metadata(
            &f.pool, id, f.repo_id, "cran", &meta,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Package: ggplot2"));
        assert!(text.contains("Version: 3.4.0"));
        assert!(text.contains("Depends: R (>= 3.5.0)"));
        f.teardown().await;
    }

    /// #2754: a bare-path generic upload (path == filename, `name` == whole
    /// basename, `version` == `sha256-<prefix>` fallback) must be advertised in
    /// PACKAGES with the coordinates the R client reconstructs the *resolvable*
    /// `{name}_{version}.tar.gz` download from — not the raw sha256 fallback
    /// (which yields `…tar.gz_sha256-….tar.gz` → 404). Fails on `main`.
    #[tokio::test]
    async fn test_cran_index_coords_resolve_for_bare_path_generic_upload() {
        let Some(f) = tdh::Fixture::setup("local", "cran").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/mypkg_1.0.0.tar.gz",
            "mypkg_1.0.0.tar.gz",
            "mypkg_1.0.0.tar.gz",
            "sha256-abcdef012345",
            "application/x-gzip",
            Bytes::from_static(b"fake-r-pkg"),
            f.user_id,
        )
        .await;

        let app = f.router_anon(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Package: mypkg"), "index was: {text}");
        assert!(text.contains("Version: 1.0.0"), "index was: {text}");
        assert!(
            !text.contains("sha256-abcdef012345"),
            "index still advertises the unresolvable sha256 fallback: {text}"
        );
        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #4877: a Remote CRAN repository must proxy the upstream PACKAGES index.
    //
    // Every test below mounts a wiremock upstream and drives the real router
    // through `rewire_remote_proxy`, so it exercises the whole
    // resolve -> fetch -> merge -> respond path and fails on `main` (where a
    // Remote repo answered an empty 200 because the index was built from
    // local rows alone).
    // -----------------------------------------------------------------------

    /// Two realistic CRAN DCF records, with fields beyond Package/Version that
    /// dependency resolution needs and must survive the merge.
    const UPSTREAM_PACKAGES: &str = "\
Package: ggplot2
Version: 3.4.4
Depends: R (>= 3.3.0)
Imports: cli, glue, rlang
License: MIT + file LICENSE

Package: dplyr
Version: 1.1.4
Depends: R (>= 3.5.0)
License: MIT + file LICENSE
";

    async fn mount_packages(server: &wiremock::MockServer, body: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/src/contrib/PACKAGES"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(server)
            .await;
    }

    /// The bug: `GET /cran/{key}/src/contrib/PACKAGES` against a Remote repo
    /// returned an empty 200, so R clients pointed at a remote repo could not
    /// discover anything. It must now serve what the upstream advertises.
    #[tokio::test]
    async fn test_cran_remote_package_index_proxies_upstream_4877() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        mount_packages(&server, UPSTREAM_PACKAGES).await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body.to_vec()).expect("utf-8 index");
        assert!(
            text.contains("Package: ggplot2") && text.contains("Version: 3.4.4"),
            "a Remote CRAN index must advertise the upstream's packages (#4877): {text}"
        );
        assert!(text.contains("Package: dplyr"), "index was: {text}");
        // Fields beyond Package/Version are what R resolves dependencies from;
        // a re-render that emitted only our three local columns would drop
        // them and break `install.packages()` dependency resolution.
        assert!(
            text.contains("Imports: cli, glue, rlang"),
            "upstream-only DCF fields must be preserved verbatim: {text}"
        );
    }

    /// `PACKAGES.gz` must carry the SAME records as `PACKAGES`: the two routes
    /// share one index builder, so they cannot disagree (both were empty
    /// against a Remote before #4877).
    #[tokio::test]
    async fn test_cran_remote_package_index_gz_matches_plain_4877() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        mount_packages(&server, UPSTREAM_PACKAGES).await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES.gz", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let mut decoder = GzDecoder::new(&body[..]);
        let mut text = String::new();
        decoder.read_to_string(&mut text).expect("gunzip index");
        assert!(
            text.contains("Package: ggplot2") && text.contains("Package: dplyr"),
            "PACKAGES.gz must proxy the upstream index too (#4877): {text}"
        );
    }

    /// An upstream that ships only the gzipped index (some mirrors do) still
    /// gets proxied: the plain fetch 404s and the gzip fallback serves it.
    #[tokio::test]
    async fn test_cran_remote_index_falls_back_to_gz_only_upstream_4877() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        // No `/src/contrib/PACKAGES` mock at all: wiremock answers 404 for it.
        let gz = gzip_compress(UPSTREAM_PACKAGES.as_bytes()).expect("gzip fixture");
        Mock::given(method("GET"))
            .and(path("/src/contrib/PACKAGES.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body.to_vec()).expect("utf-8 index");
        assert!(
            text.contains("Package: ggplot2"),
            "a gzip-only upstream must still be proxied (#4877): {text}"
        );
    }

    /// A locally-held package is served from storage before upstream is
    /// consulted, and its real stored coordinates must not be replaced by the
    /// upstream record. An upstream-only package is still appended.
    #[tokio::test]
    async fn test_cran_remote_index_local_wins_and_upstream_added_4877() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let repo = f.repo_info("remote", None);
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "cran/localpkg/9.9.9/localpkg_9.9.9.tar.gz",
            "localpkg/9.9.9/localpkg_9.9.9.tar.gz",
            "localpkg",
            "9.9.9",
            "application/x-gzip",
            Bytes::from_static(b"local-pkg"),
            f.user_id,
        )
        .await;

        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        mount_packages(&server, UPSTREAM_PACKAGES).await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8(body.to_vec()).expect("utf-8 index");
        assert!(
            text.contains("Package: localpkg") && text.contains("Version: 9.9.9"),
            "a locally-held package stays advertised: {text}"
        );
        assert!(
            text.contains("Package: ggplot2"),
            "the upstream's packages are merged in alongside the local rows: {text}"
        );
    }

    /// An upstream that publishes no `PACKAGES` (both paths 404) is not an
    /// error: the repository honestly serves its local set — here, empty.
    #[tokio::test]
    async fn test_cran_remote_index_upstream_404_is_empty_not_error_4877() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        // No mocks mounted: every path is 404.
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "nothing to serve: {body:?}");
    }

    /// With nothing held locally, an upstream failure must be LOUD: an empty
    /// 200 is indistinguishable from "upstream publishes no packages", which is
    /// the silent failure #4877 is about.
    #[tokio::test]
    async fn test_cran_remote_index_upstream_failure_without_local_is_server_error_4877() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let (server, _ssrf_guard) = tdh::non_loopback_mock_server().await;
        Mock::given(method("GET"))
            .and(path("/src/contrib/PACKAGES"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let (state, _cache_dir) = tdh::rewire_remote_proxy(&f, &server.uri()).await;

        let app = tdh::router_anon(super::router(), state);
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/{}/src/contrib/PACKAGES", f.repo_key)),
        )
        .await;
        f.teardown().await;

        assert!(
            status.is_server_error(),
            "an upstream failure with no local fallback must not be a silent \
             empty 200 (#4877): got {status}"
        );
    }

    /// The DCF parser is the heart of the merge; pin its behaviour directly so
    /// a refactor cannot silently change what is preserved or how identity is
    /// extracted.
    #[test]
    fn test_parse_upstream_dcf_preserves_fields_and_extracts_identity() {
        let records = parse_upstream_dcf(UPSTREAM_PACKAGES);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].package, "ggplot2");
        assert_eq!(records[0].version, "3.4.4");
        assert_eq!(records[1].package, "dplyr");
        assert_eq!(records[1].version, "1.1.4");
        assert!(
            records[0].text.contains("Imports: cli, glue, rlang"),
            "record text keeps every field: {}",
            records[0].text
        );
    }

    /// CRLF and a missing trailing blank line still parse (real upstreams vary).
    #[test]
    fn test_parse_upstream_dcf_handles_crlf_and_no_trailing_blank() {
        let doc = "Package: a\r\nVersion: 1.0\r\n\r\nPackage: b\r\nVersion: 2.0";
        let records = parse_upstream_dcf(doc);
        assert_eq!(records.len(), 2);
        assert_eq!(
            (records[0].package.as_str(), records[0].version.as_str()),
            ("a", "1.0")
        );
        assert_eq!(
            (records[1].package.as_str(), records[1].version.as_str()),
            ("b", "2.0")
        );
    }

    /// A record without both identity fields contributes nothing (it could
    /// never be converted into a download request).
    #[test]
    fn test_parse_upstream_dcf_skips_records_without_identity() {
        let doc = "Package: nover\nVersion:\n\nDescription: unnamed\n";
        let records = parse_upstream_dcf(doc);
        // `Version:` is empty → not a usable identity.
        assert!(records.is_empty(), "got {records:?}");
    }

    /// A local record and an upstream record for the same coordinate must not
    /// be duplicated: local wins, upstream's extra fields do not shadow it.
    #[test]
    fn test_merge_upstream_source_index_dedupes_by_identity() {
        let local = "Package: ggplot2\nVersion: 3.4.4\n\n";
        let merged = merge_upstream_source_index(local, UPSTREAM_PACKAGES);
        assert_eq!(
            merged.matches("Package: ggplot2").count(),
            1,
            "the local row must not be duplicated by the upstream one: {merged}"
        );
        assert!(
            merged.contains("Package: dplyr"),
            "upstream-only added: {merged}"
        );
        // The surviving ggplot2 record is the LOCAL one (no upstream-only fields).
        assert!(
            !merged.contains("Imports: cli, glue, rlang"),
            "the local ggplot2 record must win over upstream's: {merged}"
        );
    }

    /// An empty upstream index leaves the local document untouched.
    #[test]
    fn test_merge_upstream_source_index_empty_upstream_is_identity() {
        let local = "Package: only\nVersion: 1.0\n\n";
        assert_eq!(merge_upstream_source_index(local, ""), local);
    }

    /// Upstream records that are not held locally are appended with their DCF
    /// fields intact, and a local record without a trailing blank line still
    /// yields valid, separated records.
    #[test]
    fn test_merge_upstream_source_index_preserves_fields_and_separators() {
        let local = "Package: only\nVersion: 1.0"; // no trailing blank line
        let merged = merge_upstream_source_index(local, UPSTREAM_PACKAGES);
        assert!(merged.contains("Imports: cli, glue, rlang"), "{merged}");
        // Records must be blank-line separated for a DCF parser.
        assert!(
            merged.contains("Version: 1.0\n\nPackage: ggplot2\n"),
            "local and upstream records must be separated: {merged}"
        );
    }

    /// #5322: CRAN's Remote download shares `try_remote_or_virtual_download`
    /// with Hugging Face, so a cold `HEAD` of a source package is answered by
    /// an upstream HEAD and the package body leaves the upstream once across
    /// HEAD, GET and a warm GET (the counting mock's `expect(1)`s).
    #[tokio::test]
    async fn test_cran_remote_cold_head_downloads_the_package_once_5322() {
        let Some(f) = tdh::Fixture::setup("remote", "cran").await else {
            return;
        };
        let server = wiremock::MockServer::start().await;
        let package: Vec<u8> = (0..2048u32).map(|i| (i % 241) as u8).collect();
        tdh::mount_head_and_get_once(
            &server,
            "/src/contrib/dplyr_1.1.0.tar.gz",
            &[("etag", "\"dplyr-1.1.0\"")],
            &package,
        )
        .await;
        let (state, cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let uri = format!("/{}/src/contrib/dplyr_1.1.0.tar.gz", f.repo_key);
        let [head, cold, warm] = tdh::cold_head_then_two_gets(
            || tdh::router_anon(super::router(), state.clone()),
            &uri,
            cache.path(),
            package.len() as u64,
        )
        .await;
        f.teardown().await;

        assert_eq!(head.0, StatusCode::OK);
        assert!(head.1.is_empty());
        let size = package.len().to_string();
        assert_eq!(
            head.2.get("content-length").and_then(|v| v.to_str().ok()),
            Some(size.as_str())
        );
        assert_eq!(cold.0, StatusCode::OK);
        assert_eq!(&cold.1[..], &package[..]);
        assert_eq!(warm.0, StatusCode::OK);
        assert_eq!(&warm.1[..], &package[..]);
        tdh::drop_mock_server(server).await;
    }
}
