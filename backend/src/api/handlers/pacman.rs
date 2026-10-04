//! Arch Linux pacman repository API handlers (#3343).
//!
//! Hosted repositories only: packages are uploaded here and the package
//! databases are rendered on demand from the stored artifacts. Mirroring an
//! upstream pacman repository (remote) and aggregating members (virtual) are
//! not implemented yet (#4407); those repository types answer 501.
//!
//! Routes are mounted at `/pacman/{repo_key}/...`. A client points pacman at
//! `Server = {base}/pacman/{repo_key}/$arch`, so `pacman -Sy` fetches
//! `{base}/pacman/{repo_key}/{arch}/{section}.db` for its `[section]`; any
//! database basename is accepted, so the section can be named freely.
//!
//!   GET    /{repo_key}/{arch}/{name}.db[.tar.gz]          package database
//!   GET    /{repo_key}/{arch}/{name}.files[.tar.gz]       database with file lists
//!   GET    /{repo_key}/{arch}/{name}.{db,files}.sig       detached database signature
//!   GET    /{repo_key}/{arch}/{package}                   package download
//!   GET    /{repo_key}/{arch}/{package}.sig               uploaded package signature
//!   DELETE /{repo_key}/{arch}/{package}                   delete a package
//!   PUT    /{repo_key}/{package}                          upload a package
//!   PUT    /{repo_key}/{package}.sig                      attach a detached signature
//!   GET    /{repo_key}/gpg-key.asc                        repository signing key
//!
//! Packages built for `any` architecture are listed in every architecture's
//! database and downloadable under every `{arch}`, as on the official mirrors.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Extension, Router};
use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::pacman::{self as fmt, PkgInfo, RepoFile};
use crate::models::repository::RepositoryType;
use crate::services::signing_service::SigningService;

/// Content type of package downloads.
const PACKAGE_CONTENT_TYPE: &str = "application/octet-stream";

/// Content type of the gzip'd databases.
const DATABASE_CONTENT_TYPE: &str = "application/gzip";

/// Content type of detached OpenPGP signatures.
const SIGNATURE_CONTENT_TYPE: &str = "application/pgp-signature";

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/gpg-key.asc", get(public_key))
        .route("/:repo_key/:filename", put(upload))
        .route(
            "/:repo_key/:arch/:filename",
            get(serve_file).delete(delete_package),
        )
}

// ---------------------------------------------------------------------------
// Stored metadata
// ---------------------------------------------------------------------------

/// The `artifact_metadata` document of a pacman package: everything the
/// databases need, so rendering them never re-reads a package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct PacmanMetadata {
    filename: String,
    arch: String,
    pkginfo: PkgInfo,
    /// File list for the `.files` database. Stripped from the row by the
    /// `.db` query, which never needs it.
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<Vec<String>>,
    /// Base64 binary detached signature, once one is uploaded (`%PGPSIG%`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pgpsig: Option<String>,
}

/// One live package row, as the databases list it.
#[derive(Debug, Clone)]
struct IndexedPackage {
    csize: i64,
    sha256: String,
    mtime: u64,
    meta: PacmanMetadata,
}

/// Keep one entry per package name, the most recently uploaded, the way
/// `repo-add` replaces an existing entry when a package is added again.
/// `packages` must be ordered newest first; the result is sorted by name so
/// the rendered database is stable.
fn latest_per_name(packages: Vec<IndexedPackage>) -> Vec<IndexedPackage> {
    let mut seen = std::collections::HashSet::new();
    let mut latest: Vec<IndexedPackage> = packages
        .into_iter()
        .filter(|p| seen.insert(p.meta.pkginfo.pkgname.clone()))
        .collect();
    latest.sort_by(|a, b| a.meta.pkginfo.pkgname.cmp(&b.meta.pkginfo.pkgname));
    latest
}

/// Render `{repo}.db` (or `{repo}.files`) for an already-selected package set.
fn render_database(packages: &[IndexedPackage], with_files: bool) -> std::io::Result<Vec<u8>> {
    let entries: Vec<fmt::DbEntry<'_>> = packages
        .iter()
        .map(|p| fmt::DbEntry {
            filename: &p.meta.filename,
            csize: p.csize,
            sha256: &p.sha256,
            pgpsig: p.meta.pgpsig.as_deref(),
            info: &p.meta.pkginfo,
            files: p.meta.files.as_deref(),
            mtime: p.mtime,
        })
        .collect();
    fmt::build_database(&entries, with_files)
}

/// Artifact path a package is stored under: `{pkgarch}/{filename}`.
fn package_artifact_path(arch: &str, filename: &str) -> String {
    format!("{arch}/{filename}")
}

/// Artifact paths a package requested under `/{arch}/{filename}` may live at:
/// its own architecture, or `any`.
fn package_path_candidates(arch: &str, filename: &str) -> Vec<String> {
    let mut candidates = vec![package_artifact_path(arch, filename)];
    if arch != "any" {
        candidates.push(package_artifact_path("any", filename));
    }
    candidates
}

/// The architecture a canonical package filename ends with
/// (`foo-1.0-1-x86_64.pkg.tar.zst` -> `x86_64`).
fn filename_arch(filename: &str) -> Option<&str> {
    let (stem, _) = fmt::split_package_filename(filename)?;
    stem.rsplit_once('-')
        .map(|(_, arch)| arch)
        .filter(|arch| fmt::is_valid_arch(arch))
}

fn storage_key(repo_id: uuid::Uuid, artifact_path: &str) -> String {
    format!("pacman/{repo_id}/{artifact_path}")
}

fn bytes_response(body: Vec<u8>, content_type: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_pacman_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["pacman"], "a pacman").await
}

/// Remote and virtual pacman repositories are not implemented yet; say so
/// instead of serving an empty database that pacman would accept silently.
#[allow(clippy::result_large_err)]
fn reject_unsupported_repo_type(repo_type: &str) -> Result<(), Response> {
    if repo_type == RepositoryType::Remote || repo_type == RepositoryType::Virtual {
        return Err(error(
            StatusCode::NOT_IMPLEMENTED,
            "Remote and virtual pacman repositories are not supported yet (#4407); use a local repository",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct PackageRow {
    size_bytes: i64,
    checksum_sha256: String,
    created_at: chrono::DateTime<chrono::Utc>,
    metadata: Option<serde_json::Value>,
}

impl PackageRow {
    fn into_indexed(self) -> Option<IndexedPackage> {
        let meta: PacmanMetadata = serde_json::from_value(self.metadata?).ok()?;
        if meta.filename.is_empty() || meta.pkginfo.pkgname.is_empty() {
            return None;
        }
        Some(IndexedPackage {
            csize: self.size_bytes,
            sha256: self.checksum_sha256,
            mtime: self.created_at.timestamp().max(0) as u64,
            meta,
        })
    }
}

/// Live packages visible in `arch`'s databases (that arch plus `any`), newest
/// first. The file lists are only loaded for the `.files` database.
async fn list_packages(
    db: &PgPool,
    repo_id: uuid::Uuid,
    arch: &str,
    with_files: bool,
) -> Result<Vec<IndexedPackage>, Response> {
    let rows: Vec<PackageRow> = sqlx::query_as(
        r#"
        SELECT a.size_bytes, a.checksum_sha256, a.created_at,
               CASE WHEN $3 THEN am.metadata ELSE am.metadata - 'files' END AS metadata
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND (a.path LIKE $2 || '%' ESCAPE '\' OR a.path LIKE 'any/%')
        ORDER BY a.created_at DESC, a.id
        "#,
    )
    .bind(repo_id)
    .bind(super::escape_path_prefix(&[arch]))
    .bind(with_files)
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;

    Ok(rows
        .into_iter()
        .filter_map(PackageRow::into_indexed)
        .collect())
}

/// The live artifact row behind one of `paths`, with its metadata.
async fn find_package(
    db: &PgPool,
    repo_id: uuid::Uuid,
    paths: &[String],
) -> Result<Option<(uuid::Uuid, String, Option<serde_json::Value>)>, Response> {
    sqlx::query_as(
        r#"
        SELECT a.id, a.path, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false AND a.path = ANY($2)
        ORDER BY a.path
        LIMIT 1
        "#,
    )
    .bind(repo_id)
    .bind(paths)
    .fetch_optional(db)
    .await
    .map_err(super::db_err)
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/{arch}/{filename}
// ---------------------------------------------------------------------------

async fn serve_file(
    State(state): State<SharedState>,
    Path((repo_key, arch, filename)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_pacman_repo(&state.db, &repo_key).await?;
    reject_unsupported_repo_type(&repo.repo_type)?;
    let not_found = || error(StatusCode::NOT_FOUND, "Not found");
    if !fmt::is_valid_arch(&arch) {
        return Err(not_found());
    }
    match fmt::classify_repo_file(&filename).ok_or_else(not_found)? {
        RepoFile::Database { files, signature } => {
            serve_database(&state, &repo, &arch, files, signature).await
        }
        RepoFile::Package {
            filename,
            signature: false,
        } => serve_package(&state, &repo, &arch, filename, &ctx).await,
        RepoFile::Package {
            filename,
            signature: true,
        } => serve_package_signature(&state, &repo, &arch, filename).await,
    }
}

async fn serve_database(
    state: &SharedState,
    repo: &RepoInfo,
    arch: &str,
    with_files: bool,
    signature: bool,
) -> Result<Response, Response> {
    let packages = latest_per_name(list_packages(&state.db, repo.id, arch, with_files).await?);
    let database = render_database(&packages, with_files).map_err(|e| {
        tracing::error!(error = %e, "Failed to build pacman database");
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build the package database",
        )
    })?;
    if !signature {
        return Ok(bytes_response(database, DATABASE_CONTENT_TYPE));
    }

    // The signature covers the exact bytes the database request returns: the
    // render is deterministic, so signing a fresh render here matches the
    // `.db` pacman fetched just before. No active key means the repository is
    // unsigned (404, which pacman's `DatabaseOptional` accepts); a configured
    // key that fails to sign is a hard 500, never a silently unsigned answer.
    let signing = SigningService::new(state.db.clone(), &state.config.jwt_secret)
        .with_signature_expiry(state.config.signature_expiry_seconds);
    let armored = signing
        .sign_openpgp_detached(repo.id, &database)
        .await
        .map_err(|e| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::internal_err_message("Failed to sign the package database", &e),
            )
        })?
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "No signing key configured for this repository",
            )
        })?;
    let binary = fmt::normalize_signature(armored.as_bytes()).map_err(|e| e.into_response())?;
    Ok(bytes_response(binary, SIGNATURE_CONTENT_TYPE))
}

async fn serve_package(
    state: &SharedState,
    repo: &RepoInfo,
    arch: &str,
    filename: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let (_, path, _) = find_package(&state.db, repo.id, &package_path_candidates(arch, filename))
        .await?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Package not found"))?;

    let result = proxy_helpers::local_fetch_by_path(
        &state.db,
        state,
        repo.id,
        &repo.storage_location(),
        &path,
    )
    .await?;
    // #3143: quarantine + scan policy apply to the streamed download too.
    proxy_helpers::gate_and_record_streamed_local(&state.db, result.artifact_id, ctx).await?;
    proxy_helpers::stream_fetch_result(result, PACKAGE_CONTENT_TYPE, Some(filename))
}

/// The binary signature stored for a package, if one was uploaded.
fn stored_signature(metadata: Option<serde_json::Value>) -> Option<Vec<u8>> {
    let meta: PacmanMetadata = serde_json::from_value(metadata?).ok()?;
    base64::engine::general_purpose::STANDARD
        .decode(meta.pgpsig?)
        .ok()
}

async fn serve_package_signature(
    state: &SharedState,
    repo: &RepoInfo,
    arch: &str,
    filename: &str,
) -> Result<Response, Response> {
    let (_, _, metadata) =
        find_package(&state.db, repo.id, &package_path_candidates(arch, filename))
            .await?
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Package not found"))?;
    let signature = stored_signature(metadata).ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            "No signature was uploaded for this package",
        )
    })?;
    Ok(bytes_response(signature, SIGNATURE_CONTENT_TYPE))
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/gpg-key.asc
// ---------------------------------------------------------------------------

async fn public_key(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_pacman_repo(&state.db, &repo_key).await?;
    let key = SigningService::new(state.db.clone(), &state.config.jwt_secret)
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::internal_err_message("Failed to retrieve public key", &e),
            )
        })?
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "No signing key configured for this repository",
            )
        })?;
    Ok(bytes_response(key.into_bytes(), "application/pgp-keys"))
}

// ---------------------------------------------------------------------------
// PUT /{repo_key}/{filename}
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, filename)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "pacman", "write:artifacts")?.user_id;
    let repo = resolve_pacman_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    match fmt::classify_repo_file(&filename) {
        Some(RepoFile::Package {
            filename,
            signature: false,
        }) => store_package(&state, &repo, filename, body, user_id).await,
        Some(RepoFile::Package {
            filename,
            signature: true,
        }) => attach_signature(&state, &repo, filename, &body).await,
        _ => Err(error(
            StatusCode::BAD_REQUEST,
            format!(
                "Expected a package ({}) or its detached .sig",
                fmt::PACKAGE_EXTENSIONS.join(", ")
            ),
        )),
    }
}

/// Check the uploaded filename against the package's own `.PKGINFO`: pacman
/// downloads `%FILENAME%`, and a name that disagrees with the package's
/// coordinates would publish one package under another's name.
#[allow(clippy::result_large_err)]
fn check_upload_filename(filename: &str, info: &PkgInfo) -> Result<(), Response> {
    let ext = fmt::split_package_filename(filename)
        .map(|(_, ext)| ext)
        .unwrap_or_default();
    let expected = fmt::canonical_filename(info, ext);
    if filename != expected {
        return Err(error(
            StatusCode::BAD_REQUEST,
            format!(
                "Filename '{filename}' does not match the package's .PKGINFO (expected '{expected}')"
            ),
        ));
    }
    Ok(())
}

async fn store_package(
    state: &SharedState,
    repo: &RepoInfo,
    filename: &str,
    body: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    // #2561: hold an ingest-decompression permit across the blocking walk.
    let data = body.clone();
    let contents = crate::util::bounded_archive::with_ingest_extraction_async(|| async move {
        tokio::task::spawn_blocking(move || fmt::inspect_package(&data)).await
    })
    .await
    .map_err(|e| e.into_response())?
    .map_err(|e| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::internal_err_message("Package inspection failed", &e),
        )
    })?
    .map_err(|e| {
        error(
            StatusCode::BAD_REQUEST,
            format!("Invalid pacman package: {e}"),
        )
    })?;
    let info = contents.info;
    check_upload_filename(filename, &info)?;
    if contents.files.is_none() {
        tracing::warn!(
            filename,
            "pacman package file list exceeded its budget; publishing without %FILES%"
        );
    }

    let artifact_path = package_artifact_path(&info.arch, filename);
    proxy_helpers::ensure_unique_artifact_path(
        &state.db,
        repo.id,
        &artifact_path,
        "Package already exists",
    )
    .await?;

    let sha256 = format!("{:x}", Sha256::digest(&body));
    let size_bytes = body.len() as i64;
    let key = storage_key(repo.id, &artifact_path);
    proxy_helpers::put_artifact_bytes(state, repo, &key, body).await?;

    let artifact_id = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &info.pkgname,
            version: &info.pkgver,
            size_bytes,
            checksum_sha256: &sha256,
            content_type: PACKAGE_CONTENT_TYPE,
            storage_key: &key,
            uploaded_by: user_id,
        },
    )
    .await?;

    let files_indexed = contents.files.is_some();
    let metadata = PacmanMetadata {
        filename: filename.to_string(),
        arch: info.arch.clone(),
        pkginfo: info.clone(),
        files: contents.files,
        pgpsig: None,
    };
    let metadata = serde_json::to_value(&metadata).unwrap_or_default();
    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "pacman", &metadata)
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
        "pacman",
        &info.pkgname,
        &info.pkgver,
        size_bytes,
        &sha256,
        info.pkgdesc.as_deref(),
    )
    .await;

    info!(
        "pacman upload: {} {} ({}) to repo {}",
        info.pkgname, info.pkgver, info.arch, repo.key
    );
    let response = serde_json::json!({
        "name": info.pkgname,
        "version": info.pkgver,
        "arch": info.arch,
        "filename": filename,
        "sha256": sha256,
        "size": size_bytes,
        "files_indexed": files_indexed,
    });
    Ok((StatusCode::CREATED, axum::Json(response)).into_response())
}

/// Attach (or replace) the detached signature of an already-uploaded package.
async fn attach_signature(
    state: &SharedState,
    repo: &RepoInfo,
    filename: &str,
    body: &[u8],
) -> Result<Response, Response> {
    let signature = fmt::normalize_signature(body)
        .map_err(|e| error(StatusCode::BAD_REQUEST, e.to_string()))?;
    let arch = filename_arch(filename)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid package filename"))?;
    let (artifact_id, _, _) =
        find_package(&state.db, repo.id, &[package_artifact_path(arch, filename)])
            .await?
            .ok_or_else(|| {
                error(
                    StatusCode::NOT_FOUND,
                    "Upload the package before its signature",
                )
            })?;

    sqlx::query(
        "UPDATE artifact_metadata \
         SET metadata = jsonb_set(metadata, '{pgpsig}', to_jsonb($2::text)) \
         WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .bind(fmt::signature_base64(&signature))
    .execute(&state.db)
    .await
    .map_err(super::db_err)?;

    info!(
        "pacman signature attached: {} in repo {}",
        filename, repo.key
    );
    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({ "filename": filename, "signature": "attached" })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// DELETE /{repo_key}/{arch}/{filename}
// ---------------------------------------------------------------------------

async fn delete_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, arch, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let auth = require_auth_basic_scope(auth, "pacman", "delete:artifacts")?;
    let repo = resolve_pacman_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    proxy_helpers::reject_direct_delete_if_promotion_only(
        repo.promotion_only,
        auth.is_admin || auth.is_service_account,
    )?;

    let not_found = || error(StatusCode::NOT_FOUND, "Package not found");
    let Some(RepoFile::Package {
        filename,
        signature: false,
    }) = fmt::classify_repo_file(&filename)
    else {
        return Err(not_found());
    };
    let (artifact_id, _, _) = find_package(
        &state.db,
        repo.id,
        &package_path_candidates(&arch, filename),
    )
    .await?
    .ok_or_else(not_found)?;

    // The same soft delete the REST API performs, so the side effects
    // (search index, usage ledger, sync fan-out, audit) match exactly. The
    // databases are rendered from live rows, so the package drops out of
    // the next `pacman -Sy` with no index rewrite.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    state
        .create_artifact_service(storage)
        .delete(artifact_id)
        .await
        .map_err(|e| e.into_response())?;

    info!("pacman delete: {} from repo {}", filename, repo.key);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn indexed(name: &str, filename: &str, mtime: u64) -> IndexedPackage {
        IndexedPackage {
            csize: 1,
            sha256: "00".into(),
            mtime,
            meta: PacmanMetadata {
                filename: filename.into(),
                arch: "x86_64".into(),
                pkginfo: PkgInfo {
                    pkgname: name.into(),
                    pkgver: "1.0-1".into(),
                    arch: "x86_64".into(),
                    ..Default::default()
                },
                files: None,
                pgpsig: None,
            },
        }
    }

    #[test]
    fn latest_upload_wins_per_name_and_output_is_sorted() {
        let latest = latest_per_name(vec![
            indexed("zeta", "zeta-2", 3),
            indexed("alpha", "alpha-new", 2),
            indexed("alpha", "alpha-old", 1),
        ]);
        let names: Vec<_> = latest.iter().map(|p| p.meta.filename.as_str()).collect();
        assert_eq!(names, vec!["alpha-new", "zeta-2"]);
        let db = render_database(&latest, false).unwrap();
        assert!(!db.is_empty());
    }

    #[test]
    fn path_helpers() {
        let f = "foo-1.0-1-x86_64.pkg.tar.zst";
        assert_eq!(
            package_path_candidates("x86_64", f),
            vec![format!("x86_64/{f}"), format!("any/{f}")]
        );
        assert_eq!(package_path_candidates("any", f), vec![format!("any/{f}")]);
        assert_eq!(filename_arch(f), Some("x86_64"));
        assert_eq!(filename_arch("foo-1.0-1-any.pkg.tar"), Some("any"));
        assert_eq!(filename_arch("README"), None);
        let id = uuid::Uuid::nil();
        assert_eq!(
            storage_key(id, "any/x.pkg.tar"),
            format!("pacman/{id}/any/x.pkg.tar")
        );
    }

    #[test]
    fn upload_filename_must_match_pkginfo() {
        let info = PkgInfo {
            pkgname: "foo".into(),
            pkgver: "1:1.0-2".into(),
            arch: "x86_64".into(),
            ..Default::default()
        };
        assert!(check_upload_filename("foo-1:1.0-2-x86_64.pkg.tar.xz", &info).is_ok());
        for bad in [
            "foo-1.0-2-x86_64.pkg.tar.xz",
            "bar-1:1.0-2-x86_64.pkg.tar.xz",
            "foo-1:1.0-2-any.pkg.tar.xz",
        ] {
            let resp = check_upload_filename(bad, &info).unwrap_err();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[test]
    fn stored_signature_decodes_only_valid_metadata() {
        assert_eq!(stored_signature(None), None);
        assert_eq!(
            stored_signature(Some(serde_json::json!({ "filename": "x" }))),
            None
        );
        assert_eq!(
            stored_signature(Some(serde_json::json!({ "pgpsig": "AAE=" }))),
            Some(vec![0, 1])
        );
        assert_eq!(
            stored_signature(Some(serde_json::json!({ "pgpsig": "%%%" }))),
            None
        );
    }

    #[test]
    fn remote_and_virtual_reads_are_not_implemented() {
        for repo_type in ["remote", "virtual"] {
            let resp = reject_unsupported_repo_type(repo_type).unwrap_err();
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        }
        assert!(reject_unsupported_repo_type("local").is_ok());
        assert!(reject_unsupported_repo_type("staging").is_ok());
    }

    #[test]
    fn rows_without_usable_metadata_are_skipped() {
        let row = |metadata| PackageRow {
            size_bytes: 5,
            checksum_sha256: "ab".into(),
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            metadata,
        };
        assert!(row(None).into_indexed().is_none());
        assert!(row(Some(serde_json::json!({ "filename": "" })))
            .into_indexed()
            .is_none());
        let meta = serde_json::to_value(indexed("a", "a.pkg.tar", 0).meta).unwrap();
        let pkg = row(Some(meta)).into_indexed().unwrap();
        assert_eq!((pkg.csize, pkg.mtime), (5, 1_700_000_000));
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::{Request, StatusCode};
    use bytes::Bytes;
    use std::io::Read;

    const MARKER_PKG: &[u8] =
        include_bytes!("../../../tests/fixtures/ak-marker-1.0-1-any.pkg.tar.zst");
    const MARKER_SIG: &[u8] =
        include_bytes!("../../../tests/fixtures/ak-marker-1.0-1-any.pkg.tar.zst.sig");
    const MARKER_FILE: &str = "ak-marker-1.0-1-any.pkg.tar.zst";

    async fn send(fx: &tdh::Fixture, req: Request<axum::body::Body>) -> (StatusCode, Bytes) {
        tdh::send(fx.router_with_auth(super::router()), req).await
    }

    async fn get(fx: &tdh::Fixture, rel: &str) -> (StatusCode, Bytes) {
        send(fx, tdh::get(format!("/{}/{rel}", fx.repo_key))).await
    }

    async fn put(fx: &tdh::Fixture, rel: &str, body: &'static [u8]) -> StatusCode {
        send(
            fx,
            tdh::put(format!("/{}/{rel}", fx.repo_key), Bytes::from_static(body)),
        )
        .await
        .0
    }

    async fn delete(fx: &tdh::Fixture, rel: &str) -> StatusCode {
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/{}/{rel}", fx.repo_key))
            .body(axum::body::Body::empty())
            .unwrap();
        send(fx, req).await.0
    }

    /// `(entry path, contents)` of every regular file in a served database.
    fn db_members(db: &[u8]) -> Vec<(String, String)> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(db));
        let mut out = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.header().entry_type().is_file() {
                let path = entry.path().unwrap().to_string_lossy().to_string();
                let mut text = String::new();
                entry.read_to_string(&mut text).unwrap();
                out.push((path, text));
            }
        }
        out
    }

    /// Upload, index, download, attach a signature, delete: the hosted
    /// lifecycle pacman relies on.
    #[tokio::test]
    async fn hosted_package_lifecycle() {
        let Some(fx) = tdh::Fixture::setup("local", "pacman").await else {
            return;
        };

        assert_eq!(put(&fx, MARKER_FILE, MARKER_PKG).await, StatusCode::CREATED);
        assert_eq!(
            put(&fx, MARKER_FILE, MARKER_PKG).await,
            StatusCode::CONFLICT
        );
        // A filename that disagrees with .PKGINFO, and a non-package body.
        assert_eq!(
            put(&fx, "ak-marker-9.9-1-any.pkg.tar.zst", MARKER_PKG).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put(&fx, "junk-1-1-any.pkg.tar.zst", b"junk").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(put(&fx, "README", b"x").await, StatusCode::BAD_REQUEST);

        // `any` packages appear in every architecture's databases.
        for arch in ["x86_64", "aarch64"] {
            let (status, db) = get(&fx, &format!("{arch}/myrepo.db")).await;
            assert_eq!(status, StatusCode::OK);
            let members = db_members(&db);
            assert_eq!(members.len(), 1, "{arch}: {members:?}");
            assert_eq!(members[0].0, "ak-marker-1.0-1/desc");
            assert!(members[0]
                .1
                .starts_with(&format!("%FILENAME%\n{MARKER_FILE}\n\n")));
            assert!(!members[0].1.contains("%PGPSIG%"));
        }
        let (status, files_db) = get(&fx, "x86_64/myrepo.files.tar.gz").await;
        assert_eq!(status, StatusCode::OK);
        let members = db_members(&files_db);
        assert_eq!(members[1].0, "ak-marker-1.0-1/files");
        assert!(members[1].1.contains("usr/share/ak-marker/marker.txt\n"));

        let (status, body) = get(&fx, &format!("x86_64/{MARKER_FILE}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], MARKER_PKG);
        assert_eq!(
            get(&fx, "x86_64/other-1-1-any.pkg.tar.zst").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get(&fx, "x86_64/README").await.0, StatusCode::NOT_FOUND);
        assert_eq!(get(&fx, "bad-arch/x.db").await.0, StatusCode::NOT_FOUND);

        // No repository key: the database is unsigned.
        assert_eq!(
            get(&fx, "x86_64/myrepo.db.sig").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get(&fx, "gpg-key.asc").await.0, StatusCode::NOT_FOUND);

        // Package signatures: uploaded after the package, served and indexed.
        let sig_path = format!("x86_64/{MARKER_FILE}.sig");
        assert_eq!(get(&fx, &sig_path).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            put(&fx, &format!("{MARKER_FILE}.sig"), b"garbage").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put(&fx, "missing-1-1-any.pkg.tar.zst.sig", MARKER_SIG).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            put(&fx, &format!("{MARKER_FILE}.sig"), MARKER_SIG).await,
            StatusCode::CREATED
        );
        let (status, sig) = get(&fx, &sig_path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&sig[..], MARKER_SIG);
        let (_, db) = get(&fx, "x86_64/myrepo.db").await;
        let pgpsig = crate::formats::pacman::signature_base64(MARKER_SIG);
        assert!(db_members(&db)[0]
            .1
            .contains(&format!("%PGPSIG%\n{pgpsig}\n\n")));

        // Delete drops the package from the next database render.
        assert_eq!(
            delete(&fx, "x86_64/nothere-1-1-any.pkg.tar.zst").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(delete(&fx, "x86_64/myrepo.db").await, StatusCode::NOT_FOUND);
        assert_eq!(
            delete(&fx, &format!("x86_64/{MARKER_FILE}")).await,
            StatusCode::NO_CONTENT
        );
        let (_, db) = get(&fx, "x86_64/myrepo.db").await;
        assert!(db_members(&db).is_empty());
        assert_eq!(
            get(&fx, &format!("x86_64/{MARKER_FILE}")).await.0,
            StatusCode::NOT_FOUND
        );

        fx.teardown().await;
    }

    /// With a gpg key attached, `{repo}.db.sig` is a binary detached
    /// signature over exactly the bytes `{repo}.db` served.
    #[tokio::test]
    async fn signed_database_verifies_against_the_repository_key() {
        use crate::services::signing_service::{CreateKeyRequest, SigningService};
        use pgp::composed::{Deserializable, StandaloneSignature};

        let Some(fx) = tdh::Fixture::setup("local", "pacman").await else {
            return;
        };
        let svc = SigningService::new(fx.pool.clone(), &fx.state.config.jwt_secret);
        let key = svc
            .create_key(CreateKeyRequest {
                repository_id: Some(fx.repo_id),
                name: format!("pacman-sign-{}", fx.repo_key),
                key_type: "gpg".to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: Some("AK pacman".to_string()),
                uid_email: Some("pacman@example.invalid".to_string()),
                created_by: None,
            })
            .await
            .expect("create signing key");
        svc.update_signing_config(fx.repo_id, Some(key.id), true, false, false)
            .await
            .expect("attach signing key");
        assert_eq!(put(&fx, MARKER_FILE, MARKER_PKG).await, StatusCode::CREATED);

        let (status, served_key) = get(&fx, "gpg-key.asc").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&served_key).unwrap(),
            key.public_key_pem
        );

        for name in ["myrepo.db", "myrepo.files"] {
            let (status, db) = get(&fx, &format!("x86_64/{name}")).await;
            assert_eq!(status, StatusCode::OK);
            let (status, sig) = get(&fx, &format!("x86_64/{name}.sig")).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!sig.starts_with(b"-----BEGIN"), "{name}.sig must be binary");
            let armored = StandaloneSignature::from_bytes(&sig[..])
                .unwrap()
                .to_armored_string(pgp::ArmorOptions::default())
                .unwrap();
            crate::services::signing_service::verify_detached(&key.public_key_pem, &db, &armored)
                .unwrap_or_else(|e| panic!("{name}.sig does not verify: {e}"));
        }
        fx.teardown().await;
    }

    #[tokio::test]
    async fn remote_repositories_answer_not_implemented() {
        let Some(fx) = tdh::Fixture::setup("remote", "pacman").await else {
            return;
        };
        assert_eq!(
            get(&fx, "x86_64/core.db").await.0,
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            put(&fx, MARKER_FILE, MARKER_PKG).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        fx.teardown().await;
    }
}
