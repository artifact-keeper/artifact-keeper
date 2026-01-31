//! Conda Channel API handlers.
//!
//! Implements the endpoints required for `conda install` from a private channel.
//!
//! Routes are mounted at `/conda/{repo_key}/...`:
//!   GET  /conda/{repo_key}/channeldata.json                  - Channel metadata
//!   GET  /conda/{repo_key}/keys/repo.pub                     - Repository public key (PEM)
//!   GET  /conda/{repo_key}/{subdir}/repodata.json            - Repository data for subdir
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.bz2        - Compressed repodata
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.sig        - Repodata signature (raw bytes)
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.zst        - Compressed repodata (zstd) [stub]
//!   GET  /conda/{repo_key}/{subdir}/current_repodata.json    - Current (latest) repodata
//!   GET  /conda/{repo_key}/{subdir}/{filename}               - Download package
//!   PUT  /conda/{repo_key}/{subdir}/{filename}               - Upload package
//!   POST /conda/{repo_key}/upload                            - Upload package (alternative)

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::api::SharedState;
use crate::formats::conda_native::CondaNativeHandler;
use crate::services::auth_service::AuthService;
use crate::services::signing_service::SigningService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

/// Common Conda subdirectories.
const KNOWN_SUBDIRS: &[&str] = &[
    "noarch",
    "linux-64",
    "linux-aarch64",
    "linux-ppc64le",
    "linux-s390x",
    "osx-64",
    "osx-arm64",
    "win-64",
    "win-32",
];

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Channel metadata
        .route("/:repo_key/channeldata.json", get(channeldata_json))
        // Public key endpoint
        .route("/:repo_key/keys/repo.pub", get(repo_public_key))
        // Upload (alternative POST)
        .route("/:repo_key/upload", post(upload_post))
        // Subdir repodata endpoints
        .route("/:repo_key/:subdir/repodata.json", get(repodata_json))
        .route(
            "/:repo_key/:subdir/repodata.json.bz2",
            get(repodata_json_bz2),
        )
        .route(
            "/:repo_key/:subdir/repodata.json.sig",
            get(repodata_json_sig),
        )
        .route(
            "/:repo_key/:subdir/repodata.json.zst",
            get(repodata_json_zst),
        )
        .route(
            "/:repo_key/:subdir/current_repodata.json",
            get(current_repodata_json),
        )
        // Package download and upload
        .route(
            "/:repo_key/:subdir/:filename",
            get(download_package).put(upload_package_put),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

async fn authenticate(
    db: &sqlx::PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"conda\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"conda\"")
                .body(Body::from("Invalid credentials"))
                .unwrap()
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
}

async fn resolve_conda_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\" FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt = repo.format.to_lowercase();
    if fmt != "conda" && fmt != "conda_native" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Conda repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
    })
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct CondaArtifact {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
}

async fn list_conda_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
) -> Result<Vec<CondaArtifact>, Response> {
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    Ok(rows
        .into_iter()
        .map(|r| CondaArtifact {
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

/// Filter artifacts that belong to a given subdir based on metadata or path prefix.
fn artifacts_for_subdir<'a>(
    artifacts: &'a [CondaArtifact],
    subdir: &str,
) -> Vec<&'a CondaArtifact> {
    artifacts
        .iter()
        .filter(|a| {
            // Check metadata first
            if let Some(ref meta) = a.metadata {
                if let Some(s) = meta.get("subdir").and_then(|v| v.as_str()) {
                    return s == subdir;
                }
            }
            // Fall back to path prefix
            a.path.starts_with(&format!("{}/", subdir))
        })
        .collect()
}

/// Determine if a filename is a .conda (v2) or .tar.bz2 (v1) package.
fn is_conda_v2(filename: &str) -> bool {
    filename.ends_with(".conda")
}

fn is_conda_package(filename: &str) -> bool {
    filename.ends_with(".conda") || filename.ends_with(".tar.bz2")
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/channeldata.json
// ---------------------------------------------------------------------------

async fn channeldata_json(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let artifacts = list_conda_artifacts(&state.db, repo.id).await?;

    // Query for the latest version of each package (ordered by created_at DESC,
    // so the first row per name is the latest).
    let latest_versions: BTreeMap<String, String> = {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT ON (a.name) a.name, a.version
            FROM artifacts a
            WHERE a.repository_id = $1 AND a.is_deleted = false
            ORDER BY a.name, a.created_at DESC
            "#,
            repo.id
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response()
        })?;

        rows.into_iter()
            .filter_map(|r| r.version.map(|v| (r.name, v)))
            .collect()
    };

    // Collect all packages with their subdirs
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for artifact in &artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        let subdir = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("subdir").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .or_else(|| artifact.path.split('/').next().map(|s| s.to_string()))
            .unwrap_or_else(|| "noarch".to_string());

        let pkg_name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| artifact.name.clone());

        packages.entry(pkg_name).or_default().insert(subdir);
    }

    let packages_json: serde_json::Map<String, serde_json::Value> = packages
        .into_iter()
        .map(|(name, subdirs)| {
            let version = latest_versions.get(&name).cloned().unwrap_or_default();
            let val = serde_json::json!({
                "subdirs": subdirs.into_iter().collect::<Vec<_>>(),
                "version": version,
            });
            (name, val)
        })
        .collect();

    let channeldata = serde_json::json!({
        "channeldata_version": 1,
        "packages": packages_json,
        "subdirs": KNOWN_SUBDIRS,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string_pretty(&channeldata).unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json
// ---------------------------------------------------------------------------

async fn repodata_json(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &subdir, false).await?;

    let body = serde_json::to_string_pretty(&repodata).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.bz2
// ---------------------------------------------------------------------------

async fn repodata_json_bz2(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &subdir, false).await?;

    let json_bytes = serde_json::to_vec(&repodata).unwrap();
    let compressed = bzip2_compress(&json_bytes);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-bzip2")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.sig
// ---------------------------------------------------------------------------

/// Return the raw RSA signature of repodata.json for the given subdir.
///
/// Conda uses raw (non-PGP-armored) signatures. Returns 404 if the repository
/// has no active signing key configured.
async fn repodata_json_sig(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &subdir, false).await?;

    let json_bytes = serde_json::to_vec(&repodata).unwrap();

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, &json_bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing error: {}", e),
            )
                .into_response()
        })?;

    match signature {
        Some(sig_bytes) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, sig_bytes.len().to_string())
            .body(Body::from(sig_bytes))
            .unwrap()),
        None => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.zst
// ---------------------------------------------------------------------------

/// Return repodata.json compressed with zstd.
///
/// Modern conda/mamba clients prefer zstd over bz2 for faster decompression.
/// TODO: Add zstd crate dependency to enable this endpoint. For now returns 404.
async fn repodata_json_zst(
    State(_state): State<SharedState>,
    Path((_repo_key, _subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    // TODO: Enable once the `zstd` crate is added to Cargo.toml:
    //
    //   let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    //   let repodata = build_repodata(&state.db, repo.id, &subdir, false).await?;
    //   let json_bytes = serde_json::to_vec(&repodata).unwrap();
    //   let compressed = zstd::encode_all(std::io::Cursor::new(&json_bytes), 3)
    //       .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("zstd error: {}", e)).into_response())?;
    //   Ok(Response::builder()
    //       .status(StatusCode::OK)
    //       .header(CONTENT_TYPE, "application/zstd")
    //       .header(CONTENT_LENGTH, compressed.len().to_string())
    //       .body(Body::from(compressed))
    //       .unwrap())

    Err((
        StatusCode::NOT_FOUND,
        "repodata.json.zst not yet supported; use repodata.json or repodata.json.bz2",
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/keys/repo.pub
// ---------------------------------------------------------------------------

/// Return the repository's RSA public key in PEM format.
async fn repo_public_key(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing service error: {}", e),
            )
                .into_response()
        })?;

    match public_key {
        Some(pem) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/x-pem-file")
            .header(CONTENT_LENGTH, pem.len().to_string())
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
// GET /conda/{repo_key}/{subdir}/current_repodata.json
// ---------------------------------------------------------------------------

async fn current_repodata_json(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &subdir, true).await?;

    let body = serde_json::to_string_pretty(&repodata).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Repodata generation
// ---------------------------------------------------------------------------

/// Build repodata.json for a given subdir from the database.
///
/// When `latest_only` is true, only the most recent version of each package
/// is included (for current_repodata.json).
async fn build_repodata(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    subdir: &str,
    latest_only: bool,
) -> Result<serde_json::Value, Response> {
    let all_artifacts = list_conda_artifacts(db, repo_id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, subdir);

    // If latest_only, keep only the latest version per package name
    let filtered: Vec<&CondaArtifact> = if latest_only {
        let mut latest: BTreeMap<String, &CondaArtifact> = BTreeMap::new();
        for a in &subdir_artifacts {
            let pkg_name = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("name").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .unwrap_or_else(|| a.name.clone());

            // Use the first occurrence (already sorted by created_at DESC)
            latest.entry(pkg_name).or_insert(a);
        }
        latest.into_values().collect()
    } else {
        subdir_artifacts
    };

    let mut packages = serde_json::Map::new();
    let mut packages_conda = serde_json::Map::new();

    for artifact in &filtered {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        let pkg_name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| artifact.name.clone());

        let version = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .or_else(|| artifact.version.clone())
            .unwrap_or_else(|| "0".to_string());

        let build = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());

        let build_number = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
            .unwrap_or(0);

        let depends = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let entry = serde_json::json!({
            "name": pkg_name,
            "version": version,
            "build": build,
            "build_number": build_number,
            "depends": depends,
            "md5": artifact.metadata.as_ref()
                .and_then(|m| m.get("md5").and_then(|v| v.as_str()))
                .unwrap_or(""),
            "sha256": artifact.checksum_sha256,
            "size": artifact.size_bytes,
            "subdir": subdir,
        });

        if is_conda_v2(filename) {
            packages_conda.insert(filename.to_string(), entry);
        } else {
            packages.insert(filename.to_string(), entry);
        }
    }

    Ok(serde_json::json!({
        "info": { "subdir": subdir },
        "packages": packages,
        "packages.conda": packages_conda,
    }))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/{filename} - Download package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    // Look up artifact by path
    let artifact_path = format!("{}/{}", subdir, filename);

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;

    // Read from storage
    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let content_type = if filename.ends_with(".conda") {
        "application/octet-stream"
    } else if filename.ends_with(".tar.bz2") {
        "application/x-tar"
    } else {
        "application/octet-stream"
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /conda/{repo_key}/{subdir}/{filename} - Upload package
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// POST /conda/{repo_key}/upload - Upload package (alternative)
// ---------------------------------------------------------------------------

async fn upload_post(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    // Determine subdir and filename from headers
    let subdir = headers
        .get("X-Conda-Subdir")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "noarch".to_string());

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
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing filename: provide Content-Disposition or X-Package-Filename header",
            )
                .into_response()
        })?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

async fn store_conda_package(
    state: &SharedState,
    repo: &RepoInfo,
    subdir: &str,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    // Parse the filename using the existing conda_native handler
    let conda_path = format!("{}/{}", subdir, filename);
    let path_info = CondaNativeHandler::parse_path(&conda_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Conda package path: {}", e),
        )
            .into_response()
    })?;

    let pkg_name = path_info
        .name
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Could not parse package name").into_response())?;
    let pkg_version = path_info.version.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Could not parse package version").into_response()
    })?;
    let build_string = path_info.build.unwrap_or_else(|| "0".to_string());

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}", subdir, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Package already exists").into_response());
    }

    // Store the file
    let storage_key = format!("conda/{}/{}/{}", repo.id, subdir, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage
        .put(&storage_key, content.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let size_bytes = content.len() as i64;
    let content_type = if filename.ends_with(".conda") {
        "application/octet-stream"
    } else {
        "application/x-tar"
    };

    // Insert artifact record
    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        pkg_name,
        pkg_version,
        size_bytes,
        computed_sha256,
        content_type,
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Store conda-specific metadata
    let conda_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "build": build_string,
        "build_number": 0,
        "subdir": subdir,
        "package_format": if filename.ends_with(".conda") { "v2" } else { "v1" },
        "depends": [],
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'conda', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        conda_metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Conda upload: {}-{}-{} ({}) to repo {}/{}",
        pkg_name, pkg_version, build_string, filename, repo.id, subdir
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": pkg_name,
                "version": pkg_version,
                "build": build_string,
                "subdir": subdir,
                "sha256": computed_sha256,
                "size": size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Compress data using bzip2.
fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).expect("bzip2 write failed");
    encoder.finish().expect("bzip2 finish failed")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_conda_package() {
        assert!(is_conda_package("numpy-1.26.4-py312h02b7e37_0.conda"));
        assert!(is_conda_package("requests-2.31.0-pyhd8ed1ab_0.tar.bz2"));
        assert!(!is_conda_package("foo.whl"));
        assert!(!is_conda_package("bar.rpm"));
    }

    #[test]
    fn test_is_conda_v2() {
        assert!(is_conda_v2("numpy-1.26.4-py312h02b7e37_0.conda"));
        assert!(!is_conda_v2("requests-2.31.0-pyhd8ed1ab_0.tar.bz2"));
    }

    #[test]
    fn test_bzip2_compress() {
        let data = b"test data for bzip2 compression";
        let compressed = bzip2_compress(data);
        assert!(!compressed.is_empty());
        assert_ne!(compressed.as_slice(), data);
    }
}
