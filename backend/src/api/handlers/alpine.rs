//! Alpine/APK repository API handlers.
//!
//! Implements the endpoints required for `apk` package management.
//!
//! Routes are mounted at `/alpine/{repo_key}/...`:
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/APKINDEX.tar.gz  - Package index
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Download package
//!   PUT  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Upload package
//!   POST /alpine/{repo_key}/upload                                        - Upload package (alternative)

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::signing_service::SigningService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // APKINDEX endpoint
        .route(
            "/:repo_key/:branch/:repository/:arch/APKINDEX.tar.gz",
            get(apk_index),
        )
        // Package download and upload
        .route(
            "/:repo_key/:branch/:repository/:arch/:filename",
            get(download_package).put(upload_package_put),
        )
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_package_post))
        // Public key endpoint for signature verification
        .route(
            "/:repo_key/:branch/keys/artifact-keeper.rsa.pub",
            get(public_key),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_alpine_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["alpine", "apk"], "an Alpine").await
}

// ---------------------------------------------------------------------------
// APK filename parsing
// ---------------------------------------------------------------------------

/// Parse an APK filename into (name, version).
/// Expected format: `{name}-{version}.apk`
/// Version starts at the first hyphen followed by a digit.
///
/// Examples:
///   curl-8.5.0-r0.apk   -> ("curl", "8.5.0-r0")
///   my-app-1.2.3-r1.apk -> ("my-app", "1.2.3-r1")
fn parse_apk_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".apk")?;

    // Find version boundary: first hyphen followed by a digit
    let chars: Vec<char> = stem.chars().collect();
    for i in 1..chars.len() {
        if chars[i - 1] == '-' && chars[i].is_ascii_digit() {
            let name = &stem[..i - 1];
            let version = &stem[i..];
            if !name.is_empty() && !version.is_empty() {
                return Some((name.to_string(), version.to_string()));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct AlpineArtifact {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
}

async fn list_alpine_artifacts(
    db: &PgPool,
    repo_id: uuid::Uuid,
    branch: &str,
    repository: &str,
    arch: &str,
) -> Result<Vec<AlpineArtifact>, Response> {
    let path_prefix = format!("{}/{}/{}/", branch, repository, arch);
    let rows = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE $2 || '%'
        ORDER BY a.name, a.created_at DESC
        "#,
        repo_id,
        path_prefix
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
        .map(|r| AlpineArtifact {
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

// ---------------------------------------------------------------------------
// APKINDEX generation
// ---------------------------------------------------------------------------

/// Generate APKINDEX text content from artifact entries.
///
/// Each package entry has the format:
/// ```text
/// C:<sha1_checksum>
/// P:<pkgname>
/// V:<version>
/// A:<arch>
/// S:<size>
/// I:<installed_size>
/// T:<description>
/// U:<url>
/// L:<license>
/// D:<dependencies>
///
/// ```
fn generate_apkindex_text(artifacts: &[AlpineArtifact], arch: &str) -> String {
    let mut text = String::new();

    for artifact in artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        // Extract metadata from artifact_metadata if available, else parse filename
        let (name, version) = if let Some(ref meta) = artifact.metadata {
            (
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&artifact.name)
                    .to_string(),
                meta.get("version")
                    .and_then(|v| v.as_str())
                    .or(artifact.version.as_deref())
                    .unwrap_or("0")
                    .to_string(),
            )
        } else if let Some((n, v)) = parse_apk_filename(filename) {
            (n, v)
        } else {
            (
                artifact.name.clone(),
                artifact.version.clone().unwrap_or_else(|| "0".to_string()),
            )
        };

        let description = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let url = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let license = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let depends = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let installed_size = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("installed_size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Use first 40 chars of SHA256 as a stand-in for the checksum field (C:)
        // Real APKINDEX uses SHA1 of the package's data segment, but we use SHA256 truncated
        let checksum = &artifact.checksum_sha256;

        text.push_str(&format!("C:{}\n", checksum));
        text.push_str(&format!("P:{}\n", name));
        text.push_str(&format!("V:{}\n", version));
        text.push_str(&format!("A:{}\n", arch));
        text.push_str(&format!("S:{}\n", artifact.size_bytes));
        text.push_str(&format!("I:{}\n", installed_size));
        text.push_str(&format!("T:{}\n", description));
        text.push_str(&format!("U:{}\n", url));
        text.push_str(&format!("L:{}\n", license));
        if !depends.is_empty() {
            text.push_str(&format!("D:{}\n", depends));
        }
        text.push('\n');
    }

    text
}

/// Create an APKINDEX.tar.gz from the text content with an optional RSA signature.
///
/// When `signature` is `Some`, the archive contains:
///   1. `.SIGN.RSA.artifact-keeper.rsa.pub` — raw RSA signature bytes
///   2. `APKINDEX` — the package index
///
/// When `signature` is `None`, only the `APKINDEX` entry is included.
#[allow(clippy::result_large_err)]
fn create_apkindex_tar_gz(
    apkindex_text: &str,
    signature: Option<&[u8]>,
) -> Result<Vec<u8>, Response> {
    let gz_buf = Vec::new();
    let gz_encoder = GzEncoder::new(gz_buf, Compression::default());
    let mut tar_builder = tar::Builder::new(gz_encoder);

    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // If a signature is available, add .SIGN file FIRST (apk verifies order)
    if let Some(sig_bytes) = signature {
        let mut sig_header = tar::Header::new_gnu();
        sig_header
            .set_path(".SIGN.RSA.artifact-keeper.rsa.pub")
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to set tar path for signature: {}", e),
                )
                    .into_response()
            })?;
        sig_header.set_size(sig_bytes.len() as u64);
        sig_header.set_mode(0o644);
        sig_header.set_mtime(mtime);
        sig_header.set_cksum();

        tar_builder.append(&sig_header, sig_bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append signature to tar: {}", e),
            )
                .into_response()
        })?;
    }

    let content_bytes = apkindex_text.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_path("APKINDEX").map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to set tar path: {}", e),
        )
            .into_response()
    })?;
    header.set_size(content_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(mtime);
    header.set_cksum();

    tar_builder.append(&header, content_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to append to tar: {}", e),
        )
            .into_response()
    })?;

    let gz_encoder = tar_builder.into_inner().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to finalize tar: {}", e),
        )
            .into_response()
    })?;

    gz_encoder.finish().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to finalize gzip: {}", e),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/{repository}/{arch}/APKINDEX.tar.gz
// ---------------------------------------------------------------------------

async fn apk_index(
    State(state): State<SharedState>,
    Path((repo_key, branch, repository, arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    // For remote repos, proxy the APKINDEX.tar.gz from upstream as-is so that
    // the upstream cryptographic signatures are preserved. Generating a local
    // index would break apk's signature verification.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let upstream_path = build_apk_index_upstream_path(&branch, &repository, &arch);
            let (content, content_type) =
                proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, &upstream_path)
                    .await?;

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    content_type.unwrap_or_else(|| "application/gzip".to_string()),
                )
                .header(CONTENT_LENGTH, content.len().to_string())
                .body(Body::from(content))
                .unwrap());
        }
    }

    // For virtual repos, try each remote member in priority order so that
    // upstream-signed indexes are returned when available.
    if repo.repo_type == RepositoryType::Virtual {
        let upstream_path = build_apk_index_upstream_path(&branch, &repository, &arch);
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                continue;
            }
            let Some(ref upstream_url) = member.upstream_url else {
                continue;
            };
            let Some(ref proxy) = state.proxy_service else {
                continue;
            };

            let result = proxy_helpers::proxy_fetch(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                &upstream_path,
            )
            .await;

            match result {
                Ok((content, content_type)) => {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            CONTENT_TYPE,
                            content_type.unwrap_or_else(|| "application/gzip".to_string()),
                        )
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
                Err(_e) => {
                    tracing::debug!(
                        member_key = %member.key,
                        "APKINDEX proxy fetch failed for virtual member, trying next"
                    );
                    continue;
                }
            }
        }
    }

    // Hosted repos (and virtual fallback): generate APKINDEX from local artifacts.
    // TODO: For virtual repos this fallback queries `repo.id` (the virtual repo itself),
    // which won't find artifacts stored under hosted members. A follow-up should aggregate
    // artifacts from all hosted members of the virtual repo.
    let artifacts = list_alpine_artifacts(&state.db, repo.id, &branch, &repository, &arch).await?;

    let apkindex_text = generate_apkindex_text(&artifacts, &arch);

    // Sign the APKINDEX content if signing is configured for this repository
    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, apkindex_text.as_bytes())
        .await
        .unwrap_or(None);

    let tar_gz = create_apkindex_tar_gz(&apkindex_text, signature.as_deref())?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, tar_gz.len().to_string())
        .body(Body::from(tar_gz))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/keys/artifact-keeper.rsa.pub - Public key
// ---------------------------------------------------------------------------

async fn public_key(
    State(state): State<SharedState>,
    Path((repo_key, _branch)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_pem = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve public key: {}", e),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "No signing key configured for this repository",
            )
                .into_response()
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-pem-file")
        .header(
            "Content-Disposition",
            "attachment; filename=\"artifact-keeper.rsa.pub\"",
        )
        .header(CONTENT_LENGTH, public_pem.len().to_string())
        .body(Body::from(public_pem))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename} - Download
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, branch, repository, arch, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let Some(response) = try_proxy_apk(
                    &state,
                    &repo,
                    &repo_key,
                    &branch,
                    &repository,
                    &arch,
                    &filename,
                )
                .await?
                {
                    return Ok(response);
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);
                let artifact_path_clone = artifact_path.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = artifact_path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db, &state, member_id, &location, &path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type
                            .unwrap_or_else(|| "application/vnd.alpine.package".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    match storage.get(&artifact.storage_key).await {
        Ok(content) => {
            // Record download
            let _ = sqlx::query!(
                "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
                artifact.id
            )
            .execute(&state.db)
            .await;

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.alpine.package")
                .header(
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                )
                .header(CONTENT_LENGTH, content.len().to_string())
                .header("X-Checksum-SHA256", &artifact.checksum_sha256)
                .body(Body::from(content))
                .unwrap())
        }
        Err(e) => {
            // Storage retrieval failed. For remote repos, the DB record may
            // have been created by the proxy cache with a storage key that
            // is not accessible via the repo's own storage backend. Fall
            // through to proxy fetch to re-download from upstream.
            tracing::warn!(
                "Storage get failed for artifact {} (key: {}): {}. Falling through to proxy.",
                artifact.id,
                artifact.storage_key,
                e,
            );
            if repo.repo_type == RepositoryType::Remote {
                if let Some(response) = try_proxy_apk(
                    &state,
                    &repo,
                    &repo_key,
                    &branch,
                    &repository,
                    &arch,
                    &filename,
                )
                .await?
                {
                    return Ok(response);
                }
            }
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response())
        }
    }
}

/// Attempt to proxy-fetch an APK package from the upstream remote repository.
/// Returns `Ok(Some(response))` on success, `Ok(None)` if the repo has no
/// upstream or proxy configured, or `Err(response)` on proxy failure.
async fn try_proxy_apk(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    branch: &str,
    repository: &str,
    arch: &str,
    filename: &str,
) -> Result<Option<Response>, Response> {
    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok(None),
    };
    let upstream_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);
    let (content, content_type) =
        proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, &upstream_path).await?;
    Ok(Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(
                "Content-Type",
                content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
            )
            .body(Body::from(content))
            .unwrap(),
    ))
}

// ---------------------------------------------------------------------------
// PUT /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename} - Upload
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, branch, repository, arch, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "alpine")?.user_id;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    store_apk(
        &state,
        &repo,
        &branch,
        &repository,
        &arch,
        &filename,
        body,
        user_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /alpine/{repo_key}/upload - Upload (alternative)
// ---------------------------------------------------------------------------

async fn upload_package_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "alpine")?.user_id;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Extract filename from headers
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
            format!("{}.apk", &hash[..16])
        });

    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    // Extract branch/repository/arch from headers or use defaults
    let branch = headers
        .get("X-Alpine-Branch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("edge")
        .to_string();

    let repository = headers
        .get("X-Alpine-Repository")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("main")
        .to_string();

    let arch = headers
        .get("X-Alpine-Arch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("x86_64")
        .to_string();

    store_apk(
        &state,
        &repo,
        &branch,
        &repository,
        &arch,
        &filename,
        body,
        user_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn store_apk(
    state: &SharedState,
    repo: &RepoInfo,
    branch: &str,
    repository: &str,
    arch: &str,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    let computed_sha256 = sha256_hex(&content);

    // Parse APK filename for metadata
    let (pkg_name, pkg_version) = parse_apk_filename(filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid APK filename '{}'. Expected format: {{name}}-{{version}}.apk",
                filename
            ),
        )
            .into_response()
    })?;

    let artifact_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);

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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage_key = format!("alpine/{}/{}", repo.id, artifact_path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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
        "application/vnd.alpine.package",
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

    // Store Alpine-specific metadata
    let alpine_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "arch": arch,
        "branch": branch,
        "repository": repository,
        "filename": filename,
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'alpine', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        alpine_metadata,
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
        "Alpine upload: {}-{} arch={} to repo {} ({}/{}/{})",
        pkg_name, pkg_version, arch, repo.id, branch, repository, arch
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": pkg_name,
                "version": pkg_version,
                "arch": arch,
                "branch": branch,
                "repository": repository,
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

/// Build the upstream path for an APKINDEX request.
///
/// Alpine mirrors structure their content as:
///   `{branch}/{repository}/{arch}/APKINDEX.tar.gz`
///
/// For example, `v3.22/main/x86_64/APKINDEX.tar.gz`.
fn build_apk_index_upstream_path(branch: &str, repository: &str, arch: &str) -> String {
    format!("{}/{}/{}/APKINDEX.tar.gz", branch, repository, arch)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the artifact path for an Alpine package.
    fn build_alpine_artifact_path(
        branch: &str,
        repository: &str,
        arch: &str,
        filename: &str,
    ) -> String {
        format!("{}/{}/{}/{}", branch, repository, arch, filename)
    }

    /// Build the storage key for an Alpine package.
    fn build_alpine_storage_key(repo_id: uuid::Uuid, artifact_path: &str) -> String {
        format!("alpine/{}/{}", repo_id, artifact_path)
    }

    /// Build Alpine-specific metadata JSON.
    fn build_alpine_metadata(
        pkg_name: &str,
        pkg_version: &str,
        arch: &str,
        branch: &str,
        repository: &str,
        filename: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": pkg_name,
            "version": pkg_version,
            "arch": arch,
            "branch": branch,
            "repository": repository,
            "filename": filename,
        })
    }

    /// Build the JSON upload response for an Alpine package.
    fn build_alpine_upload_response(
        pkg_name: &str,
        pkg_version: &str,
        arch: &str,
        branch: &str,
        repository: &str,
        sha256: &str,
        size: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": pkg_name,
            "version": pkg_version,
            "arch": arch,
            "branch": branch,
            "repository": repository,
            "sha256": sha256,
            "size": size,
        })
    }

    /// Build the path prefix used for listing Alpine artifacts.
    fn build_alpine_path_prefix(branch: &str, repository: &str, arch: &str) -> String {
        format!("{}/{}/{}/", branch, repository, arch)
    }

    /// Extract filename from a Content-Disposition header value.
    fn extract_filename_from_content_disposition(value: &str) -> Option<String> {
        value
            .split("filename=")
            .nth(1)
            .map(|f| f.trim_matches('"').trim_matches('\'').to_string())
    }

    #[test]
    fn test_parse_apk_filename_simple() {
        let result = parse_apk_filename("curl-8.5.0-r0.apk");
        assert_eq!(result, Some(("curl".to_string(), "8.5.0-r0".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_hyphenated_name() {
        let result = parse_apk_filename("my-app-1.2.3-r1.apk");
        assert_eq!(result, Some(("my-app".to_string(), "1.2.3-r1".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_complex() {
        let result = parse_apk_filename("libxml2-dev-2.12.4-r0.apk");
        assert_eq!(
            result,
            Some(("libxml2-dev".to_string(), "2.12.4-r0".to_string()))
        );
    }

    #[test]
    fn test_parse_apk_filename_invalid() {
        assert_eq!(parse_apk_filename("notanapk.txt"), None);
        assert_eq!(parse_apk_filename("bad.apk"), None);
        assert_eq!(parse_apk_filename(""), None);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_generate_apkindex_text_empty() {
        let text = generate_apkindex_text(&[], "x86_64");
        assert!(text.is_empty());
    }

    #[test]
    fn test_create_apkindex_tar_gz_empty() {
        let result = create_apkindex_tar_gz("", None);
        assert!(result.is_ok());
        let tar_gz = result.unwrap();
        assert!(!tar_gz.is_empty());
    }

    #[test]
    fn test_create_apkindex_tar_gz_with_content() {
        let content = "C:abc123\nP:curl\nV:8.5.0-r0\nA:x86_64\nS:1234\nI:5678\nT:URL retrieval utility\nU:https://curl.se\nL:MIT\n\n";
        let result = create_apkindex_tar_gz(content, None);
        assert!(result.is_ok());

        // Verify it's a valid tar.gz by decompressing
        let tar_gz = result.unwrap();
        let gz = flate2::read::GzDecoder::new(&tar_gz[..]);
        let mut archive = tar::Archive::new(gz);
        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_create_apkindex_tar_gz_with_signature() {
        let content = "C:abc123\nP:curl\nV:8.5.0-r0\nA:x86_64\nS:1234\nI:5678\nT:URL retrieval utility\nU:https://curl.se\nL:MIT\n\n";
        let fake_signature = b"fake-rsa-signature-bytes";
        let result = create_apkindex_tar_gz(content, Some(fake_signature));
        assert!(result.is_ok());

        // Verify both entries exist in the correct order
        let tar_gz = result.unwrap();
        let gz = flate2::read::GzDecoder::new(&tar_gz[..]);
        let mut archive = tar::Archive::new(gz);
        let entry_names: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                e.path().ok().map(|p| p.to_string_lossy().to_string())
            })
            .collect();
        assert_eq!(entry_names.len(), 2);
        assert_eq!(entry_names[0], ".SIGN.RSA.artifact-keeper.rsa.pub");
        assert_eq!(entry_names[1], "APKINDEX");
    }

    // -----------------------------------------------------------------------
    // build_alpine_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_artifact_path_basic() {
        assert_eq!(
            build_alpine_artifact_path("edge", "main", "x86_64", "curl-8.5.0-r0.apk"),
            "edge/main/x86_64/curl-8.5.0-r0.apk"
        );
    }

    #[test]
    fn test_build_alpine_artifact_path_v3() {
        assert_eq!(
            build_alpine_artifact_path("v3.18", "community", "aarch64", "nginx-1.25.4-r0.apk"),
            "v3.18/community/aarch64/nginx-1.25.4-r0.apk"
        );
    }

    #[test]
    fn test_build_alpine_artifact_path_testing() {
        assert_eq!(
            build_alpine_artifact_path("edge", "testing", "x86_64", "zsh-5.9-r0.apk"),
            "edge/testing/x86_64/zsh-5.9-r0.apk"
        );
    }

    // -----------------------------------------------------------------------
    // build_alpine_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_storage_key_basic() {
        let repo_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            build_alpine_storage_key(repo_id, "edge/main/x86_64/curl-8.5.0-r0.apk"),
            "alpine/550e8400-e29b-41d4-a716-446655440000/edge/main/x86_64/curl-8.5.0-r0.apk"
        );
    }

    // -----------------------------------------------------------------------
    // build_alpine_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_metadata_basic() {
        let meta = build_alpine_metadata(
            "curl",
            "8.5.0-r0",
            "x86_64",
            "edge",
            "main",
            "curl-8.5.0-r0.apk",
        );
        assert_eq!(meta["name"], "curl");
        assert_eq!(meta["version"], "8.5.0-r0");
        assert_eq!(meta["arch"], "x86_64");
        assert_eq!(meta["branch"], "edge");
        assert_eq!(meta["repository"], "main");
        assert_eq!(meta["filename"], "curl-8.5.0-r0.apk");
    }

    #[test]
    fn test_build_alpine_metadata_different_arch() {
        let meta = build_alpine_metadata(
            "nginx",
            "1.25.4-r0",
            "aarch64",
            "v3.19",
            "community",
            "nginx-1.25.4-r0.apk",
        );
        assert_eq!(meta["arch"], "aarch64");
        assert_eq!(meta["branch"], "v3.19");
        assert_eq!(meta["repository"], "community");
    }

    // -----------------------------------------------------------------------
    // build_alpine_upload_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_upload_response_basic() {
        let resp = build_alpine_upload_response(
            "curl",
            "8.5.0-r0",
            "x86_64",
            "edge",
            "main",
            "abc123def456",
            1024,
        );
        assert_eq!(resp["name"], "curl");
        assert_eq!(resp["version"], "8.5.0-r0");
        assert_eq!(resp["arch"], "x86_64");
        assert_eq!(resp["branch"], "edge");
        assert_eq!(resp["repository"], "main");
        assert_eq!(resp["sha256"], "abc123def456");
        assert_eq!(resp["size"], 1024);
    }

    #[test]
    fn test_build_alpine_upload_response_zero_size() {
        let resp = build_alpine_upload_response("pkg", "1.0", "x86", "edge", "main", "hash", 0);
        assert_eq!(resp["size"], 0);
    }

    #[test]
    fn test_build_alpine_upload_response_large_size() {
        let resp = build_alpine_upload_response(
            "big-pkg",
            "2.0",
            "x86_64",
            "edge",
            "main",
            "hash",
            1_073_741_824,
        );
        assert_eq!(resp["size"], 1_073_741_824);
    }

    // -----------------------------------------------------------------------
    // build_alpine_path_prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_path_prefix_basic() {
        assert_eq!(
            build_alpine_path_prefix("edge", "main", "x86_64"),
            "edge/main/x86_64/"
        );
    }

    #[test]
    fn test_build_alpine_path_prefix_versioned() {
        assert_eq!(
            build_alpine_path_prefix("v3.18", "community", "aarch64"),
            "v3.18/community/aarch64/"
        );
    }

    // -----------------------------------------------------------------------
    // extract_filename_from_content_disposition
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_filename_from_cd_basic() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename=curl-8.5.0-r0.apk"),
            Some("curl-8.5.0-r0.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_quoted() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename=\"my-pkg-1.0.apk\""),
            Some("my-pkg-1.0.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_single_quoted() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename='test.apk'"),
            Some("test.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_no_filename() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment"),
            None
        );
    }

    #[test]
    fn test_extract_filename_from_cd_inline() {
        assert_eq!(
            extract_filename_from_content_disposition("inline; filename=data.apk"),
            Some("data.apk".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // generate_apkindex_text with artifacts
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_apkindex_text_single_artifact() {
        let artifacts = vec![AlpineArtifact {
            id: uuid::Uuid::new_v4(),
            path: "edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
            name: "curl".to_string(),
            version: Some("8.5.0-r0".to_string()),
            size_bytes: 1234,
            checksum_sha256: "abc123".to_string(),
            storage_key: "alpine/xxx/edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
            metadata: Some(serde_json::json!({
                "name": "curl",
                "version": "8.5.0-r0",
                "description": "URL retrieval utility",
                "url": "https://curl.se",
                "license": "MIT",
                "depends": "libc",
                "installed_size": 5678
            })),
        }];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        assert!(text.contains("P:curl"));
        assert!(text.contains("V:8.5.0-r0"));
        assert!(text.contains("A:x86_64"));
        assert!(text.contains("S:1234"));
        assert!(text.contains("I:5678"));
        assert!(text.contains("T:URL retrieval utility"));
        assert!(text.contains("U:https://curl.se"));
        assert!(text.contains("L:MIT"));
        assert!(text.contains("D:libc"));
        assert!(text.contains("C:abc123"));
    }

    #[test]
    fn test_generate_apkindex_text_multiple_artifacts() {
        let artifacts = vec![
            AlpineArtifact {
                id: uuid::Uuid::new_v4(),
                path: "edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
                name: "curl".to_string(),
                version: Some("8.5.0-r0".to_string()),
                size_bytes: 1234,
                checksum_sha256: "hash1".to_string(),
                storage_key: "key1".to_string(),
                metadata: None,
            },
            AlpineArtifact {
                id: uuid::Uuid::new_v4(),
                path: "edge/main/x86_64/nginx-1.25.4-r0.apk".to_string(),
                name: "nginx".to_string(),
                version: Some("1.25.4-r0".to_string()),
                size_bytes: 5678,
                checksum_sha256: "hash2".to_string(),
                storage_key: "key2".to_string(),
                metadata: None,
            },
        ];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        assert!(text.contains("P:curl"));
        assert!(text.contains("P:nginx"));
        // Should have two blank-line-terminated entries
        let entries: Vec<&str> = text.split("\n\n").filter(|s| !s.is_empty()).collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_generate_apkindex_text_no_depends() {
        let artifacts = vec![AlpineArtifact {
            id: uuid::Uuid::new_v4(),
            path: "edge/main/x86_64/busybox-1.36.apk".to_string(),
            name: "busybox".to_string(),
            version: Some("1.36".to_string()),
            size_bytes: 100,
            checksum_sha256: "hash".to_string(),
            storage_key: "key".to_string(),
            metadata: Some(serde_json::json!({
                "name": "busybox",
                "version": "1.36",
            })),
        }];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        // depends is empty, D: line should NOT be present
        assert!(!text.contains("D:"));
        assert!(text.contains("P:busybox"));
    }

    // -----------------------------------------------------------------------
    // sha256_hex with different inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_hex_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"alpine package");
        let h2 = sha256_hex(b"alpine package");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        let h1 = sha256_hex(b"data1");
        let h2 = sha256_hex(b"data2");
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // parse_apk_filename edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_apk_filename_leading_digit() {
        // Package name starts with number but has no hyphen-digit boundary
        assert_eq!(parse_apk_filename("123pkg.apk"), None);
    }

    #[test]
    fn test_parse_apk_filename_just_dash_digit() {
        let result = parse_apk_filename("a-1.apk");
        assert_eq!(result, Some(("a".to_string(), "1".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_multiple_dashes() {
        let result = parse_apk_filename("my-cool-app-2.0.0-r0.apk");
        assert_eq!(
            result,
            Some(("my-cool-app".to_string(), "2.0.0-r0".to_string()))
        );
    }

    #[test]
    fn test_parse_apk_filename_no_apk_extension() {
        assert_eq!(parse_apk_filename("curl-8.5.0-r0.tar.gz"), None);
    }

    // -----------------------------------------------------------------------
    // build_apk_index_upstream_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_apk_index_upstream_path_versioned() {
        assert_eq!(
            build_apk_index_upstream_path("v3.22", "main", "x86_64"),
            "v3.22/main/x86_64/APKINDEX.tar.gz"
        );
    }

    #[test]
    fn test_build_apk_index_upstream_path_edge() {
        assert_eq!(
            build_apk_index_upstream_path("edge", "community", "aarch64"),
            "edge/community/aarch64/APKINDEX.tar.gz"
        );
    }

    #[test]
    fn test_build_apk_index_upstream_path_testing() {
        assert_eq!(
            build_apk_index_upstream_path("v3.21", "testing", "armv7"),
            "v3.21/testing/armv7/APKINDEX.tar.gz"
        );
    }

    /// Verify the upstream path matches the real Alpine mirror structure.
    /// Given upstream_url = "https://dl-cdn.alpinelinux.org/alpine", the
    /// full URL must be:
    ///   https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz
    #[test]
    fn test_build_apk_index_upstream_path_matches_alpine_mirror_structure() {
        let path = build_apk_index_upstream_path("v3.22", "main", "x86_64");
        let upstream = "https://dl-cdn.alpinelinux.org/alpine";
        let full_url = format!("{}/{}", upstream.trim_end_matches('/'), path);
        assert_eq!(
            full_url,
            "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-version path differentiation (#653)
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_paths_differ_across_alpine_versions() {
        // The same package name must produce different artifact paths for
        // different Alpine versions, preventing cross-version collisions.
        let path_v322 = build_alpine_artifact_path("v3.22", "main", "x86_64", "curl-8.5.0-r0.apk");
        let path_v323 = build_alpine_artifact_path("v3.23", "main", "x86_64", "curl-8.5.0-r0.apk");
        assert_ne!(path_v322, path_v323);
        assert!(path_v322.starts_with("v3.22/"));
        assert!(path_v323.starts_with("v3.23/"));
    }

    #[test]
    fn test_artifact_path_includes_all_components() {
        let path =
            build_alpine_artifact_path("v3.21", "community", "aarch64", "nginx-1.26.0-r0.apk");
        assert_eq!(path, "v3.21/community/aarch64/nginx-1.26.0-r0.apk");
    }

    #[test]
    fn test_storage_keys_differ_across_alpine_versions() {
        let repo_id = uuid::Uuid::new_v4();
        let path_v322 =
            build_alpine_artifact_path("v3.22", "main", "x86_64", "busybox-1.37.0-r10.apk");
        let path_v323 =
            build_alpine_artifact_path("v3.23", "main", "x86_64", "busybox-1.37.0-r10.apk");
        let key_v322 = build_alpine_storage_key(repo_id, &path_v322);
        let key_v323 = build_alpine_storage_key(repo_id, &path_v323);
        assert_ne!(key_v322, key_v323);
    }
}
