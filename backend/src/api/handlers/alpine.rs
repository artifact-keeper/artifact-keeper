//! Alpine/APK repository API handlers.
//!
//! Implements the endpoints required for `apk` package management.
//!
//! Routes are mounted at `/alpine/{repo_key}/...`:
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/APKINDEX.tar.gz  - Package index
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Download package
//!   PUT  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Upload package
//!   POST /alpine/{repo_key}/upload                                        - Upload package (alternative)

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
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::services::signing_service::SigningService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

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

/// Authenticate via Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"alpine\"")
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
                .header("WWW-Authenticate", "Basic realm=\"alpine\"")
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

async fn resolve_alpine_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "alpine" && fmt != "apk" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an Alpine repository (format: {})",
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;

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

// ---------------------------------------------------------------------------
// PUT /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename} - Upload
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Path((repo_key, branch, repository, arch, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

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

    // Store the file
    let storage_key = format!("alpine/{}/{}", repo.id, artifact_path);
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
}
