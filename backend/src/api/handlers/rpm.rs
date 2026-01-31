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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
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
        // Package download and upload
        .route("/:repo_key/packages/*path", get(download_package))
        .route("/:repo_key/packages/*path", put(upload_package_put))
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_package_post))
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
            .header("WWW-Authenticate", "Basic realm=\"rpm\"")
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
                .header("WWW-Authenticate", "Basic realm=\"rpm\"")
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

async fn resolve_rpm_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "rpm" && fmt != "yum" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an RPM repository (format: {})",
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

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

// ---------------------------------------------------------------------------
// Shared repomd.xml generation
// ---------------------------------------------------------------------------

fn generate_repomd_xml_content(artifacts: &[RpmArtifact]) -> String {
    // Generate primary.xml content and compute its gzipped checksum
    let primary_xml = generate_primary_xml(artifacts);
    let primary_gz = gzip_bytes(primary_xml.as_bytes());
    let primary_sha256 = sha256_hex(&primary_gz);

    let filelists_xml = generate_filelists_xml(artifacts);
    let filelists_gz = gzip_bytes(filelists_xml.as_bytes());
    let filelists_sha256 = sha256_hex(&filelists_gz);

    let other_xml = generate_other_xml(artifacts);
    let other_gz = gzip_bytes(other_xml.as_bytes());
    let other_sha256 = sha256_hex(&other_gz);

    let updateinfo_xml = generate_updateinfo_xml();
    let updateinfo_gz = gzip_bytes(updateinfo_xml.as_bytes());
    let updateinfo_sha256 = sha256_hex(&updateinfo_gz);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/primary.xml.gz"/>
    <checksum type="sha256">{primary_sha256}</checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{primary_size}</size>
  </data>
  <data type="filelists">
    <location href="repodata/filelists.xml.gz"/>
    <checksum type="sha256">{filelists_sha256}</checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{filelists_size}</size>
  </data>
  <data type="other">
    <location href="repodata/other.xml.gz"/>
    <checksum type="sha256">{other_sha256}</checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{other_size}</size>
  </data>
  <data type="updateinfo">
    <location href="repodata/updateinfo.xml.gz"/>
    <checksum type="sha256">{updateinfo_sha256}</checksum>
    <timestamp>{timestamp}</timestamp>
    <size>{updateinfo_size}</size>
  </data>
</repomd>
"#,
        primary_sha256 = primary_sha256,
        filelists_sha256 = filelists_sha256,
        other_sha256 = other_sha256,
        updateinfo_sha256 = updateinfo_sha256,
        timestamp = timestamp,
        primary_size = primary_gz.len(),
        filelists_size = filelists_gz.len(),
        other_size = other_gz.len(),
        updateinfo_size = updateinfo_gz.len(),
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
    let artifacts = list_rpm_artifacts(&state.db, repo.id).await?;

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
    let artifacts = list_rpm_artifacts(&state.db, repo.id).await?;

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
    let _repo = resolve_rpm_repo(&state.db, &repo_key).await?;

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
    let artifacts = list_rpm_artifacts(&state.db, repo.id).await?;

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
    let artifacts = list_rpm_artifacts(&state.db, repo.id).await?;

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
    let artifacts = list_rpm_artifacts(&state.db, repo.id).await?;

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
// GET /rpm/{repo_key}/packages/*path — Download RPM package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, pkg_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

    let filename = pkg_path.rsplit('/').next().unwrap_or(&pkg_path);

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE '%/' || $2
        LIMIT 1
        "#,
        repo.id,
        filename
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
        .header(CONTENT_TYPE, "application/x-rpm")
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
// PUT /rpm/{repo_key}/packages/*path — Upload RPM package
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Path((repo_key, pkg_path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_rpm_repo(&state.db, &repo_key).await?;

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
    let storage_key = format!("rpm/{}/{}", repo.id, filename);
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
        full_version,
        size_bytes,
        computed_sha256,
        "application/x-rpm",
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

    // Store RPM-specific metadata
    let rpm_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "release": release,
        "arch": arch,
        "filename": filename,
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'rpm', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        rpm_metadata,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_xml_escape() {
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
    }

    #[test]
    fn test_generate_primary_xml_empty() {
        let xml = generate_primary_xml(&[]);
        assert!(xml.contains("packages=\"0\""));
        assert!(xml.contains("</metadata>"));
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
}
