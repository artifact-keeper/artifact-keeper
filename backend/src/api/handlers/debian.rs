//! Debian/APT repository handlers.
//!
//! Implements the endpoints required for `apt-get` to consume packages
//! and for uploading `.deb` files.
//!
//! Routes are mounted at `/debian/{repo_key}/...`:
//!   GET  /debian/{repo_key}/dists/{distribution}/Release                            - Release file
//!   GET  /debian/{repo_key}/dists/{distribution}/InRelease                          - Inline signed release
//!   GET  /debian/{repo_key}/dists/{distribution}/Release.gpg                        - Detached GPG signature
//!   GET  /debian/{repo_key}/dists/{distribution}/gpg-key.asc                        - Repository public key
//!   GET  /debian/{repo_key}/dists/{distribution}/{component}/binary-{arch}/Packages - Packages index
//!   GET  /debian/{repo_key}/dists/{distribution}/{component}/binary-{arch}/Packages.gz - Compressed Packages index
//!   GET  /debian/{repo_key}/pool/{component}/*path                                  - Download .deb
//!   PUT  /debian/{repo_key}/pool/{component}/*path                                  - Upload .deb
//!   POST /debian/{repo_key}/upload                                                  - Upload .deb (raw body)

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
        // Release files
        .route("/:repo_key/dists/:distribution/Release", get(release_file))
        .route(
            "/:repo_key/dists/:distribution/InRelease",
            get(in_release_file),
        )
        .route(
            "/:repo_key/dists/:distribution/Release.gpg",
            get(release_gpg),
        )
        // Public key endpoint
        .route(
            "/:repo_key/dists/:distribution/gpg-key.asc",
            get(gpg_key_asc),
        )
        // Packages index
        .route(
            "/:repo_key/dists/:distribution/:component/:binary_arch/Packages",
            get(packages_index),
        )
        .route(
            "/:repo_key/dists/:distribution/:component/:binary_arch/Packages.gz",
            get(packages_index_gz),
        )
        // TODO: Add Packages.xz support once xz2/lzma crate is available
        // .route(
        //     "/:repo_key/dists/:distribution/:component/:binary_arch/Packages.xz",
        //     get(packages_index_xz),
        // )
        // Pool: download and upload
        .route(
            "/:repo_key/pool/:component/*path",
            get(pool_download).put(pool_upload),
        )
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_raw))
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
            .header("WWW-Authenticate", "Basic realm=\"debian\"")
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
                .header("WWW-Authenticate", "Basic realm=\"debian\"")
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

async fn resolve_debian_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "debian" && fmt != "apt" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Debian repository (format: {})",
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
// Debian metadata from filename
// ---------------------------------------------------------------------------

struct DebInfo {
    name: String,
    version: String,
    arch: String,
}

/// Parse `{name}_{version}_{arch}.deb` from a filename.
fn parse_deb_filename(filename: &str) -> Option<DebInfo> {
    let stem = filename.strip_suffix(".deb")?;
    let parts: Vec<&str> = stem.splitn(3, '_').collect();
    if parts.len() != 3 {
        return None;
    }
    Some(DebInfo {
        name: parts[0].to_string(),
        version: parts[1].to_string(),
        arch: parts[2].to_string(),
    })
}

// ---------------------------------------------------------------------------
// Packages index generation
// ---------------------------------------------------------------------------

struct PackageEntry {
    name: String,
    version: String,
    arch: String,
    filename: String,
    size: i64,
    sha256: String,
    description: String,
}

/// Build the text for a Packages index from a list of entries.
fn build_packages_text(entries: &[PackageEntry]) -> String {
    let mut text = String::new();
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        text.push_str(&format!("Package: {}\n", entry.name));
        text.push_str(&format!("Version: {}\n", entry.version));
        text.push_str(&format!("Architecture: {}\n", entry.arch));
        text.push_str(&format!("Filename: {}\n", entry.filename));
        text.push_str(&format!("Size: {}\n", entry.size));
        text.push_str(&format!("SHA256: {}\n", entry.sha256));
        text.push_str(&format!("Description: {}\n", entry.description));
    }
    text
}

/// Fetch all package entries for a given repo, component, and architecture.
async fn fetch_package_entries(
    db: &PgPool,
    repo_id: uuid::Uuid,
    component: &str,
    arch: &str,
) -> Result<Vec<PackageEntry>, Response> {
    let artifacts = sqlx::query!(
        r#"
        SELECT a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE 'pool/' || $2 || '/%'
        ORDER BY a.name, a.created_at DESC
        "#,
        repo_id,
        component
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

    let mut entries = Vec::new();
    for a in &artifacts {
        let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
        let deb_info = match parse_deb_filename(filename) {
            Some(info) => info,
            None => continue,
        };

        // Filter by architecture
        if arch != "all" && deb_info.arch != arch && deb_info.arch != "all" {
            continue;
        }

        let description = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("No description available")
            .to_string();

        let version = a.version.clone().unwrap_or(deb_info.version.clone());

        entries.push(PackageEntry {
            name: deb_info.name,
            version,
            arch: deb_info.arch,
            filename: a.path.clone(),
            size: a.size_bytes,
            sha256: a.checksum_sha256.clone(),
            description,
        });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Release content generation (shared by Release, InRelease, Release.gpg)
// ---------------------------------------------------------------------------

async fn generate_release_content(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<String, Response> {
    // Gather all architectures from uploaded packages
    let mut architectures = std::collections::BTreeSet::new();
    let artifacts = sqlx::query_scalar!(
        r#"
        SELECT path
        FROM artifacts
        WHERE repository_id = $1 AND is_deleted = false AND path LIKE 'pool/%'
        "#,
        repo_id,
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

    for path in &artifacts {
        if let Some(filename) = path.rsplit('/').next() {
            if let Some(info) = parse_deb_filename(filename) {
                architectures.insert(info.arch);
            }
        }
    }

    if architectures.is_empty() {
        architectures.insert("amd64".to_string());
        architectures.insert("arm64".to_string());
    }

    let arch_list: Vec<&str> = architectures.iter().map(|s| s.as_str()).collect();
    let arch_str = arch_list.join(" ");

    // Generate Packages text for SHA256 hashes in Release
    let component = "main";
    let packages_text = {
        let mut all_entries = Vec::new();
        for arch in &architectures {
            let entries = fetch_package_entries(&state.db, repo_id, component, arch).await?;
            all_entries.extend(entries);
        }
        build_packages_text(&all_entries)
    };
    let packages_bytes = packages_text.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(packages_bytes);
    let packages_sha256 = format!("{:x}", hasher.finalize());

    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(packages_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;
    let gz_bytes = gz_encoder.finish().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    let mut gz_hasher = Sha256::new();
    gz_hasher.update(&gz_bytes);
    let gz_sha256 = format!("{:x}", gz_hasher.finalize());

    let now = chrono::Utc::now();
    let date_str = now.format("%a, %d %b %Y %H:%M:%S UTC").to_string();

    let release = format!(
        "Origin: artifact-keeper\n\
         Label: artifact-keeper\n\
         Suite: {distribution}\n\
         Codename: {distribution}\n\
         Architectures: {arch_str}\n\
         Components: {component}\n\
         Date: {date_str}\n\
         SHA256:\n \
         {packages_sha256} {packages_size} {component}/binary-all/Packages\n \
         {gz_sha256} {gz_size} {component}/binary-all/Packages.gz\n",
        distribution = distribution,
        arch_str = arch_str,
        component = component,
        date_str = date_str,
        packages_sha256 = packages_sha256,
        packages_size = packages_bytes.len(),
        gz_sha256 = gz_sha256,
        gz_size = gz_bytes.len(),
    );

    Ok(release)
}

// ---------------------------------------------------------------------------
// PGP armor helpers
// ---------------------------------------------------------------------------

/// Wrap a raw signature in PGP detached signature armor format.
fn pgp_armor_signature(signature: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    // Wrap base64 at 76 characters per line (PGP convention)
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN PGP SIGNATURE-----\n\
         \n\
         {}\n\
         -----END PGP SIGNATURE-----\n",
        wrapped.join("\n"),
    )
}

/// Produce a GPG-style clearsigned document from content and signature.
fn pgp_clearsign(content: &str, signature: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\n\
         Hash: SHA256\n\
         \n\
         {content}\
         -----BEGIN PGP SIGNATURE-----\n\
         \n\
         {sig}\n\
         -----END PGP SIGNATURE-----\n",
        content = content,
        sig = wrapped.join("\n"),
    )
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/Release
// ---------------------------------------------------------------------------

async fn release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    let release = generate_release_content(&state, repo.id, &distribution).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(release))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/InRelease
// ---------------------------------------------------------------------------

async fn in_release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    let release = generate_release_content(&state, repo.id, &distribution).await?;

    // Attempt to sign the release content
    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, release.as_bytes())
        .await
        .unwrap_or(None);

    let body = match signature {
        Some(sig) => pgp_clearsign(&release, &sig),
        None => release,
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/Release.gpg
// ---------------------------------------------------------------------------

async fn release_gpg(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    let release = generate_release_content(&state, repo.id, &distribution).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, release.as_bytes())
        .await
        .unwrap_or(None);

    match signature {
        Some(sig) => {
            let armored = pgp_armor_signature(&sig);
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
// GET /debian/{repo_key}/dists/{distribution}/gpg-key.asc
// ---------------------------------------------------------------------------

async fn gpg_key_asc(
    State(state): State<SharedState>,
    Path((repo_key, _distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve public key: {}", e),
            )
                .into_response()
        })?;

    match public_key {
        Some(pem) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/pgp-keys")
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
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages
// ---------------------------------------------------------------------------

async fn packages_index(
    State(state): State<SharedState>,
    Path((repo_key, _distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    // binary_arch is like "binary-amd64", strip the "binary-" prefix
    let arch = binary_arch.strip_prefix("binary-").unwrap_or(&binary_arch);

    let entries = fetch_package_entries(&state.db, repo.id, &component, arch).await?;
    let text = build_packages_text(&entries);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, text.len().to_string())
        .body(Body::from(text))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages.gz
// ---------------------------------------------------------------------------

async fn packages_index_gz(
    State(state): State<SharedState>,
    Path((repo_key, _distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let arch = binary_arch.strip_prefix("binary-").unwrap_or(&binary_arch);

    let entries = fetch_package_entries(&state.db, repo.id, &component, arch).await?;
    let text = build_packages_text(&entries);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;
    let compressed = encoder.finish().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/pool/{component}/*path — Download .deb
// ---------------------------------------------------------------------------

async fn pool_download(
    State(state): State<SharedState>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("pool/{}/{}", component, path);

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

    let filename = path.rsplit('/').next().unwrap_or(&path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.debian.binary-package")
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
// PUT /debian/{repo_key}/pool/{component}/*path — Upload .deb
// ---------------------------------------------------------------------------

async fn pool_upload(
    State(state): State<SharedState>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let filename = path.rsplit('/').next().unwrap_or(&path);
    let deb_info = parse_deb_filename(filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid .deb filename. Expected format: {name}_{version}_{arch}.deb",
        )
            .into_response()
    })?;

    let artifact_path = format!("pool/{}/{}", component, path);

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

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;

    // Store the file
    let storage_key = format!("debian/{}", artifact_path);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        deb_info.name,
        deb_info.version,
        size_bytes,
        sha256,
        "application/vnd.debian.binary-package",
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

    // Store metadata
    let metadata = serde_json::json!({
        "name": deb_info.name,
        "version": deb_info.version,
        "architecture": deb_info.arch,
        "component": component,
        "description": "No description available",
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'debian', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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
        "Debian upload: {} {} {} to repo {} (component: {})",
        deb_info.name, deb_info.version, deb_info.arch, repo_key, component
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /debian/{repo_key}/upload — Upload .deb (raw body, filename in header)
// ---------------------------------------------------------------------------

async fn upload_raw(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    // Extract filename from X-Filename or Content-Disposition header
    let filename = headers
        .get("X-Filename")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("Content-Disposition")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.split("filename=")
                        .nth(1)
                        .map(|s| s.trim_matches('"').trim_matches('\''))
                })
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing filename. Provide X-Filename header or Content-Disposition with filename",
            )
                .into_response()
        })?
        .to_string();

    let deb_info = parse_deb_filename(&filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid .deb filename. Expected format: {name}_{version}_{arch}.deb",
        )
            .into_response()
    })?;

    let component = "main";
    let first_char = deb_info
        .name
        .chars()
        .next()
        .unwrap_or('_')
        .to_ascii_lowercase();
    let pool_path = format!("{}/{}/{}", first_char, deb_info.name, filename);
    let artifact_path = format!("pool/{}/{}", component, pool_path);

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

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;

    // Store the file
    let storage_key = format!("debian/{}", artifact_path);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        deb_info.name,
        deb_info.version,
        size_bytes,
        sha256,
        "application/vnd.debian.binary-package",
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

    // Store metadata
    let metadata = serde_json::json!({
        "name": deb_info.name,
        "version": deb_info.version,
        "architecture": deb_info.arch,
        "component": component,
        "description": "No description available",
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'debian', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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
        "Debian upload (raw): {} {} {} to repo {}",
        deb_info.name, deb_info.version, deb_info.arch, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "status": "created",
                "package": deb_info.name,
                "version": deb_info.version,
                "architecture": deb_info.arch,
                "path": artifact_path,
                "sha256": sha256,
                "size": size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}
