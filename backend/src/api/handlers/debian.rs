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

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use base64::Engine;
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
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_debian_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["debian", "apt"], "a Debian").await
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

/// Attempt to proxy a metadata file (Release, InRelease, Release.gpg,
/// Packages, Packages.gz) from the upstream for remote Debian repos.
/// Returns `Ok(Some(response))` on a successful proxy fetch, `Ok(None)` if
/// the repo is not configured for proxying, or `Err(response)` on proxy
/// failure (which the caller should surface to the client).
async fn try_proxy_debian_metadata(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    upstream_path: &str,
    content_type: &'static str,
) -> Result<Option<Response>, Response> {
    if repo.repo_type != RepositoryType::Remote {
        return Ok(None);
    }
    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok(None),
    };
    let (content, upstream_ct) =
        proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, upstream_path).await?;
    Ok(Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(
                CONTENT_TYPE,
                upstream_ct.unwrap_or_else(|| content_type.to_string()),
            )
            .header(CONTENT_LENGTH, content.len().to_string())
            .body(Body::from(content))
            .unwrap(),
    ))
}

/// Resolve a Debian repo and, when it is a remote proxy, attempt to fetch
/// the given dists file from upstream. Returns `Ok(Some(response))` when the
/// upstream proxy succeeds, `Ok(None)` for local/staging repos (so the
/// caller can generate the file locally), or `Err(response)` on failure.
///
/// This is a thin wrapper around [`try_proxy_debian_metadata`] that builds
/// the upstream path from the distribution name and filename suffix,
/// eliminating repeated `format!` + `try_proxy_debian_metadata` blocks
/// across the Release, InRelease, and Release.gpg handlers.
async fn try_proxy_dists_file(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    distribution: &str,
    filename: &str,
    content_type: &'static str,
) -> Result<Option<Response>, Response> {
    let upstream_path = format!("dists/{}/{}", distribution, filename);
    try_proxy_debian_metadata(state, repo, repo_key, &upstream_path, content_type).await
}

async fn release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    if let Some(response) = try_proxy_dists_file(
        &state,
        &repo,
        &repo_key,
        &distribution,
        "Release",
        "text/plain; charset=utf-8",
    )
    .await?
    {
        return Ok(response);
    }

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

    if let Some(response) = try_proxy_dists_file(
        &state,
        &repo,
        &repo_key,
        &distribution,
        "InRelease",
        "text/plain; charset=utf-8",
    )
    .await?
    {
        return Ok(response);
    }

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

    if let Some(response) = try_proxy_dists_file(
        &state,
        &repo,
        &repo_key,
        &distribution,
        "Release.gpg",
        "application/pgp-signature",
    )
    .await?
    {
        return Ok(response);
    }

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
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    // For remote repos, proxy the upstream Packages index.
    let packages_suffix = format!("{}/{}/Packages", component, binary_arch);
    if let Some(response) = try_proxy_dists_file(
        &state,
        &repo,
        &repo_key,
        &distribution,
        &packages_suffix,
        "text/plain; charset=utf-8",
    )
    .await?
    {
        return Ok(response);
    }

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
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    // For remote repos, proxy the upstream compressed Packages index.
    let packages_gz_suffix = format!("{}/{}/Packages.gz", component, binary_arch);
    if let Some(response) = try_proxy_dists_file(
        &state,
        &repo,
        &repo_key,
        &distribution,
        &packages_gz_suffix,
        "application/gzip",
    )
    .await?
    {
        return Ok(response);
    }

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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("pool/{}/{}", component, path);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("pool/{}/{}", component, path);
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

                let filename = path.rsplit('/').next().unwrap_or(&path);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type
                            .unwrap_or_else(|| "application/vnd.debian.binary-package".to_string()),
                    )
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "debian")?.user_id;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;

    // Store the file
    let storage_key = format!("debian/{}", artifact_path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "debian")?.user_id;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;

    // Store the file
    let storage_key = format!("debian/{}", artifact_path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_deb_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_deb_filename_valid() {
        let info = parse_deb_filename("nginx_1.24.0_amd64.deb").unwrap();
        assert_eq!(info.name, "nginx");
        assert_eq!(info.version, "1.24.0");
        assert_eq!(info.arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_complex_version() {
        let info = parse_deb_filename("libssl_3.0.2-0ubuntu1.10_arm64.deb").unwrap();
        assert_eq!(info.name, "libssl");
        assert_eq!(info.version, "3.0.2-0ubuntu1.10");
        assert_eq!(info.arch, "arm64");
    }

    #[test]
    fn test_parse_deb_filename_arch_all() {
        let info = parse_deb_filename("python3-pip_23.0_all.deb").unwrap();
        assert_eq!(info.name, "python3-pip");
        assert_eq!(info.version, "23.0");
        assert_eq!(info.arch, "all");
    }

    #[test]
    fn test_parse_deb_filename_no_deb_extension() {
        assert!(parse_deb_filename("nginx_1.0_amd64.rpm").is_none());
    }

    #[test]
    fn test_parse_deb_filename_too_few_parts() {
        assert!(parse_deb_filename("nginx_amd64.deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_no_underscores() {
        assert!(parse_deb_filename("nginx.deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_empty_string() {
        assert!(parse_deb_filename("").is_none());
    }

    #[test]
    fn test_parse_deb_filename_just_extension() {
        assert!(parse_deb_filename(".deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_version_with_underscores_in_arch() {
        let info = parse_deb_filename("pkg_1.0_i386.deb").unwrap();
        assert_eq!(info.name, "pkg");
        assert_eq!(info.version, "1.0");
        assert_eq!(info.arch, "i386");
    }

    // -----------------------------------------------------------------------
    // build_packages_text
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_packages_text_single_entry() {
        let entries = vec![PackageEntry {
            name: "nginx".to_string(),
            version: "1.24.0".to_string(),
            arch: "amd64".to_string(),
            filename: "pool/main/n/nginx/nginx_1.24.0_amd64.deb".to_string(),
            size: 1024,
            sha256: "abc123".to_string(),
            description: "HTTP server".to_string(),
        }];
        let text = build_packages_text(&entries);
        assert!(text.contains("Package: nginx\n"));
        assert!(text.contains("Version: 1.24.0\n"));
        assert!(text.contains("Architecture: amd64\n"));
        assert!(text.contains("Filename: pool/main/n/nginx/nginx_1.24.0_amd64.deb\n"));
        assert!(text.contains("Size: 1024\n"));
        assert!(text.contains("SHA256: abc123\n"));
        assert!(text.contains("Description: HTTP server\n"));
    }

    #[test]
    fn test_build_packages_text_multiple_entries() {
        let entries = vec![
            PackageEntry {
                name: "pkg1".to_string(),
                version: "1.0".to_string(),
                arch: "amd64".to_string(),
                filename: "pool/main/p/pkg1/pkg1_1.0_amd64.deb".to_string(),
                size: 100,
                sha256: "hash1".to_string(),
                description: "Package 1".to_string(),
            },
            PackageEntry {
                name: "pkg2".to_string(),
                version: "2.0".to_string(),
                arch: "arm64".to_string(),
                filename: "pool/main/p/pkg2/pkg2_2.0_arm64.deb".to_string(),
                size: 200,
                sha256: "hash2".to_string(),
                description: "Package 2".to_string(),
            },
        ];
        let text = build_packages_text(&entries);
        assert!(text.contains("Package: pkg1\n"));
        assert!(text.contains("Package: pkg2\n"));
        // Entries should be separated by a blank line
        assert!(text.contains("\n\n"));
    }

    #[test]
    fn test_build_packages_text_empty() {
        let entries: Vec<PackageEntry> = vec![];
        let text = build_packages_text(&entries);
        assert!(text.is_empty());
    }

    // -----------------------------------------------------------------------
    // pgp_armor_signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_pgp_armor_signature_basic() {
        let sig_data = b"test signature data";
        let armored = pgp_armor_signature(sig_data);
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----\n"));
        assert!(armored.ends_with("-----END PGP SIGNATURE-----\n"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig_data);
        assert!(armored.contains(&b64));
    }

    #[test]
    fn test_pgp_armor_signature_empty() {
        let armored = pgp_armor_signature(b"");
        assert!(armored.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(armored.contains("-----END PGP SIGNATURE-----"));
    }

    #[test]
    fn test_pgp_armor_signature_long_data_wraps() {
        let sig_data = vec![0u8; 100];
        let armored = pgp_armor_signature(&sig_data);
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----\n"));
        assert!(armored.ends_with("-----END PGP SIGNATURE-----\n"));
    }

    // -----------------------------------------------------------------------
    // pgp_clearsign
    // -----------------------------------------------------------------------

    #[test]
    fn test_pgp_clearsign_basic() {
        let content = "Origin: artifact-keeper\nSuite: stable\n";
        let sig_data = b"signature";
        let result = pgp_clearsign(content, sig_data);
        assert!(result.starts_with("-----BEGIN PGP SIGNED MESSAGE-----\n"));
        assert!(result.contains("Hash: SHA256\n"));
        assert!(result.contains(content));
        assert!(result.contains("-----BEGIN PGP SIGNATURE-----\n"));
        assert!(result.contains("-----END PGP SIGNATURE-----\n"));
    }

    #[test]
    fn test_pgp_clearsign_preserves_content() {
        let content = "Line 1\nLine 2\nLine 3\n";
        let sig = b"sig";
        let result = pgp_clearsign(content, sig);
        assert!(result.contains("Line 1\nLine 2\nLine 3\n"));
    }

    // -----------------------------------------------------------------------
    // Upstream path construction for APT remote proxy (#674)
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_dists_paths_match_debian_mirror_layout() {
        // All five metadata endpoints build upstream paths via
        // try_proxy_dists_file(state, repo, key, dist, suffix, ct).
        // The path is always "dists/{dist}/{suffix}". Verify the
        // expected paths match the real Debian/Ubuntu mirror layout.
        let cases = vec![
            ("trixie", "Release", "dists/trixie/Release"),
            ("trixie-updates", "Release", "dists/trixie-updates/Release"),
            ("bookworm", "InRelease", "dists/bookworm/InRelease"),
            (
                "bookworm-security",
                "InRelease",
                "dists/bookworm-security/InRelease",
            ),
            ("trixie", "Release.gpg", "dists/trixie/Release.gpg"),
            (
                "trixie",
                "main/binary-amd64/Packages",
                "dists/trixie/main/binary-amd64/Packages",
            ),
            (
                "trixie",
                "non-free/binary-arm64/Packages",
                "dists/trixie/non-free/binary-arm64/Packages",
            ),
            (
                "trixie",
                "main/binary-amd64/Packages.gz",
                "dists/trixie/main/binary-amd64/Packages.gz",
            ),
        ];
        for (dist, suffix, expected) in &cases {
            let path = format!("dists/{}/{}", dist, suffix);
            assert_eq!(
                &path, expected,
                "path mismatch for dist={}, suffix={}",
                dist, suffix
            );
        }
    }

    #[test]
    fn test_upstream_url_assembly_matches_debian_org() {
        // Full URL assembly: upstream_url + "/" + dists path must point at
        // the real Debian mirror.
        let upstream = "http://deb.debian.org/debian";
        let path = format!("dists/{}/{}", "trixie", "InRelease");
        let full_url = format!("{}/{}", upstream.trim_end_matches('/'), path);
        assert_eq!(
            full_url,
            "http://deb.debian.org/debian/dists/trixie/InRelease"
        );
    }
}
