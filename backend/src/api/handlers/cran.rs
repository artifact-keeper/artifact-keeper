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

use std::io::Write as IoWrite;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::cran::CranHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

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
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"cran\"")
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
                .header("WWW-Authenticate", "Basic realm=\"cran\"")
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
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_cran_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        r#"SELECT id, storage_path, format::text as "format!", repo_type::text as "repo_type!", upstream_url
        FROM repositories WHERE key = $1"#,
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
    if fmt != "cran" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a CRAN repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/PACKAGES — Package index (text format)
// ---------------------------------------------------------------------------

async fn package_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    let index = build_source_index(&state.db, repo.id).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, index.len().to_string())
        .body(Body::from(index))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/PACKAGES.gz — Gzipped package index
// ---------------------------------------------------------------------------

async fn package_index_gz(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    let index = build_source_index(&state.db, repo.id).await?;

    let compressed = gzip_compress(index.as_bytes()).map_err(|e| {
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
// GET /cran/{repo_key}/src/contrib/{filename} — Download source package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, filename)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, version, size_bytes, checksum_sha256, storage_key
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("src/contrib/{}", filename);
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
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let upstream_path = format!("src/contrib/{}", filename);
                let vfilename = filename.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let vfilename = vfilename.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db,
                                member_id,
                                &storage_path,
                                &vfilename,
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
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let _ = rversion; // Used for route matching; filtering done via metadata
    let mut index = String::new();
    for a in &artifacts {
        index.push_str(&format!("Package: {}\n", a.name));
        index.push_str(&format!(
            "Version: {}\n",
            a.version.clone().unwrap_or_default()
        ));
        if let Some(deps) = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .and_then(|v| v.as_str())
        {
            index.push_str(&format!("Depends: {}\n", deps));
        }
        index.push('\n');
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, index.len().to_string())
        .body(Body::from(index))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /cran/{repo_key}/src/contrib/{filename} — Upload package (auth required)
// ---------------------------------------------------------------------------

async fn upload_package(
    State(state): State<SharedState>,
    Path((repo_key, filename)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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
        return Err((StatusCode::CONFLICT, "Package version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("cran/{}/{}/{}", pkg_name, pkg_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let pkg_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "filename": filename,
        "is_binary": false,
    });

    let size_bytes = body.len() as i64;

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
        "application/x-gzip",
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

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'cran', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pkg_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
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

/// Build PACKAGES index in CRAN DCF text format for source packages.
async fn build_source_index(db: &PgPool, repo_id: uuid::Uuid) -> Result<String, Response> {
    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY a.name, a.created_at DESC
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

    let mut index = String::new();
    for a in &artifacts {
        index.push_str(&format!("Package: {}\n", a.name));
        index.push_str(&format!(
            "Version: {}\n",
            a.version.clone().unwrap_or_default()
        ));
        if let Some(deps) = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .and_then(|v| v.as_str())
        {
            index.push_str(&format!("Depends: {}\n", deps));
        }
        index.push('\n');
    }

    Ok(index)
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use flate2::read::GzDecoder;
    use std::io::Read;

    // -----------------------------------------------------------------------
    // extract_credentials — Bearer token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token-123"),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(
            creds,
            Some(("token".to_string(), "my-token-123".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-token"),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(creds, Some(("token".to_string(), "my-token".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_credentials — Basic auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_basic() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:secret123");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(creds, Some(("alice".to_string(), "secret123".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_lowercase() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("bob:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(creds, Some(("bob".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_colon_in_password() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p:a:s:s");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let creds = extract_credentials(&headers);
        assert_eq!(creds, Some(("user".to_string(), "p:a:s:s".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_credentials — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_credentials_invalid_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Digest abc123"),
        );
        assert!(extract_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!not-valid-base64!!!"),
        );
        assert!(extract_credentials(&headers).is_none());
    }

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
            storage_path: "/data/cran-local".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.storage_path, "/data/cran-local");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cran-remote".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://cloud.r-project.org".to_string()),
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
}
