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

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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
use crate::formats::cran::CranHandler;
use crate::models::repository::RepositoryType;

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
    virtual_repo_id: uuid::Uuid,
) -> Result<String, Response> {
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo_id).await?;
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

    for (_key, remote_index) in remote_indexes {
        if !remote_index.is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(&remote_index);
        }
    }

    Ok(combined)
}

// ---------------------------------------------------------------------------
// GET /cran/{repo_key}/src/contrib/PACKAGES — Package index (text format)
// ---------------------------------------------------------------------------

async fn package_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cran_repo(&state.db, &repo_key).await?;

    if repo.repo_type == RepositoryType::Virtual {
        let combined = build_virtual_combined_index(&state, repo.id).await?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(CONTENT_LENGTH, combined.len().to_string())
            .body(Body::from(combined))
            .unwrap());
    }

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

    if repo.repo_type == RepositoryType::Virtual {
        let combined = build_virtual_combined_index(&state, repo.id).await?;
        let compressed = gzip_compress(combined.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Compression error: {}", e),
            )
                .into_response()
        })?;

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/gzip")
            .header(CONTENT_LENGTH, compressed.len().to_string())
            .body(Body::from(compressed))
            .unwrap());
    }

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

    let artifact =
        match proxy_helpers::find_local_by_filename_suffix(&state.db, repo.id, &filename).await? {
            Some(a) => a,
            None => {
                let upstream_path = format!("src/contrib/{}", filename);
                if let Some(resp) = proxy_helpers::try_remote_or_virtual_download(
                    &state,
                    &repo,
                    proxy_helpers::DownloadResponseOpts {
                        upstream_path: &upstream_path,
                        virtual_lookup: proxy_helpers::VirtualLookup::PathSuffix(&filename),
                        default_content_type: "application/octet-stream",
                        content_disposition_filename: None,
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
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "cran")?.user_id;
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
    .map_err(super::db_err)?;

    let mut index = String::new();
    for a in &artifacts {
        write_dcf_record(
            &mut index,
            &a.name,
            a.version.as_deref().unwrap_or_default(),
            a.metadata.as_ref(),
        );
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
