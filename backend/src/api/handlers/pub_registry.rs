//! Pub (Dart/Flutter) API handlers.
//!
//! Implements the Pub Repository Spec v2 endpoints for `dart pub publish`
//! and `dart pub get`.
//!
//! Routes are mounted at `/pub/{repo_key}/...`:
//!   GET  /pub/{repo_key}/api/packages/{name}                       - Package info
//!   GET  /pub/{repo_key}/api/packages/{name}/versions/{version}    - Version info
//!   GET  /pub/{repo_key}/packages/{name}/versions/{version}.tar.gz - Download archive
//!   POST /pub/{repo_key}/api/packages/versions/new                 - Get upload URL
//!   POST /pub/{repo_key}/api/packages/versions/newUpload           - Upload package
//!   GET  /pub/{repo_key}/api/packages/versions/newUploadFinish     - Finalize upload

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Upload flow (must be registered before the parameterized routes
        // so that literal segments match before `:name` captures them)
        // Spec: the "get upload URL" step is an HTTP GET, not POST. The Dart
        // SDK issues `GET /api/packages/versions/new`; serving it as POST made
        // the SDK receive 405 and abort with "Invalid server response" (#1997).
        .route("/:repo_key/api/packages/versions/new", get(new_upload_url))
        .route(
            "/:repo_key/api/packages/versions/newUpload",
            post(upload_package),
        )
        .route(
            "/:repo_key/api/packages/versions/newUploadFinish",
            get(finalize_upload),
        )
        // Package info
        .route("/:repo_key/api/packages/:name", get(package_info))
        // Version info
        .route(
            "/:repo_key/api/packages/:name/versions/:version",
            get(version_info),
        )
        // Download archive - wildcard to capture name/versions/version.tar.gz
        .route("/:repo_key/packages/*archive_path", get(download_archive))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_pub_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["pub"], "a Pub").await
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/{name} -- Package info
// ---------------------------------------------------------------------------

async fn package_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        name
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if artifacts.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            let archive_url = format!(
                "/pub/{}/packages/{}/versions/{}.tar.gz",
                repo_key, name, version
            );

            let pubspec = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("pubspec"))
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "name": name,
                        "version": version,
                    })
                });

            serde_json::json!({
                "version": version,
                "archive_url": archive_url,
                "pubspec": pubspec,
            })
        })
        .collect();

    let latest = versions.first().cloned().unwrap_or(serde_json::json!(null));

    let json = serde_json::json!({
        "name": name,
        "latest": latest,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/{name}/versions/{version} -- Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Version not found").into_response())?;

    let ver = artifact.version.clone().unwrap_or_default();
    let archive_url = format!(
        "/pub/{}/packages/{}/versions/{}.tar.gz",
        repo_key, name, ver
    );

    let pubspec = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("pubspec"))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "name": name,
                "version": ver,
            })
        });

    let json = serde_json::json!({
        "version": ver,
        "archive_url": archive_url,
        "archive_sha256": artifact.checksum_sha256,
        "pubspec": pubspec,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/packages/{name}/versions/{version}.tar.gz -- Download
// ---------------------------------------------------------------------------

async fn download_archive(
    State(state): State<SharedState>,
    Path((repo_key, archive_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let archive_path = archive_path.trim_start_matches('/');

    // Parse: {name}/versions/{version}.tar.gz
    let parts: Vec<&str> = archive_path.splitn(3, '/').collect();
    if parts.len() < 3 || parts[1] != "versions" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid archive path: expected packages/{name}/versions/{version}.tar.gz",
        )
            .into_response());
    }

    let pkg_name = parts[0];
    let version_file = parts[2];

    let version = version_file.strip_suffix(".tar.gz").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid archive path: expected .tar.gz extension",
        )
            .into_response()
    })?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        pkg_name,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package archive not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("packages/{}/versions/{}.tar.gz", pkg_name, version);
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
                let upstream_path = format!("packages/{}/versions/{}.tar.gz", pkg_name, version);
                let vname = pkg_name.to_string();
                let vversion = version.to_string();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &vname, &vversion,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
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

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
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

    let filename = format!("{}-{}.tar.gz", pkg_name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /pub/{repo_key}/api/packages/versions/new -- Get upload URL
// ---------------------------------------------------------------------------

async fn new_upload_url(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "pub")?.user_id;
    let _repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let upload_url = format!("/pub/{}/api/packages/versions/newUpload", repo_key);
    let json = serde_json::json!({
        "url": upload_url,
        "fields": {},
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /pub/{repo_key}/api/packages/versions/newUpload -- Upload package
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (assignment expr); the exempt call is marked inline below (#1608)
async fn upload_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "pub")?.user_id;
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Extract the tar.gz file from multipart form data
    let mut file_bytes: Option<bytes::Bytes> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            file_bytes = Some(field.bytes().await.map_err(|e| {
                // STREAMING-EXEMPT: upload handler buffers one bounded multipart field (capped by DefaultBodyLimit); tracked for incremental-hash put_stream conversion in a later #1608 phase
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read upload: {}", e),
                )
                    .into_response()
            })?);
            break;
        }
    }

    let body = file_bytes.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing 'file' field in upload").into_response()
    })?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package archive").into_response());
    }

    // Extract pubspec.yaml from the tar.gz archive
    let pubspec = extract_pubspec_from_archive(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Pub package: {}", e),
        )
            .into_response()
    })?;

    let pkg_name = &pubspec.name;
    let pkg_version = &pubspec.version;

    if pkg_name.is_empty() || pkg_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package name and version are required",
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let filename = format!("{}-{}.tar.gz", pkg_name, pkg_version);
    let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Package version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage_key = format!("pub/{}/{}/{}", pkg_name, pkg_version, filename);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let pub_metadata = serde_json::json!({
        "pubspec": serde_json::to_value(&pubspec).unwrap_or_default(),
        "filename": filename,
    });

    let size_bytes = body.len() as i64;

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
        pkg_version.to_string(),
        size_bytes,
        computed_sha256,
        "application/gzip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'pub', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pub_metadata,
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
        "Pub upload: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    // Per the Pub spec the upload POST must respond `204 No Content` with a
    // `Location` header pointing at the finalize endpoint. The Dart SDK sets
    // `followRedirects = false` and reads `Location` manually; a 3xx redirect
    // is treated as an unexpected response and the publish aborts (#1997).
    let finish_url = format!("/pub/{}/api/packages/versions/newUploadFinish", repo_key);

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Location", finish_url)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/versions/newUploadFinish -- Finalize
// ---------------------------------------------------------------------------

async fn finalize_upload(
    State(_state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let json = serde_json::json!({
        "success": {
            "message": format!("Successfully uploaded package to repository '{}'.", repo_key),
        },
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract pubspec.yaml from a Pub package tar.gz archive.
fn extract_pubspec_from_archive(data: &[u8]) -> Result<crate::formats::r#pub::PubSpec, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read archive entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "pubspec.yaml" || path.ends_with("/pubspec.yaml") {
            let mut contents = String::new();
            entry
                .read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read pubspec.yaml: {}", e))?;

            let pubspec: crate::formats::r#pub::PubSpec = serde_yaml::from_str(&contents)
                .map_err(|e| format!("Failed to parse pubspec.yaml: {}", e))?;

            return Ok(pubspec);
        }
    }

    Err("pubspec.yaml not found in archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_path_parsing_valid() {
        let archive_path = "my_package/versions/1.0.0.tar.gz";
        let parts: Vec<&str> = archive_path.splitn(3, '/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "my_package");
        assert_eq!(parts[1], "versions");
        assert_eq!(parts[2], "1.0.0.tar.gz");

        let version = parts[2].strip_suffix(".tar.gz");
        assert_eq!(version, Some("1.0.0"));
    }

    #[test]
    fn test_archive_path_parsing_no_tar_gz() {
        let version_file = "1.0.0.zip";
        let result = version_file.strip_suffix(".tar.gz");
        assert_eq!(result, None);
    }

    #[test]
    fn test_archive_path_parsing_too_few_parts() {
        let archive_path = "my_package/1.0.0.tar.gz";
        let parts: Vec<&str> = archive_path.splitn(3, '/').collect();
        assert_eq!(parts.len(), 2);
        // This would be rejected: parts.len() < 3
    }

    #[test]
    fn test_archive_path_wrong_middle_segment() {
        let archive_path = "my_package/other/1.0.0.tar.gz";
        let parts: Vec<&str> = archive_path.splitn(3, '/').collect();
        assert_eq!(parts.len(), 3);
        assert_ne!(parts[1], "versions");
        // This would be rejected: parts[1] != "versions"
    }

    #[test]
    fn test_pub_filename_format() {
        let pkg_name = "my_package";
        let pkg_version = "2.1.0";
        let filename = format!("{}-{}.tar.gz", pkg_name, pkg_version);
        assert_eq!(filename, "my_package-2.1.0.tar.gz");
    }

    #[test]
    fn test_pub_artifact_path_format() {
        let pkg_name = "flutter_utils";
        let pkg_version = "0.5.0";
        let filename = format!("{}-{}.tar.gz", pkg_name, pkg_version);
        let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);
        assert_eq!(
            artifact_path,
            "flutter_utils/0.5.0/flutter_utils-0.5.0.tar.gz"
        );
    }

    #[test]
    fn test_pub_storage_key_format() {
        let pkg_name = "provider";
        let pkg_version = "6.0.0";
        let filename = "provider-6.0.0.tar.gz";
        let storage_key = format!("pub/{}/{}/{}", pkg_name, pkg_version, filename);
        assert_eq!(storage_key, "pub/provider/6.0.0/provider-6.0.0.tar.gz");
    }

    #[test]
    fn test_upload_url_format() {
        let repo_key = "my-pub-repo";
        let upload_url = format!("/pub/{}/api/packages/versions/newUpload", repo_key);
        assert_eq!(
            upload_url,
            "/pub/my-pub-repo/api/packages/versions/newUpload"
        );
    }

    #[test]
    fn test_extract_pubspec_from_empty_archive() {
        let result = extract_pubspec_from_archive(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pubspec_from_invalid_archive() {
        let result = extract_pubspec_from_archive(b"not a valid gzip archive");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_pub_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/api/packages/name"),
            format!("/{k}/api/packages/name/versions/1.0.0"),
            format!("/{k}/packages/name-1.0.0.tar.gz"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}

#[cfg(test)]
mod publish_protocol_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    /// Build a minimal, valid Pub package archive (a gzipped tar containing a
    /// `pubspec.yaml` with the given name/version).
    fn pub_archive(name: &str, version: &str) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let pubspec = format!("name: {}\nversion: {}\n", name, version);
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("pubspec.yaml").unwrap();
        header.set_size(pubspec.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append(&header, pubspec.as_bytes())
            .expect("append pubspec");
        let tar_bytes = tar_builder.into_inner().expect("finish tar");

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    /// Encode a single-field (`file`) multipart/form-data body and return the
    /// `(content_type, body)` pair for the request builder.
    fn multipart_file(archive: &[u8]) -> (String, bytes::Bytes) {
        let boundary = "ak1997boundary";
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"pkg.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(archive);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
        (
            format!("multipart/form-data; boundary={}", boundary),
            bytes::Bytes::from(body),
        )
    }

    // #1997 (DEV-1): the "get upload URL" step MUST be served on HTTP GET.
    // Serving it as POST made the Dart SDK receive 405 and abort with
    // "Invalid server response". After the fix a GET returns 200 with the
    // `{url, fields}` envelope, and a POST to the same path is 405.
    #[tokio::test]
    async fn test_new_upload_url_is_get_not_post() {
        let Some(fx) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };
        let uri = format!("/{}/api/packages/versions/new", fx.repo_key);

        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(app, tdh::get(uri.clone())).await;
        assert_eq!(status, StatusCode::OK, "GET .../versions/new must be 200");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert!(
            json.get("url").is_some(),
            "response must carry an upload url"
        );
        assert!(json.get("fields").is_some(), "response must carry fields");

        // The old POST route must no longer exist.
        let app = fx.router_with_auth(super::router());
        let (status, _) =
            tdh::send(app, tdh::post(uri, "application/json", bytes::Bytes::new())).await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "POST .../versions/new must be 405 after the GET fix"
        );
        fx.teardown().await;
    }

    // #1997 (DEV-2): the multipart upload POST MUST answer 204 No Content with
    // a `Location` header. The Dart SDK sets followRedirects=false and reads
    // Location manually; a 3xx made it treat the response as unexpected. Drive
    // the full handshake and assert 204 + Location, then that the finalize
    // endpoint returns the success envelope.
    #[tokio::test]
    async fn test_upload_returns_204_with_location() {
        let Some(fx) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };
        let archive = pub_archive("ak_test_pkg", "1.2.3");
        let (ct, body) = multipart_file(&archive);

        let upload_uri = format!("/{}/api/packages/versions/newUpload", fx.repo_key);
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(app, tdh::post(upload_uri, &ct, body)).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "upload POST must be 204 No Content per the Pub spec (not a redirect)"
        );

        // Finalize step returns the spec's success envelope.
        let finish_uri = format!("/{}/api/packages/versions/newUploadFinish", fx.repo_key);
        let app = fx.router_with_auth(super::router());
        let (status, fbody) = tdh::send(app, tdh::get(finish_uri)).await;
        assert_eq!(status, StatusCode::OK, "finalize must be 200");
        let json: serde_json::Value = serde_json::from_slice(&fbody).expect("json body");
        assert!(
            json.get("success").and_then(|s| s.get("message")).is_some(),
            "finalize must return {{\"success\": {{\"message\": ...}}}}"
        );
        fx.teardown().await;
    }
}
