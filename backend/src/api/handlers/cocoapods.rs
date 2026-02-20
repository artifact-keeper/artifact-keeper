//! CocoaPods Spec Repo API handlers.
//!
//! Implements the endpoints required for CocoaPods pod install and pod push.
//!
//! Routes are mounted at `/cocoapods/{repo_key}/...`:
//!   GET  /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json - Get podspec
//!   GET  /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz              - Download pod archive
//!   POST /cocoapods/{repo_key}/pods                                      - Push pod (auth required)
//!   GET  /cocoapods/{repo_key}/all_specs                                 - List all specs

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
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::cocoapods::CocoaPodsHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Push pod
        .route("/:repo_key/pods", post(push_pod))
        // List all specs
        .route("/:repo_key/all_specs", get(all_specs))
        // Get podspec
        .route(
            "/:repo_key/Specs/:name/:version/*podspec_file",
            get(get_podspec),
        )
        // Download pod archive
        .route("/:repo_key/pods/*pod_file", get(download_pod))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    // Try Basic auth
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

/// Authenticate via Basic auth or Bearer token, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"cocoapods\"")
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
                .header("WWW-Authenticate", "Basic realm=\"cocoapods\"")
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

async fn resolve_cocoapods_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "cocoapods" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a CocoaPods repository (format: {})",
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
// GET /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json
// ---------------------------------------------------------------------------

async fn get_podspec(
    State(state): State<SharedState>,
    Path((repo_key, name, version, podspec_file)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let podspec_file = podspec_file.trim_start_matches('/');

    // Validate via the format handler
    let full_path = format!("Specs/{}/{}/{}", name, version, podspec_file);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find the artifact
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        path_info.name,
        path_info.version
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Podspec not found").into_response())?;

    // Return the podspec from metadata if available, otherwise read from storage
    let podspec_from_meta: Option<String> = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("podspec"))
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    if let Some(podspec_json) = podspec_from_meta {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(podspec_json))
            .unwrap());
    }

    // Fall back to reading the podspec file from storage
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        path_info.name, path_info.version, path_info.name
    );
    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&podspec_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz — Download pod archive
// ---------------------------------------------------------------------------

async fn download_pod(
    State(state): State<SharedState>,
    Path((repo_key, pod_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let filename = pod_file.trim_start_matches('/');

    // Parse the pod path to extract name and version
    let full_path = format!("pods/{}", filename);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find artifact by name and version
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
        path_info.name,
        path_info.version
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Pod not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("pods/{}", filename);
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
                let upstream_path = format!("pods/{}", filename);
                let vname = path_info.name.clone();
                let vversion = path_info.version.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                &state,
                                member_id,
                                &storage_path,
                                &vname,
                                &vversion,
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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /cocoapods/{repo_key}/pods — Push pod (body is tar.gz with podspec)
// ---------------------------------------------------------------------------

async fn push_pod(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty pod archive").into_response());
    }

    // Try to extract podspec from the archive body.
    // The body should contain a tar.gz with a podspec.json inside.
    let podspec = extract_podspec_from_archive(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid pod archive: {}", e),
        )
            .into_response()
    })?;

    let pod_name = &podspec.name;
    let pod_version = &podspec.version;

    if pod_name.is_empty() || pod_version.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Pod name and version are required").into_response());
    }

    let filename = format!("{}-{}.tar.gz", pod_name, pod_version);
    let artifact_path = format!("{}/{}/{}", pod_name, pod_version, filename);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

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
        return Err((StatusCode::CONFLICT, "Pod version already exists").into_response());
    }

    // Store the pod archive
    let storage_key = format!("cocoapods/{}/{}/{}", pod_name, pod_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Also store the podspec JSON separately for direct retrieval
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        pod_name, pod_version, pod_name
    );
    let podspec_json = serde_json::to_vec(&podspec).unwrap_or_default();
    storage
        .put(&podspec_key, Bytes::from(podspec_json))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    // Build metadata JSON
    let pod_metadata = serde_json::json!({
        "podspec": serde_json::to_value(&podspec).unwrap_or_default(),
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
        pod_name,
        pod_version.to_string(),
        size_bytes,
        computed_sha256,
        "application/gzip",
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
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'cocoapods', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pod_metadata,
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
        "CocoaPods push: {} {} ({}) to repo {}",
        pod_name, pod_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully registered pod"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/all_specs — List all specs (JSON)
// ---------------------------------------------------------------------------

async fn all_specs(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
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

    // Group versions by pod name
    let mut specs: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for a in &artifacts {
        let name = a.name.clone();
        let version = a.version.clone().unwrap_or_default();

        let summary = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("podspec"))
            .and_then(|ps| ps.get("summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let version_info = serde_json::json!({
            "version": version,
            "summary": summary,
        });

        specs.entry(name).or_default().push(version_info);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&specs).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::formats::cocoapods::PodSpec;

/// Extract a podspec.json from a tar.gz archive.
///
/// Scans the archive entries for any file ending in `.podspec.json` and
/// deserializes it into a PodSpec.
fn extract_podspec_from_archive(data: &[u8]) -> Result<PodSpec, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;

        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path.ends_with(".podspec.json") {
            let mut contents = Vec::new();
            entry
                .read_to_end(&mut contents)
                .map_err(|e| format!("Failed to read podspec: {}", e))?;

            let podspec: PodSpec = serde_json::from_slice(&contents)
                .map_err(|e| format!("Invalid podspec JSON: {}", e))?;

            return Ok(podspec);
        }
    }

    Err("No .podspec.json found in archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::cocoapods::PodSpec;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the filename for a CocoaPods archive.
    fn build_cocoapods_filename(name: &str, version: &str) -> String {
        format!("{}-{}.tar.gz", name, version)
    }

    /// Build the artifact path for a CocoaPods package.
    fn build_cocoapods_artifact_path(name: &str, version: &str) -> String {
        let filename = build_cocoapods_filename(name, version);
        format!("{}/{}/{}", name, version, filename)
    }

    /// Build the storage key for a CocoaPods archive.
    fn build_cocoapods_storage_key(name: &str, version: &str) -> String {
        let filename = build_cocoapods_filename(name, version);
        format!("cocoapods/{}/{}/{}", name, version, filename)
    }

    /// Build the storage key for a CocoaPods podspec JSON file.
    fn build_cocoapods_podspec_key(name: &str, version: &str) -> String {
        format!("cocoapods/{}/{}/{}.podspec.json", name, version, name)
    }

    /// Build the metadata JSON for a published pod.
    fn build_cocoapods_metadata(podspec: &PodSpec, filename: &str) -> serde_json::Value {
        serde_json::json!({
            "podspec": serde_json::to_value(podspec).unwrap_or_default(),
            "filename": filename,
        })
    }

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer cocoapods-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "cocoapods-token".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-pod-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "my-pod-token".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("dev:pw");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("dev".to_string(), "pw".to_string())));
    }

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!"),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    // -----------------------------------------------------------------------
    // extract_podspec_from_archive
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_podspec_from_archive_empty() {
        let result = extract_podspec_from_archive(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_podspec_from_archive_invalid_data() {
        let result = extract_podspec_from_archive(b"not a gzip archive");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_podspec_from_archive_no_podspec() {
        // Create a valid tar.gz with no .podspec.json file
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let data = b"random content";
            let mut header = tar::Header::new_gnu();
            header.set_path("README.md").unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let compressed = gz.finish().unwrap();

        let result = extract_podspec_from_archive(&compressed);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No .podspec.json found"));
    }

    #[test]
    fn test_extract_podspec_from_archive_valid() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let podspec_json = serde_json::json!({
            "name": "Alamofire",
            "version": "5.8.0",
            "summary": "HTTP Networking in Swift",
            "homepage": "https://github.com/Alamofire/Alamofire",
        });
        let podspec_bytes = serde_json::to_vec(&podspec_json).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("Alamofire.podspec.json").unwrap();
            header.set_size(podspec_bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, &podspec_bytes[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &tar_data).unwrap();
        let compressed = gz.finish().unwrap();

        let result = extract_podspec_from_archive(&compressed);
        assert!(result.is_ok());
        let podspec = result.unwrap();
        assert_eq!(podspec.name, "Alamofire");
        assert_eq!(podspec.version, "5.8.0");
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_filename() {
        assert_eq!(
            build_cocoapods_filename("Alamofire", "5.8.0"),
            "Alamofire-5.8.0.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_filename_prerelease() {
        assert_eq!(
            build_cocoapods_filename("Moya", "15.0.0-beta.1"),
            "Moya-15.0.0-beta.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_filename_ends_with_tar_gz() {
        let f = build_cocoapods_filename("SnapKit", "5.7.1");
        assert!(f.ends_with(".tar.gz"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_artifact_path() {
        assert_eq!(
            build_cocoapods_artifact_path("Moya", "15.0.0"),
            "Moya/15.0.0/Moya-15.0.0.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_artifact_path_simple() {
        assert_eq!(
            build_cocoapods_artifact_path("SnapKit", "5.7.1"),
            "SnapKit/5.7.1/SnapKit-5.7.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_artifact_path_contains_name() {
        let path = build_cocoapods_artifact_path("AFNetworking", "4.0.0");
        assert!(path.starts_with("AFNetworking/"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_storage_key() {
        assert_eq!(
            build_cocoapods_storage_key("SnapKit", "5.7.1"),
            "cocoapods/SnapKit/5.7.1/SnapKit-5.7.1.tar.gz"
        );
    }

    #[test]
    fn test_build_cocoapods_storage_key_starts_with_cocoapods() {
        let key = build_cocoapods_storage_key("Alamofire", "5.8.0");
        assert!(key.starts_with("cocoapods/"));
    }

    #[test]
    fn test_build_cocoapods_storage_key_ends_with_tar_gz() {
        let key = build_cocoapods_storage_key("Moya", "15.0.0");
        assert!(key.ends_with(".tar.gz"));
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_podspec_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_podspec_key() {
        assert_eq!(
            build_cocoapods_podspec_key("AFNetworking", "4.0.0"),
            "cocoapods/AFNetworking/4.0.0/AFNetworking.podspec.json"
        );
    }

    #[test]
    fn test_build_cocoapods_podspec_key_ends_with_podspec_json() {
        let key = build_cocoapods_podspec_key("Alamofire", "5.8.0");
        assert!(key.ends_with(".podspec.json"));
    }

    #[test]
    fn test_build_cocoapods_podspec_key_contains_name_twice() {
        let key = build_cocoapods_podspec_key("SnapKit", "5.7.1");
        // The name appears in both the directory path and the filename
        assert_eq!(key.matches("SnapKit").count(), 2); // cocoapods/SnapKit/5.7.1/SnapKit.podspec.json
    }

    // -----------------------------------------------------------------------
    // build_cocoapods_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cocoapods_metadata() {
        let podspec = PodSpec {
            name: "Alamofire".to_string(),
            version: "5.8.0".to_string(),
            summary: Some("HTTP Networking in Swift".to_string()),
            homepage: Some("https://github.com/Alamofire/Alamofire".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
        };
        let meta = build_cocoapods_metadata(&podspec, "Alamofire-5.8.0.tar.gz");
        assert_eq!(meta["filename"], "Alamofire-5.8.0.tar.gz");
        assert!(meta["podspec"].is_object());
        assert_eq!(meta["podspec"]["name"], "Alamofire");
        assert_eq!(meta["podspec"]["version"], "5.8.0");
    }

    #[test]
    fn test_build_cocoapods_metadata_has_two_keys() {
        let podspec = PodSpec {
            name: "Moya".to_string(),
            version: "15.0.0".to_string(),
            summary: Some("Network abstraction layer".to_string()),
            homepage: Some("https://github.com/Moya/Moya".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
        };
        let meta = build_cocoapods_metadata(&podspec, "Moya-15.0.0.tar.gz");
        assert_eq!(meta.as_object().unwrap().len(), 2);
    }

    #[test]
    fn test_build_cocoapods_metadata_podspec_fields() {
        let podspec = PodSpec {
            name: "RxSwift".to_string(),
            version: "6.6.0".to_string(),
            summary: Some("Reactive Programming in Swift".to_string()),
            homepage: Some("https://github.com/ReactiveX/RxSwift".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
        };
        let meta = build_cocoapods_metadata(&podspec, "RxSwift-6.6.0.tar.gz");
        assert_eq!(meta["podspec"]["summary"], "Reactive Programming in Swift");
        assert_eq!(
            meta["podspec"]["homepage"],
            "https://github.com/ReactiveX/RxSwift"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"pod content");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            storage_path: "/data/cocoapods".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.id, id);
        assert_eq!(repo.repo_type, "hosted");
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/cache/cocoapods".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://cdn.cocoapods.org/".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://cdn.cocoapods.org/")
        );
    }
}
