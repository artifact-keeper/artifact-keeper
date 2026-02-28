//! Maven 2 Repository Layout handlers.
//!
//! Implements the path-based Maven repository layout for `mvn deploy` and
//! `mvn dependency:resolve`.
//!
//! Routes are mounted at `/maven/{repo_key}/...`:
//!   GET  /maven/{repo_key}/*path — Download artifact, metadata, or checksum
//!   PUT  /maven/{repo_key}/*path — Upload artifact (mvn deploy)

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::maven::{generate_metadata_xml, MavenHandler};
use crate::services::auth_service::AuthService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/*path", get(download).put(upload))
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
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"maven\"")
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
                .header("WWW-Authenticate", "Basic realm=\"maven\"")
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

async fn resolve_maven_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "maven" && fmt != "gradle" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Maven repository (format: {})",
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
// Path helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pure (non-async) helper functions for testability
// ---------------------------------------------------------------------------

/// Determine if a Maven path is for metadata (groupId/artifactId level, no version).
/// Returns (groupId, artifactId) if the path ends with maven-metadata.xml
fn parse_metadata_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Minimum: groupSegment/artifactId/maven-metadata.xml
    if parts.len() < 3 {
        return None;
    }
    let filename = parts[parts.len() - 1];
    if filename != "maven-metadata.xml" {
        return None;
    }
    let artifact_id = parts[parts.len() - 2].to_string();
    let group_id = parts[..parts.len() - 2].join(".");
    Some((group_id, artifact_id))
}

/// Check if a path is a checksum request. Returns the base path and checksum type.
fn parse_checksum_path(path: &str) -> Option<(&str, ChecksumType)> {
    if let Some(base) = path.strip_suffix(".sha1") {
        Some((base, ChecksumType::Sha1))
    } else if let Some(base) = path.strip_suffix(".md5") {
        Some((base, ChecksumType::Md5))
    } else if let Some(base) = path.strip_suffix(".sha256") {
        Some((base, ChecksumType::Sha256))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum ChecksumType {
    Md5,
    Sha1,
    Sha256,
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".pom") || path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".jar") || path.ends_with(".war") {
        "application/java-archive"
    } else {
        "application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// GET /maven/{repo_key}/*path — Download artifact/metadata/checksum
// ---------------------------------------------------------------------------

async fn download(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;

    // 1. Check if this is a checksum request for metadata
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        if let Some((group_id, artifact_id)) = parse_metadata_path(base_path) {
            let xml =
                generate_metadata_for_artifact(&state.db, repo.id, &group_id, &artifact_id).await?;
            let checksum = compute_checksum(xml.as_bytes(), checksum_type);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(checksum))
                .unwrap());
        }
    }

    // 2. Check if this is a maven-metadata.xml request
    if let Some((group_id, artifact_id)) = parse_metadata_path(&path) {
        let xml =
            generate_metadata_for_artifact(&state.db, repo.id, &group_id, &artifact_id).await?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/xml")
            .header(CONTENT_LENGTH, xml.len().to_string())
            .body(Body::from(xml))
            .unwrap());
    }

    // 3. Check if this is a checksum request for a stored file
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        // First try to find a stored checksum file
        let checksum_storage_key = format!("maven/{}", path);
        let storage = state.storage_for_repo(&repo.storage_path);
        if let Ok(content) = storage.get(&checksum_storage_key).await {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(content))
                .unwrap());
        }

        // Otherwise compute from the artifact
        return serve_computed_checksum(
            &state,
            repo.id,
            &repo.storage_path,
            base_path,
            checksum_type,
        )
        .await;
    }

    // 4. Serve the artifact file
    serve_artifact(&state, &repo, &repo_key, &path).await
}

async fn generate_metadata_for_artifact(
    db: &PgPool,
    repo_id: uuid::Uuid,
    group_id: &str,
    artifact_id: &str,
) -> Result<String, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT a.version as "version?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'maven'
          AND am.metadata->>'groupId' = $2
          AND am.metadata->>'artifactId' = $3
          AND a.version IS NOT NULL
        ORDER BY a.version
        "#,
        repo_id,
        group_id,
        artifact_id,
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

    let versions: Vec<String> = rows.into_iter().filter_map(|r| r.version).collect();

    if versions.is_empty() {
        return Err((StatusCode::NOT_FOUND, "No versions found").into_response());
    }

    let latest = versions.last().unwrap().clone();
    let xml = generate_metadata_xml(group_id, artifact_id, &versions, &latest, Some(&latest));

    Ok(xml)
}

async fn serve_artifact(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    path: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, size_bytes, checksum_sha256, content_type, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        path,
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

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let (content, content_type) =
                        proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, path)
                            .await?;

                    let ct =
                        content_type.unwrap_or_else(|| content_type_for_path(path).to_string());

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let artifact_path = path.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let state = state.clone();
                        let artifact_path = artifact_path.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db,
                                &state,
                                member_id,
                                &storage_path,
                                &artifact_path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                let ct = content_type.unwrap_or_else(|| content_type_for_path(path).to_string());

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err((StatusCode::NOT_FOUND, "File not found").into_response());
        }
    };

    let storage = state.storage_for_repo(&repo.storage_path);
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

    let ct = content_type_for_path(path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

async fn serve_computed_checksum(
    state: &SharedState,
    repo_id: uuid::Uuid,
    storage_path: &str,
    base_path: &str,
    checksum_type: ChecksumType,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo_id,
        base_path,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response())?;

    // For SHA-256 we already have it stored
    let checksum = match checksum_type {
        ChecksumType::Sha256 => artifact.checksum_sha256,
        _ => {
            let storage = state.storage_for_repo(storage_path);
            let content = storage.get(&artifact.storage_key).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Storage error: {}", e),
                )
                    .into_response()
            })?;
            compute_checksum(&content, checksum_type)
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(checksum))
        .unwrap())
}

fn compute_checksum(data: &[u8], checksum_type: ChecksumType) -> String {
    match checksum_type {
        ChecksumType::Md5 => {
            use md5::Md5;
            let mut hasher = Md5::new();
            md5::Digest::update(&mut hasher, data);
            format!("{:x}", md5::Digest::finalize(hasher))
        }
        ChecksumType::Sha1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            sha1::Digest::update(&mut hasher, data);
            format!("{:x}", sha1::Digest::finalize(hasher))
        }
        ChecksumType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
    }
}

// ---------------------------------------------------------------------------
// PUT /maven/{repo_key}/*path — Upload artifact
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let storage_key = format!("maven/{}", path);
    let storage = state.storage_for_repo(&repo.storage_path);

    // If this is a checksum file (.sha1, .md5, .sha256), just store it and return
    if parse_checksum_path(&path).is_some() {
        storage.put(&storage_key, body).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // If this is a maven-metadata.xml upload, just store it
    if MavenHandler::is_metadata(&path) {
        storage.put(&storage_key, body).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // Parse Maven coordinates from the path
    let coords = MavenHandler::parse_coordinates(&path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Maven path: {}", e),
        )
            .into_response()
    })?;

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum_sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let ct = content_type_for_path(&path);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        path,
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
        if !coords.version.contains("SNAPSHOT") {
            return Err((StatusCode::CONFLICT, "Artifact already exists").into_response());
        }
        // Hard-delete old SNAPSHOT version so the UNIQUE(repository_id, path)
        // constraint allows re-insert. Safe because SNAPSHOTs are mutable by design.
        let _ = sqlx::query!(
            "DELETE FROM artifacts WHERE repository_id = $1 AND path = $2",
            repo.id,
            path,
        )
        .execute(&state.db)
        .await;
    }

    // Store file
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let handler = MavenHandler::new();
    let metadata = crate::formats::FormatHandler::parse_metadata(&handler, &path, &body)
        .await
        .unwrap_or_else(|_| {
            serde_json::json!({
                "groupId": coords.group_id,
                "artifactId": coords.artifact_id,
                "version": coords.version,
                "extension": coords.extension,
            })
        });

    let name = coords.artifact_id.clone();

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
        path,
        name,
        coords.version,
        size_bytes,
        checksum_sha256,
        ct,
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
        VALUES ($1, 'maven', $2)
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
        "Maven upload: {}:{}:{} ({}) to repo {}",
        coords.group_id, coords.artifact_id, coords.version, coords.extension, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("deploy:maven-pass");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("deploy".to_string(), "maven-pass".to_string()))
        );
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pw");
        let value = format!("basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pw".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_with_colon_in_password() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p@ss:w0rd");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "p@ss:w0rd".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_basic_credentials(&headers), None);
    }

    #[test]
    fn test_extract_basic_credentials_bearer_not_matched() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token"),
        );
        assert_eq!(extract_basic_credentials(&headers), None);
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!bad-base64!!!"),
        );
        assert_eq!(extract_basic_credentials(&headers), None);
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert_eq!(extract_basic_credentials(&headers), None);
    }

    // -----------------------------------------------------------------------
    // parse_metadata_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_path_valid_simple() {
        let result = parse_metadata_path("com/example/my-lib/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.example".to_string(), "my-lib".to_string()))
        );
    }

    #[test]
    fn test_parse_metadata_path_deep_group() {
        let result = parse_metadata_path("org/apache/commons/commons-lang3/maven-metadata.xml");
        assert_eq!(
            result,
            Some((
                "org.apache.commons".to_string(),
                "commons-lang3".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_metadata_path_leading_slash() {
        let result = parse_metadata_path("/com/google/guava/guava/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.google.guava".to_string(), "guava".to_string()))
        );
    }

    #[test]
    fn test_parse_metadata_path_not_metadata() {
        let result = parse_metadata_path("com/example/my-lib/1.0.0/my-lib-1.0.0.jar");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_too_short() {
        let result = parse_metadata_path("maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_two_parts_only() {
        // groupSegment/artifactId/maven-metadata.xml minimum
        let result = parse_metadata_path("com/my-lib/maven-metadata.xml");
        assert_eq!(result, Some(("com".to_string(), "my-lib".to_string())));
    }

    // -----------------------------------------------------------------------
    // parse_checksum_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_checksum_path_sha1() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.sha1");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(matches!(ct, ChecksumType::Sha1));
    }

    #[test]
    fn test_parse_checksum_path_md5() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.md5");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(matches!(ct, ChecksumType::Md5));
    }

    #[test]
    fn test_parse_checksum_path_sha256() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.pom.sha256");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.pom");
        assert!(matches!(ct, ChecksumType::Sha256));
    }

    #[test]
    fn test_parse_checksum_path_no_checksum_suffix() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_checksum_metadata_sha1() {
        let result = parse_checksum_path("com/example/lib/maven-metadata.xml.sha1");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/lib/maven-metadata.xml");
        assert!(matches!(ct, ChecksumType::Sha1));
    }

    // -----------------------------------------------------------------------
    // content_type_for_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_pom() {
        assert_eq!(content_type_for_path("artifact.pom"), "application/xml");
    }

    #[test]
    fn test_content_type_xml() {
        assert_eq!(
            content_type_for_path("maven-metadata.xml"),
            "application/xml"
        );
    }

    #[test]
    fn test_content_type_jar() {
        assert_eq!(
            content_type_for_path("my-lib-1.0.jar"),
            "application/java-archive"
        );
    }

    #[test]
    fn test_content_type_war() {
        assert_eq!(
            content_type_for_path("webapp-1.0.war"),
            "application/java-archive"
        );
    }

    #[test]
    fn test_content_type_other() {
        assert_eq!(
            content_type_for_path("artifact.tar.gz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_txt() {
        assert_eq!(
            content_type_for_path("notes.txt"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // compute_checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_checksum_sha256() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Sha256);
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify determinism
        let result2 = compute_checksum(data, ChecksumType::Sha256);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_compute_checksum_sha1() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Sha1);
        assert_eq!(result.len(), 40); // SHA-1 produces 40 hex chars
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_checksum_md5() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Md5);
        assert_eq!(result.len(), 32); // MD5 produces 32 hex chars
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_checksum_empty_data() {
        let data: &[u8] = b"";
        let sha256 = compute_checksum(data, ChecksumType::Sha256);
        let sha1 = compute_checksum(data, ChecksumType::Sha1);
        let md5 = compute_checksum(data, ChecksumType::Md5);

        // Well-known hashes for empty data
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_compute_checksum_different_types_differ() {
        let data = b"test";
        let sha256 = compute_checksum(data, ChecksumType::Sha256);
        let sha1 = compute_checksum(data, ChecksumType::Sha1);
        let md5 = compute_checksum(data, ChecksumType::Md5);

        assert_ne!(sha256, sha1);
        assert_ne!(sha256, md5);
        assert_ne!(sha1, md5);
    }

    // -----------------------------------------------------------------------
    // RepoInfo
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // build_maven_storage_key
    // -----------------------------------------------------------------------

    /// Build the Maven storage key from a raw path.
    fn build_maven_storage_key(path: &str) -> String {
        format!("maven/{}", path)
    }

    #[test]
    fn test_build_maven_storage_key_jar() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/1.0/lib-1.0.jar"),
            "maven/com/example/lib/1.0/lib-1.0.jar"
        );
    }

    #[test]
    fn test_build_maven_storage_key_pom() {
        assert_eq!(
            build_maven_storage_key(
                "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
            ),
            "maven/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
        );
    }

    #[test]
    fn test_build_maven_storage_key_starts_with_maven() {
        let key = build_maven_storage_key("com/example/lib.jar");
        assert!(key.starts_with("maven/"));
    }

    #[test]
    fn test_build_maven_storage_key_metadata() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/maven-metadata.xml"),
            "maven/com/example/lib/maven-metadata.xml"
        );
    }

    #[test]
    fn test_build_maven_storage_key_checksum() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/1.0/lib-1.0.jar.sha1"),
            "maven/com/example/lib/1.0/lib-1.0.jar.sha1"
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            storage_path: "/data/maven".to_string(),
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
            storage_path: "/cache/maven".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo1.maven.org/maven2".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://repo1.maven.org/maven2")
        );
    }
}
