//! SBT/Ivy repository API handlers.
//!
//! Implements the endpoints required for SBT's Ivy-style artifact resolution.
//!
//! Routes are mounted at `/ivy/{repo_key}/...`:
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/ivys/ivy.xml               - Ivy descriptor
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/jars/{name}-{version}.jar  - Download JAR
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/srcs/{name}-{version}-sources.jar - Sources
//!   GET  /ivy/{repo_key}/{org}/{name}/{version}/docs/{name}-{version}-javadoc.jar - Javadoc
//!   PUT  /ivy/{repo_key}/*path                                             - Upload artifact
//!   HEAD /ivy/{repo_key}/*path                                             - Check existence

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::sbt::SbtHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Single wildcard handles all Ivy layout paths:
        //   GET  — download artifact (ivy.xml, jars, srcs, docs, etc.)
        //   PUT  — upload artifact (auth required)
        //   HEAD — check artifact existence
        .route(
            "/:repo_key/*path",
            get(download_by_path)
                .put(upload_artifact)
                .head(check_exists),
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
            .header("WWW-Authenticate", "Basic realm=\"sbt\"")
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
                .header("WWW-Authenticate", "Basic realm=\"sbt\"")
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

async fn resolve_sbt_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "sbt" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an SBT/Ivy repository (format: {})",
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
// GET /ivy/{repo_key}/*path — Download artifact by path
// ---------------------------------------------------------------------------

async fn download_by_path(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, storage_key, size_bytes, content_type
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
    })?;

    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        artifact_path,
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
                let path_clone = artifact_path.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    artifact_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(&db, &state, member_id, &storage_path, &path)
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

            return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
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

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}\"",
                artifact_path.rsplit('/').next().unwrap_or(artifact_path)
            ),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /ivy/{repo_key}/*path — Upload artifact (auth required)
// ---------------------------------------------------------------------------

async fn upload_artifact(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = artifact_path.trim_start_matches('/').to_string();

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty artifact file").into_response());
    }

    // Validate path via format handler
    let path_info = SbtHandler::parse_path(&artifact_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid SBT path: {}", e)).into_response()
    })?;

    let artifact_name = if path_info.is_ivy_descriptor {
        format!("{}/{}", path_info.org, path_info.module)
    } else {
        path_info
            .artifact
            .clone()
            .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
    };

    let artifact_version = path_info.revision.clone().unwrap_or_default();

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
        return Err((StatusCode::CONFLICT, "Artifact already exists at this path").into_response());
    }

    // Determine content type
    let content_type = if path_info.is_ivy_descriptor {
        "application/xml"
    } else {
        "application/java-archive"
    };

    // Store the file
    let storage_key = format!("sbt/{}", artifact_path);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let sbt_metadata = serde_json::json!({
        "org": path_info.org,
        "module": path_info.module,
        "revision": path_info.revision,
        "artifact": path_info.artifact,
        "ext": path_info.ext,
        "is_ivy_descriptor": path_info.is_ivy_descriptor,
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
        artifact_name,
        artifact_version,
        size_bytes,
        computed_sha256,
        content_type,
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
        VALUES ($1, 'sbt', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        sbt_metadata,
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
        "SBT upload: {} {} to repo {}",
        artifact_path, artifact_version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Successfully uploaded SBT artifact"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// HEAD /ivy/{repo_key}/*path — Check artifact existence
// ---------------------------------------------------------------------------

async fn check_exists(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_sbt_repo(&state.db, &repo_key).await?;

    let artifact_path = artifact_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT size_bytes, content_type
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
    .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let content_type = if artifact.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &artifact.content_type
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::empty())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use base64::Engine;

    // -----------------------------------------------------------------------
    // extract_credentials — Bearer token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer_uppercase() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer mytoken123".parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "mytoken123".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bearer mytoken456".parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "mytoken456".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // extract_credentials — Basic auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_basic_auth() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:password123");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Basic {}", encoded).parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("admin".to_string(), "password123".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic_auth_lowercase() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("basic {}", encoded).parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_auth_with_colon_in_password() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass:word:extra");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Basic {}", encoded).parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("user".to_string(), "pass:word:extra".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic_auth_empty_password() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Basic {}", encoded).parse().unwrap());
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_credentials — no auth / invalid auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        let result = extract_credentials(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_credentials_unknown_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Digest abc123".parse().unwrap());
        let result = extract_credentials(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic !!!not-base64!!!".parse().unwrap());
        let result = extract_credentials(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_credentials_basic_no_colon() {
        // Valid base64 but no colon separator => splitn returns only one part
        let encoded = base64::engine::general_purpose::STANDARD.encode("useronly");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Basic {}", encoded).parse().unwrap());
        let result = extract_credentials(&headers);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Content type determination logic (from upload_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_ivy_descriptor() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: None,
            ext: Some("xml".to_string()),
            is_ivy_descriptor: true,
        };
        let content_type = if path_info.is_ivy_descriptor {
            "application/xml"
        } else {
            "application/java-archive"
        };
        assert_eq!(content_type, "application/xml");
    }

    #[test]
    fn test_content_type_jar() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: Some("mylib-1.0".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let content_type = if path_info.is_ivy_descriptor {
            "application/xml"
        } else {
            "application/java-archive"
        };
        assert_eq!(content_type, "application/java-archive");
    }

    // -----------------------------------------------------------------------
    // Artifact name construction logic (from upload_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_name_ivy_descriptor() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.example".to_string(),
            module: "mylib".to_string(),
            revision: Some("1.0".to_string()),
            artifact: None,
            ext: Some("xml".to_string()),
            is_ivy_descriptor: true,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "com.example/mylib");
    }

    #[test]
    fn test_artifact_name_with_artifact_field() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "org.apache".to_string(),
            module: "commons".to_string(),
            revision: Some("2.0".to_string()),
            artifact: Some("commons-2.0".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "commons-2.0");
    }

    #[test]
    fn test_artifact_name_no_artifact_field() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "io.spray".to_string(),
            module: "spray-json".to_string(),
            revision: Some("1.3.6".to_string()),
            artifact: None,
            ext: None,
            is_ivy_descriptor: false,
        };
        let artifact_name = if path_info.is_ivy_descriptor {
            format!("{}/{}", path_info.org, path_info.module)
        } else {
            path_info
                .artifact
                .clone()
                .unwrap_or_else(|| format!("{}/{}", path_info.org, path_info.module))
        };
        assert_eq!(artifact_name, "io.spray/spray-json");
    }

    // -----------------------------------------------------------------------
    // Storage key construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_key_format() {
        let artifact_path = "com.example/mylib/1.0/jars/mylib-1.0.jar";
        let storage_key = format!("sbt/{}", artifact_path);
        assert_eq!(storage_key, "sbt/com.example/mylib/1.0/jars/mylib-1.0.jar");
    }

    // -----------------------------------------------------------------------
    // Content-Disposition filename extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_disposition_filename() {
        let path = "com.example/mylib/1.0/jars/mylib-1.0.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "mylib-1.0.jar");
    }

    #[test]
    fn test_content_disposition_filename_no_slash() {
        let path = "mylib.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "mylib.jar");
    }

    #[test]
    fn test_content_disposition_filename_deeply_nested() {
        let path = "org/example/subgroup/lib/1.0/jars/lib-1.0.jar";
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert_eq!(filename, "lib-1.0.jar");
    }

    // -----------------------------------------------------------------------
    // Content type fallback (from download_by_path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_fallback_empty() {
        let content_type_raw = "";
        let content_type = if content_type_raw.is_empty() {
            "application/octet-stream"
        } else {
            content_type_raw
        };
        assert_eq!(content_type, "application/octet-stream");
    }

    #[test]
    fn test_content_type_no_fallback() {
        let content_type_raw = "application/xml";
        let content_type = if content_type_raw.is_empty() {
            "application/octet-stream"
        } else {
            content_type_raw
        };
        assert_eq!(content_type, "application/xml");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (from upload_artifact)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        use sha2::{Digest, Sha256};
        let body = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let computed = format!("{:x}", hasher.finalize());
        assert_eq!(
            computed,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_empty_body() {
        use sha2::{Digest, Sha256};
        let body = b"";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let computed = format!("{:x}", hasher.finalize());
        assert_eq!(
            computed,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // -----------------------------------------------------------------------
    // SBT metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbt_metadata_json() {
        let path_info = crate::formats::sbt::SbtPathInfo {
            org: "com.typesafe".to_string(),
            module: "config".to_string(),
            revision: Some("1.4.2".to_string()),
            artifact: Some("config-1.4.2".to_string()),
            ext: Some("jar".to_string()),
            is_ivy_descriptor: false,
        };
        let metadata = serde_json::json!({
            "org": path_info.org,
            "module": path_info.module,
            "revision": path_info.revision,
            "artifact": path_info.artifact,
            "ext": path_info.ext,
            "is_ivy_descriptor": path_info.is_ivy_descriptor,
        });
        assert_eq!(metadata["org"], "com.typesafe");
        assert_eq!(metadata["module"], "config");
        assert_eq!(metadata["revision"], "1.4.2");
        assert_eq!(metadata["artifact"], "config-1.4.2");
        assert_eq!(metadata["ext"], "jar");
        assert_eq!(metadata["is_ivy_descriptor"], false);
    }
}
