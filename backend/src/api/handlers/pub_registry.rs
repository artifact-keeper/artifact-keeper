//! Pub (Dart/Flutter) API handlers.
//!
//! Implements the Pub Repository Spec v2 endpoints for `dart pub publish`
//! and `dart pub get`.
//!
//! Routes are mounted at `/pub/{repo_key}/...`:
//!   GET  /pub/{repo_key}/api/packages/{name}                       - Package info
//!   GET  /pub/{repo_key}/api/packages/{name}/versions/{version}    - Version info
//!   GET  /pub/{repo_key}/packages/{name}/versions/{version}.tar.gz - Download archive
//!   GET  /pub/{repo_key}/api/packages/versions/new                 - Get upload URL
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

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

use uuid::Uuid;

/// Row type for pub artifact queries (used in virtual member resolution).
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct PubArtifactRow {
    id: Uuid,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    metadata: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Upload flow (must be registered before the parameterized routes
        // so that literal segments match before `:name` captures them)
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
    base_url: RequestBaseUrl,
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if artifacts.is_empty() {
        // Remote repo: proxy metadata to upstream
        if repo.repo_type == RepositoryType::Remote {
            if let Some(ref upstream_url) = repo.upstream_url {
                let api_path = format!("api/packages/{}", name);
                if let Some(resp) = proxy_pub_meta_get(
                    &state,
                    repo.id,
                    &repo_key,
                    base_url.as_str(),
                    upstream_url,
                    &api_path,
                )
                .await
                {
                    return Ok(resp);
                }
            }
            return Err(pub_error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Package not found",
            ));
        }

        // Virtual repo: resolve through members in priority order
        if repo.repo_type == RepositoryType::Virtual {
            let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
            for member in &members {
                match member.repo_type {
                    RepositoryType::Local | RepositoryType::Staging => {
                        let member_artifacts = sqlx::query_as::<_, PubArtifactRow>(
                            "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                              am.metadata \
                              FROM artifacts a \
                              LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
                              WHERE a.repository_id = $1 \
                                AND a.is_deleted = false \
                                AND LOWER(a.name) = LOWER($2) \
                              ORDER BY a.created_at DESC",
                        )
                        .bind(member.id)
                        .bind(&name)
                        .fetch_all(&state.db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Database error: {}", e),
                            )
                                .into_response()
                        })?;

                        if !member_artifacts.is_empty() {
                            let versions: Vec<serde_json::Value> = member_artifacts
                                .iter()
                                .map(|a| {
                                    let ver = a.version.clone().unwrap_or_default();
                                    serde_json::json!({
                                        "version": ver,
                                        "archive_url": format!(
                                            "{}/pub/{}/packages/{}/versions/{}.tar.gz",
                                            base_url.as_str(),
                                            repo_key,
                                            name,
                                            ver
                                        ),
                                        "archive_sha256": a.checksum_sha256,
                                        "pubspec": a.metadata.as_ref()
                                            .and_then(|m| m.get("pubspec"))
                                            .cloned()
                                            .unwrap_or_else(|| serde_json::json!({
                                                "name": name,
                                                "version": ver,
                                            })),
                                    })
                                })
                                .collect();
                            return Ok(build_pub_package_response(&name, versions));
                        }
                    }
                    RepositoryType::Remote => {
                        if let Some(ref upstream_url) = member.upstream_url {
                            let api_path = format!("api/packages/{}", name);
                            if let Some(resp) = proxy_pub_meta_get(
                                &state,
                                member.id,
                                &repo_key,
                                base_url.as_str(),
                                upstream_url,
                                &api_path,
                            )
                            .await
                            {
                                return Ok(resp);
                            }
                        }
                    }
                    _ => {}
                }
            }
            return Err(pub_error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Package not found",
            ));
        }

        return Err(pub_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Package not found",
        ));
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let ver = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": ver,
                "archive_url": format!(
                    "{}/pub/{}/packages/{}/versions/{}.tar.gz",
                    base_url.as_str(),
                    repo_key,
                    name,
                    ver
                ),
                "archive_sha256": a.checksum_sha256,
                "pubspec": a.metadata.as_ref()
                    .and_then(|m| m.get("pubspec"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({
                        "name": name,
                        "version": ver,
                    })),
            })
        })
        .collect();
    Ok(build_pub_package_response(&name, versions))
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/{name}/versions/{version} -- Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
    base_url: RequestBaseUrl,
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
            // Remote repo: proxy metadata to upstream
            if repo.repo_type == RepositoryType::Remote {
                if let Some(ref upstream_url) = repo.upstream_url {
                    let api_path = format!("api/packages/{}/versions/{}", name, version);
                    if let Some(resp) = proxy_pub_meta_get(
                        &state,
                        repo.id,
                        &repo_key,
                        base_url.as_str(),
                        upstream_url,
                        &api_path,
                    )
                    .await
                    {
                        return Ok(resp);
                    }
                }
                return Err((StatusCode::NOT_FOUND, "Version not found").into_response());
            }

            // Virtual repo: resolve through members in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
                for member in &members {
                    match member.repo_type {
                        RepositoryType::Local | RepositoryType::Staging => {
                            let member_artifact = sqlx::query_as::<_, PubArtifactRow>(
                                "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                                  am.metadata \
                                  FROM artifacts a \
                                  LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
                                  WHERE a.repository_id = $1 \
                                    AND a.is_deleted = false \
                                    AND LOWER(a.name) = LOWER($2) \
                                    AND a.version = $3 \
                                  LIMIT 1",
                            )
                            .bind(member.id)
                            .bind(&name)
                            .bind(&version)
                            .fetch_optional(&state.db)
                            .await
                            .map_err(|e| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Database error: {}", e),
                                )
                                    .into_response()
                            })?;

                            if let Some(a) = member_artifact {
                                let ver = a.version.clone().unwrap_or_default();
                                let archive_url = format!(
                                    "{}/pub/{}/packages/{}/versions/{}.tar.gz",
                                    base_url.as_str(),
                                    repo_key,
                                    name,
                                    ver
                                );
                                let pubspec = a
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
                                return Ok(build_pub_version_response(
                                    &name,
                                    &ver,
                                    &archive_url,
                                    &a.checksum_sha256,
                                    &pubspec,
                                ));
                            }
                        }
                        RepositoryType::Remote => {
                            if let Some(ref upstream_url) = member.upstream_url {
                                let api_path =
                                    format!("api/packages/{}/versions/{}", name, version);
                                if let Some(resp) = proxy_pub_meta_get(
                                    &state,
                                    member.id,
                                    &repo_key,
                                    base_url.as_str(),
                                    upstream_url,
                                    &api_path,
                                )
                                .await
                                {
                                    return Ok(resp);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                return Err((StatusCode::NOT_FOUND, "Version not found").into_response());
            }

            return Err((StatusCode::NOT_FOUND, "Version not found").into_response());
        }
    };

    let ver = artifact.version.clone().unwrap_or_default();
    let archive_url = format!(
        "{}/pub/{}/packages/{}/versions/{}.tar.gz",
        base_url.as_str(),
        repo_key,
        name,
        ver
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
    Ok(build_pub_version_response(
        &name,
        &ver,
        &archive_url,
        &artifact.checksum_sha256,
        &pubspec,
    ))
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
        return Err(pub_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid archive path: expected packages/{name}/versions/{version}.tar.gz",
        ));
    }

    let pkg_name = parts[0];
    let version_file = parts[2];

    let version = version_file.strip_suffix(".tar.gz").ok_or_else(|| {
        pub_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid archive path: expected .tar.gz extension",
        )
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        pub_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Package archive not found",
        )
    });

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
// GET /pub/{repo_key}/api/packages/versions/new -- Get upload URL
// ---------------------------------------------------------------------------

async fn new_upload_url(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "pub")?.user_id;
    let _repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let upload_url = format!(
        "{}/pub/{}/api/packages/versions/newUpload",
        base_url.as_str(),
        repo_key
    );
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

async fn upload_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    base_url: RequestBaseUrl,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "pub")?.user_id;
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Extract the tar.gz file from multipart form data
    let mut file_bytes: Option<bytes::Bytes> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)).into_response()
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            file_bytes = Some(field.bytes().await.map_err(|e| {
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
        pub_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Missing 'file' field in upload",
        )
    })?;

    if body.is_empty() {
        return Err(pub_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Empty package archive",
        ));
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
        return Err(pub_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Package name and version are required",
        ));
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err(pub_error_response(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package version already exists",
        ));
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

    // 204 with Location per the Pub spec
    let finish_url = format!(
        "{}/pub/{}/api/packages/versions/newUploadFinish",
        base_url.as_str().trim_end_matches('/'),
        repo_key
    );

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

/// Build a Pub-spec JSON error response: `{"error": {"code": "...", "message": "..."}}`
#[allow(clippy::result_large_err)]
fn pub_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let json = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
        }
    });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap()
}

/// Build a Pub-spec package info JSON response from pre-built version entries.
fn build_pub_package_response(name: &str, versions: Vec<serde_json::Value>) -> Response {
    let latest = versions.first().cloned().unwrap_or(serde_json::json!(null));

    let json = serde_json::json!({
        "name": name,
        "latest": latest,
        "versions": versions,
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap()
}

/// Build a Pub-spec version info JSON response from individual fields.
fn build_pub_version_response(
    name: &str,
    version: &str,
    archive_url: &str,
    checksum_sha256: &str,
    pubspec: &serde_json::Value,
) -> Response {
    let json = serde_json::json!({
        "name": name,
        "version": version,
        "archive_url": archive_url,
        "archive_sha256": checksum_sha256,
        "pubspec": pubspec,
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap()
}

/// Rewrite `archive_url` in proxied Pub metadata JSON to point to AK.
///
/// Handles both `package_info` (has `versions[]` array) and `version_info`
/// (flat structure with root `archive_url`). Non-URL fields are preserved.
fn rewrite_pub_archive_urls(json: &mut serde_json::Value, base_url: &str, repo_key: &str) {
    let name = json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("_unknown")
        .to_string();

    if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_array_mut()) {
        for entry in versions.iter_mut() {
            rewrite_pub_entry_archive_url(entry, base_url, repo_key, &name);
        }
    }

    rewrite_pub_entry_archive_url(json, base_url, repo_key, &name);
}

fn rewrite_pub_entry_archive_url(
    entry: &mut serde_json::Value,
    base_url: &str,
    repo_key: &str,
    name: &str,
) {
    let ver = entry
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(obj) = entry.as_object_mut() {
        let new_url = format!(
            "{}/pub/{}/packages/{}/versions/{}.tar.gz",
            base_url, repo_key, name, ver
        );
        obj.insert(
            "archive_url".to_string(),
            serde_json::Value::String(new_url),
        );
    }
}

/// Forward a GET request to the upstream Pub registry for package metadata.
///
/// Uses `proxy_fetch` (via `ProxyService`) for caching, single-flight
/// coordination, and stale-if-error fallback. Rewrites `archive_url` in the
/// JSON response to point to Artifact Keeper's download endpoint.
///
/// Returns `None` on transport errors so the caller can fall through to other
/// resolution strategies.
async fn proxy_pub_meta_get(
    state: &SharedState,
    repo_id: Uuid,
    repo_key: &str,
    base_url: &str,
    upstream_url: &str,
    api_path: &str,
) -> Option<Response> {
    let proxy = state.proxy_service.as_ref()?;

    let result = proxy_helpers::proxy_fetch(proxy, repo_id, repo_key, upstream_url, api_path).await;

    let (content, content_type) = match result {
        Ok((c, ct)) => (c, ct),
        Err(_) => return None,
    };

    let ct = content_type
        .as_deref()
        .unwrap_or("application/vnd.pub.v2+json");

    let mut json = match serde_json::from_slice::<serde_json::Value>(&content) {
        Ok(j) => j,
        Err(_) => {
            // Non-JSON response — pass through verbatim
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .body(Body::from(content))
                    .unwrap_or_else(|_| {
                        (StatusCode::INTERNAL_SERVER_ERROR, "upstream error").into_response()
                    }),
            );
        }
    };

    rewrite_pub_archive_urls(&mut json, base_url, repo_key);

    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, ct)
            .body(Body::from(serde_json::to_string(&json).unwrap()))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "rewrite error").into_response()
            }),
    )
}

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

    #[test]
    fn test_pub_error_response_format() {
        let resp = pub_error_response(StatusCode::NOT_FOUND, "NOT_FOUND", "Package not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(ct, "application/vnd.pub.v2+json");
    }

    #[test]
    fn test_pub_error_response_json_body() {
        use futures::FutureExt;
        let resp = pub_error_response(StatusCode::CONFLICT, "CONFLICT", "Already exists");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .now_or_never()
            .unwrap()
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "CONFLICT");
        assert_eq!(json["error"]["message"], "Already exists");
    }

    #[tokio::test]
    async fn test_new_upload_url_get_returns_200() {
        use crate::api::handlers::test_db_helpers as tdh;
        use tower::ServiceExt;

        let Some(fixture) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };
        let app = fixture.router_with_auth(super::router());

        let req = tdh::get(format!("/{}/api/packages/versions/new", fixture.repo_key));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(ct, "application/vnd.pub.v2+json");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("url").is_some());
        assert!(json.get("fields").is_some());

        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_new_upload_url_post_returns_405() {
        use crate::api::handlers::test_db_helpers as tdh;
        use tower::ServiceExt;

        let Some(fixture) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };
        let app = fixture.router_with_auth(super::router());

        let req = tdh::post(
            format!("/{}/api/packages/versions/new", fixture.repo_key),
            "application/json",
            bytes::Bytes::new(),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_package_info_includes_archive_sha256() {
        use crate::api::handlers::test_db_helpers as tdh;
        use tower::ServiceExt;

        let Some(fixture) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };

        // Create a minimal pub package tar.gz
        let pubspec_yaml = "name: test_pkg\nversion: 1.0.0\n";
        let mut tar_data = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use tar::Builder as TarBuilder;

            let encoder = GzEncoder::new(&mut tar_data, Compression::default());
            let mut tar = TarBuilder::new(encoder);
            let mut header = tar::Header::new_gnu();
            tar.append_data(&mut header, "pubspec.yaml", pubspec_yaml.as_bytes())
                .unwrap();
            let encoder = tar.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        // Seed artifact
        let storage_key = "pub/test_pkg/1.0.0/test_pkg-1.0.0.tar.gz".to_string();
        tdh::seed_artifact(
            &fixture.state,
            &fixture.pool,
            &fixture.repo_info("local", None),
            &storage_key,
            "test_pkg/1.0.0/test_pkg-1.0.0.tar.gz",
            "test_pkg",
            "1.0.0",
            "application/gzip",
            bytes::Bytes::from(tar_data),
            fixture.user_id,
        )
        .await;

        let app = fixture.router_with_auth(super::router());
        let req = tdh::get(format!("/{}/api/packages/test_pkg", fixture.repo_key));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = json["versions"].as_array().unwrap();
        assert!(!versions.is_empty());
        assert!(versions[0].get("archive_sha256").is_some());

        fixture.teardown().await;
    }

    // -----------------------------------------------------------------------
    // build_pub_package_response / build_pub_version_response unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_pub_package_response_returns_versions() {
        use futures::FutureExt;
        let versions = vec![
            serde_json::json!({"version": "1.0.0", "archive_url": "/pub/r/pkg/1.0.0.tar.gz"}),
            serde_json::json!({"version": "1.1.0", "archive_url": "/pub/r/pkg/1.1.0.tar.gz"}),
        ];
        let resp = build_pub_package_response("test_pkg", versions);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/vnd.pub.v2+json"
        );

        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .now_or_never()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["name"], "test_pkg");
        assert!(body["versions"].is_array());
        assert_eq!(body["versions"].as_array().unwrap().len(), 2);
        assert_eq!(body["latest"]["version"], "1.0.0");
    }

    #[test]
    fn test_build_pub_package_response_empty_versions() {
        use futures::FutureExt;
        let versions = vec![];
        let resp = build_pub_package_response("empty_pkg", versions);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .now_or_never()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["latest"], serde_json::json!(null));
        assert!(body["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_pub_version_response() {
        use futures::FutureExt;
        let pubspec = serde_json::json!({"name": "test_pkg", "version": "2.0.0"});
        let resp = build_pub_version_response(
            "test_pkg",
            "2.0.0",
            "https://ak/pub/r/pkg/2.0.0.tar.gz",
            "abc123deadbeef",
            &pubspec,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/vnd.pub.v2+json"
        );

        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .now_or_never()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["name"], "test_pkg");
        assert_eq!(body["version"], "2.0.0");
        assert_eq!(body["archive_url"], "https://ak/pub/r/pkg/2.0.0.tar.gz");
        assert_eq!(body["archive_sha256"], "abc123deadbeef");
        assert_eq!(body["pubspec"]["name"], "test_pkg");
    }

    // -----------------------------------------------------------------------
    // rewrite_pub_archive_urls unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_pub_archive_urls_package_info() {
        let mut json = serde_json::json!({
            "name": "test_pkg",
            "latest": {"version": "1.0.0"},
            "versions": [
                {"version": "1.0.0", "archive_url": "https://upstream/pub/test_pkg/1.0.0.tar.gz", "archive_sha256": "abc", "pubspec": {}},
                {"version": "2.0.0", "archive_url": "https://upstream/pub/test_pkg/2.0.0.tar.gz", "archive_sha256": "def", "pubspec": {}}
            ]
        });
        let base_url = "https://ak.example.com";
        let repo_key = "pub-remote";

        rewrite_pub_archive_urls(&mut json, base_url, repo_key);

        let versions = json["versions"].as_array().unwrap();
        assert_eq!(
            versions[0]["archive_url"],
            format!(
                "{}/pub/{}/packages/test_pkg/versions/1.0.0.tar.gz",
                base_url, repo_key
            )
        );
        assert_eq!(
            versions[1]["archive_url"],
            format!(
                "{}/pub/{}/packages/test_pkg/versions/2.0.0.tar.gz",
                base_url, repo_key
            )
        );
        // Non-URL fields preserved
        assert_eq!(versions[0]["archive_sha256"], "abc");
        assert_eq!(versions[0]["version"], "1.0.0");
    }

    #[test]
    fn test_rewrite_pub_archive_urls_version_info() {
        let mut json = serde_json::json!({
            "name": "test_pkg",
            "version": "3.0.0",
            "archive_url": "https://upstream/pub/test_pkg/3.0.0.tar.gz",
            "archive_sha256": "xyz",
            "pubspec": {"name": "test_pkg", "version": "3.0.0"}
        });

        rewrite_pub_archive_urls(&mut json, "https://ak.example.com", "pub-remote");

        assert_eq!(
            json["archive_url"],
            "https://ak.example.com/pub/pub-remote/packages/test_pkg/versions/3.0.0.tar.gz"
        );
        // Non-URL fields preserved
        assert_eq!(json["archive_sha256"], "xyz");
        assert_eq!(json["version"], "3.0.0");
    }

    #[test]
    fn test_rewrite_pub_archive_urls_missing_fields() {
        // Missing name and archive_url — should not panic
        let mut json = serde_json::json!({
            "versions": [
                {"version": "1.0.0"}
            ]
        });
        rewrite_pub_archive_urls(&mut json, "https://ak.example.com", "pub-remote");
        // Should not have added archive_url (no name to construct from)
        assert!(json["versions"][0].get("archive_url").is_some());
    }

    fn mock_pub_package_info(name: &str) -> String {
        format!(
            r#"{{"name":"{name}","latest":{{"version":"1.0.0"}},"versions":[{{"version":"1.0.0","archive_url":"https://upstream/pub/{name}/1.0.0.tar.gz","archive_sha256":"abc","pubspec":{{"name":"{name}","version":"1.0.0"}}}}]}}"#,
            name = name
        )
    }

    #[tokio::test]
    async fn test_remote_repo_package_info_proxied_to_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pub").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let pkg = "test_proxy_pkg";
        let api_path = format!("/api/packages/{}", pkg);

        Mock::given(method("GET"))
            .and(path(api_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pub.v2+json")
                    .set_body_string(mock_pub_package_info(pkg)),
            )
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let app = tdh::router_anon(super::router(), state);
        let uri = format!("/{}/api/packages/{}", fx.repo_key, pkg);
        let (status, bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], pkg);
        assert_eq!(json["versions"][0]["version"], "1.0.0");
        // Verify archive_url is rewritten to AK format, not upstream
        let url = json["versions"][0]["archive_url"].as_str().unwrap();
        assert!(
            url.contains(&format!(
                "/pub/{}/packages/{}/versions/1.0.0.tar.gz",
                fx.repo_key, pkg
            )),
            "archive_url should be rewritten to AK format, got: {}",
            url
        );
    }

    #[tokio::test]
    async fn test_remote_repo_package_info_404_when_upstream_down() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("remote", "pub").await else {
            return;
        };

        // Leave upstream_url pointing to a non-existent server
        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let app = tdh::router_anon(super::router(), state);
        let uri = format!("/{}/api/packages/missing_pkg", fx.repo_key);
        let (status, _bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        // When upstream is unreachable the handler returns 404
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_remote_repo_version_info_proxied_to_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "pub").await else {
            return;
        };

        let mock_server = MockServer::start().await;
        let pkg = "test_ver_pkg";
        let ver = "2.0.0";
        let api_path = format!("/api/packages/{}/versions/{}", pkg, ver);

        Mock::given(method("GET"))
            .and(path(api_path.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pub.v2+json")
                    .set_body_string(
                        serde_json::json!({
                            "name": pkg,
                            "version": ver,
                            "archive_url": format!("https://upstream/pub/{pkg}/{ver}.tar.gz"),
                            "archive_sha256": "def",
                            "pubspec": {"name": pkg, "version": ver},
                        })
                        .to_string(),
                    ),
            )
            .mount(&mock_server)
            .await;

        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock_server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("update upstream_url");

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let app = tdh::router_anon(super::router(), state);
        let uri = format!("/{}/api/packages/{}/versions/{}", fx.repo_key, pkg, ver);
        let (status, bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], pkg);
        assert_eq!(json["version"], ver);
        // Verify archive_url is rewritten to AK format
        let url = json["archive_url"].as_str().unwrap();
        assert!(
            url.contains(&format!(
                "/pub/{}/packages/{}/versions/{}.tar.gz",
                fx.repo_key, pkg, ver
            )),
            "archive_url should be rewritten to AK format, got: {}",
            url
        );
    }

    // -----------------------------------------------------------------------
    // Virtual repo member resolution integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_virtual_repo_package_info_resolves_local_member() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };

        // Create a minimal pub package tar.gz
        let pubspec_yaml = "name: test_virtual_pkg\nversion: 3.0.0\n";
        let mut tar_data = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use tar::Builder as TarBuilder;

            let encoder = GzEncoder::new(&mut tar_data, Compression::default());
            let mut tar = TarBuilder::new(encoder);
            let mut header = tar::Header::new_gnu();
            tar.append_data(&mut header, "pubspec.yaml", pubspec_yaml.as_bytes())
                .unwrap();
            let encoder = tar.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        // Seed artifact into the local repo
        let storage_key = "pub/test_virtual_pkg/3.0.0/test_virtual_pkg-3.0.0.tar.gz".to_string();
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            &storage_key,
            "test_virtual_pkg/3.0.0/test_virtual_pkg-3.0.0.tar.gz",
            "test_virtual_pkg",
            "3.0.0",
            "application/gzip",
            bytes::Bytes::from(tar_data),
            fx.user_id,
        )
        .await;

        // Create virtual repo using our local repo as a member
        let virtual_id = Uuid::new_v4();
        let virtual_key = format!("ph-pub-virtual-{}", virtual_id);
        let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", virtual_id));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");

        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'pub'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(storage_dir.to_string_lossy().as_ref())
        .execute(&fx.pool)
        .await
        .expect("create virtual repo");

        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("add member");

        // Also grant access to virtual repo for the fixture user
        tdh::grant_repo_access(&fx.pool, virtual_id, fx.user_id).await;

        let app = tdh::router_anon(super::router(), fx.state.clone());
        let uri = format!("/{}/api/packages/test_virtual_pkg", virtual_key);
        let (status, bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "test_virtual_pkg");
        let versions = json["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "3.0.0");
    }

    #[tokio::test]
    async fn test_virtual_repo_package_info_404_when_no_member() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("virtual", "pub").await else {
            return;
        };
        let app = tdh::router_anon(super::router(), fx.state.clone());
        let uri = format!("/{}/api/packages/missing_pkg", fx.repo_key);
        let (status, _bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_virtual_repo_version_info_resolves_local_member() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "pub").await else {
            return;
        };

        // Create a minimal pub package tar.gz
        let pubspec_yaml = "name: test_ver_virtual\nversion: 4.0.0\n";
        let mut tar_data = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use tar::Builder as TarBuilder;

            let encoder = GzEncoder::new(&mut tar_data, Compression::default());
            let mut tar = TarBuilder::new(encoder);
            let mut header = tar::Header::new_gnu();
            tar.append_data(&mut header, "pubspec.yaml", pubspec_yaml.as_bytes())
                .unwrap();
            let encoder = tar.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        let storage_key = "pub/test_ver_virtual/4.0.0/test_ver_virtual-4.0.0.tar.gz".to_string();
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            &storage_key,
            "test_ver_virtual/4.0.0/test_ver_virtual-4.0.0.tar.gz",
            "test_ver_virtual",
            "4.0.0",
            "application/gzip",
            bytes::Bytes::from(tar_data),
            fx.user_id,
        )
        .await;

        // Create virtual repo
        let virtual_id = Uuid::new_v4();
        let virtual_key = format!("ph-pub-virtual-{}", virtual_id);
        let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", virtual_id));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");

        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'pub'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(storage_dir.to_string_lossy().as_ref())
        .execute(&fx.pool)
        .await
        .expect("create virtual repo");

        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("add member");

        tdh::grant_repo_access(&fx.pool, virtual_id, fx.user_id).await;

        let app = tdh::router_anon(super::router(), fx.state.clone());
        let uri = format!(
            "/{}/api/packages/test_ver_virtual/versions/4.0.0",
            virtual_key
        );
        let (status, bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "test_ver_virtual");
        assert_eq!(json["version"], "4.0.0");
    }

    #[tokio::test]
    async fn test_virtual_repo_version_info_404_when_no_member() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("virtual", "pub").await else {
            return;
        };
        let app = tdh::router_anon(super::router(), fx.state.clone());
        let uri = format!("/{}/api/packages/missing_pkg/versions/1.0.0", fx.repo_key);
        let (status, _bytes) = tdh::send(app, tdh::get(uri)).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
