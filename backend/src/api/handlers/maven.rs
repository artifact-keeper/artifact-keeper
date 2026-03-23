//! Maven 2 Repository Layout handlers.
//!
//! Implements the path-based Maven repository layout for `mvn deploy` and
//! `mvn dependency:resolve`.
//!
//! Routes are mounted at `/maven/{repo_key}/...`:
//!   GET  /maven/{repo_key}/*path — Download artifact, metadata, or checksum
//!   PUT  /maven/{repo_key}/*path — Upload artifact (mvn deploy)

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::error::AppError;
use crate::formats::maven::{generate_metadata_xml, MavenCoordinates, MavenHandler};
use crate::models::repository::RepositoryType;

// TODO: Remaining format handlers (beyond maven, npm, pypi, cargo) still use
// plain-text error responses and should be migrated to AppError (#553).

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new().route("/:repo_key/*path", get(download).put(upload))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_maven_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["maven", "gradle"], "a Maven").await
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Given a `-SNAPSHOT` artifact path, build a SQL LIKE pattern that matches
/// the corresponding timestamp-resolved filename stored in the database.
///
/// Example: `com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar`
///       -> `com/example/lib/1.0-SNAPSHOT/lib-1.0-%.jar`
///
/// Returns `None` if the path does not contain a `-SNAPSHOT` filename segment.
fn snapshot_like_pattern(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    let filename = parts[parts.len() - 1];
    let version_dir = parts[parts.len() - 2];

    // Only applies when the version directory is a SNAPSHOT version
    if !version_dir.ends_with("-SNAPSHOT") {
        return None;
    }

    // Replace `-SNAPSHOT` in the filename with `-%` for the LIKE pattern.
    // The filename may be e.g. "lib-1.0-SNAPSHOT.jar" or "lib-1.0-SNAPSHOT-sources.jar".
    // We want to match   "lib-1.0-20260304.095300-1.jar" / "...-sources.jar".
    let base_version = version_dir.strip_suffix("-SNAPSHOT").unwrap();
    let snapshot_token = format!("{}-SNAPSHOT", base_version);
    let timestamp_wildcard = format!("{}-%", base_version);

    if !filename.contains(&snapshot_token) {
        return None;
    }

    let resolved_filename = filename.replace(&snapshot_token, &timestamp_wildcard);
    let dir = parts[..parts.len() - 1].join("/");
    Some(format!("{}/{}", dir, resolved_filename))
}

/// Look up the latest timestamped artifact path matching a SNAPSHOT pattern.
/// Uses a SQL LIKE query to find artifacts stored under timestamp-resolved names
/// when the client requests the `-SNAPSHOT` form.
async fn resolve_snapshot_artifact(
    db: &PgPool,
    repo_id: uuid::Uuid,
    snapshot_path: &str,
) -> Option<ResolvedSnapshot> {
    let pattern = snapshot_like_pattern(snapshot_path)?;

    // Use runtime sqlx::query (not the query! macro) to avoid needing an
    // offline cache entry. The LIKE pattern matches timestamped filenames
    // and we pick the latest one by created_at.
    let row = sqlx::query(
        r#"
        SELECT id, storage_key, checksum_sha256, path
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(repo_id)
    .bind(&pattern)
    .fetch_optional(db)
    .await
    .ok()??;

    use sqlx::Row;
    Some(ResolvedSnapshot {
        storage_key: row.get("storage_key"),
        checksum_sha256: row.get("checksum_sha256"),
        path: row.get("path"),
    })
}

struct ResolvedSnapshot {
    storage_key: String,
    checksum_sha256: String,
    path: String,
}

fn checksum_suffix(ct: ChecksumType) -> &'static str {
    match ct {
        ChecksumType::Md5 => "md5",
        ChecksumType::Sha1 => "sha1",
        ChecksumType::Sha256 => "sha256",
    }
}

// ---------------------------------------------------------------------------
// Pure (non-async) helper functions for testability
// ---------------------------------------------------------------------------

/// Determine if a Maven path is for artifact-level metadata (groupId/artifactId level).
/// Returns (groupId, artifactId) if the path ends with maven-metadata.xml AND the
/// segment before it is an artifactId (not a version).
///
/// Version-level metadata (groupId/artifactId/version/maven-metadata.xml) returns None
/// so the caller can serve it from storage instead of generating it dynamically.
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
    let candidate = parts[parts.len() - 2];
    // If the segment before maven-metadata.xml looks like a version, this is
    // version-level metadata (e.g. .../1.0.0-SNAPSHOT/maven-metadata.xml).
    // Return None so the download handler serves it from storage.
    if looks_like_maven_version(candidate) {
        return None;
    }
    let artifact_id = candidate.to_string();
    let group_id = parts[..parts.len() - 2].join(".");
    Some((group_id, artifact_id))
}

/// Heuristic: Maven versions start with a digit (1.0.0, 2.0-rc1, 3.12.0-SNAPSHOT).
/// Artifact IDs practically never start with a digit.
fn looks_like_maven_version(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_digit())
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
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    // 1. Check if this is a checksum request for metadata
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        if MavenHandler::is_metadata(base_path) {
            // Try stored checksum file first
            let checksum_storage_key = format!("maven/{}", path);
            if let Ok(content) = storage.get(&checksum_storage_key).await {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(Body::from(content))
                    .unwrap());
            }

            // Try stored metadata file and compute checksum from it
            let meta_storage_key = format!("maven/{}", base_path);
            if let Ok(content) = storage.get(&meta_storage_key).await {
                let checksum = compute_checksum(&content, checksum_type);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(Body::from(checksum))
                    .unwrap());
            }

            // Fall back to dynamic generation for artifact-level metadata
            if let Some((group_id, artifact_id)) = parse_metadata_path(base_path) {
                let xml =
                    generate_metadata_for_artifact(&state.db, repo.id, &group_id, &artifact_id)
                        .await?;
                let checksum = compute_checksum(xml.as_bytes(), checksum_type);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(Body::from(checksum))
                    .unwrap());
            }
        }
    }

    // 2. Check if this is a maven-metadata.xml request
    if MavenHandler::is_metadata(&path) {
        // Try stored metadata file first (handles version-level metadata)
        let meta_storage_key = format!("maven/{}", path);
        if let Ok(content) = storage.get(&meta_storage_key).await {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/xml")
                .header(CONTENT_LENGTH, content.len().to_string())
                .body(Body::from(content))
                .unwrap());
        }

        // Fall back to dynamic generation for artifact-level metadata
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

        // Metadata not found anywhere
        return Err(AppError::NotFound("Metadata not found".to_string()).into_response());
    }

    // 3. Check if this is a checksum request for a stored file
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        // First try to find a stored checksum file
        let checksum_storage_key = format!("maven/{}", path);
        if let Ok(content) = storage.get(&checksum_storage_key).await {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(content))
                .unwrap());
        }

        // If this is a SNAPSHOT path, try the stored checksum under the
        // timestamp-resolved filename before falling through to compute.
        if base_path.contains("-SNAPSHOT") {
            if let Some(resolved) = resolve_snapshot_artifact(&state.db, repo.id, base_path).await {
                let resolved_checksum_key =
                    format!("maven/{}.{}", resolved.path, checksum_suffix(checksum_type));
                if let Ok(content) = storage.get(&resolved_checksum_key).await {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Body::from(content))
                        .unwrap());
                }
            }
        }

        // Otherwise compute from the artifact
        return serve_computed_checksum(
            &state,
            repo.id,
            &repo.storage_location(),
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
    .map_err(|e| AppError::Database(e.to_string()).into_response())?;

    let versions: Vec<String> = rows.into_iter().filter_map(|r| r.version).collect();

    if versions.is_empty() {
        return Err(AppError::NotFound("No versions found".to_string()).into_response());
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
    .map_err(|e| AppError::Database(e.to_string()).into_response())?;

    // If artifact not found by exact path, try SNAPSHOT resolution
    let artifact = match artifact {
        Some(a) => Some(a),
        None if path.contains("-SNAPSHOT") => {
            if let Some(resolved) = resolve_snapshot_artifact(&state.db, repo.id, path).await {
                let storage = state
                    .storage_for_repo(&repo.storage_location())
                    .map_err(|e| e.into_response())?;
                let content = storage.get(&resolved.storage_key).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;

                let ct = content_type_for_path(path);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, ct)
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .header("X-Checksum-SHA256", &resolved.checksum_sha256)
                    .body(Body::from(content))
                    .unwrap());
            }
            None
        }
        None => None,
    };

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
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
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let artifact_path = path.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let artifact_path = artifact_path.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db,
                                &state,
                                member_id,
                                &location,
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

            // For hosted repos, fall back to serving from storage directly.
            // This handles secondary files (POM, sources, javadoc) that were
            // grouped under a primary artifact record by GAV grouping — their
            // database `path` was replaced but the file still exists in storage.
            if repo.repo_type == RepositoryType::Local || repo.repo_type == RepositoryType::Staging
            {
                let storage = state
                    .storage_for_repo(&repo.storage_location())
                    .map_err(|e| e.into_response())?;
                let storage_key = format!("maven/{}", path);
                if let Ok(content) = storage.get(&storage_key).await {
                    let ct = content_type_for_path(path);
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
            }

            return Err(AppError::NotFound("File not found".to_string()).into_response());
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage.get(&artifact.storage_key).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;

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
    location: &crate::storage::StorageLocation,
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
    .map_err(|e| AppError::Database(e.to_string()).into_response())?;

    // If the exact path was not found and this is a SNAPSHOT request, resolve
    // the `-SNAPSHOT` filename to the latest timestamped version.
    let (resolved_storage_key, resolved_sha256) = match artifact {
        Some(a) => (a.storage_key, a.checksum_sha256),
        None => {
            if base_path.contains("-SNAPSHOT") {
                let resolved = resolve_snapshot_artifact(&state.db, repo_id, base_path)
                    .await
                    .ok_or_else(|| AppError::NotFound("File not found".to_string()).into_response())?;
                (resolved.storage_key, resolved.checksum_sha256)
            } else {
                return Err(AppError::NotFound("File not found".to_string()).into_response());
            }
        }
    };

    // For SHA-256 we already have it stored
    let checksum = match checksum_type {
        ChecksumType::Sha256 => resolved_sha256,
        _ => {
            let storage = state.storage_for_repo_or_500(location)?;
            let content = storage.get(&resolved_storage_key).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;
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
// Maven GAV grouping helpers
// ---------------------------------------------------------------------------

/// Extract the GAV directory prefix from a Maven path.
/// For example: `com/example/mylib/1.0.0/mylib-1.0.0.jar` -> `com/example/mylib/1.0.0/`
fn gav_directory(path: &str) -> &str {
    let trimmed = path.trim_start_matches('/');
    match trimmed.rfind('/') {
        Some(pos) => &trimmed[..=pos],
        None => trimmed,
    }
}

/// Determine whether a Maven file is a "primary" packaging artifact (JAR, WAR, EAR, etc.)
/// without a classifier. POM files and classifier-bearing files (sources, javadoc) are
/// considered secondary.
fn is_primary_maven_artifact(coords: &MavenCoordinates) -> bool {
    if coords.classifier.is_some() {
        return false;
    }
    matches!(
        coords.extension.as_str(),
        "jar" | "war" | "ear" | "aar" | "bundle" | "zip" | "tar.gz"
    )
}

/// Build a JSON object describing a single file within a Maven package.
fn make_file_entry(
    path: &str,
    extension: &str,
    classifier: Option<&str>,
    storage_key: &str,
    size_bytes: i64,
    sha256: &str,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "path": path,
        "extension": extension,
        "storageKey": storage_key,
        "sizeBytes": size_bytes,
        "sha256": sha256,
    });
    if let Some(c) = classifier {
        entry["classifier"] = serde_json::Value::String(c.to_string());
    }
    entry
}

/// Update an existing artifact record to point to a new file (used when a
/// primary upload replaces a secondary, or a SNAPSHOT re-upload updates the
/// primary). Cleans up any soft-deleted artifact at the target path first.
#[allow(clippy::too_many_arguments)]
async fn update_artifact_record(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    path: &str,
    size_bytes: i64,
    checksum_sha256: &str,
    content_type: &str,
    storage_key: &str,
) -> Result<(), Response> {
    super::cleanup_soft_deleted_artifact(db, repo_id, path).await;
    sqlx::query(
        r#"
        UPDATE artifacts
        SET path = $1, size_bytes = $2, checksum_sha256 = $3,
            content_type = $4, storage_key = $5, updated_at = NOW()
        WHERE id = $6
        "#,
    )
    .bind(path)
    .bind(size_bytes)
    .bind(checksum_sha256)
    .bind(content_type)
    .bind(storage_key)
    .bind(artifact_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()).into_response())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PUT /maven/{repo_key}/*path — Upload artifact
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "maven")?.user_id;
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let storage_key = format!("maven/{}", path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    // If this is a checksum file (.sha1, .md5, .sha256), just store it and return
    if parse_checksum_path(&path).is_some() {
        storage.put(&storage_key, body).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // If this is a maven-metadata.xml upload, just store it
    if MavenHandler::is_metadata(&path) {
        storage.put(&storage_key, body).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // Parse Maven coordinates from the path
    let coords = MavenHandler::parse_coordinates(&path).map_err(|e| {
        AppError::Validation(format!("Invalid Maven path: {}", e)).into_response()
    })?;

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum_sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let ct = content_type_for_path(&path);

    // Check for active (non-deleted) duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()).into_response())?;

    if existing.is_some() {
        if !coords.version.contains("SNAPSHOT") {
            return Err(AppError::Conflict("Artifact already exists".to_string()).into_response());
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
    } else {
        // Clean up any soft-deleted artifact at the same path so the
        // UNIQUE(repository_id, path) constraint doesn't block re-upload.
        super::cleanup_soft_deleted_artifact(&state.db, repo.id, &path).await;
    }

    // Store file in object storage regardless of grouping outcome
    storage.put(&storage_key, body.clone()).await.map_err(|e| AppError::Storage(e.to_string()).into_response())?;

    // Build metadata JSON for this file
    let handler = MavenHandler::new();
    let file_metadata = crate::formats::FormatHandler::parse_metadata(&handler, &path, &body)
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
    let gav_dir = gav_directory(&path);
    let is_primary = is_primary_maven_artifact(&coords);

    // Look for an existing artifact record for the same GAV directory.
    // This groups POM, JAR, sources, javadoc, etc. under a single record
    // so the UI shows one package per GAV instead of separate entries.
    let gav_existing: Option<(uuid::Uuid, String, String, Option<serde_json::Value>)> = {
        let gav_pattern = format!("{}%", gav_dir);
        let row = sqlx::query(
            r#"
            SELECT a.id, a.path, a.storage_key, am.metadata
            FROM artifacts a
            LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.path LIKE $2
              AND a.name = $3
              AND a.version = $4
            ORDER BY a.created_at ASC
            LIMIT 1
            "#,
        )
        .bind(repo.id)
        .bind(&gav_pattern)
        .bind(&name)
        .bind(&coords.version)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()).into_response())?;

        use sqlx::Row;
        row.map(|r| {
            (
                r.get::<uuid::Uuid, _>("id"),
                r.get::<String, _>("path"),
                r.get::<String, _>("storage_key"),
                r.get::<Option<serde_json::Value>, _>("metadata"),
            )
        })
    };

    match gav_existing {
        Some((existing_id, existing_path, existing_storage_key, existing_meta)) => {
            // An artifact record already exists for this GAV.
            let existing_is_pom = MavenHandler::is_pom(&existing_path);

            let new_file = make_file_entry(
                &path,
                &coords.extension,
                coords.classifier.as_deref(),
                &storage_key,
                size_bytes,
                &checksum_sha256,
            );

            if is_primary && existing_is_pom {
                // The existing record is a POM-only placeholder. Promote the new
                // JAR/WAR to primary and demote the POM into the files list.
                let old_pom_coords = MavenHandler::parse_coordinates(&existing_path).ok();
                let old_ext = old_pom_coords
                    .as_ref()
                    .map(|c| c.extension.as_str())
                    .unwrap_or("pom");
                let old_classifier = old_pom_coords
                    .as_ref()
                    .and_then(|c| c.classifier.as_deref());

                let old_size: i64 =
                    if let Ok(old_content) = storage.get(&existing_storage_key).await {
                        old_content.len() as i64
                    } else {
                        0
                    };
                let old_sha = existing_meta
                    .as_ref()
                    .and_then(|m| m.get("sha256"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let pom_file = make_file_entry(
                    &existing_path,
                    old_ext,
                    old_classifier,
                    &existing_storage_key,
                    old_size,
                    &old_sha,
                );

                let mut files = existing_meta
                    .as_ref()
                    .and_then(|m| m.get("files"))
                    .and_then(|f| f.as_array())
                    .cloned()
                    .unwrap_or_default();
                files.push(pom_file);

                // Merge POM-parsed fields into the new primary metadata
                let mut merged = file_metadata.clone();
                if let Some(existing) = &existing_meta {
                    for key in &["name", "description", "url", "dependencies"] {
                        if let Some(val) = existing.get(*key) {
                            merged[*key] = val.clone();
                        }
                    }
                }
                merged["files"] = serde_json::Value::Array(files);

                // Update the artifact record to point to the JAR as primary
                update_artifact_record(
                    &state.db,
                    repo.id,
                    existing_id,
                    &path,
                    size_bytes,
                    &checksum_sha256,
                    ct,
                    &storage_key,
                )
                .await?;

                let _ = sqlx::query(
                    r#"
                    INSERT INTO artifact_metadata (artifact_id, format, metadata)
                    VALUES ($1, 'maven', $2)
                    ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
                    "#,
                )
                .bind(existing_id)
                .bind(&merged)
                .execute(&state.db)
                .await;
            } else if is_primary && coords.version.contains("SNAPSHOT") {
                // SNAPSHOT re-upload: update the artifact record, then fall
                // through to shared metadata update below.
                update_artifact_record(
                    &state.db,
                    repo.id,
                    existing_id,
                    &path,
                    size_bytes,
                    &checksum_sha256,
                    ct,
                    &storage_key,
                )
                .await?;
                // Secondary file (POM when JAR exists, or classifier like sources/javadoc).
                // Add it to the existing artifact's metadata files array.
                let mut updated_meta = existing_meta.unwrap_or_else(|| {
                    serde_json::json!({
                        "groupId": coords.group_id,
                        "artifactId": coords.artifact_id,
                        "version": coords.version,
                    })
                });

                let mut files = updated_meta
                    .get("files")
                    .and_then(|f| f.as_array())
                    .cloned()
                    .unwrap_or_default();
                files.push(new_file);
                updated_meta["files"] = serde_json::Value::Array(files);

                // Merge POM-parsed fields if this is a POM upload
                if MavenHandler::is_pom(&path) {
                    for key in &["name", "description", "url", "dependencies"] {
                        if let Some(val) = file_metadata.get(*key) {
                            if updated_meta.get(*key).is_none() {
                                updated_meta[*key] = val.clone();
                            }
                        }
                    }
                }

                let _ = sqlx::query(
                    r#"
                    INSERT INTO artifact_metadata (artifact_id, format, metadata)
                    VALUES ($1, 'maven', $2)
                    ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
                    "#,
                )
                .bind(existing_id)
                .bind(&updated_meta)
                .execute(&state.db)
                .await;

                let _ = sqlx::query("UPDATE artifacts SET updated_at = NOW() WHERE id = $1")
                    .bind(existing_id)
                    .execute(&state.db)
                    .await;
            }
        }
        None => {
            // No existing artifact for this GAV. Create a new record.
            let mut metadata = file_metadata;

            use sqlx::Row;
            let row = sqlx::query(
                r#"
                INSERT INTO artifacts (
                    repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key, uploaded_by
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
                "#,
            )
            .bind(repo.id)
            .bind(&path)
            .bind(&name)
            .bind(&coords.version)
            .bind(size_bytes)
            .bind(&checksum_sha256)
            .bind(ct)
            .bind(&storage_key)
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()).into_response())?;
            let artifact_id: uuid::Uuid = row.get("id");

            // Initialize empty files array; the primary info lives on the
            // artifact record itself.
            metadata["files"] = serde_json::json!([]);

            let _ = sqlx::query(
                r#"
                INSERT INTO artifact_metadata (artifact_id, format, metadata)
                VALUES ($1, 'maven', $2)
                ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
                "#,
            )
            .bind(artifact_id)
            .bind(&metadata)
            .execute(&state.db)
            .await;
        }
    }

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

    #[test]
    fn test_parse_metadata_path_version_level_snapshot() {
        let result = parse_metadata_path("com/test/artifacthub/0.0.1-SNAPSHOT/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_version_level_release() {
        let result = parse_metadata_path("com/example/my-lib/1.0.0/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_version_level_complex() {
        let result = parse_metadata_path(
            "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/maven-metadata.xml",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_artifact_level_still_works() {
        let result = parse_metadata_path("com/example/my-lib/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.example".to_string(), "my-lib".to_string())),
        );
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
            key: String::new(),
            storage_path: "/data/maven".to_string(),
            storage_backend: "filesystem".to_string(),
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
            key: String::new(),
            storage_path: "/cache/maven".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo1.maven.org/maven2".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://repo1.maven.org/maven2")
        );
    }

    // -----------------------------------------------------------------------
    // snapshot_like_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_like_pattern_jar() {
        let result = snapshot_like_pattern(
            "com/test/artifacthub/0.0.1-SNAPSHOT/artifacthub-0.0.1-SNAPSHOT.jar",
        );
        assert_eq!(
            result,
            Some("com/test/artifacthub/0.0.1-SNAPSHOT/artifacthub-0.0.1-%.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_pom() {
        let result =
            snapshot_like_pattern("com/example/mylib/1.0.0-SNAPSHOT/mylib-1.0.0-SNAPSHOT.pom");
        assert_eq!(
            result,
            Some("com/example/mylib/1.0.0-SNAPSHOT/mylib-1.0.0-%.pom".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_with_classifier() {
        let result =
            snapshot_like_pattern("com/example/lib/2.0-SNAPSHOT/lib-2.0-SNAPSHOT-sources.jar");
        assert_eq!(
            result,
            Some("com/example/lib/2.0-SNAPSHOT/lib-2.0-%-sources.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_non_snapshot_returns_none() {
        let result = snapshot_like_pattern("com/example/lib/1.0.0/lib-1.0.0.jar");
        assert_eq!(result, None);
    }

    #[test]
    fn test_snapshot_like_pattern_metadata_returns_none() {
        // maven-metadata.xml does not contain -SNAPSHOT in the filename
        let result = snapshot_like_pattern("com/example/lib/1.0.0-SNAPSHOT/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_snapshot_like_pattern_leading_slash() {
        let result = snapshot_like_pattern("/com/test/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        assert_eq!(
            result,
            Some("com/test/lib/1.0-SNAPSHOT/lib-1.0-%.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_deep_group() {
        let result = snapshot_like_pattern(
            "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/commons-lang3-3.12.0-SNAPSHOT.jar",
        );
        assert_eq!(
            result,
            Some(
                "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/commons-lang3-3.12.0-%.jar"
                    .to_string()
            )
        );
    }

    // -----------------------------------------------------------------------
    // checksum_suffix
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_suffix_md5() {
        assert_eq!(checksum_suffix(ChecksumType::Md5), "md5");
    }

    #[test]
    fn test_checksum_suffix_sha1() {
        assert_eq!(checksum_suffix(ChecksumType::Sha1), "sha1");
    }

    #[test]
    fn test_checksum_suffix_sha256() {
        assert_eq!(checksum_suffix(ChecksumType::Sha256), "sha256");
    }

    // -----------------------------------------------------------------------
    // gav_directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_gav_directory_jar() {
        assert_eq!(
            gav_directory("com/example/mylib/1.0.0/mylib-1.0.0.jar"),
            "com/example/mylib/1.0.0/"
        );
    }

    #[test]
    fn test_gav_directory_pom() {
        assert_eq!(
            gav_directory("com/example/mylib/1.0.0/mylib-1.0.0.pom"),
            "com/example/mylib/1.0.0/"
        );
    }

    #[test]
    fn test_gav_directory_sources() {
        assert_eq!(
            gav_directory("com/example/mylib/1.0.0/mylib-1.0.0-sources.jar"),
            "com/example/mylib/1.0.0/"
        );
    }

    #[test]
    fn test_gav_directory_leading_slash() {
        assert_eq!(
            gav_directory("/com/example/mylib/1.0.0/mylib-1.0.0.jar"),
            "com/example/mylib/1.0.0/"
        );
    }

    #[test]
    fn test_gav_directory_deep_group() {
        assert_eq!(
            gav_directory("org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
            "org/apache/commons/commons-lang3/3.12.0/"
        );
    }

    // -----------------------------------------------------------------------
    // is_primary_maven_artifact
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_primary_jar() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0.jar").unwrap();
        assert!(is_primary_maven_artifact(&coords));
    }

    #[test]
    fn test_is_primary_war() {
        let coords =
            MavenHandler::parse_coordinates("com/example/webapp/1.0.0/webapp-1.0.0.war").unwrap();
        assert!(is_primary_maven_artifact(&coords));
    }

    #[test]
    fn test_is_not_primary_pom() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0.pom").unwrap();
        assert!(!is_primary_maven_artifact(&coords));
    }

    #[test]
    fn test_is_not_primary_sources() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0-sources.jar")
                .unwrap();
        assert!(!is_primary_maven_artifact(&coords));
    }

    #[test]
    fn test_is_not_primary_javadoc() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0-javadoc.jar")
                .unwrap();
        assert!(!is_primary_maven_artifact(&coords));
    }

    // -----------------------------------------------------------------------
    // make_file_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_file_entry_without_classifier() {
        let entry = make_file_entry(
            "com/example/mylib/1.0.0/mylib-1.0.0.pom",
            "pom",
            None,
            "maven/com/example/mylib/1.0.0/mylib-1.0.0.pom",
            1024,
            "abc123",
        );
        assert_eq!(entry["path"], "com/example/mylib/1.0.0/mylib-1.0.0.pom");
        assert_eq!(entry["extension"], "pom");
        assert!(entry.get("classifier").is_none());
        assert_eq!(entry["sizeBytes"], 1024);
        assert_eq!(entry["sha256"], "abc123");
    }

    #[test]
    fn test_make_file_entry_with_classifier() {
        let entry = make_file_entry(
            "com/example/mylib/1.0.0/mylib-1.0.0-sources.jar",
            "jar",
            Some("sources"),
            "maven/com/example/mylib/1.0.0/mylib-1.0.0-sources.jar",
            2048,
            "def456",
        );
        assert_eq!(entry["classifier"], "sources");
        assert_eq!(entry["extension"], "jar");
    }
}
