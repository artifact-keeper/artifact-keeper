//! JetBrains Plugin Repository API handlers.
//!
//! Implements endpoints for JetBrains IDE plugin hosting and retrieval.
//!
//! Routes are mounted at `/jetbrains/{repo_key}/...`:
//!   GET  /jetbrains/{repo_key}/plugins/list/                       - List plugins (XML)
//!   GET  /jetbrains/{repo_key}/plugin/download/{name}/{version}    - Download plugin
//!   GET  /jetbrains/{repo_key}/plugins/{id}/updates                - Check for updates (XML)
//!   POST /jetbrains/{repo_key}/plugin/uploadPlugin                 - Upload plugin (multipart)
//!   GET  /jetbrains/{repo_key}/plugin/details/{name}               - Plugin details (JSON)

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

use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // List plugins (XML)
        .route("/:repo_key/plugins/list/", get(list_plugins))
        // Plugin updates (XML)
        .route("/:repo_key/plugins/:id/updates", get(plugin_updates))
        // Upload plugin (multipart)
        .route("/:repo_key/plugin/uploadPlugin", post(upload_plugin))
        // Plugin details (JSON)
        .route("/:repo_key/plugin/details/:name", get(plugin_details))
        // Download plugin
        .route(
            "/:repo_key/plugin/download/:name/:version",
            get(download_plugin),
        )
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

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"jetbrains\"")
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
                .header("WWW-Authenticate", "Basic realm=\"jetbrains\"")
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

async fn resolve_jetbrains_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "jetbrains" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a JetBrains repository (format: {})",
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
// GET /jetbrains/{repo_key}/plugins/list/ — List plugins (XML)
// ---------------------------------------------------------------------------

async fn list_plugins(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, a.size_bytes,
               am.metadata as "metadata?"
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

    // Build XML response
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plugin-repository>\n");

    // Group by category
    xml.push_str("  <category name=\"All\">\n");

    for a in &artifacts {
        let version = a.version.clone().unwrap_or_default();
        let description = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let vendor = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("vendor"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let plugin_id = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("plugin_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(&a.name);

        xml.push_str(&format!(
            "    <idea-plugin>\n\
             \x20     <id>{}</id>\n\
             \x20     <name>{}</name>\n\
             \x20     <version>{}</version>\n\
             \x20     <vendor>{}</vendor>\n\
             \x20     <description><![CDATA[{}]]></description>\n\
             \x20     <download-url>/jetbrains/{}/plugin/download/{}/{}</download-url>\n\
             \x20     <size>{}</size>\n\
             \x20   </idea-plugin>\n",
            xml_escape(plugin_id),
            xml_escape(&a.name),
            xml_escape(&version),
            xml_escape(vendor),
            description,
            repo_key,
            a.name,
            version,
            a.size_bytes,
        ));
    }

    xml.push_str("  </category>\n</plugin-repository>\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(xml))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /jetbrains/{repo_key}/plugin/download/{name}/{version} — Download plugin
// ---------------------------------------------------------------------------

async fn download_plugin(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, storage_key, size_bytes, name
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
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
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Plugin not found").into_response())?;

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

    let filename = format!("{}-{}.zip", name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /jetbrains/{repo_key}/plugins/{id}/updates — Check for updates (XML)
// ---------------------------------------------------------------------------

async fn plugin_updates(
    State(state): State<SharedState>,
    Path((repo_key, plugin_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, a.size_bytes,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        plugin_id
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

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plugin-updates>\n");

    for a in &artifacts {
        let version = a.version.clone().unwrap_or_default();
        let since_build = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("since_build"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let until_build = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("until_build"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        xml.push_str(&format!(
            "  <plugin id=\"{}\" url=\"/jetbrains/{}/plugin/download/{}/{}\" \
             version=\"{}\">\n\
             \x20   <idea-version since-build=\"{}\" until-build=\"{}\" />\n\
             \x20 </plugin>\n",
            xml_escape(&plugin_id),
            repo_key,
            a.name,
            version,
            xml_escape(&version),
            xml_escape(since_build),
            xml_escape(until_build),
        ));
    }

    xml.push_str("</plugin-updates>\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(xml))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /jetbrains/{repo_key}/plugin/uploadPlugin — Upload plugin (multipart)
// ---------------------------------------------------------------------------

async fn upload_plugin(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty upload body").into_response());
    }

    // Extract file content from multipart body
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (file_bytes, plugin_name, plugin_version) = if content_type.contains("multipart/form-data")
    {
        extract_plugin_from_multipart(content_type, &body)?
    } else {
        // Raw upload - extract name/version from headers
        let name = headers
            .get("x-plugin-name")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let version = headers
            .get("x-plugin-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0.0.0")
            .to_string();
        (body.clone(), name, version)
    };

    if plugin_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Plugin name is required").into_response());
    }

    let filename = format!("{}-{}.zip", plugin_name, plugin_version);
    let artifact_path = format!("{}/{}/{}", plugin_name, plugin_version, filename);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&file_bytes);
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
        return Err((StatusCode::CONFLICT, "Plugin version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("jetbrains/{}/{}/{}", plugin_name, plugin_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage
        .put(&storage_key, file_bytes.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let size_bytes = file_bytes.len() as i64;

    let metadata = serde_json::json!({
        "plugin_id": plugin_name,
        "filename": filename,
    });

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
        plugin_name,
        plugin_version,
        size_bytes,
        computed_sha256,
        "application/octet-stream",
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
        VALUES ($1, 'jetbrains', $2)
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
        "JetBrains upload: {} {} ({}) to repo {}",
        plugin_name, plugin_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully uploaded plugin"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /jetbrains/{repo_key}/plugin/details/{name} — Plugin details (JSON)
// ---------------------------------------------------------------------------

async fn plugin_details(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, a.created_at,
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
        return Err((StatusCode::NOT_FOUND, "Plugin not found").into_response());
    }

    let latest = &artifacts[0];
    let description = latest
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let vendor = latest
        .metadata
        .as_ref()
        .and_then(|m| m.get("vendor"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Get total download count
    let download_count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) FROM download_statistics
        WHERE artifact_id = ANY(
            SELECT id FROM artifacts
            WHERE repository_id = $1 AND LOWER(name) = LOWER($2) AND is_deleted = false
        )
        "#,
        repo.id,
        name
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "size": a.size_bytes,
                "sha256": a.checksum_sha256,
                "downloadUrl": format!(
                    "/jetbrains/{}/plugin/download/{}/{}",
                    repo_key, a.name, version
                ),
            })
        })
        .collect();

    let json = serde_json::json!({
        "name": name,
        "description": description,
        "vendor": vendor,
        "downloads": download_count,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Escape special XML characters in attribute values and text content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Extract plugin file and metadata from a multipart/form-data body.
///
/// Returns (file_bytes, plugin_name, plugin_version).
fn extract_plugin_from_multipart(
    content_type: &str,
    body: &[u8],
) -> Result<(Bytes, String, String), Response> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|b| b.trim().trim_matches('"'))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing multipart boundary").into_response())?;

    let boundary_marker = format!("--{}", boundary);
    let body_str = String::from_utf8_lossy(body);
    let parts: Vec<&str> = body_str.split(&boundary_marker).collect();

    let mut file_bytes: Option<Bytes> = None;
    let mut plugin_name = String::new();
    let mut plugin_version = String::new();

    for part in &parts {
        if part.is_empty() || *part == "--\r\n" || *part == "--" {
            continue;
        }

        // Split headers from body at the double newline
        let header_body_split = if part.contains("\r\n\r\n") {
            "\r\n\r\n"
        } else if part.contains("\n\n") {
            "\n\n"
        } else {
            continue;
        };

        if let Some(idx) = part.find(header_body_split) {
            let headers_section = &part[..idx];
            let body_section = &part[idx + header_body_split.len()..];
            let headers_lower = headers_section.to_lowercase();

            if headers_lower.contains("name=\"file\"")
                || headers_lower.contains("name=\"plugin\"")
                || headers_lower.contains("filename=")
            {
                // Strip trailing \r\n before next boundary
                let content = body_section.trim_end_matches("\r\n");
                // Re-extract as bytes from original body for binary content
                let header_offset = part.as_ptr() as usize - body_str.as_ptr() as usize;
                let body_offset = header_offset + idx + header_body_split.len();
                let end = header_offset + part.len();
                let end = if end > 2 && &body[end - 2..end] == b"\r\n" {
                    end - 2
                } else {
                    end
                };
                if body_offset <= body.len() && end <= body.len() {
                    file_bytes = Some(Bytes::copy_from_slice(&body[body_offset..end]));
                } else {
                    file_bytes = Some(Bytes::copy_from_slice(content.as_bytes()));
                }
            } else if headers_lower.contains("name=\"name\"") {
                plugin_name = body_section.trim().to_string();
            } else if headers_lower.contains("name=\"version\"") {
                plugin_version = body_section.trim().to_string();
            }
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No plugin file found in multipart body",
        )
            .into_response()
    })?;

    if plugin_name.is_empty() {
        plugin_name = "unknown-plugin".to_string();
    }
    if plugin_version.is_empty() {
        plugin_version = "0.0.0".to_string();
    }

    Ok((file_bytes, plugin_name, plugin_version))
}
