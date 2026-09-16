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

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

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
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_jetbrains_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["jetbrains"], "a JetBrains").await
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
    .map_err(crate::api::handlers::db_err)?;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
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
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Plugin not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("plugin/download/{}/{}", name, version);
                    // #1608 Phase 4: stream the plugin archive to the client
                    // while teeing to the proxy cache, instead of buffering the
                    // whole plugin in memory. Single-flight via the merged
                    // coordinator (#1609).
                    let response = proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        "application/octet-stream",
                    )
                    .await?;
                    // #3649: count the proxied serve. The streaming helper answers a warm
                    // cache HIT from storage and a cold MISS from upstream through the same
                    // call, so recording once it resolves counts both -- the cache hit #3649
                    // reported as invisible included -- while a 404/502 still counts nothing.
                    // Keyed on the proxy-cache path this fetch commits under, so the count
                    // lines up with the catalog row the artifact listing renders.
                    proxy_helpers::record_proxy_download(
                        &state,
                        repo.id,
                        &repo_key,
                        &upstream_path,
                        &ctx,
                    )
                    .await;
                    return Ok(response);
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("plugin/download/{}/{}", name, version);
                let vname = name.clone();
                let vversion = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth.as_ref(),
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
                crate::api::handlers::storage_err_message(&e),
            )
                .into_response()
        })?;

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let filename = format!("{}-{}.zip", name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
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
    .map_err(crate::api::handlers::db_err)?;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "jetbrains", "write:artifacts")?.user_id;
    let repo = resolve_jetbrains_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Ingest the body as a STREAM — the IDE and the gradle plugin send
    // multipart/form-data, other clients send the raw zip with
    // `X-Plugin-Name`/`X-Plugin-Version`. Both spool to a bounded scratch file
    // while computing SHA-256/SHA-1/MD5 incrementally, so a plugin is never
    // held on the heap (Core Invariant (1), #1608; same shape as the nuget push
    // and the swift publish of #3595).
    let (staged, digests, plugin_name, plugin_version) = if content_type
        .contains("multipart/form-data")
    {
        stage_plugin_from_multipart(&state, content_type, body).await?
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
        let (staged, digests) =
            proxy_helpers::stage_stream_content_addressed(&state, body.into_data_stream()).await?;
        (staged, digests, name, version)
    };

    if staged.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty upload body").into_response());
    }

    if plugin_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Plugin name is required").into_response());
    }

    let filename = format!("{}-{}.zip", plugin_name, plugin_version);
    let artifact_path = format!("{}/{}/{}", plugin_name, plugin_version, filename);

    // GHSA-vcq6-8hxw-4q67: plugin name/version (x-plugin-name /
    // x-plugin-version headers or multipart fields) are spliced into the path
    // verbatim; reject traversal at ingest.
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    // The digest the staging pass already computed over the bytes on disk —
    // the same bytes `put_artifact_stream` uploads, so the stored checksum
    // cannot describe anything other than the stored object (#3848).
    let computed_sha256 = digests.sha256.clone();

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
        return Err((StatusCode::CONFLICT, "Plugin version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file — streamed from the staged scratch file, not a heap
    // buffer. `put_artifact_stream` performs the cross-repo write guard itself
    // and unlinks the scratch file on every exit path.
    let storage_key = format!("jetbrains/{}/{}/{}", plugin_name, plugin_version, filename);
    let size_bytes = staged.size_bytes();
    proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;

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
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

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

    // Surface the plugin on the Packages page (#3659), keyed on the plugin id
    // and version from the upload's own parameters, never the filename. The
    // upload carries no plugin description.
    crate::services::package_service::register_published_package(
        &state.db,
        repo.id,
        "jetbrains",
        &plugin_name,
        &plugin_version,
        size_bytes,
        &computed_sha256,
        None,
    )
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
    .map_err(crate::api::handlers::db_err)?;

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

/// Largest a `name` / `version` multipart part may be. Both are short plugin
/// coordinates spliced into a path; anything larger is a malformed envelope,
/// not a plugin name.
const MAX_PLUGIN_FIELD_BYTES: usize = 1024;

/// Stage the plugin file and read its metadata from a `multipart/form-data`
/// body. Returns the spooled archive plus its digests and coordinates.
///
/// Parsing is delegated to `multer` driven straight off the request-body
/// stream — the shape `nuget.rs` and `swift.rs` (#3595 / #3847) already use —
/// and the file part goes to a bounded scratch file through
/// [`proxy_helpers::stage_stream_content_addressed`]. Nothing is ever converted
/// to a string, and nothing is ever held whole in memory.
///
/// The hand-rolled parser this replaces (#3848) converted the whole body with
/// `String::from_utf8_lossy` and then indexed the ORIGINAL byte slice with
/// offsets taken from that copy. A plugin is a zip, so the body is never valid
/// UTF-8 and the two coordinate systems never agreed: every U+FFFD replacement
/// is three bytes, shifting every later offset, and for an invalid-UTF-8 body
/// the `Cow` is a separate allocation whose pointers bear no relation to the
/// body at all. In practice a real plugin drove the offsets past the end of the
/// body and PANICKED the request; short of that, the bounds check's fallback
/// stored the *lossy* bytes — and the SHA-256 was taken over that corruption,
/// so nothing detected it at upload, at download, or in any integrity check.
///
/// The envelope is bounded by `max_upload_size_bytes` (the staging primitive
/// enforces it as the part arrives, 413 mid-stream), and a malformed envelope,
/// a missing `file`/`plugin` part, or a duplicate one is a `400` rather than a
/// silent partial store.
#[allow(clippy::type_complexity)]
async fn stage_plugin_from_multipart(
    state: &SharedState,
    content_type: &str,
    body: Body,
) -> Result<
    (
        proxy_helpers::StagedUpload,
        crate::services::artifact_service::ContentDigests,
        String,
        String,
    ),
    Response,
> {
    let boundary = multer::parse_boundary(content_type).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed multipart/form-data upload: missing boundary",
        )
            .into_response()
    })?;

    let mut constraints = multer::Constraints::new();
    let max_upload_size_bytes = state.config.max_upload_size_bytes;
    if max_upload_size_bytes > 0 {
        constraints =
            constraints.size_limit(multer::SizeLimit::new().whole_stream(max_upload_size_bytes));
    }
    let mut multipart =
        multer::Multipart::with_constraints(body.into_data_stream(), boundary, constraints);

    let bad_request = |e: multer::Error| {
        (
            StatusCode::BAD_REQUEST,
            format!("Malformed multipart/form-data upload: {}", e),
        )
            .into_response()
    };

    let mut archive: Option<(
        proxy_helpers::StagedUpload,
        crate::services::artifact_service::ContentDigests,
    )> = None;
    let mut plugin_name = String::new();
    let mut plugin_version = String::new();

    while let Some(mut field) = multipart.next_field().await.map_err(bad_request)? {
        // `name()`/`file_name()` borrow the field the readers below consume.
        let field_name = field.name().unwrap_or_default().to_string();
        let has_filename = field.file_name().is_some();

        if field_name == "file" || field_name == "plugin" || has_filename {
            if archive.is_some() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Upload carries more than one plugin file part",
                )
                    .into_response());
            }
            archive = Some(proxy_helpers::stage_stream_content_addressed(state, field).await?);
        } else if field_name == "name" {
            plugin_name = read_small_field(&mut field).await?;
        } else if field_name == "version" {
            plugin_version = read_small_field(&mut field).await?;
        }
        // Unread parts are skipped (not accumulated) by `next_field()`.
    }

    let (staged, digests) = archive.ok_or_else(|| {
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

    Ok((staged, digests, plugin_name, plugin_version))
}

/// Read one short metadata part (`name` / `version`) as text.
///
/// Chunked rather than read whole so the cap is enforced as the part arrives,
/// not after it has already been buffered — the same shape `swift.rs` uses for
/// its `metadata` part.
#[allow(clippy::result_large_err)]
async fn read_small_field(field: &mut multer::Field<'_>) -> Result<String, Response> {
    let mut raw: Vec<u8> = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Malformed multipart/form-data upload: {}", e),
        )
            .into_response()
    })? {
        if raw.len().saturating_add(chunk.len()) > MAX_PLUGIN_FIELD_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "multipart part exceeds the {} byte limit",
                    MAX_PLUGIN_FIELD_BYTES
                ),
            )
                .into_response());
        }
        raw.extend_from_slice(&chunk);
    }
    String::from_utf8(raw)
        .map(|s| s.trim().to_string())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "multipart plugin name/version must be valid UTF-8",
            )
                .into_response()
        })
}

#[cfg(test)]
mod tests {

    /// A genuinely binary plugin zip: a real local-file-header signature, a
    /// deflate-shaped payload, and bytes that are invalid UTF-8 on their own
    /// (`0xC3 0x28`, a lone `0xFF`, an unpaired surrogate encoding). An ASCII
    /// fixture passes against the pre-#3848 parser and proves nothing.
    #[cfg(test)]
    fn binary_plugin_zip() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
        v.extend_from_slice(&[0xC3, 0x28, 0xFF, 0xFE, 0xED, 0xA0, 0x80]);
        v.extend_from_slice(b"META-INF/plugin.xml");
        // A stretch of high bytes: each one is a separate invalid sequence, so
        // `from_utf8_lossy` inflates them 1 -> 3 bytes and every offset past
        // here shifts.
        v.extend((0u16..512).map(|i| (128 + (i % 128)) as u8));
        v.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
        v.extend_from_slice(&[0x00, 0xFF, 0x00, 0xFF]);
        v
    }

    /// Build a `multipart/form-data` body by hand so the test controls the
    /// exact bytes on the wire (no client library normalising them).
    #[cfg(test)]
    fn multipart_body(boundary: &str, file: &[u8], name: &str, version: &str) -> bytes::Bytes {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"plugin.zip\"\r\n",
        );
        b.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
        b.extend_from_slice(file);
        b.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        b.extend_from_slice(b"Content-Disposition: form-data; name=\"name\"\r\n\r\n");
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        b.extend_from_slice(b"Content-Disposition: form-data; name=\"version\"\r\n\r\n");
        b.extend_from_slice(version.as_bytes());
        b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        bytes::Bytes::from(b)
    }

    /// #3848: a multipart plugin publish must store the part's bytes VERBATIM.
    ///
    /// The old parser converted the whole body with `String::from_utf8_lossy`
    /// and then indexed the original byte slice with offsets taken from that
    /// copy. A plugin zip is never valid UTF-8, so the two coordinate systems
    /// never agreed (each U+FFFD is three bytes) and, for an invalid-UTF-8
    /// body, the `Cow` was a separate allocation whose pointers bore no
    /// relation to the body at all. The bounds check's fallback then stored the
    /// LOSSY bytes — and the SHA-256 was taken over the corruption, so nothing
    /// detected it at upload, at download, or in any integrity check.
    ///
    /// Publish -> download round trip on a genuinely binary payload, plus the
    /// stored checksum, so a revert fails here rather than at a user's
    /// "invalid zip" install error.
    #[tokio::test]
    async fn test_jetbrains_multipart_publish_preserves_binary_zip_3848() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;
        use sha2::{Digest, Sha256};

        let Some(fx) = tdh::Fixture::setup("local", "jetbrains").await else {
            return;
        };

        let zip = binary_plugin_zip();
        assert!(
            String::from_utf8(zip.clone()).is_err(),
            "the fixture must be invalid UTF-8 or it cannot discriminate"
        );
        let expected_sha = format!("{:x}", Sha256::digest(&zip));

        let boundary = "----AKBoundary3848";
        let body = multipart_body(boundary, &zip, "com.example.binplugin", "2.1.0");

        let (up_status, up_body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!("/{}/plugin/uploadPlugin", fx.repo_key),
                &format!("multipart/form-data; boundary={boundary}"),
                body,
            ),
        )
        .await;

        let (dl_status, dl_body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!(
                "/{}/plugin/download/com.example.binplugin/2.1.0",
                fx.repo_key
            )),
        )
        .await;

        let stored_sha: Option<String> = sqlx::query_scalar(
            "SELECT checksum_sha256 FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(fx.repo_id)
        .fetch_optional(&fx.pool)
        .await
        .expect("read stored checksum");

        fx.teardown().await;

        assert_eq!(
            up_status,
            StatusCode::OK,
            "multipart publish must succeed; body={}",
            String::from_utf8_lossy(&up_body)
        );
        assert_eq!(dl_status, StatusCode::OK, "published plugin must download");
        assert_eq!(
            dl_body.len(),
            zip.len(),
            "stored length must equal the uploaded part's length (a lossy copy \
             inflates every invalid sequence 1 -> 3 bytes)"
        );
        assert_eq!(
            &dl_body[..],
            &zip[..],
            "a publish -> download round trip must return the exact uploaded bytes"
        );
        assert_eq!(
            stored_sha.as_deref().map(str::trim),
            Some(expected_sha.as_str()),
            "the stored checksum must be over the uploaded bytes, not over a \
             corrupted copy of them"
        );
    }

    /// #3848: a malformed multipart envelope is a 400, never a partial store.
    /// The old parser answered a missing `boundary=` with 400 but silently
    /// swallowed the rest — a truncated body or a duplicate file part still
    /// produced a 201 over whatever bytes it managed to slice out.
    #[tokio::test]
    async fn test_jetbrains_multipart_malformed_envelopes_are_400_3848() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        let Some(fx) = tdh::Fixture::setup("local", "jetbrains").await else {
            return;
        };

        let zip = binary_plugin_zip();
        let boundary = "----AKBoundary3848bad";
        let good = multipart_body(boundary, &zip, "com.example.badplugin", "1.0.0");

        // No `boundary=` in the content type.
        let no_boundary = (
            "no boundary",
            "multipart/form-data".to_string(),
            good.clone(),
        );
        // Body cut mid-part: the closing boundary never arrives.
        let truncated = (
            "truncated body",
            format!("multipart/form-data; boundary={boundary}"),
            good.slice(..good.len() / 2),
        );
        // Two file parts: ambiguous, so refuse rather than pick one.
        let duplicated = {
            let mut b: Vec<u8> = Vec::new();
            for _ in 0..2 {
                b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                b.extend_from_slice(
                    b"Content-Disposition: form-data; name=\"file\"; filename=\"p.zip\"\r\n\r\n",
                );
                b.extend_from_slice(&zip);
                b.extend_from_slice(b"\r\n");
            }
            b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            (
                "duplicate file part",
                format!("multipart/form-data; boundary={boundary}"),
                bytes::Bytes::from(b),
            )
        };
        // A part-less envelope: nothing to store.
        let missing_part = {
            let mut b: Vec<u8> = Vec::new();
            b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            b.extend_from_slice(b"Content-Disposition: form-data; name=\"name\"\r\n\r\n");
            b.extend_from_slice(b"com.example.badplugin");
            b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            (
                "missing file part",
                format!("multipart/form-data; boundary={boundary}"),
                bytes::Bytes::from(b),
            )
        };

        let mut observed = Vec::new();
        for (label, ct, body) in [no_boundary, truncated, duplicated, missing_part] {
            let (status, resp) = tdh::send(
                fx.router_with_auth(super::router()),
                tdh::post(format!("/{}/plugin/uploadPlugin", fx.repo_key), &ct, body),
            )
            .await;
            observed.push((label, status, resp));
        }

        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .expect("count artifacts");

        fx.teardown().await;

        for (label, status, resp) in observed {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{label}: a malformed multipart envelope must be refused; body={}",
                String::from_utf8_lossy(&resp)
            );
        }
        assert_eq!(
            rows, 0,
            "no malformed envelope may leave an artifact behind"
        );
    }

    #[tokio::test]
    async fn test_remote_plugin_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "jetbrains").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/plugin/download/my.plugin/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/plugin/download/my.plugin/1.0.0",
                key = fx.repo_key
            )),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from streamed remote download, got {status}");
        }
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        teardown().await;
    }
    use super::*;

    #[test]
    fn test_upload_artifact_path_traversal_rejected() {
        // GHSA-vcq6-8hxw-4q67: x-plugin-name / x-plugin-version headers were
        // spliced into the artifact path verbatim. upload_plugin now routes
        // the composed path through validate_artifact_path.
        for (name, version) in [("../evil", "1.0.0"), ("my.plugin", "1.0/../../x")] {
            let filename = format!("{}-{}.zip", name, version);
            let path = format!("{}/{}/{}", name, version, filename);
            assert!(
                crate::services::upload_service::validate_artifact_path(&path).is_err(),
                "composed path from plugin {name:?}@{version:?} must be rejected"
            );
        }
        let ok = format!("{}/{}/{}", "my.plugin", "1.0.0", "my.plugin-1.0.0.zip");
        assert!(crate::services::upload_service::validate_artifact_path(&ok).is_ok());
    }

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // xml_escape
    // -----------------------------------------------------------------------

    #[test]
    fn test_xml_escape_no_special() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    #[test]
    fn test_xml_escape_ampersand() {
        assert_eq!(xml_escape("A & B"), "A &amp; B");
    }

    #[test]
    fn test_xml_escape_less_than() {
        assert_eq!(xml_escape("a < b"), "a &lt; b");
    }

    #[test]
    fn test_xml_escape_greater_than() {
        assert_eq!(xml_escape("a > b"), "a &gt; b");
    }

    #[test]
    fn test_xml_escape_quotes() {
        assert_eq!(xml_escape("say \"hello\""), "say &quot;hello&quot;");
    }

    #[test]
    fn test_xml_escape_apostrophe() {
        assert_eq!(xml_escape("it's"), "it&apos;s");
    }

    #[test]
    fn test_xml_escape_all_special() {
        assert_eq!(
            xml_escape("<tag attr=\"val\" & 'x'>"),
            "&lt;tag attr=&quot;val&quot; &amp; &apos;x&apos;&gt;"
        );
    }

    #[test]
    fn test_xml_escape_empty() {
        assert_eq!(xml_escape(""), "");
    }

    // -----------------------------------------------------------------------
    // stage_plugin_from_multipart
    // -----------------------------------------------------------------------

    /// A DB-free `SharedState` for the multipart-staging cases: the staging
    /// primitive only reads `storage_path` and `max_upload_size_bytes` from the
    /// config and never touches the database, so a lazily-connecting pool is
    /// enough. The temp dir is the scratch root; the staged file is unlinked on
    /// drop either way.
    fn staging_state() -> (crate::api::SharedState, std::path::PathBuf) {
        use crate::api::handlers::test_db_helpers as tdh;
        let dir = std::env::temp_dir().join(format!("ak-jb-stage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let state = tdh::build_state(tdh::lazy_pool(), dir.to_str().unwrap());
        (state, dir)
    }

    #[tokio::test]
    async fn test_stage_plugin_from_multipart_valid() {
        let (state, dir) = staging_state();
        let boundary = "myboundary";
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"name\"\r\n\
             \r\n\
             my-plugin\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"version\"\r\n\
             \r\n\
             1.0.0\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"plugin.zip\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             FILECONTENT\r\n\
             --{boundary}--\r\n",
            boundary = boundary,
        );
        let result =
            super::stage_plugin_from_multipart(&state, &content_type, Body::from(body)).await;
        let ok = result.is_ok();
        let coords = result.ok().map(|(staged, digests, name, version)| {
            (staged.size_bytes(), digests.sha256.clone(), name, version)
        });
        let _ = std::fs::remove_dir_all(&dir);

        assert!(ok);
        let (size, sha256, name, version) = coords.unwrap();
        assert_eq!(name, "my-plugin");
        assert_eq!(version, "1.0.0");
        assert_eq!(size, "FILECONTENT".len() as i64);
        assert_eq!(sha256.len(), 64);
    }

    #[tokio::test]
    async fn test_stage_plugin_from_multipart_missing_boundary() {
        let (state, dir) = staging_state();
        let result = super::stage_plugin_from_multipart(
            &state,
            "multipart/form-data",
            Body::from("some body"),
        )
        .await;
        let is_err = result.is_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(is_err);
    }

    #[tokio::test]
    async fn test_stage_plugin_from_multipart_no_file() {
        let (state, dir) = staging_state();
        let boundary = "boundary";
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"name\"\r\n\
             \r\n\
             my-plugin\r\n\
             --{boundary}--\r\n",
            boundary = boundary,
        );
        let result =
            super::stage_plugin_from_multipart(&state, &content_type, Body::from(body)).await;
        let is_err = result.is_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(is_err);
    }

    #[tokio::test]
    async fn test_stage_plugin_from_multipart_defaults() {
        let (state, dir) = staging_state();
        let boundary = "b123";
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        // Only file, no name or version fields
        let body = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"plugin.zip\"\r\n\
             \r\n\
             DATA\r\n\
             --{boundary}--\r\n",
            boundary = boundary,
        );
        let result =
            super::stage_plugin_from_multipart(&state, &content_type, Body::from(body)).await;
        let coords = result.ok().map(|(_, _, name, version)| (name, version));
        let _ = std::fs::remove_dir_all(&dir);

        let (name, version) = coords.expect("a file-only envelope must stage");
        assert_eq!(name, "unknown-plugin");
        assert_eq!(version, "0.0.0");
    }

    #[tokio::test]
    async fn test_stage_plugin_from_multipart_quoted_boundary() {
        let (state, dir) = staging_state();
        let content_type = "multipart/form-data; boundary=\"myboundary\"";
        let body: &[u8] = b"--myboundary\r\nContent-Disposition: form-data; name=\"plugin\"; filename=\"p.zip\"\r\n\r\nFILE\r\n--myboundary--\r\n";
        let result =
            super::stage_plugin_from_multipart(&state, content_type, Body::from(body)).await;
        let is_ok = result.is_ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(is_ok);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/jetbrains".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // Plugin filename and paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_filename() {
        let name = "my-plugin";
        let version = "2.1.0";
        let filename = format!("{}-{}.zip", name, version);
        assert_eq!(filename, "my-plugin-2.1.0.zip");
    }

    #[test]
    fn test_plugin_artifact_path() {
        let name = "my-plugin";
        let version = "2.1.0";
        let filename = format!("{}-{}.zip", name, version);
        let artifact_path = format!("{}/{}/{}", name, version, filename);
        assert_eq!(artifact_path, "my-plugin/2.1.0/my-plugin-2.1.0.zip");
    }

    #[test]
    fn test_plugin_storage_key() {
        let name = "intellij-rust";
        let version = "0.4.0";
        let filename = format!("{}-{}.zip", name, version);
        let storage_key = format!("jetbrains/{}/{}/{}", name, version, filename);
        assert_eq!(
            storage_key,
            "jetbrains/intellij-rust/0.4.0/intellij-rust-0.4.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        use sha2::{Digest, Sha256};

        let data = b"jetbrains plugin file";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Plugin download URL
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_url_format() {
        let repo_key = "jb-hosted";
        let name = "my-plugin";
        let version = "1.0.0";
        let url = format!(
            "/jetbrains/{}/plugin/download/{}/{}",
            repo_key, name, version
        );
        assert_eq!(url, "/jetbrains/jb-hosted/plugin/download/my-plugin/1.0.0");
    }

    // -----------------------------------------------------------------------
    // Plugin metadata JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_metadata() {
        let metadata = serde_json::json!({
            "plugin_id": "my-plugin",
            "filename": "my-plugin-1.0.0.zip",
        });
        assert_eq!(metadata["plugin_id"], "my-plugin");
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_jetbrains_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "jetbrains").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/plugins/list/"),
            format!("/{k}/plugins/1/updates"),
            format!("/{k}/plugin/details/name"),
            format!("/{k}/plugin/download/name/1.0.0"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// #3659: the native publish path must register the package catalog row.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// A plugin upload must register the catalog row under the plugin id and
    /// version carried by the request, not the generated filename.
    #[tokio::test]
    async fn plugin_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "jetbrains").await else {
            return;
        };
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/plugin/uploadPlugin", fx.repo_key))
            .header("x-plugin-name", "com.example.plugin")
            .header("x-plugin-version", "2.4.1")
            .body(axum::body::Body::from("plugin-zip-bytes"))
            .unwrap();
        let (status, body) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "plugin upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "com.example.plugin").await;
        fx.teardown().await;

        let row = row.expect("a jetbrains upload must write a packages row (#3659)");
        assert_eq!(row.version, "2.4.1");
        assert_eq!(row.versions, vec!["2.4.1".to_string()]);
    }
}
