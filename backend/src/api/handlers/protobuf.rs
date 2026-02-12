//! Protobuf/BSR (Buf Schema Registry) format handlers.
//!
//! Implements Connect RPC endpoints compatible with `buf push`, `buf pull`,
//! and the BSR module/commit/label services.
//!
//! Routes are mounted at `/protobuf/{repo_key}/...`:
//!   POST /:repo_key/buf.registry.module.v1.ModuleService/GetModules
//!   POST /:repo_key/buf.registry.module.v1.ModuleService/CreateModules
//!   POST /:repo_key/buf.registry.module.v1.CommitService/GetCommits
//!   POST /:repo_key/buf.registry.module.v1.CommitService/ListCommits
//!   POST /:repo_key/buf.registry.module.v1beta1.UploadService/Upload
//!   POST /:repo_key/buf.registry.module.v1beta1.DownloadService/Download
//!   POST /:repo_key/buf.registry.module.v1.LabelService/GetLabels
//!   POST /:repo_key/buf.registry.module.v1.LabelService/CreateOrUpdateLabels
//!   POST /:repo_key/buf.registry.module.v1.GraphService/GetGraph
//!   POST /:repo_key/buf.registry.module.v1.ResourceService/GetResources

use std::io::{Read, Write};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:repo_key/buf.registry.module.v1.ModuleService/GetModules",
            post(get_modules),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.ModuleService/CreateModules",
            post(create_modules),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.CommitService/GetCommits",
            post(get_commits),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.CommitService/ListCommits",
            post(list_commits),
        )
        .route(
            "/:repo_key/buf.registry.module.v1beta1.UploadService/Upload",
            post(upload),
        )
        .route(
            "/:repo_key/buf.registry.module.v1beta1.DownloadService/Download",
            post(download),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.LabelService/GetLabels",
            post(get_labels),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.LabelService/CreateOrUpdateLabels",
            post(create_or_update_labels),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.GraphService/GetGraph",
            post(get_graph),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.ResourceService/GetResources",
            post(get_resources),
        )
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024)) // 256 MB
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ModuleRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    module: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ResourceRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ModuleInfo {
    id: String,
    owner_id: String,
    name: String,
    create_time: String,
    update_time: String,
    state: String,
    default_label_name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CommitInfo {
    id: String,
    create_time: String,
    owner_id: String,
    module_id: String,
    digest: CommitDigest,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CommitDigest {
    #[serde(rename = "type")]
    digest_type: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LabelRef {
    name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LabelInfo {
    id: String,
    name: String,
    commit_id: String,
    create_time: String,
    update_time: String,
}

// -- GetModules
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetModulesRequest {
    #[serde(default)]
    module_refs: Vec<ModuleRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetModulesResponse {
    modules: Vec<ModuleInfo>,
}

// -- GetCommits
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetCommitsRequest {
    #[serde(default)]
    resource_refs: Vec<ResourceRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetCommitsResponse {
    commits: Vec<CommitInfo>,
}

// -- ListCommits
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListCommitsRequest {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    page_size: Option<i64>,
    #[serde(default)]
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListCommitsResponse {
    commits: Vec<CommitInfo>,
    next_page_token: String,
}

// -- Upload
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadRequest {
    #[serde(default)]
    contents: Vec<UploadContent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadContent {
    module_ref: ModuleRef,
    #[serde(default)]
    files: Vec<UploadFile>,
    #[serde(default)]
    dep_refs: Vec<ModuleRef>,
    #[serde(default)]
    label_refs: Vec<LabelRef>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UploadFile {
    path: String,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadResponse {
    commits: Vec<CommitInfo>,
}

// -- Download
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadRequest {
    #[serde(default)]
    values: Vec<DownloadValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadValue {
    resource_ref: ResourceRef,
    #[serde(default)]
    #[allow(dead_code)]
    file_types: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadResponse {
    contents: Vec<DownloadContent>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadContent {
    commit: CommitInfo,
    files: Vec<DownloadFile>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DownloadFile {
    path: String,
    content: String,
}

// -- GetLabels
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetLabelsRequest {
    #[serde(default)]
    label_refs: Vec<LabelResourceRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelResourceRef {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetLabelsResponse {
    labels: Vec<LabelInfo>,
}

// -- CreateOrUpdateLabels
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrUpdateLabelsRequest {
    #[serde(default)]
    values: Vec<CreateLabelValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateLabelValue {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    module: Option<String>,
    name: String,
    commit_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrUpdateLabelsResponse {
    labels: Vec<LabelInfo>,
}

// -- GetGraph
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetGraphRequest {
    #[serde(default)]
    resource_refs: Vec<ResourceRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdge {
    from_commit_id: String,
    to_commit_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetGraphResponse {
    commits: Vec<CommitInfo>,
    edges: Vec<GraphEdge>,
}

// -- GetResources
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetResourcesRequest {
    #[serde(default)]
    resource_refs: Vec<ResourceRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceInfo {
    module: ModuleInfo,
    commit: CommitInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetResourcesResponse {
    resources: Vec<ResourceInfo>,
}

// ---------------------------------------------------------------------------
// Connect RPC error helper
// ---------------------------------------------------------------------------

fn connect_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({ "code": code, "message": message });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
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

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|t| t.to_string())
}

/// Authenticate via Basic auth (username:password) or Bearer token (API key).
/// Returns user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));

    // Try Bearer token first (API key)
    if let Some(token) = extract_bearer_token(headers) {
        let user = auth_service.validate_api_token(&token).await.map_err(|_| {
            connect_error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Invalid API token",
            )
        })?;
        return Ok(user.id);
    }

    // Fall back to Basic auth
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        connect_error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Authentication required. Provide Basic or Bearer credentials.",
        )
    })?;

    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            connect_error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Invalid credentials",
            )
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

async fn resolve_protobuf_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let row = sqlx::query(
        r#"SELECT id, storage_path, format::text AS format, repo_type::text AS repo_type, upstream_url
        FROM repositories WHERE key = $1"#,
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| {
        connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Repository '{}' not found", repo_key),
        )
    })?;

    let fmt: String = row.get("format");
    if fmt.to_lowercase() != "protobuf" {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            &format!(
                "Repository '{}' is not a Protobuf repository (format: {})",
                repo_key, fmt
            ),
        ));
    }

    Ok(RepoInfo {
        id: row.get("id"),
        storage_path: row.get("storage_path"),
        repo_type: row.get("repo_type"),
        upstream_url: row.get("upstream_url"),
    })
}

// ---------------------------------------------------------------------------
// Helper: module name from ref
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
fn module_name_from_ref(module_ref: &ModuleRef) -> Result<String, Response> {
    match (&module_ref.owner, &module_ref.module) {
        (Some(owner), Some(module)) => Ok(format!("{}/{}", owner, module)),
        _ => {
            if let Some(id) = &module_ref.id {
                Ok(id.clone())
            } else {
                Err(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "Module reference must specify owner/module or id",
                ))
            }
        }
    }
}

#[allow(clippy::result_large_err)]
fn module_name_from_resource_ref(resource_ref: &ResourceRef) -> Result<String, Response> {
    match (&resource_ref.owner, &resource_ref.module) {
        (Some(owner), Some(module)) => Ok(format!("{}/{}", owner, module)),
        _ => {
            if let Some(id) = &resource_ref.id {
                Ok(id.clone())
            } else {
                Err(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "Resource reference must specify owner/module or id",
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build/extract tar.gz bundles
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
fn build_bundle(files: &[UploadFile]) -> Result<Vec<u8>, Response> {
    let mut tar_builder = tar::Builder::new(Vec::new());

    for file in files {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&file.content)
            .map_err(|e| {
                connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    &format!("Invalid base64 content for file '{}': {}", file.path, e),
                )
            })?;

        let mut header = tar::Header::new_gnu();
        header.set_path(&file.path).map_err(|e| {
            connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                &format!("Invalid file path '{}': {}", file.path, e),
            )
        })?;
        header.set_size(decoded.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        tar_builder
            .append(&header, decoded.as_slice())
            .map_err(|e| {
                connect_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    &format!("Failed to build tar archive: {}", e),
                )
            })?;
    }

    let tar_data = tar_builder.into_inner().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Failed to finalize tar archive: {}", e),
        )
    })?;

    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(&tar_data).map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Failed to compress bundle: {}", e),
        )
    })?;

    gz_encoder.finish().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Failed to finalize gzip: {}", e),
        )
    })
}

#[allow(clippy::result_large_err)]
fn extract_files_from_bundle(data: &[u8]) -> Result<Vec<DownloadFile>, Response> {
    let gz_decoder = GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz_decoder);

    let mut files = Vec::new();

    for entry_result in archive.entries().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Failed to read tar archive: {}", e),
        )
    })? {
        let mut entry = entry_result.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Failed to read tar entry: {}", e),
            )
        })?;

        let path = entry
            .path()
            .map_err(|e| {
                connect_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    &format!("Failed to read entry path: {}", e),
                )
            })?
            .to_string_lossy()
            .to_string();

        let mut content_bytes = Vec::new();
        entry.read_to_end(&mut content_bytes).map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Failed to read entry content: {}", e),
            )
        })?;

        let encoded = base64::engine::general_purpose::STANDARD.encode(&content_bytes);

        files.push(DownloadFile {
            path,
            content: encoded,
        });
    }

    Ok(files)
}

// ---------------------------------------------------------------------------
// Helper: label management
// ---------------------------------------------------------------------------

/// Load the label index for a module. Returns a map of label_name -> commit_digest.
async fn load_label_index(
    db: &PgPool,
    repo_id: uuid::Uuid,
    module_name: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    let label_path = format!("modules/{}/_labels", module_name);

    let row = sqlx::query(
        r#"SELECT am.metadata
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.path = $2
          AND a.is_deleted = false
        LIMIT 1"#,
    )
    .bind(repo_id)
    .bind(&label_path)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Database error loading labels: {}", e),
        )
    })?;

    match row {
        Some(row) => {
            let metadata: serde_json::Value = row.get("metadata");
            Ok(metadata
                .get("labels")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default())
        }
        None => Ok(serde_json::Map::new()),
    }
}

/// Save the label index for a module. Creates or updates the _labels artifact.
async fn save_label_index(
    db: &PgPool,
    repo_id: uuid::Uuid,
    module_name: &str,
    labels: &serde_json::Map<String, serde_json::Value>,
    user_id: uuid::Uuid,
) -> Result<(), Response> {
    let label_path = format!("modules/{}/_labels", module_name);
    let metadata = serde_json::json!({ "labels": labels });

    // Check if the label artifact already exists
    let existing_id: Option<uuid::Uuid> = sqlx::query(
        r#"SELECT id FROM artifacts
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        LIMIT 1"#,
    )
    .bind(repo_id)
    .bind(&label_path)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Database error: {}", e),
        )
    })?
    .map(|row| row.get("id"));

    let artifact_id = match existing_id {
        Some(id) => id,
        None => {
            // Create label index artifact
            let row = sqlx::query(
                r#"INSERT INTO artifacts (
                    repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key, uploaded_by
                )
                VALUES ($1, $2, $3, '_labels', 0, 'none', 'application/json', $4, $5)
                RETURNING id"#,
            )
            .bind(repo_id)
            .bind(&label_path)
            .bind(module_name)
            .bind(&label_path)
            .bind(user_id)
            .fetch_one(db)
            .await
            .map_err(|e| {
                connect_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    &format!("Database error creating label index: {}", e),
                )
            })?;
            row.get("id")
        }
    };

    // Upsert metadata with the label map
    sqlx::query(
        r#"INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'protobuf', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2"#,
    )
    .bind(artifact_id)
    .bind(&metadata)
    .execute(db)
    .await
    .map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Database error saving labels: {}", e),
        )
    })?;

    Ok(())
}

/// Update labels for a module, mapping each label name to a commit digest.
async fn update_labels(
    db: &PgPool,
    repo_id: uuid::Uuid,
    module_name: &str,
    label_refs: &[LabelRef],
    commit_digest: &str,
    user_id: uuid::Uuid,
) -> Result<(), Response> {
    if label_refs.is_empty() {
        return Ok(());
    }

    let mut labels = load_label_index(db, repo_id, module_name).await?;

    for label_ref in label_refs {
        labels.insert(
            label_ref.name.clone(),
            serde_json::Value::String(commit_digest.to_string()),
        );
    }

    save_label_index(db, repo_id, module_name, &labels, user_id).await
}

/// Resolve a label to a commit digest for a given module.
async fn resolve_commit_by_label(
    db: &PgPool,
    repo_id: uuid::Uuid,
    module_name: &str,
    label: &str,
) -> Option<String> {
    let labels = load_label_index(db, repo_id, module_name).await.ok()?;
    labels
        .get(label)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Helper: build ModuleInfo / CommitInfo from artifact rows
// ---------------------------------------------------------------------------

fn build_module_info_from_row(row: &sqlx::postgres::PgRow) -> ModuleInfo {
    let id: uuid::Uuid = row.get("id");
    let name: String = row.get("name");
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let uploaded_by: Option<uuid::Uuid> = row.get("uploaded_by");

    ModuleInfo {
        id: id.to_string(),
        owner_id: uploaded_by.map(|u| u.to_string()).unwrap_or_default(),
        name,
        create_time: created_at.to_rfc3339(),
        update_time: updated_at.to_rfc3339(),
        state: "ACTIVE".to_string(),
        default_label_name: "main".to_string(),
    }
}

fn build_commit_info_from_row(row: &sqlx::postgres::PgRow) -> CommitInfo {
    let id: uuid::Uuid = row.get("id");
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let uploaded_by: Option<uuid::Uuid> = row.get("uploaded_by");
    let name: String = row.get("name");
    let checksum: String = row.get("checksum_sha256");
    let version: Option<String> = row.get("version");

    CommitInfo {
        id: id.to_string(),
        create_time: created_at.to_rfc3339(),
        owner_id: uploaded_by.map(|u| u.to_string()).unwrap_or_default(),
        module_id: name,
        digest: CommitDigest {
            digest_type: "sha256".to_string(),
            value: version.unwrap_or(checksum),
        },
    }
}

// ---------------------------------------------------------------------------
// POST GetModules
// ---------------------------------------------------------------------------

async fn get_modules(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<GetModulesRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut modules = Vec::new();

    for module_ref in &body.module_refs {
        let module_name = module_name_from_ref(module_ref)?;

        let row = sqlx::query(
            r#"SELECT DISTINCT ON (name)
                id, name, created_at, updated_at, uploaded_by
            FROM artifacts
            WHERE repository_id = $1
              AND name = $2
              AND is_deleted = false
            ORDER BY name, created_at DESC
            LIMIT 1"#,
        )
        .bind(repo.id)
        .bind(&module_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if let Some(row) = row {
            modules.push(build_module_info_from_row(&row));
        }
    }

    let resp = GetModulesResponse { modules };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST CreateModules
// ---------------------------------------------------------------------------

async fn create_modules(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // CreateModules is implicitly handled during upload. Return the request
    // echoed back as acknowledgement (modules are created on first push).
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST GetCommits
// ---------------------------------------------------------------------------

async fn get_commits(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<GetCommitsRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut commits = Vec::new();

    for resource_ref in &body.resource_refs {
        let module_name = module_name_from_resource_ref(resource_ref)?;

        // If a label is specified, resolve it to a commit digest first
        let digest_filter = if let Some(label) = &resource_ref.label {
            resolve_commit_by_label(&state.db, repo.id, &module_name, label).await
        } else {
            resource_ref.id.clone()
        };

        let row = if let Some(digest) = &digest_filter {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND version = $3
                  AND is_deleted = false
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .bind(digest)
            .fetch_optional(&state.db)
            .await
        } else {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND is_deleted = false
                ORDER BY created_at DESC
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .fetch_optional(&state.db)
            .await
        };

        let row = row.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if let Some(row) = row {
            commits.push(build_commit_info_from_row(&row));
        }
    }

    let resp = GetCommitsResponse { commits };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST ListCommits
// ---------------------------------------------------------------------------

async fn list_commits(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<ListCommitsRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let module_name = match (&body.owner, &body.module) {
        (Some(owner), Some(module)) => format!("{}/{}", owner, module),
        _ => {
            return Err(connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "owner and module are required for ListCommits",
            ));
        }
    };

    let page_size = body.page_size.unwrap_or(50).min(250);
    let offset: i64 = body
        .page_token
        .as_deref()
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or(0);

    let rows = sqlx::query(
        r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4"#,
    )
    .bind(repo.id)
    .bind(&module_name)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("Database error: {}", e),
        )
    })?;

    let commits: Vec<CommitInfo> = rows.iter().map(build_commit_info_from_row).collect();

    let next_page_token = if commits.len() as i64 >= page_size {
        (offset + page_size).to_string()
    } else {
        String::new()
    };

    let resp = ListCommitsResponse {
        commits,
        next_page_token,
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST Upload (buf push)
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<UploadRequest>,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let mut result_commits = Vec::new();

    for content in &body.contents {
        let module_name = module_name_from_ref(&content.module_ref)?;

        // Decode and hash all files to compute the commit digest
        let mut hasher = Sha256::new();
        for file in &content.files {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&file.content)
                .map_err(|e| {
                    connect_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_argument",
                        &format!("Invalid base64 content for file '{}': {}", file.path, e),
                    )
                })?;
            hasher.update(file.path.as_bytes());
            hasher.update(&decoded);
        }
        let commit_digest = format!("{:x}", hasher.finalize_reset());

        // Check for duplicate (idempotent)
        let existing = sqlx::query(
            r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
            FROM artifacts
            WHERE repository_id = $1
              AND name = $2
              AND version = $3
              AND is_deleted = false
            LIMIT 1"#,
        )
        .bind(repo.id)
        .bind(&module_name)
        .bind(&commit_digest)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if let Some(existing_row) = existing {
            let commit = build_commit_info_from_row(&existing_row);
            result_commits.push(commit);

            // Still update labels if provided
            update_labels(
                &state.db,
                repo.id,
                &module_name,
                &content.label_refs,
                &commit_digest,
                user_id,
            )
            .await?;

            continue;
        }

        // Build tar.gz bundle from files
        let bundle = build_bundle(&content.files)?;
        let bundle_bytes = Bytes::from(bundle);
        let size_bytes = bundle_bytes.len() as i64;

        // Store via StorageBackend
        let storage_key = format!("modules/{}/commits/{}", module_name, commit_digest);
        let storage = FilesystemStorage::new(&repo.storage_path);
        storage.put(&storage_key, bundle_bytes).await.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Storage error: {}", e),
            )
        })?;

        let artifact_path = format!("modules/{}/commits/{}", module_name, commit_digest);

        // Insert artifact record
        let row = sqlx::query(
            r#"INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, name, version, created_at, updated_at, uploaded_by, checksum_sha256"#,
        )
        .bind(repo.id)
        .bind(&artifact_path)
        .bind(&module_name)
        .bind(&commit_digest)
        .bind(size_bytes)
        .bind(&commit_digest)
        .bind("application/gzip")
        .bind(&storage_key)
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        let artifact_id: uuid::Uuid = row.get("id");

        // Build metadata including dependency refs
        let dep_names: Vec<String> = content
            .dep_refs
            .iter()
            .filter_map(|d| match (&d.owner, &d.module) {
                (Some(o), Some(m)) => Some(format!("{}/{}", o, m)),
                _ => d.id.clone(),
            })
            .collect();

        let protobuf_metadata = serde_json::json!({
            "module": module_name,
            "commitDigest": commit_digest,
            "fileCount": content.files.len(),
            "dependencies": dep_names,
        });

        // Store metadata
        let _ = sqlx::query(
            r#"INSERT INTO artifact_metadata (artifact_id, format, metadata)
            VALUES ($1, 'protobuf', $2)
            ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2"#,
        )
        .bind(artifact_id)
        .bind(&protobuf_metadata)
        .execute(&state.db)
        .await;

        // Update labels (default to "main" if none provided)
        let mut effective_labels = content.label_refs.clone();
        if effective_labels.is_empty() {
            effective_labels.push(LabelRef {
                name: "main".to_string(),
            });
        }
        update_labels(
            &state.db,
            repo.id,
            &module_name,
            &effective_labels,
            &commit_digest,
            user_id,
        )
        .await?;

        // Update repository timestamp
        let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
            .bind(repo.id)
            .execute(&state.db)
            .await;

        let commit = build_commit_info_from_row(&row);
        result_commits.push(commit);

        info!(
            "Protobuf upload: module {} commit {} to repo {}",
            module_name, commit_digest, repo_key
        );
    }

    let resp = UploadResponse {
        commits: result_commits,
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST Download (buf pull)
// ---------------------------------------------------------------------------

async fn download(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<DownloadRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut contents = Vec::new();

    for value in &body.values {
        let module_name = module_name_from_resource_ref(&value.resource_ref)?;

        // Resolve commit digest: prefer label, then direct id, then latest
        let commit_digest = if let Some(label) = &value.resource_ref.label {
            resolve_commit_by_label(&state.db, repo.id, &module_name, label).await
        } else {
            value.resource_ref.id.clone()
        };

        // Fetch the artifact
        let artifact_row = if let Some(digest) = &commit_digest {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by,
                    checksum_sha256, storage_key
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND version = $3
                  AND is_deleted = false
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .bind(digest)
            .fetch_optional(&state.db)
            .await
        } else {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by,
                    checksum_sha256, storage_key
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND is_deleted = false
                ORDER BY created_at DESC
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .fetch_optional(&state.db)
            .await
        };

        let artifact_row = artifact_row.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        let artifact_row = match artifact_row {
            Some(row) => row,
            None => {
                // Try proxy for remote repos
                if repo.repo_type == "remote" {
                    if let (Some(upstream_url), Some(proxy)) =
                        (&repo.upstream_url, &state.proxy_service)
                    {
                        let digest = commit_digest.as_deref().unwrap_or("latest");
                        let upstream_path = format!("modules/{}/commits/{}", module_name, digest);
                        let (bundle_data, _content_type) = proxy_helpers::proxy_fetch(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &upstream_path,
                        )
                        .await?;

                        let files = extract_files_from_bundle(&bundle_data)?;
                        let commit = CommitInfo {
                            id: digest.to_string(),
                            create_time: chrono::Utc::now().to_rfc3339(),
                            owner_id: String::new(),
                            module_id: module_name.clone(),
                            digest: CommitDigest {
                                digest_type: "sha256".to_string(),
                                value: digest.to_string(),
                            },
                        };
                        contents.push(DownloadContent { commit, files });
                        continue;
                    }
                }

                // Virtual repo: try each member in priority order
                if repo.repo_type == "virtual" {
                    let db = state.db.clone();
                    let digest = commit_digest.as_deref().unwrap_or("latest").to_string();
                    let upstream_path = format!("modules/{}/commits/{}", module_name, digest);
                    let mname = module_name.clone();

                    let (bundle_data, _content_type) = proxy_helpers::resolve_virtual_download(
                        &state.db,
                        state.proxy_service.as_deref(),
                        repo.id,
                        &upstream_path,
                        |member_id, storage_path| {
                            let db = db.clone();
                            let path = format!("modules/{}/commits/{}", mname, digest);
                            async move {
                                proxy_helpers::local_fetch_by_path(
                                    &db,
                                    member_id,
                                    &storage_path,
                                    &path,
                                )
                                .await
                            }
                        },
                    )
                    .await?;

                    let files = extract_files_from_bundle(&bundle_data)?;
                    let commit = CommitInfo {
                        id: digest.clone(),
                        create_time: chrono::Utc::now().to_rfc3339(),
                        owner_id: String::new(),
                        module_id: module_name.clone(),
                        digest: CommitDigest {
                            digest_type: "sha256".to_string(),
                            value: digest,
                        },
                    };
                    contents.push(DownloadContent { commit, files });
                    continue;
                }

                return Err(connect_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    &format!("Module '{}' not found", module_name),
                ));
            }
        };

        // Read bundle from local storage
        let storage_key: String = artifact_row.get("storage_key");
        let storage = FilesystemStorage::new(&repo.storage_path);
        let bundle_data = storage.get(&storage_key).await.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Storage error: {}", e),
            )
        })?;

        let files = extract_files_from_bundle(&bundle_data)?;
        let commit = build_commit_info_from_row(&artifact_row);

        // Record download
        let artifact_id: uuid::Uuid = artifact_row.get("id");
        let _ = sqlx::query(
            "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        )
        .bind(artifact_id)
        .execute(&state.db)
        .await;

        contents.push(DownloadContent { commit, files });
    }

    let resp = DownloadResponse { contents };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST GetLabels
// ---------------------------------------------------------------------------

async fn get_labels(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<GetLabelsRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut labels = Vec::new();

    for label_ref in &body.label_refs {
        let module_name = match (&label_ref.owner, &label_ref.module) {
            (Some(owner), Some(module)) => format!("{}/{}", owner, module),
            _ => continue,
        };

        let label_index = load_label_index(&state.db, repo.id, &module_name).await?;

        if let Some(label_name) = &label_ref.label {
            // Return specific label
            if let Some(digest_val) = label_index.get(label_name) {
                let digest = digest_val.as_str().unwrap_or_default();
                let now = chrono::Utc::now().to_rfc3339();
                labels.push(LabelInfo {
                    id: format!("{}:{}:{}", module_name, label_name, digest),
                    name: label_name.clone(),
                    commit_id: digest.to_string(),
                    create_time: now.clone(),
                    update_time: now,
                });
            }
        } else {
            // Return all labels for the module
            let now = chrono::Utc::now().to_rfc3339();
            for (name, digest_val) in &label_index {
                let digest = digest_val.as_str().unwrap_or_default();
                labels.push(LabelInfo {
                    id: format!("{}:{}:{}", module_name, name, digest),
                    name: name.clone(),
                    commit_id: digest.to_string(),
                    create_time: now.clone(),
                    update_time: now.clone(),
                });
            }
        }
    }

    let resp = GetLabelsResponse { labels };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST CreateOrUpdateLabels
// ---------------------------------------------------------------------------

async fn create_or_update_labels(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreateOrUpdateLabelsRequest>,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let mut labels = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    for value in &body.values {
        let module_name = match (&value.owner, &value.module) {
            (Some(owner), Some(module)) => format!("{}/{}", owner, module),
            _ => {
                return Err(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "owner and module are required for label creation",
                ));
            }
        };

        // Verify the commit exists
        let commit_exists = sqlx::query(
            r#"SELECT id FROM artifacts
            WHERE repository_id = $1
              AND name = $2
              AND version = $3
              AND is_deleted = false
            LIMIT 1"#,
        )
        .bind(repo.id)
        .bind(&module_name)
        .bind(&value.commit_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if commit_exists.is_none() {
            return Err(connect_error(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!(
                    "Commit '{}' not found for module '{}'",
                    value.commit_id, module_name
                ),
            ));
        }

        update_labels(
            &state.db,
            repo.id,
            &module_name,
            &[LabelRef {
                name: value.name.clone(),
            }],
            &value.commit_id,
            user_id,
        )
        .await?;

        labels.push(LabelInfo {
            id: format!("{}:{}:{}", module_name, value.name, value.commit_id),
            name: value.name.clone(),
            commit_id: value.commit_id.clone(),
            create_time: now.clone(),
            update_time: now.clone(),
        });
    }

    let resp = CreateOrUpdateLabelsResponse { labels };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST GetGraph
// ---------------------------------------------------------------------------

async fn get_graph(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<GetGraphRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut commits = Vec::new();
    let mut edges = Vec::new();

    for resource_ref in &body.resource_refs {
        let module_name = module_name_from_resource_ref(resource_ref)?;

        // Resolve the target commit
        let commit_digest = if let Some(label) = &resource_ref.label {
            resolve_commit_by_label(&state.db, repo.id, &module_name, label).await
        } else {
            resource_ref.id.clone()
        };

        // Fetch the artifact and its metadata for dependency graph
        let row = if let Some(digest) = &commit_digest {
            sqlx::query(
                r#"SELECT a.id, a.name, a.version, a.created_at, a.updated_at,
                    a.uploaded_by, a.checksum_sha256, am.metadata
                FROM artifacts a
                LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
                WHERE a.repository_id = $1
                  AND a.name = $2
                  AND a.version = $3
                  AND a.is_deleted = false
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .bind(digest)
            .fetch_optional(&state.db)
            .await
        } else {
            sqlx::query(
                r#"SELECT a.id, a.name, a.version, a.created_at, a.updated_at,
                    a.uploaded_by, a.checksum_sha256, am.metadata
                FROM artifacts a
                LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
                WHERE a.repository_id = $1
                  AND a.name = $2
                  AND a.is_deleted = false
                ORDER BY a.created_at DESC
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .fetch_optional(&state.db)
            .await
        };

        let row = row.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if let Some(row) = row {
            let commit = build_commit_info_from_row(&row);
            let commit_id = commit.id.clone();

            // Extract dependency edges from metadata
            let metadata: Option<serde_json::Value> = row.get("metadata");
            if let Some(meta) = metadata {
                if let Some(deps) = meta.get("dependencies").and_then(|d| d.as_array()) {
                    for dep in deps {
                        if let Some(dep_name) = dep.as_str() {
                            edges.push(GraphEdge {
                                from_commit_id: commit_id.clone(),
                                to_commit_id: dep_name.to_string(),
                            });
                        }
                    }
                }
            }

            commits.push(commit);
        }
    }

    let resp = GetGraphResponse { commits, edges };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST GetResources
// ---------------------------------------------------------------------------

async fn get_resources(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::Json(body): axum::Json<GetResourcesRequest>,
) -> Result<Response, Response> {
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut resources = Vec::new();

    for resource_ref in &body.resource_refs {
        let module_name = module_name_from_resource_ref(resource_ref)?;

        // Resolve commit digest via label if provided
        let commit_digest = if let Some(label) = &resource_ref.label {
            resolve_commit_by_label(&state.db, repo.id, &module_name, label).await
        } else {
            resource_ref.id.clone()
        };

        let row = if let Some(digest) = &commit_digest {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND version = $3
                  AND is_deleted = false
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .bind(digest)
            .fetch_optional(&state.db)
            .await
        } else {
            sqlx::query(
                r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
                FROM artifacts
                WHERE repository_id = $1
                  AND name = $2
                  AND is_deleted = false
                ORDER BY created_at DESC
                LIMIT 1"#,
            )
            .bind(repo.id)
            .bind(&module_name)
            .fetch_optional(&state.db)
            .await
        };

        let row = row.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &format!("Database error: {}", e),
            )
        })?;

        if let Some(row) = row {
            let module = build_module_info_from_row(&row);
            let commit = build_commit_info_from_row(&row);
            resources.push(ResourceInfo { module, commit });
        }
    }

    let resp = GetResourcesResponse { resources };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap())
}
