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
        let validation = auth_service.validate_api_token(&token).await.map_err(|_| {
            connect_error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Invalid API token",
            )
        })?;
        return Ok(validation.user.id);
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
                            let state = state.clone();
                            let path = format!("modules/{}/commits/{}", mname, digest);
                            async move {
                                proxy_helpers::local_fetch_by_path(
                                    &db,
                                    &state,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Compute the commit digest from a list of file path/content pairs.
    /// The digest is the hex-encoded SHA-256 of all (path_bytes || content_bytes).
    fn compute_commit_digest(files: &[(String, Vec<u8>)]) -> String {
        let mut hasher = Sha256::new();
        for (path, content) in files {
            hasher.update(path.as_bytes());
            hasher.update(content);
        }
        format!("{:x}", hasher.finalize())
    }

    /// Build the storage key for a protobuf module commit.
    fn build_module_storage_key(module_name: &str, commit_digest: &str) -> String {
        format!("modules/{}/commits/{}", module_name, commit_digest)
    }

    /// Build the artifact path for a protobuf module commit.
    fn build_module_artifact_path(module_name: &str, commit_digest: &str) -> String {
        format!("modules/{}/commits/{}", module_name, commit_digest)
    }

    /// Build the label path for a module.
    fn build_label_path(module_name: &str) -> String {
        format!("modules/{}/_labels", module_name)
    }

    /// Build protobuf metadata JSON for an upload.
    fn build_protobuf_metadata(
        module_name: &str,
        commit_digest: &str,
        file_count: usize,
        dep_names: &[String],
    ) -> serde_json::Value {
        serde_json::json!({
            "module": module_name,
            "commitDigest": commit_digest,
            "fileCount": file_count,
            "dependencies": dep_names,
        })
    }

    /// Extract dependency names from a list of ModuleRefs.
    fn extract_dep_names(dep_refs: &[ModuleRef]) -> Vec<String> {
        dep_refs
            .iter()
            .filter_map(|d| match (&d.owner, &d.module) {
                (Some(o), Some(m)) => Some(format!("{}/{}", o, m)),
                _ => d.id.clone(),
            })
            .collect()
    }

    /// Build a ModuleInfo struct from plain parameters.
    fn build_module_info(
        id: &str,
        owner_id: &str,
        name: &str,
        create_time: &str,
        update_time: &str,
    ) -> ModuleInfo {
        ModuleInfo {
            id: id.to_string(),
            owner_id: owner_id.to_string(),
            name: name.to_string(),
            create_time: create_time.to_string(),
            update_time: update_time.to_string(),
            state: "ACTIVE".to_string(),
            default_label_name: "main".to_string(),
        }
    }

    /// Build a CommitInfo struct from plain parameters.
    fn build_commit_info(
        id: &str,
        create_time: &str,
        owner_id: &str,
        module_id: &str,
        digest_value: &str,
    ) -> CommitInfo {
        CommitInfo {
            id: id.to_string(),
            create_time: create_time.to_string(),
            owner_id: owner_id.to_string(),
            module_id: module_id.to_string(),
            digest: CommitDigest {
                digest_type: "sha256".to_string(),
                value: digest_value.to_string(),
            },
        }
    }

    /// Build a LabelInfo struct from parameters.
    fn build_label_info(
        module_name: &str,
        label_name: &str,
        digest: &str,
        timestamp: &str,
    ) -> LabelInfo {
        LabelInfo {
            id: format!("{}:{}:{}", module_name, label_name, digest),
            name: label_name.to_string(),
            commit_id: digest.to_string(),
            create_time: timestamp.to_string(),
            update_time: timestamp.to_string(),
        }
    }

    /// Compute the next page token for pagination.
    fn compute_next_page_token(count: usize, page_size: i64, offset: i64) -> String {
        if count as i64 >= page_size {
            (offset + page_size).to_string()
        } else {
            String::new()
        }
    }

    /// Parse a page token string into an offset.
    fn parse_page_token(token: Option<&str>) -> i64 {
        token.and_then(|t| t.parse::<i64>().ok()).unwrap_or(0)
    }

    /// Clamp page size to a maximum value.
    fn clamp_page_size(page_size: Option<i64>, max: i64) -> i64 {
        page_size.unwrap_or(50).min(max)
    }

    /// Extract graph edges from artifact metadata.
    fn extract_graph_edges(
        metadata: &Option<serde_json::Value>,
        commit_id: &str,
    ) -> Vec<GraphEdge> {
        let mut edges = Vec::new();
        if let Some(meta) = metadata {
            if let Some(deps) = meta.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    if let Some(dep_name) = dep.as_str() {
                        edges.push(GraphEdge {
                            from_commit_id: commit_id.to_string(),
                            to_commit_id: dep_name.to_string(),
                        });
                    }
                }
            }
        }
        edges
    }

    // -----------------------------------------------------------------------
    // connect_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_connect_error_returns_correct_status_and_body() {
        let resp = connect_error(StatusCode::NOT_FOUND, "not_found", "thing missing");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_connect_error_internal_server_error() {
        let resp = connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "db down");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_connect_error_bad_request() {
        let resp = connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "bad input");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        // "user:pass" in base64 = "dXNlcjpwYXNz"
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_auth_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid!!!"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        // "useronly" in base64 = "dXNlcm9ubHk="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcm9ubHk="),
        );
        // Without a colon, splitn(2, ':') yields only one part, parts.next() for pass returns None
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        // "user:pa:ss" in base64 = "dXNlcjpwYTpzcw=="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYTpzcw=="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pa:ss".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token-123"),
        );
        assert_eq!(
            extract_bearer_token(&headers),
            Some("my-token-123".to_string())
        );
    }

    #[test]
    fn test_extract_bearer_token_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-token"),
        );
        assert_eq!(extract_bearer_token(&headers), Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
    }

    #[test]
    fn test_extract_bearer_token_basic_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(extract_bearer_token(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // module_name_from_ref
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_from_ref_owner_and_module() {
        let r = ModuleRef {
            id: None,
            owner: Some("buf".to_string()),
            module: Some("validate".to_string()),
        };
        assert_eq!(module_name_from_ref(&r).unwrap(), "buf/validate");
    }

    #[test]
    fn test_module_name_from_ref_id_only() {
        let r = ModuleRef {
            id: Some("some-uuid".to_string()),
            owner: None,
            module: None,
        };
        assert_eq!(module_name_from_ref(&r).unwrap(), "some-uuid");
    }

    #[test]
    fn test_module_name_from_ref_no_fields() {
        let r = ModuleRef {
            id: None,
            owner: None,
            module: None,
        };
        assert!(module_name_from_ref(&r).is_err());
    }

    #[test]
    fn test_module_name_from_ref_owner_only() {
        let r = ModuleRef {
            id: None,
            owner: Some("buf".to_string()),
            module: None,
        };
        // Without module, falls to id check, id is None => error
        assert!(module_name_from_ref(&r).is_err());
    }

    #[test]
    fn test_module_name_from_ref_module_only() {
        let r = ModuleRef {
            id: None,
            owner: None,
            module: Some("validate".to_string()),
        };
        assert!(module_name_from_ref(&r).is_err());
    }

    #[test]
    fn test_module_name_from_ref_owner_module_and_id() {
        // owner+module takes priority over id
        let r = ModuleRef {
            id: Some("some-id".to_string()),
            owner: Some("buf".to_string()),
            module: Some("validate".to_string()),
        };
        assert_eq!(module_name_from_ref(&r).unwrap(), "buf/validate");
    }

    // -----------------------------------------------------------------------
    // module_name_from_resource_ref
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_from_resource_ref_owner_and_module() {
        let r = ResourceRef {
            id: None,
            owner: Some("org".to_string()),
            module: Some("pkg".to_string()),
            label: None,
        };
        assert_eq!(module_name_from_resource_ref(&r).unwrap(), "org/pkg");
    }

    #[test]
    fn test_module_name_from_resource_ref_id_only() {
        let r = ResourceRef {
            id: Some("id-123".to_string()),
            owner: None,
            module: None,
            label: None,
        };
        assert_eq!(module_name_from_resource_ref(&r).unwrap(), "id-123");
    }

    #[test]
    fn test_module_name_from_resource_ref_no_fields() {
        let r = ResourceRef {
            id: None,
            owner: None,
            module: None,
            label: None,
        };
        assert!(module_name_from_resource_ref(&r).is_err());
    }

    // -----------------------------------------------------------------------
    // build_bundle + extract_files_from_bundle (round-trip)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_and_extract_bundle_round_trip() {
        let files = vec![
            UploadFile {
                path: "hello.proto".to_string(),
                content: base64::engine::general_purpose::STANDARD.encode(b"syntax = \"proto3\";"),
            },
            UploadFile {
                path: "world.proto".to_string(),
                content: base64::engine::general_purpose::STANDARD.encode(b"message World {}"),
            },
        ];

        let bundle = build_bundle(&files).unwrap();
        assert!(!bundle.is_empty());

        let extracted = extract_files_from_bundle(&bundle).unwrap();
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].path, "hello.proto");
        assert_eq!(extracted[1].path, "world.proto");

        // Verify content round-trip
        let decoded0 = base64::engine::general_purpose::STANDARD
            .decode(&extracted[0].content)
            .unwrap();
        assert_eq!(decoded0, b"syntax = \"proto3\";");

        let decoded1 = base64::engine::general_purpose::STANDARD
            .decode(&extracted[1].content)
            .unwrap();
        assert_eq!(decoded1, b"message World {}");
    }

    #[test]
    fn test_build_bundle_empty_files() {
        let files: Vec<UploadFile> = vec![];
        let bundle = build_bundle(&files).unwrap();
        // Should still produce a valid (empty) gzip tar
        assert!(!bundle.is_empty());
        let extracted = extract_files_from_bundle(&bundle).unwrap();
        assert!(extracted.is_empty());
    }

    #[test]
    fn test_build_bundle_invalid_base64() {
        let files = vec![UploadFile {
            path: "bad.proto".to_string(),
            content: "not-valid-base64!!!".to_string(),
        }];
        assert!(build_bundle(&files).is_err());
    }

    #[test]
    fn test_extract_files_from_bundle_invalid_gzip() {
        let bad_data = b"this is not a gzip file";
        assert!(extract_files_from_bundle(bad_data).is_err());
    }

    #[test]
    fn test_build_bundle_single_file() {
        let files = vec![UploadFile {
            path: "single.proto".to_string(),
            content: base64::engine::general_purpose::STANDARD.encode(b"content here"),
        }];
        let bundle = build_bundle(&files).unwrap();
        let extracted = extract_files_from_bundle(&bundle).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].path, "single.proto");
    }

    // -----------------------------------------------------------------------
    // Struct serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_ref_deserialization_camel_case() {
        let json = r#"{"id":"123","owner":"buf","module":"validate"}"#;
        let r: ModuleRef = serde_json::from_str(json).unwrap();
        assert_eq!(r.id, Some("123".to_string()));
        assert_eq!(r.owner, Some("buf".to_string()));
        assert_eq!(r.module, Some("validate".to_string()));
    }

    #[test]
    fn test_module_ref_deserialization_defaults() {
        let json = r#"{}"#;
        let r: ModuleRef = serde_json::from_str(json).unwrap();
        assert!(r.id.is_none());
        assert!(r.owner.is_none());
        assert!(r.module.is_none());
    }

    #[test]
    fn test_get_modules_request_empty() {
        let json = r#"{}"#;
        let r: GetModulesRequest = serde_json::from_str(json).unwrap();
        assert!(r.module_refs.is_empty());
    }

    #[test]
    fn test_get_modules_request_with_refs() {
        let json = r#"{"moduleRefs":[{"owner":"a","module":"b"}]}"#;
        let r: GetModulesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(r.module_refs.len(), 1);
        assert_eq!(r.module_refs[0].owner, Some("a".to_string()));
    }

    #[test]
    fn test_get_modules_response_serialization() {
        let resp = GetModulesResponse {
            modules: vec![ModuleInfo {
                id: "id-1".to_string(),
                owner_id: "owner-1".to_string(),
                name: "test/module".to_string(),
                create_time: "2024-01-01T00:00:00Z".to_string(),
                update_time: "2024-01-01T00:00:00Z".to_string(),
                state: "ACTIVE".to_string(),
                default_label_name: "main".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ownerId\":\"owner-1\""));
        assert!(json.contains("\"defaultLabelName\":\"main\""));
    }

    #[test]
    fn test_commit_info_serialization() {
        let ci = CommitInfo {
            id: "commit-1".to_string(),
            create_time: "2024-01-01T00:00:00Z".to_string(),
            owner_id: "owner-1".to_string(),
            module_id: "mod-1".to_string(),
            digest: CommitDigest {
                digest_type: "sha256".to_string(),
                value: "abc123".to_string(),
            },
        };
        let json = serde_json::to_string(&ci).unwrap();
        assert!(json.contains("\"createTime\""));
        assert!(json.contains("\"ownerId\""));
        assert!(json.contains("\"moduleId\""));
        assert!(json.contains("\"type\":\"sha256\""));
    }

    #[test]
    fn test_list_commits_request_defaults() {
        let json = r#"{}"#;
        let r: ListCommitsRequest = serde_json::from_str(json).unwrap();
        assert!(r.owner.is_none());
        assert!(r.module.is_none());
        assert!(r.page_size.is_none());
        assert!(r.page_token.is_none());
    }

    #[test]
    fn test_upload_request_empty() {
        let json = r#"{}"#;
        let r: UploadRequest = serde_json::from_str(json).unwrap();
        assert!(r.contents.is_empty());
    }

    #[test]
    fn test_download_response_serialization() {
        let resp = DownloadResponse {
            contents: vec![DownloadContent {
                commit: CommitInfo {
                    id: "c1".to_string(),
                    create_time: "2024-01-01T00:00:00Z".to_string(),
                    owner_id: "o1".to_string(),
                    module_id: "m1".to_string(),
                    digest: CommitDigest {
                        digest_type: "sha256".to_string(),
                        value: "hash".to_string(),
                    },
                },
                files: vec![DownloadFile {
                    path: "file.proto".to_string(),
                    content: "Y29udGVudA==".to_string(),
                }],
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"contents\""));
        assert!(json.contains("file.proto"));
    }

    #[test]
    fn test_graph_edge_serialization() {
        let edge = GraphEdge {
            from_commit_id: "from".to_string(),
            to_commit_id: "to".to_string(),
        };
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"fromCommitId\":\"from\""));
        assert!(json.contains("\"toCommitId\":\"to\""));
    }

    #[test]
    fn test_resource_ref_deserialization() {
        let json = r#"{"id":"id1","owner":"org","module":"mod","label":"v1"}"#;
        let r: ResourceRef = serde_json::from_str(json).unwrap();
        assert_eq!(r.id, Some("id1".to_string()));
        assert_eq!(r.label, Some("v1".to_string()));
    }

    #[test]
    fn test_label_info_serialization() {
        let li = LabelInfo {
            id: "label-1".to_string(),
            name: "main".to_string(),
            commit_id: "commit-1".to_string(),
            create_time: "2024-01-01T00:00:00Z".to_string(),
            update_time: "2024-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&li).unwrap();
        assert!(json.contains("\"commitId\":\"commit-1\""));
    }

    #[test]
    fn test_create_label_value_deserialization() {
        let json = r#"{"owner":"org","module":"mod","name":"v1","commitId":"abc"}"#;
        let v: CreateLabelValue = serde_json::from_str(json).unwrap();
        assert_eq!(v.owner, Some("org".to_string()));
        assert_eq!(v.name, "v1");
        assert_eq!(v.commit_id, "abc");
    }

    // -----------------------------------------------------------------------
    // compute_commit_digest
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_commit_digest_deterministic() {
        let files = vec![
            ("a.proto".to_string(), b"content a".to_vec()),
            ("b.proto".to_string(), b"content b".to_vec()),
        ];
        let d1 = compute_commit_digest(&files);
        let d2 = compute_commit_digest(&files);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_compute_commit_digest_different_files() {
        let f1 = vec![("a.proto".to_string(), b"content a".to_vec())];
        let f2 = vec![("a.proto".to_string(), b"content b".to_vec())];
        assert_ne!(compute_commit_digest(&f1), compute_commit_digest(&f2));
    }

    #[test]
    fn test_compute_commit_digest_empty() {
        let files: Vec<(String, Vec<u8>)> = vec![];
        let digest = compute_commit_digest(&files);
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_compute_commit_digest_is_hex() {
        let files = vec![("test.proto".to_string(), b"syntax = \"proto3\";".to_vec())];
        let digest = compute_commit_digest(&files);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // build_module_storage_key / build_module_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_storage_key() {
        assert_eq!(
            build_module_storage_key("buf/validate", "abc123"),
            "modules/buf/validate/commits/abc123"
        );
    }

    #[test]
    fn test_build_module_artifact_path() {
        assert_eq!(
            build_module_artifact_path("org/pkg", "def456"),
            "modules/org/pkg/commits/def456"
        );
    }

    #[test]
    fn test_build_module_storage_key_same_as_artifact_path() {
        let key = build_module_storage_key("a/b", "hash");
        let path = build_module_artifact_path("a/b", "hash");
        assert_eq!(key, path);
    }

    // -----------------------------------------------------------------------
    // build_label_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_label_path() {
        assert_eq!(
            build_label_path("buf/validate"),
            "modules/buf/validate/_labels"
        );
    }

    #[test]
    fn test_build_label_path_nested() {
        assert_eq!(
            build_label_path("org/deep/module"),
            "modules/org/deep/module/_labels"
        );
    }

    // -----------------------------------------------------------------------
    // build_protobuf_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_protobuf_metadata_basic() {
        let deps = vec!["dep/one".to_string()];
        let meta = build_protobuf_metadata("buf/validate", "abc", 3, &deps);
        assert_eq!(meta["module"], "buf/validate");
        assert_eq!(meta["commitDigest"], "abc");
        assert_eq!(meta["fileCount"], 3);
        assert_eq!(meta["dependencies"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_build_protobuf_metadata_no_deps() {
        let meta = build_protobuf_metadata("m", "d", 0, &[]);
        assert!(meta["dependencies"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_protobuf_metadata_many_deps() {
        let deps = vec!["a/b".to_string(), "c/d".to_string(), "e/f".to_string()];
        let meta = build_protobuf_metadata("mod", "hash", 10, &deps);
        assert_eq!(meta["dependencies"].as_array().unwrap().len(), 3);
    }

    // -----------------------------------------------------------------------
    // extract_dep_names
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dep_names_owner_and_module() {
        let refs = vec![ModuleRef {
            id: None,
            owner: Some("buf".to_string()),
            module: Some("validate".to_string()),
        }];
        let names = extract_dep_names(&refs);
        assert_eq!(names, vec!["buf/validate"]);
    }

    #[test]
    fn test_extract_dep_names_id_only() {
        let refs = vec![ModuleRef {
            id: Some("some-id".to_string()),
            owner: None,
            module: None,
        }];
        let names = extract_dep_names(&refs);
        assert_eq!(names, vec!["some-id"]);
    }

    #[test]
    fn test_extract_dep_names_no_fields() {
        let refs = vec![ModuleRef {
            id: None,
            owner: None,
            module: None,
        }];
        let names = extract_dep_names(&refs);
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_dep_names_empty() {
        let refs: Vec<ModuleRef> = vec![];
        let names = extract_dep_names(&refs);
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_dep_names_mixed() {
        let refs = vec![
            ModuleRef {
                id: None,
                owner: Some("a".to_string()),
                module: Some("b".to_string()),
            },
            ModuleRef {
                id: Some("id-1".to_string()),
                owner: None,
                module: None,
            },
        ];
        let names = extract_dep_names(&refs);
        assert_eq!(names, vec!["a/b", "id-1"]);
    }

    // -----------------------------------------------------------------------
    // build_module_info / build_commit_info / build_label_info
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_info_fields() {
        let info = build_module_info(
            "id1",
            "owner1",
            "buf/validate",
            "2024-01-01T00:00:00Z",
            "2024-06-01T00:00:00Z",
        );
        assert_eq!(info.id, "id1");
        assert_eq!(info.owner_id, "owner1");
        assert_eq!(info.name, "buf/validate");
        assert_eq!(info.state, "ACTIVE");
        assert_eq!(info.default_label_name, "main");
    }

    #[test]
    fn test_build_module_info_serialization() {
        let info = build_module_info("id", "o", "n", "t1", "t2");
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"ownerId\""));
        assert!(json.contains("\"defaultLabelName\":\"main\""));
    }

    #[test]
    fn test_build_commit_info_fields() {
        let info = build_commit_info("c1", "2024-01-01T00:00:00Z", "o1", "m1", "hash");
        assert_eq!(info.id, "c1");
        assert_eq!(info.module_id, "m1");
        assert_eq!(info.digest.digest_type, "sha256");
        assert_eq!(info.digest.value, "hash");
    }

    #[test]
    fn test_build_commit_info_serialization() {
        let info = build_commit_info("c", "t", "o", "m", "d");
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"type\":\"sha256\""));
    }

    #[test]
    fn test_build_label_info_fields() {
        let info = build_label_info("buf/validate", "main", "abc123", "2024-01-01T00:00:00Z");
        assert_eq!(info.id, "buf/validate:main:abc123");
        assert_eq!(info.name, "main");
        assert_eq!(info.commit_id, "abc123");
    }

    #[test]
    fn test_build_label_info_id_format() {
        let info = build_label_info("org/mod", "v1", "digest", "ts");
        assert_eq!(info.id, "org/mod:v1:digest");
    }

    // -----------------------------------------------------------------------
    // compute_next_page_token / parse_page_token / clamp_page_size
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_next_page_token_has_more() {
        assert_eq!(compute_next_page_token(50, 50, 0), "50");
    }

    #[test]
    fn test_compute_next_page_token_no_more() {
        assert_eq!(compute_next_page_token(10, 50, 0), "");
    }

    #[test]
    fn test_compute_next_page_token_with_offset() {
        assert_eq!(compute_next_page_token(25, 25, 50), "75");
    }

    #[test]
    fn test_parse_page_token_valid() {
        assert_eq!(parse_page_token(Some("42")), 42);
    }

    #[test]
    fn test_parse_page_token_none() {
        assert_eq!(parse_page_token(None), 0);
    }

    #[test]
    fn test_parse_page_token_invalid() {
        assert_eq!(parse_page_token(Some("not-a-number")), 0);
    }

    #[test]
    fn test_parse_page_token_empty() {
        assert_eq!(parse_page_token(Some("")), 0);
    }

    #[test]
    fn test_clamp_page_size_default() {
        assert_eq!(clamp_page_size(None, 250), 50);
    }

    #[test]
    fn test_clamp_page_size_within_limit() {
        assert_eq!(clamp_page_size(Some(100), 250), 100);
    }

    #[test]
    fn test_clamp_page_size_exceeds_limit() {
        assert_eq!(clamp_page_size(Some(500), 250), 250);
    }

    #[test]
    fn test_clamp_page_size_zero() {
        assert_eq!(clamp_page_size(Some(0), 250), 0);
    }

    // -----------------------------------------------------------------------
    // extract_graph_edges
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_graph_edges_with_deps() {
        let meta = Some(serde_json::json!({
            "dependencies": ["dep/a", "dep/b"]
        }));
        let edges = extract_graph_edges(&meta, "commit-1");
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].from_commit_id, "commit-1");
        assert_eq!(edges[0].to_commit_id, "dep/a");
        assert_eq!(edges[1].to_commit_id, "dep/b");
    }

    #[test]
    fn test_extract_graph_edges_no_deps() {
        let meta = Some(serde_json::json!({"module": "test"}));
        let edges = extract_graph_edges(&meta, "c1");
        assert!(edges.is_empty());
    }

    #[test]
    fn test_extract_graph_edges_none_metadata() {
        let edges = extract_graph_edges(&None, "c1");
        assert!(edges.is_empty());
    }

    #[test]
    fn test_extract_graph_edges_empty_deps() {
        let meta = Some(serde_json::json!({"dependencies": []}));
        let edges = extract_graph_edges(&meta, "c1");
        assert!(edges.is_empty());
    }

    #[test]
    fn test_extract_graph_edges_non_string_deps_ignored() {
        let meta = Some(serde_json::json!({"dependencies": [123, null, "valid/dep"]}));
        let edges = extract_graph_edges(&meta, "c1");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].to_commit_id, "valid/dep");
    }
}
