//! Repository management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Multipart, Path, Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::download_response::{DownloadResponse, X_ARTIFACT_STORAGE};
use crate::api::dto::Pagination;
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::artifact_service::ArtifactService;
use crate::services::repository_service::{
    CreateRepositoryRequest as ServiceCreateRepoReq, RepositoryService,
    UpdateRepositoryRequest as ServiceUpdateRepoReq,
};
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::s3::{S3Backend, S3Config};
use crate::storage::StorageBackend;

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create repository routes
pub fn router() -> Router<SharedState> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::delete;

    Router::new()
        .route("/", get(list_repositories).post(create_repository))
        .route(
            "/:key",
            get(get_repository)
                .patch(update_repository)
                .delete(delete_repository),
        )
        // Virtual repository member management
        .route(
            "/:key/members",
            get(list_virtual_members)
                .post(add_virtual_member)
                .put(update_virtual_members),
        )
        .route("/:key/members/:member_key", delete(remove_virtual_member))
        // Artifact routes nested under repository
        .route(
            "/:key/artifacts",
            get(list_artifacts).post(upload_artifact_multipart),
        )
        .route(
            "/:key/artifacts/*path",
            get(get_artifact_metadata)
                .put(upload_artifact)
                .post(upload_artifact_multipart_with_path)
                .delete(delete_artifact),
        )
        // Download uses a separate route prefix to avoid wildcard conflict
        .route("/:key/download/*path", get(download_artifact))
        // Security routes nested under repository
        .merge(super::security::repo_security_router())
        // Label routes nested under repository
        .merge(super::repository_labels::repo_labels_router())
        // Allow up to 512MB uploads (matches format-specific handlers)
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListRepositoriesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub format: Option<String>,
    #[serde(rename = "type")]
    pub repo_type: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRepositoryRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: Option<bool>,
    pub upstream_url: Option<String>,
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRepositoryRequest {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryResponse {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: bool,
    pub storage_used_bytes: i64,
    pub quota_bytes: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryListResponse {
    pub items: Vec<RepositoryResponse>,
    pub pagination: Pagination,
}

/// Convert a Repository model to a RepositoryResponse with optional storage usage.
fn repo_to_response(
    repo: crate::models::repository::Repository,
    storage_used_bytes: i64,
) -> RepositoryResponse {
    RepositoryResponse {
        id: repo.id,
        key: repo.key,
        name: repo.name,
        description: repo.description,
        format: format!("{:?}", repo.format).to_lowercase(),
        repo_type: format!("{:?}", repo.repo_type).to_lowercase(),
        is_public: repo.is_public,
        storage_used_bytes,
        quota_bytes: repo.quota_bytes,
        created_at: repo.created_at,
        updated_at: repo.updated_at,
    }
}

/// Validate that a repository key is safe and well-formed.
fn validate_repository_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 {
        return Err(AppError::Validation(
            "Repository key must be between 1 and 128 characters".to_string(),
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::Validation(
            "Repository key must contain only alphanumeric characters, hyphens, underscores, and dots".to_string(),
        ));
    }
    if key.starts_with('.') || key.starts_with('-') {
        return Err(AppError::Validation(
            "Repository key must not start with a dot or hyphen".to_string(),
        ));
    }
    if key.contains("..") {
        return Err(AppError::Validation(
            "Repository key must not contain consecutive dots".to_string(),
        ));
    }
    Ok(())
}

fn parse_format(s: &str) -> Result<RepositoryFormat> {
    match s.to_lowercase().as_str() {
        "maven" => Ok(RepositoryFormat::Maven),
        "gradle" => Ok(RepositoryFormat::Gradle),
        "npm" => Ok(RepositoryFormat::Npm),
        "pypi" => Ok(RepositoryFormat::Pypi),
        "nuget" => Ok(RepositoryFormat::Nuget),
        "go" => Ok(RepositoryFormat::Go),
        "rubygems" => Ok(RepositoryFormat::Rubygems),
        "docker" => Ok(RepositoryFormat::Docker),
        "helm" => Ok(RepositoryFormat::Helm),
        "rpm" => Ok(RepositoryFormat::Rpm),
        "debian" => Ok(RepositoryFormat::Debian),
        "conan" => Ok(RepositoryFormat::Conan),
        "cargo" => Ok(RepositoryFormat::Cargo),
        "generic" => Ok(RepositoryFormat::Generic),
        "podman" => Ok(RepositoryFormat::Podman),
        "buildx" => Ok(RepositoryFormat::Buildx),
        "oras" => Ok(RepositoryFormat::Oras),
        "wasm_oci" => Ok(RepositoryFormat::WasmOci),
        "helm_oci" => Ok(RepositoryFormat::HelmOci),
        "poetry" => Ok(RepositoryFormat::Poetry),
        "conda" => Ok(RepositoryFormat::Conda),
        "yarn" => Ok(RepositoryFormat::Yarn),
        "bower" => Ok(RepositoryFormat::Bower),
        "pnpm" => Ok(RepositoryFormat::Pnpm),
        "chocolatey" => Ok(RepositoryFormat::Chocolatey),
        "powershell" => Ok(RepositoryFormat::Powershell),
        "terraform" => Ok(RepositoryFormat::Terraform),
        "opentofu" => Ok(RepositoryFormat::Opentofu),
        "alpine" => Ok(RepositoryFormat::Alpine),
        "conda_native" => Ok(RepositoryFormat::CondaNative),
        "composer" => Ok(RepositoryFormat::Composer),
        "hex" => Ok(RepositoryFormat::Hex),
        "cocoapods" => Ok(RepositoryFormat::Cocoapods),
        "swift" => Ok(RepositoryFormat::Swift),
        "pub" => Ok(RepositoryFormat::Pub),
        "sbt" => Ok(RepositoryFormat::Sbt),
        "chef" => Ok(RepositoryFormat::Chef),
        "puppet" => Ok(RepositoryFormat::Puppet),
        "ansible" => Ok(RepositoryFormat::Ansible),
        "gitlfs" => Ok(RepositoryFormat::Gitlfs),
        "vscode" => Ok(RepositoryFormat::Vscode),
        "jetbrains" => Ok(RepositoryFormat::Jetbrains),
        "huggingface" => Ok(RepositoryFormat::Huggingface),
        "mlmodel" => Ok(RepositoryFormat::Mlmodel),
        "cran" => Ok(RepositoryFormat::Cran),
        "vagrant" => Ok(RepositoryFormat::Vagrant),
        "opkg" => Ok(RepositoryFormat::Opkg),
        "p2" => Ok(RepositoryFormat::P2),
        "bazel" => Ok(RepositoryFormat::Bazel),
        "protobuf" => Ok(RepositoryFormat::Protobuf),
        "incus" => Ok(RepositoryFormat::Incus),
        "lxc" => Ok(RepositoryFormat::Lxc),
        _ => Err(AppError::Validation(format!("Invalid format: {}", s))),
    }
}

fn parse_repo_type(s: &str) -> Result<RepositoryType> {
    match s.to_lowercase().as_str() {
        "local" => Ok(RepositoryType::Local),
        "remote" => Ok(RepositoryType::Remote),
        "virtual" => Ok(RepositoryType::Virtual),
        "staging" => Ok(RepositoryType::Staging),
        _ => Err(AppError::Validation(format!("Invalid repo type: {}", s))),
    }
}

/// List repositories
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(ListRepositoriesQuery),
    responses(
        (status = 200, description = "List of repositories", body = RepositoryListResponse),
    )
)]
pub async fn list_repositories(
    State(state): State<SharedState>,
    Query(query): Query<ListRepositoriesQuery>,
) -> Result<Json<RepositoryListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let format_filter = query.format.as_ref().map(|f| parse_format(f)).transpose()?;
    let type_filter = query
        .repo_type
        .as_ref()
        .map(|t| parse_repo_type(t))
        .transpose()?;

    let service = RepositoryService::new(state.db.clone());
    let (repos, total) = service
        .list(
            offset,
            per_page as i64,
            format_filter,
            type_filter,
            false,
            query.q.as_deref(),
        )
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    // Batch fetch storage usage for all repos in one query
    let repo_ids: Vec<Uuid> = repos.iter().map(|r| r.id).collect();
    let storage_map: std::collections::HashMap<Uuid, i64> = if !repo_ids.is_empty() {
        sqlx::query_as::<_, (Uuid, i64)>(
            r#"
            SELECT repository_id, COALESCE(SUM(size_bytes), 0)::BIGINT
            FROM artifacts
            WHERE repository_id = ANY($1) AND is_deleted = false
            GROUP BY repository_id
            "#,
        )
        .bind(&repo_ids)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .into_iter()
        .collect()
    } else {
        std::collections::HashMap::new()
    };

    let items: Vec<RepositoryResponse> = repos
        .into_iter()
        .map(|r| {
            let storage = storage_map.get(&r.id).copied().unwrap_or(0);
            repo_to_response(r, storage)
        })
        .collect();

    Ok(Json(RepositoryListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Create a new repository
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    request_body = CreateRepositoryRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository created", body = RepositoryResponse),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Repository key already exists"),
    )
)]
pub async fn create_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    let _auth = require_auth(auth)?;
    validate_repository_key(&payload.key)?;
    let format = parse_format(&payload.format)?;
    let repo_type = parse_repo_type(&payload.repo_type)?;

    // Generate storage path using the configured storage directory
    let storage_path = format!("{}/{}", state.config.storage_path, payload.key);

    let service = state.create_repository_service();
    let repo = service
        .create(ServiceCreateRepoReq {
            key: payload.key,
            name: payload.name,
            description: payload.description,
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path,
            upstream_url: payload.upstream_url,
            is_public: payload.is_public.unwrap_or(false),
            quota_bytes: payload.quota_bytes,
        })
        .await?;

    Ok(Json(repo_to_response(repo, 0)))
}

/// Get repository details
#[utoipa::path(
    get,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "Repository details", body = RepositoryResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn get_repository(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<RepositoryResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    let storage_used = service.get_storage_usage(repo.id).await?;

    Ok(Json(repo_to_response(repo, storage_used)))
}

/// Update repository
#[utoipa::path(
    patch,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = UpdateRepositoryRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository updated", body = RepositoryResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
        (status = 409, description = "Repository key already exists"),
    )
)]
pub async fn update_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    let _auth = require_auth(auth)?;

    // Validate new key if provided
    if let Some(ref new_key) = payload.key {
        validate_repository_key(new_key)?;
    }

    let service = state.create_repository_service();

    // Get existing repo by key
    let existing = service.get_by_key(&key).await?;

    let repo = service
        .update(
            existing.id,
            ServiceUpdateRepoReq {
                key: payload.key,
                name: payload.name,
                description: payload.description,
                is_public: payload.is_public,
                quota_bytes: payload.quota_bytes.map(Some),
                upstream_url: None,
            },
        )
        .await?;

    let storage_used = service.get_storage_usage(repo.id).await?;

    Ok(Json(repo_to_response(repo, storage_used)))
}

/// Delete repository
#[utoipa::path(
    delete,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn delete_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<()> {
    let _auth = require_auth(auth)?;
    let service = state.create_repository_service();
    let repo = service.get_by_key(&key).await?;
    service.delete(repo.id).await?;
    Ok(())
}

// Artifact handlers (nested under repository)

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListArtifactsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub q: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub content_type: String,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactListResponse {
    pub items: Vec<ArtifactResponse>,
    pub pagination: Pagination,
}

/// List artifacts in repository
#[utoipa::path(
    get,
    path = "/{key}/artifacts",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ListArtifactsQuery,
    ),
    responses(
        (status = 200, description = "List of artifacts", body = ArtifactListResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_artifacts(
    State(state): State<SharedState>,
    Path(key): Path<String>,
    Query(query): Query<ListArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let (artifacts, total) = artifact_service
        .list(
            repo.id,
            query.path_prefix.as_deref(),
            query.q.as_deref(),
            offset,
            per_page as i64,
        )
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let mut items = Vec::new();
    for artifact in artifacts {
        let downloads = artifact_service.get_download_stats(artifact.id).await?;
        items.push(ArtifactResponse {
            id: artifact.id,
            repository_key: key.clone(),
            path: artifact.path,
            name: artifact.name,
            version: artifact.version,
            size_bytes: artifact.size_bytes,
            checksum_sha256: artifact.checksum_sha256,
            content_type: artifact.content_type,
            download_count: downloads,
            created_at: artifact.created_at,
            metadata: None,
        });
    }

    Ok(Json(ArtifactListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get artifact metadata
#[utoipa::path(
    get,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    operation_id = "get_repository_artifact_metadata",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    responses(
        (status = 200, description = "Artifact metadata", body = ArtifactResponse),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn get_artifact_metadata(
    State(state): State<SharedState>,
    Path((key, path)): Path<(String, String)>,
) -> Result<Json<ArtifactResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let artifact = sqlx::query_as!(
        crate::models::artifact::Artifact,
        r#"
        SELECT
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, is_deleted, uploaded_by,
            created_at, updated_at
        FROM artifacts
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        "#,
        repo.id,
        path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    let downloads = artifact_service.get_download_stats(artifact.id).await?;
    let metadata = artifact_service.get_metadata(artifact.id).await?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count: downloads,
        created_at: artifact.created_at,
        metadata: metadata.map(|m| m.metadata),
    }))
}

/// Upload artifact
#[utoipa::path(
    put,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact uploaded", body = ArtifactResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn upload_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ArtifactResponse>> {
    let auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = state.create_artifact_service(storage);

    // Extract name from path
    let name = path.split('/').next_back().unwrap_or(&path).to_string();

    // Infer content type from extension
    let content_type = mime_guess::from_path(&name)
        .first_or_octet_stream()
        .to_string();

    let artifact = artifact_service
        .upload(
            repo.id,
            &path,
            &name,
            None, // version extracted from format handler
            &content_type,
            body,
            Some(auth.user_id),
        )
        .await?;

    let downloads = artifact_service.get_download_stats(artifact.id).await?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count: downloads,
        created_at: artifact.created_at,
        metadata: None,
    }))
}

/// Upload artifact via multipart/form-data POST (with path in URL).
///
/// Accepts a multipart form with a `file` field. The URL path is used as the
/// artifact path, falling back to the uploaded filename.
async fn upload_artifact_multipart_with_path(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    // Prefer the URL path; fall back to the filename from the form field
    let artifact_path = if path.is_empty() || path == "/" {
        filename
    } else {
        path
    };
    upload_artifact(
        State(state),
        Extension(auth),
        Path((key, artifact_path)),
        body,
    )
    .await
}

/// Upload artifact via multipart/form-data POST (no path in URL).
///
/// The artifact path comes from the `file` field's filename.
async fn upload_artifact_multipart(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    upload_artifact(State(state), Extension(auth), Path((key, filename)), body).await
}

/// Extract the first file field from a multipart form.
async fn extract_multipart_file(mut multipart: Multipart) -> Result<(Bytes, String)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Invalid multipart data: {e}")))?
    {
        // Accept any field that has a filename (i.e. a file upload)
        let filename = field.file_name().map(|s| s.to_string());
        if let Some(filename) = filename {
            let data: Bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::Validation(format!("Failed to read file: {e}")))?;
            return Ok((data, filename));
        }
    }
    Err(AppError::Validation(
        "No file field found in multipart form".to_string(),
    ))
}

/// Download artifact
#[utoipa::path(
    get,
    path = "/{key}/download/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    responses(
        (status = 200, description = "Artifact binary content", content_type = "application/octet-stream"),
        (status = 302, description = "Redirect to S3 presigned URL"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn download_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    // Get client IP for analytics
    let ip_addr = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Check if S3 storage with redirect enabled
    if repo.storage_backend == "s3" {
        // Try to use S3 with redirect
        if let Ok(s3_config) = S3Config::from_env() {
            if s3_config.redirect_downloads {
                let s3_backend = S3Backend::new(s3_config).await?;

                // Get artifact metadata first using query_as for runtime checking
                #[derive(sqlx::FromRow)]
                struct ArtifactRow {
                    id: Uuid,
                    storage_key: String,
                }
                let artifact: ArtifactRow = sqlx::query_as(
                    r#"
                    SELECT id, storage_key
                    FROM artifacts
                    WHERE repository_id = $1 AND path = $2 AND is_deleted = false
                    "#,
                )
                .bind(repo.id)
                .bind(&path)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

                // Record download analytics
                let _ = sqlx::query(
                    r#"
                    INSERT INTO download_events (artifact_id, user_id, ip_address, user_agent, downloaded_at)
                    VALUES ($1, $2, $3, $4, NOW())
                    "#,
                )
                .bind(artifact.id)
                .bind(auth.as_ref().map(|a| a.user_id))
                .bind(ip_addr.to_string())
                .bind(user_agent.as_deref())
                .execute(&state.db)
                .await;

                // Try to get presigned URL
                if let Some(presigned) = s3_backend
                    .get_presigned_url(&artifact.storage_key, Duration::from_secs(3600))
                    .await?
                {
                    tracing::info!(
                        repo = %key,
                        path = %path,
                        source = ?presigned.source,
                        "Serving artifact via redirect"
                    );
                    return Ok(DownloadResponse::redirect(presigned).into_response());
                }
            }
        }
    }

    // Fall back to proxied download (filesystem or S3 without redirect)
    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let download_result = artifact_service
        .download(
            repo.id,
            &path,
            auth.map(|a| a.user_id),
            Some(ip_addr.to_string()),
            user_agent.as_deref(),
        )
        .await;

    match download_result {
        Ok((artifact, content)) => Ok((
            [
                (header::CONTENT_TYPE, artifact.content_type),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", artifact.name),
                ),
                (header::CONTENT_LENGTH, artifact.size_bytes.to_string()),
                (
                    header::HeaderName::from_static("x-checksum-sha256"),
                    artifact.checksum_sha256,
                ),
                (
                    header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                    "proxy".to_string(),
                ),
            ],
            content,
        )
            .into_response()),
        Err(AppError::NotFound(_)) if repo.repo_type == RepositoryType::Remote => {
            // Try proxy for remote repositories
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let (content, content_type) =
                    proxy_helpers::proxy_fetch(proxy, repo.id, &key, upstream_url, &path)
                        .await
                        .map_err(|_| {
                            AppError::NotFound("Artifact not found upstream".to_string())
                        })?;

                let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
                let filename = path.rsplit('/').next().unwrap_or(&path);

                Ok((
                    [
                        (header::CONTENT_TYPE, ct),
                        (
                            header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{}\"", filename),
                        ),
                        (header::CONTENT_LENGTH, content.len().to_string()),
                        (
                            header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                            "upstream".to_string(),
                        ),
                    ],
                    content,
                )
                    .into_response())
            } else {
                Err(AppError::NotFound("Artifact not found".to_string()))
            }
        }
        Err(AppError::NotFound(_)) if repo.repo_type == RepositoryType::Virtual => {
            // Virtual repo: try each member in priority order
            let db = state.db.clone();
            let path_clone = path.clone();
            let (content, content_type) = proxy_helpers::resolve_virtual_download(
                &state.db,
                state.proxy_service.as_deref(),
                repo.id,
                &path,
                |member_id, storage_path| {
                    let db = db.clone();
                    let p = path_clone.clone();
                    async move {
                        proxy_helpers::local_fetch_by_path(&db, member_id, &storage_path, &p).await
                    }
                },
            )
            .await
            .map_err(|_| {
                AppError::NotFound("Artifact not found in any member repository".to_string())
            })?;

            let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
            let filename = path.rsplit('/').next().unwrap_or(&path);

            Ok((
                [
                    (header::CONTENT_TYPE, ct),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ),
                    (header::CONTENT_LENGTH, content.len().to_string()),
                    (
                        header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                        "virtual".to_string(),
                    ),
                ],
                content,
            )
                .into_response())
        }
        Err(e) => Err(e),
    }
}

/// Delete artifact
#[utoipa::path(
    delete,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn delete_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
) -> Result<()> {
    let _auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = state.create_artifact_service(storage);

    // Find the artifact
    let artifact = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    artifact_service.delete(artifact).await?;

    Ok(())
}

// Virtual repository member management handlers

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddVirtualMemberRequest {
    pub member_key: String,
    pub priority: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateVirtualMembersRequest {
    pub members: Vec<VirtualMemberPriority>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VirtualMemberPriority {
    pub member_key: String,
    pub priority: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VirtualMemberResponse {
    pub id: Uuid,
    pub member_repo_id: Uuid,
    pub member_repo_key: String,
    pub member_repo_name: String,
    pub member_repo_type: String,
    pub priority: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VirtualMembersListResponse {
    pub items: Vec<VirtualMemberResponse>,
}

// Row type for virtual member queries
#[derive(sqlx::FromRow)]
struct VirtualMemberRow {
    id: Uuid,
    member_repo_id: Uuid,
    priority: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    member_key: String,
    member_name: String,
    repo_type: RepositoryType,
}

/// List virtual repository members
#[utoipa::path(
    get,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "List of virtual repository members", body = VirtualMembersListResponse),
        (status = 400, description = "Repository is not virtual"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_virtual_members(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<VirtualMembersListResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    if repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Query members with their repository info
    let members: Vec<VirtualMemberRow> = sqlx::query_as(
        r#"
        SELECT
            vrm.id,
            vrm.member_repo_id,
            vrm.priority,
            vrm.created_at,
            r.key as member_key,
            r.name as member_name,
            r.repo_type
        FROM virtual_repo_members vrm
        INNER JOIN repositories r ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = $1
        ORDER BY vrm.priority
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = members
        .into_iter()
        .map(|m| VirtualMemberResponse {
            id: m.id,
            member_repo_id: m.member_repo_id,
            member_repo_key: m.member_key,
            member_repo_name: m.member_name,
            member_repo_type: format!("{:?}", m.repo_type).to_lowercase(),
            priority: m.priority,
            created_at: m.created_at,
        })
        .collect();

    Ok(Json(VirtualMembersListResponse { items }))
}

/// Add a member to a virtual repository
#[utoipa::path(
    post,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = AddVirtualMemberRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Member added", body = VirtualMemberResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository or member not found"),
    )
)]
pub async fn add_virtual_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<AddVirtualMemberRequest>,
) -> Result<Json<VirtualMemberResponse>> {
    let _auth = require_auth(auth)?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;
    let member_repo = service.get_by_key(&payload.member_key).await?;

    // Get current max priority if not specified
    let priority = match payload.priority {
        Some(p) => p,
        None => {
            let max: Option<i32> = sqlx::query_scalar(
                "SELECT MAX(priority) FROM virtual_repo_members WHERE virtual_repo_id = $1",
            )
            .bind(virtual_repo.id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            max.unwrap_or(0) + 1
        }
    };

    service
        .add_virtual_member(virtual_repo.id, member_repo.id, priority)
        .await?;

    // Fetch the created member record
    let member: VirtualMemberRow = sqlx::query_as(
        r#"
        SELECT
            vrm.id,
            vrm.member_repo_id,
            vrm.priority,
            vrm.created_at,
            r.key as member_key,
            r.name as member_name,
            r.repo_type
        FROM virtual_repo_members vrm
        INNER JOIN repositories r ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = $1 AND vrm.member_repo_id = $2
        "#,
    )
    .bind(virtual_repo.id)
    .bind(member_repo.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(VirtualMemberResponse {
        id: member.id,
        member_repo_id: member.member_repo_id,
        member_repo_key: member.member_key,
        member_repo_name: member.member_name,
        member_repo_type: format!("{:?}", member.repo_type).to_lowercase(),
        priority: member.priority,
        created_at: member.created_at,
    }))
}

/// Remove a member from a virtual repository
#[utoipa::path(
    delete,
    path = "/{key}/members/{member_key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("member_key" = String, Path, description = "Member repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Member removed"),
        (status = 400, description = "Repository is not virtual"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository or member not found"),
    )
)]
pub async fn remove_virtual_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, member_key)): Path<(String, String)>,
) -> Result<()> {
    let _auth = require_auth(auth)?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;
    let member_repo = service.get_by_key(&member_key).await?;

    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    sqlx::query(
        "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2",
    )
    .bind(virtual_repo.id)
    .bind(member_repo.id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Update priorities for all members (bulk reorder)
#[utoipa::path(
    put,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = UpdateVirtualMembersRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Members updated", body = VirtualMembersListResponse),
        (status = 400, description = "Repository is not virtual"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn update_virtual_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateVirtualMembersRequest>,
) -> Result<Json<VirtualMembersListResponse>> {
    let _auth = require_auth(auth)?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;

    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Update priorities for each member
    for member in &payload.members {
        let member_repo = service.get_by_key(&member.member_key).await?;

        sqlx::query(
            "UPDATE virtual_repo_members SET priority = $1 WHERE virtual_repo_id = $2 AND member_repo_id = $3",
        )
        .bind(member.priority)
        .bind(virtual_repo.id)
        .bind(member_repo.id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    // Return updated list
    list_virtual_members(State(state), Path(key)).await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_repositories,
        create_repository,
        get_repository,
        update_repository,
        delete_repository,
        list_artifacts,
        get_artifact_metadata,
        upload_artifact,
        download_artifact,
        delete_artifact,
        list_virtual_members,
        add_virtual_member,
        remove_virtual_member,
        update_virtual_members,
    ),
    components(schemas(
        ListRepositoriesQuery,
        CreateRepositoryRequest,
        UpdateRepositoryRequest,
        RepositoryResponse,
        RepositoryListResponse,
        ListArtifactsQuery,
        ArtifactResponse,
        ArtifactListResponse,
        AddVirtualMemberRequest,
        UpdateVirtualMembersRequest,
        VirtualMemberPriority,
        VirtualMemberResponse,
        VirtualMembersListResponse,
    ))
)]
pub struct RepositoriesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    // -----------------------------------------------------------------------
    // Extracted pure functions for testability
    // -----------------------------------------------------------------------

    /// Compute pagination offset from page number and per_page size.
    fn compute_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32, i64) {
        let page = page.unwrap_or(1).max(1);
        let per_page = per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        (page, per_page, offset)
    }

    /// Compute total number of pages given total items and per_page size.
    fn compute_total_pages(total: i64, per_page: u32) -> u32 {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }

    /// Extract the filename from a slash-delimited path.
    fn extract_name_from_path(path: &str) -> String {
        path.split('/').next_back().unwrap_or(path).to_string()
    }

    /// Build a storage path from a base dir and repository key.
    fn build_storage_path(storage_base: &str, repo_key: &str) -> String {
        format!("{}/{}", storage_base, repo_key)
    }

    /// Build a Content-Disposition attachment header value.
    fn content_disposition_attachment(filename: &str) -> String {
        format!("attachment; filename=\"{}\"", filename)
    }

    /// Extract the download filename from an artifact path.
    fn extract_download_filename(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Parse a client IP address from an X-Forwarded-For header value.
    fn parse_client_ip(xff_value: Option<&str>) -> std::net::IpAddr {
        xff_value
            .and_then(|s| s.split(',').next())
            .unwrap_or("127.0.0.1")
            .trim()
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    // -----------------------------------------------------------------------
    // validate_repository_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_repository_key_valid_simple() {
        assert!(validate_repository_key("my-repo").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_with_dots() {
        assert!(validate_repository_key("my.repo.name").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_with_underscores() {
        assert!(validate_repository_key("my_repo_name").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_alphanumeric() {
        assert!(validate_repository_key("myRepo123").is_ok());
    }

    #[test]
    fn test_validate_repository_key_empty() {
        let result = validate_repository_key("");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("between 1 and 128")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_too_long() {
        let long_key = "a".repeat(129);
        let result = validate_repository_key(&long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_max_length() {
        let key = "a".repeat(128);
        assert!(validate_repository_key(&key).is_ok());
    }

    #[test]
    fn test_validate_repository_key_starts_with_dot() {
        let result = validate_repository_key(".hidden");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("must not start with")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_starts_with_hyphen() {
        let result = validate_repository_key("-bad");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("must not start with")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_consecutive_dots() {
        let result = validate_repository_key("bad..key");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("consecutive dots")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_special_chars() {
        let result = validate_repository_key("bad/key");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("alphanumeric")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_spaces() {
        let result = validate_repository_key("bad key");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_at_sign() {
        let result = validate_repository_key("bad@key");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_single_char() {
        assert!(validate_repository_key("a").is_ok());
    }

    #[test]
    fn test_validate_repository_key_underscore_start() {
        assert!(validate_repository_key("_repo").is_ok());
    }

    // -----------------------------------------------------------------------
    // parse_format
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_format_maven() {
        assert_eq!(parse_format("maven").unwrap(), RepositoryFormat::Maven);
    }

    #[test]
    fn test_parse_format_npm() {
        assert_eq!(parse_format("npm").unwrap(), RepositoryFormat::Npm);
    }

    #[test]
    fn test_parse_format_pypi() {
        assert_eq!(parse_format("pypi").unwrap(), RepositoryFormat::Pypi);
    }

    #[test]
    fn test_parse_format_docker() {
        assert_eq!(parse_format("docker").unwrap(), RepositoryFormat::Docker);
    }

    #[test]
    fn test_parse_format_cargo() {
        assert_eq!(parse_format("cargo").unwrap(), RepositoryFormat::Cargo);
    }

    #[test]
    fn test_parse_format_conan() {
        assert_eq!(parse_format("conan").unwrap(), RepositoryFormat::Conan);
    }

    #[test]
    fn test_parse_format_debian() {
        assert_eq!(parse_format("debian").unwrap(), RepositoryFormat::Debian);
    }

    #[test]
    fn test_parse_format_generic() {
        assert_eq!(parse_format("generic").unwrap(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_parse_format_helm() {
        assert_eq!(parse_format("helm").unwrap(), RepositoryFormat::Helm);
    }

    #[test]
    fn test_parse_format_nuget() {
        assert_eq!(parse_format("nuget").unwrap(), RepositoryFormat::Nuget);
    }

    #[test]
    fn test_parse_format_go() {
        assert_eq!(parse_format("go").unwrap(), RepositoryFormat::Go);
    }

    #[test]
    fn test_parse_format_rubygems() {
        assert_eq!(
            parse_format("rubygems").unwrap(),
            RepositoryFormat::Rubygems
        );
    }

    #[test]
    fn test_parse_format_rpm() {
        assert_eq!(parse_format("rpm").unwrap(), RepositoryFormat::Rpm);
    }

    #[test]
    fn test_parse_format_protobuf() {
        assert_eq!(
            parse_format("protobuf").unwrap(),
            RepositoryFormat::Protobuf
        );
    }

    #[test]
    fn test_parse_format_case_insensitive() {
        assert_eq!(parse_format("Maven").unwrap(), RepositoryFormat::Maven);
        assert_eq!(parse_format("NPM").unwrap(), RepositoryFormat::Npm);
        assert_eq!(parse_format("DOCKER").unwrap(), RepositoryFormat::Docker);
    }

    #[test]
    fn test_parse_format_invalid() {
        let result = parse_format("invalid_format");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("Invalid format")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_format_all_formats() {
        // Ensure all 45+ formats parse correctly
        let formats = vec![
            "maven",
            "gradle",
            "npm",
            "pypi",
            "nuget",
            "go",
            "rubygems",
            "docker",
            "helm",
            "rpm",
            "debian",
            "conan",
            "cargo",
            "generic",
            "podman",
            "buildx",
            "oras",
            "wasm_oci",
            "helm_oci",
            "poetry",
            "conda",
            "yarn",
            "bower",
            "pnpm",
            "chocolatey",
            "powershell",
            "terraform",
            "opentofu",
            "alpine",
            "conda_native",
            "composer",
            "hex",
            "cocoapods",
            "swift",
            "pub",
            "sbt",
            "chef",
            "puppet",
            "ansible",
            "gitlfs",
            "vscode",
            "jetbrains",
            "huggingface",
            "mlmodel",
            "cran",
            "vagrant",
            "opkg",
            "p2",
            "bazel",
            "protobuf",
        ];
        for f in formats {
            assert!(parse_format(f).is_ok(), "parse_format failed for: {}", f);
        }
    }

    // -----------------------------------------------------------------------
    // parse_repo_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_repo_type_local() {
        assert_eq!(parse_repo_type("local").unwrap(), RepositoryType::Local);
    }

    #[test]
    fn test_parse_repo_type_remote() {
        assert_eq!(parse_repo_type("remote").unwrap(), RepositoryType::Remote);
    }

    #[test]
    fn test_parse_repo_type_virtual() {
        assert_eq!(parse_repo_type("virtual").unwrap(), RepositoryType::Virtual);
    }

    #[test]
    fn test_parse_repo_type_staging() {
        assert_eq!(parse_repo_type("staging").unwrap(), RepositoryType::Staging);
    }

    #[test]
    fn test_parse_repo_type_case_insensitive() {
        assert_eq!(parse_repo_type("Local").unwrap(), RepositoryType::Local);
        assert_eq!(parse_repo_type("REMOTE").unwrap(), RepositoryType::Remote);
        assert_eq!(parse_repo_type("Virtual").unwrap(), RepositoryType::Virtual);
    }

    #[test]
    fn test_parse_repo_type_invalid() {
        let result = parse_repo_type("nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("Invalid repo type")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // require_auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_some() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            scopes: None,
        };
        assert!(require_auth(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_auth_none() {
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // DTO serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repository_request_deserialization() {
        let json = r#"{
            "key": "my-repo",
            "name": "My Repo",
            "description": "A test repo",
            "format": "maven",
            "repo_type": "local",
            "is_public": true,
            "upstream_url": null,
            "quota_bytes": 1073741824
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "my-repo");
        assert_eq!(req.name, "My Repo");
        assert_eq!(req.description, Some("A test repo".to_string()));
        assert_eq!(req.format, "maven");
        assert_eq!(req.repo_type, "local");
        assert_eq!(req.is_public, Some(true));
        assert!(req.upstream_url.is_none());
        assert_eq!(req.quota_bytes, Some(1073741824));
    }

    #[test]
    fn test_create_repository_request_minimal() {
        let json = r#"{
            "key": "k",
            "name": "n",
            "format": "npm",
            "repo_type": "local"
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "k");
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.upstream_url.is_none());
        assert!(req.quota_bytes.is_none());
    }

    #[test]
    fn test_update_repository_request_all_none() {
        let json = r#"{}"#;
        let req: UpdateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert!(req.key.is_none());
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.quota_bytes.is_none());
    }

    #[test]
    fn test_repository_response_serialization() {
        let resp = RepositoryResponse {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            key: "my-repo".to_string(),
            name: "My Repo".to_string(),
            description: Some("desc".to_string()),
            format: "maven".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            storage_used_bytes: 1024,
            quota_bytes: Some(1048576),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"storage_used_bytes\":1024"));
        assert!(json.contains("\"quota_bytes\":1048576"));
    }

    #[test]
    fn test_list_repositories_query_deserialization() {
        let json = r#"{
            "page": 2,
            "per_page": 50,
            "format": "npm",
            "type": "local",
            "q": "test"
        }"#;
        let query: ListRepositoriesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.format, Some("npm".to_string()));
        assert_eq!(query.repo_type, Some("local".to_string()));
        assert_eq!(query.q, Some("test".to_string()));
    }

    #[test]
    fn test_list_artifacts_query_defaults() {
        let json = r#"{}"#;
        let query: ListArtifactsQuery = serde_json::from_str(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.q.is_none());
        assert!(query.path_prefix.is_none());
    }

    #[test]
    fn test_artifact_response_serialization() {
        let resp = ArtifactResponse {
            id: Uuid::new_v4(),
            repository_key: "my-repo".to_string(),
            path: "org/example/1.0/example-1.0.jar".to_string(),
            name: "example".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            download_count: 42,
            created_at: chrono::Utc::now(),
            metadata: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1024"));
    }

    #[test]
    fn test_add_virtual_member_request_deserialization() {
        let json = r#"{"member_key": "upstream-repo", "priority": 10}"#;
        let req: AddVirtualMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.member_key, "upstream-repo");
        assert_eq!(req.priority, Some(10));
    }

    #[test]
    fn test_add_virtual_member_request_no_priority() {
        let json = r#"{"member_key": "upstream-repo"}"#;
        let req: AddVirtualMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.member_key, "upstream-repo");
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_update_virtual_members_request_deserialization() {
        let json = r#"{
            "members": [
                {"member_key": "repo-a", "priority": 1},
                {"member_key": "repo-b", "priority": 2}
            ]
        }"#;
        let req: UpdateVirtualMembersRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.members.len(), 2);
        assert_eq!(req.members[0].member_key, "repo-a");
        assert_eq!(req.members[0].priority, 1);
        assert_eq!(req.members[1].member_key, "repo-b");
        assert_eq!(req.members[1].priority, 2);
    }

    #[test]
    fn test_virtual_member_response_serialization() {
        let resp = VirtualMemberResponse {
            id: Uuid::new_v4(),
            member_repo_id: Uuid::new_v4(),
            member_repo_key: "upstream".to_string(),
            member_repo_name: "Upstream Repo".to_string(),
            member_repo_type: "remote".to_string(),
            priority: 1,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"member_repo_key\":\"upstream\""));
        assert!(json.contains("\"priority\":1"));
    }

    // -----------------------------------------------------------------------
    // compute_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_pagination_defaults() {
        let (page, per_page, offset) = compute_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_pagination_custom_values() {
        let (page, per_page, offset) = compute_pagination(Some(3), Some(50));
        assert_eq!(page, 3);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 100);
    }

    #[test]
    fn test_compute_pagination_page_zero_becomes_one() {
        let (page, _, offset) = compute_pagination(Some(0), Some(10));
        assert_eq!(page, 1);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_pagination_per_page_capped_at_100() {
        let (_, per_page, _) = compute_pagination(Some(1), Some(200));
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_compute_pagination_large_page() {
        let (page, per_page, offset) = compute_pagination(Some(100), Some(25));
        assert_eq!(page, 100);
        assert_eq!(per_page, 25);
        assert_eq!(offset, 2475);
    }

    // -----------------------------------------------------------------------
    // compute_total_pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_total_pages_exact() {
        assert_eq!(compute_total_pages(100, 20), 5);
    }

    #[test]
    fn test_compute_total_pages_remainder() {
        assert_eq!(compute_total_pages(101, 20), 6);
    }

    #[test]
    fn test_compute_total_pages_zero_total() {
        assert_eq!(compute_total_pages(0, 20), 0);
    }

    #[test]
    fn test_compute_total_pages_single_item() {
        assert_eq!(compute_total_pages(1, 20), 1);
    }

    #[test]
    fn test_compute_total_pages_one_per_page() {
        assert_eq!(compute_total_pages(5, 1), 5);
    }

    // -----------------------------------------------------------------------
    // extract_name_from_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_from_path_nested() {
        assert_eq!(
            extract_name_from_path("org/example/1.0/example-1.0.jar"),
            "example-1.0.jar"
        );
    }

    #[test]
    fn test_extract_name_from_path_simple() {
        assert_eq!(extract_name_from_path("myfile.txt"), "myfile.txt");
    }

    #[test]
    fn test_extract_name_from_path_trailing_slash() {
        // rsplit next_back gives empty string after trailing slash
        assert_eq!(extract_name_from_path("some/path/"), "");
    }

    #[test]
    fn test_extract_name_from_path_deep() {
        assert_eq!(extract_name_from_path("a/b/c/d/e/file.bin"), "file.bin");
    }

    // -----------------------------------------------------------------------
    // build_storage_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_storage_path_basic() {
        assert_eq!(
            build_storage_path("/var/data", "my-repo"),
            "/var/data/my-repo"
        );
    }

    #[test]
    fn test_build_storage_path_relative() {
        assert_eq!(
            build_storage_path("./storage", "repo-1"),
            "./storage/repo-1"
        );
    }

    // -----------------------------------------------------------------------
    // content_disposition_attachment
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_disposition_attachment_simple() {
        assert_eq!(
            content_disposition_attachment("file.jar"),
            "attachment; filename=\"file.jar\""
        );
    }

    #[test]
    fn test_content_disposition_attachment_spaces() {
        assert_eq!(
            content_disposition_attachment("my file.zip"),
            "attachment; filename=\"my file.zip\""
        );
    }

    // -----------------------------------------------------------------------
    // extract_download_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_download_filename_path() {
        assert_eq!(
            extract_download_filename("org/example/1.0/example.jar"),
            "example.jar"
        );
    }

    #[test]
    fn test_extract_download_filename_no_slash() {
        assert_eq!(
            extract_download_filename("single-file.txt"),
            "single-file.txt"
        );
    }

    // -----------------------------------------------------------------------
    // parse_client_ip
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_client_ip_single() {
        let ip = parse_client_ip(Some("10.0.0.1"));
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_chain() {
        let ip = parse_client_ip(Some("10.0.0.1, 192.168.1.1, 172.16.0.1"));
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_none() {
        let ip = parse_client_ip(None);
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_invalid() {
        let ip = parse_client_ip(Some("not-an-ip"));
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_ipv6() {
        let ip = parse_client_ip(Some("::1"));
        assert_eq!(ip.to_string(), "::1");
    }

    #[test]
    fn test_parse_client_ip_empty() {
        let ip = parse_client_ip(Some(""));
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    // -----------------------------------------------------------------------
    // repo_to_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_to_response_basic() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            key: "maven-central".to_string(),
            name: "Maven Central".to_string(),
            description: Some("Central Maven repo".to_string()),
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/maven".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1073741824),
            replication_priority: ReplicationPriority::Immediate,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 5000);
        assert_eq!(response.key, "maven-central");
        assert_eq!(response.name, "Maven Central");
        assert_eq!(response.format, "maven");
        assert_eq!(response.repo_type, "local");
        assert!(response.is_public);
        assert_eq!(response.storage_used_bytes, 5000);
        assert_eq!(response.quota_bytes, Some(1073741824));
    }

    #[test]
    fn test_repo_to_response_zero_storage() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "npm-hosted".to_string(),
            name: "NPM Local".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Remote,
            storage_backend: "s3".to_string(),
            storage_path: "/data/npm".to_string(),
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            is_public: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 0);
        assert_eq!(response.format, "npm");
        assert_eq!(response.repo_type, "remote");
        assert!(!response.is_public);
        assert_eq!(response.storage_used_bytes, 0);
        assert!(response.quota_bytes.is_none());
        assert!(response.description.is_none());
    }

    #[test]
    fn test_repo_to_response_virtual() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "docker-all".to_string(),
            name: "Docker Virtual".to_string(),
            description: Some("Aggregated Docker".to_string()),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Virtual,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/docker".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 1024 * 1024);
        assert_eq!(response.format, "docker");
        assert_eq!(response.repo_type, "virtual");
        assert_eq!(response.storage_used_bytes, 1024 * 1024);
    }

    #[test]
    fn test_repo_to_response_staging_with_promotion() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let target_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "cargo-staging".to_string(),
            name: "Cargo Staging".to_string(),
            description: None,
            format: RepositoryFormat::Cargo,
            repo_type: RepositoryType::Staging,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/cargo-staging".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: Some(5_000_000_000),
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: Some(target_id),
            promotion_policy_id: Some(policy_id),
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 42);
        assert_eq!(response.format, "cargo");
        assert_eq!(response.repo_type, "staging");
        assert_eq!(response.storage_used_bytes, 42);
        assert_eq!(response.quota_bytes, Some(5_000_000_000));
    }
}
