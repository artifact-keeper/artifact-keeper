//! Repository management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::api::dto::Pagination;
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

/// Create repository routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_repositories).post(create_repository))
        .route(
            "/:key",
            get(get_repository)
                .patch(update_repository)
                .delete(delete_repository),
        )
        // Artifact routes nested under repository
        .route("/:key/artifacts", get(list_artifacts))
        .route(
            "/:key/artifacts/*path",
            get(get_artifact_metadata)
                .put(upload_artifact)
                .delete(delete_artifact),
        )
        // Download uses a separate route prefix to avoid wildcard conflict
        .route("/:key/download/*path", get(download_artifact))
}

#[derive(Debug, Deserialize)]
pub struct ListRepositoriesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub format: Option<String>,
    #[serde(rename = "type")]
    pub repo_type: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct UpdateRepositoryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
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
        _ => Err(AppError::Validation(format!("Invalid format: {}", s))),
    }
}

fn parse_repo_type(s: &str) -> Result<RepositoryType> {
    match s.to_lowercase().as_str() {
        "local" => Ok(RepositoryType::Local),
        "remote" => Ok(RepositoryType::Remote),
        "virtual" => Ok(RepositoryType::Virtual),
        _ => Err(AppError::Validation(format!("Invalid repo type: {}", s))),
    }
}

/// List repositories
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
        .list(offset, per_page as i64, format_filter, type_filter, false, query.q.as_deref())
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let items: Vec<RepositoryResponse> = repos
        .into_iter()
        .map(|r| repo_to_response(r, 0)) // Storage usage calculated on-demand per repo
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
pub async fn create_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    // Require authentication
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
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
pub async fn update_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    // Require authentication
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let service = state.create_repository_service();

    // Get existing repo by key
    let existing = service.get_by_key(&key).await?;

    let repo = service
        .update(
            existing.id,
            ServiceUpdateRepoReq {
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
pub async fn delete_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<()> {
    // Require authentication
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let service = state.create_repository_service();
    let repo = service.get_by_key(&key).await?;
    service.delete(repo.id).await?;
    Ok(())
}

// Artifact handlers (nested under repository)

#[derive(Debug, Deserialize)]
pub struct ListArtifactsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub q: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Serialize)]
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
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactListResponse {
    pub items: Vec<ArtifactResponse>,
    pub pagination: Pagination,
}

/// List artifacts in repository
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
pub async fn upload_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ArtifactResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
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

/// Download artifact
pub async fn download_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let storage = Arc::new(FilesystemStorage::new(&repo.storage_path));
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    // Get client IP
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

    let (artifact, content) = artifact_service
        .download(
            repo.id,
            &path,
            auth.map(|a| a.user_id),
            Some(ip_addr.to_string()),
            user_agent.as_deref(),
        )
        .await?;

    Ok((
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
        ],
        content,
    ))
}

/// Delete artifact
pub async fn delete_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
) -> Result<()> {
    // Require authentication
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
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
