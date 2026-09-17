//! Image builder and inspector for container repositories.
//!
//! - `GET  /repositories/{key}/image-inspect?image=&reference=` — describe
//!   a pushed image from storage (config, history, layers, provenance).
//! - `GET  /repositories/{key}/image-builds/settings` — whether builds are
//!   configured on this instance and what policy applies.
//! - `POST /repositories/{key}/image-builds/render` — validate a spec and
//!   return the Containerfile the server would build (dry run).
//! - `POST /repositories/{key}/image-builds` — queue a build; 202 with the
//!   record. `GET` lists, `GET /{id}` reads one, `GET /{id}/log` streams
//!   the buildctl output so far as text.
//!
//! Reads need the repository to be visible to the caller; building needs
//! write access and a local container repository (a remote or virtual repo
//! cannot receive a push).

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::{require_repo_write_access, require_visible};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};
use crate::services::image_build_service::{
    self, image_name_re, tag_re, BuildJob, ImageBuildRecord, ImageBuildSettings, ImageBuildSpec,
    ImageBuildStore, NewImageBuild,
};
use crate::services::oci_inspect::{
    self, ImageConfig, ImageHistoryEntry, ImageInspect, ImageLayer, ImagePlatform, ImageProvenance,
};
use crate::services::repository_service::RepositoryService;

#[derive(OpenApi)]
#[openapi(
    paths(inspect_image, build_settings, render_build, list_builds, create_build, get_build, get_build_log),
    components(schemas(
        ImageInspect, ImageConfig, ImageHistoryEntry, ImageLayer, ImagePlatform, ImageProvenance,
        ImageBuildSpec, ImageBuildSettingsResponse, RenderImageBuildRequest, RenderImageBuildResponse,
        CreateImageBuildRequest, ImageBuildResponse, ImageBuildListResponse
    )),
    tags((name = "image-builds", description = "Server-side container image builds and image inspection"))
)]
pub struct ImageBuildsApiDoc;

/// Routes nested under `/api/v1/repositories`.
pub fn repo_router() -> Router<SharedState> {
    Router::new()
        .route("/:key/image-inspect", get(inspect_image))
        .route("/:key/image-builds", get(list_builds).post(create_build))
        .route("/:key/image-builds/settings", get(build_settings))
        .route("/:key/image-builds/render", post(render_build))
        .route("/:key/image-builds/:id", get(get_build))
        .route("/:key/image-builds/:id/log", get(get_build_log))
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct InspectQuery {
    /// Image path within the repository (`spike`, `team/ray`).
    pub image: String,
    /// Tag or `sha256:` digest.
    pub reference: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImageBuildSettingsResponse {
    /// False when `AK_BUILDKIT_ADDR` / `AK_IMAGE_BUILD_PUSH_REGISTRY` are unset.
    pub enabled: bool,
    /// Whether this repository can receive builds (local container repo).
    pub repository_buildable: bool,
    pub base_allowlist: Vec<String>,
    pub allow_run: bool,
    pub timeout_secs: u64,
    pub max_concurrent: usize,
    /// The address buildkitd pushes to, for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_registry: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenderImageBuildRequest {
    pub spec: ImageBuildSpec,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RenderImageBuildResponse {
    pub containerfile: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateImageBuildRequest {
    /// Image path within the repository (`team/ray`).
    pub image: String,
    /// Tag to push (`2.56.0-genomics`).
    pub tag: String,
    pub spec: ImageBuildSpec,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImageBuildResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub image: String,
    pub tag: String,
    /// `<repo key>/<image>:<tag>` — the reference within this registry.
    pub reference: String,
    /// queued | running | succeeded | failed
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub spec: serde_json::Value,
    pub containerfile: String,
    pub requested_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub log_bytes: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImageBuildListResponse {
    pub items: Vec<ImageBuildResponse>,
    pub total: usize,
}

fn to_response(repo_key: &str, r: ImageBuildRecord) -> ImageBuildResponse {
    ImageBuildResponse {
        reference: format!("{}/{}:{}", repo_key, r.image, r.tag),
        id: r.id,
        repository_key: repo_key.to_string(),
        image: r.image,
        tag: r.tag,
        status: r.status,
        digest: r.digest,
        error: r.error,
        spec: r.spec,
        containerfile: r.containerfile,
        requested_by: r.requested_by_name,
        created_at: r.created_at,
        started_at: r.started_at,
        finished_at: r.finished_at,
        log_bytes: r.log_bytes,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Container-image repositories: the Docker format and its OCI-compatible
/// aliases. Helm-as-OCI and WASM-as-OCI hold other artifact kinds.
pub fn is_container_image_repo(repo: &Repository) -> bool {
    matches!(
        repo.format,
        RepositoryFormat::Docker
            | RepositoryFormat::Podman
            | RepositoryFormat::Buildx
            | RepositoryFormat::Oras
    )
}

fn require_container_repo(repo: &Repository) -> Result<()> {
    if !is_container_image_repo(repo) {
        return Err(AppError::Validation(format!(
            "repository {} is a {} repository, not a container image repository",
            repo.key,
            repo.format.as_key()
        )));
    }
    Ok(())
}

fn require_buildable(repo: &Repository) -> Result<()> {
    require_container_repo(repo)?;
    if repo.repo_type != RepositoryType::Local {
        return Err(AppError::Validation(format!(
            "repository {} is not a local repository; builds push into local repositories only",
            repo.key
        )));
    }
    Ok(())
}

async fn resolve_manifest_digest(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    image: &str,
    reference: &str,
) -> Result<String> {
    if reference.starts_with("sha256:") {
        return Ok(reference.to_string());
    }
    let digest = sqlx::query_scalar::<_, String>(
        "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
    )
    .bind(repo_id)
    .bind(image)
    .bind(reference)
    .fetch_optional(db)
    .await?;
    digest.ok_or_else(|| AppError::NotFound(format!("no tag {reference} for image {image}")))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    operation_id = "inspect_image",
    path = "/{key}/image-inspect",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("image" = String, Query, description = "Image path within the repository"),
        ("reference" = String, Query, description = "Tag or sha256: digest")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The image as its manifest, config and provenance describe it", body = ImageInspect),
        (status = 404, description = "Repository, image or reference not found")
    )
)]
async fn inspect_image(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(q): Query<InspectQuery>,
) -> Result<Json<ImageInspect>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    require_container_repo(&repo)?;
    if !image_name_re().is_match(&q.image) {
        return Err(AppError::Validation(format!(
            "{:?} is not a valid image name",
            q.image
        )));
    }
    let digest = resolve_manifest_digest(&state.db, repo.id, &q.image, &q.reference).await?;
    let storage = state.storage_for_repo(&repo.storage_location())?;
    let reference = format!("{}/{}:{}", repo.key, q.image, q.reference);
    let doc = oci_inspect::inspect(storage.as_ref(), &reference, &digest).await?;
    Ok(Json(doc))
}

#[utoipa::path(
    get,
    operation_id = "image_build_settings",
    path = "/{key}/image-builds/settings",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(("key" = String, Path, description = "Repository key")),
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Builder availability and policy", body = ImageBuildSettingsResponse))
)]
async fn build_settings(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<ImageBuildSettingsResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    let s = ImageBuildSettings::from_env();
    Ok(Json(ImageBuildSettingsResponse {
        enabled: s.enabled(),
        repository_buildable: require_buildable(&repo).is_ok(),
        base_allowlist: s.base_allowlist.clone(),
        allow_run: s.allow_run,
        timeout_secs: s.timeout.as_secs(),
        max_concurrent: s.max_concurrent,
        push_registry: s.push_registry.clone(),
    }))
}

#[utoipa::path(
    post,
    operation_id = "render_image_build",
    path = "/{key}/image-builds/render",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(("key" = String, Path, description = "Repository key")),
    request_body = RenderImageBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The Containerfile the server would build", body = RenderImageBuildResponse),
        (status = 400, description = "The spec is invalid or refused by policy")
    )
)]
async fn render_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<RenderImageBuildRequest>,
) -> Result<Json<RenderImageBuildResponse>> {
    let auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &repo_service).await?;
    require_container_repo(&repo)?;
    let settings = ImageBuildSettings::from_env();
    let warnings = image_build_service::validate_spec(&req.spec, &settings)?;
    Ok(Json(RenderImageBuildResponse {
        containerfile: image_build_service::render_containerfile(&req.spec),
        warnings,
    }))
}

#[utoipa::path(
    get,
    operation_id = "list_image_builds",
    path = "/{key}/image-builds",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(("key" = String, Path, description = "Repository key")),
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Builds, newest first", body = ImageBuildListResponse))
)]
async fn list_builds(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<ImageBuildListResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    let rows = ImageBuildStore::new(&state.db).list(repo.id, 100).await?;
    let items: Vec<ImageBuildResponse> = rows
        .into_iter()
        .map(|r| to_response(&repo.key, r))
        .collect();
    let total = items.len();
    Ok(Json(ImageBuildListResponse { items, total }))
}

#[utoipa::path(
    post,
    operation_id = "create_image_build",
    path = "/{key}/image-builds",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CreateImageBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 202, description = "Build queued", body = ImageBuildResponse),
        (status = 400, description = "Invalid spec, image name or tag; or the repository cannot receive builds"),
        (status = 503, description = "Image builds are not configured on this instance")
    )
)]
async fn create_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<CreateImageBuildRequest>,
) -> Result<Response> {
    let auth = require_auth(auth)?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &repo_service).await?;
    require_buildable(&repo)?;
    let settings = ImageBuildSettings::from_env();
    if !settings.enabled() {
        return Err(AppError::ServiceUnavailable(
            "image builds are not configured: set AK_BUILDKIT_ADDR and AK_IMAGE_BUILD_PUSH_REGISTRY".to_string(),
        ));
    }
    if !image_name_re().is_match(&req.image) {
        return Err(AppError::Validation(format!(
            "{:?} is not a valid image name (lowercase path segments)",
            req.image
        )));
    }
    if !tag_re().is_match(&req.tag) {
        return Err(AppError::Validation(format!(
            "{:?} is not a valid tag",
            req.tag
        )));
    }
    image_build_service::validate_spec(&req.spec, &settings)?;
    let containerfile = image_build_service::render_containerfile(&req.spec);
    let store = ImageBuildStore::new(&state.db);
    let record = store
        .insert(NewImageBuild {
            repository_id: repo.id,
            image: &req.image,
            tag: &req.tag,
            spec: &req.spec,
            containerfile: &containerfile,
            requested_by: Some(auth.user_id),
            requested_by_name: &auth.username,
        })
        .await?;
    tracing::info!(
        build = %record.id, repo = %repo.key, image = %req.image, tag = %req.tag, user = %auth.username,
        "image build queued"
    );
    let job = BuildJob {
        db: state.db.clone(),
        config: Arc::new(state.config.clone()),
        settings,
        record: record.clone(),
        repository_key: repo.key.clone(),
        user_id: auth.user_id,
        username: auth.username.clone(),
    };
    tokio::spawn(image_build_service::run_build(job));
    Ok((StatusCode::ACCEPTED, Json(to_response(&repo.key, record))).into_response())
}

#[utoipa::path(
    get,
    operation_id = "get_image_build",
    path = "/{key}/image-builds/{id}",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Build id")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The build", body = ImageBuildResponse),
        (status = 404, description = "No such build")
    )
)]
async fn get_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Json<ImageBuildResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    let record = ImageBuildStore::new(&state.db)
        .get(repo.id, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no build {id} in repository {key}")))?;
    Ok(Json(to_response(&repo.key, record)))
}

#[utoipa::path(
    get,
    operation_id = "get_image_build_log",
    path = "/{key}/image-builds/{id}/log",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("id" = Uuid, Path, description = "Build id")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The buildctl output so far, text/plain"),
        (status = 404, description = "No such build")
    )
)]
async fn get_build_log(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Response> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    let log = ImageBuildStore::new(&state.db)
        .log(repo.id, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no build {id} in repository {key}")))?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        log,
    )
        .into_response())
}
