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
    ImageBuildStore, NewImageBuild, PackageGroup, PackageManager,
};
use crate::services::oci_inspect::{
    self, ImageConfig, ImageHistoryEntry, ImageInspect, ImageLayer, ImagePlatform, ImageProvenance,
};
use crate::services::repository_service::RepositoryService;

#[derive(OpenApi)]
#[openapi(
    paths(inspect_image, build_settings, base_image_info, render_build, list_builds, create_build, get_build, get_build_log),
    components(schemas(
        ImageInspect, ImageConfig, ImageHistoryEntry, ImageLayer, ImagePlatform, ImageProvenance,
        ImageBuildSpec, PackageGroup, PackageManager, ImageBuildSettingsResponse, RenderImageBuildRequest, RenderImageBuildResponse,
        CreateImageBuildRequest, ImageBuildResponse, ImageBuildListResponse, BaseImageInfo
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
        .route("/:key/image-builds/base-info", get(base_image_info))
        .route("/:key/image-builds/render", post(render_build))
        .route("/:key/image-builds/:id", get(get_build))
        .route("/:key/image-builds/:id/log", get(get_build_log))
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct InspectQuery {
    /// Image path within the repository (`spike`, `team/app`).
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
    /// Whole-Dockerfile specs are accepted on this instance.
    pub allow_dockerfile: bool,
    /// Package managers a spec may install with, for the UI's dropdown.
    pub supported_package_managers: Vec<String>,
    /// Building is restricted to administrators on this instance.
    pub admin_only: bool,
    /// Whether the caller may build here: repository write access, plus
    /// admin when `admin_only`.
    pub caller_may_build: bool,
    /// The pip index every generated `pip install` uses, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pip_index_url: Option<String>,
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
    /// Image path within the repository (`team/app`).
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct BaseInfoQuery {
    /// The base image reference as a spec would name it.
    pub image: String,
}

/// What this registry knows about a base image: filled in only when the
/// reference names an image stored here (a local repository, or a remote
/// repository's cache), otherwise `found: false` and the console falls back
/// to guessing from the name.
#[derive(Debug, Serialize, ToSchema)]
pub struct BaseImageInfo {
    pub found: bool,
    /// `<repo>/<image>:<tag>` inside this registry, when found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// The user the base image runs as; the spec's `user` defaults to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// apt | dnf | microdnf | yum | apk, from the image's build history and
    /// labels; absent when the image does not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_manager: Option<String>,
    /// Whether the image carries pip (a `pip install` in its history or a
    /// Python image label).
    pub has_pip: bool,
    /// Whether the image carries conda.
    pub has_conda: bool,
}

/// Split a base image reference into `(repo key, image, tag)` when it names
/// an image in this registry: `[<push host>/]<repo>/<image>:<tag>`, with
/// the push host optional so `images/base:1.0` works too. A digest
/// reference (`@sha256:…`) is accepted in place of the tag.
pub fn parse_local_base_reference(
    image: &str,
    push_registry: Option<&str>,
) -> Option<(String, String, String)> {
    let mut rest = image.trim();
    if let Some(host) = push_registry {
        if let Some(r) = rest.strip_prefix(host) {
            rest = r.strip_prefix('/')?;
        }
    }
    let (path, reference) = match rest.rsplit_once('@') {
        Some((p, d)) if d.starts_with("sha256:") => (p, d.to_string()),
        _ => {
            let (p, t) = rest.rsplit_once(':')?;
            if t.contains('/') {
                return None;
            }
            (p, t.to_string())
        }
    };
    let (repo, name) = path.split_once('/')?;
    if repo.is_empty() || name.is_empty() || repo.contains('.') || repo.contains(':') {
        return None;
    }
    Some((repo.to_string(), name.to_string(), reference))
}

fn base_info_from_inspect(reference: &str, doc: &ImageInspect) -> BaseImageInfo {
    let mentions = |needle: &str| doc.history.iter().any(|h| h.created_by.contains(needle));
    let platform = doc.platforms.first();
    BaseImageInfo {
        found: true,
        reference: Some(reference.to_string()),
        digest: Some(doc.digest.clone()),
        os: platform.map(|p| p.os.clone()),
        architecture: platform.map(|p| p.architecture.clone()),
        user: Some(doc.config.user.clone()).filter(|u| !u.is_empty()),
        system_manager: oci_inspect::detect_system_manager(&doc.history, &doc.config.labels)
            .map(str::to_string),
        has_pip: mentions("pip install")
            || mentions("pip3 install")
            || doc.config.env.contains_key("PYTHON_VERSION")
            || doc
                .config
                .env
                .get("PATH")
                .is_some_and(|p| p.contains("anaconda") || p.contains("conda")),
        has_conda: mentions("conda install")
            || doc.config.env.contains_key("CONDA_DIR")
            || doc
                .config
                .env
                .get("PATH")
                .is_some_and(|p| p.contains("conda")),
    }
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

/// The instance-wide gate on top of repository write access: administrators
/// only unless `AK_IMAGE_BUILD_ADMIN_ONLY=false`.
fn require_may_build(auth: &AuthExtension, settings: &ImageBuildSettings) -> Result<()> {
    if !settings.caller_may_build(auth.is_admin) {
        return Err(AppError::Authorization(
            "image builds are restricted to administrators on this instance (AK_IMAGE_BUILD_ADMIN_ONLY)".to_string(),
        ));
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

/// The settings document for one repository and caller.
fn settings_response(
    repo: &Repository,
    s: &ImageBuildSettings,
    caller_may_build: bool,
) -> ImageBuildSettingsResponse {
    ImageBuildSettingsResponse {
        enabled: s.enabled(),
        repository_buildable: require_buildable(repo).is_ok(),
        base_allowlist: s.base_allowlist.clone(),
        allow_run: s.allow_run,
        allow_dockerfile: s.allow_dockerfile,
        supported_package_managers: s
            .supported_managers()
            .iter()
            .map(|m| m.to_string())
            .collect(),
        admin_only: s.admin_only,
        caller_may_build,
        pip_index_url: s.pip_index_url.clone(),
        timeout_secs: s.timeout.as_secs(),
        max_concurrent: s.max_concurrent,
        push_registry: s.push_registry.clone(),
    }
}

/// Validate a spec and render it: the dry run.
fn render_response(
    spec: &ImageBuildSpec,
    settings: &ImageBuildSettings,
) -> Result<RenderImageBuildResponse> {
    let warnings = image_build_service::validate_spec(spec, settings)?;
    Ok(RenderImageBuildResponse {
        containerfile: image_build_service::render_containerfile_with(
            spec,
            settings.pip_index_url.as_deref(),
        ),
        warnings,
    })
}

/// Everything about a build request that can be refused before touching
/// the database; returns the Containerfile to build.
fn prepare_build(req: &CreateImageBuildRequest, settings: &ImageBuildSettings) -> Result<String> {
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
    image_build_service::validate_spec(&req.spec, settings)?;
    Ok(image_build_service::render_containerfile_with(
        &req.spec,
        settings.pip_index_url.as_deref(),
    ))
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
    let caller_may_build = match &auth {
        Some(a) => {
            s.caller_may_build(a.is_admin)
                && require_repo_write_access(a, &repo, &repo_service)
                    .await
                    .is_ok()
        }
        None => false,
    };
    Ok(Json(settings_response(&repo, &s, caller_may_build)))
}

#[utoipa::path(
    get,
    operation_id = "image_build_base_info",
    path = "/{key}/image-builds/base-info",
    context_path = "/api/v1/repositories",
    tag = "image-builds",
    params(
        ("key" = String, Path, description = "Repository key (the one being built into)"),
        ("image" = String, Query, description = "Base image reference as the spec names it")
    ),
    responses((status = 200, body = BaseImageInfo)),
    security(("bearer_auth" = []))
)]
/// What the registry knows about a base image, for the wizard: its
/// distribution family from its own build history and labels, its user, and
/// whether it carries pip or conda. Only images stored in this registry are
/// looked up; anything else is `found: false`.
async fn base_image_info(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(q): Query<BaseInfoQuery>,
) -> Result<Json<BaseImageInfo>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;
    let settings = ImageBuildSettings::from_env();
    let not_found = BaseImageInfo {
        found: false,
        reference: None,
        digest: None,
        os: None,
        architecture: None,
        user: None,
        system_manager: None,
        has_pip: false,
        has_conda: false,
    };
    let Some((base_repo_key, image, reference)) =
        parse_local_base_reference(&q.image, settings.push_registry.as_deref())
    else {
        return Ok(Json(not_found));
    };
    let base_repo = match repo_service.get_by_key(&base_repo_key).await {
        Ok(r) => r,
        Err(AppError::NotFound(_)) => return Ok(Json(not_found)),
        Err(e) => return Err(e),
    };
    require_visible(&base_repo, &auth, &repo_service).await?;
    if !is_container_image_repo(&base_repo) {
        return Ok(Json(not_found));
    }
    let digest = match resolve_manifest_digest(&state.db, base_repo.id, &image, &reference).await {
        Ok(d) => d,
        Err(AppError::NotFound(_)) => return Ok(Json(not_found)),
        Err(e) => return Err(e),
    };
    let storage = state.storage_for_repo(&base_repo.storage_location())?;
    let full = format!("{}/{}:{}", base_repo.key, image, reference);
    match oci_inspect::inspect(storage.as_ref(), &full, &digest).await {
        Ok(doc) => Ok(Json(base_info_from_inspect(&full, &doc))),
        Err(AppError::NotFound(_)) => Ok(Json(not_found)),
        Err(e) => Err(e),
    }
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
    require_may_build(&auth, &settings)?;
    Ok(Json(render_response(&req.spec, &settings)?))
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
    require_may_build(&auth, &settings)?;
    let containerfile = prepare_build(&req, &settings)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::repository::ReplicationPriority;
    use chrono::Utc;
    use std::time::Duration;

    fn repo(format: RepositoryFormat, repo_type: RepositoryType) -> Repository {
        Repository {
            versioning_enabled: false,
            id: Uuid::new_v4(),
            key: "images".to_string(),
            name: "Container images".to_string(),
            description: None,
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/images".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            project_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn auth(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "builder".to_string(),
            email: "builder@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    fn settings() -> ImageBuildSettings {
        ImageBuildSettings {
            buildkit_addr: Some("tcp://buildkitd:1234".into()),
            buildctl_path: "buildctl".into(),
            push_registry: Some("registry:8080".into()),
            registry_insecure: true,
            base_allowlist: vec!["python:".into()],
            allow_run: false,
            allow_dockerfile: false,
            timeout: Duration::from_secs(1800),
            max_concurrent: 2,
            admin_only: true,
            pip_index_url: Some("http://pypi/simple/".into()),
        }
    }

    fn spec() -> ImageBuildSpec {
        ImageBuildSpec {
            base_image: "python:3.12-slim".into(),
            packages: vec![PackageGroup {
                manager: PackageManager::Pip,
                packages: vec!["polars-lts-cpu==1.9.0".into()],
                channels: vec![],
            }],
            ..Default::default()
        }
    }

    fn test_state() -> SharedState {
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new("/tmp/test-image-builds"),
        );
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(crate::api::AppState::new(
            crate::config::Config::test_config(),
            pool,
            storage,
            registry,
        ))
    }

    #[test]
    fn container_repositories_are_the_docker_family_minus_helm_and_wasm() {
        for f in [
            RepositoryFormat::Docker,
            RepositoryFormat::Podman,
            RepositoryFormat::Buildx,
            RepositoryFormat::Oras,
        ] {
            let r = repo(f, RepositoryType::Local);
            assert!(is_container_image_repo(&r));
            assert!(require_container_repo(&r).is_ok());
            assert!(require_buildable(&r).is_ok());
        }
        let helm = repo(RepositoryFormat::HelmOci, RepositoryType::Local);
        assert!(!is_container_image_repo(&helm));
        let err = require_container_repo(&helm).unwrap_err().to_string();
        assert!(err.contains("not a container image repository"), "{err}");
        let remote = repo(RepositoryFormat::Docker, RepositoryType::Remote);
        assert!(require_container_repo(&remote).is_ok());
        assert!(require_buildable(&remote)
            .unwrap_err()
            .to_string()
            .contains("local repositories only"));
    }

    #[test]
    fn the_admin_only_gate_and_the_auth_requirement() {
        let s = settings();
        assert!(require_may_build(&auth(true), &s).is_ok());
        let err = require_may_build(&auth(false), &s).unwrap_err();
        assert!(matches!(err, AppError::Authorization(_)), "{err}");
        let mut open = s.clone();
        open.admin_only = false;
        assert!(require_may_build(&auth(false), &open).is_ok());

        assert!(matches!(
            require_auth(None).unwrap_err(),
            AppError::Authentication(_)
        ));
        assert_eq!(require_auth(Some(auth(false))).unwrap().username, "builder");
    }

    #[test]
    fn settings_response_reports_policy_and_repository_state() {
        let s = settings();
        let r = settings_response(
            &repo(RepositoryFormat::Docker, RepositoryType::Local),
            &s,
            true,
        );
        assert!(r.enabled && r.repository_buildable && r.caller_may_build && r.admin_only);
        assert_eq!(r.supported_package_managers.len(), 7);
        assert_eq!(r.supported_package_managers[0], "apt");
        assert_eq!(r.base_allowlist, vec!["python:"]);
        assert_eq!(r.timeout_secs, 1800);
        assert_eq!(r.max_concurrent, 2);
        assert_eq!(r.push_registry.as_deref(), Some("registry:8080"));
        assert_eq!(r.pip_index_url.as_deref(), Some("http://pypi/simple/"));
        assert!(!r.allow_run && !r.allow_dockerfile);

        let mut off = s.clone();
        off.buildkit_addr = None;
        let r = settings_response(
            &repo(RepositoryFormat::Docker, RepositoryType::Virtual),
            &off,
            false,
        );
        assert!(!r.enabled && !r.repository_buildable && !r.caller_may_build);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(
            json["supported_package_managers"].as_array().unwrap().len(),
            7
        );
    }

    #[test]
    fn render_response_validates_then_renders_with_the_pip_index() {
        let out = render_response(&spec(), &settings()).unwrap();
        assert!(out.containerfile.contains("FROM python:3.12-slim"));
        assert!(out
            .containerfile
            .contains("--index-url 'http://pypi/simple/'"));
        assert!(out.warnings.is_empty());
        let mut bad = spec();
        bad.base_image = "nginx:1".into();
        assert!(matches!(
            render_response(&bad, &settings()).unwrap_err(),
            AppError::Validation(_)
        ));
    }

    #[test]
    fn prepare_build_refuses_what_the_runner_could_not_use() {
        let req = |image: &str, tag: &str| CreateImageBuildRequest {
            image: image.into(),
            tag: tag.into(),
            spec: spec(),
        };
        let s = settings();
        let containerfile = prepare_build(&req("team/app", "1.0-genomics"), &s).unwrap();
        assert!(containerfile.contains("polars-lts-cpu==1.9.0"));

        let err = |r: CreateImageBuildRequest, s: &ImageBuildSettings| {
            prepare_build(&r, s).unwrap_err().to_string()
        };
        assert!(err(req("Team/App", "1"), &s).contains("not a valid image name"));
        assert!(err(req("team/app", "bad tag"), &s).contains("not a valid tag"));
        let mut disabled = s.clone();
        disabled.push_registry = None;
        assert!(err(req("team/app", "1"), &disabled).contains("not configured"));
        let mut outside = req("team/app", "1");
        outside.spec.base_image = "nginx:1".into();
        assert!(err(outside, &s).contains("allowed prefix"));
    }

    #[test]
    fn to_response_names_the_reference_inside_the_repository() {
        let now = Utc::now();
        let rec = ImageBuildRecord {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            image: "team/app".into(),
            tag: "1.0".into(),
            spec: serde_json::json!({"base_image": "x"}),
            containerfile: "FROM x\n".into(),
            status: "queued".into(),
            digest: None,
            error: None,
            requested_by: None,
            requested_by_name: "alice".into(),
            created_at: now,
            started_at: None,
            finished_at: None,
            log_bytes: 0,
        };
        let r = to_response("images", rec);
        assert_eq!(r.reference, "images/team/app:1.0");
        assert_eq!(r.repository_key, "images");
        assert_eq!(r.requested_by, "alice");
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("digest").is_none(), "None fields are omitted");
        assert_eq!(json["status"], "queued");
    }

    #[test]
    fn local_base_references_are_recognised_with_or_without_the_push_host() {
        let host = Some("registry.svc:8080");
        assert_eq!(
            parse_local_base_reference("registry.svc:8080/images/base:1.0", host),
            Some(("images".into(), "base".into(), "1.0".into()))
        );
        assert_eq!(
            parse_local_base_reference("images/team/base:1.0", host),
            Some(("images".into(), "team/base".into(), "1.0".into()))
        );
        let d = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            parse_local_base_reference(&format!("images/base@{d}"), None),
            Some(("images".into(), "base".into(), d))
        );
        // External references: a registry host or no repository segment.
        assert_eq!(
            parse_local_base_reference("someorg/app:1.0", host),
            Some(("someorg".into(), "app".into(), "1.0".into()))
        );
        assert_eq!(
            parse_local_base_reference("docker.io/library/python:3.12", host),
            None
        );
        assert_eq!(
            parse_local_base_reference("registry.access.redhat.com/ubi9/ubi:9.4", host),
            None
        );
        assert_eq!(parse_local_base_reference("python:3.12", host), None);
        assert_eq!(parse_local_base_reference("images/base", host), None);
    }

    #[test]
    fn base_info_summarises_an_inspected_image() {
        let mut doc = ImageInspect {
            reference: "images/base:1.0".into(),
            digest: "sha256:abc".into(),
            index_digest: None,
            platforms: vec![ImagePlatform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            }],
            size_bytes: 1,
            config: ImageConfig::default(),
            history: vec![],
            layers: vec![],
            provenance: None,
            source: "registry".into(),
        };
        doc.config.user = "app".into();
        doc.config
            .env
            .insert("PATH".into(), "/opt/conda/bin:/usr/bin".into());
        doc.history.push(ImageHistoryEntry {
            created: None,
            created_by: "RUN /bin/sh -c apt-get update && apt-get install -y libgomp1".into(),
            comment: None,
            empty_layer: false,
            layer_digest: None,
            size_bytes: None,
        });
        let info = base_info_from_inspect("images/base:1.0", &doc);
        assert!(info.found);
        assert_eq!(info.system_manager.as_deref(), Some("apt"));
        assert_eq!(info.user.as_deref(), Some("app"));
        assert_eq!(info.architecture.as_deref(), Some("amd64"));
        assert!(info.has_pip && info.has_conda, "conda on PATH");
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["system_manager"], "apt");

        doc.config = ImageConfig::default();
        doc.history.clear();
        let bare = base_info_from_inspect("x/y:1", &doc);
        assert!(
            bare.system_manager.is_none()
                && bare.user.is_none()
                && !bare.has_pip
                && !bare.has_conda
        );
    }

    #[tokio::test]
    async fn a_digest_reference_resolves_without_the_database() {
        let state = test_state();
        let d = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            resolve_manifest_digest(&state.db, Uuid::nil(), "team/app", &d)
                .await
                .unwrap(),
            d
        );
    }

    #[tokio::test]
    async fn write_handlers_reject_anonymous_callers_before_touching_the_database() {
        let state = test_state();
        let err = render_build(
            State(state.clone()),
            Extension(None),
            Path("images".to_string()),
            Json(RenderImageBuildRequest { spec: spec() }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "{err}");
        let err = create_build(
            State(state),
            Extension(None),
            Path("images".to_string()),
            Json(CreateImageBuildRequest {
                image: "team/app".into(),
                tag: "1".into(),
                spec: spec(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "{err}");
    }
}
