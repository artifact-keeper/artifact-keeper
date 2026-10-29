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

use crate::api::handlers::repositories::{
    require_repo_action, require_repo_write_access, require_visible,
};
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

/// Everything a caller needs to render or start a build into `repo`.
///
/// A build pushes an image into the repository, so beyond the instance-wide
/// admin-only switch (`require_may_build`) it is a repository write: the
/// `write:artifacts` token scope, the tenant gate, and the deny-by-default
/// repository `write` action. The tenant gate alone is a no-op on a public
/// repository and admits a read-only member of a private one, which with
/// `AK_IMAGE_BUILD_ADMIN_ONLY=false` let either build and push
/// (GHSA-mvmh-g8wm-r3cp).
async fn authorize_build(
    state: &SharedState,
    auth: &AuthExtension,
    repo: &Repository,
    settings: &ImageBuildSettings,
) -> Result<()> {
    auth.require_scope("write:artifacts")?;
    let repo_service = RepositoryService::new(state.db.clone());
    require_repo_write_access(auth, repo, &repo_service).await?;
    require_may_build(auth, settings)?;
    require_repo_action(auth, repo.id, "write", &state.permission_service).await
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

/// Resolve `reference` (a tag or a `sha256:` digest) to the manifest digest
/// to inspect, within ONE repository and image.
///
/// A tag resolves through that image's `oci_tags` row. A digest is accepted
/// only when the manifest belongs to the repository and image
/// ([`digest_belongs_to_image`]): manifest and blob objects are addressed by
/// digest alone, and on a cloud backend shared by several repositories the
/// object for another repository's digest is readable under any key prefix,
/// so the storage read cannot be what decides. A digest that belongs to
/// another repository or image gets the same `NotFound` as one that does not
/// exist anywhere. A Virtual repository records no manifests of its own, so
/// neither tags nor digests resolve on one.
async fn resolve_manifest_digest(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    repo_key: &str,
    image: &str,
    reference: &str,
) -> Result<String> {
    if reference.starts_with("sha256:") {
        if digest_belongs_to_image(db, repo_id, repo_key, image, reference).await? {
            return Ok(reference.to_string());
        }
        return Err(AppError::NotFound(format!(
            "no manifest {reference} for image {image}"
        )));
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

/// Deepest index nesting [`digest_belongs_to_image`] follows from a child
/// manifest up to an owning index (the registry's own limit for the same
/// walk).
const MAX_OWNING_INDEX_DEPTH: i32 = 8;

/// Upper bound on the catalog rows read for the path-attribution half of the
/// ancestor check, so a pathological reference graph cannot turn one request
/// into an unbounded read. The tag half has no such bound.
const MAX_ANCESTOR_CATALOG_ROWS: i64 = 256;

/// The repository's indexes that reference `$2`, directly or through nested
/// indexes, at most `$3` levels up.
macro_rules! ancestor_indexes_cte {
    () => {
        r#"
    WITH RECURSIVE anc(digest, depth) AS (
        SELECT omr.parent_digest, 1
        FROM oci_manifest_refs omr
        WHERE omr.repository_id = $1 AND omr.child_digest = $2
      UNION
        SELECT omr.parent_digest, anc.depth + 1
        FROM oci_manifest_refs omr
        JOIN anc ON omr.child_digest = anc.digest
        WHERE omr.repository_id = $1 AND anc.depth < $3
    )
"#
    };
}

/// Whether a tag of image `$4` names any index above `$2`.
const ANCESTOR_TAGGED_UNDER_IMAGE_SQL: &str = concat!(
    ancestor_indexes_cte!(),
    r#"
    SELECT EXISTS (
        SELECT 1 FROM anc
        JOIN oci_tags ot
          ON ot.repository_id = $1 AND ot.name = $4 AND ot.manifest_digest = anc.digest
    )
"#
);

/// Live manifest-shaped catalog rows of any index above `$2` (`$4` caps the
/// count), for path attribution in Rust.
const ANCESTOR_CATALOG_PATHS_SQL: &str = concat!(
    ancestor_indexes_cte!(),
    r#"
    SELECT a.path::text
    FROM artifacts a
    JOIN anc
      ON anc.digest LIKE 'sha256:%'
     AND a.checksum_sha256 = SUBSTRING(anc.digest FROM 8)::bpchar
    WHERE a.repository_id = $1
      AND a.is_deleted = false
      AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
    LIMIT $4
"#
);

/// Whether the manifest `digest` belongs to `image` in repository `repo_id`:
///
/// * the image has a tag pointing at it (a push or proxy fetch by digest
///   records a digest-keyed tag too), or a live manifest row in the
///   repository's catalog whose path names this image (data migrated from
///   another registry can carry only that); or
/// * the repository itself records the manifest, AND it is reached from an
///   index that belongs to the image in one of those ways (the platform
///   manifests and attestations of a multi-platform image are usually
///   untagged).
///
/// Every lookup is scoped to the repository. The record requirement on the
/// second arm matters because pushing an index records a reference to every
/// digest it lists, whether or not this repository holds that manifest.
async fn digest_belongs_to_image(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    repo_key: &str,
    image: &str,
    digest: &str,
) -> Result<bool> {
    if digest_directly_owned(db, repo_id, repo_key, image, digest).await? {
        return Ok(true);
    }
    if !manifest_recorded_in_repository(db, repo_id, digest).await? {
        return Ok(false);
    }
    let tagged: bool = sqlx::query_scalar(ANCESTOR_TAGGED_UNDER_IMAGE_SQL)
        .bind(repo_id)
        .bind(digest)
        .bind(MAX_OWNING_INDEX_DEPTH)
        .bind(image)
        .fetch_one(db)
        .await?;
    if tagged {
        return Ok(true);
    }
    let paths: Vec<String> = sqlx::query_scalar(ANCESTOR_CATALOG_PATHS_SQL)
        .bind(repo_id)
        .bind(digest)
        .bind(MAX_OWNING_INDEX_DEPTH)
        .bind(MAX_ANCESTOR_CATALOG_ROWS)
        .fetch_all(db)
        .await?;
    Ok(paths_attribute_to_image(&paths, repo_key, image))
}

/// Whether repository `repo_id` itself records manifest `digest`: its
/// `oci_manifests` row, or any tag of the repository naming it (a manifest a
/// pre-1.11 replica pushed before the row existed). Used for the children an
/// index lists, which are read only when this repository holds them.
async fn manifest_recorded_in_repository(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    digest: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_manifests WHERE repository_id = $1 AND digest = $2) \
             OR EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2)",
    )
    .bind(repo_id)
    .bind(digest)
    .fetch_one(db)
    .await?)
}

/// The non-recursive half of [`digest_belongs_to_image`]: a tag of `image`
/// names `digest`, or a live manifest-shaped catalog row of the repository
/// with those bytes is attributed to `image` by its path.
async fn digest_directly_owned(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    repo_key: &str,
    image: &str,
    digest: &str,
) -> Result<bool> {
    let tagged: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_tags \
         WHERE repository_id = $1 AND name = $2 AND manifest_digest = $3)",
    )
    .bind(repo_id)
    .bind(image)
    .bind(digest)
    .fetch_one(db)
    .await?;
    if tagged {
        return Ok(true);
    }
    let Some(hex) = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
    else {
        return Ok(false);
    };
    let paths: Vec<String> = sqlx::query_scalar(SELECT_LIVE_MANIFEST_ROW_PATHS_SQL)
        .bind(repo_id)
        .bind(hex)
        .fetch_all(db)
        .await?;
    Ok(paths_attribute_to_image(&paths, repo_key, image))
}

/// Whether any catalog path is attributed to `image` by
/// `manifest_row_image`, the attribution the registry's by-digest delete
/// uses. Like that delete, a repository-key prefix on the path is stripped
/// first, so a migrated source-layout row is read relative to the key.
fn paths_attribute_to_image(paths: &[String], repo_key: &str, image: &str) -> bool {
    paths.iter().any(|path| {
        crate::services::oci_migration_reindex::manifest_row_image(path, repo_key).as_deref()
            == Some(image)
    })
}

/// Live manifest-shaped catalog rows of a repository (`$1`) whose bytes are
/// one sha256 digest (`$2`, hex). The image each row belongs to is read from
/// its path ([`paths_attribute_to_image`]).
const SELECT_LIVE_MANIFEST_ROW_PATHS_SQL: &str = concat!(
    r#"
    SELECT a.path::text
    FROM artifacts a
    WHERE a.repository_id = $1
      AND a.checksum_sha256 = $2::bpchar
      AND a.is_deleted = false
      AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
);

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
    let digest =
        resolve_manifest_digest(&state.db, repo.id, &repo.key, &q.image, &q.reference).await?;
    let storage = state.storage_for_repo(&repo.storage_location())?;
    let reference = format!("{}/{}:{}", repo.key, q.image, q.reference);
    let (db, repo_id) = (&state.db, repo.id);
    let doc = oci_inspect::inspect(storage.as_ref(), &reference, &digest, |child| async move {
        manifest_recorded_in_repository(db, repo_id, &child).await
    })
    .await?;
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
        Some(a) => authorize_build(&state, a, &repo, &s).await.is_ok(),
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
    let digest =
        match resolve_manifest_digest(&state.db, base_repo.id, &base_repo.key, &image, &reference)
            .await
        {
            Ok(d) => d,
            Err(AppError::NotFound(_)) => return Ok(Json(not_found)),
            Err(e) => return Err(e),
        };
    let storage = state.storage_for_repo(&base_repo.storage_location())?;
    let full = format!("{}/{}:{}", base_repo.key, image, reference);
    let db = &state.db;
    let base_repo_id = base_repo.id;
    match oci_inspect::inspect(storage.as_ref(), &full, &digest, |child| async move {
        manifest_recorded_in_repository(db, base_repo_id, &child).await
    })
    .await
    {
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
        (status = 403, description = "Builds are admin-only on this instance, or the caller lacks the repository write action"),
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
    let settings = ImageBuildSettings::from_env();
    authorize_build(&state, &auth, &repo, &settings).await?;
    require_container_repo(&repo)?;
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
        (status = 403, description = "Builds are admin-only on this instance, or the caller lacks the repository write action"),
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
    let settings = ImageBuildSettings::from_env();
    authorize_build(&state, &auth, &repo, &settings).await?;
    require_buildable(&repo)?;
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

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::repository::{ReplicationPriority, RepositoryVisibility};
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
            visibility: RepositoryVisibility::Public,
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

    // -----------------------------------------------------------------------
    // Digest references resolve only within the requested repository and
    // image, even when several repositories share one storage backend.
    // -----------------------------------------------------------------------

    const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

    fn sha256_digest(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    /// Store an image (config + manifest) whose config carries `marker` in its
    /// environment. Returns the manifest bytes and digest.
    async fn store_image(
        storage: &dyn crate::storage::StorageBackend,
        marker: &str,
    ) -> (Vec<u8>, String) {
        use crate::api::handlers::oci_v2::{blob_storage_key, manifest_storage_key};
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": "amd64", "os": "linux",
            "config": {"Env": [format!("MARKER={marker}")], "User": marker},
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": []
        }))
        .unwrap();
        let config_digest = sha256_digest(&config);
        storage
            .put(&blob_storage_key(&config_digest), config.clone().into())
            .await
            .expect("put config");
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": config.len()},
            "layers": []
        }))
        .unwrap();
        let digest = sha256_digest(&manifest);
        storage
            .put(&manifest_storage_key(&digest), manifest.clone().into())
            .await
            .expect("put manifest");
        (manifest, digest)
    }

    async fn tag(pool: &sqlx::PgPool, repo_id: Uuid, image: &str, tag: &str, digest: &str) {
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(repo_id)
        .bind(image)
        .bind(tag)
        .bind(digest)
        .bind(OCI_MANIFEST)
        .execute(pool)
        .await
        .expect("insert tag");
    }

    /// A manifest catalog row (`v2/<image>/manifests/<digest>`) with no tag, as
    /// data migrated from another registry can carry.
    async fn catalog_manifest(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        image: &str,
        digest: &str,
        size: usize,
    ) {
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(repo_id)
        .bind(format!("v2/{image}/manifests/{digest}"))
        .bind(image)
        .bind(size as i64)
        .bind(digest.strip_prefix("sha256:").unwrap())
        .bind(OCI_MANIFEST)
        .bind(format!("oci-manifests/{digest}"))
        .execute(pool)
        .await
        .expect("insert manifest row");
    }

    async fn record_manifest(pool: &sqlx::PgPool, repo_id: Uuid, digest: &str, media: &str) {
        sqlx::query(
            "INSERT INTO oci_manifests (repository_id, digest, content_type, size_bytes) \
             VALUES ($1, $2, $3, 1) ON CONFLICT DO NOTHING",
        )
        .bind(repo_id)
        .bind(digest)
        .bind(media)
        .execute(pool)
        .await
        .expect("insert oci_manifests row");
    }

    async fn reference(pool: &sqlx::PgPool, repo_id: Uuid, parent: &str, child: &str) {
        sqlx::query(
            "INSERT INTO oci_manifest_refs (repository_id, parent_digest, child_digest) \
             VALUES ($1, $2, $3)",
        )
        .bind(repo_id)
        .bind(parent)
        .bind(child)
        .execute(pool)
        .await
        .expect("insert ref");
    }

    /// Store an index listing `children` (each `(digest, size)`); returns its digest.
    async fn store_index(
        storage: &dyn crate::storage::StorageBackend,
        children: &[(&str, usize)],
        media: &str,
    ) -> String {
        let manifests: Vec<serde_json::Value> = children
            .iter()
            .map(|(d, size)| {
                serde_json::json!({"mediaType": media, "digest": d, "size": size,
                                   "platform": {"os": "linux", "architecture": "amd64"}})
            })
            .collect();
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests
        }))
        .unwrap();
        let digest = sha256_digest(&index);
        storage
            .put(
                &crate::api::handlers::oci_v2::manifest_storage_key(&digest),
                index.into(),
            )
            .await
            .expect("put index");
        digest
    }

    /// A private and a public container repository on ONE storage location,
    /// as two repositories on a shared cloud bucket are. Both hold an image
    /// named `team/app`, so only the repository scope separates them.
    struct SharedStoragePair {
        pool: sqlx::PgPool,
        dir: std::path::PathBuf,
        private_id: Uuid,
        public_id: Uuid,
        public_key: String,
        /// Private `team/app:1`.
        foreign: String,
        /// Private `team/app`, catalogued only (untagged push by digest).
        foreign_untagged: String,
        /// The platform child of private `team/app:multi`.
        foreign_child: String,
        /// Public `team/app:1`.
        owned_tagged: String,
        /// Public `team/app`, pushed by digest (digest-keyed tag).
        owned_by_digest: String,
        /// Public `team/app`, catalogued only (migrated data).
        owned_untagged: String,
        /// Public `team/app`, catalogued but the row is in the trash.
        owned_deleted: String,
        /// Public `team/app:multi`, an index with one platform child.
        owned_index: String,
        /// The index's untagged platform child (recorded in the repository).
        owned_child: String,
        /// The leaf of public `team/app:nested` -> inner index -> leaf.
        nested_leaf: String,
        /// Public `team/other:1`.
        other_image: String,
    }

    impl SharedStoragePair {
        async fn setup() -> Option<Self> {
            use crate::api::handlers::test_db_helpers as tdh;
            let pool = tdh::try_pool().await?;
            let (private_id, _private_key, dir) = tdh::create_repo(&pool, "local", "docker").await;
            let (public_id, public_key, public_dir) =
                tdh::create_repo(&pool, "local", "docker").await;
            let _ = std::fs::remove_dir_all(&public_dir);
            tdh::publish_repo(&pool, public_id).await;
            sqlx::query("UPDATE repositories SET storage_path = $1 WHERE id = $2")
                .bind(dir.to_string_lossy().to_string())
                .bind(public_id)
                .execute(&pool)
                .await
                .expect("share storage");

            let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
            let repo = RepositoryService::new(pool.clone())
                .get_by_key(&public_key)
                .await
                .expect("public repo");
            let storage = state
                .storage_for_repo(&repo.storage_location())
                .expect("storage");
            let storage = storage.as_ref();
            let app = "team/app";

            // Private repository: tagged, catalogued-only, and an index child.
            let (_, foreign) = store_image(storage, "private-marker").await;
            tag(&pool, private_id, app, "1", &foreign).await;
            record_manifest(&pool, private_id, &foreign, OCI_MANIFEST).await;
            let (bytes, foreign_untagged) = store_image(storage, "private-untagged").await;
            catalog_manifest(&pool, private_id, app, &foreign_untagged, bytes.len()).await;
            record_manifest(&pool, private_id, &foreign_untagged, OCI_MANIFEST).await;
            let (bytes, foreign_child) = store_image(storage, "private-child").await;
            let foreign_index =
                store_index(storage, &[(&foreign_child, bytes.len())], OCI_MANIFEST).await;
            tag(&pool, private_id, app, "multi", &foreign_index).await;
            record_manifest(&pool, private_id, &foreign_index, OCI_INDEX).await;
            record_manifest(&pool, private_id, &foreign_child, OCI_MANIFEST).await;
            reference(&pool, private_id, &foreign_index, &foreign_child).await;

            // Public repository.
            let (_, owned_tagged) = store_image(storage, "public-tagged").await;
            tag(&pool, public_id, app, "1", &owned_tagged).await;
            record_manifest(&pool, public_id, &owned_tagged, OCI_MANIFEST).await;

            let (_, owned_by_digest) = store_image(storage, "public-by-digest").await;
            tag(&pool, public_id, app, &owned_by_digest, &owned_by_digest).await;
            record_manifest(&pool, public_id, &owned_by_digest, OCI_MANIFEST).await;

            let (bytes, owned_untagged) = store_image(storage, "public-untagged").await;
            catalog_manifest(&pool, public_id, app, &owned_untagged, bytes.len()).await;

            let (bytes, owned_deleted) = store_image(storage, "public-deleted").await;
            catalog_manifest(&pool, public_id, app, &owned_deleted, bytes.len()).await;
            sqlx::query(
                "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
            )
            .bind(public_id)
            .bind(format!("v2/{app}/manifests/{owned_deleted}"))
            .execute(&pool)
            .await
            .expect("trash row");

            let (bytes, owned_child) = store_image(storage, "public-child").await;
            let owned_index =
                store_index(storage, &[(&owned_child, bytes.len())], OCI_MANIFEST).await;
            tag(&pool, public_id, app, "multi", &owned_index).await;
            record_manifest(&pool, public_id, &owned_index, OCI_INDEX).await;
            record_manifest(&pool, public_id, &owned_child, OCI_MANIFEST).await;
            reference(&pool, public_id, &owned_index, &owned_child).await;

            // Two levels: tagged outer index -> untagged inner index -> leaf.
            let (bytes, nested_leaf) = store_image(storage, "public-nested").await;
            let inner = store_index(storage, &[(&nested_leaf, bytes.len())], OCI_MANIFEST).await;
            let outer = store_index(storage, &[(&inner, 1)], OCI_INDEX).await;
            tag(&pool, public_id, app, "nested", &outer).await;
            for (d, media) in [
                (&outer, OCI_INDEX),
                (&inner, OCI_INDEX),
                (&nested_leaf, OCI_MANIFEST),
            ] {
                record_manifest(&pool, public_id, d, media).await;
            }
            reference(&pool, public_id, &outer, &inner).await;
            reference(&pool, public_id, &inner, &nested_leaf).await;

            // An index pushed into the PUBLIC repository that lists the
            // private child. Pushing records the reference whatever the
            // repository holds; the private child has no row here.
            let forged = store_index(storage, &[(&foreign_child, 1)], OCI_MANIFEST).await;
            tag(&pool, public_id, app, "forged", &forged).await;
            record_manifest(&pool, public_id, &forged, OCI_INDEX).await;
            reference(&pool, public_id, &forged, &foreign_child).await;

            let (_, other_image) = store_image(storage, "public-other").await;
            tag(&pool, public_id, "team/other", "1", &other_image).await;
            record_manifest(&pool, public_id, &other_image, OCI_MANIFEST).await;

            Some(Self {
                pool,
                dir,
                private_id,
                public_id,
                public_key,
                foreign,
                foreign_untagged,
                foreign_child,
                owned_tagged,
                owned_by_digest,
                owned_untagged,
                owned_deleted,
                owned_index,
                owned_child,
                nested_leaf,
                other_image,
            })
        }

        /// Anonymous GET against the public repository's routes.
        async fn get(&self, uri: String) -> (StatusCode, String) {
            use crate::api::handlers::test_db_helpers as tdh;
            let state = tdh::build_state(self.pool.clone(), self.dir.to_string_lossy().as_ref());
            let app = tdh::router_anon(repo_router(), state);
            let (status, body) = tdh::send(app, tdh::get(uri)).await;
            (status, String::from_utf8_lossy(&body).into_owned())
        }

        async fn inspect(&self, image: &str, reference: &str) -> (StatusCode, String) {
            self.get(format!(
                "/{}/image-inspect?image={image}&reference={reference}",
                self.public_key
            ))
            .await
        }

        async fn base_info(&self, image: &str, reference: &str) -> serde_json::Value {
            let sep = if reference.starts_with("sha256:") {
                '@'
            } else {
                ':'
            };
            let (status, body) = self
                .get(format!(
                    "/{}/image-builds/base-info?image={}/{image}{sep}{reference}",
                    self.public_key, self.public_key
                ))
                .await;
            assert_eq!(status, StatusCode::OK, "base-info: {body}");
            serde_json::from_str(&body).expect("base-info JSON")
        }

        async fn cleanup(self) {
            for id in [self.private_id, self.public_id] {
                let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await;
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The refusal for `digest` with the digest itself masked, so a foreign
    /// digest's response can be compared byte for byte with an absent one's.
    fn masked(body: &str, digest: &str) -> String {
        body.replace(digest, "<digest>")
    }

    #[tokio::test]
    async fn inspect_by_digest_stays_within_the_repository_and_image() {
        let Some(f) = SharedStoragePair::setup().await else {
            return;
        };
        let app = "team/app";
        let absent = format!("sha256:{}", "0".repeat(64));
        let (absent_status, absent_body) = f.inspect(app, &absent).await;
        assert_eq!(absent_status, StatusCode::NOT_FOUND, "{absent_body}");

        // The private repository's manifests of the SAME image name, on the
        // same storage: tagged, catalogued only, and an index child. Each is
        // refused exactly like a digest that does not exist.
        for digest in [&f.foreign, &f.foreign_untagged, &f.foreign_child] {
            let (status, body) = f.inspect(app, digest).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "foreign {digest}: {body}");
            assert!(!body.contains("private-"), "{body}");
            assert_eq!(masked(&body, digest), masked(&absent_body, &absent));
        }

        // An index in the public repository that lists the private child
        // does not make the child readable, by digest or through the index.
        let (status, body) = f.inspect(app, "forged").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "forged index: {body}");
        assert!(!body.contains("private-"), "{body}");

        // The right repository but the wrong image, both ways round.
        let (status, body) = f.inspect(app, &f.other_image).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "wrong image: {body}");
        assert_eq!(masked(&body, &f.other_image), masked(&absent_body, &absent));
        let (status, body) = f.inspect("team/other", &f.owned_tagged).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "wrong image: {body}");

        // A catalogued manifest whose row is in the trash is gone.
        let (status, body) = f.inspect(app, &f.owned_deleted).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "trashed: {body}");

        // Owned references resolve.
        for (reference, marker) in [
            ("1", "public-tagged"),
            (f.owned_tagged.as_str(), "public-tagged"),
            (f.owned_by_digest.as_str(), "public-by-digest"),
            (f.owned_untagged.as_str(), "public-untagged"),
            ("multi", "public-child"),
            (f.owned_index.as_str(), "public-child"),
            (f.owned_child.as_str(), "public-child"),
            // Two levels up: the leaf of a nested index, by digest. (`inspect`
            // does not descend a nested index by tag, so only the leaf is read.)
            (f.nested_leaf.as_str(), "public-nested"),
        ] {
            let (status, body) = f.inspect(app, reference).await;
            assert_eq!(status, StatusCode::OK, "{reference}: {body}");
            assert!(body.contains(marker), "{reference}: {body}");
        }
        let (status, body) = f.inspect("team/other", &f.other_image).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The child is not reachable under another image name.
        let (status, _) = f.inspect("team/other", &f.owned_child).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        f.cleanup().await;
    }

    #[tokio::test]
    async fn base_image_info_by_digest_stays_within_the_repository_and_image() {
        let Some(f) = SharedStoragePair::setup().await else {
            return;
        };
        let app = "team/app";
        let absent = format!("sha256:{}", "0".repeat(64));
        for reference in [
            absent.as_str(),
            f.foreign.as_str(),
            f.foreign_untagged.as_str(),
            f.foreign_child.as_str(),
            f.other_image.as_str(),
            "forged",
        ] {
            let info = f.base_info(app, reference).await;
            assert_eq!(info["found"], false, "{reference}: {info}");
            assert!(!info.to_string().contains("private-"), "{info}");
        }
        for (reference, user) in [
            ("1", "public-tagged"),
            (f.owned_tagged.as_str(), "public-tagged"),
            (f.owned_untagged.as_str(), "public-untagged"),
            (f.owned_child.as_str(), "public-child"),
        ] {
            let info = f.base_info(app, reference).await;
            assert_eq!(info["found"], true, "{reference}: {info}");
            assert_eq!(info["user"], user, "{reference}: {info}");
        }
        f.cleanup().await;
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

    /// GHSA-mvmh-g8wm-r3cp #5: with `AK_IMAGE_BUILD_ADMIN_ONLY=false`,
    /// rendering or starting a build pushes into the repository, so it needs
    /// the repository `write` action. A signed-in user with no grant on a
    /// public repository, and a read-only member, used to pass the tenant
    /// gate alone. Router-level, so the full extractor chain runs.
    #[tokio::test]
    async fn builds_need_repository_write_when_not_admin_only_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Process-global, but nextest runs each test in its own process.
        std::env::set_var("AK_IMAGE_BUILD_ADMIN_ONLY", "false");
        std::env::remove_var("AK_IMAGE_BUILD_BASE_ALLOWLIST");
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "docker").await;
        tdh::publish_repo(&pool, repo_id).await;
        let session = tdh::make_auth(user_id, &username);
        let call = |path: &str, body: serde_json::Value| {
            let app = tdh::router_with_auth(
                repo_router(),
                tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref()),
                session.clone(),
            );
            let req = tdh::post(
                format!("/{key}/image-builds{path}"),
                "application/json",
                axum::body::Bytes::from(body.to_string()),
            );
            async move { tdh::send(app, req).await.0 }
        };
        let spec = serde_json::json!({ "base_image": "python:3.12" });
        let render = || call("/render", serde_json::json!({ "spec": spec }));
        let create = || {
            call(
                "",
                serde_json::json!({ "image": "team/app", "tag": "1", "spec": spec }),
            )
        };
        let builds = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM image_builds WHERE repository_id = $1",
            )
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .expect("count builds")
        };

        // 1) No grant, then 2) a read-only member: both refused.
        assert_eq!(render().await, StatusCode::FORBIDDEN, "render, no grant");
        assert_eq!(create().await, StatusCode::FORBIDDEN, "create, no grant");
        tdh::grant_repo_role(&pool, repo_id, user_id, "reader").await;
        assert_eq!(render().await, StatusCode::FORBIDDEN, "render, reader");
        assert_eq!(create().await, StatusCode::FORBIDDEN, "create, reader");
        assert_eq!(builds().await, 0, "a refused build must queue nothing");

        // 3) A write member renders.
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        assert_eq!(render().await, StatusCode::OK, "render, developer");

        let _ = sqlx::query("DELETE FROM image_builds WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
